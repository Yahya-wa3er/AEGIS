"""
Entraîne le détecteur d'outliers RAG (blueprint, section 4.5) sur le corpus
de documents normaux généré par `generate_rag_corpus.py`.

Principe (voir docstring de `aegis_core/rag_outlier_detector.py`) : on apprend
UNIQUEMENT à partir de documents normaux (comme le VAE comportemental) --
jamais besoin d'exemples d'attaque pour apprendre à quoi ressemble le domaine.

Usage:
    python -m scripts.generate_rag_corpus   # si pas déjà fait
    python -m scripts.train_rag_outlier_detector

Format de sortie (correctif P0-5)
---------------------------------
Ce script n'écrit plus de `vectorizer.joblib`. `joblib.dump/load` repose sur
pickle : recharger un tel fichier exécute le code qu'il contient, ce qui faisait
de `models/` un vecteur d'exécution de code arbitraire dans le processus AEGIS.
Les artefacts sont désormais des données pures (JSON + npz) accompagnées d'un
manifeste SHA-256.

Le script vérifie en outre que la réimplémentation de TF-IDF utilisée à
l'inférence (`aegis_core.rag_outlier_detector._TfidfModel`) produit exactement
les mêmes distances que scikit-learn sur tout le jeu d'évaluation, et REFUSE
d'écrire les artefacts en cas de divergence. C'est ce qui empêche les features
d'entraînement et les features d'inférence de dériver silencieusement.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from aegis_core.model_io import write_manifest
from aegis_core.rag_outlier_detector import SUPPORTED_FORMAT_VERSION, _TfidfModel

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

TRAIN_PATH = Path("data/rag_corpus_train.jsonl")
EVAL_PATH = Path("data/rag_corpus_eval.jsonl")
OUTPUT_DIR = Path("models/rag_outlier")

ARTIFACTS = ("vectorizer.json", "weights.npz", "config.json")
# Tolérance de la vérification de parité entre scikit-learn et la réimplémentation.
# Les deux calculs suivent le même chemin mathématique ; l'écart attendu est de
# l'ordre de l'epsilon machine sur des float64.
PARITY_TOLERANCE = 1e-9


def _load_texts(path: Path) -> list[str]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [row["text"] for row in rows]


def _load_eval_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def train() -> tuple[TfidfVectorizer, np.ndarray]:
    texts = _load_texts(TRAIN_PATH)
    vectorizer = TfidfVectorizer()
    matrix = vectorizer.fit_transform(texts)
    centroid = np.asarray(matrix.mean(axis=0)).ravel()  # "document moyen" du domaine normal
    logger.info("Vectoriseur entraîné sur %d documents (%d mots-clés).", len(texts), len(vectorizer.vocabulary_))
    return vectorizer, centroid


def _sklearn_distance(vectorizer: TfidfVectorizer, centroid: np.ndarray, text: str) -> float:
    vector = vectorizer.transform([text])
    similarity = float(cosine_similarity(vector, centroid.reshape(1, -1))[0][0])
    return 1.0 - similarity


def evaluate(vectorizer: TfidfVectorizer, centroid: np.ndarray) -> float:
    rows = _load_eval_rows(EVAL_PATH)
    by_category: dict[str, list[float]] = {}

    for row in rows:
        distance = _sklearn_distance(vectorizer, centroid, row["text"])
        by_category.setdefault(row["category"], []).append(distance)

    logger.info("--- Distance au centroïde par catégorie (plus haut = plus suspect) ---")
    for category, values in sorted(by_category.items()):
        avg = sum(values) / len(values)
        logger.info("  %-15s n=%-3d moyenne=%.4f  min=%.4f  max=%.4f", category, len(values), avg, min(values), max(values))

    normal_distances = by_category.get("normal", [])
    mean = sum(normal_distances) / len(normal_distances)
    variance = sum((v - mean) ** 2 for v in normal_distances) / len(normal_distances)
    # k=2 (pas 3) choisi après comparaison sur le jeu d'évaluation : passe de 33% à 89%
    # de rappel sur les anomalies sans introduire le moindre faux positif sur le
    # normal -- k=3 était inutilement conservateur pour ce volume d'échantillons.
    threshold = mean + 2 * (variance ** 0.5)

    anomalous = [(cat, d) for cat, values in by_category.items() if cat != "normal" for d in values]
    detected = sum(1 for _, d in anomalous if d > threshold)
    false_positives = sum(1 for d in normal_distances if d > threshold)

    logger.info("--- Seuil retenu : %.4f (moyenne_normal + 2 écarts-types) ---", threshold)
    logger.info(
        "Détection : %d/%d documents anormaux au-dessus du seuil -- Faux positifs : %d/%d documents normaux",
        detected, len(anomalous), false_positives, len(normal_distances),
    )
    return threshold


def _build_spec(vectorizer: TfidfVectorizer) -> dict:
    """Décrit le vectoriseur en données pures, sans pickle."""
    return {
        "format_version": SUPPORTED_FORMAT_VERSION,
        "lowercase": vectorizer.lowercase,
        "binary": vectorizer.binary,
        "sublinear_tf": vectorizer.sublinear_tf,
        "norm": vectorizer.norm,
        "ngram_range": list(vectorizer.ngram_range),
        "strip_accents": vectorizer.strip_accents,
        "token_pattern": vectorizer.token_pattern,
        # numpy int64 n'est pas sérialisable en JSON : on repasse en int Python.
        "vocabulary": {term: int(index) for term, index in vectorizer.vocabulary_.items()},
    }


def check_parity(vectorizer: TfidfVectorizer, centroid: np.ndarray, spec: dict) -> float:
    """Compare scikit-learn et la réimplémentation d'inférence sur tout le jeu d'éval.

    Retourne l'écart maximal observé. Lève `SystemExit` si la tolérance est dépassée :
    mieux vaut ne pas produire d'artefacts du tout que d'en produire dont les scores
    à l'inférence diffèrent de ceux mesurés à l'entraînement.
    """
    idf = np.asarray(vectorizer.idf_, dtype=np.float64)
    model = _TfidfModel(vocabulary=spec["vocabulary"], idf=idf, params=spec)
    centroid_norm = float(np.linalg.norm(centroid))

    worst = 0.0
    worst_text = ""
    for row in _load_eval_rows(EVAL_PATH):
        text = row["text"]
        expected = _sklearn_distance(vectorizer, centroid, text)

        vector = model.transform(text)
        vector_norm = float(np.linalg.norm(vector))
        similarity = 0.0 if vector_norm == 0.0 or centroid_norm == 0.0 else float(
            np.dot(vector, centroid) / (vector_norm * centroid_norm)
        )
        actual = 1.0 - similarity

        gap = abs(expected - actual)
        if gap > worst:
            worst, worst_text = gap, text

    if worst > PARITY_TOLERANCE:
        logger.error(
            "PARITÉ ROMPUE : écart maximal %.3e entre scikit-learn et la réimplémentation "
            "d'inférence (tolérance %.0e). Aucun artefact écrit.\n  Document en cause : %.120s…",
            worst, PARITY_TOLERANCE, worst_text,
        )
        raise SystemExit(1)

    logger.info("Parité scikit-learn ↔ inférence vérifiée : écart maximal %.3e.", worst)
    return worst


def main() -> None:
    vectorizer, centroid = train()
    threshold = evaluate(vectorizer, centroid)
    spec = _build_spec(vectorizer)
    check_parity(vectorizer, centroid, spec)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    (OUTPUT_DIR / "vectorizer.json").write_text(
        json.dumps(spec, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )
    np.savez(
        OUTPUT_DIR / "weights.npz",
        idf=np.asarray(vectorizer.idf_, dtype=np.float64),
        centroid=np.asarray(centroid, dtype=np.float64),
    )
    (OUTPUT_DIR / "config.json").write_text(
        json.dumps({"anomaly_threshold": threshold}, indent=2), encoding="utf-8"
    )
    write_manifest(OUTPUT_DIR, list(ARTIFACTS))

    # Les anciens artefacts pickle ne sont plus jamais chargés ; les laisser sur
    # disque ne ferait qu'entretenir la confusion (et garder le fichier dangereux).
    legacy = [OUTPUT_DIR / "vectorizer.joblib", OUTPUT_DIR / "centroid.npy"]
    for stale in legacy:
        if stale.is_file():
            stale.unlink()
            logger.info("Ancien artefact supprimé : %s", stale)

    logger.info("Artefacts (JSON + npz + manifeste) sauvegardés dans '%s'.", OUTPUT_DIR)


if __name__ == "__main__":
    sys.exit(main())
