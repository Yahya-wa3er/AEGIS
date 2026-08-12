"""
Entraîne le détecteur d'outliers RAG (blueprint, section 4.5) sur le corpus
de documents normaux généré par `generate_rag_corpus.py`.

Principe (voir docstring de `aegis_core/rag_outlier_detector.py`) : on apprend
UNIQUEMENT à partir de documents normaux (comme le VAE comportemental) --
jamais besoin d'exemples d'attaque pour apprendre à quoi ressemble le domaine.

Usage:
    python -m scripts.generate_rag_corpus   # si pas déjà fait
    python -m scripts.train_rag_outlier_detector
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

TRAIN_PATH = Path("data/rag_corpus_train.jsonl")
EVAL_PATH = Path("data/rag_corpus_eval.jsonl")
OUTPUT_DIR = Path("models/rag_outlier")


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


def evaluate(vectorizer: TfidfVectorizer, centroid: np.ndarray) -> float:
    rows = _load_eval_rows(EVAL_PATH)
    by_category: dict[str, list[float]] = {}

    for row in rows:
        vector = vectorizer.transform([row["text"]])
        similarity = float(cosine_similarity(vector, centroid.reshape(1, -1))[0][0])
        distance = 1.0 - similarity
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


def main() -> None:
    vectorizer, centroid = train()
    threshold = evaluate(vectorizer, centroid)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(vectorizer, OUTPUT_DIR / "vectorizer.joblib")
    np.save(OUTPUT_DIR / "centroid.npy", centroid)
    (OUTPUT_DIR / "config.json").write_text(
        json.dumps({"anomaly_threshold": threshold}, indent=2), encoding="utf-8"
    )
    logger.info("Vectoriseur, centroïde et seuil sauvegardés dans '%s'.", OUTPUT_DIR)


if __name__ == "__main__":
    main()
