"""
Entraîne le détecteur d'outliers RAG (blueprint, section 4.5) sur le corpus
de documents normaux généré par `generate_rag_corpus.py`.

Principe (voir docstring de `aegis_core/rag_outlier_detector.py`) : on apprend
UNIQUEMENT à partir de documents normaux (comme le VAE comportemental) --
jamais besoin d'exemples d'attaque pour apprendre à quoi ressemble le domaine.

Usage:
    python -m scripts.generate_rag_corpus   # si pas déjà fait
    python -m scripts.train_rag_outlier_detector

Discipline de mesure (correctif P1-M2)
--------------------------------------
Trois jeux, et un seul rôle chacun. Le modèle s'ajuste sur **train**, le seuil se
choisit sur **calibration**, et la mesure publiée sort de **test** -- lu une
seule fois, à la fin.

La version précédente calculait `seuil = moyenne(normaux du jeu d'éval) + 2σ`
puis annonçait le taux de faux positifs sur ces mêmes normaux. Un seuil placé à
deux écarts-types d'un échantillon laisse par construction ~2 % de cet
échantillon au-dessus : sur 30 documents, 0 ou 1. Le « 0 % de faux positifs »
n'était pas une mesure du détecteur, c'était une propriété du seuil. Le
coefficient lui-même (k=2 plutôt que k=3) avait été choisi en comparant les
rappels *sur le jeu d'évaluation* -- un hyperparamètre réglé sur le test.

Le seuil est désormais un **quantile des distances de calibration** : « je
tolère au plus TARGET_FALSE_POSITIVE_RATE de faux positifs sur des documents
légitimes ». C'est une décision d'exploitation, elle se prend explicitement, et
elle se prend sur des données que la mesure ne verra jamais.

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
from aegis_core.stats import rate
from scripts.dataset_split import assert_no_leakage

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

TRAIN_PATH = Path("data/rag_corpus_train.jsonl")
CALIB_PATH = Path("data/rag_corpus_calibration.jsonl")
TEST_PATH = Path("data/rag_corpus_test.jsonl")
OUTPUT_DIR = Path("models/rag_outlier")

# Taux de faux positifs qu'on accepte sur des documents légitimes. C'est LE
# paramètre d'exploitation du détecteur : le fixer ici, en clair, vaut mieux que
# de le laisser émerger d'un « moyenne + 2 écarts-types » dont personne ne sait
# à quel taux il correspond.
TARGET_FALSE_POSITIVE_RATE = 0.05

ARTIFACTS = ("vectorizer.json", "weights.npz", "config.json", "metrics.json")
# Tolérance de la vérification de parité entre scikit-learn et la réimplémentation.
# Les deux calculs suivent le même chemin mathématique ; l'écart attendu est de
# l'ordre de l'epsilon machine sur des float64.
PARITY_TOLERANCE = 1e-9


def _load_texts(path: Path) -> list[str]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [row["text"] for row in rows]


def _load_rows(path: Path) -> list[dict]:
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


def calibrate(vectorizer: TfidfVectorizer, centroid: np.ndarray) -> float:
    """Choisit le seuil sur le jeu de CALIBRATION, jamais sur le test.

    Le seuil est le quantile des distances des documents légitimes de
    calibration à `1 - TARGET_FALSE_POSITIVE_RATE`. Traduction : « le seuil qui
    laisse passer au plus 5 % de documents légitimes que je n'ai jamais mesurés
    ailleurs ». Le jeu de calibration contient volontairement les deux natures
    de document légitime -- domaine et hors-domaine -- parce qu'un seuil calé
    sur le seul domaine du support client neutralise tout le reste.
    """
    rows = _load_rows(CALIB_PATH)
    distances = [_sklearn_distance(vectorizer, centroid, row["text"]) for row in rows]
    threshold = float(np.quantile(distances, 1.0 - TARGET_FALSE_POSITIVE_RATE))
    logger.info(
        "Seuil calibré sur %d documents légitimes : %.4f (quantile %.0f%%, cible %.0f%% de faux positifs).",
        len(distances), threshold, 100 * (1 - TARGET_FALSE_POSITIVE_RATE), 100 * TARGET_FALSE_POSITIVE_RATE,
    )
    return threshold


def measure(vectorizer: TfidfVectorizer, centroid: np.ndarray, threshold: float) -> dict[str, object]:
    """Mesure sur le jeu de TEST, une seule fois, seuil déjà figé.

    Les taux sont publiés avec leur intervalle de confiance à 95 % (Wilson) :
    à ces volumes, un taux nu suggère une précision qu'il n'a pas. « 100 % » sur
    14 attaques, c'est [78 % ; 100 %] -- et c'est cette seconde écriture qui dit
    la vérité sur ce que le corpus permet d'affirmer.
    """
    rows = _load_rows(TEST_PATH)
    by_category: dict[str, list[float]] = {}
    for row in rows:
        distance = _sklearn_distance(vectorizer, centroid, row["text"])
        by_category.setdefault(row["category"], []).append(distance)

    logger.info("--- Distance au centroïde par catégorie (jeu de test) ---")
    for category, values in sorted(by_category.items()):
        avg = sum(values) / len(values)
        logger.info("  %-22s n=%-3d moyenne=%.4f  min=%.4f  max=%.4f",
                    category, len(values), avg, min(values), max(values))

    def flagged(category: str) -> tuple[int, int]:
        values = by_category.get(category, [])
        return sum(1 for d in values if d > threshold), len(values)

    recall = rate(*flagged("poisoned"))
    fp_domain = rate(*flagged("normal"))
    fp_ood = rate(*flagged("benign_out_of_domain"))
    legit_hits = flagged("normal")[0] + flagged("benign_out_of_domain")[0]
    legit_total = flagged("normal")[1] + flagged("benign_out_of_domain")[1]
    fp_all = rate(legit_hits, legit_total)

    logger.info("--- Mesure sur le jeu de test (seuil figé : %.4f) ---", threshold)
    logger.info("  Rappel sur attaques                    : %s", recall.format())
    logger.info("  Faux positifs, domaine                 : %s", fp_domain.format())
    logger.info("  Faux positifs, légitime hors-domaine   : %s", fp_ood.format())
    logger.info("  Faux positifs, tous documents légitimes: %s", fp_all.format())

    if fp_ood.rate > fp_domain.rate:
        logger.warning(
            "Le détecteur signale davantage les documents légitimes HORS DOMAINE "
            "que ceux du domaine : à ce stade il mesure surtout un écart de "
            "registre, pas une attaque. C'est la limite documentée au README."
        )

    return {
        "threshold": threshold,
        "target_false_positive_rate": TARGET_FALSE_POSITIVE_RATE,
        "recall_attacks": recall.as_dict(),
        "false_positive_rate_in_domain": fp_domain.as_dict(),
        "false_positive_rate_out_of_domain": fp_ood.as_dict(),
        "false_positive_rate_legitimate": fp_all.as_dict(),
    }


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
    """Compare scikit-learn et la réimplémentation d'inférence sur tout le jeu de test.

    Retourne l'écart maximal observé. Lève `SystemExit` si la tolérance est dépassée :
    mieux vaut ne pas produire d'artefacts du tout que d'en produire dont les scores
    à l'inférence diffèrent de ceux mesurés à l'entraînement.
    """
    idf = np.asarray(vectorizer.idf_, dtype=np.float64)
    model = _TfidfModel(vocabulary=spec["vocabulary"], idf=idf, params=spec)
    centroid_norm = float(np.linalg.norm(centroid))

    worst = 0.0
    worst_text = ""
    for row in _load_rows(TEST_PATH):
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
    # Contrôle bloquant AVANT tout apprentissage : un modèle entraîné sur un jeu
    # contaminé produit une mesure qui inspire confiance sans en mériter.
    assert_no_leakage({
        "train": [r["text"] for r in _load_rows(TRAIN_PATH)],
        "calibration": [r["text"] for r in _load_rows(CALIB_PATH)],
        "test": [r["text"] for r in _load_rows(TEST_PATH)],
    })

    vectorizer, centroid = train()
    threshold = calibrate(vectorizer, centroid)
    spec = _build_spec(vectorizer)
    check_parity(vectorizer, centroid, spec)
    metrics = measure(vectorizer, centroid, threshold)

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
    # La mesure voyage AVEC le modèle. Un seuil sans le taux de faux positifs
    # qu'il produit, et sans l'intervalle de confiance de ce taux, est un nombre
    # que personne ne peut interpréter six mois plus tard.
    (OUTPUT_DIR / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    write_manifest(OUTPUT_DIR, list(ARTIFACTS))

    # Les anciens artefacts pickle ne sont plus jamais chargés ; les laisser sur
    # disque ne ferait qu'entretenir la confusion (et garder le fichier dangereux).
    legacy = [OUTPUT_DIR / "vectorizer.joblib", OUTPUT_DIR / "centroid.npy"]
    for stale in legacy:
        if stale.is_file():
            stale.unlink()
            logger.info("Ancien artefact supprimé : %s", stale)

    logger.info("Artefacts (JSON + npz + manifeste + mesures) sauvegardés dans '%s'.", OUTPUT_DIR)


if __name__ == "__main__":
    sys.exit(main())
