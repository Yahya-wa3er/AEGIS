"""
Détection d'outliers dans l'espace des embeddings d'un document (blueprint,
section 4.5 - volet SentinelRAG).

Principe : apprendre à quoi "ressemble" le domaine documentaire normal de
l'agent (ici : des documents de contexte de support client), puis mesurer à
quel point un nouveau document récupéré s'en écarte. Un document empoisonné
change souvent aussi le SENS du texte (instructions système, jargon technique
inhabituel), pas seulement sa forme -- un signal indépendant du regex/ML de
`injection_detector.py`, qui lui analyse des motifs textuels précis.

Simplification assumée (voir "Limites connues" du README) : le blueprint
(section 5) prévoit des embeddings de phrases (sentence-transformers) + FAISS.
Ici, on utilise TF-IDF (scikit-learn, déjà une dépendance du projet, aucun
téléchargement de modèle nécessaire) + une distance au centroïde du corpus
normal -- une notion de "sens" plus grossière qu'un vrai embedding sémantique,
mais qui suit exactement le même principe et suffit à démontrer l'idée.
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import joblib
    import numpy as np
    from sklearn.metrics.pairwise import cosine_similarity

    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    logger.warning(
        "scikit-learn/joblib non installés -- RagOutlierDetector tournera "
        "toujours en mode dégradé (risque nul)."
    )

DEFAULT_MODEL_DIR = Path("models/rag_outlier")


@dataclass(frozen=True)
class RagOutlierScanResult:
    """Résultat du scan d'un document. Même convention de `risk` que les
    autres détecteurs (0 = confiant que c'est dans le domaine normal, proche
    de 1 = sémantiquement très éloigné de tout ce qui a été vu à l'entraînement)."""

    risk: float
    flagged: bool
    distance: float | None = None
    threshold: float | None = None


def _load_artifacts(model_dir: str) -> tuple[object | None, object | None, dict | None]:
    if not _SKLEARN_AVAILABLE:
        return None, None, None

    path = Path(model_dir)
    vectorizer_path = path / "vectorizer.joblib"
    centroid_path = path / "centroid.npy"
    config_path = path / "config.json"
    if not (vectorizer_path.is_file() and centroid_path.is_file() and config_path.is_file()):
        logger.warning(
            "Modèle d'outliers RAG introuvable dans '%s' (lance "
            "scripts/generate_rag_corpus.py puis scripts/train_rag_outlier_detector.py) "
            "-- RagOutlierDetector renverra un risque nul.",
            model_dir,
        )
        return None, None, None

    try:
        vectorizer = joblib.load(vectorizer_path)
        centroid = np.load(centroid_path)
        config = json.loads(config_path.read_text(encoding="utf-8"))
        return vectorizer, centroid, config
    except Exception:
        logger.exception(
            "Échec du chargement du modèle d'outliers RAG depuis '%s' -- "
            "RagOutlierDetector renverra un risque nul.",
            model_dir,
        )
        return None, None, None


class RagOutlierDetector:
    """Détecteur d'anomalies sémantiques (distance au domaine documentaire normal)."""

    def __init__(self, model_dir: Path | str = DEFAULT_MODEL_DIR):
        self._vectorizer, self._centroid, self._config = _load_artifacts(str(model_dir))

    @property
    def ml_available(self) -> bool:
        return self._vectorizer is not None

    def score(self, text: str) -> RagOutlierScanResult:
        if self._vectorizer is None or self._centroid is None or self._config is None:
            return RagOutlierScanResult(risk=0.0, flagged=False)

        vector = self._vectorizer.transform([text])
        similarity = float(cosine_similarity(vector, self._centroid.reshape(1, -1))[0][0])
        distance = 1.0 - similarity

        threshold = float(self._config["anomaly_threshold"])
        risk = 1.0 - math.exp(-distance / threshold) if threshold > 0 else 0.0
        return RagOutlierScanResult(risk=risk, flagged=distance > threshold, distance=distance, threshold=threshold)
