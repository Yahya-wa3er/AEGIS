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
Ici, on utilise TF-IDF + une distance au centroïde du corpus normal -- une
notion de "sens" plus grossière qu'un vrai embedding sémantique, mais qui suit
exactement le même principe et suffit à démontrer l'idée.

Format d'artefacts (correctif P0-5)
-----------------------------------
Ce module ne charge PLUS de `vectorizer.joblib`. `joblib.load()` désérialise du
pickle, c'est-à-dire qu'il **exécute le contenu du fichier** : quiconque peut
écrire dans `models/` obtenait ainsi l'exécution de code dans le processus
AEGIS. Contrairement à `torch.load`, joblib n'offre aucun équivalent de
`weights_only=True` -- il n'existe pas de version sûre.

Le vectoriseur est donc désormais stocké en données pures et rechargé sans
sklearn :

    models/rag_outlier/
      vectorizer.json   vocabulaire + paramètres d'analyse (JSON)
      weights.npz       idf + centroïde (numpy, allow_pickle=False)
      config.json       seuil d'anomalie
      MANIFEST.json     SHA-256 de chacun des fichiers ci-dessus

La transformation TF-IDF est réimplémentée ici (`_TfidfModel.transform`) en une
vingtaine de lignes, strictement équivalente à `TfidfVectorizer` de scikit-learn
pour les paramètres que l'on utilise. `scripts/train_rag_outlier_detector.py`
vérifie cette équivalence à chaque entraînement et refuse d'écrire les artefacts
si les scores divergent -- la réimplémentation ne peut donc pas dériver
silencieusement de l'entraînement.

Effet de bord bienvenu : scikit-learn n'est plus nécessaire à l'**exécution**,
seulement à l'entraînement. La surface de dépendance du composant en production
se réduit à numpy.
"""
from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path

from aegis_core.model_io import ModelIntegrityError, load_json, verify_manifest

logger = logging.getLogger(__name__)

try:
    import numpy as np

    _NUMPY_AVAILABLE = True
except ImportError:  # pragma: no cover - dépend de l'environnement
    _NUMPY_AVAILABLE = False
    logger.warning("numpy non installé -- RagOutlierDetector tournera toujours en mode dégradé (risque nul).")

DEFAULT_MODEL_DIR = Path("models/rag_outlier")
SUPPORTED_FORMAT_VERSION = 1


@dataclass(frozen=True)
class RagOutlierScanResult:
    """Résultat du scan d'un document. Même convention de `risk` que les
    autres détecteurs (0 = confiant que c'est dans le domaine normal, proche
    de 1 = sémantiquement très éloigné de tout ce qui a été vu à l'entraînement)."""

    risk: float
    flagged: bool
    distance: float | None = None
    threshold: float | None = None


class _TfidfModel:
    """Réimplémentation minimale et sans dépendance de `TfidfVectorizer.transform`.

    Ne couvre que les paramètres réellement utilisés par l'entraînement (unigrammes,
    norme L2, tf brut ou sous-linéaire). Tout paramètre non supporté rencontré dans
    l'artefact lève une erreur explicite plutôt que de produire silencieusement des
    scores faux -- une divergence entre features d'entraînement et features
    d'inférence est exactement le genre de bug qui rend un détecteur inutile sans
    qu'on s'en aperçoive.
    """

    def __init__(self, vocabulary: dict[str, int], idf: "np.ndarray", params: dict) -> None:
        version = params.get("format_version")
        if version != SUPPORTED_FORMAT_VERSION:
            raise ModelIntegrityError(
                f"Format d'artefact non supporté (version {version!r}, attendu {SUPPORTED_FORMAT_VERSION}). "
                "Relance scripts/train_rag_outlier_detector.py."
            )
        if tuple(params.get("ngram_range", (1, 1))) != (1, 1):
            raise ModelIntegrityError("Seuls les unigrammes sont supportés par ce chargeur.")
        if params.get("norm", "l2") != "l2":
            raise ModelIntegrityError("Seule la norme 'l2' est supportée par ce chargeur.")
        if params.get("strip_accents") is not None:
            raise ModelIntegrityError("Le retrait d'accents n'est pas supporté par ce chargeur.")
        if len(idf) != len(vocabulary):
            raise ModelIntegrityError(
                f"Incohérence d'artefact : {len(vocabulary)} termes pour {len(idf)} valeurs d'idf."
            )

        self._vocabulary = vocabulary
        self._idf = idf
        self._lowercase = bool(params.get("lowercase", True))
        self._binary = bool(params.get("binary", False))
        self._sublinear_tf = bool(params.get("sublinear_tf", False))
        self._token_re = re.compile(params.get("token_pattern", r"(?u)\b\w\w+\b"))

    @property
    def n_features(self) -> int:
        return len(self._idf)

    def transform(self, text: str) -> "np.ndarray":
        """Retourne le vecteur TF-IDF dense et normalisé L2 du texte."""
        if self._lowercase:
            text = text.lower()

        counts = np.zeros(self.n_features, dtype=np.float64)
        for token in self._token_re.findall(text):
            index = self._vocabulary.get(token)
            if index is not None:
                counts[index] += 1.0

        if self._binary:
            counts = (counts > 0).astype(np.float64)
        elif self._sublinear_tf:
            nonzero = counts > 0
            counts[nonzero] = 1.0 + np.log(counts[nonzero])

        vector = counts * self._idf
        norm = float(np.linalg.norm(vector))
        return vector / norm if norm > 0.0 else vector


def _load_artifacts(model_dir: str) -> tuple[_TfidfModel | None, "np.ndarray | None", dict | None]:
    """Charge les artefacts en refusant toute désérialisation de code.

    Retourne `(None, None, None)` si le modèle n'est pas entraîné (mode dégradé,
    cf. P0-4 -- la bascule en fail-closed est traitée au lot suivant). Laisse en
    revanche remonter `ModelIntegrityError` : un artefact présent mais falsifié
    n'est PAS un cas de dégradation silencieuse, c'est un incident.
    """
    if not _NUMPY_AVAILABLE:
        return None, None, None

    path = Path(model_dir)
    vectorizer_path = path / "vectorizer.json"
    weights_path = path / "weights.npz"
    config_path = path / "config.json"

    if not (vectorizer_path.is_file() and weights_path.is_file() and config_path.is_file()):
        if (path / "vectorizer.joblib").is_file():
            logger.warning(
                "Artefacts au format joblib détectés dans '%s' : ce format n'est plus chargé "
                "(désérialisation de code, cf. correctif P0-5). Relance "
                "scripts/train_rag_outlier_detector.py pour régénérer les artefacts.",
                model_dir,
            )
        else:
            logger.warning(
                "Modèle d'outliers RAG introuvable dans '%s' (lance "
                "scripts/generate_rag_corpus.py puis scripts/train_rag_outlier_detector.py) "
                "-- RagOutlierDetector renverra un risque nul.",
                model_dir,
            )
        return None, None, None

    verify_manifest(path)  # lève ModelIntegrityError si une empreinte ne correspond pas

    try:
        spec = load_json(vectorizer_path)
        config = load_json(config_path)
        # allow_pickle=False : un .npz piégé produit une ValueError, jamais une exécution.
        with np.load(weights_path, allow_pickle=False) as weights:
            idf = np.asarray(weights["idf"], dtype=np.float64)
            centroid = np.asarray(weights["centroid"], dtype=np.float64)
    except ModelIntegrityError:
        raise
    except Exception:
        logger.exception(
            "Échec du chargement du modèle d'outliers RAG depuis '%s' -- "
            "RagOutlierDetector renverra un risque nul.",
            model_dir,
        )
        return None, None, None

    try:
        model = _TfidfModel(vocabulary=spec["vocabulary"], idf=idf, params=spec)
    except ModelIntegrityError:
        raise
    except Exception:
        logger.exception("Artefact de vectoriseur invalide dans '%s'.", model_dir)
        return None, None, None

    if centroid.shape != (model.n_features,):
        raise ModelIntegrityError(
            f"Centroïde de dimension {centroid.shape} incompatible avec {model.n_features} termes."
        )

    return model, centroid, config


class RagOutlierDetector:
    """Détecteur d'anomalies sémantiques (distance au domaine documentaire normal)."""

    def __init__(self, model_dir: Path | str = DEFAULT_MODEL_DIR):
        self._model, self._centroid, self._config = _load_artifacts(str(model_dir))

    @property
    def ml_available(self) -> bool:
        return self._model is not None

    def score(self, text: str) -> RagOutlierScanResult:
        if self._model is None or self._centroid is None or self._config is None:
            return RagOutlierScanResult(risk=0.0, flagged=False)

        vector = self._model.transform(text)
        centroid_norm = float(np.linalg.norm(self._centroid))
        vector_norm = float(np.linalg.norm(vector))
        if centroid_norm == 0.0 or vector_norm == 0.0:
            similarity = 0.0
        else:
            similarity = float(np.dot(vector, self._centroid) / (vector_norm * centroid_norm))
        distance = 1.0 - similarity

        threshold = float(self._config["anomaly_threshold"])
        risk = 1.0 - math.exp(-distance / threshold) if threshold > 0 else 0.0
        return RagOutlierScanResult(risk=risk, flagged=distance > threshold, distance=distance, threshold=threshold)
