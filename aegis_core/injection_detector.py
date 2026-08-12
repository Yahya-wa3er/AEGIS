"""Détection d'injection de prompt — défense en profondeur (regex + ML).

Deux couches indépendantes, combinées par un OR sur le flag et un MAX sur le score
de risque :

1. Règles regex (V0) : rapides, déterministes, explicables — couvrent les patterns
   d'attaque connus (ex. "ignore les instructions précédentes", "system override").
2. Classifieur ML (Phase 2) : DistilBERT fine-tuné sur `deepset/prompt-injections`
   (voir `scripts/train_injection_classifier.py`) — généralise à des formulations
   jamais vues, que le regex ne peut pas anticiper par construction.

Principe de fail-safe : si le modèle ML n'est pas disponible (pas encore entraîné,
fichiers absents, erreur de chargement), le détecteur bascule silencieusement en
mode regex uniquement plutôt que de planter — un log WARNING signale la dégradation.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer, PreTrainedModel, PreTrainedTokenizerBase

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = Path("models/injection_classifier")
DEFAULT_ML_THRESHOLD = 0.5
ML_MAX_SEQ_LENGTH = 256
# Convention du dataset deepset/prompt-injections : label 1 = injection, label 0 = légitime.
ML_INJECTION_CLASS_INDEX = 1

SUSPICIOUS_PATTERNS: tuple[str, ...] = (
    r"ignore\s+(toutes\s+)?les?\s+instructions?\s+pr[ée]c[ée]dentes?",
    r"system\s*override",
    r"tu\s+es\s+maintenant\s+en\s+mode",
    r"tu\s+dois\s+imm[ée]diatement\s+appeler",
    r"ne\s+mentionne\s+(jamais|pas)\s+cette\s+instruction",
    r"<!--.*-->",
)


@dataclass(frozen=True)
class ScanResult:
    """Résultat d'un scan, combinant les deux couches de détection.

    `ml_score` vaut `None` quand le classifieur ML n'était pas disponible au moment
    du scan — cela permet de distinguer "le ML n'a rien détecté" (score bas) de
    "le ML n'a pas tourné" (score absent), utile pour le reporting de robustesse.
    """

    risk: float
    flagged: bool
    matched_patterns: tuple[str, ...] = field(default_factory=tuple)
    ml_score: float | None = None


@lru_cache(maxsize=None)
def _load_ml_classifier(
    model_dir: str,
) -> tuple[PreTrainedTokenizerBase, PreTrainedModel] | tuple[None, None]:
    """Charge (et met en cache pour le process) le tokenizer et le modèle ML.

    Le cache évite de recharger les poids à chaque instanciation de InjectionDetector
    (utile en particulier pour la suite de tests, qui crée de nombreuses instances).
    """
    path = Path(model_dir)
    if not path.is_dir():
        logger.warning(
            "Modèle ML introuvable dans '%s' (lance scripts/train_injection_classifier.py "
            "pour l'entraîner) — bascule en mode regex uniquement.",
            model_dir,
        )
        return None, None

    try:
        tokenizer = AutoTokenizer.from_pretrained(model_dir)
        model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        model.eval()
        return tokenizer, model
    except Exception:
        logger.exception(
            "Échec du chargement du classifieur ML depuis '%s' — bascule en mode regex uniquement.",
            model_dir,
        )
        return None, None


class InjectionDetector:
    """Détecteur d'injection combinant règles regex et classifieur ML.

    Args:
        model_dir: répertoire du modèle fine-tuné (voir `train_injection_classifier.py`).
        ml_threshold: score ML à partir duquel une entrée est considérée comme injection.
    """

    def __init__(
        self,
        model_dir: Path | str = DEFAULT_MODEL_DIR,
        ml_threshold: float = DEFAULT_ML_THRESHOLD,
    ) -> None:
        self._ml_threshold = ml_threshold
        self._tokenizer, self._model = _load_ml_classifier(str(model_dir))

    @property
    def ml_available(self) -> bool:
        """Indique si la couche ML est active pour cette instance."""
        return self._model is not None

    def scan(self, text: str) -> ScanResult:
        """Scanne un texte et retourne le résultat combiné des deux couches."""
        matched_patterns = tuple(
            pattern for pattern in SUSPICIOUS_PATTERNS if re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        )
        regex_risk = min(1.0, len(matched_patterns) / 3)

        ml_score = self._ml_score(text)
        risk = regex_risk if ml_score is None else max(regex_risk, ml_score)
        flagged = bool(matched_patterns) or (ml_score is not None and ml_score >= self._ml_threshold)

        return ScanResult(risk=risk, flagged=flagged, matched_patterns=matched_patterns, ml_score=ml_score)

    def _ml_score(self, text: str) -> float | None:
        """Retourne la probabilité "injection" selon le classifieur ML, ou None si absent."""
        if self._tokenizer is None or self._model is None:
            return None

        try:
            inputs = self._tokenizer(
                text,
                truncation=True,
                max_length=ML_MAX_SEQ_LENGTH,
                return_tensors="pt",
            )
            with torch.no_grad():
                logits = self._model(**inputs).logits
            probabilities = torch.softmax(logits, dim=-1)
            return float(probabilities[0, ML_INJECTION_CLASS_INDEX])
        except Exception:
            logger.exception("Échec de l'inférence ML sur le texte scanné — score ML ignoré pour cet appel.")
            return None