"""Détection d'injection de prompt — défense en profondeur (regex + ML).

Deux couches indépendantes, combinées par un OR sur le flag et un MAX sur le score
de risque :

1. Règles regex (V0) : rapides, déterministes, explicables — couvrent les patterns
   d'attaque connus (ex. "ignore les instructions précédentes", "system override").
2. Classifieur ML (Phase 2) : DistilBERT fine-tuné sur `deepset/prompt-injections`
   (voir `scripts/train_injection_classifier.py`) — généralise à des formulations
   jamais vues, que le regex ne peut pas anticiper par construction.

Principe de fail-open (assumé, pas subi -- voir aegis_core/config.py) : si le
modèle ML n'est pas disponible (pas encore entraîné,
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

@dataclass(frozen=True)
class Rule:
    """Une règle de détection, identifiée par un `id` stable.

    Pourquoi un identifiant plutôt que le motif lui-même (correctif P1-9e) :
    l'ancienne version journalisait les expressions régulières brutes dans
    `matched_patterns`, et `web/app.py` renvoie les entrées du journal au
    frontend. **N'importe quel visiteur de la démo pouvait donc lire l'intégralité
    des règles de détection**, et formuler son attaque en dehors -- ce que l'audit
    a montré être trivial.

    Un identifiant dit à l'opérateur *ce qui* a été reconnu sans dire à
    l'attaquant *comment*. La `description` est destinée à l'affichage humain ;
    le `pattern` ne quitte jamais ce module.
    """

    id: str
    pattern: str
    description: str


RULES: tuple[Rule, ...] = (
    Rule("fr.ignore_previous", r"ignore\s+(toutes\s+)?les?\s+instructions?\s+pr[ée]c[ée]dentes?",
         "Demande d'ignorer les instructions précédentes"),
    Rule("any.system_override", r"system\s*override",
         "Prétendue directive système prioritaire"),
    Rule("fr.mode_switch", r"tu\s+es\s+maintenant\s+en\s+mode",
         "Tentative de changement de rôle ou de mode"),
    Rule("fr.forced_tool_call", r"tu\s+dois\s+imm[ée]diatement\s+appeler",
         "Injonction d'appeler un outil immédiatement"),
    Rule("fr.conceal_instruction", r"ne\s+mentionne\s+(jamais|pas)\s+cette\s+instruction",
         "Demande de dissimuler l'instruction à l'utilisateur"),
    Rule("markup.html_comment", r"<!--.*-->",
         "Instruction cachée dans un commentaire HTML"),
)

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in RULES}

# Conservé pour la compatibilité des scripts qui inspectaient les motifs bruts.
SUSPICIOUS_PATTERNS: tuple[str, ...] = tuple(rule.pattern for rule in RULES)


@dataclass(frozen=True)
class ScanResult:
    """Résultat d'un scan, combinant les deux couches de détection.

    `ml_score` vaut `None` quand le classifieur ML n'était pas disponible au moment
    du scan — cela permet de distinguer "le ML n'a rien détecté" (score bas) de
    "le ML n'a pas tourné" (score absent), utile pour le reporting de robustesse.
    """

    risk: float
    flagged: bool
    # Identifiants de règles (ex. "fr.ignore_previous"), JAMAIS les motifs bruts :
    # ces valeurs traversent le journal d'audit puis l'API publique (voir `Rule`).
    matched_rules: tuple[str, ...] = field(default_factory=tuple)
    ml_score: float | None = None

    @property
    def matched_descriptions(self) -> tuple[str, ...]:
        """Libellés lisibles des règles déclenchées, pour affichage humain."""
        return tuple(RULES_BY_ID[rule_id].description for rule_id in self.matched_rules if rule_id in RULES_BY_ID)


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
        matched_rules = tuple(
            rule.id for rule in RULES if re.search(rule.pattern, text, re.IGNORECASE | re.DOTALL)
        )
        regex_risk = min(1.0, len(matched_rules) / 3)

        ml_score = self._ml_score(text)
        risk = regex_risk if ml_score is None else max(regex_risk, ml_score)
        flagged = bool(matched_rules) or (ml_score is not None and ml_score >= self._ml_threshold)

        return ScanResult(risk=risk, flagged=flagged, matched_rules=matched_rules, ml_score=ml_score)

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