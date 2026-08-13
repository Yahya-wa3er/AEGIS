"""Détection d'injection de prompt — défense en profondeur (regex + ML).

Deux couches indépendantes, combinées par un OR sur le flag et un MAX sur le score
de risque :

1. Règles regex (V0) : rapides, déterministes, explicables — couvrent les patterns
   d'attaque connus, en **français et en anglais**, appliquées à un texte
   préalablement **normalisé** (voir `aegis_core/normalization.py`).
2. Classifieur ML (Phase 2) : DistilBERT fine-tuné sur `deepset/prompt-injections`
   (voir `scripts/train_injection_classifier.py`) — généralise à des formulations
   jamais vues, que le regex ne peut pas anticiper par construction.

Principe de fail-open (assumé, pas subi -- voir aegis_core/config.py) : si le
modèle ML n'est pas disponible (pas encore entraîné,
fichiers absents, erreur de chargement), le détecteur bascule silencieusement en
mode regex uniquement plutôt que de planter — un log WARNING signale la dégradation.

Correctifs P0-3a et P1-8
------------------------
**Les règles étaient francophones.** `IGNORE ALL PREVIOUS INSTRUCTIONS` -- la
chaîne d'attaque la plus canonique du domaine, et un payload du corpus de
red-teaming du projet -- n'était pas détectée. Les règles couvrent désormais les
deux langues, et chaque règle porte un identifiant préfixé par sa langue.

**Le texte brut était comparé tel quel.** Dix contournements mesurés, dix succès
(largeur nulle, homoglyphes, pleine chasse, espacement, leet, base64...). Chaque
règle est maintenant évaluée sur plusieurs *vues* normalisées du document, ce qui
ramène toutes ces écritures à une forme unique. Quand une règle ne se déclenche
que sur une vue dérivée, une méta-règle d'évasion est ajoutée : dissimuler une
instruction est en soi un signal, et souvent plus fort que l'instruction.

**La couche ML ne voyait que les 256 premiers tokens.** Il suffisait de placer
2 000 tokens de texte anodin avant l'injection. Le score ML est désormais le
maximum sur des fenêtres glissantes qui se recouvrent.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer, PreTrainedModel, PreTrainedTokenizerBase

from aegis_core.normalization import views

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = Path("models/injection_classifier")
DEFAULT_ML_THRESHOLD = 0.5
ML_MAX_SEQ_LENGTH = 256
# Fenêtres glissantes pour la couche ML (correctif P1-8). ~1000 caractères tient
# largement dans 256 tokens ; le recouvrement évite qu'une injection coupée en
# deux échappe aux deux fenêtres. Le nombre de fenêtres est borné pour qu'un
# document très long ne se transforme pas en déni de service.
ML_WINDOW_CHARS = 1000
ML_WINDOW_OVERLAP = 250
ML_MAX_WINDOWS = 16
# Borne du texte réellement analysé par les règles. `MAX_DOCUMENT_CHARS` existait
# côté API mais PAS sur le chemin de production (`on_retrieval`) : un document de
# 10 Mo y passait intégralement.
MAX_SCAN_CHARS = 100_000
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
    # --- Neutralisation des instructions en place ---
    Rule("fr.ignore_previous",
         r"(ignor\w*|oubli\w*|fais\s+abstraction\s+d\w*)\s+(de\s+)?(toutes?\s+)?(les?\s+|ces\s+|tes\s+)?"
         r"(instructions?|consignes?|directives?|r[eè]gles?)\s*(pr[ée]c[ée]dentes?|ant[ée]rieures?|ci-dessus)?",
         "Demande d'ignorer les instructions précédentes"),
    Rule("en.ignore_previous",
         r"(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+)?(the\s+|your\s+|previous\s+|prior\s+|above\s+)*"
         r"(instructions?|prompts?|rules?|directives?|guidelines?)",
         "Demande d'ignorer les instructions précédentes (anglais)"),

    # --- Fausse autorité système ---
    Rule("any.system_override", r"system\s*(override|prompt\s*override)|<\s*\|?\s*(system|im_start)\s*\|?\s*>",
         "Prétendue directive système prioritaire"),
    Rule("en.new_instructions", r"(new|updated|revised)\s+(system\s+)?(instructions?|prompt)\s*[:.]",
         "Prétendues nouvelles instructions système (anglais)"),
    Rule("fr.new_instructions", r"nouvelles?\s+(instructions?|consignes?)\s*[:.]",
         "Prétendues nouvelles instructions système"),

    # --- Changement de rôle ---
    Rule("fr.mode_switch", r"tu\s+es\s+(maintenant|d[ée]sormais)\s+(en\s+mode|un\s+|une\s+)",
         "Tentative de changement de rôle ou de mode"),
    Rule("en.mode_switch",
         r"you\s+are\s+now\s+(in\s+\w+\s+mode|a\s+|an\s+)|(enter|enable|activate)\s+(developer|admin\w*|god|dan)\s+mode"
         r"|act\s+as\s+(if\s+you\s+are\s+)?(a|an|the)\s+",
         "Tentative de changement de rôle ou de mode (anglais)"),

    # --- Injonction d'agir ---
    Rule("fr.forced_tool_call",
         r"tu\s+(dois|devras)\s+(imm[ée]diatement\s+)?(appeler|ex[ée]cuter|utiliser|lancer)"
         r"|appelle\s+(imm[ée]diatement\s+)?l['\s]outil",
         "Injonction d'appeler un outil immédiatement"),
    Rule("en.forced_tool_call",
         r"you\s+must\s+(now\s+)?(immediately\s+)?(call|invoke|execute|run|use)\s+|immediately\s+(call|invoke|execute)\s+",
         "Injonction d'appeler un outil immédiatement (anglais)"),

    # --- Exfiltration de configuration ---
    Rule("en.reveal_system", r"(reveal|show|print|repeat|output|dump)\s+(me\s+)?(the\s+|your\s+|all\s+)*"
                             r"(system\s+prompt|initial\s+instructions?|api\s+keys?|secrets?|credentials?)",
         "Demande de divulguer le prompt système ou des secrets (anglais)"),
    Rule("fr.reveal_system", r"(r[ée]v[èe]le|affiche|montre|donne)[\w\s]{0,20}"
                             r"(prompt\s+syst[èe]me|instructions?\s+initiales?|cl[ée]s?\s+d['\s]api|secrets?)",
         "Demande de divulguer le prompt système ou des secrets"),

    # --- Dissimulation ---
    Rule("fr.conceal_instruction",
         r"ne\s+(mentionne|parle|dis|r[ée]v[èe]le)\s+(jamais|pas|surtout\s+pas)\s+"
         r"[\w\s']{0,30}(cette\s+)?(instruction|proc[ée]dure|consigne|message)",
         "Demande de dissimuler l'instruction à l'utilisateur"),
    Rule("en.conceal_instruction",
         r"(do\s+not|don't|never)\s+(mention|reveal|tell|disclose|show)\s+"
         r"[\w\s]{0,30}(this|these)\s+(instruction|message|prompt|to\s+the\s+user)",
         "Demande de dissimuler l'instruction à l'utilisateur (anglais)"),
)

# Méta-règles : elles ne cherchent pas un motif, elles décrivent COMMENT une
# règle a été trouvée. Dissimuler une instruction est un signal en soi -- souvent
# plus fort que l'instruction elle-même, car le texte anodin ne s'obfusque pas.
# Elles sont hors de `RULES` : leur `pattern` est vide et ne doit jamais être
# passé à `re.search` (une chaîne vide matche tout).
META_RULES: tuple[Rule, ...] = (
    Rule("evasion.hidden_in_markup", "",
         "Instruction dissimulée dans un commentaire de balisage"),
    Rule("evasion.encoded_payload", "",
         "Instruction dissimulée dans un bloc encodé (base64)"),
    Rule("evasion.obfuscated_text", "",
         "Texte obfusqué : homoglyphes, caractères invisibles, espacement ou leet"),
)

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in RULES}
ALL_RULES_BY_ID: dict[str, Rule] = {**RULES_BY_ID, **{rule.id: rule for rule in META_RULES}}

_COMPILED: dict[str, re.Pattern[str]] = {
    rule.id: re.compile(rule.pattern, re.IGNORECASE | re.DOTALL) for rule in RULES
}

# La vue d'où provient un match détermine la méta-règle d'évasion associée.
_EVASION_BY_VIEW: dict[str, str] = {
    "commentaire": "evasion.hidden_in_markup",
    "base64": "evasion.encoded_payload",
    "leet": "evasion.obfuscated_text",
}

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
    # True si le document a dû être tronqué avant analyse. Ne pas le dire
    # reviendrait à laisser croire que tout a été scanné.
    truncated: bool = False

    @property
    def matched_descriptions(self) -> tuple[str, ...]:
        """Libellés lisibles des règles déclenchées, pour affichage humain."""
        return tuple(ALL_RULES_BY_ID[rule_id].description for rule_id in self.matched_rules if rule_id in ALL_RULES_BY_ID)


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
        """Scanne un texte et retourne le résultat combiné des deux couches.

        Les règles sont évaluées sur chaque *vue* du document (forme canonique,
        contenu des commentaires, blocs base64 décodés, variante dé-leetée). Une
        règle qui ne se déclenche que sur une vue dérivée ajoute une méta-règle
        d'évasion : le fait qu'une instruction ait été dissimulée est un signal
        distinct, et souvent plus fiable que l'instruction elle-même -- un texte
        anodin ne s'obfusque pas.
        """
        truncated = len(text) > MAX_SCAN_CHARS
        if truncated:
            logger.warning(
                "Document tronqué à %d caractères avant analyse (taille reçue : %d).",
                MAX_SCAN_CHARS, len(text),
            )
            text = text[:MAX_SCAN_CHARS]

        # Ce qui matche sur le texte BRUT : sert de référence pour savoir si la
        # normalisation a été ce qui a révélé l'instruction.
        raw_hits = {rule_id for rule_id, pattern in _COMPILED.items() if pattern.search(text)}

        # On retient TOUTES les vues où chaque règle a matché, pas seulement la
        # première : une instruction peut être à la fois lisible dans le texte
        # canonique ET cachée dans un commentaire. Le second fait est un signal
        # à part entière, qu'un « on s'arrête au premier match » ferait perdre.
        hit_views: dict[str, set[str]] = {}
        for view in views(text):
            for rule_id, pattern in _COMPILED.items():
                if pattern.search(view.text):
                    hit_views.setdefault(rule_id, set()).add(view.name)

        evasions: set[str] = set()
        for rule_id, view_names in hit_views.items():
            for view_name in view_names:
                if view_name in _EVASION_BY_VIEW:
                    evasions.add(_EVASION_BY_VIEW[view_name])
            if "canonique" in view_names and rule_id not in raw_hits:
                # La règle n'a matché qu'APRÈS normalisation : le texte d'origine
                # portait des homoglyphes, de l'invisible ou de l'espacement.
                evasions.add("evasion.obfuscated_text")

        matched_rules = tuple(sorted(hit_views) + sorted(evasions))
        regex_risk = min(1.0, len(matched_rules) / 3)

        ml_score = self._ml_score(text)
        risk = regex_risk if ml_score is None else max(regex_risk, ml_score)
        flagged = bool(matched_rules) or (ml_score is not None and ml_score >= self._ml_threshold)

        return ScanResult(
            risk=risk, flagged=flagged, matched_rules=matched_rules,
            ml_score=ml_score, truncated=truncated,
        )

    @staticmethod
    def _windows(text: str) -> list[str]:
        """Découpe le texte en fenêtres qui se recouvrent (correctif P1-8).

        Sans ça, la couche ML ne voyait que les 256 premiers tokens : il suffisait
        de faire précéder l'injection de deux pages de texte anodin. Le
        recouvrement garantit qu'une phrase à cheval sur deux fenêtres apparaît
        entière dans au moins une.
        """
        if len(text) <= ML_WINDOW_CHARS:
            return [text]
        step = ML_WINDOW_CHARS - ML_WINDOW_OVERLAP
        windows = [text[i:i + ML_WINDOW_CHARS] for i in range(0, len(text), step)]
        if len(windows) > ML_MAX_WINDOWS:
            logger.warning(
                "Document trop long pour un balayage ML complet : %d fenêtres réduites à %d. "
                "La fin du document n'est pas couverte par la couche ML.",
                len(windows), ML_MAX_WINDOWS,
            )
            windows = windows[:ML_MAX_WINDOWS]
        return windows

    def _ml_score(self, text: str) -> float | None:
        """Probabilité maximale d'injection sur les fenêtres du document, ou None.

        On prend le MAX et non la moyenne : une injection de deux lignes noyée
        dans dix pages anodines doit remonter, pas être diluée.
        """
        if self._tokenizer is None or self._model is None:
            return None

        scores = [s for s in (self._score_window(w) for w in self._windows(text)) if s is not None]
        return max(scores) if scores else None

    def _score_window(self, text: str) -> float | None:
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