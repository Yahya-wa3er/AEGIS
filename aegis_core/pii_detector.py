"""
Assainissement des documents récupérés : masquage des données personnelles et
secrets techniques (blueprint, section 4.5 - volet SentinelRAG, "assainissement
des documents à l'indexation").

Contrairement à `injection_detector.py` (qui cherche des INSTRUCTIONS cachées)
et `rag_outlier_detector.py` (qui cherche un document hors du domaine normal),
ce détecteur ne cherche pas une attaque -- il cherche des données qui n'ont
tout simplement rien à faire dans un contexte envoyé à un LLM tiers : un
document parfaitement légitime (une vraie note de support, un vrai contact
client) peut très bien contenir un email, un numéro de carte, une clé d'API
laissée par erreur. Le masquer n'est pas une question de confiance envers le
document, mais d'hygiène : moins il y a de données sensibles dans le contexte
qui transite vers un tiers (le LLM, potentiellement journalisé côté
fournisseur), moins la surface de fuite est grande.

Principe : uniquement des règles regex (comme la V0 de `injection_detector.py`)
-- rapide, déterministe, explicable, sans dépendance ML. Voir "Limites
connues" du README pour ce que cette approche ne couvre pas.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Chaque motif est associé à une étiquette utilisée à la fois comme texte de
# remplacement et pour le reporting (quel TYPE de donnée a été masqué).
PII_PATTERNS: tuple[tuple[str, str], ...] = (
    ("EMAIL", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    # IBAN : 2 lettres pays + 2 chiffres de contrôle + jusqu'à 30 caractères alphanumériques.
    ("IBAN", r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
    # Carte bancaire : 13 à 16 chiffres, groupés ou non par 4.
    ("CARTE_BANCAIRE", r"\b(?:\d[ -]?){13,16}\b"),
    # Téléphone français : 0X XX XX XX XX (espaces, points ou tirets en séparateur, ou aucun).
    ("TELEPHONE", r"\b0[1-9](?:[ .-]?\d{2}){4}\b"),
    # Clés d'API courantes (OpenAI/OpenRouter sk-..., AWS AKIA..., tokens génériques longs).
    ("CLE_API", r"\b(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|(?:api|secret)[_-]?key[\"'\s:=]+[a-zA-Z0-9/+]{20,})\b"),
)


@dataclass(frozen=True)
class RedactionResult:
    """Résultat d'un passage d'assainissement sur un texte.

    `redacted_text` vaut `text` inchangé quand rien n'a été trouvé -- on peut
    donc toujours utiliser `redacted_text` sans tester `redacted` au préalable.
    """

    redacted_text: str
    redacted: bool
    categories: tuple[str, ...] = field(default_factory=tuple)
    count: int = 0


class PiiDetector:
    """Masque les données personnelles/secrets détectés dans un texte, par regex."""

    def scan(self, text: str) -> RedactionResult:
        """Masque toutes les occurrences trouvées et retourne le texte assaini
        ainsi qu'un résumé de ce qui a été masqué (pour le journal d'audit)."""
        categories_hit: list[str] = []
        total = 0
        redacted_text = text

        for label, pattern in PII_PATTERNS:
            redacted_text, n = re.subn(pattern, f"[{label}_MASQUÉ]", redacted_text)
            if n > 0:
                categories_hit.append(label)
                total += n

        return RedactionResult(
            redacted_text=redacted_text,
            redacted=total > 0,
            categories=tuple(categories_hit),
            count=total,
        )
