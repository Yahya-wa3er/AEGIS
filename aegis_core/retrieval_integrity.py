"""
Intégrité du classement : détecter un document écrit pour *être récupéré*
(correctif issu du lot 6, volet OWASP LLM09).

Le problème
-----------
Un attaquant qui ne contrôle que le contenu d'un document contrôle aussi sa
sélection : il suffit d'y bourrer du vocabulaire du domaine pour remonter en
tête sur n'importe quelle requête. AEGIS neutralise ensuite le document, donc
l'injection ne passe pas -- mais l'attaquant a gagné le droit d'**occuper tout
le contexte** de l'agent, évinçant les documents légitimes. C'est un déni de
service sur la pertinence, et aucune des cinq couches existantes ne le voyait.

La régularité qu'on exploite
----------------------------
Le langage naturel a une redondance caractéristique : les articles, les
prépositions, les mots du sujet reviennent. Le rapport type/token (TTR = mots
distincts / mots au total) d'une prose française réelle tient dans une bande
étroite, et un texte fabriqué pour le classement en sort -- dans un sens ou
dans l'autre :

* **bourrage en profondeur** (répéter les mots de la requête) fait chuter le TTR
  bien en dessous de la bande ;
* **bourrage en largeur** (empiler des mots tous différents) le pousse vers 1,0,
  ce qu'aucune prose n'atteint.

Le TTR dépend fortement de la longueur (loi de Heaps) : un extrait de 60 mots a
mécaniquement un TTR plus haut qu'un extrait de 800. La bande est donc
**interpolée par longueur**, à partir des percentiles 5 et 95 mesurés sur la
prose française réelle du dépôt (README et documents du corpus : 10 281 mots de prose, 200 fenêtres par taille).
Une bande constante aurait signalé tout document long.

Ce que ça ne détecte pas -- et c'est mesuré, pas supposé
--------------------------------------------------------
Un attaquant qui connaît ce contrôle le contourne en mélangeant les deux
techniques : assez de répétitions pour gagner le classement, assez de termes
nouveaux pour rester dans la bande. Mesuré sur l'attaque « hybride » :
**TTR = 0,530 pour 432 mots**, quand la prose réelle de même longueur va de
0,356 à 0,653. Le document est rigoureusement indistinguable.

Ce signal attrape donc les bourrages naïfs, pas un adversaire qui l'a lu. Il est
livré comme **consultatif** pour cette raison, et `tests/test_retrieval_integrity.py`
fige explicitement l'évasion : le jour où quelqu'un annonce l'avoir corrigée, le
test dira le contraire.

La vraie défense n'est pas statistique : c'est de faire en sorte que gagner le
classement ne donne pas tout le contexte (voir `MAX_SHARE_PER_DOCUMENT` dans
`victim/agent.py` et la note LLM09 du README).
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable

# Tokenizer AUTONOME, volontairement dupliqué de `victim/rag.py`.
#
# Le détecteur doit compter les mêmes mots que le classement, sinon il mesure
# autre chose que ce qui décide de la sélection. Mais `aegis_core` ne peut pas
# importer `victim` : le noyau est distribué seul (voir pyproject.toml), et la
# promesse « branchable sur n'importe quel orchestrateur » interdit une
# dépendance vers l'agent de démonstration.
#
# La duplication est donc assumée, et la dérive est empêchée par un test de
# parité sur le corpus complet -- même dispositif que la vérification
# scikit-learn ↔ inférence du détecteur d'outliers.
_TOKEN_RE = re.compile(r"[a-z0-9àâäéèêëïîôöùûüçñ]+")


def tokenize(text: str) -> list[str]:
    """Mots en minuscules, répétitions comprises."""
    return _TOKEN_RE.findall(text.lower())

# Enveloppe du TTR de la prose française réelle, par longueur en mots.
# Mesure : 60 fenêtres aléatoires par taille sur le français du dépôt (README,
# docstrings), percentiles 5 et 95, puis marge de 0,05 de chaque côté pour ne
# pas transformer une queue de distribution en alerte.
#
# Reproduire : scripts/measure_ttr_envelope.py
_TTR_ENVELOPE: tuple[tuple[int, float, float], ...] = (
    #  n     bas    haut
    (60  , 0.667, 0.950),
    (100 , 0.610, 0.890),
    (150 , 0.583, 0.830),
    (250 , 0.530, 0.762),
    (450 , 0.470, 0.679),
    (800 , 0.415, 0.601),
)

# En dessous de ce nombre de mots, le TTR n'est plus informatif : une phrase de
# dix mots a presque toujours un TTR de 1. Signaler là-dessus produirait un
# faux positif à chaque document court, c'est-à-dire tout le temps.
MIN_TOKENS = 40


@dataclass(frozen=True)
class StuffingScanResult:
    """Verdict sur la fabrication d'un document pour le classement."""

    flagged: bool
    reason: str | None
    ttr: float
    tokens: int
    expected_low: float
    expected_high: float

    def as_dict(self) -> dict[str, object]:
        return {
            "flagged": self.flagged,
            "reason": self.reason,
            "ttr": round(self.ttr, 4),
            "tokens": self.tokens,
            "expected_range": [self.expected_low, self.expected_high],
        }


def _bounds(n_tokens: int) -> tuple[float, float]:
    """Bande attendue à cette longueur, par interpolation linéaire."""
    points = _TTR_ENVELOPE
    if n_tokens <= points[0][0]:
        return points[0][1], points[0][2]
    if n_tokens >= points[-1][0]:
        return points[-1][1], points[-1][2]
    for (n0, lo0, hi0), (n1, lo1, hi1) in zip(points, points[1:]):
        if n0 <= n_tokens <= n1:
            t = (n_tokens - n0) / (n1 - n0)
            return lo0 + t * (lo1 - lo0), hi0 + t * (hi1 - hi0)
    return points[-1][1], points[-1][2]  # pragma: no cover - inatteignable


class RetrievalStuffingDetector:
    """Signale un document dont la redondance lexicale n'est pas celle d'un texte.

    Déterministe, sans dépendance, sans modèle à entraîner -- au même titre que
    les règles d'injection, et pour la même raison : ce qu'on peut décider par
    une statistique explicable, on ne l'apprend pas.
    """

    def __init__(self, min_tokens: int = MIN_TOKENS):
        self.min_tokens = min_tokens

    def scan(self, text: str, tokenizer: Callable[[str], list[str]] = tokenize) -> StuffingScanResult:
        """`tokenizer` est surchargeable : une intégration dont le moteur de
        recherche découpe autrement doit pouvoir mesurer sur SES mots."""
        tokens = tokenizer(text)
        n = len(tokens)
        if n < self.min_tokens:
            return StuffingScanResult(False, None, 1.0 if not n else len(set(tokens)) / n, n, 0.0, 1.0)

        ttr = len(set(tokens)) / n
        low, high = _bounds(n)

        if ttr < low:
            return StuffingScanResult(
                True,
                f"redondance anormalement élevée (TTR {ttr:.3f} < {low:.3f}) : "
                "le document répète un petit vocabulaire, motif typique d'un bourrage "
                "destiné à gagner le classement",
                ttr, n, low, high,
            )
        if ttr > high:
            return StuffingScanResult(
                True,
                f"redondance anormalement faible (TTR {ttr:.3f} > {high:.3f}) : "
                "presque aucun mot ne se répète, ce qu'aucune prose ne fait -- "
                "signature d'un empilement de termes",
                ttr, n, low, high,
            )
        return StuffingScanResult(False, None, ttr, n, low, high)


def repetition_profile(text: str, tokenizer: Callable[[str], list[str]] = tokenize, top: int = 5) -> list[tuple[str, int]]:
    """Mots les plus répétés -- pour montrer à l'opérateur *ce qui* a été bourré.

    Un score sans explication n'aide personne à décider : c'est la même exigence
    que `matched_rules` pour les règles d'injection.
    """
    return Counter(tokenizer(text)).most_common(top)
