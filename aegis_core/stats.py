"""
Intervalles de confiance sur les taux mesurés (correctif P1-M1).

Pourquoi un module pour ça
--------------------------
Le README annonçait « 100 % de blocage » et « 0 % de faux positifs ». Les deux
chiffres sont exacts. Ils sont aussi calculés sur **12 attaques et 10 contrôles**,
et c'est ce que la formulation cache.

Un taux mesuré sur un petit échantillon n'est pas une propriété du système :
c'est une estimation, et son incertitude est énorme à ces volumes. 12 succès sur
12 tirages sont parfaitement compatibles avec un système qui échouerait une fois
sur cinq -- il suffit de ne pas être tombé sur le mauvais cas.

    12/12  ->  100 %  [75,8 % ; 100 %]
     0/10  ->    0 %  [ 0 %   ; 27,8 %]

Ces deux lignes disent la vérité que « 100 % / 0 % » laisse croire fausse. Elles
disent aussi, sans qu'on ait à l'écrire, ce qui manque : du volume. C'est plus
utile qu'une note de bas de page, parce que l'intervalle rétrécit visiblement à
mesure que le corpus grandit -- il transforme « ajouter des payloads » en
progrès mesurable au lieu d'une corvée.

Pourquoi Wilson et pas la formule habituelle
--------------------------------------------
L'intervalle « normal » (p ± 1,96·√(p(1-p)/n)) donne [0 ; 0] pour 0/10 et
[100 % ; 100 %] pour 12/12 : à p=0 ou p=1 la variance estimée s'annule, et
l'intervalle affirme une certitude absolue précisément là où on n'en a aucune.
C'est le cas le plus fréquent dans ce projet, donc le pire choix possible.

L'intervalle de Wilson (1927) ne s'effondre pas aux bornes et reste correct à
petit n. Il n'a besoin d'aucune dépendance : c'est une formule fermée.

Ce que ça ne fait pas
---------------------
Un intervalle de confiance quantifie l'incertitude d'**échantillonnage** -- le
fait qu'on ait tiré 12 payloads plutôt que 12 autres. Il ne dit rien du biais de
sélection : si les 12 payloads ont été écrits en regardant les règles, l'intervalle
sera étroit et le chiffre restera faux. C'est un problème de corpus, pas de
statistique, et aucune formule ne le corrigera.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

# 1,959964 = quantile normal bilatéral à 95 %. En dur plutôt qu'importé de
# scipy : le noyau n'a pas à tirer une dépendance scientifique pour une constante.
Z_95 = 1.959963984540054


@dataclass(frozen=True)
class Proportion:
    """Un taux mesuré, avec ce qu'on sait vraiment de lui.

    `successes/total` est le fait observé ; `low/high` est ce que ce fait permet
    d'affirmer. Les publier ensemble est le minimum pour qu'un lecteur puisse
    juger si la mesure soutient la conclusion.
    """

    successes: int
    total: int
    low: float
    high: float
    confidence: float = 0.95

    @property
    def rate(self) -> float:
        return self.successes / self.total if self.total else 0.0

    @property
    def width(self) -> float:
        """Largeur de l'intervalle -- l'indicateur direct du manque de volume."""
        return self.high - self.low

    def as_dict(self) -> dict[str, object]:
        return {
            "rate": self.rate,
            "successes": self.successes,
            "total": self.total,
            "ci_low": self.low,
            "ci_high": self.high,
            "confidence": self.confidence,
        }

    def format(self, digits: int = 0) -> str:
        """« 100% [76%-100%] (12/12) » -- format retenu pour les rapports."""
        if not self.total:
            return "n/a (0 échantillon)"
        return (
            f"{self.rate:.{digits}%} [{self.low:.{digits}%}-{self.high:.{digits}%}] "
            f"({self.successes}/{self.total})"
        )

    def __str__(self) -> str:  # pragma: no cover - confort
        return self.format()


def wilson_interval(successes: int, total: int, z: float = Z_95) -> Proportion:
    """Intervalle de Wilson pour une proportion binomiale.

    Args:
        successes: nombre de cas positifs observés.
        total: nombre d'essais. `0` renvoie l'intervalle [0, 1] : sans mesure,
            on ne sait rien -- et c'est ce qu'il faut afficher, pas 0 %.

    Raises:
        ValueError: si les comptes sont incohérents. Un taux calculé sur des
            comptes faux serait plus dangereux qu'une absence de taux.
    """
    if successes < 0 or total < 0:
        raise ValueError("Les comptes ne peuvent pas être négatifs.")
    if successes > total:
        raise ValueError(f"{successes} succès pour {total} essais : incohérent.")
    if total == 0:
        return Proportion(0, 0, 0.0, 1.0)

    p = successes / total
    denominator = 1 + z**2 / total
    center = (p + z**2 / (2 * total)) / denominator
    margin = (z / denominator) * math.sqrt(p * (1 - p) / total + z**2 / (4 * total**2))
    return Proportion(
        successes=successes,
        total=total,
        low=max(0.0, center - margin),
        high=min(1.0, center + margin),
    )


def rate(successes: int, total: int) -> Proportion:
    """Alias lisible de `wilson_interval` sur le chemin d'appel courant."""
    return wilson_interval(successes, total)


def min_samples_for_lower_bound(target_low: float, max_failures: int = 0, cap: int = 100_000) -> int:
    """Combien d'essais parfaits pour que la BORNE BASSE dépasse `target_low`.

    C'est la question utile quand on mesure un taux proche de 1 : « 12/12 » ne
    garantit que 76 % ; combien de payloads faut-il pour garantir 80 % ? La
    formule normale ne répond pas (sa variance s'annule à p=1), on cherche donc
    directement le plus petit n dont l'intervalle de Wilson convient.

    `max_failures` permet de poser la question honnête : on ne restera pas à 0
    échec éternellement, et un corpus qui ne tolère aucun raté est un corpus qui
    fera rougir la CI au premier ajout.

    Retourne `cap` si aucun n raisonnable ne convient -- signe que la cible est
    hors de portée du protocole plutôt que du corpus.
    """
    if not 0 < target_low < 1:
        raise ValueError("target_low doit être dans ]0, 1[.")
    n = max(1, max_failures + 1)
    while n <= cap:
        if wilson_interval(n - max_failures, n).low >= target_low:
            return n
        n += 1
    return cap


def samples_needed_for_width(target_width: float, assumed_rate: float = 0.5) -> int:
    """Combien d'échantillons pour resserrer l'intervalle à `target_width`.

    Sert à répondre à la seule question qui compte une fois l'incertitude
    affichée : « combien il m'en faut ? ». `assumed_rate=0.5` est le cas le plus
    défavorable, donc une borne haute honnête.

    C'est une approximation normale, suffisante pour dimensionner un effort de
    collecte -- pas pour publier une garantie.
    """
    if not 0 < target_width <= 1:
        raise ValueError("target_width doit être dans ]0, 1].")
    half = target_width / 2
    return math.ceil((Z_95**2) * assumed_rate * (1 - assumed_rate) / half**2)
