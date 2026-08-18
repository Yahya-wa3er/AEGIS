"""
Dérive : comparer ce que le détecteur voit à ce sur quoi il a été calibré.

L'honnêteté d'abord
-------------------
Un module de « détection de dérive » est facile à mettre en scène et difficile à
faire dire quelque chose. Ce dépôt n'a **aucun trafic de production** : personne
n'a jamais branché AEGIS sur un vrai flux d'agent. Publier une courbe de dérive
dans ces conditions serait exactement le genre de chiffre décoratif que le projet
passe son temps à débusquer ailleurs.

Ce module fait donc une chose, précisément, et le dit :

    il compare la distribution des scores RÉELLEMENT observés depuis le
    démarrage du processus à la distribution des scores mesurée sur le jeu de
    calibration, et il refuse de conclure tant qu'il n'a pas assez d'observations.

Pourquoi c'est utile quand même
--------------------------------
Le seuil d'un détecteur n'a de sens que sur la distribution qui a servi à le
calibrer. Déployé sur un autre domaine — un corpus juridique là où on a calibré
sur des tickets de support — le même seuil produit un tout autre taux de faux
positifs, sans qu'aucune erreur ne soit visible : le système continue de tourner,
il se trompe simplement plus souvent. C'est le mode de défaillance silencieux le
plus courant en apprentissage automatique, et le seul signal disponible est ce
décalage de distribution.

La règle du dépôt s'applique ici comme ailleurs : **pas de verdict sans effectif
suffisant**. En dessous de `MIN_OBSERVATIONS`, le rapport dit « je n'ai pas assez
vu », pas « rien à signaler ».

Ce que ça ne fait pas
---------------------
* Ce n'est pas un test statistique de dérive (Kolmogorov-Smirnov, Population
  Stability Index). C'est une comparaison de quantiles, lisible et sans
  dépendance, qui donne un ordre de grandeur — pas une p-valeur.
* L'état vit en mémoire du processus, comme les compteurs de LLM06 : un
  redémarrage remet le compteur à zéro et plusieurs répliques observent chacune
  leur part du trafic.
* Aucun seuil d'alerte n'est proposé. Il faudrait pour cela savoir quel décalage
  est tolérable, et ça ne se décide pas sans données de production.
"""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field

# En dessous, un décalage de quantiles n'est que du bruit d'échantillonnage.
# Le chiffre est un ordre de grandeur assumé, pas un résultat : il dit
# simplement qu'on ne prétend rien conclure sur une poignée d'observations.
MIN_OBSERVATIONS = 50

# Fenêtre glissante bornée : l'état d'observation ne doit pas croître avec le
# trafic, sinon on rejoue le défaut d'état non borné corrigé au lot 4B.
FENETRE_MAX = 2_000

QUANTILES = (0.5, 0.9, 0.99)


def quantile(valeurs: list[float], q: float) -> float:
    """Quantile par interpolation linéaire, sans dépendance à numpy.

    `aegis_core` doit rester importable sans la pile ML (voir la séparation
    requirements.txt / requirements-ml.txt, vérifiée en CI). Réimporter numpy
    ici pour trois quantiles casserait cette promesse.
    """
    if not valeurs:
        raise ValueError("quantile sur une liste vide")
    triees = sorted(valeurs)
    if len(triees) == 1:
        return triees[0]
    position = q * (len(triees) - 1)
    bas = int(position)
    haut = min(bas + 1, len(triees) - 1)
    poids = position - bas
    return triees[bas] * (1 - poids) + triees[haut] * poids


@dataclass(frozen=True)
class DriftReport:
    signal: str
    observations: int
    suffisant: bool
    reference: dict[str, float]
    observe: dict[str, float]
    ecarts: dict[str, float]
    commentaire: str

    def as_dict(self) -> dict[str, object]:
        return {
            "signal": self.signal,
            "observations": self.observations,
            "suffisant": self.suffisant,
            "reference": self.reference,
            "observe": self.observe,
            "ecarts": self.ecarts,
            "commentaire": self.commentaire,
        }


@dataclass
class ScoreObserver:
    """Fenêtre bornée des scores observés, comparée à une référence.

    `reference` est la distribution mesurée à la calibration (quantiles écrits
    dans `metrics.json` par le script d'entraînement). Absente, l'observateur
    collecte quand même : savoir ce que le détecteur voit reste utile, on ne
    peut simplement pas dire si c'est différent d'avant.
    """

    signal: str
    reference: dict[str, float] | None = None
    fenetre_max: int = FENETRE_MAX
    min_observations: int = MIN_OBSERVATIONS
    _valeurs: deque[float] = field(default_factory=deque)
    _vus: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def observe(self, score: float) -> None:
        with self._lock:
            self._vus += 1
            self._valeurs.append(float(score))
            while len(self._valeurs) > self.fenetre_max:
                self._valeurs.popleft()

    def report(self) -> DriftReport:
        with self._lock:
            valeurs = list(self._valeurs)
            vus = self._vus

        if len(valeurs) < self.min_observations:
            return DriftReport(
                signal=self.signal,
                observations=vus,
                suffisant=False,
                reference=dict(self.reference or {}),
                observe={},
                ecarts={},
                commentaire=(
                    f"{vus} observation(s) : trop peu pour comparer des quantiles. "
                    f"Il en faut au moins {self.min_observations}. « Pas assez vu » "
                    "n'est pas « rien à signaler »."
                ),
            )

        observe = {f"q{int(q * 100)}": quantile(valeurs, q) for q in QUANTILES}
        if not self.reference:
            return DriftReport(
                signal=self.signal,
                observations=vus,
                suffisant=True,
                reference={},
                observe=observe,
                ecarts={},
                commentaire=(
                    "Aucune distribution de référence enregistrée pour ce signal : on "
                    "sait ce que le détecteur voit, pas si ça a changé. La référence est "
                    "écrite par le script d'entraînement dans metrics.json."
                ),
            )

        ecarts = {
            cle: observe[cle] - self.reference[cle]
            for cle in observe
            if cle in self.reference
        }
        pire = max(ecarts.items(), key=lambda kv: abs(kv[1]), default=None)
        detail = (
            f"écart maximal sur {pire[0]} : {pire[1]:+.3f}"
            if pire is not None
            else "aucun quantile commun avec la référence"
        )
        return DriftReport(
            signal=self.signal,
            observations=vus,
            suffisant=True,
            reference=dict(self.reference),
            observe=observe,
            ecarts=ecarts,
            commentaire=(
                f"{detail}. Comparaison de quantiles, pas un test statistique : elle "
                "donne un ordre de grandeur, pas une p-valeur. Aucun seuil d'alerte "
                "n'est proposé — il faudrait des données de production pour savoir "
                "quel décalage est tolérable, et il n'y en a pas."
            ),
        )
