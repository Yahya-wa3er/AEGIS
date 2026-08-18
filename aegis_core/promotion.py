"""
Porte de promotion : « ce modèle est meilleur » est une affirmation qui se prouve.

Le problème que ça règle
------------------------
Un projet de ML qui n'a pas de règle de promotion en a une quand même, implicite,
et c'est toujours la même : *le nouveau chiffre est plus grand, donc on garde le
nouveau modèle*. Sur des effectifs comme ceux de ce dépôt, c'est un tirage à pile
ou face présenté comme un progrès. Passer de 12/14 à 13/14 de rappel fait monter
le point de 86 % à 93 % — et les deux intervalles de Wilson se recouvrent
largement. On n'a rien démontré du tout.

La règle appliquée ici est celle du lot 5A, transposée du constat isolé au cycle
de vie :

* **Régression prouvée** — les intervalles sont disjoints dans le mauvais sens.
  La promotion est **refusée**. C'est le seul cas bloquant, et il est bloquant
  sans discussion.
* **Amélioration prouvée** — intervalles disjoints dans le bon sens. Promotion
  acceptée, et l'affirmation « c'est mieux » est soutenue.
* **Indécidable** — les intervalles se recouvrent. La promotion est autorisée
  (rien ne prouve que c'est pire), mais le rapport interdit d'écrire que c'est
  mieux, et il dit **combien d'échantillons il faudrait** pour trancher.

Une subtilité statistique qu'il faut écrire
--------------------------------------------
Comparer deux intervalles de confiance par recouvrement est un test
**conservateur**, pas un test exact. L'implication ne va que dans un sens :

* intervalles **disjoints** ⟹ différence significative (au seuil considéré) ;
* intervalles qui **se recouvrent** ⟹ on ne peut rien conclure — et surtout
  **pas** « il n'y a pas de différence ». Deux intervalles à 95 % peuvent se
  recouvrir alors qu'un test exact de comparaison de proportions rejetterait
  l'égalité.

Ce choix est délibéré. Un test exact (deux proportions, ou un test de score)
détecterait plus de vraies différences, au prix de plus de fausses alertes sur
de petits effectifs. Ici, le coût d'une promotion injustifiée — publier « 92 % »
et le voir s'effondrer sur d'autres données — est supérieur au coût d'une
promotion manquée. La conséquence assumée est qu'à ces volumes, presque tout est
« indécidable » : ce n'est pas un défaut de la règle, c'est ce que disent
réellement les données, et le rapport le dit au lieu de le masquer.
"""
from __future__ import annotations

from dataclasses import dataclass

from aegis_core.model_registry import MetricEntry, ModelCard
from aegis_core.stats import samples_needed_for_width

PLUS_HAUT = "plus_haut_est_mieux"
PLUS_BAS = "plus_bas_est_mieux"

AMELIORATION = "amélioration prouvée"
REGRESSION = "régression prouvée"
INDECIDABLE = "indécidable"
NOUVEAU = "nouvelle métrique"


@dataclass(frozen=True)
class Comparaison:
    """Verdict sur UNE métrique, entre le modèle en place et le candidat."""

    metrique: str
    statut: str
    incumbent: str | None
    candidat: str
    explication: str
    echantillons_pour_trancher: int | None = None

    @property
    def bloquant(self) -> bool:
        return self.statut == REGRESSION

    def as_dict(self) -> dict[str, object]:
        return {
            "metrique": self.metrique,
            "statut": self.statut,
            "incumbent": self.incumbent,
            "candidat": self.candidat,
            "explication": self.explication,
            "echantillons_pour_trancher": self.echantillons_pour_trancher,
        }


@dataclass(frozen=True)
class RapportPromotion:
    modele: str
    comparaisons: tuple[Comparaison, ...]
    premiere_publication: bool = False

    @property
    def autorisee(self) -> bool:
        return not any(c.bloquant for c in self.comparaisons)

    @property
    def ameliorations(self) -> tuple[Comparaison, ...]:
        return tuple(c for c in self.comparaisons if c.statut == AMELIORATION)

    @property
    def regressions(self) -> tuple[Comparaison, ...]:
        return tuple(c for c in self.comparaisons if c.statut == REGRESSION)

    @property
    def indecidables(self) -> tuple[Comparaison, ...]:
        return tuple(c for c in self.comparaisons if c.statut == INDECIDABLE)

    def as_dict(self) -> dict[str, object]:
        return {
            "modele": self.modele,
            "autorisee": self.autorisee,
            "premiere_publication": self.premiere_publication,
            "comparaisons": [c.as_dict() for c in self.comparaisons],
        }


def _disjoints(a: MetricEntry, b: MetricEntry) -> bool:
    """Les deux intervalles ne se chevauchent pas du tout."""
    return a.high < b.low or b.high < a.low


def compare_metrique(avant: MetricEntry, apres: MetricEntry) -> Comparaison:
    """Compare une métrique entre le modèle en place et le candidat.

    Le sens de « mieux » vient de `direction` : sans lui, une baisse du taux de
    faux positifs et une baisse du rappel se ressemblent, et la porte laisserait
    passer la seconde en croyant voir la première.
    """
    lisible_avant = avant.proportion.format()
    lisible_apres = apres.proportion.format()

    if not _disjoints(avant, apres):
        # Largeur visée : celle du plus étroit des deux, pour que la question
        # « combien il m'en faut » ait une réponse concrète plutôt qu'un vœu.
        cible = min(avant.proportion.width, apres.proportion.width) / 2
        besoin = samples_needed_for_width(max(cible, 0.01)) if cible > 0 else None
        return Comparaison(
            metrique=apres.name,
            statut=INDECIDABLE,
            incumbent=lisible_avant,
            candidat=lisible_apres,
            explication=(
                "Les intervalles se recouvrent : à ces effectifs, la différence observée "
                "est compatible avec le hasard. Attention au sens de cette phrase — un "
                "recouvrement ne prouve PAS l'absence de différence, il constate qu'on ne "
                "peut pas trancher. La promotion reste autorisée (rien n'indique une "
                "dégradation), mais on n'a pas le droit d'annoncer une amélioration."
            ),
            echantillons_pour_trancher=besoin,
        )

    meilleur = (
        apres.proportion.rate > avant.proportion.rate
        if apres.direction == PLUS_HAUT
        else apres.proportion.rate < avant.proportion.rate
    )
    if meilleur:
        return Comparaison(
            metrique=apres.name,
            statut=AMELIORATION,
            incumbent=lisible_avant,
            candidat=lisible_apres,
            explication=(
                "Les intervalles sont disjoints dans le bon sens : l'amélioration est "
                "soutenue par les données, pas seulement par le point estimé."
            ),
        )
    return Comparaison(
        metrique=apres.name,
        statut=REGRESSION,
        incumbent=lisible_avant,
        candidat=lisible_apres,
        explication=(
            "Les intervalles sont disjoints dans le MAUVAIS sens : ce n'est pas du bruit, "
            "c'est une dégradation mesurée. La promotion est refusée."
        ),
    )


def evalue(candidat: ModelCard, en_place: ModelCard | None) -> RapportPromotion:
    """Compare un candidat au modèle enregistré, métrique par métrique.

    Sans modèle en place, tout est nouveau et rien ne peut être refusé : une
    première publication n'a pas de point de comparaison. Le rapport le dit
    plutôt que d'afficher un « autorisé » qui laisserait croire à une
    vérification qui n'a pas eu lieu.
    """
    if en_place is None:
        return RapportPromotion(
            modele=candidat.name,
            premiere_publication=True,
            comparaisons=tuple(
                Comparaison(
                    metrique=m.name,
                    statut=NOUVEAU,
                    incumbent=None,
                    candidat=m.proportion.format(),
                    explication=(
                        "Aucun modèle enregistré sous ce nom : c'est une première "
                        "publication, il n'y a rien à comparer. Ces chiffres deviennent "
                        "la référence des promotions suivantes."
                    ),
                )
                for m in candidat.metrics
            ),
        )

    comparaisons: list[Comparaison] = []
    for metrique in candidat.metrics:
        avant = en_place.metric(metrique.name)
        if avant is None:
            comparaisons.append(
                Comparaison(
                    metrique=metrique.name,
                    statut=NOUVEAU,
                    incumbent=None,
                    candidat=metrique.proportion.format(),
                    explication=(
                        "Métrique absente du modèle en place : elle n'a pas d'antécédent "
                        "et ne peut donc ni s'améliorer ni régresser."
                    ),
                )
            )
            continue
        comparaisons.append(compare_metrique(avant, metrique))

    # Une métrique qui DISPARAÎT compte aussi. Sinon, retirer la mesure gênante
    # d'un modèle deviendrait le moyen le plus simple de passer la porte.
    for perdue in en_place.metrics:
        if candidat.metric(perdue.name) is None:
            comparaisons.append(
                Comparaison(
                    metrique=perdue.name,
                    statut=REGRESSION,
                    incumbent=perdue.proportion.format(),
                    candidat="absente",
                    explication=(
                        "Cette métrique était publiée et ne l'est plus. Arrêter de mesurer "
                        "n'est pas un progrès : sans ce contrôle, supprimer la mesure "
                        "gênante serait le moyen le plus simple de franchir la porte."
                    ),
                )
            )

    return RapportPromotion(modele=candidat.name, comparaisons=tuple(comparaisons))


def formate(rapport: RapportPromotion) -> str:
    """Rapport lisible dans un terminal ou un journal de CI."""
    lignes = [
        "=" * 78,
        f"Porte de promotion — modèle « {rapport.modele} »",
        "=" * 78,
    ]
    if rapport.premiere_publication:
        lignes.append("Première publication : aucun modèle en place, rien à comparer.\n")

    for c in rapport.comparaisons:
        marque = {
            AMELIORATION: "  MIEUX     ",
            REGRESSION: "  RÉGRESSION",
            INDECIDABLE: "  INDÉCIDABLE",
            NOUVEAU: "  NOUVEAU   ",
        }[c.statut]
        lignes.append(f"{marque} {c.metrique}")
        if c.incumbent:
            lignes.append(f"      en place : {c.incumbent}")
        lignes.append(f"      candidat : {c.candidat}")
        lignes.append(f"      {c.explication}")
        if c.echantillons_pour_trancher:
            lignes.append(
                f"      Pour trancher, il faudrait de l'ordre de "
                f"{c.echantillons_pour_trancher} échantillons."
            )
        lignes.append("")

    lignes.append("-" * 78)
    if rapport.autorisee:
        lignes.append("PROMOTION AUTORISÉE")
        if rapport.indecidables and not rapport.ameliorations:
            lignes.append(
                "Aucune amélioration prouvée : ce modèle n'est pas démontré meilleur que\n"
                "celui qu'il remplace. Ne l'annonce pas comme tel."
            )
    else:
        lignes.append("PROMOTION REFUSÉE")
        for c in rapport.regressions:
            lignes.append(f"  - {c.metrique} : {c.incumbent} → {c.candidat}")
    lignes.append("-" * 78)
    return "\n".join(lignes)
