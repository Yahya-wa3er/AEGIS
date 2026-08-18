"""
Porte de promotion : « ce modèle est meilleur » est une affirmation qui se prouve.

Le test central de ce fichier est `test_une_amelioration_du_point_ne_suffit_pas` :
il fige le comportement qui distingue cette porte d'un simple `>`. Passer de
12/14 à 13/14 fait monter le point de 86 % à 93 %, et ne démontre rien du tout.
"""
from __future__ import annotations

from aegis_core.model_registry import MetricEntry, ModelCard
from aegis_core.promotion import (
    AMELIORATION,
    INDECIDABLE,
    NOUVEAU,
    PLUS_BAS,
    PLUS_HAUT,
    REGRESSION,
    compare_metrique,
    evalue,
    formate,
)
from aegis_core.stats import wilson_interval


def metrique(nom: str, succes: int, total: int, direction: str = PLUS_HAUT) -> MetricEntry:
    """Construit une entrée avec un intervalle de Wilson RÉEL.

    Écrire les bornes à la main dans un test de comparaison d'intervalles
    reviendrait à tester l'arithmétique du test plutôt que celle du code.
    """
    p = wilson_interval(succes, total)
    return MetricEntry(
        name=nom, successes=succes, total=total, low=p.low, high=p.high, direction=direction
    )


def carte(nom: str, metriques: tuple[MetricEntry, ...]) -> ModelCard:
    return ModelCard(
        name=nom, version="v", created_at="2026-01-01T00:00:00+00:00",
        artifact_sha256="a" * 64, dataset_sha256="d" * 64, dataset_files=(),
        threshold=None, target_false_positive_rate=None, metrics=metriques,
        intended_use="", known_failures=(), training_command="",
        decision_role="consultatif",
    )


# -- la règle, cas par cas --------------------------------------------------


def test_une_amelioration_du_point_ne_suffit_pas():
    """Le cœur de la porte, et la raison pour laquelle elle existe.

    12/14 → 13/14, c'est 86 % → 93 %. Un projet sans règle de promotion garde le
    nouveau modèle et annonce un progrès. Les intervalles de Wilson se
    recouvrent largement : à ces effectifs, la différence observée est
    compatible avec le hasard.
    """
    verdict = compare_metrique(metrique("rappel", 12, 14), metrique("rappel", 13, 14))
    assert verdict.statut == INDECIDABLE
    assert not verdict.bloquant
    assert verdict.echantillons_pour_trancher


def test_une_amelioration_franche_est_reconnue():
    verdict = compare_metrique(metrique("rappel", 40, 100), metrique("rappel", 90, 100))
    assert verdict.statut == AMELIORATION


def test_une_regression_franche_bloque():
    verdict = compare_metrique(metrique("rappel", 90, 100), metrique("rappel", 40, 100))
    assert verdict.statut == REGRESSION
    assert verdict.bloquant


def test_le_sens_de_mieux_est_respecte():
    """Une baisse des faux positifs et une baisse du rappel se ressemblent.

    Sans `direction`, la porte laisserait passer la seconde en croyant voir la
    première : les deux sont « une baisse ».
    """
    baisse_fp = compare_metrique(
        metrique("fp", 40, 100, PLUS_BAS), metrique("fp", 5, 100, PLUS_BAS)
    )
    assert baisse_fp.statut == AMELIORATION

    baisse_rappel = compare_metrique(
        metrique("rappel", 40, 100, PLUS_HAUT), metrique("rappel", 5, 100, PLUS_HAUT)
    )
    assert baisse_rappel.statut == REGRESSION


def test_le_recouvrement_ne_prouve_pas_l_absence_de_difference():
    """Limite du test par recouvrement, figée pour ne pas être oubliée.

    Comparer deux intervalles par recouvrement est CONSERVATEUR : disjoints ⟹
    différence significative, mais recouvrement ⟹ on ne peut rien conclure. Le
    texte du rapport doit le dire, sinon un lecteur pressé lira « indécidable »
    comme « équivalent ».
    """
    verdict = compare_metrique(metrique("rappel", 12, 14), metrique("rappel", 13, 14))
    assert "ne prouve PAS l'absence de différence" in verdict.explication


# -- rapport complet --------------------------------------------------------


def test_une_premiere_publication_ne_peut_rien_refuser():
    rapport = evalue(carte("m", (metrique("rappel", 12, 14),)), None)
    assert rapport.premiere_publication
    assert rapport.autorisee
    assert all(c.statut == NOUVEAU for c in rapport.comparaisons)


def test_une_seule_regression_suffit_a_refuser():
    en_place = carte("m", (metrique("rappel", 90, 100), metrique("fp", 5, 100, PLUS_BAS)))
    candidat = carte("m", (metrique("rappel", 40, 100), metrique("fp", 5, 100, PLUS_BAS)))
    rapport = evalue(candidat, en_place)
    assert not rapport.autorisee
    assert len(rapport.regressions) == 1


def test_supprimer_une_metrique_genante_ne_passe_pas_la_porte():
    """Sans ce contrôle, le moyen le plus simple de franchir la porte serait
    d'arrêter de publier la mesure qui dérange."""
    en_place = carte("m", (metrique("rappel", 90, 100), metrique("fp", 5, 100, PLUS_BAS)))
    candidat = carte("m", (metrique("rappel", 90, 100),))
    rapport = evalue(candidat, en_place)
    assert not rapport.autorisee
    perdue = next(c for c in rapport.regressions if c.metrique == "fp")
    assert perdue.candidat == "absente"


def test_une_metrique_nouvelle_ne_bloque_pas():
    en_place = carte("m", (metrique("rappel", 90, 100),))
    candidat = carte("m", (metrique("rappel", 90, 100), metrique("nouvelle", 50, 100)))
    rapport = evalue(candidat, en_place)
    assert rapport.autorisee
    assert any(c.statut == NOUVEAU for c in rapport.comparaisons)


def test_un_changement_indecidable_est_autorise_mais_pas_vantable():
    en_place = carte("m", (metrique("rappel", 12, 14),))
    candidat = carte("m", (metrique("rappel", 13, 14),))
    rapport = evalue(candidat, en_place)
    assert rapport.autorisee
    assert not rapport.ameliorations
    texte = formate(rapport)
    assert "PROMOTION AUTORISÉE" in texte
    assert "n'est pas démontré meilleur" in texte


def test_le_rapport_refuse_lisiblement():
    en_place = carte("m", (metrique("rappel", 90, 100),))
    candidat = carte("m", (metrique("rappel", 40, 100),))
    texte = formate(evalue(candidat, en_place))
    assert "PROMOTION REFUSÉE" in texte
    assert "RÉGRESSION" in texte
