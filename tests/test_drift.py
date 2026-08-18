"""
Surveillance de dérive : ce que le détecteur voit vs ce sur quoi il est calibré.

Le test le plus important ici est celui qui vérifie qu'on **refuse de conclure**
sous un effectif minimal. Un module de dérive qui affiche « rien à signaler »
après trois observations est pire qu'un module absent : il donne une assurance
que rien ne soutient.
"""
from __future__ import annotations

import pytest

from aegis_core.drift import MIN_OBSERVATIONS, ScoreObserver, quantile

REFERENCE = {"q50": 0.50, "q90": 0.80, "q99": 0.95}


def test_pas_assez_d_observations_n_est_pas_rien_a_signaler():
    observateur = ScoreObserver(signal="essai", reference=REFERENCE)
    for _ in range(MIN_OBSERVATIONS - 1):
        observateur.observe(0.5)
    rapport = observateur.report()
    assert rapport.suffisant is False
    assert rapport.observe == {}
    assert "n'est pas" in rapport.commentaire


def test_au_dela_du_minimum_les_quantiles_sont_compares():
    observateur = ScoreObserver(signal="essai", reference=REFERENCE)
    for i in range(200):
        observateur.observe(i / 200)
    rapport = observateur.report()
    assert rapport.suffisant
    assert set(rapport.observe) == {"q50", "q90", "q99"}
    assert set(rapport.ecarts) == {"q50", "q90", "q99"}


def test_un_decalage_franc_apparait_dans_les_ecarts():
    observateur = ScoreObserver(signal="essai", reference=REFERENCE)
    for _ in range(100):
        observateur.observe(0.95)  # tout le monde au-dessus de la médiane de référence
    rapport = observateur.report()
    assert rapport.ecarts["q50"] > 0.4


def test_sans_reference_on_observe_sans_conclure():
    """« Pas de référence » et « référence vide » ne veulent pas dire la même
    chose, et le rapport doit pouvoir dire laquelle des deux il a."""
    observateur = ScoreObserver(signal="essai", reference=None)
    for i in range(100):
        observateur.observe(i / 100)
    rapport = observateur.report()
    assert rapport.suffisant
    assert rapport.observe
    assert rapport.ecarts == {}
    assert "Aucune distribution de référence" in rapport.commentaire


def test_l_etat_d_observation_est_borne():
    """Une fenêtre qui grandit avec le trafic rejouerait le défaut d'état non
    borné corrigé au lot 4B — sur le composant censé surveiller la santé du
    système, ce serait particulièrement malvenu."""
    observateur = ScoreObserver(signal="essai", fenetre_max=100)
    for i in range(10_000):
        observateur.observe(i / 10_000)
    rapport = observateur.report()
    assert len(observateur._valeurs) == 100
    # Le compteur total, lui, garde la mémoire de ce qui a été vu.
    assert rapport.observations == 10_000


def test_le_rapport_dit_ce_qu_il_n_est_pas():
    """Limite assumée, figée : c'est une comparaison de quantiles, pas un test
    statistique, et aucun seuil d'alerte n'est proposé."""
    observateur = ScoreObserver(signal="essai", reference=REFERENCE)
    for i in range(100):
        observateur.observe(i / 100)
    commentaire = observateur.report().commentaire
    assert "pas un test statistique" in commentaire
    assert "Aucun seuil d'alerte" in commentaire


def test_quantile_sans_numpy():
    assert quantile([1.0], 0.5) == 1.0
    assert quantile([0.0, 1.0], 0.5) == pytest.approx(0.5)
    assert quantile([0.0, 1.0, 2.0, 3.0], 0.9) == pytest.approx(2.7)
    with pytest.raises(ValueError):
        quantile([], 0.5)


def test_le_garde_expose_la_derive_dans_son_rapport():
    """La dérive doit être observable là où le reste de l'état l'est déjà."""
    from aegis_core.middleware import AegisGuard

    garde = AegisGuard()
    for i in range(5):
        garde._content_verdict(f"Bonjour, ticket {i}, merci de traiter la demande.")
    rapport = garde.robustness_report()
    assert "score_drift" in rapport
    assert rapport["score_drift"]["signal"] == "rag_outlier"
