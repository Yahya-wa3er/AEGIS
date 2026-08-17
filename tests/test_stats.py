"""
Intervalles de confiance (correctif P1-M1).

Le test le plus important de ce fichier est
`test_interval_does_not_collapse_at_the_boundaries` : c'est exactement le cas où
la formule habituelle ment, et exactement le cas dans lequel ce projet se trouve
en permanence (12/12, 0/10).
"""
from __future__ import annotations

import pytest

from aegis_core.stats import (
    min_samples_for_lower_bound,
    rate,
    samples_needed_for_width,
    wilson_interval,
)


def test_known_values_match_an_independent_implementation():
    """Valeurs vérifiées contre `statsmodels.stats.proportion.proportion_confint`
    (méthode « wilson », alpha=0.05), identiques à 1e-6 près sur ces cas.

    statsmodels n'est PAS une dépendance du projet -- la vérification a été faite
    une fois, à la main, et ses résultats sont figés ici. Reproduire :

        pip install statsmodels
        python -c "from statsmodels.stats.proportion import proportion_confint; \
                   print(proportion_confint(12, 12, alpha=0.05, method='wilson'))"
    """
    twelve = wilson_interval(12, 12)
    assert twelve.rate == 1.0
    assert twelve.low == pytest.approx(0.757506, abs=1e-6)
    assert twelve.high == 1.0

    zero = wilson_interval(0, 10)
    assert zero.rate == 0.0
    assert zero.low == 0.0
    assert zero.high == pytest.approx(0.277533, abs=1e-6)

    assert wilson_interval(3, 10).low == pytest.approx(0.107791, abs=1e-6)
    assert wilson_interval(35, 40).high == pytest.approx(0.945405, abs=1e-6)


def test_interval_does_not_collapse_at_the_boundaries():
    """À p=0 et p=1, l'intervalle normal donne un point : « certitude » absolue
    sur la base de dix observations. C'est le piège que ce module évite."""
    assert wilson_interval(20, 20).low < 1.0
    assert wilson_interval(0, 20).high > 0.0


def test_interval_narrows_as_the_sample_grows():
    """La propriété qui rend l'affichage utile : agrandir le corpus se VOIT."""
    widths = [wilson_interval(n, n).width for n in (5, 20, 100, 500)]
    assert widths == sorted(widths, reverse=True)


def test_symmetry_around_one_half():
    a = wilson_interval(3, 10)
    b = wilson_interval(7, 10)
    assert a.low == pytest.approx(1 - b.high, abs=1e-12)
    assert a.high == pytest.approx(1 - b.low, abs=1e-12)


def test_no_measurement_means_no_knowledge_not_zero():
    """0 essai doit afficher « je ne sais rien », pas « 0 % ». Un rapport qui
    annonce 0 % de faux positifs sans avoir rien mesuré est le pire des deux."""
    empty = wilson_interval(0, 0)
    assert (empty.low, empty.high) == (0.0, 1.0)
    assert empty.format() == "n/a (0 échantillon)"


def test_incoherent_counts_are_refused():
    with pytest.raises(ValueError):
        wilson_interval(11, 10)
    with pytest.raises(ValueError):
        wilson_interval(-1, 10)


def test_format_shows_the_estimate_the_interval_and_the_counts():
    assert rate(12, 12).format() == "100% [76%-100%] (12/12)"
    assert rate(0, 10).format() == "0% [0%-28%] (0/10)"


def test_as_dict_is_serialisable():
    payload = rate(12, 14).as_dict()
    assert payload["successes"] == 12 and payload["total"] == 14
    assert 0.0 <= payload["ci_low"] <= payload["rate"] <= payload["ci_high"] <= 1.0


# -- dimensionnement du corpus --------------------------------------------


def test_min_samples_answers_the_question_the_interval_raises():
    """« 12/12 ne garantit que 76 %, il m'en faut combien pour 80 % ? »"""
    needed = min_samples_for_lower_bound(0.80)
    assert wilson_interval(needed, needed).low >= 0.80
    assert wilson_interval(needed - 1, needed - 1).low < 0.80


def test_tolerating_failures_costs_more_samples():
    assert min_samples_for_lower_bound(0.80, max_failures=2) > min_samples_for_lower_bound(0.80)


def test_higher_target_costs_more_samples():
    assert min_samples_for_lower_bound(0.90) > min_samples_for_lower_bound(0.80)


def test_samples_needed_for_width_is_the_usual_order_of_magnitude():
    # ±5 points à 95 % sur une proportion inconnue : le fameux « n ≈ 385 ».
    assert samples_needed_for_width(0.10) == 385


def test_invalid_targets_are_refused():
    with pytest.raises(ValueError):
        min_samples_for_lower_bound(0.0)
    with pytest.raises(ValueError):
        min_samples_for_lower_bound(1.0)
    with pytest.raises(ValueError):
        samples_needed_for_width(0.0)
