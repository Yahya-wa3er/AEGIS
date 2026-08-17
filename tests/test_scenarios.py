"""
Banc de scénarios (lot 6).

Ces tests protègent la DÉMONSTRATION, ce qui est moins accessoire qu'il n'y
paraît : une démo qui se met à mentir après un correctif est pire qu'une absence
de démo. Chaque scénario porte son attendu ; on vérifie qu'il tient.
"""
from __future__ import annotations

import pytest

from redteam.run_scenarios import ARRETS, ecarts, joue
from victim.scenarios import SCENARIOS, SCENARIOS_PAR_ID, familles


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_each_scenario_behaves_as_documented(scenario):
    """Le verdict ET les signaux correspondent à ce que le scénario annonce.

    Les deux comptent : un blocage obtenu par le mauvais signal est un coup de
    chance, pas une défense.
    """
    problemes = ecarts(joue(scenario))
    assert not problemes, f"{scenario.id} : {problemes}"


def test_every_attack_scenario_is_stopped():
    arretees = [s.id for s in SCENARIOS if s.est_attaque and joue(s)["verdict"] in ARRETS]
    attendues = [s.id for s in SCENARIOS if s.est_attaque]
    assert arretees == attendues


def test_no_legitimate_scenario_is_blocked():
    """Le garde-fou symétrique : un détecteur qui bloque tout passe tous les
    tests d'attaque."""
    bloques = [s.id for s in SCENARIOS if not s.est_attaque and joue(s)["verdict"] in ARRETS]
    assert bloques == []


def test_scenarios_cover_the_five_interception_points():
    """Une démonstration qui ne joue qu'un point d'interception donne une image
    fausse de l'architecture."""
    points = {joue(s)["point"] for s in SCENARIOS}
    assert {"on_prompt", "on_retrieval", "on_tool_result", "on_tool_call"} <= points


def test_scenario_ids_are_unique():
    assert len(SCENARIOS_PAR_ID) == len(SCENARIOS)


def test_every_scenario_says_where_to_look():
    """Un banc d'essai qui montre un résultat sans dire quoi observer ne
    démontre rien."""
    muets = [s.id for s in SCENARIOS if not s.regarder.strip() or not s.attendu.strip()]
    assert muets == []


def test_families_are_listed_in_order_of_appearance():
    assert familles()[0] == SCENARIOS[0].famille
    assert len(familles()) == len({s.famille for s in SCENARIOS})


def test_the_known_evasion_is_declared_as_such():
    """Le scénario d'évasion doit rester déclaré comme une limite : s'il perd sa
    contrainte `signaux_absents`, plus rien ne fige le constat."""
    hybride = SCENARIOS_PAR_ID["bourrage-classement-hybride"]
    assert "retrieval_stuffing" in hybride.signaux_absents
