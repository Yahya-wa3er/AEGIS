"""
Tests du Policy Engine -- la couche qui adresse LLM03:2026 Excessive Agency,
3e risque mondial de l'OWASP GenAI Top 10.

Chaque contournement testé ici a été exploité contre la version précédente.
"""
from __future__ import annotations

import pytest

from aegis_core.policy_engine import AgentPolicy, PolicyEngine


def _teller(**kwargs) -> PolicyEngine:
    """Un agent autorisé à virer de l'argent, plafonné à 1000."""
    policy = AgentPolicy(allowed_tools=frozenset({"transfer_funds"}), max_amount=1000.0, **kwargs)
    return PolicyEngine({"Teller": policy})


# --- Comportements de base -------------------------------------------------

def test_sensitive_tool_blocked_by_default():
    engine = PolicyEngine()
    decision, _ = engine.check("SupportAgent", "transfer_funds", {"amount": 100})
    assert decision == "block"


def test_unknown_agent_denied_by_default():
    engine = PolicyEngine()
    decision, _ = engine.check("UnknownAgent", "close_ticket", {})
    assert decision == "block"


def test_allowed_tool_with_valid_params_passes():
    engine = PolicyEngine()
    decision, _ = engine.check("SupportAgent", "close_ticket", {"ticket_id": "48291"})
    assert decision == "allow"


def test_amount_over_cap_is_blocked():
    engine = _teller()
    assert engine.check("Teller", "transfer_funds", {"amount": 1000})[0] == "allow"
    assert engine.check("Teller", "transfer_funds", {"amount": 1001})[0] == "block"


# --- P1-1 : le plafond se contournait par le typage ------------------------

@pytest.mark.parametrize("amount", ["99999", "99 999,00", "99999.00"])
def test_numeric_string_over_cap_is_understood_then_blocked(amount):
    """Une chaîne numérique est INTERPRÉTÉE, puis soumise au plafond.

    L'ancienne version faisait `isinstance(amount, (int, float))` avant de
    comparer : `"99999"` n'étant ni int ni float, le contrôle de plafond était
    purement et simplement sauté. Les paramètres venant d'un JSON produit par un
    LLM, le type n'est jamais garanti -- et les modèles produisent régulièrement
    des nombres sous forme de chaîne, y compris au format francophone.
    """
    decision, reason = _teller().check("Teller", "transfer_funds", {"amount": amount})
    assert decision == "block", f"{amount!r} a contourné le plafond"
    assert "dépasse le plafond" in reason


@pytest.mark.parametrize("amount", [True, False, [99999], {"value": 99999}, "beaucoup", object()])
def test_uninterpretable_amount_is_blocked_not_ignored(amount):
    """Un montant qu'on ne sait pas interpréter n'est pas un montant sûr.

    Cas particulièrement retors : `True`. En Python `isinstance(True, int)` vaut
    True -- le booléen passait donc le test de type -- mais `True > 1000.0` vaut
    False, donc il franchissait aussi le plafond.
    """
    decision, reason = _teller().check("Teller", "transfer_funds", {"amount": amount})
    assert decision == "block", f"{amount!r} a contourné le plafond"
    assert "amount" in reason


def test_numeric_string_within_cap_is_accepted():
    """On bloque ce qu'on ne comprend pas, pas ce qu'on comprend très bien.

    Refuser `"500"` alors que le plafond est à 1000 serait un faux positif :
    la valeur est parfaitement interprétable et conforme.
    """
    assert _teller().check("Teller", "transfer_funds", {"amount": "500"})[0] == "allow"
    assert _teller().check("Teller", "transfer_funds", {"amount": "500,50"})[0] == "allow"


# --- P1-1b : la forme des paramètres n'était pas validée -------------------

def test_missing_required_param_is_blocked():
    """`close_ticket()` sans ticket_id lèverait un TypeError à l'exécution.

    Une couche de sécurité qui autorise un appel doit en valider la forme --
    sinon elle autorise quelque chose qu'elle n'a pas compris.
    """
    decision, reason = PolicyEngine().check("SupportAgent", "close_ticket", {})
    assert decision == "block"
    assert "schéma" in reason


def test_unexpected_param_is_blocked():
    """`additionalProperties: False` : un paramètre en trop fait planter l'appel
    réel (`TypeError: unexpected keyword argument`) et signale souvent que le
    modèle improvise."""
    decision, reason = PolicyEngine().check(
        "SupportAgent", "close_ticket", {"ticket_id": "48291", "force": True}
    )
    assert decision == "block"
    assert "schéma" in reason


def test_param_of_wrong_shape_is_blocked():
    decision, _ = PolicyEngine().check("SupportAgent", "close_ticket", {"ticket_id": "'; DROP TABLE--"})
    assert decision == "block"


def test_params_that_are_not_a_dict_are_blocked():
    """`json.loads` d'arguments malformés peut produire autre chose qu'un objet."""
    decision, _ = PolicyEngine().check("SupportAgent", "close_ticket", ["48291"])  # type: ignore[arg-type]
    assert decision == "block"


# --- P1-2 : sensitive_tools était du code mort -----------------------------

def test_sensitive_tool_needs_approval_even_when_allowed():
    """Le champ ne changeait JAMAIS une décision auparavant : la condition
    `tool in sensitive and tool not in allowed` était entièrement englobée par
    le test d'allow-list qui suivait. Un outil à la fois autorisé ET sensible,
    avec un montant d'un million, passait sans broncher."""
    engine = _teller(sensitive_tools=frozenset({"transfer_funds"}))
    decision, reason = engine.check("Teller", "transfer_funds", {"amount": 500})
    assert decision == "block"
    assert "validation externe" in reason


def test_sensitive_tool_passes_when_approval_granted():
    policy = AgentPolicy(
        allowed_tools=frozenset({"transfer_funds"}),
        sensitive_tools=frozenset({"transfer_funds"}),
        max_amount=1000.0,
    )
    engine = PolicyEngine({"Teller": policy}, approval_hook=lambda agent, tool, params: True)
    decision, reason = engine.check("Teller", "transfer_funds", {"amount": 500})
    assert decision == "allow"
    assert "validation externe" in reason


def test_sensitive_tool_blocked_when_approval_refused():
    policy = AgentPolicy(
        allowed_tools=frozenset({"transfer_funds"}),
        sensitive_tools=frozenset({"transfer_funds"}),
        max_amount=1000.0,
    )
    engine = PolicyEngine({"Teller": policy}, approval_hook=lambda *a: False)
    assert engine.check("Teller", "transfer_funds", {"amount": 500})[0] == "block"


def test_approval_hook_sees_the_actual_parameters():
    """Une validation humaine qui ne verrait pas le montant ne servirait à rien."""
    seen: list[tuple] = []

    def hook(agent, tool, params):
        seen.append((agent, tool, dict(params)))
        return params.get("amount", 0) < 100

    policy = AgentPolicy(
        allowed_tools=frozenset({"transfer_funds"}),
        sensitive_tools=frozenset({"transfer_funds"}),
        max_amount=10_000.0,
    )
    engine = PolicyEngine({"Teller": policy}, approval_hook=hook)

    assert engine.check("Teller", "transfer_funds", {"amount": 50})[0] == "allow"
    assert engine.check("Teller", "transfer_funds", {"amount": 5000})[0] == "block"
    assert seen[0] == ("Teller", "transfer_funds", {"amount": 50})


# --- Liste blanche de valeurs ---------------------------------------------

def test_destination_allowlist_blocks_exfiltration():
    """Autoriser `send_email` sans contraindre le destinataire, c'est autoriser
    l'exfiltration. C'est exactement l'action que la démo a exécutée sur un
    document pourtant légitime."""
    policy = AgentPolicy(
        allowed_tools=frozenset({"send_email"}),
        param_allowlists={"send_email": {"to": frozenset({"support@acme.fr"})}},
    )
    engine = PolicyEngine({"Bot": policy})

    assert engine.check("Bot", "send_email", {"to": "support@acme.fr", "body": "ok"})[0] == "allow"

    decision, reason = engine.check("Bot", "send_email", {"to": "external@attacker.example", "body": "export"})
    assert decision == "block"
    assert "non autorisée" in reason


def test_allowlisted_param_must_be_present():
    policy = AgentPolicy(
        allowed_tools=frozenset({"send_email"}),
        param_allowlists={"send_email": {"to": frozenset({"support@acme.fr"})}},
    )
    decision, reason = PolicyEngine({"Bot": policy}).check("Bot", "send_email", {"body": "ok"})
    assert decision == "block"
    assert "absent" in reason
