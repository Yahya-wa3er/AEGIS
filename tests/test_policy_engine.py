from aegis_core.policy_engine import AgentPolicy, PolicyEngine


def test_sensitive_tool_blocked_by_default():
    engine = PolicyEngine()
    decision, _ = engine.check("SupportAgent", "transfer_funds", {"amount": 100})
    assert decision == "block"


def test_unknown_agent_denied_by_default():
    engine = PolicyEngine()
    decision, _ = engine.check("UnknownAgent", "close_ticket", {})
    assert decision == "block"


def test_allowed_tool_within_limits_passes():
    engine = PolicyEngine()
    decision, _ = engine.check("SupportAgent", "close_ticket", {})
    assert decision == "allow"


def test_amount_over_cap_is_blocked():
    policies = {"Teller": AgentPolicy(allowed_tools=frozenset({"transfer_funds"}), max_amount=500)}
    engine = PolicyEngine(policies)

    decision, _ = engine.check("Teller", "transfer_funds", {"amount": 1000})
    assert decision == "block"

    decision, _ = engine.check("Teller", "transfer_funds", {"amount": 100})
    assert decision == "allow"