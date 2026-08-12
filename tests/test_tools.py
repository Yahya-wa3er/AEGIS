# tests/test_tools.py
from victim import tools


def test_reset_clears_executed_actions():
    tools.send_email(to="a@b.com", body="test")
    tools.reset()
    assert tools.EXECUTED_ACTIONS == []


def test_transfer_funds_is_recorded():
    tools.reset()
    tools.transfer_funds(account="FR001", amount=100.0)
    assert len(tools.EXECUTED_ACTIONS) == 1
    record = tools.EXECUTED_ACTIONS[0]
    assert record.tool == "transfer_funds"
    assert record.params["amount"] == 100.0