import pytest

from victim.llm_client import MissingApiKeyError, _build_client


def test_missing_api_key_raises_clear_error(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(MissingApiKeyError):
        _build_client()