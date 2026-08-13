"""
Séparation des données personnelles et de la preuve (correctif P1-7).

Le test central de ce fichier est `test_erasure_leaves_the_audit_chain_verifiable` :
il vérifie la propriété qui semblait impossible, à savoir effacer une personne
d'un registre **immuable par construction** sans casser une seule signature.
Tout le reste n'est que la plomberie qui la rend vraie.
"""
from __future__ import annotations

import pytest

from aegis_core.audit_log import AuditLog
from aegis_core.personal_data import (
    ENV_VAULT_KEY,
    TOKEN_PREFIX,
    EventPseudonymizer,
    PersonalDataVault,
)

KEY = b"cle-de-test-32-octets-suffisants"


@pytest.fixture
def vault() -> PersonalDataVault:
    return PersonalDataVault(key=KEY)


@pytest.fixture
def pseudo(vault: PersonalDataVault) -> EventPseudonymizer:
    return EventPseudonymizer(vault=vault)


# -- le jeton --------------------------------------------------------------


def test_token_is_deterministic_under_the_same_key(vault):
    """Sans déterminisme, impossible de corréler deux événements de la même
    personne -- ni, surtout, de retrouver toutes ses occurrences pour l'effacer."""
    assert vault.tokenize("m.durand@example.com") == vault.tokenize("m.durand@example.com")


def test_token_differs_under_a_different_key():
    a = PersonalDataVault(key=b"cle-A")
    b = PersonalDataVault(key=b"cle-B")
    assert a.tokenize("m.durand@example.com") != b.tokenize("m.durand@example.com")


def test_token_does_not_leak_the_value(vault):
    token = vault.tokenize("m.durand@example.com")
    assert token.startswith(TOKEN_PREFIX)
    assert "durand" not in token and "@" not in token


def test_missing_key_is_warned_not_silently_accepted(monkeypatch, caplog):
    """Une clé éphémère n'est pas une erreur -- c'est un choix par défaut aux
    conséquences précises (jetons instables, effacement rétroactif impossible).
    Le silence laisserait croire à une configuration correcte."""
    monkeypatch.delenv(ENV_VAULT_KEY, raising=False)
    with caplog.at_level("WARNING", logger="aegis_core.personal_data"):
        PersonalDataVault()
    assert any(ENV_VAULT_KEY in record.getMessage() for record in caplog.records)


def test_key_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv(ENV_VAULT_KEY, "cle-configuree")
    a = PersonalDataVault()
    b = PersonalDataVault()
    assert a.tokenize("m.durand@example.com") == b.tokenize("m.durand@example.com")


# -- la pseudonymisation ---------------------------------------------------


def test_email_in_a_nested_event_is_replaced_by_a_token(pseudo):
    event = {"type": "tool_call", "params": {"to": "m.durand@example.com", "amount": 120}}
    out = pseudo.pseudonymize(event)
    assert "m.durand@example.com" not in str(out)
    assert out["params"]["to"].startswith("[EMAIL:" + TOKEN_PREFIX)
    # Ce qui n'est pas une donnée personnelle passe intact : un événement
    # illisible ne serait pas un journal.
    assert out["type"] == "tool_call"
    assert out["params"]["amount"] == 120


def test_lists_and_tuples_are_traversed(pseudo):
    out = pseudo.pseudonymize({"destinataires": ["a@example.com", ("b@example.com",)]})
    assert "a@example.com" not in str(out)
    assert "b@example.com" not in str(out)


def test_several_categories_are_labelled(pseudo):
    out = pseudo.tokenize_text("Contact m.durand@example.com, IBAN FR7630006000011234567890189.")
    assert set(out.categories) == {"EMAIL", "IBAN"}
    assert out.changed


def test_text_without_personal_data_is_returned_unchanged(pseudo):
    text = "Le ticket 48291 a été clôturé conformément à la procédure interne."
    result = pseudo.tokenize_text(text)
    assert result.text == text
    assert not result.changed


def test_the_same_value_yields_the_same_token_across_events(pseudo):
    """C'est ce qui permet à un analyste de suivre un incident sans jamais lire
    la donnée : il corrèle des jetons."""
    a = pseudo.pseudonymize({"to": "m.durand@example.com"})
    b = pseudo.pseudonymize({"cc": "m.durand@example.com"})
    assert a["to"] == b["cc"]


def test_authorized_operator_can_resolve_a_token(pseudo):
    event = pseudo.pseudonymize({"to": "m.durand@example.com"})
    assert pseudo.resolve_event(event) == {"to": "m.durand@example.com"}


def test_resolution_after_erasure_returns_the_token_not_the_value(pseudo, vault):
    event = pseudo.pseudonymize({"to": "m.durand@example.com"})
    vault.erase_value("m.durand@example.com")
    resolved = pseudo.resolve_event(event)
    assert "m.durand@example.com" not in str(resolved)
    assert resolved == event  # le jeton reste, la valeur a disparu


# -- l'effacement ----------------------------------------------------------


def test_erase_removes_the_value_and_reports_the_count(vault, pseudo):
    pseudo.pseudonymize({"to": "m.durand@example.com", "cc": "autre@example.com"})
    assert vault.count() == 2
    assert vault.erase_value("m.durand@example.com") == 1
    assert vault.count() == 1
    assert vault.resolve(vault.tokenize("m.durand@example.com")) is None


def test_erasing_an_unknown_value_is_a_no_op(vault):
    assert vault.erase_value("jamais-vu@example.com") == 0


# -- la propriété centrale -------------------------------------------------


def test_erasure_leaves_the_audit_chain_verifiable():
    """RGPD art. 17 contre journal immuable : les deux tiennent ensemble.

    Le journal ne hache que des JETONS. Effacer une personne se fait donc dans le
    coffre, sans toucher au journal -- l'entrée reste, la chaîne reste vérifiable,
    et la preuve qu'un événement a eu lieu à telle date survit à l'effacement de
    son contenu personnel. C'est exactement ce qu'un DPO demandera de démontrer.
    """
    vault = PersonalDataVault(key=KEY)
    log = AuditLog(pseudonymizer=EventPseudonymizer(vault=vault))
    log.log({"type": "tool_call", "params": {"to": "m.durand@example.com"}})
    log.log({"type": "tool_call", "params": {"to": "autre@example.com"}})

    assert log.verify_integrity().ok
    entries_before = [e.event for e in log.all_entries()]

    assert vault.erase_value("m.durand@example.com") == 1

    report = log.verify_integrity()
    assert report.ok, report.reason
    # Le journal est rigoureusement inchangé : c'est la condition pour que les
    # signatures restent valides.
    assert [e.event for e in log.all_entries()] == entries_before


def test_the_journal_never_contained_the_value_in_the_first_place():
    """L'effacement ne « nettoie » pas le journal après coup -- il n'y a jamais
    rien eu à nettoyer. La pseudonymisation a lieu AVANT le calcul du hash."""
    log = AuditLog(pseudonymizer=EventPseudonymizer(vault=PersonalDataVault(key=KEY)))
    log.log({"type": "tool_call", "params": {"to": "m.durand@example.com"}})
    assert "m.durand@example.com" not in str([e.event for e in log.all_entries()])


def test_opting_out_is_possible_but_loud(caplog):
    """Un journal en clair reste possible -- pour un déploiement sans donnée
    personnelle, ou soumis à une obligation de conservation intégrale. Ça doit
    être un choix explicite et bruyant, pas un défaut silencieux."""
    with caplog.at_level("WARNING", logger="aegis_core.audit_log"):
        log = AuditLog(pseudonymizer=False)
    log.log({"type": "tool_call", "params": {"to": "m.durand@example.com"}})
    assert "m.durand@example.com" in str([e.event for e in log.all_entries()])
    assert any("art. 17" in record.getMessage() for record in caplog.records)
    assert log.vault is None


def test_pseudonymization_is_on_by_default():
    """Le défaut protège. Un opérateur qui ne configure rien n'obtient pas un
    registre immuable rempli de données personnelles."""
    log = AuditLog()
    log.log({"type": "tool_call", "params": {"to": "m.durand@example.com"}})
    assert "m.durand@example.com" not in str([e.event for e in log.all_entries()])
    assert log.vault is not None
