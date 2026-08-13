"""
Portée et bornes de l'état conversationnel (correctif P1-5a).

Ces tests ne vérifient pas une détection : ils vérifient une **isolation**. La
distinction compte, parce qu'une fenêtre comportementale partagée ne produit pas
d'erreur -- elle produit un score, et le score a l'air normal.
"""
from __future__ import annotations

from aegis_core.session import (
    ANONYMOUS_SESSION,
    DEFAULT_TENANT,
    SessionKey,
    SessionStore,
)


class FakeClock:
    """Horloge pilotée : le TTL doit être testable sans faire dormir la suite."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# -- la clé ---------------------------------------------------------------


def test_key_reads_tenant_agent_and_session_from_ctx():
    key = SessionKey.from_ctx({"agent": "SupportAgent", "session_id": "s-42", "tenant": "acme"})
    assert (key.tenant, key.agent, key.session_id) == ("acme", "SupportAgent", "s-42")
    assert key.identified and not key.anonymous


def test_key_without_session_id_is_marked_anonymous_not_invented():
    """Sans identifiant de session, on NE fabrique PAS une clé plausible.

    Inventer un identifiant (un uuid, un hash du contexte) donnerait une
    isolation apparente et fausse : chaque requête aurait sa propre fenêtre, donc
    le détecteur comportemental n'observerait plus jamais de séquence. Le
    comportement dégradé assumé est le partage -- et il est signalé.
    """
    key = SessionKey.from_ctx({"agent": "SupportAgent"})
    assert key.session_id == ANONYMOUS_SESSION
    assert key.anonymous
    assert key.tenant == DEFAULT_TENANT


def test_key_accepts_the_usual_orchestrator_names():
    assert SessionKey.from_ctx({"conversation_id": "c-1"}).session_id == "c-1"
    assert SessionKey.from_ctx({"thread_id": "t-1"}).session_id == "t-1"
    assert SessionKey.from_ctx({"tenant_id": "acme"}).tenant == "acme"


def test_key_ignores_blank_values():
    """Une chaîne vide n'est pas un identifiant : la traiter comme tel donnerait
    une clé commune à tous ceux qui n'en fournissent pas, en la présentant comme
    identifiée."""
    key = SessionKey.from_ctx({"agent": "SupportAgent", "session_id": "   "})
    assert key.anonymous


def test_keys_are_hashable_and_distinct_per_field():
    a = SessionKey("acme", "SupportAgent", "s-1")
    b = SessionKey("acme", "SupportAgent", "s-2")
    c = SessionKey("globex", "SupportAgent", "s-1")
    assert len({a, b, c}) == 3
    assert a == SessionKey("acme", "SupportAgent", "s-1")


# -- le magasin -----------------------------------------------------------


def test_two_sessions_of_the_same_agent_do_not_share_state():
    store = SessionStore()
    a = store.get(SessionKey("acme", "SupportAgent", "s-1"), list)
    b = store.get(SessionKey("acme", "SupportAgent", "s-2"), list)
    a.append("virement")
    assert b == []


def test_same_session_id_across_tenants_stays_separate():
    """Deux clients peuvent parfaitement numéroter leurs sessions « 1 »."""
    store = SessionStore()
    a = store.get(SessionKey("acme", "SupportAgent", "1"), list)
    b = store.get(SessionKey("globex", "SupportAgent", "1"), list)
    a.append("virement")
    assert b == []


def test_state_persists_across_calls_for_the_same_key():
    store = SessionStore()
    key = SessionKey("acme", "SupportAgent", "s-1")
    store.get(key, list).append("virement")
    assert store.get(key, list) == ["virement"]


def test_expired_sessions_are_forgotten():
    clock = FakeClock()
    store = SessionStore(ttl_seconds=60, clock=clock)
    key = SessionKey("acme", "SupportAgent", "s-1")
    store.get(key, list).append("virement")

    clock.advance(61)
    assert store.get(key, list) == []  # nouvelle fenêtre, pas l'ancienne
    assert store.stats()["expired"] == 1


def test_activity_refreshes_the_ttl():
    clock = FakeClock()
    store = SessionStore(ttl_seconds=60, clock=clock)
    key = SessionKey("acme", "SupportAgent", "s-1")
    store.get(key, list).append("virement")

    clock.advance(40)
    store.get(key, list)  # activité : la session est vivante
    clock.advance(40)     # 80 s depuis la création, 40 s depuis le dernier accès
    assert store.get(key, list) == ["virement"]


def test_session_count_is_capped_and_evicts_the_least_recent():
    """OWASP LLM06 : la clé vient du client, donc le nombre de clés aussi.

    Sans plafond, `session_id` aléatoire à chaque requête = croissance mémoire
    linéaire et gratuite pour l'attaquant.
    """
    store = SessionStore(max_sessions=3)
    for i in range(5):
        store.get(SessionKey("acme", "SupportAgent", f"s-{i}"), list)

    assert len(store) == 3
    assert store.stats()["evicted"] == 2
    assert store.peek(SessionKey("acme", "SupportAgent", "s-0")) is None
    assert store.peek(SessionKey("acme", "SupportAgent", "s-4")) is not None


def test_eviction_spares_the_recently_used_session():
    store = SessionStore(max_sessions=2)
    old = SessionKey("acme", "SupportAgent", "s-old")
    store.get(old, list)
    store.get(SessionKey("acme", "SupportAgent", "s-mid"), list)
    store.get(old, list)  # on s'en resert : ce n'est plus la moins récente
    store.get(SessionKey("acme", "SupportAgent", "s-new"), list)

    assert store.peek(old) is not None
    assert store.peek(SessionKey("acme", "SupportAgent", "s-mid")) is None


def test_drop_forgets_a_session_on_demand():
    store = SessionStore()
    key = SessionKey("acme", "SupportAgent", "s-1")
    store.get(key, list)
    assert store.drop(key) is True
    assert store.peek(key) is None
    assert store.drop(key) is False


def test_stats_report_degraded_when_a_window_is_anonymous():
    store = SessionStore()
    store.get(SessionKey.from_ctx({"agent": "SupportAgent"}), list)
    stats = store.stats()
    assert stats["degraded"] is True
    assert stats["anonymous"] == 1
    assert stats["identified"] == 0


def test_stats_report_isolation_when_every_window_is_identified():
    store = SessionStore()
    store.get(SessionKey.from_ctx({"agent": "SupportAgent", "session_id": "s-1"}), list)
    stats = store.stats()
    assert stats["degraded"] is False
    assert stats["identified"] == 1
    assert stats["keyed_by"] == ["tenant", "agent", "session_id"]


def test_anonymous_usage_is_warned_once(caplog):
    """Le partage doit être signalé -- une fois, pas à chaque requête : un
    avertissement répété dix mille fois est un avertissement que personne ne lit."""
    store = SessionStore()
    with caplog.at_level("WARNING", logger="aegis_core.session"):
        for _ in range(3):
            store.get(SessionKey.from_ctx({"agent": "SupportAgent"}), list)
    assert sum("PARTAGÉ" in record.message for record in caplog.records) == 1
