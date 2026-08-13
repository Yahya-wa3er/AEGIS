"""
Tests du mode fail-closed et de l'exposition de l'état des détecteurs (P0-4).

Ce que ces tests protègent : la propriété la plus dangereuse de la version
précédente n'était pas qu'un détecteur puisse être absent -- c'est qu'il puisse
l'être **en silence**, en renvoyant `risk=0.0` sur tout, pendant que le rapport
et le tableau de bord affichaient « aucune anomalie ».
"""
from __future__ import annotations

import pytest

from aegis_core.config import (
    DETECTOR_BEHAVIOR,
    DETECTOR_INJECTION_ML,
    DETECTOR_RAG_OUTLIER,
    AegisConfig,
    DetectorUnavailableError,
)
from aegis_core.middleware import AegisGuard


class _UnavailableDetector:
    """Détecteur dont le modèle n'est pas chargé -- le cas d'un clone frais."""

    ml_available = False

    def score(self, *args, **kwargs):
        raise AssertionError("ne doit jamais être appelé : le démarrage doit échouer avant")


def test_default_config_is_fail_open_and_says_so():
    """Le défaut reste permissif -- mais il est nommé, pas subi.

    `fail_mode == "open"` est la description exacte du comportement quand rien
    n'est exigé. C'est le mot « fail-safe » de la version précédente qui était
    faux : un composant qui laisse tout passer quand il défaille est fail-open.
    """
    config = AegisConfig()
    assert config.required_detectors == frozenset()
    assert config.fail_mode == "open"


def test_requiring_a_detector_switches_to_fail_closed():
    config = AegisConfig(required_detectors=frozenset({DETECTOR_RAG_OUTLIER}))
    assert config.fail_mode == "closed"


def test_unknown_detector_name_is_rejected_at_config_time():
    """Une faute de frappe dans required_detectors ne doit pas se traduire par
    une exigence silencieusement ignorée -- ce serait une fausse sécurité."""
    with pytest.raises(ValueError, match="Détecteur"):
        AegisConfig(required_detectors=frozenset({"rag_outliers"}))  # pluriel fautif


def test_guard_refuses_to_start_when_a_required_detector_is_missing():
    """Le refus intervient au DÉMARRAGE, pas à la première requête."""
    config = AegisConfig(required_detectors=frozenset({DETECTOR_RAG_OUTLIER}))
    with pytest.raises(DetectorUnavailableError, match=DETECTOR_RAG_OUTLIER):
        AegisGuard(rag_outlier_detector=_UnavailableDetector(), config=config)


def test_guard_starts_when_nothing_is_required():
    """Sans exigence, un détecteur absent dégrade au lieu de bloquer."""
    guard = AegisGuard(rag_outlier_detector=_UnavailableDetector())
    assert guard.detector_status()[DETECTOR_RAG_OUTLIER]["available"] is False


def test_detector_status_distinguishes_absent_from_silent():
    """Le cœur du correctif : « rien détecté » et « rien ne tourne » ne sont plus
    la même chose dans le rapport."""
    guard = AegisGuard(rag_outlier_detector=_UnavailableDetector())
    status = guard.detector_status()

    assert set(status) == {DETECTOR_INJECTION_ML, DETECTOR_RAG_OUTLIER, DETECTOR_BEHAVIOR}
    absent = status[DETECTOR_RAG_OUTLIER]
    assert absent["available"] is False
    assert absent["required"] is False
    assert "train_rag_outlier_detector" in absent["reason"]


def test_robustness_report_always_carries_detector_state():
    """Un rapport qui annonce « 0 anomalie » sans dire si le capteur tournait est
    trompeur : l'information doit être là systématiquement, pas sur demande."""
    guard = AegisGuard(rag_outlier_detector=_UnavailableDetector())
    report = guard.robustness_report()

    assert "detectors" in report
    assert report["fail_mode"] == "open"
    assert report["detectors"][DETECTOR_RAG_OUTLIER]["available"] is False
    assert report["audit_integrity"]["ok"] is True


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("AEGIS_REQUIRED_DETECTORS", "rag_outlier, behavior")
    monkeypatch.setenv("AEGIS_AUDIT_DB", "/tmp/aegis-audit.db")
    monkeypatch.setenv("AEGIS_REQUIRE_SIGNED_AUDIT", "1")

    config = AegisConfig.from_env()
    assert config.required_detectors == frozenset({DETECTOR_RAG_OUTLIER, DETECTOR_BEHAVIOR})
    assert config.audit_db_path == "/tmp/aegis-audit.db"
    assert config.require_signed_audit is True
    assert config.fail_mode == "closed"


def test_audit_db_path_reaches_the_audit_log(tmp_path):
    """Régression P1-5c : le journal était irrémédiablement en `:memory:`, donc
    détruit à chaque requête. Aucun chemin de configuration ne l'exposait."""
    db = tmp_path / "audit.db"
    guard = AegisGuard(config=AegisConfig(audit_db_path=str(db)))
    guard.on_tool_call("transfer_funds", {"amount": 1}, {"agent": "SupportAgent"})

    assert db.is_file()
    assert len(guard.audit_log.all_entries()) == 1
