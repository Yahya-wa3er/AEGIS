from aegis_core.behavior_detector import BehaviorDetector
from aegis_core.behavior_features import ActionEvent


def test_model_loads_when_trained():
    detector = BehaviorDetector()
    assert detector.ml_available is True


def test_fail_safe_when_model_missing():
    detector = BehaviorDetector(model_dir="models/does_not_exist")
    assert detector.ml_available is False
    result = detector.score([ActionEvent("close_ticket")])
    assert result == detector.score([ActionEvent("close_ticket")])  # déterministe
    assert result.flagged is False
    assert result.risk == 0.0


def test_scores_short_session_without_crashing():
    detector = BehaviorDetector()
    result = detector.score([ActionEvent("no_action")])  # moins de 5 événements -> complété en interne
    assert 0.0 <= result.risk < 1.0


def test_flags_clearly_anomalous_burst():
    detector = BehaviorDetector()
    # Rafale d'outils sensibles à montants élevés : la catégorie la plus nettement
    # séparée du normal dans l'évaluation (voir scripts/train_behavior_vae.py) --
    # celle des trois qu'on choisit pour un test déterministe et non fragile.
    burst = [ActionEvent("transfer_funds", amount=150_000) for _ in range(5)]
    result = detector.score(burst)
    assert result.flagged is True
    assert result.risk > 0.5


def test_normal_session_not_flagged():
    detector = BehaviorDetector()
    normal = [
        ActionEvent("no_action"),
        ActionEvent("close_ticket"),
        ActionEvent("no_action"),
        ActionEvent("no_action"),
        ActionEvent("close_ticket"),
    ]
    result = detector.score(normal)
    assert result.flagged is False
