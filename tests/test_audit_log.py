from aegis_core.audit_log import AuditLog


def test_chain_is_valid_after_normal_logging():
    log = AuditLog()
    log.log({"type": "test", "value": 1})
    log.log({"type": "test", "value": 2})
    ok, bad_id = log.verify_integrity()
    assert ok is True
    assert bad_id is None


def test_tampering_is_detected():
    log = AuditLog()
    log.log({"type": "test", "value": 1})
    log.log({"type": "test", "value": 2})
    log.tamper_with(1, {"type": "test", "value": 999})
    ok, bad_id = log.verify_integrity()
    assert ok is False
    assert bad_id == 1


def test_entries_are_chained_by_hash():
    log = AuditLog()
    log.log({"type": "a"})
    log.log({"type": "b"})
    entries = log.all_entries()
    assert entries[1].prev_hash == entries[0].hash