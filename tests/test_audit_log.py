"""
Tests du journal d'audit, y compris l'attaque qui a motivé le correctif P0-2.

Le test central est `test_forged_chain_is_rejected_when_signed` : il rejoue
exactement l'attaque menée pendant l'audit -- un attaquant qui a l'accès en
écriture à la base réécrit une entrée ET recalcule toute la chaîne. Contre la
version non signée, `verify_integrity()` répondait `OK` et le virement de
50 000 € disparaissait sans trace. C'est ce scénario, et lui seul, qui distingue
un journal « détecte la modification naïve » d'un journal opposable.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from aegis_core.audit_log import GENESIS_HASH, AuditLog
from aegis_core.signing import (
    SIGNATURE_MODE_NONE,
    AuditSigningError,
    Ed25519Signer,
    NullSigner,
    generate_keypair,
    load_signer,
)


def _signer(tmp_path) -> Ed25519Signer:
    """Paire de clés jetable, propre à un test."""
    private_pem, public_pem = generate_keypair()
    (tmp_path / "k").write_bytes(private_pem)
    (tmp_path / "k.pub").write_bytes(public_pem)
    return load_signer(private_key_path=tmp_path / "k", public_key_path=tmp_path / "k.pub")


def _reforge_chain(db_path: str, entry_id: int, new_event: dict) -> None:
    """Simule un attaquant disposant d'un accès en écriture au fichier SQLite.

    Il fait ce que ferait n'importe qui de compétent : il supprime les triggers
    append-only qui le gênent, réécrit l'entrée visée, puis **recalcule toute la
    chaîne de hachage** exactement comme le fait `verify_integrity()`. Filtrer
    l'attaquant naïf ne prouve rien -- c'est celui-ci qu'il faut arrêter.
    """
    con = sqlite3.connect(db_path)
    con.execute("DROP TRIGGER IF EXISTS audit_log_append_only_update")
    con.execute("DROP TRIGGER IF EXISTS audit_log_append_only_delete")

    prev = GENESIS_HASH
    for rid, ts, ev in con.execute("SELECT id, timestamp, event FROM audit_log ORDER BY id").fetchall():
        event = new_event if rid == entry_id else json.loads(ev)
        payload = json.dumps({"timestamp": ts, "event": event, "prev_hash": prev}, sort_keys=True)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        con.execute(
            "UPDATE audit_log SET event = ?, prev_hash = ?, hash = ? WHERE id = ?",
            (json.dumps(event, ensure_ascii=False), prev, digest, rid),
        )
        prev = digest
    con.commit()
    con.close()


def _sample_log(log: AuditLog) -> None:
    log.log({"type": "tool_call", "tool": "transfer_funds", "params": {"amount": 50_000}, "decision": "allow"})
    log.log({"type": "tool_call", "tool": "close_ticket", "decision": "allow"})
    log.log({"type": "citation_check", "cited": "doc2", "flagged": False})


def test_chain_is_valid_after_normal_logging():
    log = AuditLog(signer=NullSigner())
    log.log({"type": "test", "value": 1})
    log.log({"type": "test", "value": 2})
    report = log.verify_integrity()
    assert report.ok is True
    assert report.first_bad_entry is None
    assert report.entries_checked == 2


def test_entries_are_chained_by_hash():
    log = AuditLog(signer=NullSigner())
    log.log({"type": "a"})
    log.log({"type": "b"})
    entries = log.all_entries()
    assert entries[1].prev_hash == entries[0].hash


def test_naive_tampering_is_detected(tmp_path):
    """Modification d'une entrée SANS recalcul de la chaîne : détectée par le hash seul."""
    db = str(tmp_path / "audit.db")
    log = AuditLog(db, signer=NullSigner())
    log.log({"type": "test", "value": 1})
    log.log({"type": "test", "value": 2})

    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER IF EXISTS audit_log_append_only_update")
    con.execute("UPDATE audit_log SET event = ? WHERE id = 1", (json.dumps({"type": "test", "value": 999}),))
    con.commit()
    con.close()

    report = log.verify_integrity()
    assert report.ok is False
    assert report.first_bad_entry == 1
    assert "modifié" in report.reason


def test_forged_chain_slips_past_an_unsigned_log(tmp_path):
    """LA faille du rapport d'audit, telle qu'exploitée : sans signature, la
    reforge complète de la chaîne est indétectable.

    Ce test documente la vulnérabilité au lieu de la supposer corrigée -- s'il se
    mettait un jour à échouer, cela voudrait dire que le hachage seul suffit, et
    il faudrait comprendre pourquoi avant de se réjouir.
    """
    db = str(tmp_path / "audit.db")
    log = AuditLog(db, signer=NullSigner())
    _sample_log(log)
    assert log.verify_integrity().ok is True

    _reforge_chain(db, 1, {"type": "tool_call", "tool": "close_ticket", "decision": "allow"})

    report = AuditLog(db, signer=NullSigner()).verify_integrity()
    assert report.ok is True, "sans signature, la reforge doit passer -- c'est la faille"
    assert report.signature_mode == SIGNATURE_MODE_NONE
    assert report.is_signed is False, "un journal non signé ne doit jamais se déclarer signé"


def test_forged_chain_is_rejected_when_signed(tmp_path):
    """Le correctif : la même attaque, sur un journal signé, est rejetée."""
    db = str(tmp_path / "audit.db")
    signer = _signer(tmp_path)
    log = AuditLog(db, signer=signer)
    _sample_log(log)

    before = log.verify_integrity()
    assert before.ok is True
    assert before.is_signed is True
    assert before.signatures_verified == 3

    _reforge_chain(db, 1, {"type": "tool_call", "tool": "close_ticket", "decision": "allow"})

    report = AuditLog(db, signer=signer).verify_integrity()
    assert report.ok is False
    assert report.first_bad_entry == 1
    assert "signature" in report.reason


def test_public_key_alone_verifies_but_cannot_write(tmp_path):
    """Ce que l'asymétrique apporte : un tiers vérifie sans pouvoir forger."""
    db = str(tmp_path / "audit.db")
    _sample_log(AuditLog(db, signer=_signer(tmp_path)))

    auditor = load_signer(private_key_path=tmp_path / "absente", public_key_path=tmp_path / "k.pub")
    auditor_log = AuditLog(db, signer=auditor)

    assert auditor_log.verify_integrity().ok is True
    with pytest.raises(AuditSigningError):
        auditor_log.log({"type": "entree_forgee_par_l_auditeur"})


def test_signature_from_another_key_is_rejected(tmp_path):
    """Un attaquant qui signe avec SA clé ne passe pas la vérification."""
    db = str(tmp_path / "audit.db")
    _sample_log(AuditLog(db, signer=_signer(tmp_path)))

    other = tmp_path / "other"
    other.mkdir()
    report = AuditLog(db, signer=_signer(other)).verify_integrity()
    assert report.ok is False
    assert "signature" in report.reason


def test_append_only_triggers_block_update_and_delete(tmp_path):
    """Deuxième couche : le moteur SQLite refuse lui-même toute réécriture.

    Ça n'arrête pas l'attaquant du test précédent (il supprime le trigger), mais
    ça arrête un bug, un script maladroit ou une injection SQL -- et ça coûte
    deux lignes de schéma.
    """
    db = str(tmp_path / "audit.db")
    log = AuditLog(db, signer=NullSigner())
    log.log({"type": "test"})

    con = sqlite3.connect(db)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        con.execute("UPDATE audit_log SET event = '{}' WHERE id = 1")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        con.execute("DELETE FROM audit_log WHERE id = 1")
    con.close()


def test_missing_signature_is_rejected_when_a_key_is_configured(tmp_path):
    """Un journal partiellement signé n'est pas un journal signé."""
    db = str(tmp_path / "audit.db")
    signer = _signer(tmp_path)
    log = AuditLog(db, signer=signer)
    log.log({"type": "test"})

    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER IF EXISTS audit_log_append_only_update")
    con.execute("UPDATE audit_log SET signature = NULL WHERE id = 1")
    con.commit()
    con.close()

    report = AuditLog(db, signer=signer).verify_integrity()
    assert report.ok is False
    assert "absente" in report.reason


def test_require_signature_fails_loudly_when_no_key(tmp_path, monkeypatch):
    """Perdre sa clé ne doit pas dégrader en silence vers un journal non signé."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_AUDIT_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("AEGIS_AUDIT_PUBLIC_KEY", raising=False)
    with pytest.raises(AuditSigningError):
        AuditLog(":memory:", require_signature=True)


def test_le_journal_est_utilisable_depuis_un_autre_thread():
    """Défaut trouvé au lot 8, sur un vrai serveur.

    Un `AegisGuard` partagé, construit à l'import d'une application FastAPI,
    plantait dès qu'un endpoint synchrone était servi depuis le pool de threads
    de Starlette :

        sqlite3.ProgrammingError: SQLite objects created in a thread can only be
        used in that same thread.

    Ce n'était pas un défaut de l'endpoint. N'importe quel hôte multi-thread --
    c'est-à-dire à peu près tous -- aurait rencontré la même chose, et une
    couche annoncée « branchable sur n'importe quel orchestrateur » ne peut pas
    exiger d'être appelée depuis le thread qui l'a construite.
    """
    import threading

    journal = AuditLog()
    erreurs: list[Exception] = []

    def ecrire():
        try:
            journal.log({"type": "test", "thread": threading.get_ident()})
        except Exception as e:  # noqa: BLE001 - c'est le sujet du test
            erreurs.append(e)

    fil = threading.Thread(target=ecrire)
    fil.start()
    fil.join()

    assert erreurs == [], erreurs
    assert len(journal.all_entries()) == 1


def test_des_ecritures_concurrentes_ne_cassent_pas_la_chaine():
    """Lever la contrainte de thread sans verrou serait pire que le bug.

    `log()` fait lire-le-dernier-hash PUIS insérer. Deux threads entrelacés
    chaîneraient deux entrées sur le même prédécesseur : la chaîne d'audit
    casse, la preuve devient invalide, et le résultat est indiscernable d'une
    falsification. C'est pour ça que le verrou couvre la séquence entière et pas
    seulement l'INSERT.
    """
    import threading

    journal = AuditLog()
    fils = [
        threading.Thread(target=lambda n=n: journal.log({"type": "test", "n": n}))
        for n in range(40)
    ]
    for f in fils:
        f.start()
    for f in fils:
        f.join()

    entrees = journal.all_entries()
    assert len(entrees) == 40
    # Chaque entrée doit chaîner sur la précédente : aucun prev_hash dupliqué.
    prevs = [e.prev_hash for e in entrees]
    assert len(set(prevs)) == len(prevs)
    assert journal.verify_integrity().ok
