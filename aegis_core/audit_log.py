"""
Journal d'audit signé par chaînage de hachage (SHA-256), façon Merkle log.

Chaque entrée contient le hash de l'entrée précédente : falsifier ou
supprimer une entrée casse la chaîne pour toutes les entrées suivantes, ce
qui rend la falsification détectable -- sans dépendance externe (pas de
blockchain, pas de service tiers, juste des maths).

Version de démo en SQLite (blueprint section 4.3) : en V1, remplacer par
PostgreSQL et ajouter des signatures Ed25519 par agent.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    """Une entrée immuable du journal d'audit, telle que lue depuis la base."""

    id: int
    timestamp: float
    event: dict[str, object]
    prev_hash: str
    hash: str


class AuditLog:
    """Journal d'audit append-only, chaîné par hachage SHA-256."""

    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                event TEXT,
                prev_hash TEXT,
                hash TEXT
            )
            """
        )
        self._conn.commit()

    def _last_hash(self) -> str:
        row = self._conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS_HASH

    @staticmethod
    def _compute_hash(timestamp: float, event: dict[str, object], prev_hash: str) -> str:
        payload = json.dumps({"timestamp": timestamp, "event": event, "prev_hash": prev_hash}, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def log(self, event: dict[str, object]) -> str:
        """Ajoute une entrée au journal et renvoie son hash."""
        prev_hash = self._last_hash()
        timestamp = time.time()
        new_hash = self._compute_hash(timestamp, event, prev_hash)
        self._conn.execute(
            "INSERT INTO audit_log (timestamp, event, prev_hash, hash) VALUES (?, ?, ?, ?)",
            (timestamp, json.dumps(event, ensure_ascii=False), prev_hash, new_hash),
        )
        self._conn.commit()
        return new_hash

    def all_entries(self) -> list[AuditEntry]:
        rows = self._conn.execute(
            "SELECT id, timestamp, event, prev_hash, hash FROM audit_log ORDER BY id ASC"
        ).fetchall()
        return [
            AuditEntry(id=r[0], timestamp=r[1], event=json.loads(r[2]), prev_hash=r[3], hash=r[4])
            for r in rows
        ]

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Recalcule la chaîne entière et vérifie qu'aucune entrée n'a été altérée."""
        prev_hash = GENESIS_HASH
        for entry in self.all_entries():
            expected_hash = self._compute_hash(entry.timestamp, entry.event, prev_hash)
            if expected_hash != entry.hash or entry.prev_hash != prev_hash:
                return False, entry.id
            prev_hash = entry.hash
        return True, None

    def tamper_with(self, entry_id: int, new_event: dict[str, object]) -> None:
        """Réservé à la démo : simule une falsification a posteriori d'une entrée."""
        self._conn.execute(
            "UPDATE audit_log SET event = ? WHERE id = ?",
            (json.dumps(new_event, ensure_ascii=False), entry_id),
        )
        self._conn.commit()