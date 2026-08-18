"""
Journal d'audit chaîné par hachage **et signé** (Ed25519).

Chaque entrée contient le hash de l'entrée précédente : falsifier ou supprimer
une entrée casse la chaîne pour toutes les suivantes. Chaque entrée porte en
outre une signature Ed25519 de son hash.

Pourquoi la signature est indispensable (correctif P0-2)
--------------------------------------------------------
La version précédente de ce module affirmait qu'une chaîne SHA-256 rendait la
falsification détectable. C'était faux contre un attaquant réel : il lui suffit
de recalculer toute la chaîne avec le même `hashlib`, puisque `verify_integrity`
recalcule exactement de la même façon. L'audit l'a démontré -- un virement de
50 000 € effacé, chaîne reforgée, intégrité rapportée `OK`.

La signature ferme cette porte : reforger les hachages reste possible, produire
des signatures valides ne l'est pas sans la clé privée. Et comme Ed25519 est
asymétrique, un tiers peut vérifier le journal avec la seule clé publique, sans
pouvoir y écrire (voir `aegis_core/signing.py`).

Trois couches, du plus faible au plus fort :

1. **Chaînage de hachage** -- détecte la modification naïve. Gratuit.
2. **Triggers SQLite append-only** -- `UPDATE` et `DELETE` sur la table sont
   refusés par le moteur lui-même. Arrête un bug, une injection SQL, un script
   maladroit. N'arrête pas quelqu'un qui supprime le trigger.
3. **Signature Ed25519** -- arrête la reforge. C'est la seule des trois qui
   résiste à un attaquant disposant d'un accès en écriture.

Ce qui reste non couvert, et qui doit être dit : un attaquant qui compromet le
processus **pendant** qu'il écrit signera ses propres entrées ; et la troncature
(suppression des N dernières entrées) reste indétectable sans ancrage externe
du hash de tête. Voir la docstring de `signing.py`.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field

from aegis_core.personal_data import EventPseudonymizer
from aegis_core.signing import (
    SIGNATURE_MODE_NONE,
    NullSigner,
    Signer,
    load_signer,
)

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64

# Le moteur refuse lui-même toute modification a posteriori. `RAISE(ABORT)`
# annule la transaction et remonte une sqlite3.IntegrityError côté Python.
_APPEND_ONLY_TRIGGERS = (
    """
    CREATE TRIGGER IF NOT EXISTS audit_log_append_only_update
    BEFORE UPDATE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log est append-only : UPDATE interdit');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_log_append_only_delete
    BEFORE DELETE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log est append-only : DELETE interdit');
    END
    """,
)


@dataclass(frozen=True)
class AuditEntry:
    """Une entrée immuable du journal d'audit, telle que lue depuis la base."""

    id: int
    timestamp: float
    event: dict[str, object]
    prev_hash: str
    hash: str
    signature: str | None = None


@dataclass(frozen=True)
class IntegrityReport:
    """Verdict détaillé de `verify_integrity()`.

    Un booléen ne suffisait plus : « intact » et « intact ET signé » ne sont pas
    la même affirmation, et le tableau de bord doit pouvoir dire laquelle des
    deux il montre. `signature_mode` vaut `unsigned` quand aucune clé n'était
    disponible -- dans ce cas `ok=True` signifie seulement « pas de falsification
    naïve », pas « preuve opposable ».
    """

    ok: bool
    first_bad_entry: int | None = None
    reason: str | None = None
    entries_checked: int = 0
    signature_mode: str = SIGNATURE_MODE_NONE
    signatures_verified: int = 0
    unsigned_entries: int = 0

    @property
    def is_signed(self) -> bool:
        return self.signature_mode != SIGNATURE_MODE_NONE and self.unsigned_entries == 0

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "first_bad_entry": self.first_bad_entry,
            "reason": self.reason,
            "entries_checked": self.entries_checked,
            "signature_mode": self.signature_mode,
            "signatures_verified": self.signatures_verified,
            "unsigned_entries": self.unsigned_entries,
            "is_signed": self.is_signed,
        }


class AuditLog:
    """Journal d'audit append-only, chaîné par hachage et signé Ed25519.

    Args:
        db_path: chemin SQLite. `:memory:` par défaut -- pratique pour les tests,
            mais **le journal ne survit alors pas au processus**. Un déploiement
            réel doit passer un chemin (voir `AegisConfig.audit_db_path`).
        signer: signataire à utiliser. `None` déclenche la résolution automatique
            (argument, environnement, `keys/`) via `signing.load_signer`.
        require_signature: refuse de démarrer si aucune clé privée n'est
            disponible, au lieu de retomber silencieusement en mode non signé.
        pseudonymizer: remplace les données personnelles par des jetons avant
            écriture (correctif P1-7). `None` active la pseudonymisation avec un
            coffre en mémoire ; passer `False` la désactive explicitement -- un
            journal en clair reste possible, mais ce doit être un choix.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        signer: Signer | None = None,
        *,
        require_signature: bool = False,
        pseudonymizer: EventPseudonymizer | bool | None = None,
    ):
        self.db_path = db_path
        if pseudonymizer is False:
            logger.warning(
                "Pseudonymisation DÉSACTIVÉE : le journal contiendra les données "
                "personnelles en clair. Un registre immuable rempli de données "
                "personnelles est en tension avec le droit à l'effacement (RGPD art. 17)."
            )
            self._pseudonymizer = None
        elif pseudonymizer in (None, True):
            self._pseudonymizer = EventPseudonymizer()
        else:
            self._pseudonymizer = pseudonymizer
        self._signer = signer if signer is not None else load_signer(required=require_signature)
        # `check_same_thread=False` + un verrou, et pas l'un sans l'autre.
        #
        # Défaut trouvé au lot 8 : un `AegisGuard` partagé, construit à l'import
        # d'un serveur web, plante dès qu'un endpoint synchrone est servi depuis
        # le pool de threads de Starlette --
        #
        #     sqlite3.ProgrammingError: SQLite objects created in a thread can
        #     only be used in that same thread.
        #
        # Ce n'était pas un défaut de l'endpoint : n'importe quel hôte
        # multi-thread, c'est-à-dire à peu près tous, aurait rencontré la même
        # chose. Une couche de sécurité annoncée « branchable sur n'importe quel
        # orchestrateur » ne peut pas exiger d'être appelée depuis le thread qui
        # l'a construite.
        #
        # Lever la contrainte de thread SANS sérialiser les écritures serait
        # pire que le bug : `log()` fait lire-le-dernier-hash puis insérer, et
        # deux threads entrelacés produiraient deux entrées chaînées sur le même
        # prédécesseur — une chaîne d'audit cassée, donc une preuve invalide,
        # indiscernable d'une falsification. Le verrou couvre la séquence
        # entière, pas seulement l'INSERT.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                event TEXT,
                prev_hash TEXT,
                hash TEXT,
                signature TEXT
            )
            """
        )
        self._migrate_legacy_schema()
        for trigger in _APPEND_ONLY_TRIGGERS:
            self._conn.execute(trigger)
        self._conn.commit()

    def _migrate_legacy_schema(self) -> None:
        """Ajoute la colonne `signature` à une base créée avant ce correctif.

        Les entrées existantes restent sans signature et seront comptées comme
        telles par `verify_integrity()` -- on ne prétend pas rétroactivement
        qu'un journal ancien était signé.
        """
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(audit_log)")}
        if "signature" not in columns:
            self._conn.execute("ALTER TABLE audit_log ADD COLUMN signature TEXT")
            logger.warning(
                "Base d'audit antérieure à la signature : colonne ajoutée. Les entrées "
                "déjà présentes resteront non signées et seront rapportées comme telles."
            )

    @property
    def signature_mode(self) -> str:
        return getattr(self._signer, "mode", SIGNATURE_MODE_NONE)

    def _last_hash(self) -> str:
        row = self._conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS_HASH

    @staticmethod
    def _compute_hash(timestamp: float, event: dict[str, object], prev_hash: str) -> str:
        payload = json.dumps({"timestamp": timestamp, "event": event, "prev_hash": prev_hash}, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @property
    def vault(self):
        """Coffre des données personnelles, ou None si la pseudonymisation est désactivée."""
        return self._pseudonymizer.vault if self._pseudonymizer else None

    def log(self, event: dict[str, object]) -> str:
        """Ajoute une entrée au journal et renvoie son hash.

        L'événement est pseudonymisé AVANT calcul du hash : la chaîne ne couvre
        donc jamais que des jetons. C'est ce qui permet d'effacer une personne du
        coffre sans invalider une seule signature (correctif P1-7).
        """
        if self._pseudonymizer is not None:
            event = self._pseudonymizer.pseudonymize(event)
        # Le verrou couvre lire-le-dernier-hash ET insérer. Le scinder en deux
        # sections critiques laisserait deux threads chaîner sur le même
        # prédécesseur, ce qui casse la chaîne d'audit -- et une chaîne cassée
        # est indiscernable d'une falsification.
        with self._lock:
            prev_hash = self._last_hash()
            timestamp = time.time()
            new_hash = self._compute_hash(timestamp, event, prev_hash)
            # On signe le hash : il couvre déjà (timestamp, event, prev_hash),
            # donc la signature lie l'entrée entière ET sa position dans la chaîne.
            signature = self._signer.sign(new_hash.encode("utf-8"))
            self._conn.execute(
                "INSERT INTO audit_log (timestamp, event, prev_hash, hash, signature) VALUES (?, ?, ?, ?, ?)",
                (timestamp, json.dumps(event, ensure_ascii=False), prev_hash, new_hash, signature),
            )
            self._conn.commit()
        return new_hash

    def all_entries(self) -> list[AuditEntry]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, timestamp, event, prev_hash, hash, signature FROM audit_log ORDER BY id ASC"
            ).fetchall()
        return [
            AuditEntry(id=r[0], timestamp=r[1], event=json.loads(r[2]), prev_hash=r[3], hash=r[4], signature=r[5])
            for r in rows
        ]

    def verify_integrity(self) -> IntegrityReport:
        """Recontrôle la chaîne ET les signatures, de bout en bout.

        La vérification de la chaîne seule ne prouve rien contre un attaquant qui
        la recalcule (voir docstring du module). C'est la signature qui porte la
        garantie -- et son absence est rapportée, jamais tue.
        """
        prev_hash = GENESIS_HASH
        entries = self.all_entries()
        signatures_verified = 0
        unsigned = 0

        for entry in entries:
            expected_hash = self._compute_hash(entry.timestamp, entry.event, prev_hash)
            if entry.prev_hash != prev_hash:
                return IntegrityReport(
                    ok=False, first_bad_entry=entry.id,
                    reason="chaînage rompu : prev_hash ne correspond pas à l'entrée précédente",
                    entries_checked=len(entries), signature_mode=self.signature_mode,
                    signatures_verified=signatures_verified, unsigned_entries=unsigned,
                )
            if expected_hash != entry.hash:
                return IntegrityReport(
                    ok=False, first_bad_entry=entry.id,
                    reason="hash recalculé différent : le contenu de l'entrée a été modifié",
                    entries_checked=len(entries), signature_mode=self.signature_mode,
                    signatures_verified=signatures_verified, unsigned_entries=unsigned,
                )

            if entry.signature is None:
                unsigned += 1
                if self.signature_mode != SIGNATURE_MODE_NONE:
                    return IntegrityReport(
                        ok=False, first_bad_entry=entry.id,
                        reason="signature absente alors qu'une clé est configurée",
                        entries_checked=len(entries), signature_mode=self.signature_mode,
                        signatures_verified=signatures_verified, unsigned_entries=unsigned,
                    )
            elif self._signer.verify(entry.hash.encode("utf-8"), entry.signature):
                signatures_verified += 1
            else:
                return IntegrityReport(
                    ok=False, first_bad_entry=entry.id,
                    reason="signature invalide : entrée forgée ou clé différente",
                    entries_checked=len(entries), signature_mode=self.signature_mode,
                    signatures_verified=signatures_verified, unsigned_entries=unsigned,
                )

            prev_hash = entry.hash

        return IntegrityReport(
            ok=True, entries_checked=len(entries), signature_mode=self.signature_mode,
            signatures_verified=signatures_verified, unsigned_entries=unsigned,
        )
