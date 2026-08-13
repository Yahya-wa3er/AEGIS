"""
Signature Ed25519 du journal d'audit (correctif P0-2).

Le problème
-----------
Une chaîne de hachage SHA-256 **sans clé** ne protège que contre quelqu'un qui
modifie une entrée sans recalculer les hachages suivants. Un attaquant qui a
l'accès en écriture à la base -- le même accès qu'il lui faut pour falsifier
quoi que ce soit -- recalcule toute la chaîne avec le même `hashlib`, et
`verify_integrity()` ne peut pas voir la différence puisqu'il recalcule à
l'identique.

Démontré pendant l'audit : un virement de 50 000 € effacé du journal, chaîne
reforgée, intégrité rapportée `OK`.

La correction
-------------
Chaque entrée porte une **signature Ed25519 de son hash**. Le hash couvrant
déjà `(timestamp, event, prev_hash)`, signer le hash lie l'entrée entière et
sa position dans la chaîne. Un attaquant peut toujours recalculer les hachages,
mais il ne peut pas produire de signature valide sans la clé privée.

Pourquoi Ed25519 plutôt que HMAC
--------------------------------
HMAC casserait l'attaque tout aussi bien, avec la bibliothèque standard. Mais
il faut la clé secrète pour **vérifier**, donc un auditeur externe ne peut pas
contrôler le journal sans recevoir de quoi le forger.

Ed25519 sépare les deux rôles : la clé privée signe, la clé publique vérifie.
Tu peux publier la clé publique, un client ou un commissaire aux comptes vérifie
lui-même l'intégrité de ton journal, et personne d'autre que le détenteur de la
clé privée ne peut y écrire une ligne crédible. C'est ce qui fait passer le log
de « trace technique » à **preuve opposable** -- l'argument qui compte face à un
DPO ou dans un dossier de conformité.

Limite qui reste, et qu'il faut dire
------------------------------------
La signature protège contre la falsification *a posteriori*. Elle ne protège
pas contre un attaquant qui a compromis le processus **au moment où il écrit**
(il signera ses propres entrées avec la clé légitime), ni contre la suppression
des dernières entrées de la chaîne (troncature). Le premier cas relève de
l'isolation de la clé (HSM, KMS, service de signature séparé) ; le second, de
l'ancrage périodique du hash de tête dans un stockage externe append-only.
Aucun des deux n'est fait ici. C'est écrit pour ne pas être oublié.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

ENV_PRIVATE_KEY = "AEGIS_AUDIT_PRIVATE_KEY"
ENV_PUBLIC_KEY = "AEGIS_AUDIT_PUBLIC_KEY"
DEFAULT_PRIVATE_KEY = Path("keys/audit_ed25519")
DEFAULT_PUBLIC_KEY = Path("keys/audit_ed25519.pub")

SIGNATURE_MODE_ED25519 = "ed25519"
SIGNATURE_MODE_VERIFY_ONLY = "ed25519-verify-only"
SIGNATURE_MODE_NONE = "unsigned"

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover - dépend de l'environnement
    _CRYPTO_AVAILABLE = False
    logger.warning(
        "Le paquet 'cryptography' n'est pas installé -- le journal d'audit sera "
        "NON SIGNÉ. Voir requirements.txt et scripts/generate_audit_key.py."
    )


class AuditSigningError(RuntimeError):
    """Levée quand une clé est demandée mais inutilisable."""


class Signer(Protocol):
    """Ce dont `AuditLog` a besoin, et rien de plus."""

    mode: str

    def sign(self, payload: bytes) -> str | None: ...

    def verify(self, payload: bytes, signature: str | None) -> bool: ...


@dataclass(frozen=True)
class NullSigner:
    """Mode non signé, explicite.

    Utile pour les tests et pour rester rétrocompatible avec un journal existant,
    mais `verify_integrity()` le signale toujours : un journal non signé ne doit
    jamais pouvoir passer pour un journal signé.
    """

    mode: str = SIGNATURE_MODE_NONE

    def sign(self, payload: bytes) -> str | None:
        return None

    def verify(self, payload: bytes, signature: str | None) -> bool:
        # Sans clé, on ne peut rien affirmer. On refuse de valider une signature
        # présente plutôt que de la déclarer bonne par défaut.
        return signature is None


class Ed25519Signer:
    """Signe et vérifie avec une paire de clés Ed25519.

    Si seule la clé publique est fournie, l'objet est en mode **vérification
    seule** : il vérifie les signatures existantes mais ne peut pas en produire.
    C'est le mode d'un auditeur externe -- et c'est tout l'intérêt de
    l'asymétrique.
    """

    def __init__(self, private_key: object | None = None, public_key: object | None = None) -> None:
        if not _CRYPTO_AVAILABLE:
            raise AuditSigningError("Le paquet 'cryptography' est requis pour la signature Ed25519.")
        if private_key is None and public_key is None:
            raise AuditSigningError("Au moins une clé (privée ou publique) est nécessaire.")

        self._private = private_key
        self._public = public_key or (private_key.public_key() if private_key is not None else None)
        self.mode = SIGNATURE_MODE_ED25519 if private_key is not None else SIGNATURE_MODE_VERIFY_ONLY

    @property
    def can_sign(self) -> bool:
        return self._private is not None

    def sign(self, payload: bytes) -> str | None:
        if self._private is None:
            raise AuditSigningError(
                "Journal ouvert en vérification seule (clé publique uniquement) : "
                "impossible d'écrire une nouvelle entrée."
            )
        return self._private.sign(payload).hex()

    def verify(self, payload: bytes, signature: str | None) -> bool:
        if self._public is None or signature is None:
            return False
        try:
            self._public.verify(bytes.fromhex(signature), payload)
            return True
        except (InvalidSignature, ValueError):
            return False

    def public_key_hex(self) -> str:
        """Empreinte publiable de la clé -- à afficher dans un rapport d'audit."""
        raw = self._public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()


def generate_keypair() -> tuple[bytes, bytes]:
    """Génère une paire Ed25519 et la renvoie au format PEM (privée, publique)."""
    if not _CRYPTO_AVAILABLE:
        raise AuditSigningError("Le paquet 'cryptography' est requis pour générer une clé.")

    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # Pas de chiffrement de la clé au repos : ce serait un faux confort ici,
        # puisque la passphrase devrait vivre à côté pour un service non interactif.
        # La vraie réponse en production est un KMS/HSM (voir docstring du module).
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _read_private(path: Path) -> object:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _read_public(path: Path) -> object:
    return serialization.load_pem_public_key(path.read_bytes())


def load_signer(
    private_key_path: Path | str | None = None,
    public_key_path: Path | str | None = None,
    *,
    required: bool = False,
) -> Signer:
    """Construit le signataire à partir des chemins fournis, de l'environnement, ou des défauts.

    Ordre de résolution : argument explicite, puis variable d'environnement
    (`AEGIS_AUDIT_PRIVATE_KEY` / `AEGIS_AUDIT_PUBLIC_KEY`), puis `keys/`.

    `required=True` fait échouer bruyamment plutôt que de retomber en mode non
    signé -- c'est ce que branche `AegisConfig.require_signed_audit`. Sans ça, un
    déploiement qui perd sa clé continuerait à produire un journal sans
    signature, en silence, tout en affichant « journal signé » : exactement le
    genre de mensonge que ce lot corrige.
    """
    private_path = Path(private_key_path or os.getenv(ENV_PRIVATE_KEY) or DEFAULT_PRIVATE_KEY)
    public_path = Path(public_key_path or os.getenv(ENV_PUBLIC_KEY) or DEFAULT_PUBLIC_KEY)

    if not _CRYPTO_AVAILABLE:
        if required:
            raise AuditSigningError(
                "Signature du journal exigée, mais le paquet 'cryptography' n'est pas installé."
            )
        return NullSigner()

    try:
        if private_path.is_file():
            return Ed25519Signer(private_key=_read_private(private_path))
        if public_path.is_file():
            logger.warning(
                "Clé privée absente de '%s', clé publique trouvée : journal ouvert en "
                "VÉRIFICATION SEULE (aucune nouvelle entrée ne pourra être écrite).",
                private_path,
            )
            return Ed25519Signer(public_key=_read_public(public_path))
    except Exception as exc:
        if required:
            raise AuditSigningError(f"Clé de signature illisible ({private_path}) : {exc}") from exc
        logger.exception("Clé de signature illisible -- journal NON SIGNÉ.")
        return NullSigner()

    if required:
        raise AuditSigningError(
            f"Signature du journal exigée mais aucune clé trouvée (cherché : {private_path}, "
            f"{public_path}, ${ENV_PRIVATE_KEY}). Lance scripts/generate_audit_key.py."
        )

    logger.warning(
        "Aucune clé de signature trouvée (cherché : %s, %s, $%s) -- le journal d'audit "
        "sera NON SIGNÉ : détectable en cas de falsification naïve, reforgeable par un "
        "attaquant disposant d'un accès en écriture. Lance scripts/generate_audit_key.py.",
        private_path, public_path, ENV_PRIVATE_KEY,
    )
    return NullSigner()
