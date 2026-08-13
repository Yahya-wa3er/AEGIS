"""
Génère la paire de clés Ed25519 qui signe le journal d'audit (correctif P0-2).

    python -m scripts.generate_audit_key

Écrit `keys/audit_ed25519` (privée, permissions 0600) et `keys/audit_ed25519.pub`
(publique). Refuse d'écraser une clé existante : regénérer une clé invaliderait
d'un coup toutes les signatures déjà produites, et un journal qui ne se vérifie
plus est pire qu'un journal non signé -- il ressemble à un journal falsifié.

Que faire de ces deux fichiers
------------------------------
La clé **privée** ne doit jamais être versionnée (le `.gitignore` l'exclut) ni
quitter le serveur qui écrit le journal. En production elle n'a rien à faire sur
un disque : sa place est dans un KMS ou un HSM, ou derrière un service de
signature distinct du service applicatif -- de sorte qu'une compromission
d'AEGIS ne donne pas la capacité de réécrire son propre passé.

La clé **publique**, elle, est faite pour être diffusée. C'est elle qui permet à
un client, un auditeur ou un commissaire aux comptes de vérifier ton journal
sans pouvoir y écrire une ligne. C'est ce qui fait la différence entre une trace
technique et une preuve opposable.

Vérifier un journal sans la clé privée :

    from aegis_core.audit_log import AuditLog
    from aegis_core.signing import load_signer
    log = AuditLog("audit.db", signer=load_signer(public_key_path="audit_ed25519.pub"))
    print(log.verify_integrity())
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from aegis_core.signing import DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY, generate_keypair

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def main() -> int:
    private_path = Path(os.getenv("AEGIS_AUDIT_PRIVATE_KEY", DEFAULT_PRIVATE_KEY))
    public_path = Path(os.getenv("AEGIS_AUDIT_PUBLIC_KEY", DEFAULT_PUBLIC_KEY))

    for path in (private_path, public_path):
        if path.exists():
            logger.error(
                "'%s' existe déjà -- aucune clé générée.\n"
                "  Regénérer une clé invaliderait TOUTES les signatures déjà produites : "
                "le journal existant deviendrait invérifiable, ce qui est indiscernable "
                "d'une falsification.\n"
                "  Si tu veux vraiment repartir de zéro, déplace l'ancienne paire ET "
                "archive le journal qu'elle signait.",
                path,
            )
            return 1

    private_pem, public_pem = generate_keypair()

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    # Écriture puis restriction immédiate des permissions. On crée le fichier
    # avec O_CREAT|O_EXCL en 0600 plutôt que d'écrire puis chmod : entre les deux
    # il y aurait une fenêtre où la clé privée est lisible par tous.
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private_pem)
    public_path.write_bytes(public_pem)

    logger.info("Clé privée écrite : %s (permissions 0600 -- à ne jamais versionner)", private_path)
    logger.info("Clé publique écrite : %s (diffusable : elle permet de vérifier, pas de signer)", public_path)
    logger.info("Le journal d'audit sera signé automatiquement à la prochaine exécution.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
