"""
Configuration d'AEGIS : mode de défaillance, détecteurs exigés, journal d'audit.

Pourquoi ce module (correctif P0-4)
-----------------------------------
Jusqu'ici, un détecteur dont le modèle n'était pas entraîné renvoyait
`risk=0.0` sur **tout**, avec un simple WARNING dans les logs. Sur un clone
frais du dépôt, trois couches de protection sur cinq étaient donc inertes -- et
le tableau de bord affichait « ✔ Comportement jugé normal » pour des capteurs
éteints.

Deux problèmes distincts, corrigés ici.

**Le vocabulaire.** Le code appelait ce comportement « fail-safe ». En sécurité,
un composant qui laisse tout passer quand il défaille est **fail-open** --
l'exact opposé. C'est un choix parfaitement défendable pour une couche non
bloquante, mais il doit être nommé correctement et assumé, pas subi.

**Le comportement.** Il faut pouvoir exiger qu'un détecteur soit là. C'est le
rôle de `required_detectors` : chaque détecteur qui y figure doit être
opérationnel, sinon `AegisGuard` refuse de démarrer -- **au démarrage**, pas
silencieusement à la première requête, quand il est déjà trop tard.

Choix de conception : `required_detectors` est **vide par défaut**. Rien ne
bloque tant que tu n'as pas déclaré ce que tu exiges. On obtient la sémantique
fail-closed là où elle est demandée, sans transformer un `git clone` en mur.
C'est à l'opérateur de dire ce qui est indispensable à SON déploiement -- AEGIS
ne peut pas le deviner, et prétendre le deviner serait une autre forme de
mensonge.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# Noms canoniques des détecteurs, utilisés dans `required_detectors` et dans le
# rapport de robustesse. Ce sont ces chaînes que le tableau de bord affiche.
DETECTOR_INJECTION_ML = "injection_ml"
DETECTOR_RAG_OUTLIER = "rag_outlier"
DETECTOR_BEHAVIOR = "behavior"

ALL_DETECTORS: frozenset[str] = frozenset(
    {DETECTOR_INJECTION_ML, DETECTOR_RAG_OUTLIER, DETECTOR_BEHAVIOR}
)

ENV_REQUIRED_DETECTORS = "AEGIS_REQUIRED_DETECTORS"
ENV_AUDIT_DB = "AEGIS_AUDIT_DB"
ENV_REQUIRE_SIGNED_AUDIT = "AEGIS_REQUIRE_SIGNED_AUDIT"

_TRUTHY = {"1", "true", "yes", "on", "oui"}


class DetectorUnavailableError(RuntimeError):
    """Levée au démarrage quand un détecteur exigé n'est pas opérationnel."""


@dataclass(frozen=True)
class AegisConfig:
    """Ce qu'un déploiement exige d'AEGIS.

    Args:
        required_detectors: détecteurs sans lesquels AEGIS refuse de démarrer.
            Vide par défaut -- voir la docstring du module.
        audit_db_path: chemin du journal. `:memory:` par défaut, ce qui veut dire
            que **le journal ne survit pas au processus** : acceptable pour la
            démo et les tests, jamais pour un déploiement.
        require_signed_audit: exige une clé de signature Ed25519 disponible.
            Sans ça, un déploiement qui perd sa clé continuerait à produire un
            journal non signé, en silence.
        audit_private_key_path / audit_public_key_path: surchargent la résolution
            automatique (voir `aegis_core.signing.load_signer`).
    """

    required_detectors: frozenset[str] = field(default_factory=frozenset)
    audit_db_path: str = ":memory:"
    require_signed_audit: bool = False
    audit_private_key_path: Path | None = None
    audit_public_key_path: Path | None = None

    def __post_init__(self) -> None:
        unknown = set(self.required_detectors) - ALL_DETECTORS
        if unknown:
            raise ValueError(
                f"Détecteur(s) inconnu(s) dans required_detectors : {sorted(unknown)}. "
                f"Valeurs acceptées : {sorted(ALL_DETECTORS)}."
            )

    @property
    def fail_mode(self) -> str:
        """Étiquette lisible du comportement en cas de détecteur manquant.

        « fail-open » n'est pas un gros mot : c'est la description exacte de ce
        qui se passe quand rien n'est exigé. Le dire permet de le choisir.
        """
        return "closed" if self.required_detectors else "open"

    @classmethod
    def from_env(cls) -> AegisConfig:
        """Construit la configuration depuis l'environnement.

            AEGIS_REQUIRED_DETECTORS=rag_outlier,behavior
            AEGIS_AUDIT_DB=/var/lib/aegis/audit.db
            AEGIS_REQUIRE_SIGNED_AUDIT=1
        """
        raw = os.getenv(ENV_REQUIRED_DETECTORS, "")
        required = frozenset(name.strip() for name in raw.split(",") if name.strip())
        return cls(
            required_detectors=required,
            audit_db_path=os.getenv(ENV_AUDIT_DB, ":memory:"),
            require_signed_audit=os.getenv(ENV_REQUIRE_SIGNED_AUDIT, "").lower() in _TRUTHY,
        )
