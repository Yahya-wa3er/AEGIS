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

Quels signaux ont le droit de bloquer
------------------------------------
Les trois signaux de contenu n'ont pas la même nature, et les traiter à
l'identique était une erreur mesurable.

Les **règles** sont déterministes et explicables. Mesure sur le corpus de
contrôle : 100 % de blocage des attaques, **0 %** de faux positifs.

Le **classifieur ML** et le **détecteur d'outliers** sont probabilistes. Mesure
sur le même corpus : **50 % de faux positifs chacun** -- un document légitime sur
deux neutralisé. Un rapport financier, un bulletin météo, une note RGPD, de la
documentation d'API.

`blocking_signals` ne contient donc que `rules` par défaut. Les deux autres
continuent de tourner, leur score est journalisé et affiché, et le journal
compte les cas où ils **auraient** bloqué (`would_have_blocked`) -- mais ils ne
neutralisent rien seuls.

Ce n'est pas une mise au rebut. Le corpus actuel ne peut pas mesurer ce que le
ML apporte vraiment : sa valeur est de généraliser à des formulations qu'aucune
règle n'anticipe, et douze payloads calibrés sur les règles ne testent pas cela.
Le compteur `would_have_blocked` est précisément ce qui permettra de lui rendre
le pouvoir de bloquer -- le jour où il montrera des détections que les règles
ratent, avec des chiffres plutôt qu'une intuition.

Un opérateur qui a mesuré son propre taux de faux positifs sur SON corpus peut
évidemment décider autrement :

    AegisConfig(blocking_signals=frozenset({"rules", "rag_outlier"}))

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

# Signaux capables de DÉCIDER un blocage. Les autres continuent de tourner et
# d'être journalisés, mais ne neutralisent rien -- ils informent.
SIGNAL_RULES = "rules"                # règles déterministes, explicables
SIGNAL_INJECTION_ML = "injection_ml"  # classifieur DistilBERT
SIGNAL_RAG_OUTLIER = "rag_outlier"    # distance au domaine documentaire

ALL_SIGNALS: frozenset[str] = frozenset({SIGNAL_RULES, SIGNAL_INJECTION_ML, SIGNAL_RAG_OUTLIER})

ENV_BLOCKING_SIGNALS = "AEGIS_BLOCKING_SIGNALS"
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

    # Par défaut, SEULES les règles déterministes bloquent (voir la note plus bas).
    blocking_signals: frozenset[str] = field(default_factory=lambda: frozenset({SIGNAL_RULES}))
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
        unknown_signals = set(self.blocking_signals) - ALL_SIGNALS
        if unknown_signals:
            raise ValueError(
                f"Signal(aux) inconnu(s) dans blocking_signals : {sorted(unknown_signals)}. "
                f"Valeurs acceptées : {sorted(ALL_SIGNALS)}."
            )

    def blocks(self, signal: str) -> bool:
        return signal in self.blocking_signals

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

            AEGIS_BLOCKING_SIGNALS=rules,rag_outlier
            AEGIS_REQUIRED_DETECTORS=rag_outlier,behavior
            AEGIS_AUDIT_DB=/var/lib/aegis/audit.db
            AEGIS_REQUIRE_SIGNED_AUDIT=1
        """
        raw = os.getenv(ENV_REQUIRED_DETECTORS, "")
        required = frozenset(name.strip() for name in raw.split(",") if name.strip())
        raw_signals = os.getenv(ENV_BLOCKING_SIGNALS, "")
        signals = frozenset(name.strip() for name in raw_signals.split(",") if name.strip())
        return cls(
            blocking_signals=signals or frozenset({SIGNAL_RULES}),
            required_detectors=required,
            audit_db_path=os.getenv(ENV_AUDIT_DB, ":memory:"),
            require_signed_audit=os.getenv(ENV_REQUIRE_SIGNED_AUDIT, "").lower() in _TRUTHY,
        )
