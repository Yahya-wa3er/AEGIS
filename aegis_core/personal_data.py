"""
Séparation des données personnelles et du journal d'audit (correctif P1-7).

La contradiction
----------------
Le journal d'audit est **immuable par construction** : c'est ce qui fait sa
valeur de preuve. Il journalisait aussi les paramètres d'outils *en clair* --
adresses email, corps de messages, identifiants clients.

Un registre immuable rempli de données personnelles est en tension directe avec
le droit à l'effacement (RGPD, article 17). On ne peut pas supprimer une entrée
sans casser la chaîne, donc sans détruire la preuve ; et on ne peut pas
conserver la donnée sans manquer à l'obligation. C'est la première question que
posera le DPO d'un client, et elle n'a pas de bonne réponse une fois le système
en production : ça se conçoit au début, ça se rétrofitte très mal.

La séparation
-------------
Le journal ne contient plus que des **jetons** : `[EMAIL:pd_3f9a…]` à la place
de `m.durand@example.com`. Le jeton est un HMAC-SHA256 de la valeur, avec une
clé que le journal ne détient pas en clair.

Les valeurs elles-mêmes vivent dans un **coffre séparé** (`PersonalDataVault`,
une base distincte), effaçable ligne par ligne. Effacer une personne consiste à
supprimer ses valeurs du coffre : la chaîne d'audit n'a jamais couvert que les
jetons, elle reste donc intacte et vérifiable.

On garde ainsi les deux propriétés qui semblaient s'exclure :

* **la preuve** -- on démontre toujours qu'un événement a eu lieu, à telle date,
  et qu'il n'a pas été modifié depuis ;
* **l'effacement** -- le contenu personnel disparaît réellement.

Le jeton est déterministe : la même adresse produit toujours le même jeton, ce
qui permet de corréler des événements sans jamais lire la donnée. C'est aussi ce
qui rend l'effacement possible -- on retrouve toutes les occurrences d'une
personne à partir de sa valeur.

Ce que ça ne fait pas
---------------------
Un jeton déterministe reste vulnérable à une attaque par dictionnaire si la clé
HMAC fuite : l'espace des adresses email est petit. La clé doit donc être
traitée comme la clé de signature -- idéalement dans un KMS, pas sur le disque à
côté du coffre. Et si la donnée personnelle apparaît dans un champ qu'aucun
motif ne reconnaît (un identifiant métier, un nom propre), elle passe en clair :
c'est la limite du détecteur regex, documentée dans le README.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import sqlite3
from dataclasses import dataclass

from aegis_core.pii_detector import PII_PATTERNS, PiiDetector

logger = logging.getLogger(__name__)

ENV_VAULT_KEY = "AEGIS_PERSONAL_DATA_KEY"
TOKEN_PREFIX = "pd_"
TOKEN_LENGTH = 16  # 64 bits d'empreinte : assez pour ne pas collisionner ici

# Reconstruit à partir des mêmes motifs que le détecteur, pour qu'il n'existe
# qu'une seule définition de « ce qui est une donnée personnelle ».
_COMPILED_PII = tuple((label, re.compile(pattern)) for label, pattern in PII_PATTERNS)
_TOKEN_RE = re.compile(rf"\[([A-Z_]+):({TOKEN_PREFIX}[0-9a-f]+)\]")


@dataclass(frozen=True)
class TokenizationResult:
    text: str
    tokens: dict[str, str]  # jeton -> valeur d'origine
    categories: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return bool(self.tokens)


class PersonalDataVault:
    """Coffre séparé et effaçable des valeurs personnelles.

    Base distincte du journal d'audit -- c'est le point : les deux doivent
    pouvoir être supprimées indépendamment. Le coffre est mutable et effaçable,
    le journal est immuable et signé.
    """

    def __init__(self, db_path: str = ":memory:", key: bytes | None = None):
        self.db_path = db_path
        self._key = key or self._load_key()
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS personal_data (
                token TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                value TEXT NOT NULL,
                first_seen REAL NOT NULL
            )
            """
        )
        self._conn.commit()

    @staticmethod
    def _load_key() -> bytes:
        raw = os.getenv(ENV_VAULT_KEY)
        if raw:
            return raw.encode("utf-8")
        # Sans clé configurée, on en tire une aléatoire : les jetons ne seront
        # pas stables d'un processus à l'autre, ce qui casse la corrélation mais
        # ne compromet rien. Le WARNING dit quoi faire -- silence ici
        # signifierait « tout va bien », ce qui serait faux.
        logger.warning(
            "Aucune clé de pseudonymisation (%s) : une clé éphémère est générée. "
            "Les jetons ne seront pas stables entre deux exécutions, et un "
            "effacement ne retrouvera pas les occurrences des exécutions passées.",
            ENV_VAULT_KEY,
        )
        return os.urandom(32)

    def tokenize(self, value: str) -> str:
        """Jeton déterministe d'une valeur, sous la clé du coffre."""
        digest = hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return TOKEN_PREFIX + digest[:TOKEN_LENGTH]

    def store(self, token: str, category: str, value: str) -> None:
        import time

        self._conn.execute(
            "INSERT OR IGNORE INTO personal_data (token, category, value, first_seen) VALUES (?, ?, ?, ?)",
            (token, category, value, time.time()),
        )
        self._conn.commit()

    def resolve(self, token: str) -> str | None:
        row = self._conn.execute("SELECT value FROM personal_data WHERE token = ?", (token,)).fetchone()
        return row[0] if row else None

    def erase_value(self, value: str) -> int:
        """Efface une valeur du coffre. Retourne le nombre de lignes supprimées.

        C'est l'opération « droit à l'effacement » : après elle, le journal
        d'audit contient toujours le jeton -- donc la preuve que l'événement a
        eu lieu et n'a pas été modifié -- mais plus personne ne peut remonter à
        la personne.
        """
        cursor = self._conn.execute("DELETE FROM personal_data WHERE token = ?", (self.tokenize(value),))
        self._conn.commit()
        return cursor.rowcount

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM personal_data").fetchone()[0])


class EventPseudonymizer:
    """Remplace les données personnelles d'un événement par des jetons.

    Parcourt récursivement l'événement (dictionnaires, listes, chaînes) et
    applique les mêmes motifs que `PiiDetector` -- une seule définition de ce
    qu'est une donnée personnelle, partagée entre l'assainissement des documents
    et la pseudonymisation du journal.
    """

    def __init__(self, vault: PersonalDataVault | None = None):
        self.vault = vault if vault is not None else PersonalDataVault()
        self._detector = PiiDetector()

    def tokenize_text(self, text: str) -> TokenizationResult:
        tokens: dict[str, str] = {}
        categories: list[str] = []

        def _replace(label: str, match: re.Match[str]) -> str:
            value = match.group(0)
            token = self.vault.tokenize(value)
            self.vault.store(token, label, value)
            tokens[token] = value
            if label not in categories:
                categories.append(label)
            return f"[{label}:{token}]"

        out = text
        for label, pattern in _COMPILED_PII:
            out = pattern.sub(lambda m, lbl=label: _replace(lbl, m), out)
        return TokenizationResult(text=out, tokens=tokens, categories=tuple(categories))

    def pseudonymize(self, event: object) -> object:
        """Version pseudonymisée d'un événement, prête à être journalisée."""
        if isinstance(event, str):
            return self.tokenize_text(event).text
        if isinstance(event, dict):
            return {key: self.pseudonymize(value) for key, value in event.items()}
        if isinstance(event, (list, tuple)):
            return [self.pseudonymize(item) for item in event]
        return event

    def resolve_event(self, event: object) -> object:
        """Rétablit les valeurs d'un événement, pour un opérateur autorisé.

        Un jeton dont la valeur a été effacée du coffre reste un jeton : c'est
        exactement le comportement attendu après un effacement.
        """
        if isinstance(event, str):
            return _TOKEN_RE.sub(
                lambda m: self.vault.resolve(m.group(2)) or m.group(0),
                event,
            )
        if isinstance(event, dict):
            return {key: self.resolve_event(value) for key, value in event.items()}
        if isinstance(event, (list, tuple)):
            return [self.resolve_event(item) for item in event]
        return event
