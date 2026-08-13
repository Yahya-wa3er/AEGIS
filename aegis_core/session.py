"""
Portée de l'état par session (correctif P1-5).

Le problème
-----------
La fenêtre comportementale d'AEGIS était indexée par **nom d'agent** :

    self._behavior_windows: dict[str, list[ActionEvent]] = {}
    window = self._behavior_windows.setdefault(agent_name, [])

Sur la démo, où un seul utilisateur parle à un seul `SupportAgent`, ça se
remarque à peine. En production, tous les utilisateurs de `SupportAgent`
partagent la même fenêtre de cinq événements. Deux conséquences, et aucune
n'est théorique :

* **dilution.** Un attaquant fait passer sa séquence sensible pendant que le
  trafic légitime remplit la fenêtre : son comportement n'apparaît jamais comme
  une suite anormale, parce que la suite qu'observe le détecteur n'est celle de
  personne en particulier.
* **contamination.** Symétriquement, les actions d'un utilisateur font monter le
  score d'un autre. Un signal de sécurité qui accuse la mauvaise personne est
  pire qu'un signal absent : il coûte la confiance qu'on lui accordait.

C'est aussi, plus prosaïquement, une fuite de contexte entre clients. Un
déploiement multi-tenant qui mélange l'état comportemental de deux clients dans
le même dictionnaire a un problème d'isolation avant d'avoir un problème de
détection.

La clé
------
`(tenant, agent, session_id)`. Les trois comptent : le même agent chez deux
clients n'est pas le même agent, et deux sessions du même utilisateur ne
devraient pas non plus se contaminer -- une session est l'unité naturelle de
« ce que quelqu'un est en train de faire ».

Quand le contexte ne porte pas de `session_id`, on ne l'invente pas : la clé est
marquée **anonyme**, l'appelant est prévenu une fois, et `robustness_report()`
compte ces fenêtres séparément. Le comportement dégradé (partage) est alors
exactement l'ancien -- mais il est *visible*, ce qui est toute la différence.

La borne
--------
Un dictionnaire indexé par session est un dictionnaire qui grandit avec le
trafic. Sans borne, c'est une fuite mémoire à croissance linéaire -- et, comme
la clé vient de données contrôlées par le client, un vecteur d'épuisement de
ressources (OWASP LLM06, *Unbounded Consumption*) : il suffit d'envoyer des
`session_id` tous différents.

Deux garde-fous, donc : une **expiration** (une session inactive depuis
`ttl_seconds` n'apprend plus rien à personne) et un **plafond** (au-delà de
`max_sessions`, la session la moins récemment utilisée est évincée). Les deux
sont comptés et remontés dans le rapport : une éviction massive est un signal
d'exploitation, pas une statistique de fonctionnement normal.
"""
from __future__ import annotations

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Iterator, TypeVar

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 30 * 60
DEFAULT_MAX_SESSIONS = 10_000

DEFAULT_TENANT = "default"
UNKNOWN_AGENT = "unknown"
ANONYMOUS_SESSION = "anonymous"

# Plusieurs orchestrateurs, plusieurs conventions. On accepte les noms courants
# plutôt que d'imposer le nôtre : l'intégration ne doit pas buter sur un nom de
# clé, sans quoi elle se fera « plus tard » et la fenêtre restera partagée.
_SESSION_CTX_KEYS = ("session_id", "session", "conversation_id", "thread_id")
_TENANT_CTX_KEYS = ("tenant", "tenant_id", "org_id", "organisation")

T = TypeVar("T")


@dataclass(frozen=True)
class SessionKey:
    """Portée d'un état conversationnel : un tenant, un agent, une session."""

    tenant: str = DEFAULT_TENANT
    agent: str = UNKNOWN_AGENT
    session_id: str = ANONYMOUS_SESSION
    identified: bool = True

    @property
    def anonymous(self) -> bool:
        """Vrai quand aucun identifiant de session n'a été fourni.

        La fenêtre est alors partagée par tous les appels du même agent chez le
        même tenant -- c'est-à-dire l'ancien comportement, mais annoncé.
        """
        return not self.identified

    @classmethod
    def from_ctx(cls, ctx: dict[str, object] | None, agent: str | None = None) -> SessionKey:
        ctx = ctx or {}
        tenant = _first_str(ctx, _TENANT_CTX_KEYS) or DEFAULT_TENANT
        session_id = _first_str(ctx, _SESSION_CTX_KEYS)
        resolved_agent = agent or _first_str(ctx, ("agent", "agent_name")) or UNKNOWN_AGENT
        return cls(
            tenant=tenant,
            agent=resolved_agent,
            session_id=session_id or ANONYMOUS_SESSION,
            identified=session_id is not None,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "tenant": self.tenant,
            "agent": self.agent,
            "session_id": self.session_id,
            "identified": self.identified,
        }

    def __str__(self) -> str:  # pragma: no cover - confort de log
        return f"{self.tenant}/{self.agent}/{self.session_id}"


def _first_str(ctx: dict[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = ctx.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


class SessionStore:
    """Dictionnaire d'états conversationnels, borné en taille et dans le temps.

    Générique à dessein : il stocke ce qu'on lui donne (aujourd'hui la fenêtre
    comportementale) sans rien savoir de la détection. Ce qu'il garantit, c'est
    qu'un état par session ne devienne pas un état sans limite.
    """

    def __init__(
        self,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ):
        if max_sessions < 1:
            raise ValueError("max_sessions doit valoir au moins 1")
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        # Ordonné par récence d'usage : les entrées expirables sont donc
        # toujours en tête, ce qui rend la purge O(nombre d'expirés) et non
        # O(nombre de sessions) à chaque appel.
        self._entries: OrderedDict[SessionKey, tuple[float, object]] = OrderedDict()
        self._evicted = 0
        self._expired = 0
        self._anonymous_warned = False

    # -- accès -------------------------------------------------------------

    def get(self, key: SessionKey, factory: Callable[[], T]) -> T:
        """État de cette session, créé par `factory` s'il n'existe pas encore."""
        if key.anonymous and not self._anonymous_warned:
            self._anonymous_warned = True
            logger.warning(
                "Aucun identifiant de session dans le contexte (clés acceptées : %s) : "
                "l'état comportemental est PARTAGÉ entre tous les appelants de "
                "l'agent « %s ». Un attaquant peut diluer son profil dans le "
                "trafic légitime, ou faire monter le score de quelqu'un d'autre.",
                ", ".join(_SESSION_CTX_KEYS),
                key.agent,
            )
        self._expire()
        existing = self._entries.get(key)
        if existing is not None:
            self._entries.move_to_end(key)
            self._entries[key] = (self._clock(), existing[1])
            return existing[1]  # type: ignore[return-value]
        value = factory()
        self._entries[key] = (self._clock(), value)
        self._evict_overflow()
        return value

    def peek(self, key: SessionKey) -> object | None:
        """Lecture sans création ni rafraîchissement (tests, introspection)."""
        entry = self._entries.get(key)
        return entry[1] if entry else None

    def drop(self, key: SessionKey) -> bool:
        """Oublie une session -- par exemple à la déconnexion de l'utilisateur."""
        return self._entries.pop(key, None) is not None

    def keys(self) -> Iterator[SessionKey]:
        return iter(tuple(self._entries.keys()))

    def __len__(self) -> int:
        return len(self._entries)

    # -- bornes ------------------------------------------------------------

    def _expire(self) -> None:
        if self.ttl_seconds <= 0:
            return
        deadline = self._clock() - self.ttl_seconds
        while self._entries:
            key, (last_seen, _) = next(iter(self._entries.items()))
            if last_seen > deadline:
                break
            self._entries.pop(key)
            self._expired += 1

    def _evict_overflow(self) -> None:
        while len(self._entries) > self.max_sessions:
            self._entries.popitem(last=False)
            self._evicted += 1
            if self._evicted == 1 or self._evicted % 1000 == 0:
                logger.warning(
                    "Plafond de sessions atteint (%d) : éviction de la session la moins "
                    "récente (%d au total). Un pic d'évictions peut signaler un "
                    "épuisement de ressources par identifiants de session jetables.",
                    self.max_sessions,
                    self._evicted,
                )

    # -- rapport -----------------------------------------------------------

    def stats(self) -> dict[str, object]:
        """Ce qu'un opérateur doit pouvoir lire sans ouvrir le code.

        `degraded` est le chiffre qui compte : tant qu'il est vrai, au moins une
        fenêtre est partagée et le détecteur comportemental observe une suite
        d'actions qui n'appartient à personne.
        """
        self._expire()
        anonymous = sum(1 for key in self._entries if key.anonymous)
        return {
            "keyed_by": ["tenant", "agent", "session_id"],
            "active": len(self._entries),
            "anonymous": anonymous,
            "identified": len(self._entries) - anonymous,
            "degraded": anonymous > 0,
            "evicted": self._evicted,
            "expired": self._expired,
            "max_sessions": self.max_sessions,
            "ttl_seconds": self.ttl_seconds,
        }
