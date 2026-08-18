"""
Limitation de débit et jeton partagé sur les endpoints coûteux (OWASP LLM06).

Le problème concret
-------------------
Deux endpoints de la démonstration déclenchent de vrais appels LLM :
`/api/simulate/{mode}` et `/api/test-document`. Ni l'un ni l'autre n'avait
d'authentification ni de plafond. Publier l'URL de la démo, c'est publier une
facture OpenRouter que n'importe qui peut faire monter avec une boucle `curl`.

Ce n'est pas une faille théorique du produit : c'est *Unbounded Consumption*
appliqué à sa propre vitrine, et le README le classait « 🔴 absente » sans que
la démonstration en tire la conséquence.

Ce que ça fait
--------------
* **Un seau à jetons par client**, identifié par IP. Rechargé en continu, il
  autorise une rafale courte puis impose le rythme moyen configuré — un
  compteur par fenêtre fixe laisserait passer deux fois le quota à cheval sur
  deux fenêtres.
* **Un jeton partagé facultatif** (`AEGIS_DEMO_TOKEN`). Non défini, l'API reste
  ouverte : c'est le mode démonstration publique, et il est *choisi*. Défini,
  chaque appel coûteux doit présenter l'en-tête.

Ce que ça ne fait pas -- et il faut le dire
-------------------------------------------
L'état vit **en mémoire du processus**. Deux conséquences : un redémarrage remet
tous les compteurs à zéro, et derrière plusieurs répliques chaque instance
compte pour elle seule (le plafond réel est donc multiplié par le nombre de
répliques). Pour un déploiement sérieux, ça se met devant, dans le reverse proxy
ou un Redis partagé.

L'identification par IP est également faible : derrière un CGNAT, des visiteurs
distincts partagent un seau ; avec un pool d'adresses, un attaquant en obtient
plusieurs. C'est un garde-fou contre l'abus opportuniste et l'emballement
accidentel, pas contre un adversaire déterminé — la protection qui compte contre
lui reste le jeton partagé.

Pourquoi une limite par client ne suffit pas
--------------------------------------------
Un seau par IP borne ce que *chaque* visiteur consomme, jamais ce que la
facture totalise. À 10 appels/minute et 100 adresses, le plafond réel est de
1 000 appels/minute — c'est-à-dire aucun plafond. Or LLM06 parle de la
consommation agrégée, pas du rythme individuel.

D'où `BudgetGlobal` : un compteur d'appels sur fenêtre glissante, partagé par
tous les clients, qui coupe net quand l'enveloppe est épuisée. Les deux gardes
répondent à deux menaces différentes et aucune ne remplace l'autre — le seau
protège la disponibilité entre visiteurs, le budget protège le portefeuille.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field

ENV_TOKEN = "AEGIS_DEMO_TOKEN"
ENV_RATE = "AEGIS_RATE_PER_MINUTE"
ENV_BURST = "AEGIS_RATE_BURST"
ENV_BUDGET = "AEGIS_LLM_CALLS_PER_HOUR"
HEADER_TOKEN = "x-aegis-token"

DEFAULT_RATE_PER_MINUTE = 10.0
DEFAULT_BURST = 5

# Enveloppe globale par heure glissante, tous clients confondus.
#
# Le chiffre est un choix, pas une constante de la nature : 300 appels/heure
# couvre largement une visite guidée (un aller-retour du laboratoire de
# robustesse en consomme deux) tout en bornant la facture d'une journée
# d'exposition publique. Le régler à 0 désactive le budget — c'est le mode
# « je paie, j'assume », et il doit être explicite.
DEFAULT_CALLS_PER_HOUR = 300
BUDGET_WINDOW_SECONDS = 3600.0

# Au-delà, on oublie les seaux inactifs : la clé vient du client, donc le nombre
# de clés aussi. Un dictionnaire non borné rejouerait exactement le défaut qu'on
# vient de corriger sur l'état par session.
MAX_BUCKETS = 10_000
BUCKET_TTL_SECONDS = 900.0


@dataclass
class _Bucket:
    tokens: float
    last: float


@dataclass
class RateLimiter:
    """Seau à jetons par client, borné en nombre de seaux."""

    rate_per_minute: float = DEFAULT_RATE_PER_MINUTE
    burst: int = DEFAULT_BURST
    max_buckets: int = MAX_BUCKETS
    ttl_seconds: float = BUCKET_TTL_SECONDS
    clock: object = time.monotonic
    _buckets: dict[str, _Bucket] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _now(self) -> float:
        return float(self.clock())  # type: ignore[operator]

    def _expire(self, now: float) -> None:
        morts = [k for k, b in self._buckets.items() if now - b.last > self.ttl_seconds]
        for k in morts:
            del self._buckets[k]

    def _evict_overflow(self) -> None:
        """Filet de sécurité si le TTL ne suffit pas à contenir un pic.

        Appelé APRÈS insertion : purger avant laissait passer un seau de plus à
        chaque appel, et le dictionnaire s'installait durablement à `max + 1`.
        """
        if len(self._buckets) <= self.max_buckets:
            return
        anciens = sorted(self._buckets.items(), key=lambda kv: kv[1].last)
        for k, _ in anciens[: len(self._buckets) - self.max_buckets]:
            del self._buckets[k]

    def check(self, client: str) -> tuple[bool, float]:
        """Consomme un jeton. Retourne `(autorisé, secondes avant le prochain)`."""
        per_second = self.rate_per_minute / 60.0
        with self._lock:
            now = self._now()
            self._expire(now)
            bucket = self._buckets.get(client)
            if bucket is None:
                bucket = _Bucket(tokens=float(self.burst), last=now)
                self._buckets[client] = bucket
                self._evict_overflow()

            bucket.tokens = min(
                float(self.burst), bucket.tokens + (now - bucket.last) * per_second
            )
            bucket.last = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True, 0.0
            manque = 1.0 - bucket.tokens
            return False, manque / per_second if per_second > 0 else float("inf")

    def stats(self) -> dict[str, object]:
        with self._lock:
            return {
                "clients_suivis": len(self._buckets),
                "rate_per_minute": self.rate_per_minute,
                "burst": self.burst,
                "portee": "processus",
            }


@dataclass
class BudgetGlobal:
    """Plafond d'appels LLM sur fenêtre glissante, tous clients confondus.

    Fenêtre glissante et non compteur remis à zéro à l'heure ronde : ce dernier
    autorise deux fois l'enveloppe à cheval sur deux heures (59 min + 1 min),
    exactement le défaut que le seau à jetons évite côté client.

    L'état est en mémoire : après un redémarrage, l'enveloppe repart pleine.
    C'est une limite assumée pour une démonstration mono-processus ; un vrai
    garde-fou budgétaire vit chez le fournisseur (plafond de dépense sur la clé
    API), et ceci n'en est que le complément applicatif.
    """

    max_calls: int = DEFAULT_CALLS_PER_HOUR
    window_seconds: float = BUDGET_WINDOW_SECONDS
    clock: object = time.monotonic
    _appels: deque[float] = field(default_factory=deque)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _now(self) -> float:
        return float(self.clock())  # type: ignore[operator]

    def check(self) -> tuple[bool, float]:
        """Consomme une unité. Retourne `(autorisé, secondes avant libération)`."""
        if self.max_calls <= 0:
            return True, 0.0
        with self._lock:
            now = self._now()
            limite = now - self.window_seconds
            while self._appels and self._appels[0] <= limite:
                self._appels.popleft()
            if len(self._appels) >= self.max_calls:
                # Le plus ancien appel encore dans la fenêtre libère une place.
                return False, max(0.0, self._appels[0] + self.window_seconds - now)
            self._appels.append(now)
            return True, 0.0

    def stats(self) -> dict[str, object]:
        with self._lock:
            if self.max_calls <= 0:
                return {"actif": False, "max_par_heure": 0}
            now = self._now()
            limite = now - self.window_seconds
            while self._appels and self._appels[0] <= limite:
                self._appels.popleft()
            return {
                "actif": True,
                "consommes": len(self._appels),
                "max_par_heure": self.max_calls,
                "portee": "processus",
            }


def from_env() -> RateLimiter:
    """Construit le limiteur depuis l'environnement.

    Une valeur illisible fait tomber sur le défaut plutôt que de faire planter
    le serveur : une erreur de frappe dans une variable d'environnement ne doit
    pas empêcher la démonstration de démarrer, mais elle ne doit pas non plus
    désactiver silencieusement la limite.
    """
    def _nombre(nom: str, defaut: float) -> float:
        brut = os.getenv(nom)
        if not brut:
            return defaut
        try:
            valeur = float(brut)
        except ValueError:
            return defaut
        return valeur if valeur > 0 else defaut

    return RateLimiter(
        rate_per_minute=_nombre(ENV_RATE, DEFAULT_RATE_PER_MINUTE),
        burst=int(_nombre(ENV_BURST, DEFAULT_BURST)),
    )


def budget_from_env() -> BudgetGlobal:
    """Enveloppe globale depuis l'environnement.

    Contrairement à `from_env`, la valeur 0 est ici RETENUE et non remplacée par
    le défaut : désactiver le budget est un choix légitime (instance privée avec
    plafond de dépense côté fournisseur), et le silencieusement réactiver serait
    aussi trompeur que le silencieusement désactiver.
    """
    brut = os.getenv(ENV_BUDGET)
    if not brut:
        return BudgetGlobal()
    try:
        valeur = int(float(brut))
    except ValueError:
        return BudgetGlobal()
    return BudgetGlobal(max_calls=max(0, valeur))


def expected_token() -> str | None:
    """Jeton partagé attendu, ou None si la démo est ouverte (choix assumé)."""
    valeur = os.getenv(ENV_TOKEN, "").strip()
    return valeur or None
