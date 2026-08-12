"""
Représentation numérique d'une "session" comportementale d'agent (blueprint,
section 4.4 - détection d'anomalies comportementales).

Une session = les N dernières requêtes traitées par un agent, chacune résumée
par l'action dominante qu'elle a déclenchée (aucun outil, ou un outil précis)
et, si pertinent, un montant. C'est volontairement la même structure de
features qu'on utiliserait pour des transactions bancaires (cf. le Beta-VAE
de détection de fraude) -- seul le domaine change.

Ce module est importé À LA FOIS par la génération de données synthétiques,
l'entraînement, et le détecteur en production : une seule fonction
d'encodage, jamais dupliquée, pour éviter que features d'entraînement et
features d'inférence divergent silencieusement (la même classe de bug que la
divergence entre `repo/` et `aegis_core/` qu'on a déjà croisée sur ce
projet).
"""
from __future__ import annotations

from dataclasses import dataclass

ACTIONS: tuple[str, ...] = ("no_action", "close_ticket", "send_email", "transfer_funds")
ACTION_INDEX: dict[str, int] = {action: i for i, action in enumerate(ACTIONS)}

SESSION_LENGTH = 5  # nombre de requêtes consécutives résumées dans une session
FEATURE_DIM = len(ACTIONS) + 1  # one-hot de l'action + montant normalisé
INPUT_DIM = SESSION_LENGTH * FEATURE_DIM

# Cap de normalisation du montant : au-delà, on sature à 1.0. Les sessions
# normales n'ont jamais de transfer_funds (voir generate_behavior_sessions.py),
# donc ce cap ne sert qu'à distinguer les montants anormaux entre eux.
MAX_AMOUNT = 50_000.0


@dataclass(frozen=True)
class ActionEvent:
    """Une requête résumée par l'action dominante qu'elle a déclenchée."""

    action: str
    amount: float = 0.0

    def __post_init__(self) -> None:
        if self.action not in ACTION_INDEX:
            raise ValueError(f"Action inconnue : '{self.action}' (attendu parmi {ACTIONS})")


def encode_event(event: ActionEvent) -> list[float]:
    """Encode un seul événement en vecteur one-hot(action) + montant normalisé."""
    vector = [0.0] * FEATURE_DIM
    vector[ACTION_INDEX[event.action]] = 1.0
    vector[-1] = min(event.amount / MAX_AMOUNT, 1.0)
    return vector


def encode_session(events: list[ActionEvent]) -> list[float]:
    """
    Encode une session (liste d'événements) en un vecteur de taille fixe
    `INPUT_DIM`, en tronquant ou en complétant avec du "no_action" (padding
    neutre : ne rien faire n'est jamais suspect en soi).
    """
    padded = list(events[:SESSION_LENGTH])
    while len(padded) < SESSION_LENGTH:
        padded.append(ActionEvent(action="no_action", amount=0.0))

    flat: list[float] = []
    for event in padded:
        flat.extend(encode_event(event))
    return flat
