"""
Outils "métier" simulés que l'agent peut appeler.

Ces outils ne font rien de réel (pas de vraie transaction bancaire, pas de
vrai email envoyé) : ils journalisent simplement l'appel dans EXECUTED_ACTIONS.
Cette liste sert de "preuve" pendant la démo -- elle permet de vérifier si une
action sensible a réellement été déclenchée, avec ou sans la protection AEGIS.

Volontairement, aucun contrôle de permission n'est fait ici : la sécurité doit
venir entièrement de la couche AEGIS (aegis_core/), pas des outils eux-mêmes.
C'est le principe de séparation des responsabilités décrit dans le blueprint
(section 3 - Vue d'ensemble de l'architecture).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("victim.tools")


@dataclass(frozen=True)
class ToolCallRecord:
    """Trace immuable d'un appel d'outil, utilisée comme preuve pendant la démo."""

    tool: str
    params: dict[str, object] = field(default_factory=dict)


EXECUTED_ACTIONS: list[ToolCallRecord] = []


def reset() -> None:
    """Vide l'historique des actions -- appelé au début de chaque run de démo."""
    EXECUTED_ACTIONS.clear()


def send_email(to: str, body: str) -> str:
    """Simule l'envoi d'un email. Ne fait rien de réel, journalise l'appel."""
    record = ToolCallRecord(tool="send_email", params={"to": to, "body": body})
    EXECUTED_ACTIONS.append(record)
    logger.info("send_email appelé -> to=%s", to)
    return f"[MOCK] Email envoyé à {to}"


def transfer_funds(account: str, amount: float) -> str:
    """Simule un virement bancaire. Ne fait rien de réel, journalise l'appel."""
    record = ToolCallRecord(tool="transfer_funds", params={"account": account, "amount": amount})
    EXECUTED_ACTIONS.append(record)
    logger.info("transfer_funds appelé -> account=%s amount=%s", account, amount)
    return f"[MOCK] Virement de {amount} EUR vers {account} exécuté"


def close_ticket(ticket_id: str) -> str:
    """Simule la clôture d'un ticket de support. Ne fait rien de réel."""
    record = ToolCallRecord(tool="close_ticket", params={"ticket_id": ticket_id})
    EXECUTED_ACTIONS.append(record)
    logger.info("close_ticket appelé -> ticket_id=%s", ticket_id)
    return f"[MOCK] Ticket {ticket_id} clôturé"


TOOLS = {
    "send_email": send_email,
    "transfer_funds": transfer_funds,
    "close_ticket": close_ticket,
}