"""
Policy Engine minimal (allow-list par agent, principe du moindre privilège).

En V1 "production" (blueprint section 4.1), ce module peut être remplacé par
Open Policy Agent (OPA) sans changer l'interface `PolicyEngine.check()` --
c'est elle que `middleware.py` appellera, pas les détails d'implémentation.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger("aegis_core.policy_engine")


@dataclass(frozen=True)
class AgentPolicy:
    """Politique de permissions d'un agent : ce qu'il a le droit de faire."""

    allowed_tools: frozenset[str] = frozenset()
    sensitive_tools: frozenset[str] = frozenset()
    max_amount: float = 0.0


DEFAULT_POLICIES: dict[str, AgentPolicy] = {
    "SupportAgent": AgentPolicy(
        allowed_tools=frozenset({"close_ticket"}),
        sensitive_tools=frozenset({"send_email", "transfer_funds"}),
        max_amount=0.0,
    ),
}

Decision = tuple[str, str]  # ("allow" | "block", raison)


class PolicyEngine:
    """Applique le moindre privilège : tout ce qui n'est pas explicitement autorisé est bloqué."""

    def __init__(self, policies: dict[str, AgentPolicy] | None = None):
        self.policies = policies if policies is not None else DEFAULT_POLICIES

    def check(self, agent_name: str, tool_name: str, params: dict[str, object]) -> Decision:
        policy = self.policies.get(agent_name)
        if policy is None:
            logger.warning("Aucune politique définie pour '%s' -- deny by default", agent_name)
            return "block", f"Aucune politique définie pour l'agent '{agent_name}' (deny by default)."

        if tool_name in policy.sensitive_tools and tool_name not in policy.allowed_tools:
            return "block", f"Outil sensible '{tool_name}' non autorisé pour l'agent '{agent_name}' (least privilege)."

        if tool_name not in policy.allowed_tools:
            return "block", f"Outil '{tool_name}' absent de l'allow-list de l'agent '{agent_name}'."

        amount = params.get("amount")
        if isinstance(amount, (int, float)) and amount > policy.max_amount:
            return "block", f"Montant {amount} dépasse le plafond autorisé ({policy.max_amount})."

        return "allow", "Conforme à la politique."