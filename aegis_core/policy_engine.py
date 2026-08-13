"""
Policy Engine : allow-list par agent, principe du moindre privilège, et
validation de la FORME des appels d'outils.

Pourquoi ce module compte plus que les autres
---------------------------------------------
L'OWASP GenAI LLM Top 10 **2026** a fait remonter *Excessive Agency* de la 6ᵉ à
la **3ᵉ** place mondiale, sur la base de 7 714 incidents réels. C'est-à-dire le
risque que ce fichier adresse directement -- et le seul endroit d'AEGIS où l'on
gouverne des *actions* plutôt que du texte. C'est aussi ce qu'un concurrent
copie le moins facilement.

La démo l'a montré sans qu'on le cherche : sur un document **parfaitement
légitime** (un message de bienvenue), l'agent non protégé a appelé `send_email`.
Aucune injection, aucun attaquant -- juste un agent à qui on a donné trop de
pouvoir et un system prompt qui l'encourage à s'en servir. L'*Excessive Agency*
n'a pas besoin d'une attaque pour causer un dégât.

Correctifs apportés ici
-----------------------
**P1-1 -- le plafond de montant se contournait par le typage.** L'ancienne
version faisait `isinstance(amount, (int, float))` avant de comparer. Or les
paramètres viennent d'un JSON produit par un LLM : rien ne garantit le type.
Mesuré, avec `max_amount=1000` :

    amount=99999    (int)   -> BLOCK   correct
    amount="99999"  (str)   -> ALLOW   contournement
    amount=True     (bool)  -> ALLOW   (True > 1000.0 est False en Python)
    amount=[99999]  (list)  -> ALLOW   contournement

Un type inattendu n'est plus ignoré : il est **bloqué**. Une valeur qu'on ne
sait pas interpréter n'est pas une valeur sûre.

**P1-1b -- rien ne validait la forme des paramètres.** `victim/agent.py` faisait
`TOOLS[name](**params)` sans contrôle : clé inattendue -> TypeError, JSON
malformé -> 500. Autoriser un appel sans en valider la forme, c'est autoriser
quelque chose qu'on n'a pas compris. `AgentPolicy.tool_schemas` accepte un JSON
Schema par outil ; un appel non conforme est refusé avant exécution.

**P1-2 -- `sensitive_tools` était du code mort.** L'ancienne logique testait
`tool in sensitive_tools and tool not in allowed_tools`, condition entièrement
englobée par le test d'allow-list qui suivait : le champ ne changeait jamais une
décision, seulement le message d'erreur. Il a désormais le sens qu'il aurait dû
avoir -- un outil sensible, **même autorisé**, exige une validation externe
(`approval_hook`). Sans hook configuré, il est bloqué : c'est un défaut
fail-closed assumé, et c'est ce qui aurait arrêté le `send_email` de la démo.

**Liste blanche de destinataires.** `param_allowlists` contraint la *valeur* de
certains paramètres, pas seulement le nom de l'outil. Autoriser `send_email`
sans contraindre le destinataire, c'est autoriser l'exfiltration.

En V1 "production" (blueprint section 4.1), ce module peut être remplacé par
Open Policy Agent sans changer l'interface `check()` -- c'est elle que
`middleware.py` appelle, pas les détails d'implémentation.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("aegis_core.policy_engine")

try:
    import jsonschema

    _JSONSCHEMA_AVAILABLE = True
except ImportError:  # pragma: no cover - dépend de l'environnement
    _JSONSCHEMA_AVAILABLE = False
    logger.warning(
        "jsonschema non installé -- la validation de forme des paramètres d'outils "
        "est INACTIVE. Voir requirements.txt."
    )


@dataclass(frozen=True)
class AgentPolicy:
    """Politique de permissions d'un agent : ce qu'il a le droit de faire.

    Args:
        allowed_tools: seuls outils appelables. Tout le reste est refusé.
        sensitive_tools: outils qui, **même autorisés**, exigent une validation
            externe (voir `PolicyEngine(approval_hook=...)`).
        max_amount: plafond appliqué au paramètre `amount`, quel que soit l'outil.
        tool_schemas: JSON Schema par outil. Si un schéma est déclaré, les
            paramètres doivent le respecter, sinon l'appel est refusé.
        param_allowlists: valeurs autorisées par paramètre et par outil, par ex.
            `{"send_email": {"to": frozenset({"support@acme.fr"})}}`. Contraindre
            l'outil sans contraindre sa cible ne sert à rien pour un outil qui
            envoie des données vers l'extérieur.
    """

    allowed_tools: frozenset[str] = frozenset()
    sensitive_tools: frozenset[str] = frozenset()
    max_amount: float = 0.0
    tool_schemas: dict[str, dict] = field(default_factory=dict)
    param_allowlists: dict[str, dict[str, frozenset[str]]] = field(default_factory=dict)


DEFAULT_POLICIES: dict[str, AgentPolicy] = {
    "SupportAgent": AgentPolicy(
        allowed_tools=frozenset({"close_ticket"}),
        sensitive_tools=frozenset({"send_email", "transfer_funds"}),
        max_amount=0.0,
        tool_schemas={
            "close_ticket": {
                "type": "object",
                "properties": {
                    # Tolère le '#' que les modèles ajoutent spontanément ; refuse
                    # tout le reste, y compris une clé inattendue (additionalProperties).
                    "ticket_id": {"type": "string", "pattern": r"^#?[0-9]{1,10}$"},
                },
                "required": ["ticket_id"],
                "additionalProperties": False,
            },
        },
    ),
}

Decision = tuple[str, str]  # ("allow" | "block", raison)

# Un hook de validation reçoit (agent, outil, paramètres) et retourne True pour
# autoriser. En production : une file d'approbation, un second facteur, un appel
# à un opérateur. Volontairement synchrone et simple ici.
ApprovalHook = Callable[[str, str, dict], bool]


class PolicyEngine:
    """Applique le moindre privilège : tout ce qui n'est pas explicitement autorisé est bloqué."""

    def __init__(
        self,
        policies: dict[str, AgentPolicy] | None = None,
        approval_hook: ApprovalHook | None = None,
    ):
        self.policies = policies if policies is not None else DEFAULT_POLICIES
        self._approval_hook = approval_hook

    @staticmethod
    def _coerce_amount(raw: object) -> tuple[float | None, str | None]:
        """Convertit `amount` en float, ou explique pourquoi c'est impossible.

        `bool` est exclu explicitement : en Python `isinstance(True, int)` vaut
        True et `True > 1000.0` vaut False, donc un booléen passait tous les
        plafonds sans être vu.
        """
        if raw is None:
            return None, None
        if isinstance(raw, bool):
            return None, "le paramètre 'amount' est un booléen"
        if isinstance(raw, (int, float)):
            return float(raw), None
        if isinstance(raw, str):
            try:
                # Les LLM produisent régulièrement "1 000,50" ou "1000.50".
                return float(raw.replace(" ", "").replace(",", ".")), None
            except ValueError:
                return None, f"le paramètre 'amount' n'est pas un nombre ({raw!r})"
        return None, f"le paramètre 'amount' est de type {type(raw).__name__}"

    def _check_schema(self, policy: AgentPolicy, tool_name: str, params: dict[str, object]) -> str | None:
        """Retourne un motif de refus si les paramètres ne respectent pas le schéma."""
        schema = policy.tool_schemas.get(tool_name)
        if schema is None:
            return None
        if not _JSONSCHEMA_AVAILABLE:
            # Un schéma déclaré mais non vérifiable est une fausse sécurité : on
            # refuse plutôt que de laisser croire que le contrôle a eu lieu.
            return "un schéma est déclaré pour cet outil mais jsonschema n'est pas installé"
        try:
            jsonschema.validate(instance=params, schema=schema)
        except jsonschema.ValidationError as exc:
            return f"paramètres non conformes au schéma de l'outil ({exc.message})"
        except jsonschema.SchemaError as exc:  # pragma: no cover - erreur de configuration
            return f"schéma d'outil invalide ({exc.message})"
        return None

    @staticmethod
    def _check_allowlists(policy: AgentPolicy, tool_name: str, params: dict[str, object]) -> str | None:
        allowlists = policy.param_allowlists.get(tool_name, {})
        for param, allowed in allowlists.items():
            value = params.get(param)
            if value is None:
                return f"paramètre requis '{param}' absent (liste blanche configurée)"
            if str(value) not in allowed:
                return f"valeur non autorisée pour '{param}' : {value!r}"
        return None

    def check(self, agent_name: str, tool_name: str, params: dict[str, object]) -> Decision:
        policy = self.policies.get(agent_name)
        if policy is None:
            logger.warning("Aucune politique définie pour '%s' -- deny by default", agent_name)
            return "block", f"Aucune politique définie pour l'agent '{agent_name}' (deny by default)."

        if not isinstance(params, dict):
            return "block", f"Paramètres d'outil invalides (attendu un objet, reçu {type(params).__name__})."

        if tool_name not in policy.allowed_tools:
            return "block", f"Outil '{tool_name}' absent de l'allow-list de l'agent '{agent_name}'."

        schema_error = self._check_schema(policy, tool_name, params)
        if schema_error:
            return "block", f"Appel refusé : {schema_error}."

        allowlist_error = self._check_allowlists(policy, tool_name, params)
        if allowlist_error:
            return "block", f"Appel refusé : {allowlist_error}."

        amount, amount_error = self._coerce_amount(params.get("amount"))
        if amount_error:
            # On refuse ce qu'on ne sait pas interpréter. L'ancienne version
            # ignorait simplement le plafond dans ce cas (correctif P1-1).
            return "block", f"Appel refusé : {amount_error} -- montant non vérifiable."
        if amount is not None and amount > policy.max_amount:
            return "block", f"Montant {amount} dépasse le plafond autorisé ({policy.max_amount})."

        # Outil sensible ET autorisé : exige une validation externe (correctif P1-2).
        if tool_name in policy.sensitive_tools:
            if self._approval_hook is None:
                return "block", (
                    f"Outil sensible '{tool_name}' : validation externe requise, "
                    "mais aucun approval_hook n'est configuré (deny by default)."
                )
            if not self._approval_hook(agent_name, tool_name, params):
                return "block", f"Outil sensible '{tool_name}' : validation externe refusée."
            return "allow", f"Conforme à la politique, après validation externe de '{tool_name}'."

        return "allow", "Conforme à la politique."
