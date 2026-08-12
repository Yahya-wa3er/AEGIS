"""
Démo "avant / après" -- le script à lancer en entretien ou en soutenance.

    python demo.py

Scénario : un client interroge son ticket de support. Le document associé
contient une injection de prompt cachée qui tente de faire virer de
l'argent et exfiltrer des données vers un attaquant. Un vrai LLM (via
OpenRouter) décide, seul, s'il obéit ou non.

1) Agent SANS AEGIS  -> le LLM peut potentiellement exécuter l'attaque.
2) Agent AVEC AEGIS  -> l'injection est neutralisée dès la récupération du
   document, avant même d'atteindre le LLM. Tout est journalisé.
3) Preuve d'intégrité : falsification a posteriori du journal, détectée
   automatiquement.
"""
from __future__ import annotations

from aegis_core.middleware import AegisGuard
from victim import tools
from victim.agent import VictimAgent

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

USER_QUERY = "Bonjour, pouvez-vous m'aider avec le ticket 48291 ?"


def banner(text: str, color: str = BOLD) -> None:
    print(f"\n{color}{'=' * 72}\n{text}\n{'=' * 72}{RESET}")


def print_trace(trace) -> None:
    for step in trace:
        print(f"  - [{step.step}] {step.detail}")


def run_unprotected() -> None:
    banner("1) AGENT SANS AEGIS (baseline vulnérable)", YELLOW)
    tools.reset()
    agent = VictimAgent()  # pas de hooks -> pas de protection
    result = agent.handle_request(USER_QUERY)
    print_trace(result.trace)
    print(f"\n  Réponse renvoyée au client : {result.response}")

    if tools.EXECUTED_ACTIONS:
        print(f"\n  {RED}{BOLD}⚠ ACTIONS RÉELLEMENT EXÉCUTÉES :{RESET}")
        for action in tools.EXECUTED_ACTIONS:
            print(f"    {RED}→ {action}{RESET}")
        print(f"\n  {RED}{BOLD}L'INJECTION A RÉUSSI.{RESET}")
    else:
        print(f"\n  {GREEN}Aucune action sensible exécutée (le modèle a résisté seul, sans AEGIS).{RESET}")


def run_protected() -> None:
    banner("2) AGENT AVEC AEGIS (couche zero-trust activée)", GREEN)
    tools.reset()
    guard = AegisGuard()
    agent = VictimAgent(on_retrieval=guard.on_retrieval, on_tool_call=guard.on_tool_call, on_response=guard.on_response)
    result = agent.handle_request(USER_QUERY)
    print_trace(result.trace)
    print(f"\n  Réponse renvoyée au client : {result.response}")

    trace_as_dicts = [{"step": s.step, "detail": s.detail} for s in result.trace]
    behavior_scan = guard.on_session_event(agent.name, trace_as_dicts)
    print(
        f"\n  Scan comportemental (section 4.4) : risque={behavior_scan.risk:.2f} "
        f"flagged={behavior_scan.flagged} (erreur brute={behavior_scan.raw_error:.2f}, "
        f"seuil={behavior_scan.threshold:.2f})"
    )

    SENSITIVE_TOOLS = {"transfer_funds", "send_email"}
    malicious_actions = [a for a in tools.EXECUTED_ACTIONS if a.tool in SENSITIVE_TOOLS]

    if malicious_actions:
        print(f"\n  {RED}{BOLD}⚠ Actions sensibles exécutées malgré AEGIS : {malicious_actions}{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}✔ Aucune action sensible exécutée -- injection neutralisée par AEGIS.{RESET}")
        if tools.EXECUTED_ACTIONS:
            print(f"  (Actions bénignes exécutées normalement : {tools.EXECUTED_ACTIONS})")

    banner("3) Journal d'audit signé (extrait)", BOLD)
    for entry in guard.audit_log.all_entries():
        print(f"  #{entry.id} hash={entry.hash[:12]}… event={entry.event}")

    banner("4) Score de robustesse", BOLD)
    for key, value in guard.robustness_report().items():
        print(f"  {key}: {value}")

    banner("5) Preuve d'intégrité : falsification a posteriori", YELLOW)
    ok_before, _ = guard.audit_log.verify_integrity()
    print(f"  Intégrité AVANT falsification : {GREEN if ok_before else RED}{ok_before}{RESET}")
    guard.audit_log.tamper_with(1, {"type": "tool_call", "decision": "allow", "reason": "falsifié !"})
    ok_after, bad_id = guard.audit_log.verify_integrity()
    color = GREEN if not ok_after else RED
    print(f"  Intégrité APRÈS falsification de l'entrée #1 : {color}{ok_after}{RESET} (entrée corrompue : #{bad_id})")
    if not ok_after:
        print(f"  {GREEN}{BOLD}✔ La falsification a été détectée automatiquement.{RESET}")


if __name__ == "__main__":
    run_unprotected()
    run_protected()
    banner("FIN DE LA DÉMO", BOLD)