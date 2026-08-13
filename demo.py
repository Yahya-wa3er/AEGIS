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
3) Preuve d'intégrité : on rejoue une attaque RÉELLE contre le journal --
   l'attaquant réécrit une entrée puis recalcule toute la chaîne de hachage.
   Sans clé de signature, elle passe (et la démo le dit). Avec une clé
   Ed25519, elle est rejetée.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3

from pathlib import Path

from aegis_core.audit_log import GENESIS_HASH
from aegis_core.config import AegisConfig
from aegis_core.middleware import AegisGuard
from victim import tools
from victim.agent import VictimAgent

# Journal de la démo, recréé à chaque exécution (voir run_protected).
AUDIT_DB_PATH = Path("demo_audit.db")

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


def _reforge_audit_chain(db_path: str, entry_id: int) -> None:
    """Rejoue l'attaque réelle contre le journal (voir section 5 de la démo).

    L'attaquant a l'accès en écriture au fichier SQLite -- le même accès qu'il lui
    faut pour falsifier quoi que ce soit. Il supprime les triggers append-only,
    réécrit l'entrée visée, puis **recalcule toute la chaîne** avec le même
    SHA-256 que nous. Un chaînage de hachage non signé ne peut pas distinguer ce
    résultat d'un journal authentique : il recalcule exactement de la même façon.
    """
    con = sqlite3.connect(db_path)
    con.execute("DROP TRIGGER IF EXISTS audit_log_append_only_update")
    con.execute("DROP TRIGGER IF EXISTS audit_log_append_only_delete")

    innocent = {"type": "tool_call", "tool": "close_ticket", "params": {"ticket_id": "48291"}, "decision": "allow"}
    prev = GENESIS_HASH
    for rid, ts, ev in con.execute("SELECT id, timestamp, event FROM audit_log ORDER BY id").fetchall():
        event = innocent if rid == entry_id else json.loads(ev)
        payload = json.dumps({"timestamp": ts, "event": event, "prev_hash": prev}, sort_keys=True)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        con.execute(
            "UPDATE audit_log SET event = ?, prev_hash = ?, hash = ? WHERE id = ?",
            (json.dumps(event, ensure_ascii=False), prev, digest, rid),
        )
        prev = digest
    con.commit()
    con.close()


def run_protected() -> None:
    banner("2) AGENT AVEC AEGIS (couche zero-trust activée)", GREEN)
    tools.reset()
    AUDIT_DB_PATH.unlink(missing_ok=True)  # repartir d'un journal vierge à chaque démo
    # Journal sur disque plutôt qu'en mémoire : l'attaque de la section 5 suppose
    # un attaquant qui ouvre le fichier SQLite, ce qui n'aurait aucun sens sur une
    # base ':memory:'. C'est aussi ce que ferait un vrai déploiement -- une preuve
    # qui ne survit pas au processus qui l'a produite n'est pas une preuve.
    guard = AegisGuard(config=AegisConfig(audit_db_path=str(AUDIT_DB_PATH)))
    agent = VictimAgent(
            on_retrieval=guard.on_retrieval,
            on_tool_call=guard.on_tool_call,
            on_response=guard.on_response,
            on_prompt=guard.on_prompt,
            on_tool_result=guard.on_tool_result,
        )
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

    banner("5) Preuve d'intégrité : attaque par reforge complète de la chaîne", YELLOW)
    # On ne simule PAS un attaquant naïf qui modifierait une entrée sans toucher
    # aux hachages suivants : n'importe quelle chaîne de hachage l'attrape, et le
    # démontrer ne prouve rien. On rejoue l'attaque réelle -- l'attaquant a
    # l'accès en écriture, supprime les triggers append-only, réécrit l'entrée
    # ET recalcule toute la chaîne avec le même SHA-256 que nous.
    before = guard.audit_log.verify_integrity()
    print(f"  Intégrité initiale : {GREEN if before.ok else RED}{before.ok}{RESET}"
          f"  (mode de signature : {before.signature_mode}, {before.signatures_verified} signature(s) vérifiée(s))")

    _reforge_audit_chain(guard.audit_log.db_path, entry_id=1)
    after = guard.audit_log.verify_integrity()

    if after.ok:
        print(f"  Intégrité après reforge : {RED}{BOLD}True{RESET} -- {RED}la falsification est PASSÉE.{RESET}")
        print(f"  {YELLOW}Journal non signé : le chaînage seul ne résiste pas à un attaquant qui")
        print(f"  recalcule la chaîne. Lance {BOLD}python -m scripts.generate_audit_key{RESET}{YELLOW}"
              f" puis rejoue cette démo.{RESET}")
    else:
        print(f"  Intégrité après reforge : {GREEN}{BOLD}False{RESET} (entrée #{after.first_bad_entry})")
        print(f"  Motif : {after.reason}")
        print(f"  {GREEN}{BOLD}✔ La reforge est rejetée : l'attaquant peut recalculer les hachages,")
        print(f"    pas produire de signature valide sans la clé privée.{RESET}")


if __name__ == "__main__":
    run_unprotected()
    run_protected()
    banner("FIN DE LA DÉMO", BOLD)