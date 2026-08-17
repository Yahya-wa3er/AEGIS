"""
Banc de scénarios : rejoue chaque situation de `victim/scenarios.py` à travers
l'arbitrage complet d'AEGIS.

    python -m redteam.run_scenarios
    python -m redteam.run_scenarios --scenario bourrage-classement-hybride
    python -m redteam.run_scenarios --json scenarios.json

Différence avec `run_redteam`
-----------------------------
`run_redteam` mesure un taux sur un corpus : c'est la porte de non-régression.
Celui-ci **explique** — pour chaque scénario, quel signal a tiré, lequel avait le
droit de décider, et où regarder. Le premier répond « est-ce que ça marche
encore ? », le second « qu'est-ce que ça fait, exactement ? ».

Aucun appel LLM n'est effectué : on mesure la décision d'AEGIS, qui ne dépend
d'aucun service externe. C'est précisément ce qu'il faut pouvoir montrer.
"""
from __future__ import annotations

import argparse
import json
import sys

from aegis_core.middleware import AegisGuard
from victim import rag
from victim.scenarios import SCENARIOS, SCENARIOS_PAR_ID, Scenario

VERT, ROUGE, JAUNE, GRIS, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[90m", "\033[0m"


def document_du_scenario(scenario: Scenario) -> tuple[str, str] | None:
    """Document joué : celui planté par le scénario, sinon le mieux classé du corpus.

    Un scénario sans document planté est un scénario qui teste le corpus normal
    -- c'est le cas des contrôles légitimes, et c'est là qu'on vérifie que le
    classement rend bien le document pertinent.
    """
    if scenario.document is not None:
        return scenario.document_id, scenario.document
    classement = rag.rank(scenario.requete)
    if not classement:
        return None
    return classement[0].id, classement[0].document.content


def joue(scenario: Scenario, guard: AegisGuard | None = None) -> dict[str, object]:
    """Rejoue un scénario par le point d'interception qui le concerne.

    Tous les scénarios ne sont pas « un document suspect » : une injection de
    second ordre vit dans le retour d'un outil, un excès de pouvoir dans l'appel
    lui-même. Les faire tous passer par `_content_verdict` mesurerait la mauvaise
    couche et afficherait un écart là où il n'y en a pas.
    """
    guard = guard or AegisGuard()
    ctx = {"agent": "SupportAgent", "session_id": f"scenario:{scenario.id}"}

    prompt = guard.on_prompt(scenario.requete, ctx)
    resultat: dict[str, object] = {
        "scenario": scenario.as_dict(),
        "point": "on_prompt",
        "prompt": {"decision": prompt.decision, "reason": prompt.reason,
                   "matched_rules": list(prompt.matched_rules)},
        "document": None,
        "details": {},
        "verdict": None,
    }

    # Une requête refusée n'atteint jamais la suite : on s'arrête là, comme le
    # fait l'agent.
    if prompt.blocked:
        resultat["verdict"] = "requête bloquée"
        return resultat

    if scenario.appel_outil is not None:
        outil, params = scenario.appel_outil
        decision, raison = guard.on_tool_call(outil, params, ctx)
        resultat.update(point="on_tool_call",
                        outil={"nom": outil, "params": params, "raison": raison},
                        verdict="appel d'outil refusé" if decision == "block" else "appel d'outil autorisé")
        return resultat

    if scenario.retour_outil is not None:
        outil, contenu = scenario.retour_outil
        rendu = guard.on_tool_result(outil, contenu, ctx)
        neutralise = rendu != contenu
        _, details = guard._content_verdict(contenu)
        resultat.update(point="on_tool_result", details=details,
                        outil={"nom": outil, "rendu": rendu},
                        verdict="retour d'outil neutralisé" if neutralise else "retour d'outil transmis")
        return resultat

    doc = document_du_scenario(scenario)
    if doc is None:
        resultat["verdict"] = "aucun document"
        return resultat

    doc_id, contenu = doc
    bloque, details = guard._content_verdict(contenu)
    resultat.update(point="on_retrieval", details=details,
                    document={"id": doc_id, "taille": len(contenu)},
                    verdict="document neutralisé" if bloque else "document transmis")
    return resultat


ARRETS = {"requête bloquée", "document neutralisé", "retour d'outil neutralisé",
          "appel d'outil refusé"}


def ecarts(res: dict[str, object]) -> list[str]:
    """Ce qui ne correspond pas à l'attendu du scénario.

    Deux niveaux : le verdict (l'attaque a-t-elle été arrêtée ?) et les signaux
    (est-ce le bon détecteur qui a parlé ?). Le second compte autant : un blocage
    obtenu par le mauvais signal est un coup de chance, pas une défense.
    """
    scenario = res["scenario"]
    problemes = []
    arrete = res["verdict"] in ARRETS
    if arrete != scenario["est_attaque"]:
        problemes.append("verdict inattendu")

    details = res.get("details") or {}
    tires = set(details.get("blocking_signals", [])) | set(details.get("advisory_signals", []))
    for attendu in scenario["signaux_attendus"]:
        if attendu not in tires:
            problemes.append(f"signal manquant : {attendu}")
    for absent in scenario["signaux_absents"]:
        if absent in tires:
            problemes.append(f"signal inattendu : {absent}")
    return problemes


def _ligne(res: dict[str, object]) -> str:
    scenario = res["scenario"]
    problemes = ecarts(res)
    couleur = VERT if not problemes else ROUGE
    marque = "OK   " if not problemes else "ÉCART"
    suffixe = f"  — {', '.join(problemes)}" if problemes else ""
    return (f"{couleur}[{marque}]{RESET} {scenario['id']:34s} {scenario['owasp']:6s} "
            f"{res['point']:16s} {res['verdict']}{suffixe}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", help="ne jouer qu'un scénario, par identifiant")
    parser.add_argument("--json", help="écrire le rapport machine dans ce fichier")
    parser.add_argument("--verbeux", action="store_true", help="détailler les signaux")
    args = parser.parse_args()

    if args.scenario:
        if args.scenario not in SCENARIOS_PAR_ID:
            print(f"Scénario inconnu : {args.scenario}\nDisponibles : {', '.join(SCENARIOS_PAR_ID)}")
            return 2
        selection = (SCENARIOS_PAR_ID[args.scenario],)
    else:
        selection = SCENARIOS

    print("=" * 88)
    print("AEGIS — banc de scénarios (décision du pipeline, aucun appel LLM)")
    print("=" * 88)

    resultats = []
    famille = None
    for scenario in selection:
        if scenario.famille != famille:
            famille = scenario.famille
            print(f"\n{famille}")
        res = joue(scenario)
        resultats.append(res)
        print("  " + _ligne(res))
        if args.verbeux or args.scenario:
            d = res.get("details") or {}
            if d:
                print(f"       signaux bloquants  : {d.get('blocking_signals')}")
                print(f"       signaux consultatifs: {d.get('advisory_signals')}")
                if d.get("matched_rules"):
                    print(f"       règles déclenchées : {d['matched_rules']}")
                stuffing = d.get("stuffing") or {}
                if stuffing.get("flagged"):
                    print(f"       bourrage           : TTR={stuffing['ttr']} "
                          f"attendu {stuffing['expected_range']} — {stuffing['top_terms'][:3]}")
            print(f"{GRIS}       à regarder : {scenario.regarder}{RESET}")

    attaques = [r for r in resultats if r["scenario"]["est_attaque"]]
    controles = [r for r in resultats if not r["scenario"]["est_attaque"]]
    arretees = sum(1 for r in attaques if r["verdict"] in ARRETS)
    faux_pos = sum(1 for r in controles if r["verdict"] in ARRETS)
    non_conformes = [r for r in resultats if ecarts(r)]

    print("\n" + "=" * 88)
    print(f"Attaques arrêtées : {arretees}/{len(attaques)}    "
          f"Contrôles bloqués à tort : {faux_pos}/{len(controles)}    "
          f"Scénarios non conformes : {len(non_conformes)}/{len(resultats)}")
    print("Ce banc EXPLIQUE ; il ne mesure pas un taux — pour ça, `python -m redteam.run_redteam`.")
    print("=" * 88)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(resultats, f, ensure_ascii=False, indent=2, default=str)
        print(f"Rapport écrit dans {args.json}")

    # Le scénario d'évasion connue n'est PAS un échec : il documente une limite.
    # L'écart réel, c'est un contrôle légitime bloqué.
    return 1 if non_conformes else 0


if __name__ == "__main__":
    sys.exit(main())
