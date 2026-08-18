"""
Mesure du filtre de sortie : ce qu'il attrape, et ce qu'il casse.

    python -m scripts.measure_output_guard

La métrique qui compte n'est pas le taux de détection. C'est le **taux de
réponses légitimes abîmées** : ce filtre est le seul composant du produit qui
modifie ce que l'utilisateur reçoit, et une réponse cassée sur dix suffit à le
rendre inutilisable en production.

Trois taux sont donc publiés séparément, avec leur intervalle de Wilson :

* **détection** — parmi les réponses qui doivent être signalées, combien le
  sont ;
* **modification injustifiée** — parmi les réponses légitimes, combien voient
  leur texte changer. C'est le chiffre grave : le texte rendu à l'utilisateur
  n'est plus celui que le modèle a écrit ;
* **signalement injustifié** — parmi les réponses légitimes, combien déclenchent
  un signal sans être modifiées. Moins grave (rien n'est cassé), mais un journal
  qui crie sur du trafic normal finit ignoré.

Les distinguer est le cœur du sujet : un filtre qui signale beaucoup et ne
modifie jamais est utilisable ; l'inverse ne l'est pas.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from aegis_core.output_guard import OutputGuard
from aegis_core.stats import wilson_interval
from victim.agent import SYSTEM_PROMPT

CORPUS = Path("data/output_responses.jsonl")


def charge() -> list[dict]:
    if not CORPUS.is_file():
        print(f"Corpus introuvable : {CORPUS}. Lance `python -m scripts.generate_output_corpus`.")
        raise SystemExit(2)
    return [json.loads(ligne) for ligne in CORPUS.read_text(encoding="utf-8").splitlines() if ligne.strip()]


def main() -> int:
    cas = charge()
    garde = OutputGuard(hidden_context=(SYSTEM_PROMPT,))

    a_signaler = [c for c in cas if c["attendu"] != "laisser"]
    a_masquer = [c for c in cas if c["attendu"] == "masquer"]
    legitimes = [c for c in cas if c["attendu"] == "laisser"]

    detectes = modifies_attendus = 0
    manques: list[str] = []
    for c in a_signaler:
        resultat = garde.scan(c["texte"])
        if resultat.flagged:
            detectes += 1
        else:
            manques.append(c["id"])
        if c["attendu"] == "masquer" and resultat.modified:
            modifies_attendus += 1

    modifies_a_tort: list[str] = []
    signales_a_tort: list[str] = []
    for c in legitimes:
        resultat = garde.scan(c["texte"])
        if resultat.modified:
            modifies_a_tort.append(c["id"])
        elif resultat.flagged:
            signales_a_tort.append(c["id"])

    detection = wilson_interval(detectes, len(a_signaler))
    neutralisation = wilson_interval(modifies_attendus, len(a_masquer))
    modification_injustifiee = wilson_interval(len(modifies_a_tort), len(legitimes))
    signalement_injustifie = wilson_interval(len(signales_a_tort), len(legitimes))

    print("=" * 78)
    print("Filtre de sortie — mesure sur data/output_responses.jsonl")
    print("=" * 78)
    print(f"  détection (à signaler)            : {detection.format()}")
    print(f"  neutralisation effective          : {neutralisation.format()}")
    print(f"  MODIFICATION injustifiée          : {modification_injustifiee.format()}")
    print(f"  signalement injustifié            : {signalement_injustifie.format()}")
    print("-" * 78)
    if manques:
        print(f"  non détectés : {', '.join(manques)}")
    if modifies_a_tort:
        print(f"  réponses légitimes MODIFIÉES : {', '.join(modifies_a_tort)}")
    if signales_a_tort:
        print(f"  réponses légitimes signalées sans modification : {', '.join(signales_a_tort)}")
    print("-" * 78)
    print(
        "Rappel de lecture : les intervalles sont larges parce que le corpus est petit.\n"
        "Ils disent ce que la mesure permet d'affirmer, pas ce qu'on aimerait annoncer."
    )

    # Porte : une réponse légitime modifiée est un défaut bloquant. Le
    # signalement injustifié, lui, ne casse rien et reste tolérable.
    if modifies_a_tort:
        print(
            "\nÉCHEC : au moins une réponse légitime a été modifiée. Ce filtre est le seul\n"
            "composant qui change ce que l'utilisateur reçoit ; un faux positif y coûte\n"
            "plus cher qu'ailleurs."
        )
        return 1
    print("\nSUCCÈS : aucune réponse légitime n'a été modifiée.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
