"""
Génère des sessions comportementales synthétiques pour le Beta-VAE de
détection d'anomalies (blueprint, section 4.4).

Deux fichiers en sortie :
- data/behavior_sessions_train.jsonl : sessions NORMALES uniquement (un VAE
  s'entraîne exclusivement sur la normalité -- il n'a jamais besoin d'exemples
  d'attaque pour apprendre à les détecter, contrairement au classifieur
  d'injection).
- data/behavior_sessions_eval.jsonl : jeu étiqueté (normal + 3 catégories
  d'anomalies) pour MESURER le modèle après entraînement, jamais pour
  l'entraîner.

Usage:
    python scripts/generate_behavior_sessions.py
"""
from __future__ import annotations

import json
import random
from dataclasses import asdict
from pathlib import Path

from aegis_core.behavior_features import ActionEvent

SEED = 42
N_TRAIN_SESSIONS = 1000
N_EVAL_NORMAL = 60
N_EVAL_PER_ANOMALY_CATEGORY = 20

TRAIN_PATH = Path("data/behavior_sessions_train.jsonl")
EVAL_PATH = Path("data/behavior_sessions_eval.jsonl")

# Distribution d'une session NORMALE de SupportAgent : majoritairement des
# questions qui ne déclenchent aucun outil ou une clôture de ticket: un email
# légitime est rare, un virement n'arrive JAMAIS (il n'est de toute façon pas
# dans l'allow-list du Policy Engine -- voir aegis_core/policy_engine.py).
NORMAL_ACTION_WEIGHTS = {
    "no_action": 0.50,
    "close_ticket": 0.45,
    "send_email": 0.05,
    "transfer_funds": 0.0,
}


def _sample_normal_event(rng: random.Random) -> ActionEvent:
    action = rng.choices(list(NORMAL_ACTION_WEIGHTS), weights=list(NORMAL_ACTION_WEIGHTS.values()))[0]
    return ActionEvent(action=action, amount=0.0)


# Nombre max de clôtures de ticket dans une session normale. Sans ce plafond, chaque
# position est tirée indépendamment des autres -- le modèle apprendrait alors que
# "close_ticket" est fréquent À CHAQUE position, mais jamais que le total sur 5
# positions doit rester borné. Résultat observé : une session de 5 clôtures d'affilée
# (bulk_close_ticket) n'était PAS détectée, car chaque position prise isolément est
# banale. Ce plafond force la corrélation entre positions que le VAE doit apprendre.
MAX_CLOSE_TICKETS_PER_NORMAL_SESSION = 2


def make_normal_session(rng: random.Random) -> list[ActionEvent]:
    while True:
        session = [_sample_normal_event(rng) for _ in range(5)]
        if sum(1 for e in session if e.action == "close_ticket") <= MAX_CLOSE_TICKETS_PER_NORMAL_SESSION:
            return session


def make_hijack_injection_session(rng: random.Random) -> list[ActionEvent]:
    """Attaque réussie : virement(s) vers un compte externe, montant élevé.

    Détectable en théorie par le Policy Engine seul (transfer_funds est hors
    allow-list) -- utile ici comme test de cohérence : le VAE doit LUI AUSSI
    le voir comme statistiquement aberrant, en couche de secours indépendante.
    """
    n_attacks = rng.randint(1, 2)
    events = [ActionEvent(action="transfer_funds", amount=rng.uniform(20_000, 999_999)) for _ in range(n_attacks)]
    events += [_sample_normal_event(rng) for _ in range(5 - n_attacks)]
    rng.shuffle(events)
    return events


def make_bulk_close_ticket_session(rng: random.Random) -> list[ActionEvent]:
    """Anomalie de FRÉQUENCE, pas de permission : clôturer 5 tickets d'affilée
    est individuellement autorisé (Policy Engine ne dirait rien), mais ne
    ressemble à aucune session normale -- c'est exactement le cas d'usage où
    le VAE apporte quelque chose que le Policy Engine ne peut pas voir.
    """
    return [ActionEvent(action="close_ticket", amount=0.0) for _ in range(5)]


def make_sensitive_burst_session(rng: random.Random) -> list[ActionEvent]:
    """Rafale d'outils sensibles variés (email + virement mêlés) -- profil
    qui ne correspond à aucun usage légitime observé à l'entraînement.
    """
    events = [
        ActionEvent(action=rng.choice(["send_email", "transfer_funds"]), amount=rng.uniform(5_000, 200_000))
        for _ in range(5)
    ]
    return events


ANOMALY_GENERATORS = {
    "hijack_injection": make_hijack_injection_session,
    "bulk_close_ticket": make_bulk_close_ticket_session,
    "sensitive_burst": make_sensitive_burst_session,
}


def _session_to_json(events: list[ActionEvent]) -> list[dict]:
    return [asdict(e) for e in events]


def main() -> None:
    rng = random.Random(SEED)
    TRAIN_PATH.parent.mkdir(parents=True, exist_ok=True)

    with TRAIN_PATH.open("w", encoding="utf-8") as f:
        for _ in range(N_TRAIN_SESSIONS):
            session = make_normal_session(rng)
            f.write(json.dumps({"events": _session_to_json(session)}) + "\n")
    print(f"{N_TRAIN_SESSIONS} sessions normales écrites dans '{TRAIN_PATH}'.")

    eval_rows = []
    for _ in range(N_EVAL_NORMAL):
        session = make_normal_session(rng)
        eval_rows.append({"events": _session_to_json(session), "label": "normal", "category": "normal"})

    for category, generator in ANOMALY_GENERATORS.items():
        for _ in range(N_EVAL_PER_ANOMALY_CATEGORY):
            session = generator(rng)
            eval_rows.append({"events": _session_to_json(session), "label": "anomalous", "category": category})

    rng.shuffle(eval_rows)
    with EVAL_PATH.open("w", encoding="utf-8") as f:
        for row in eval_rows:
            f.write(json.dumps(row) + "\n")
    print(f"{len(eval_rows)} sessions étiquetées écrites dans '{EVAL_PATH}' (évaluation uniquement).")


if __name__ == "__main__":
    main()
