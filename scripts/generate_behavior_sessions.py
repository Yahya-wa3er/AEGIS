"""
Génère des sessions comportementales synthétiques pour le Beta-VAE de
détection d'anomalies (blueprint, section 4.4).

Deux fichiers en sortie :
- data/behavior_sessions_train.jsonl : sessions NORMALES uniquement (un VAE
  s'entraîne exclusivement sur la normalité -- il n'a jamais besoin d'exemples
  d'attaque pour apprendre à les détecter, contrairement au classifieur
  d'injection).
- data/behavior_sessions_calibration.jsonl : sessions NORMALES tenues à l'écart,
  servant uniquement à CHOISIR le seuil d'anomalie (correctif P1-M2).
- data/behavior_sessions_test.jsonl : jeu étiqueté (normal + 3 catégories
  d'anomalies) pour MESURER le modèle après entraînement, jamais pour
  l'entraîner ni pour régler quoi que ce soit.

Pourquoi un troisième fichier
-----------------------------
`train_behavior_vae.py` calculait son seuil sur le jeu d'évaluation puis
annonçait le taux de faux positifs *sur ce même jeu*. Avec `seuil =
moyenne(normaux) + 3σ`, obtenir « 0 faux positif » n'apprend rien sur le modèle :
c'est ce que produit mécaniquement un seuil à trois écarts-types d'un
échantillon de 60. Le seuil se choisit désormais sur un jeu de calibration
distinct, et la mesure porte sur un jeu de test que rien n'a touché.

Note de méthode : contrairement au corpus RAG, on n'exige PAS ici l'absence de
sessions identiques entre les jeux. L'espace des sessions normales est discret
et petit (5 positions, 3 actions réellement possibles), donc des doublons entre
tirages sont la conséquence normale de la distribution -- pas une fuite. Traiter
mécaniquement toute répétition comme une contamination reviendrait à interdire
d'échantillonner deux fois la même loi.

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
N_CALIB_NORMAL = 200   # sert UNIQUEMENT au choix du seuil
N_TEST_NORMAL = 200    # sert UNIQUEMENT à la mesure -- 60 donnait un intervalle
                       # de confiance plus large que la différence à démontrer
N_TEST_PER_ANOMALY_CATEGORY = 40

TRAIN_PATH = Path("data/behavior_sessions_train.jsonl")
CALIB_PATH = Path("data/behavior_sessions_calibration.jsonl")
TEST_PATH = Path("data/behavior_sessions_test.jsonl")

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
    print(f"{N_TRAIN_SESSIONS} sessions normales -> '{TRAIN_PATH}' (ajustement du modèle).")

    with CALIB_PATH.open("w", encoding="utf-8") as f:
        for _ in range(N_CALIB_NORMAL):
            session = make_normal_session(rng)
            f.write(json.dumps({"events": _session_to_json(session), "label": "normal", "category": "normal"}) + "\n")
    print(f"{N_CALIB_NORMAL} sessions normales -> '{CALIB_PATH}' (choix du seuil, jamais mesuré).")

    test_rows = []
    for _ in range(N_TEST_NORMAL):
        session = make_normal_session(rng)
        test_rows.append({"events": _session_to_json(session), "label": "normal", "category": "normal"})

    for category, generator in ANOMALY_GENERATORS.items():
        for _ in range(N_TEST_PER_ANOMALY_CATEGORY):
            session = generator(rng)
            test_rows.append({"events": _session_to_json(session), "label": "anomalous", "category": category})

    rng.shuffle(test_rows)
    with TEST_PATH.open("w", encoding="utf-8") as f:
        for row in test_rows:
            f.write(json.dumps(row) + "\n")
    print(f"{len(test_rows)} sessions étiquetées -> '{TEST_PATH}' (mesure uniquement).")


if __name__ == "__main__":
    main()
