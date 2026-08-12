"""
Entraîne le Beta-VAE de détection d'anomalies comportementales (blueprint,
section 4.4) sur les sessions normales générées par
`generate_behavior_sessions.py`.

Principe (voir docstring de `aegis_core/behavior_features.py` pour la
représentation des données) : le modèle apprend à compresser puis reconstruire
UNIQUEMENT des sessions normales. Une session dont la reconstruction est
mauvaise (erreur élevée) s'écarte de tout ce que le modèle a appris comme
normal -- c'est le signal d'anomalie.

Usage:
    python scripts/generate_behavior_sessions.py   # si pas déjà fait
    python scripts/train_behavior_vae.py
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from aegis_core.behavior_detector import BetaVAE, vae_loss
from aegis_core.behavior_features import INPUT_DIM, ActionEvent, encode_session

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

TRAIN_PATH = Path("data/behavior_sessions_train.jsonl")
EVAL_PATH = Path("data/behavior_sessions_eval.jsonl")
OUTPUT_DIR = Path("models/behavior_vae")

LATENT_DIM = 4
HIDDEN_DIM = 16
BETA = 4.0  # poids de la régularisation KL -- au-delà de 1.0, c'est ça qui fait un "Beta"-VAE
N_EPOCHS = 60
BATCH_SIZE = 32
LEARNING_RATE = 1e-3
SEED = 42


def reconstruction_error(model: BetaVAE, x: torch.Tensor) -> torch.Tensor:
    """Score d'anomalie = erreur de reconstruction par session (pas de terme KL ici :
    c'est bien la fidélité de la reconstruction qui nous intéresse pour détecter, le
    KL n'a servi qu'à structurer l'espace latent pendant l'entraînement)."""
    model.eval()
    with torch.no_grad():
        recon, _, _ = model(x)
        return nn.functional.mse_loss(recon, x, reduction="none").sum(dim=1)


def _load_sessions(path: Path) -> list[list[ActionEvent]]:
    sessions = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        sessions.append([ActionEvent(**e) for e in row["events"]])
    return sessions


def load_training_tensor() -> torch.Tensor:
    sessions = _load_sessions(TRAIN_PATH)
    vectors = [encode_session(s) for s in sessions]
    return torch.tensor(vectors, dtype=torch.float32)


@dataclass(frozen=True)
class EvalRow:
    x: torch.Tensor
    label: str
    category: str


def load_eval_rows() -> list[EvalRow]:
    rows = []
    for line in EVAL_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        events = [ActionEvent(**e) for e in row["events"]]
        x = torch.tensor(encode_session(events), dtype=torch.float32)
        rows.append(EvalRow(x=x, label=row["label"], category=row["category"]))
    return rows


def train() -> BetaVAE:
    torch.manual_seed(SEED)
    x_train = load_training_tensor()
    loader = DataLoader(TensorDataset(x_train), batch_size=BATCH_SIZE, shuffle=True)

    model = BetaVAE(input_dim=INPUT_DIM, hidden_dim=HIDDEN_DIM, latent_dim=LATENT_DIM)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)

    for epoch in range(1, N_EPOCHS + 1):
        model.train()
        total_loss = 0.0
        for (batch,) in loader:
            optimizer.zero_grad()
            recon, mu, logvar = model(batch)
            loss = vae_loss(recon, batch, mu, logvar, BETA)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * batch.size(0)
        if epoch % 10 == 0 or epoch == 1:
            logger.info("Epoch %d/%d -- loss moyenne: %.4f", epoch, N_EPOCHS, total_loss / len(x_train))

    return model


def evaluate(model: BetaVAE) -> float:
    """Mesure la séparation normal/anormal sur le jeu d'évaluation, choisit un seuil,
    et affiche un rapport lisible catégorie par catégorie."""
    rows = load_eval_rows()
    x_eval = torch.stack([r.x for r in rows])
    errors = reconstruction_error(model, x_eval).tolist()

    by_category: dict[str, list[float]] = {}
    for row, err in zip(rows, errors):
        by_category.setdefault(row.category, []).append(err)

    logger.info("--- Erreur de reconstruction par catégorie (plus haut = plus suspect) ---")
    for category, values in sorted(by_category.items()):
        avg = sum(values) / len(values)
        logger.info("  %-20s n=%-3d moyenne=%.4f  min=%.4f  max=%.4f", category, len(values), avg, min(values), max(values))

    normal_errors = by_category.get("normal", [])
    threshold = max(normal_errors) if normal_errors else 0.0
    # Marge de sécurité : le seuil brut serait le pire score normal observé, ce qui est
    # fragile (un seul point extrême le fixerait) -- on prend plutôt une marge au-dessus
    # de la moyenne + écart-type, plus robuste sur un jeu de validation plus large en prod.
    if normal_errors:
        mean = sum(normal_errors) / len(normal_errors)
        variance = sum((v - mean) ** 2 for v in normal_errors) / len(normal_errors)
        threshold = mean + 3 * (variance ** 0.5)

    anomalous_errors = [err for row, err in zip(rows, errors) if row.label == "anomalous"]
    detected = sum(1 for err in anomalous_errors if err > threshold)
    false_positives = sum(1 for err in normal_errors if err > threshold)

    logger.info("--- Seuil retenu : %.4f (moyenne_normal + 3 écarts-types) ---", threshold)
    logger.info(
        "Détection : %d/%d anomalies au-dessus du seuil -- Faux positifs : %d/%d sessions normales",
        detected, len(anomalous_errors), false_positives, len(normal_errors),
    )
    return threshold


def main() -> None:
    model = train()
    threshold = evaluate(model)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), OUTPUT_DIR / "model.pt")
    (OUTPUT_DIR / "config.json").write_text(
        json.dumps(
            {
                "input_dim": INPUT_DIM,
                "hidden_dim": HIDDEN_DIM,
                "latent_dim": LATENT_DIM,
                "beta": BETA,
                "anomaly_threshold": threshold,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    logger.info("Modèle et seuil sauvegardés dans '%s'.", OUTPUT_DIR)


if __name__ == "__main__":
    main()
