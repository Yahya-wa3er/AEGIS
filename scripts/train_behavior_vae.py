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
from aegis_core.model_io import write_manifest
from aegis_core.stats import rate

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

TRAIN_PATH = Path("data/behavior_sessions_train.jsonl")
CALIB_PATH = Path("data/behavior_sessions_calibration.jsonl")
TEST_PATH = Path("data/behavior_sessions_test.jsonl")

# Taux de faux positifs accepté sur des sessions légitimes. Le seuil en découle,
# au lieu de découler d'un « moyenne + 3 écarts-types » dont personne ne sait à
# quel taux il correspond. Un scan comportemental ne bloque rien (il journalise) :
# on peut donc se permettre 2 % plutôt que 0, et gagner en rappel.
TARGET_FALSE_POSITIVE_RATE = 0.02
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


def load_rows(path: Path) -> list[EvalRow]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
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


def calibrate(model: BetaVAE) -> float:
    """Choisit le seuil sur des sessions normales TENUES À L'ÉCART.

    La version précédente prenait `moyenne(normaux du jeu d'éval) + 3σ` puis
    annonçait « 0 faux positif » sur ces mêmes normaux. Trois écarts-types
    au-dessus de la moyenne d'un échantillon de 60 laissent zéro point au-dessus
    dans l'immense majorité des tirages : le chiffre décrivait le seuil, pas le
    modèle.
    """
    rows = load_rows(CALIB_PATH)
    errors = reconstruction_error(model, torch.stack([r.x for r in rows])).tolist()
    threshold = float(torch.quantile(torch.tensor(errors), 1.0 - TARGET_FALSE_POSITIVE_RATE))
    logger.info(
        "Seuil calibré sur %d sessions normales : %.4f (quantile %.0f%%, cible %.0f%% de faux positifs).",
        len(errors), threshold, 100 * (1 - TARGET_FALSE_POSITIVE_RATE), 100 * TARGET_FALSE_POSITIVE_RATE,
    )
    return threshold


def measure(model: BetaVAE, threshold: float) -> dict[str, object]:
    """Mesure sur le jeu de test, seuil déjà figé, intervalles de confiance publiés."""
    rows = load_rows(TEST_PATH)
    errors = reconstruction_error(model, torch.stack([r.x for r in rows])).tolist()

    by_category: dict[str, list[float]] = {}
    for row, err in zip(rows, errors):
        by_category.setdefault(row.category, []).append(err)

    logger.info("--- Erreur de reconstruction par catégorie (jeu de test) ---")
    for category, values in sorted(by_category.items()):
        avg = sum(values) / len(values)
        logger.info("  %-20s n=%-3d moyenne=%.4f  min=%.4f  max=%.4f",
                    category, len(values), avg, min(values), max(values))

    per_category: dict[str, object] = {}
    logger.info("--- Mesure (seuil figé : %.4f) ---", threshold)
    for category, values in sorted(by_category.items()):
        hits = sum(1 for v in values if v > threshold)
        measured = rate(hits, len(values))
        per_category[category] = measured.as_dict()
        kind = "faux positifs" if category == "normal" else "rappel"
        logger.info("  %-20s %-12s : %s", category, kind, measured.format())

    anomalous = [(cat, v) for cat, values in by_category.items() if cat != "normal" for v in values]
    overall_recall = rate(sum(1 for _, v in anomalous if v > threshold), len(anomalous))
    logger.info("  %-20s %-12s : %s", "TOUTES anomalies", "rappel", overall_recall.format())

    return {
        "threshold": threshold,
        "target_false_positive_rate": TARGET_FALSE_POSITIVE_RATE,
        "recall_all_anomalies": overall_recall.as_dict(),
        "per_category": per_category,
    }


def main() -> None:
    model = train()
    threshold = calibrate(model)
    metrics = measure(model, threshold)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    # `state_dict()` ne contient que des tenseurs : le fichier est donc rechargeable
    # avec `torch.load(..., weights_only=True)` côté détecteur (correctif P0-5).
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
    # La mesure voyage avec le modèle : un seuil sans le taux qu'il produit, et
    # sans l'intervalle de confiance de ce taux, n'est pas interprétable plus tard.
    (OUTPUT_DIR / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    write_manifest(OUTPUT_DIR, ["model.pt", "config.json", "metrics.json"])
    logger.info("Modèle, seuil et manifeste d'intégrité sauvegardés dans '%s'.", OUTPUT_DIR)


if __name__ == "__main__":
    main()
