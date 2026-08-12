"""
Détection d'anomalies comportementales par Beta-VAE (blueprint, section 4.4).

Contrairement à `injection_detector.py` (règles + ML en couches indépendantes),
ce détecteur est purement ML : il n'existe pas de "règle" équivalente pour
repérer qu'une séquence d'actions est statistiquement inhabituelle -- c'est
précisément ce que le VAE apporte. Le principe de fail-safe reste le même :
si torch n'est pas installé, ou si le modèle n'est pas encore entraîné, le
détecteur ne plante pas -- il renvoie un risque nul avec un WARNING, plutôt
que de bloquer tout le pipeline AEGIS pour un module optionnel.

La classe `BetaVAE` est définie ICI (et non dans `scripts/train_behavior_vae.py`)
pour qu'il n'existe qu'une seule définition de l'architecture, utilisée à la
fois pour l'entraînement et pour le chargement en production -- éviter que
les deux dérivent l'une de l'autre.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from aegis_core.behavior_features import INPUT_DIM, ActionEvent, encode_session

logger = logging.getLogger(__name__)

try:
    import torch
    from torch import nn

    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False
    logger.warning(
        "torch non installé (voir requirements-ml.txt) -- BehaviorDetector "
        "tournera toujours en mode dégradé (risque nul)."
    )

DEFAULT_MODEL_DIR = Path("models/behavior_vae")
DEFAULT_HIDDEN_DIM = 16
DEFAULT_LATENT_DIM = 4


if _TORCH_AVAILABLE:

    class BetaVAE(nn.Module):
        """VAE minimal : encodeur/décodeur feedforward pour un vecteur d'entrée court."""

        def __init__(self, input_dim: int = INPUT_DIM, hidden_dim: int = DEFAULT_HIDDEN_DIM, latent_dim: int = DEFAULT_LATENT_DIM):
            super().__init__()
            self.encoder = nn.Sequential(nn.Linear(input_dim, hidden_dim), nn.ReLU())
            self.to_mu = nn.Linear(hidden_dim, latent_dim)
            self.to_logvar = nn.Linear(hidden_dim, latent_dim)
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, input_dim),
                nn.Sigmoid(),  # toutes nos features sont dans [0, 1] (one-hot + montant normalisé)
            )

        def encode(self, x: "torch.Tensor") -> tuple["torch.Tensor", "torch.Tensor"]:
            h = self.encoder(x)
            return self.to_mu(h), self.to_logvar(h)

        @staticmethod
        def reparameterize(mu: "torch.Tensor", logvar: "torch.Tensor") -> "torch.Tensor":
            std = torch.exp(0.5 * logvar)
            eps = torch.randn_like(std)
            return mu + eps * std

        def forward(self, x: "torch.Tensor") -> tuple["torch.Tensor", "torch.Tensor", "torch.Tensor"]:
            mu, logvar = self.encode(x)
            z = self.reparameterize(mu, logvar)
            recon = self.decoder(z)
            return recon, mu, logvar

    def vae_loss(recon: "torch.Tensor", x: "torch.Tensor", mu: "torch.Tensor", logvar: "torch.Tensor", beta: float) -> "torch.Tensor":
        """Perte de reconstruction (somme sur les features) + beta * divergence KL, moyennées sur le batch."""
        recon_loss = nn.functional.mse_loss(recon, x, reduction="none").sum(dim=1)
        kl = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp(), dim=1)
        return (recon_loss + beta * kl).mean()


@dataclass(frozen=True)
class BehaviorScanResult:
    """Résultat du scan d'une session comportementale.

    `raw_error` est l'erreur de reconstruction brute (non bornée) -- utile pour
    le débogage/reporting. `risk` est la même information écrasée dans [0, 1)
    via 1 - exp(-erreur/seuil), pour rester cohérent avec le risque de
    `InjectionDetector.scan()` (0 = confiant que c'est normal, proche de 1 =
    très éloigné de tout ce qui a été vu à l'entraînement).
    """

    risk: float
    flagged: bool
    raw_error: float | None = None
    threshold: float | None = None


def _load_model_and_config(model_dir: str) -> tuple[object | None, dict | None]:
    if not _TORCH_AVAILABLE:
        return None, None

    path = Path(model_dir)
    config_path = path / "config.json"
    weights_path = path / "model.pt"
    if not config_path.is_file() or not weights_path.is_file():
        logger.warning(
            "Modèle comportemental introuvable dans '%s' (lance "
            "scripts/generate_behavior_sessions.py puis scripts/train_behavior_vae.py "
            "pour l'entraîner) -- BehaviorDetector renverra un risque nul.",
            model_dir,
        )
        return None, None

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        model = BetaVAE(
            input_dim=config["input_dim"],
            hidden_dim=config["hidden_dim"],
            latent_dim=config["latent_dim"],
        )
        model.load_state_dict(torch.load(weights_path, map_location="cpu"))
        model.eval()
        return model, config
    except Exception:
        logger.exception(
            "Échec du chargement du modèle comportemental depuis '%s' -- "
            "BehaviorDetector renverra un risque nul.",
            model_dir,
        )
        return None, None


class BehaviorDetector:
    """Détecteur d'anomalies comportementales (fréquence/enchaînement d'actions par agent)."""

    def __init__(self, model_dir: Path | str = DEFAULT_MODEL_DIR):
        self._model, self._config = _load_model_and_config(str(model_dir))

    @property
    def ml_available(self) -> bool:
        return self._model is not None

    def score(self, events: list[ActionEvent]) -> BehaviorScanResult:
        """Score une session (liste d'événements, la plus récente en dernier)."""
        if self._model is None or self._config is None:
            return BehaviorScanResult(risk=0.0, flagged=False)

        vector = encode_session(events)
        x = torch.tensor([vector], dtype=torch.float32)
        with torch.no_grad():
            recon, _, _ = self._model(x)
            error = float(nn.functional.mse_loss(recon, x, reduction="none").sum(dim=1).item())

        threshold = float(self._config["anomaly_threshold"])
        risk = 1.0 - pow(2.718281828, -error / threshold) if threshold > 0 else 0.0
        return BehaviorScanResult(risk=risk, flagged=error > threshold, raw_error=error, threshold=threshold)
