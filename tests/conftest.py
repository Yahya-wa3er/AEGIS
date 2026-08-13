"""
Configuration commune des tests.

Le marqueur `requires_models`
-----------------------------
Huit tests dépendent de modèles entraînés que le dépôt ne versionne pas (les
poids sont trop volumineux, `models/` est dans `.gitignore`). Sur un clone
frais, ils échouaient -- et un `pytest` rouge au premier lancement est le plus
mauvais accueil possible pour quelqu'un qui découvre le projet : il ne sait pas
si le code est cassé ou s'il lui manque une étape.

Un test qui ne peut pas s'exécuter doit être **sauté**, pas échoué. La
distinction est celle entre « ça ne marche pas » et « je n'ai pas pu vérifier ».
Le message de skip dit quoi lancer pour l'activer.

En intégration continue, les modèles légers sont entraînés avant la suite : rien
n'y est sauté, et une régression sur ces détecteurs fait bien rougir le pipeline.

    @pytest.mark.requires_models("rag_outlier")
    def test_quelque_chose(): ...
"""
from __future__ import annotations

from pathlib import Path

import pytest

MODELS_DIR = Path("models")

# Comment obtenir chaque modèle, pour que le message de skip soit actionnable
# plutôt que constatif.
_HOW_TO_TRAIN = {
    "rag_outlier": "python -m scripts.generate_rag_corpus && python -m scripts.train_rag_outlier_detector",
    "behavior_vae": "python -m scripts.generate_behavior_sessions && python -m scripts.train_behavior_vae",
    "injection_classifier": "python -m scripts.train_injection_classifier",
}


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_models(*names): saute le test si les modèles nommés ne sont pas entraînés",
    )


def pytest_runtest_setup(item: pytest.Item) -> None:
    for marker in item.iter_markers("requires_models"):
        missing = [name for name in marker.args if not (MODELS_DIR / name).is_dir()]
        if missing:
            instructions = " ; ".join(_HOW_TO_TRAIN.get(name, name) for name in missing)
            pytest.skip(f"modèle(s) non entraîné(s) : {', '.join(missing)} — pour l'activer : {instructions}")
