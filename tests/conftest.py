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
    config.addinivalue_line(
        "markers",
        "autorise_appel_llm: lève l'interdiction d'appel LLM réel (à n'utiliser que "
        "si l'appel lui-même est le sujet du test)",
    )


def pytest_runtest_setup(item: pytest.Item) -> None:
    for marker in item.iter_markers("requires_models"):
        missing = [name for name in marker.args if not (MODELS_DIR / name).is_dir()]
        if missing:
            instructions = " ; ".join(_HOW_TO_TRAIN.get(name, name) for name in missing)
            pytest.skip(f"modèle(s) non entraîné(s) : {', '.join(missing)} — pour l'activer : {instructions}")


# ---------------------------------------------------------------------------
# Aucune sortie réseau, aucune dépense, par défaut
# ---------------------------------------------------------------------------
# Ce garde-fou existe parce que le même défaut est apparu deux fois en deux
# lots :
#
# * lot 7.2b — les tests de limitation de débit appelaient RÉELLEMENT
#   OpenRouter sur la machine de développement. Ils passaient en CI parce
#   qu'aucune clé n'y était configurée : l'absence de clé masquait le problème
#   au lieu de le révéler.
# * lot 8 — les tests de l'assistant ont refait exactement la même chose, dans
#   un fichier écrit après avoir documenté le premier cas.
#
# La leçon est qu'une discipline qu'on se rappelle d'appliquer n'en est pas
# une. Le repli sûr doit être structurel : ici, tout appel LLM lève, sauf dans
# un test qui remplace explicitement `get_completion`. Une suite de tests qui
# dépense de l'argent est une suite qu'on finit par ne plus lancer.
@pytest.fixture(autouse=True)
def _aucun_appel_llm_reel(monkeypatch, request):
    if "autorise_appel_llm" in request.keywords:
        return

    def _interdit(*_a, **_kw):
        raise RuntimeError(
            "Appel LLM réel tenté depuis un test. Remplace `get_completion` dans le "
            "test, ou marque-le @pytest.mark.autorise_appel_llm si l'appel est le sujet."
        )

    for module in ("victim.llm_client", "victim.agent", "web.app"):
        try:
            monkeypatch.setattr(f"{module}.get_completion", _interdit, raising=False)
        except (ImportError, AttributeError):  # pragma: no cover - module absent
            pass


# ---------------------------------------------------------------------------
# L'état de garde de l'application est rendu tel qu'il a été trouvé
# ---------------------------------------------------------------------------
# Deuxième récidive du lot 7.2b : un test qui vide le seau à jetons de
# `web.app` faisait échouer un test d'un AUTRE fichier avec un 429 au lieu du
# 404 attendu. Corrigé une fois dans `test_ratelimit.py`, le défaut est revenu
# par `test_assistant.py` — parce que la correction vivait dans un fichier au
# lieu de vivre dans l'infrastructure.
#
# Chaque test repart donc d'un limiteur et d'une enveloppe neufs. L'isolation
# est garantie par construction, pas par la vigilance de qui écrit le prochain
# fichier de tests.
@pytest.fixture(autouse=True)
def _gardes_llm_neuves(monkeypatch):
    try:
        import web.app as module
        from web import ratelimit
    except ImportError:  # pragma: no cover - l'API n'est pas toujours importable
        return
    monkeypatch.setattr(module.app.state, "rate_limiter", ratelimit.from_env())
    monkeypatch.setattr(module.app.state, "llm_budget", ratelimit.budget_from_env())
