"""
Client minimal pour appeler un LLM via OpenRouter (API compatible OpenAI),
utilisé comme "cerveau" de l'agent victime (victim/agent.py).

OpenRouter expose un point d'entrée unique compatible avec le SDK officiel
`openai` -- il suffit de changer `base_url` et d'utiliser une clé OpenRouter.
Ça permet de basculer entre modèles OpenAI et Anthropic juste en changeant
OPENROUTER_MODEL dans le `.env`, sans toucher au code.
"""
from __future__ import annotations

import os

from dotenv import load_dotenv
from openai import OpenAI
from openai.types.chat import ChatCompletionMessage

load_dotenv()

_DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
_DEFAULT_MODEL = "openai/gpt-4o-mini"


class MissingApiKeyError(RuntimeError):
    """Levée quand OPENROUTER_API_KEY est absent ou vide dans l'environnement."""


def _build_client() -> OpenAI:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise MissingApiKeyError(
            "OPENROUTER_API_KEY est absent ou vide. Vérifie ton fichier .env "
            "à la racine du projet (voir .env.example)."
        )
    base_url = os.getenv("OPENROUTER_BASE_URL", _DEFAULT_BASE_URL)
    return OpenAI(base_url=base_url, api_key=api_key)


def get_completion(
    messages: list[dict[str, object]],
    tools: list[dict[str, object]] | None = None,
) -> ChatCompletionMessage:
    """
    Envoie une conversation (+ outils disponibles, au format function-calling
    OpenAI) au modèle défini par OPENROUTER_MODEL, renvoie le message de
    réponse (texte et/ou tool_calls).
    """
    client = _build_client()
    model = os.getenv("OPENROUTER_MODEL", _DEFAULT_MODEL)
    response = client.chat.completions.create(model=model, messages=messages, tools=tools)
    return response.choices[0].message