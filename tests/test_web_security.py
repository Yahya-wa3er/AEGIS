"""
Tests de non-régression sur la surface HTTP (correctif P0-1, traversée de chemin).

Pourquoi ces tests n'utilisent PAS `TestClient`
-----------------------------------------------
`TestClient` s'appuie sur httpx, qui **normalise les `..` dans l'URL avant
l'envoi** : `client.get("/../../.env")` part sur le réseau comme `GET /.env`.
Un test écrit avec `TestClient` ne peut donc pas reproduire la faille -- et c'est
exactement pour ça qu'elle avait survécu à une suite de 66 tests verts.

Un vrai client, lui, peut envoyer le chemin brut (`curl --path-as-is`), et
uvicorn le transmet tel quel à l'application. On appelle donc l'application ASGI
directement, avec un `scope` fabriqué à la main contenant le chemin non
normalisé : c'est la représentation la plus fidèle de ce qui arrive en production.

Chaque cible ci-dessous a été effectivement exfiltrée avant le correctif.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from web.app import _static_root, app

# Le nombre exact de `../` nécessaire dépend de la profondeur de FRONTEND_DIR
# (`<repo>/frontend/out`). On balaie une plage large plutôt que de coder en dur
# une profondeur qui casserait le test si l'arborescence bougeait.
TRAVERSAL_DEPTHS = range(1, 10)


def _raw_get(path: str) -> tuple[int | None, bytes]:
    """Envoie un GET à l'app ASGI avec le chemin BRUT, sans passer par un client HTTP."""

    async def call() -> tuple[int | None, bytes]:
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [(b"host", b"testserver")],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
        }
        body = bytearray()
        status: dict[str, int] = {}

        async def receive() -> dict:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            elif message["type"] == "http.response.body":
                body.extend(message.get("body", b""))

        await app(scope, receive, send)
        return status.get("code"), bytes(body)

    return asyncio.run(call())


@pytest.fixture(autouse=True)
def _built_frontend():
    """Garantit qu'un index.html existe pendant le test, sans laisser de trace.

    Sans index.html, la route répond 503 et les tests passeraient pour de mauvaises
    raisons (on veut vérifier le refus de la traversée, pas l'absence de build).
    On travaille volontairement sur la VRAIE racine statique et non sur un
    répertoire temporaire : les cibles de traversée (`.env`, le code source, les
    artefacts de modèle) ne sont à la bonne profondeur relative que depuis
    l'arborescence réelle du dépôt.

    Tout ce que la fixture crée, elle le supprime -- sinon elle casserait
    `tests/test_web_app.py`, qui vérifie le cas « frontend non buildé ».
    """
    root = _static_root()
    index = root / "index.html"
    created_dir = not root.exists()
    created_index = not index.is_file()

    root.mkdir(parents=True, exist_ok=True)
    if created_index:
        index.write_text("<html><body>test index</body></html>", encoding="utf-8")

    yield

    if created_index and index.is_file():
        index.unlink()
    if created_dir and root.is_dir() and not any(root.iterdir()):
        root.rmdir()


def test_traversal_cannot_read_etc_passwd() -> None:
    for depth in TRAVERSAL_DEPTHS:
        _, body = _raw_get("/" + "../" * depth + "etc/passwd")
        assert b"root:x:0:0" not in body, f"traversée réussie avec {depth} x '../'"


def test_traversal_cannot_read_dotenv() -> None:
    """La cible la plus dangereuse : `.env` contient OPENROUTER_API_KEY."""
    repo_root = Path(__file__).resolve().parent.parent
    dotenv = repo_root / ".env"
    created = False
    if not dotenv.is_file():
        dotenv.write_text("OPENROUTER_API_KEY=sk-or-v1-CANARY-DO-NOT-LEAK\n", encoding="utf-8")
        created = True
    try:
        for depth in TRAVERSAL_DEPTHS:
            for target in (".env", ".env.example"):
                _, body = _raw_get("/" + "../" * depth + target)
                assert b"OPENROUTER_API_KEY" not in body, f"fuite de {target} avec {depth} x '../'"
    finally:
        if created:
            dotenv.unlink()


def test_traversal_cannot_read_project_files() -> None:
    """Code source, corpus d'attaques et artefacts de modèle sont aussi hors limites."""
    targets = {
        "aegis_core/policy_engine.py": b"class PolicyEngine",
        "victim/documents/doc2_poisoned.txt": b"SYSTEM OVERRIDE",
        "models/rag_outlier/config.json": b"anomaly_threshold",
    }
    for depth in TRAVERSAL_DEPTHS:
        for target, needle in targets.items():
            _, body = _raw_get("/" + "../" * depth + target)
            assert needle not in body, f"fuite de {target} avec {depth} x '../'"


@pytest.mark.parametrize(
    "path",
    [
        "/..%2f..%2f..%2f..%2fetc%2fpasswd",   # séparateurs encodés
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",  # points encodés
        "/....//....//....//....//etc/passwd",  # doublement, contourne un strip naïf de '../'
        "/..\\..\\..\\..\\etc\\passwd",         # séparateurs Windows
    ],
)
def test_traversal_encoded_variants(path: str) -> None:
    _, body = _raw_get(path)
    assert b"root:x:0:0" not in body


def test_legitimate_asset_is_still_served() -> None:
    """Le correctif ne doit pas casser la fonction : un fichier réel sous la racine passe."""
    asset = _static_root() / "aegis-probe.txt"
    asset.write_text("contenu-legitime", encoding="utf-8")
    try:
        status, body = _raw_get("/aegis-probe.txt")
        assert status == 200
        assert b"contenu-legitime" in body
    finally:
        asset.unlink()


def test_unknown_route_falls_back_to_index() -> None:
    """Comportement single-page préservé : une route inconnue retombe sur index.html."""
    status, body = _raw_get("/une/route/inexistante")
    assert status == 200
    assert b"<html" in body.lower()
