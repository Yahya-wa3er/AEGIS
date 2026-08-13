"""
Retrieval minimal pour la démo -- sans dépendance ML lourde, pour que le
projet tourne instantanément sans téléchargement de modèle.

Scoring par recouvrement de mots-clés (façon BM25 simplifié). C'est
volontairement basique : le blueprint (section 5 - Stack technique) prévoit
FAISS + embeddings pour la V1 "production". L'interface `retrieve()` ne
changera pas le jour où on branchera un vrai moteur vectoriel -- c'est ça,
l'intérêt de séparer clairement cette couche du reste de l'agent.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

DOCS_DIR = os.path.join(os.path.dirname(__file__), "documents")

_TOKEN_RE = re.compile(r"[a-z0-9àâäéèêëïîôöùûüç]+")


@dataclass(frozen=True)
class Document:
    """Un document indexé, identifié par son nom de fichier."""

    id: str
    content: str


def _tokenize(text: str) -> set[str]:
    """Découpe un texte en un ensemble de mots-clés en minuscules."""
    return set(_TOKEN_RE.findall(text.lower()))


def load_documents(docs_dir: str = DOCS_DIR) -> list[Document]:
    """Charge tous les documents `.txt` du dossier `documents/`."""
    documents = []
    for filename in sorted(os.listdir(docs_dir)):
        if not filename.endswith(".txt"):
            continue
        path = os.path.join(docs_dir, filename)
        with open(path, encoding="utf-8") as file:
            documents.append(Document(id=filename, content=file.read()))
    return documents


def retrieve(query: str, top_k: int = 1) -> list[Document]:
    """
    Retourne les `top_k` documents les plus pertinents pour `query`, triés
    par nombre de mots-clés communs (score décroissant).
    """
    query_tokens = _tokenize(query)
    documents = load_documents()

    scored = [
        (len(query_tokens & _tokenize(doc.content)), doc)
        for doc in documents
    ]
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [doc for _, doc in scored[:top_k]]