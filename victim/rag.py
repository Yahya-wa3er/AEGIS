"""
Retrieval de la démonstration -- et, accessoirement, la surface d'attaque qu'on
oublie le plus souvent dans un RAG.

Le défaut trouvé au lot 6
-------------------------
La première version classait les documents par **nombre brut de mots communs**
avec la requête :

    scored = [(len(query_tokens & _tokenize(doc.content)), doc) for doc in docs]

Aucune normalisation par la longueur. Un document long a mécaniquement plus de
vocabulaire, donc plus de recouvrement avec n'importe quelle requête. Sur le
corpus de démonstration, `doc2_poisoned.txt` (113 mots distincts) l'emportait
sur `doc1_clean.txt` (73 mots distincts) pour le seul mot « Bonjour ».

Ce n'était pas un travers d'affichage. C'est une **manipulation de classement** :
un attaquant qui ne contrôle que le *contenu* d'un document contrôle aussi sa
*sélection*. Il suffit d'y bourrer du vocabulaire courant du domaine pour être
récupéré à chaque requête. Mesuré : un document piégé rembourré de vingt-quatre
mots de support client remontait en tête sur quatre requêtes sur cinq, y compris
sur des sujets qu'il ne traitait pas.

La conséquence n'est pas que l'attaque passe -- AEGIS neutralise ensuite le
document. C'est qu'un attaquant peut **occuper tout le contexte** de l'agent, et
donc évincer les documents légitimes : un déni de service sur la pertinence.
C'est le volet « classement » d'OWASP LLM09, distinct du contrôle d'accès à
l'index.

BM25, et pourquoi ça n'efface pas complètement le problème
----------------------------------------------------------
`bm25_score` applique les deux corrections qui manquaient :

* **saturation de la fréquence** (`k1`) -- répéter « commande » dix fois ne vaut
  pas dix fois une occurrence, les gains décroissent vite ;
* **normalisation par la longueur** (`b`) -- un document deux fois plus long doit
  être deux fois plus pertinent pour obtenir le même score.

Le bourrage devient donc coûteux au lieu d'être gratuit. Il ne devient pas
impossible : BM25 reste un modèle de sac de mots, et un attaquant qui rembourre
avec les mots *exacts* d'une requête qu'il anticipe peut encore remonter. La
mesure du gain est dans `tests/test_rag.py` ; la limite résiduelle est au README
plutôt que passée sous silence.

L'ancien classement n'est pas supprimé
--------------------------------------
`overlap_score` reste disponible, sous son nom, documenté comme vulnérable. Il
sert à rejouer l'attaque côte à côte avec le correctif : une faille qu'on peut
reproduire à la demande est plus convaincante qu'une ligne de changelog.
"""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable

DOCS_DIR = os.path.join(os.path.dirname(__file__), "documents")

_TOKEN_RE = re.compile(r"[a-z0-9àâäéèêëïîôöùûüçñ]+")

# Paramètres BM25 usuels (Robertson & Zaragoza). k1 pilote la saturation de la
# fréquence, b la force de la normalisation par la longueur. b=0.75 est la
# valeur de référence ; c'est elle qui rend le bourrage coûteux.
BM25_K1 = 1.5
BM25_B = 0.75


@dataclass(frozen=True)
class Document:
    """Un document indexé, identifié par son nom de fichier."""

    id: str
    content: str


@dataclass(frozen=True)
class ScoredDocument:
    """Un document et son score, pour pouvoir montrer le classement lui-même."""

    document: Document
    score: float

    @property
    def id(self) -> str:
        return self.document.id


def _tokenize(text: str) -> list[str]:
    """Découpe un texte en mots-clés minuscules, **avec** les répétitions.

    La version précédente renvoyait un `set` : elle perdait les fréquences, donc
    ne pouvait ni saturer ni normaliser. C'est cette perte d'information qui
    rendait le classement manipulable.
    """
    return _TOKEN_RE.findall(text.lower())


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


# -- les deux classements --------------------------------------------------


def overlap_score(query: str, documents: list[Document]) -> list[float]:
    """Classement **vulnérable** d'origine : recouvrement brut de vocabulaire.

    Conservé volontairement, et uniquement pour la démonstration. À ne pas
    utiliser sur un chemin de production : il récompense la longueur, donc le
    bourrage de mots-clés.
    """
    query_tokens = set(_tokenize(query))
    return [float(len(query_tokens & set(_tokenize(doc.content)))) for doc in documents]


def bm25_score(
    query: str,
    documents: list[Document],
    k1: float = BM25_K1,
    b: float = BM25_B,
) -> list[float]:
    """Classement BM25 : fréquence saturée, longueur normalisée.

    L'IDF employée est la variante « probabiliste » de Robertson/Sparck-Jones,
    bornée à zéro : un terme présent dans plus de la moitié des documents
    donnerait sinon une contribution négative, ce qui ferait *baisser* le score
    d'un document parce qu'il contient un mot courant.
    """
    if not documents:
        return []

    tokenized = [_tokenize(doc.content) for doc in documents]
    lengths = [len(tokens) for tokens in tokenized]
    avg_length = (sum(lengths) / len(lengths)) or 1.0
    frequencies = [Counter(tokens) for tokens in tokenized]
    n_docs = len(documents)

    scores = [0.0] * n_docs
    for term in set(_tokenize(query)):
        containing = sum(1 for freq in frequencies if term in freq)
        if containing == 0:
            continue
        idf = max(0.0, math.log(1 + (n_docs - containing + 0.5) / (containing + 0.5)))
        for i, freq in enumerate(frequencies):
            occurrences = freq.get(term, 0)
            if not occurrences:
                continue
            norm = 1 - b + b * (lengths[i] / avg_length)
            scores[i] += idf * (occurrences * (k1 + 1)) / (occurrences + k1 * norm)
    return scores


Scorer = Callable[[str, list[Document]], list[float]]

# Nommés pour que le tableau de bord puisse rejouer l'attaque côte à côte.
RANKERS: dict[str, Scorer] = {
    "bm25": bm25_score,
    "overlap": overlap_score,
}
DEFAULT_RANKER = "bm25"


def rank(
    query: str,
    documents: list[Document] | None = None,
    docs_dir: str = DOCS_DIR,
    ranker: str = DEFAULT_RANKER,
) -> list[ScoredDocument]:
    """Classement complet, scores compris.

    Le tri départage les égalités par identifiant : sans ça, deux exécutions
    peuvent renvoyer des documents différents à score identique, et une
    démonstration non reproductible n'est pas une démonstration.
    """
    if ranker not in RANKERS:
        raise ValueError(f"Classement inconnu : {ranker!r}. Valeurs acceptées : {sorted(RANKERS)}.")
    documents = load_documents(docs_dir) if documents is None else documents
    scores = RANKERS[ranker](query, documents)
    scored = [ScoredDocument(document=doc, score=score) for doc, score in zip(documents, scores)]
    scored.sort(key=lambda s: (-s.score, s.id))
    return scored


def retrieve(
    query: str,
    top_k: int = 1,
    docs_dir: str = DOCS_DIR,
    ranker: str = DEFAULT_RANKER,
) -> list[Document]:
    """Retourne les `top_k` documents les plus pertinents pour `query`."""
    return [scored.document for scored in rank(query, docs_dir=docs_dir, ranker=ranker)[:top_k]]
