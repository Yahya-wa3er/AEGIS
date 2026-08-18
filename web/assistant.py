"""
Assistant sécurité ancré : il explique le produit sans jamais inventer un chiffre.

Le choix de conception
----------------------
Un assistant branché directement sur un LLM aurait été plus rapide à écrire et
plus agréable à lire. Il aurait aussi été capable de répondre « AEGIS bloque
97 % des injections » avec un aplomb parfait — et ce projet tient entièrement
sur la promesse inverse : *un chiffre qu'on publie, on l'a mesuré*. Un assistant
qui hallucine une métrique ne fait pas une erreur de détail, il retourne
l'argument central du dépôt contre lui-même, sur l'écran fait pour convaincre.

L'assistant est donc **ancré par construction** :

1. La réponse est **composée à partir d'extraits réels** du dépôt — sections du
   README, scénarios du banc, mesures lues dans `models/*/metrics.json`. Ces
   extraits sont cités, et le visiteur peut les rouvrir.
2. Un LLM n'intervient que si une clé est configurée, et **uniquement pour
   reformuler** ces extraits. Sa sortie passe par
   `aegis_core.grounding.GroundingVerifier` : tout chiffre ou identifiant absent
   des extraits fait rejeter la reformulation, et la réponse déterministe est
   servie à la place. Le LLM peut améliorer la forme ; il ne peut pas ajouter de
   fait.
3. Quand la recherche ne ramène rien de pertinent, l'assistant **dit qu'il ne
   sait pas**. C'est le comportement le plus difficile à obtenir d'un modèle de
   langage, et le plus important sur un outil de sécurité.

Pourquoi aucun chiffre n'est écrit dans ce fichier
---------------------------------------------------
Parce qu'un chiffre recopié à la main dérive. C'est exactement le défaut corrigé
au lot 5A sur les corpus (`data/` ne correspondait plus à son générateur) et au
lot 7 sur la console (un TTR figé dans le texte pédagogique divergeait de la
mesure vive de 0,014). La base de connaissances est **relue depuis les fichiers
sources à chaque construction** ; un test vérifie qu'aucun littéral numérique
n'est codé en dur ici.

Sur LLM09, et pourquoi il ne s'applique pas ici
------------------------------------------------
Le classement de l'assistant est le même BM25 que celui du laboratoire de
classement (`victim.rag.rank`, `ranker="bm25"`) — pas une seconde implémentation
qui dériverait. La manipulation de classement démontrée ailleurs suppose que
l'attaquant puisse **écrire dans l'index** ; ici l'index est fait du README et
des scénarios du dépôt, et le visiteur ne contrôle que la requête. La propriété
est donc énoncée, pas supposée : si un jour l'assistant indexait un document
fourni par l'utilisateur, cette phrase deviendrait fausse et il faudrait
rebrancher `RetrievalStuffingDetector` à l'indexation.
"""
from __future__ import annotations

import ast
import json
import math
from dataclasses import dataclass
from pathlib import Path

from aegis_core.retrieval_integrity import tokenize
from aegis_core.stats import Proportion
from victim import rag
from victim.scenarios import SCENARIOS

RACINE = Path(__file__).resolve().parent.parent
README = RACINE / "README.md"
# Cartes de modèle (lot 9). Elles sont GÉNÉRÉES depuis le registre, donc les
# indexer n'introduit aucun chiffre saisi à la main : l'assistant apprend les
# mesures, les seuils et les modes d'échec de chaque détecteur en même temps que
# le registre les publie.
CARTES_DIR = RACINE / "docs" / "model_cards"
METRIQUES = {
    "rag_outlier": RACINE / "models" / "rag_outlier" / "metrics.json",
    "behavior_vae": RACINE / "models" / "behavior_vae" / "metrics.json",
}

# Sous ce score BM25, on considère que la recherche n'a rien trouvé. Le seuil
# n'est pas magique : il sépare « un mot en commun par hasard » de « ce passage
# parle du sujet ». Le comportement qu'il protège compte plus que sa valeur —
# répondre « je ne sais pas » plutôt que servir le passage le moins mauvais.
SCORE_MINIMUM = 1.0
EXTRAITS_PAR_REPONSE = 3
# Taille de citation : assez pour que l'extrait se suffise, assez court pour
# qu'on le lise. La coupe tombe sur une frontière de paragraphe ou de phrase.
RESUME_MAX_CARACTERES = 900

# Fraction des mots porteurs de la question qui doit réellement figurer dans un
# extrait pour qu'il soit retenu.
#
# Exiger UN mot en commun ne suffit pas, et c'est une leçon payée. « Quelle est
# la recette du gratin dauphinois au comté ? » recevait une réponse : le mot
# « recette » venait d'apparaître dans le README — dans la section qui raconte
# précisément ce contre-exemple — et comme il y est RARE, BM25 lui accordait un
# poids IDF élevé. Un terme rare et hors sujet pesait donc plus lourd que trois
# termes absents.
#
# Deux constats en découlent. Un score plancher ne protège pas de ça : ce qui
# compte est la **couverture** de la question, pas la force d'un seul appui. Et
# comme le corpus de l'assistant EST le README, y documenter un contre-exemple
# le fait entrer dans le champ des réponses possibles — boucle amusante, et
# rappel que ce corpus n'est pas une abstraction.
COUVERTURE_MINIMALE = 0.5

# Mots vides français. Sans ce filtre, « quelle est la recette de la tarte aux
# pommes ? » recevait une réponse : « quelle », « est », « la », « de » et
# « aux » apparaissent dans tout le README, BM25 leur donnait un score non nul,
# et l'assistant servait les trois sections les moins mauvaises comme si elles
# répondaient. Un assistant de sécurité qui répond toujours quelque chose est
# pire qu'un assistant qui se tait : il apprend au lecteur à ne pas le croire.
_MOTS_VIDES = frozenset("""
a ai au aux avec ce ces dans de des du elle en est et eux il ils je la le les
leur lui ma mais me meme même mes moi mon ne nos notre nous on ou où par pas
peu pour qu que quel quelle quelles quels qui sa se ses son sur ta te tes toi
ton tu un une vos votre vous y c d j l m n s t comment pourquoi quoi quand
combien fait faire fais dit dire etre être avoir as ont sont etait était sera
plus moins tres très bien tout tous toute toutes autre autres cette cela ca ça
donc alors ainsi aussi encore deja déjà entre sans sous vers chez apres après
avant depuis pendant contre selon comme si non oui
""".split())

# En dessous, un mot n'est pas discriminant (« un », « le », « ml » mis à part —
# d'où le garde sur les sigles connus juste après).
_LONGUEUR_MINIMALE = 3
_SIGLES_UTILES = frozenset({"ml", "ci", "ia", "pj"})

# Sections du README trop génériques pour faire une bonne réponse : elles
# ramassent tous les mots-clés du projet et remonteraient sur n'importe quelle
# question, en écrasant la section qui répond vraiment.
SECTIONS_IGNOREES = frozenset({"AEGIS — Zero-Trust Security Layer pour Systèmes IA Agentiques & RAG"})


@dataclass(frozen=True)
class Extrait:
    """Un passage citable du dépôt."""

    id: str
    titre: str
    texte: str
    source: str
    origine: str  # "readme" | "scenario" | "carte" | "mesure"

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "titre": self.titre,
            "texte": self.texte,
            "source": self.source,
            "origine": self.origine,
        }


def _sections_readme(markdown: str) -> list[tuple[str, str]]:
    """Découpe le README par titre de niveau 2 et 3.

    Le niveau du titre est conservé dans le libellé (« Latence » vs
    « Limites connues › Classifieur ML ») : une réponse doit pouvoir dire d'où
    elle vient assez précisément pour qu'on la retrouve.
    """
    sections: list[tuple[str, str]] = []
    titre_h2 = ""
    titre_courant = ""
    corps: list[str] = []

    def pousser() -> None:
        texte = "\n".join(corps).strip()
        if titre_courant and texte:
            sections.append((titre_courant, texte))

    for ligne in markdown.splitlines():
        if ligne.startswith("## ") and not ligne.startswith("###"):
            pousser()
            titre_h2 = ligne[3:].strip()
            titre_courant = titre_h2
            corps = []
        elif ligne.startswith("### ") or ligne.startswith("#### "):
            pousser()
            sous = ligne.lstrip("#").strip()
            titre_courant = f"{titre_h2} › {sous}" if titre_h2 else sous
            corps = []
        elif ligne.startswith("# "):
            pousser()
            titre_h2 = ligne[2:].strip()
            titre_courant = titre_h2
            corps = []
        else:
            corps.append(ligne)
    pousser()
    return [(t, c) for t, c in sections if t not in SECTIONS_IGNOREES]


def _mesures() -> list[Extrait]:
    """Mesures lues dans `models/*/metrics.json`, formatées avec leur intervalle.

    Absents (modèle non entraîné), les fichiers ne produisent rien : mieux vaut
    que l'assistant ne connaisse pas un chiffre que d'en servir un périmé.
    """
    extraits: list[Extrait] = []
    libelles = {
        "recall_attacks": "rappel sur les attaques",
        "recall_all_anomalies": "rappel sur les anomalies",
        "false_positive_rate_in_domain": "faux positifs dans le domaine",
        "false_positive_rate_out_of_domain": "faux positifs hors-domaine",
        "false_positive_rate_legitimate": "faux positifs sur l'ensemble des documents légitimes",
    }
    for nom, chemin in METRIQUES.items():
        if not chemin.is_file():
            continue
        try:
            donnees = json.loads(chemin.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        lignes = []
        for cle, libelle in libelles.items():
            brut = donnees.get(cle)
            if not isinstance(brut, dict):
                continue
            proportion = Proportion(
                successes=int(brut["successes"]), total=int(brut["total"]),
                low=float(brut["ci_low"]), high=float(brut["ci_high"]),
                confidence=float(brut.get("confidence", 0.95)),
            )
            lignes.append(f"- {libelle} : {proportion.format()}")
        seuil = donnees.get("threshold")
        if seuil is not None:
            lignes.append(
                f"- seuil de décision calibré : {seuil} "
                "(fixé sur le jeu de calibration, jamais sur le jeu de test)"
            )
        if not lignes:
            continue
        extraits.append(
            Extrait(
                id=f"mesure-{nom}",
                titre=f"Mesures du détecteur « {nom} »",
                texte=(
                    f"Mesures publiées pour le détecteur {nom}, relues à chaud dans son "
                    f"fichier de métriques. Chaque taux est donné avec son intervalle de "
                    f"Wilson et l'effectif qui le soutient.\n" + "\n".join(lignes)
                ),
                source=str(chemin.relative_to(RACINE)),
                origine="mesure",
            )
        )
    return extraits


def charge_base() -> list[Extrait]:
    """Construit la base de connaissances à partir des fichiers du dépôt.

    Rien n'est mis en cache au niveau du module : sur une console de
    démonstration le coût est négligeable, et un cache ferait mentir la
    promesse « les valeurs affichées viennent de l'exécution en cours ».
    """
    extraits: list[Extrait] = []

    if README.is_file():
        for i, (titre, corps) in enumerate(_sections_readme(README.read_text(encoding="utf-8"))):
            extraits.append(
                Extrait(
                    id=f"readme-{i}",
                    titre=titre,
                    texte=corps,
                    source=f"README.md § {titre}",
                    origine="readme",
                )
            )

    for scenario in SCENARIOS:
        corps = "\n".join(
            part
            for part in (
                f"Famille : {scenario.famille}. Référence OWASP : {scenario.owasp}.",
                f"Requête jouée : {scenario.requete}",
                f"Attendu : {scenario.attendu}" if scenario.attendu else "",
                f"À regarder : {scenario.regarder}" if scenario.regarder else "",
                f"Mots-clés : {', '.join(scenario.tags)}" if scenario.tags else "",
            )
            if part
        )
        extraits.append(
            Extrait(
                id=f"scenario-{scenario.id}",
                titre=f"Scénario : {scenario.titre}",
                texte=corps,
                source=f"victim/scenarios.py › {scenario.id}",
                origine="scenario",
            )
        )

    if CARTES_DIR.is_dir():
        for chemin in sorted(CARTES_DIR.glob("*.md")):
            extraits.append(
                Extrait(
                    id=f"carte-{chemin.stem}",
                    titre=f"Carte de modèle : {chemin.stem}",
                    texte=chemin.read_text(encoding="utf-8"),
                    source=str(chemin.relative_to(RACINE)),
                    origine="carte",
                )
            )

    extraits.extend(_mesures())
    return extraits


@dataclass(frozen=True)
class ExtraitTrouve:
    extrait: Extrait
    score: float


def mots_utiles(question: str) -> list[str]:
    """Termes porteurs de sens d'une question, mots vides retirés.

    Retourner une liste vide est une information, pas un échec : cela veut dire
    que la question ne contient aucun mot sur lequel chercher, et l'appelant
    doit alors avouer son ignorance plutôt que classer du bruit.
    """
    return [
        mot
        for mot in tokenize(question)
        if mot not in _MOTS_VIDES
        and (len(mot) >= _LONGUEUR_MINIMALE or mot in _SIGLES_UTILES)
    ]


def cherche(question: str, base: list[Extrait], top: int = EXTRAITS_PAR_REPONSE) -> list[ExtraitTrouve]:
    """Classement BM25 des extraits, sur les seuls mots porteurs de sens.

    Réutilise `victim.rag.rank` plutôt qu'un second classement : une deuxième
    implémentation de BM25 dériverait de la première, et le laboratoire de
    classement cesserait de décrire ce que l'assistant fait réellement.

    Deux garde-fous en sortie, et le second compte plus que le premier :

    * un **score plancher**, qui écarte le passage « le moins mauvais » ;
    * une **couverture minimale** de la question par l'extrait (voir
      `COUVERTURE_MINIMALE`). BM25 sait attribuer un score élevé sur un seul
      terme rare : sans ce contrôle, un mot inhabituel et hors sujet suffit à
      faire remonter un passage qui ne répond à rien.
    """
    if not base:
        return []
    termes = mots_utiles(question)
    if not termes:
        return []

    documents = [
        rag.Document(id=e.id, content=f"{e.titre}\n{e.texte}") for e in base
    ]
    par_id = {e.id: e for e in base}
    classement = rag.rank(" ".join(termes), documents=documents, ranker="bm25")

    uniques = set(termes)
    requis = max(1, math.ceil(len(uniques) * COUVERTURE_MINIMALE))

    trouves: list[ExtraitTrouve] = []
    for score_doc in classement[:top]:
        if score_doc.score < SCORE_MINIMUM:
            continue
        extrait = par_id[score_doc.id]
        presents = set(tokenize(f"{extrait.titre}\n{extrait.texte}"))
        if len(presents & uniques) < requis:
            continue
        trouves.append(ExtraitTrouve(extrait=extrait, score=score_doc.score))
    return trouves


def _resume(texte: str, limite: int = RESUME_MAX_CARACTERES) -> str:
    """Coupe un extrait à une taille lisible, sur une frontière de paragraphe.

    Couper au milieu d'une phrase produirait une citation tronquée, c'est-à-dire
    une citation qu'on ne peut pas vérifier d'un coup d'œil.
    """
    texte = texte.strip()
    if len(texte) <= limite:
        return texte
    coupe = texte[:limite]
    for separateur in ("\n\n", ". ", "\n"):
        position = coupe.rfind(separateur)
        if position > limite * 0.5:
            return coupe[: position + len(separateur)].strip() + " […]"
    return coupe.strip() + " […]"


AVEU_IGNORANCE = (
    "Je n'ai rien trouvé dans le dépôt qui réponde à ça, et je préfère le dire plutôt "
    "que de composer une réponse plausible. Cet assistant ne sait que ce qui est écrit "
    "et mesuré dans le projet : les signaux et leurs taux d'erreur, les scénarios du "
    "banc, la couverture OWASP, les limites connues, la discipline de mesure. "
    "Reformule avec un de ces termes, ou passe en mode attaque pour essayer de me piéger."
)


@dataclass(frozen=True)
class Reponse:
    texte: str
    extraits: tuple[ExtraitTrouve, ...]
    a_repondu: bool

    def sources_brutes(self) -> list[str]:
        """Textes servant de référence au vérificateur d'ancrage."""
        return [f"{t.extrait.titre}\n{t.extrait.texte}" for t in self.extraits]


def repond(question: str, base: list[Extrait] | None = None) -> Reponse:
    """Réponse déterministe : des extraits réels, cités, et rien d'autre.

    Aucun LLM ici. C'est la réponse servie par défaut, celle qui marche sans clé
    d'API, et celle sur laquelle on retombe quand la reformulation échoue au
    contrôle d'ancrage.
    """
    base = charge_base() if base is None else base
    trouves = cherche(question, base)
    if not trouves:
        return Reponse(texte=AVEU_IGNORANCE, extraits=(), a_repondu=False)

    morceaux = [
        f"**{t.extrait.titre}**\n\n{_resume(t.extrait.texte)}" for t in trouves
    ]
    return Reponse(texte="\n\n---\n\n".join(morceaux), extraits=tuple(trouves), a_repondu=True)


# Consigne de reformulation. Volontairement étroite : on ne demande pas au
# modèle d'être utile, on lui demande de ne rien ajouter. « Sois concis et
# pédagogue » suffirait à lui faire combler les trous avec du vraisemblable.
CONSIGNE_REFORMULATION = (
    "Tu reformules des extraits de documentation technique pour un visiteur.\n"
    "Règles absolues :\n"
    "1. N'utilise QUE les informations des extraits ci-dessous.\n"
    "2. N'invente aucun chiffre. Ne calcule, n'arrondis et ne convertis aucun "
    "chiffre : recopie-les tels quels.\n"
    "3. N'invente aucun nom de fichier, de fonction, de classe ni d'option.\n"
    "4. Si les extraits ne répondent pas à la question, dis-le franchement.\n"
    "5. Réponds en français, en 6 phrases maximum, sans titre ni liste.\n"
)


def prompt_reformulation(question: str, reponse: Reponse) -> str:
    extraits = "\n\n".join(
        f"[Extrait {i + 1} — {t.extrait.source}]\n{_resume(t.extrait.texte)}"
        for i, t in enumerate(reponse.extraits)
    )
    return f"{CONSIGNE_REFORMULATION}\nQuestion du visiteur : {question}\n\n{extraits}\n"


def mesures_en_dur(chemin: Path | None = None) -> list[str]:
    """Littéraux numériques exécutables de ce module, hors constantes déclarées.

    Sert au test qui interdit d'écrire une mesure à la main ici : un chiffre
    recopié dérive de sa source, et c'est exactement le défaut corrigé au lot 5A
    sur `data/` puis au lot 7 sur le TTR figé de la console.

    L'analyse passe par l'AST et non par une expression régulière sur le texte.
    La première version lisait ligne à ligne : elle signalait « lot 5A », « 0,014 »
    et « utf-8 » dans les commentaires et les chaînes, c'est-à-dire de la prose
    qui explique justement pourquoi il ne faut pas coder un chiffre en dur. Un
    contrôle qui crie sur sa propre documentation finit désactivé.

    Sont tolérés : les constantes de module en MAJUSCULES (déclarées, relues par
    les tests) et les petits entiers de mécanique (indices, bornes de découpe).
    """
    chemin = Path(__file__) if chemin is None else chemin
    arbre = ast.parse(chemin.read_text(encoding="utf-8"))

    # Les affectations de constantes de module sont du paramétrage assumé.
    lignes_constantes: set[int] = set()
    for noeud in arbre.body:
        cibles = []
        if isinstance(noeud, ast.Assign):
            cibles = noeud.targets
        elif isinstance(noeud, ast.AnnAssign):
            cibles = [noeud.target]
        if any(isinstance(c, ast.Name) and c.id.isupper() for c in cibles):
            for sous in ast.walk(noeud):
                if hasattr(sous, "lineno"):
                    lignes_constantes.add(sous.lineno)

    toleres = {0, 1, 2, 3, 0.5, 0.95}
    suspects: list[str] = []
    for noeud in ast.walk(arbre):
        if not isinstance(noeud, ast.Constant):
            continue
        if not isinstance(noeud.value, (int, float)) or isinstance(noeud.value, bool):
            continue
        if noeud.lineno in lignes_constantes or noeud.value in toleres:
            continue
        suspects.append(f"ligne {noeud.lineno} : {noeud.value}")
    return suspects
