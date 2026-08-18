"""
Le seul côté que ce produit ne regardait pas : ce qui SORT.

L'angle mort
------------
AEGIS inspectait la requête (`on_prompt`), les documents récupérés
(`on_retrieval`), les retours d'outils (`on_tool_result`) et les appels d'outils
(`on_tool_call`). Quatre points d'interception, tous en entrée. La réponse
finale, elle, traversait sans être regardée : `on_response` ne servait qu'à
vérifier qu'une source était citée, et ne modifiait rien.

Trois lignes du tableau OWASP tenaient à ce seul manque — LLM02 (aucun filtre de
sortie), LLM08 (rien ne détecte que le modèle restitue son prompt système),
LLM10 (la réponse traverse sans validation, le seul rempart étant l'échappement
de React, côté client).

Ce qui change dans le contrat, et pourquoi il faut le dire
----------------------------------------------------------
C'est le premier endroit où AEGIS **modifie ce que l'utilisateur reçoit**.
Jusqu'ici, un faux positif coûtait un bout de contexte : l'agent perdait un
document et continuait. Ici, un faux positif abîme la réponse rendue à une
personne. Le curseur de prudence est donc réglé plus haut qu'ailleurs, et ça se
voit dans deux décisions :

* **Deux niveaux de gravité, pas un.** Les *secrets* (clé d'API, jeton) sont
  masqués : ils n'ont aucune raison légitime d'apparaître dans une réponse, et
  le motif est spécifique. Les *données personnelles* (email, téléphone) sont
  **signalées et comptées, pas masquées par défaut** — parce que dans une
  réponse, un numéro est le plus souvent celui que l'utilisateur a lui-même
  fourni, ou celui du service qu'il demandait. Masquer « voici le numéro du
  service client : 01 23 45 67 89 » ne protège personne et casse la réponse.
  `mask_personal_data=True` renverse ce choix quand le contexte l'exige.
* **Aucun signal probabiliste ne décide ici.** Comme sur `on_prompt`, et pour la
  même raison mesurée : les règles déterministes sont à 0 % de faux positifs, le
  classifieur à 50 %.

Sur la détection de restitution du prompt système
--------------------------------------------------
Elle ne cherche pas des phrases suspectes devinées à l'avance (« mes
instructions sont… »), qui ne couvriraient que les formulations prévues. Elle
compare la réponse au prompt **réellement envoyé**, par empreintes de n-grammes.
C'est le même raisonnement que la vérification d'ancrage du lot 8 : on confronte
à la source, pas à une liste d'intuitions.

Ce que ça ne fait pas
---------------------
* **La paraphrase échappe au contrôle.** Un modèle qui résume ses instructions
  avec d'autres mots ne déclenche aucune empreinte. Détecter ça demanderait un
  modèle d'inférence, et ce n'est pas fait.
* **La neutralisation du balisage est une défense en profondeur, pas la
  correction.** La vraie correction est un encodage contextuel au point de
  rendu. Neutraliser ici réduit la surface ; ça ne dispense pas le client de
  faire son travail, et un client qui ferait confiance à ce filtre plutôt qu'à
  son propre échappement serait moins sûr, pas plus.
* **Aucun contrôle sémantique.** Une réponse fausse, biaisée ou dangereuse
  passe : ce module regarde des formes, pas du sens.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from aegis_core.pii_detector import PII_PATTERNS, VALIDATEURS

# Catégories qui n'ont aucune raison légitime d'apparaître dans une réponse
# rendue à un utilisateur. Le masquage y est sans regret.
CATEGORIES_SECRETES = frozenset({"CLE_API"})

# Le reste : signalé et compté, masqué seulement si l'appelant le demande.
# Un email dans une réponse est le plus souvent celui que l'utilisateur vient
# de donner, ou celui du service qu'il demandait.
CATEGORIES_PERSONNELLES = frozenset(
    nom for nom, _ in PII_PATTERNS if nom not in CATEGORIES_SECRETES
)

MARQUEUR = "[MASQUÉ PAR AEGIS]"

# Longueur de l'empreinte, en mots, pour la détection de restitution du prompt
# système. Huit mots consécutifs identiques ne se produisent pas par hasard dans
# du texte naturel ; en descendre à quatre attraperait des tournures courantes
# (« n'hésitez pas à me contacter si »), et un détecteur qui crie sur du français
# ordinaire finit désactivé.
TAILLE_EMPREINTE = 8

# Schémas d'URL qui exécutent au lieu de naviguer.
#
# La première version matchait `data\s*:` tout court. Mesuré sur le corpus de
# contrôle, ça neutralisait « Le fichier data: 3 colonnes, 1 200 lignes » — une
# phrase française parfaitement ordinaire. `data:` n'est une URL que suivi d'un
# type MIME ; et `javascript:` suivi d'une espace est de la prose, pas un lien.
_SCHEMES_ACTIFS = re.compile(
    r"\b(?:javascript|vbscript):\S[^\s\"'>]*"
    r"|\bdata:[a-z]+/[a-z0-9.+-]+[^\s\"'>]*",
    re.IGNORECASE,
)

# Balises et attributs actifs. On ne prétend pas assainir du HTML — on neutralise
# ce qui exécute, et on le dit.
_BALISES_ACTIVES = re.compile(
    r"</?\s*(?:script|iframe|object|embed|form|svg|math|style|link|meta|base)\b[^>]*>",
    re.IGNORECASE,
)
# Attribut d'événement, cherché UNIQUEMENT à l'intérieur d'une balise.
#
# Mesuré aussi : la version qui balayait tout le texte neutralisait
# « bouton.onclick = validerFormulaire » dans un extrait de code JavaScript
# cité en exemple. Un gestionnaire d'événement n'est dangereux que s'il est
# posé sur un élément ; hors d'une balise, c'est du texte.
_BALISE_QUELCONQUE = re.compile(r"<[^>]{1,2000}>")
_ATTRIBUTS_EVENEMENT = re.compile(
    r"\bon[a-z]{3,20}\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE
)

# Image Markdown pointant vers un domaine extérieur : le navigateur la charge
# SANS action de l'utilisateur, donc l'URL — et tout ce qu'un modèle y a glissé
# en paramètre — part chez son propriétaire. C'est un canal d'exfiltration réel
# et bien documenté contre les agents, pas une hypothèse.
_IMAGE_MARKDOWN = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)[^)]*\)", re.IGNORECASE)

_MOT = re.compile(r"[\wàâäéèêëïîôöùûüçñ]+", re.UNICODE)


def _mots(texte: str) -> list[str]:
    return _MOT.findall(texte.lower())


def empreintes(texte: str, taille: int = TAILLE_EMPREINTE) -> set[str]:
    """N-grammes de mots normalisés, pour comparer deux textes sans regex devinée.

    Retourne un ensemble vide si le texte est plus court que `taille` : on ne
    peut alors rien affirmer, et fabriquer une empreinte plus courte ferait
    monter les faux positifs sans prévenir.
    """
    mots = _mots(texte)
    if len(mots) < taille:
        return set()
    return {" ".join(mots[i : i + taille]) for i in range(len(mots) - taille + 1)}


@dataclass(frozen=True)
class OutputScanResult:
    """Ce qui a été trouvé dans une réponse, et ce qui en a été fait."""

    text: str
    modified: bool = False
    secrets_masques: tuple[str, ...] = field(default_factory=tuple)
    donnees_personnelles: tuple[str, ...] = field(default_factory=tuple)
    donnees_personnelles_masquees: bool = False
    contexte_restitue: tuple[str, ...] = field(default_factory=tuple)
    balisage_neutralise: tuple[str, ...] = field(default_factory=tuple)

    @property
    def flagged(self) -> bool:
        """Quelque chose a été vu — masqué ou seulement signalé."""
        return bool(
            self.secrets_masques
            or self.donnees_personnelles
            or self.contexte_restitue
            or self.balisage_neutralise
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "modified": self.modified,
            "flagged": self.flagged,
            "secrets_masques": list(self.secrets_masques),
            "donnees_personnelles": list(self.donnees_personnelles),
            "donnees_personnelles_masquees": self.donnees_personnelles_masquees,
            "contexte_restitue": list(self.contexte_restitue),
            "balisage_neutralise": list(self.balisage_neutralise),
        }


@dataclass
class OutputGuard:
    """Contrôle de la réponse avant qu'elle n'atteigne l'utilisateur.

    Args:
        mask_personal_data: masquer aussi les données personnelles, et pas
            seulement les secrets. Faux par défaut — voir la docstring du module
            pour la raison, qui n'est pas de la timidité mais un arbitrage de
            faux positifs.
        hidden_context: textes qui ne doivent jamais ressortir (prompt système,
            consignes internes). Comparés par empreintes de n-grammes, donc à ce
            qui a réellement été envoyé.
        neutralize_markup: neutraliser le balisage actif et les schémas d'URL
            exécutables. Défense en profondeur : la correction est un encodage
            contextuel au point de rendu.
    """

    mask_personal_data: bool = False
    hidden_context: tuple[str, ...] = ()
    neutralize_markup: bool = True
    taille_empreinte: int = TAILLE_EMPREINTE
    # Hôtes d'images autorisés. Vide = on ne neutralise que les images dont
    # l'URL PORTE DES DONNÉES (chaîne de requête), pas toutes les images —
    # mesuré : neutraliser un `![schéma](https://docs.exemple.fr/img/x.png)`
    # de documentation cassait une réponse légitime sur six.
    allowed_image_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self._empreintes_cachees: set[str] = set()
        for texte in self.hidden_context:
            self._empreintes_cachees |= empreintes(texte, self.taille_empreinte)

    # -- LLM02 : ce qui ne doit pas sortir ---------------------------------

    def _filtre_donnees(self, texte: str) -> tuple[str, list[str], list[str]]:
        """Applique les MÊMES motifs ET les mêmes validateurs que le détecteur d'entrée.

        Réutiliser les motifs sans les validateurs ferait diverger les deux
        chemins : `PiiDetector` cesserait de masquer un numéro de dossier grâce
        à Luhn pendant que le filtre de sortie continuerait de le signaler. Deux
        composants qui appliquent « la même règle » avec des résultats
        différents, c'est la source de bug que ce dépôt traque partout ailleurs.
        """
        secrets: list[str] = []
        personnelles: list[str] = []
        resultat = texte
        for nom, motif in PII_PATTERNS:
            validateur = VALIDATEURS.get(nom)
            occurrences = [
                m for m in re.finditer(motif, resultat)
                if validateur is None or validateur(m.group(0))
            ]
            if not occurrences:
                continue
            if nom in CATEGORIES_SECRETES or self.mask_personal_data:
                for m in reversed(occurrences):
                    resultat = resultat[: m.start()] + MARQUEUR + resultat[m.end() :]
                (secrets if nom in CATEGORIES_SECRETES else personnelles).append(nom)
            else:
                personnelles.append(nom)
        return resultat, secrets, personnelles

    # -- LLM08 : ce qui devait rester caché --------------------------------

    def _cherche_contexte(self, texte: str) -> list[str]:
        """Passages du contexte caché retrouvés mot pour mot dans la réponse.

        On ne retourne pas les n-grammes bruts. Un passage de vingt mots
        restitué produit treize empreintes qui se chevauchent, et une liste de
        treize fragments quasi identiques est illisible : l'opérateur doit voir
        *ce qui a fuité*, pas la mécanique de détection. Les positions
        correspondantes sont donc fusionnées en segments contigus, et c'est le
        texte de ces segments qui est rapporté — même exigence que
        `matched_rules` pour les règles d'injection.
        """
        if not self._empreintes_cachees:
            return []
        mots = _mots(texte)
        n = self.taille_empreinte
        if len(mots) < n:
            return []

        debuts = [
            i
            for i in range(len(mots) - n + 1)
            if " ".join(mots[i : i + n]) in self._empreintes_cachees
        ]
        if not debuts:
            return []

        segments: list[tuple[int, int]] = []
        debut, fin = debuts[0], debuts[0] + n
        for position in debuts[1:]:
            if position <= fin:  # chevauchement ou contiguïté
                fin = position + n
            else:
                segments.append((debut, fin))
                debut, fin = position, position + n
        segments.append((debut, fin))

        return [" ".join(mots[a:b]) for a, b in segments]

    # -- LLM10 : ce qui ne doit pas s'exécuter -----------------------------

    def _neutralise_balisage(self, texte: str) -> tuple[str, list[str]]:
        trouve: list[str] = []
        resultat = texte

        if _BALISES_ACTIVES.search(resultat):
            trouve.append("balise_active")
            resultat = _BALISES_ACTIVES.sub("[BALISE NEUTRALISÉE]", resultat)
        def _dans_la_balise(correspondance: re.Match[str]) -> str:
            balise = correspondance.group(0)
            nettoyee = _ATTRIBUTS_EVENEMENT.sub("[ATTRIBUT NEUTRALISÉ]", balise)
            if nettoyee != balise:
                trouve.append("attribut_evenement")
            return nettoyee

        resultat = _BALISE_QUELCONQUE.sub(_dans_la_balise, resultat)
        if _SCHEMES_ACTIFS.search(resultat):
            trouve.append("schema_url_actif")
            resultat = _SCHEMES_ACTIFS.sub("[URL NEUTRALISÉE]", resultat)
        # L'image distante est traitée en DERNIER : la neutraliser plus tôt
        # transformerait son URL en marqueur, et les contrôles précédents ne
        # verraient plus le schéma qu'elle transporte.
        def _image(correspondance: re.Match[str]) -> str:
            url = correspondance.group(1)
            if self._image_autorisee(url):
                return correspondance.group(0)
            trouve.append("image_distante")
            return "[IMAGE DISTANTE NEUTRALISÉE]"

        resultat = _IMAGE_MARKDOWN.sub(_image, resultat)
        return resultat, sorted(set(trouve))

    def _image_autorisee(self, url: str) -> bool:
        """Décide si une image distante peut rester.

        Avec une liste d'hôtes autorisés, la règle est nette. Sans elle, on ne
        neutralise que les URL **porteuses de données** (chaîne de requête) :
        c'est le canal d'exfiltration, et c'est ce qui distingue un
        `?d=<secret>` d'un `/img/schema.png` de documentation.

        La limite est réelle et doit être dite : un attaquant qui encode sa
        charge dans le CHEMIN plutôt que dans la requête passe au travers. La
        correction robuste est la liste d'hôtes ; l'heuristique n'est là que
        pour ne pas casser toutes les images quand personne ne l'a configurée.
        """
        if self.allowed_image_hosts:
            hote = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].lower()
            hote = hote.split("@")[-1].split(":")[0]
            return any(
                hote == autorise.lower() or hote.endswith("." + autorise.lower())
                for autorise in self.allowed_image_hosts
            )
        return "?" not in url

    # -- entrée publique ---------------------------------------------------

    def scan(self, response_text: str) -> OutputScanResult:
        """Inspecte une réponse et retourne le texte à rendre.

        L'ordre compte : on filtre les données AVANT de neutraliser le balisage,
        pour qu'une clé d'API cachée dans une URL soit masquée en tant que clé
        plutôt que noyée dans un marqueur d'URL neutralisée.
        """
        texte, secrets, personnelles = self._filtre_donnees(response_text)
        contexte = self._cherche_contexte(response_text)

        balisage: list[str] = []
        if self.neutralize_markup:
            texte, balisage = self._neutralise_balisage(texte)

        return OutputScanResult(
            text=texte,
            modified=texte != response_text,
            secrets_masques=tuple(secrets),
            donnees_personnelles=tuple(personnelles),
            donnees_personnelles_masquees=self.mask_personal_data,
            contexte_restitue=tuple(contexte),
            balisage_neutralise=tuple(balisage),
        )
