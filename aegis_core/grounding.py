"""
Vérification d'ancrage : une réponse générée dit-elle ce que ses sources disent ?

Le problème
-----------
La vérification de citation (section 4.5) répond à « le modèle a-t-il cité une
source ? ». C'est nécessaire et très insuffisant : citer un document n'oblige à
rien sur ce qu'on lui fait dire. Le README classe cette lacune depuis le début
sous LLM07 — *« Manque la vérification d'ancrage : la réponse est-elle réellement
soutenue par la source citée ? »*.

Ce module ferme la partie de ce trou qui compte le plus ici : **les chiffres**.

Pourquoi les chiffres d'abord
------------------------------
Ce dépôt tient entièrement sur une promesse — *un chiffre qu'on publie, on l'a
mesuré*. Un assistant qui répondrait « AEGIS bloque 97 % des injections » ferait
plus de dégâts qu'une faille : il retournerait l'argument du projet contre
lui-même, et il le ferait avec aplomb. Un modèle de langage est précisément bon
à produire un nombre plausible et faux.

La règle est donc brutale et vérifiable : **tout littéral numérique présent dans
la réponse doit être présent dans les sources**. Pas d'arrondi, pas de calcul,
pas de « à peu près ». Une réponse qui échoue n'est pas corrigée, elle est
rejetée — l'appelant sert alors la réponse déterministe.

Deuxième famille : les identifiants
------------------------------------
`AegisConfig.strict_mode`, `scripts/train_something.py`, `on_tool_result` — un
modèle invente ces noms avec la même aisance. Ils sont vérifiables exactement
comme les nombres, et un nom d'API inexistant dans une documentation est une
perte de confiance immédiate pour un lecteur technique.

Ce que ça ne fait pas — et il faut le dire
-------------------------------------------
* **Aucune inférence sémantique.** « Le détecteur bloque 100 % des attaques » et
  « le détecteur laisse passer 100 % des attaques » contiennent les mêmes
  chiffres et les mêmes mots. Ce vérificateur les accepte tous les deux. Ancrer
  le *sens* demanderait un modèle d'inférence (NLI), c'est un autre chantier et
  il n'est pas fait.
* **Les nombres écrits en toutes lettres échappent au contrôle.** « quatre-vingt
  pour cent » n'est pas un littéral numérique. La parade est de contraindre le
  style de la réponse, pas de deviner.
* **Un nombre présent dans une source mais sur un autre sujet passe.** Le
  contrôle est lexical, à l'échelle du lot de sources fourni.

Autrement dit : ce module rend impossible d'*inventer* un chiffre, pas de le
*mal employer*. C'est une garantie étroite, et c'est pour ça qu'elle est écrite
noir sur blanc plutôt que résumée en « réponses vérifiées ».
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

# Un littéral numérique : chiffres, séparateur décimal virgule OU point, et
# séparateurs de milliers usuels en français (espace fine insécable, espace
# insécable, espace ordinaire) tolérés à l'intérieur.
_NOMBRE_RE = re.compile(r"\d[\d   ]*(?:[.,]\d+)?")

# Identifiants de code : snake_case, CamelCase, chemins de fichiers, attributs
# pointés. Le motif exige un marqueur (`_`, `/`, `.py`, une majuscule interne)
# pour ne pas ramasser tous les mots courants.
_IDENT_RE = re.compile(
    r"\b(?:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"   # a.b / a.b.c
    r"|[a-z][a-z0-9]*(?:_[a-z0-9]+)+"                          # snake_case
    r"|[a-z_][A-Za-z0-9_/]*\.(?:py|ts|tsx|json|jsonl|yml|yaml|css|md)"  # fichiers
    r"|[a-z]+(?:/[a-z_][a-z0-9_]*)+"                           # chemins
    r"|[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+"                      # CamelCase
    r")\b"
)

# Nombres trop banals pour porter une information : les exiger dans les sources
# ferait échouer « les 2 endpoints » ou « en 1 seconde » sans rien protéger.
# 0 et 1 sont volontairement DANS la liste : un « 0 % » ou « 1,00 » qui compte
# vraiment apparaîtra de toute façon dans les sources, et l'exempter évite de
# rejeter une phrase pour un « une » numérique.
_BANALS = frozenset({Decimal(0), Decimal(1), Decimal(2)})


def _valeur(brut: str) -> Decimal | None:
    """Normalise un littéral en valeur comparable.

    `1,00`, `1.0` et `1` doivent être la même chose : sinon le vérificateur
    rejetterait une réponse pour une différence de typographie, ce qui le
    rendrait inutilisable et donc désactivé.
    """
    nettoye = brut.replace(" ", "").replace(" ", "").replace(" ", "")
    nettoye = nettoye.replace(",", ".")
    if not nettoye or nettoye in {".", ""}:
        return None
    try:
        return Decimal(nettoye).normalize()
    except InvalidOperation:
        return None


def nombres(texte: str) -> set[Decimal]:
    """Valeurs numériques distinctes d'un texte."""
    trouves = set()
    for brut in _NOMBRE_RE.findall(texte):
        valeur = _valeur(brut)
        if valeur is not None:
            trouves.add(valeur)
    return trouves


def identifiants(texte: str) -> set[str]:
    """Identifiants de code distincts d'un texte, casse conservée."""
    return set(_IDENT_RE.findall(texte))


@dataclass(frozen=True)
class GroundingReport:
    """Verdict d'ancrage, avec le détail de ce qui n'est pas soutenu."""

    ok: bool
    nombres_non_soutenus: tuple[str, ...] = ()
    identifiants_non_soutenus: tuple[str, ...] = ()
    nombres_verifies: int = 0
    identifiants_verifies: int = 0

    @property
    def raison(self) -> str | None:
        if self.ok:
            return None
        morceaux = []
        if self.nombres_non_soutenus:
            morceaux.append(
                "chiffre(s) absent(s) des sources : "
                + ", ".join(self.nombres_non_soutenus)
            )
        if self.identifiants_non_soutenus:
            morceaux.append(
                "identifiant(s) absent(s) des sources : "
                + ", ".join(self.identifiants_non_soutenus)
            )
        return " ; ".join(morceaux)

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "raison": self.raison,
            "nombres_non_soutenus": list(self.nombres_non_soutenus),
            "identifiants_non_soutenus": list(self.identifiants_non_soutenus),
            "nombres_verifies": self.nombres_verifies,
            "identifiants_verifies": self.identifiants_verifies,
        }


@dataclass
class GroundingVerifier:
    """Rejette une réponse dont un chiffre ou un identifiant n'est pas dans les sources.

    `verifier_identifiants` peut être coupé : sur du texte de conversation libre,
    le motif d'identifiant ramasse parfois un mot composé légitime. Le contrôle
    numérique, lui, n'est pas désactivable — c'est le seul qui protège la
    promesse centrale du projet.
    """

    verifier_identifiants: bool = True
    banals: frozenset[Decimal] = field(default_factory=lambda: _BANALS)

    def check(self, reponse: str, sources: list[str] | tuple[str, ...]) -> GroundingReport:
        texte_sources = "\n".join(sources)
        nombres_sources = nombres(texte_sources)
        idents_sources = identifiants(texte_sources)

        nombres_reponse = nombres(reponse)
        a_verifier = {n for n in nombres_reponse if n not in self.banals}
        manquants = sorted(a_verifier - nombres_sources)

        idents_manquants: list[str] = []
        idents_reponse: set[str] = set()
        if self.verifier_identifiants:
            idents_reponse = identifiants(reponse)
            # Comparaison insensible à la casse : « AegisConfig » et
            # « aegisconfig » désignent la même chose, et rejeter sur la casse
            # produirait du bruit sans rien attraper de dangereux.
            bas = {i.lower() for i in idents_sources}
            idents_manquants = sorted(i for i in idents_reponse if i.lower() not in bas)

        return GroundingReport(
            ok=not manquants and not idents_manquants,
            nombres_non_soutenus=tuple(str(n) for n in manquants),
            identifiants_non_soutenus=tuple(idents_manquants),
            nombres_verifies=len(a_verifier),
            identifiants_verifies=len(idents_reponse),
        )
