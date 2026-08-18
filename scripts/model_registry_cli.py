"""
Cycle de vie des modèles : construire une carte, passer la porte, publier.

    python -m scripts.model_registry_cli check      # porte de promotion (sans écrire)
    python -m scripts.model_registry_cli promote    # passe la porte PUIS enregistre
    python -m scripts.model_registry_cli cards      # (re)génère docs/model_cards/
    python -m scripts.model_registry_cli verify     # le disque correspond-il au registre ?

Pourquoi `check` et `promote` sont deux commandes
--------------------------------------------------
Une porte qui enregistre en même temps qu'elle juge n'est pas une porte : elle
constate après coup. `check` est ce que lance la CI sur une proposition de
modification — il lit, compare, et sort en erreur si une régression est prouvée,
sans jamais toucher au registre. `promote` est le geste délibéré de quelqu'un qui
a lu le rapport.

Aucune description n'est saisie deux fois
------------------------------------------
Les métadonnées éditoriales (usage prévu, modes d'échec) vivent dans
`DESCRIPTIONS` ci-dessous, et tout le reste — mesures, intervalles, seuils,
empreintes — est dérivé des artefacts produits par l'entraînement. C'est la même
règle que partout ailleurs dans ce dépôt : un chiffre recopié dérive de sa
source, donc on ne le recopie pas.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from aegis_core.model_registry import (
    MetricEntry,
    ModelCard,
    check_integrity,
    incumbent,
    load_registry,
    record,
    sha256_files,
)
from aegis_core.promotion import PLUS_BAS, PLUS_HAUT, evalue, formate

RACINE = Path(__file__).resolve().parent.parent
CARTES_DIR = RACINE / "docs" / "model_cards"

MODEL_DIRS = {
    "rag_outlier": RACINE / "models" / "rag_outlier",
    "behavior_vae": RACINE / "models" / "behavior_vae",
}

DATASETS = {
    "rag_outlier": [
        RACINE / "data" / "rag_corpus_train.jsonl",
        RACINE / "data" / "rag_corpus_calibration.jsonl",
        RACINE / "data" / "rag_corpus_test.jsonl",
    ],
    "behavior_vae": [
        RACINE / "data" / "behavior_sessions_train.jsonl",
        RACINE / "data" / "behavior_sessions_calibration.jsonl",
        RACINE / "data" / "behavior_sessions_test.jsonl",
    ],
}

# Sens de « mieux » par métrique. Sans cette table, la porte de promotion
# confondrait une baisse des faux positifs (bonne nouvelle) avec une baisse du
# rappel (mauvaise) : les deux sont « une baisse ».
DIRECTIONS = {
    "recall_attacks": PLUS_HAUT,
    "recall_all_anomalies": PLUS_HAUT,
    "false_positive_rate_in_domain": PLUS_BAS,
    "false_positive_rate_out_of_domain": PLUS_BAS,
    "false_positive_rate_legitimate": PLUS_BAS,
}

# Partie éditoriale des cartes : ce qu'aucun artefact ne peut déduire.
DESCRIPTIONS: dict[str, dict[str, object]] = {
    "rag_outlier": {
        "intended_use": (
            "Signaler qu'un document récupéré s'éloigne du domaine documentaire sur "
            "lequel l'agent a été calibré. Signal **consultatif** : il est journalisé "
            "et compté, il ne neutralise rien par lui-même."
        ),
        "decision_role": "consultatif",
        "known_failures": (
            "Tout texte légitime hors du registre du corpus (note juridique, bulletin "
            "météo, rapport financier) le fait réagir : c'est la cause directe du taux "
            "de faux positifs hors-domaine mesuré plus haut, et la raison pour laquelle "
            "ce détecteur n'a pas le droit de bloquer.",
            "Représentation TF-IDF : deux textes qui disent la même chose avec un autre "
            "vocabulaire sont vus comme éloignés. Aucune notion de sens.",
            "Le seuil est calibré sur un corpus de tickets de support en français. "
            "Déployé sur un autre domaine, il doit être recalibré — le réutiliser tel "
            "quel revient à publier un taux qui n'a pas été mesuré là où il sert.",
        ),
        "training_command": (
            "python -m scripts.generate_rag_corpus && "
            "python -m scripts.train_rag_outlier_detector"
        ),
        "notes": (
            "Découpe train/calibration/test disjointe par gabarit : deux variantes d'un "
            "même modèle de document ne peuvent pas se retrouver de part et d'autre de "
            "la frontière. Le seuil est fixé sur la calibration, jamais sur le test."
        ),
    },
    "behavior_vae": {
        "intended_use": (
            "Repérer une suite d'actions d'agent statistiquement anormale sur une "
            "fenêtre de session (rafale d'actions sensibles, clôture en masse, "
            "détournement). Signal **consultatif**."
        ),
        "decision_role": "consultatif",
        "known_failures": (
            "Un comportement légitime mais rare — une opération de maintenance groupée, "
            "par exemple — ressemble à une anomalie : le détecteur apprend l'habituel, "
            "pas le licite.",
            "La fenêtre est indexée par (tenant, agent, session). Sans identifiant de "
            "session fourni par l'orchestrateur, l'état se dégrade en fenêtre partagée, "
            "et le rapport de robustesse le signale.",
            "Un attaquant qui étale ses actions sur plusieurs sessions courtes reste "
            "sous le seuil, par construction.",
        ),
        "training_command": (
            "python -m scripts.generate_behavior_sessions && "
            "python -m scripts.train_behavior_vae"
        ),
        "notes": (
            "Seuil calibré à un taux de faux positifs visé sur le jeu de calibration, "
            "puis mesuré sur un jeu de test tenu à l'écart."
        ),
    },
}


def _version(dossier: Path) -> str:
    """Version = date UTC + préfixe d'empreinte.

    Un numéro incrémental supposerait un compteur partagé ; l'empreinte suffit à
    distinguer deux entraînements, et la date rend la lecture humaine possible.
    """
    fichiers = sorted(p for p in dossier.iterdir() if p.is_file() and p.name != "MANIFEST.json")
    empreinte = sha256_files(fichiers)
    horodatage = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"{horodatage}-{empreinte[:8]}"


def _metriques(brut: dict) -> tuple[MetricEntry, ...]:
    entrees = []
    for cle, valeur in brut.items():
        if not isinstance(valeur, dict) or "successes" not in valeur:
            continue
        direction = DIRECTIONS.get(cle)
        if direction is None:
            # Une métrique sans sens de lecture ne peut pas être arbitrée. La
            # taire serait pire : elle disparaîtrait silencieusement du contrôle.
            print(
                f"  attention : métrique « {cle} » sans direction déclarée — "
                "ajoute-la dans DIRECTIONS, sinon la porte de promotion l'ignore.",
                file=sys.stderr,
            )
            continue
        entrees.append(
            MetricEntry(
                name=cle,
                successes=int(valeur["successes"]),
                total=int(valeur["total"]),
                low=float(valeur["ci_low"]),
                high=float(valeur["ci_high"]),
                direction=direction,
            )
        )
    return tuple(sorted(entrees, key=lambda m: m.name))


def construit_carte(nom: str) -> ModelCard | None:
    """Assemble une carte depuis les artefacts sur disque, ou None si absents."""
    dossier = MODEL_DIRS[nom]
    metrics_path = dossier / "metrics.json"
    if not metrics_path.is_file():
        return None

    brut = json.loads(metrics_path.read_text(encoding="utf-8"))
    fichiers = sorted(p for p in dossier.iterdir() if p.is_file() and p.name != "MANIFEST.json")
    donnees = [p for p in DATASETS[nom] if p.is_file()]
    edito = DESCRIPTIONS[nom]

    empreinte_artefact = sha256_files(fichiers)
    empreinte_donnees = sha256_files(donnees)

    # Idempotence : un modèle inchangé garde SA version et SA date.
    #
    # Sans ça, relancer `promote` sur des artefacts identiques produisait une
    # nouvelle version et une nouvelle date — donc un diff dans un fichier
    # versionné, sans qu'aucun modèle n'ait bougé. Un registre qui bruite à
    # chaque exécution est un registre dont on cesse de lire les diffs, et un
    # diff qu'on ne lit plus ne protège plus de rien.
    en_place = incumbent(nom)
    if (
        en_place is not None
        and en_place.artifact_sha256 == empreinte_artefact
        and en_place.dataset_sha256 == empreinte_donnees
    ):
        version = en_place.version
        cree_le = en_place.created_at
    else:
        version = _version(dossier)
        cree_le = datetime.now(timezone.utc).isoformat(timespec="seconds")

    return ModelCard(
        name=nom,
        version=version,
        created_at=cree_le,
        artifact_sha256=empreinte_artefact,
        dataset_sha256=empreinte_donnees,
        dataset_files=tuple(p.name for p in donnees),
        threshold=brut.get("threshold"),
        target_false_positive_rate=brut.get("target_false_positive_rate"),
        metrics=_metriques(brut),
        intended_use=str(edito["intended_use"]),
        known_failures=tuple(edito["known_failures"]),  # type: ignore[arg-type]
        training_command=str(edito["training_command"]),
        decision_role=str(edito["decision_role"]),
        notes=str(edito["notes"]),
    )


def rend_carte(carte: ModelCard) -> str:
    """Carte de modèle en Markdown, entièrement dérivée des artefacts."""
    lignes = [
        f"# Carte de modèle — `{carte.name}`",
        "",
        "> Fichier **généré** par `python -m scripts.model_registry_cli cards`.",
        "> Ne pas l'éditer à la main : la CI vérifie qu'il correspond à son générateur,",
        "> exactement comme pour `data/`. Un chiffre recopié dérive de sa source.",
        "",
        "| | |",
        "|---|---|",
        f"| Version | `{carte.version}` |",
        f"| Rôle dans la décision | **{carte.decision_role}** |",
        f"| Empreinte de l'artefact | `{carte.artifact_sha256[:16]}…` |",
        f"| Empreinte du jeu de données | `{carte.dataset_sha256[:16]}…` |",
        f"| Fichiers de données | {', '.join(f'`{f}`' for f in carte.dataset_files) or '—'} |",
    ]
    if carte.threshold is not None:
        lignes.append(f"| Seuil de décision calibré | `{carte.threshold}` |")
    if carte.target_false_positive_rate is not None:
        lignes.append(
            f"| Taux de faux positifs visé à la calibration | `{carte.target_false_positive_rate}` |"
        )
    lignes += [
        "",
        "## Usage prévu",
        "",
        carte.intended_use,
        "",
        "## Mesures",
        "",
        "Chaque taux est donné avec son intervalle de Wilson à 95 % et l'effectif qui le",
        "soutient. L'intervalle est l'information principale : à ces volumes, c'est lui",
        "qui dit ce que la mesure permet réellement d'affirmer.",
        "",
        "| Métrique | Sens de « mieux » | Mesure |",
        "|---|---|---|",
    ]
    for m in carte.metrics:
        sens = "plus haut" if m.direction == PLUS_HAUT else "plus bas"
        lignes.append(f"| `{m.name}` | {sens} | {m.proportion.format()} |")

    lignes += [
        "",
        "## Modes d'échec connus",
        "",
    ]
    lignes += [f"- {echec}" for echec in carte.known_failures]
    lignes += [
        "",
        "## Reproduire",
        "",
        "```bash",
        carte.training_command,
        "python -m scripts.model_registry_cli check",
        "```",
        "",
        "## Notes de méthode",
        "",
        carte.notes,
        "",
    ]
    return "\n".join(lignes)


def _cartes_disponibles() -> dict[str, ModelCard]:
    cartes = {}
    for nom in MODEL_DIRS:
        carte = construit_carte(nom)
        if carte is not None:
            cartes[nom] = carte
    return cartes


def commande_check(_args) -> int:
    cartes = _cartes_disponibles()
    if not cartes:
        print(
            "Aucun modèle entraîné localement : rien à comparer.\n"
            "Lance les scripts d'entraînement, puis relance cette commande."
        )
        return 0

    echec = False
    for nom, carte in sorted(cartes.items()):
        rapport = evalue(carte, incumbent(nom))
        print(formate(rapport))
        print()
        echec = echec or not rapport.autorisee
    return 1 if echec else 0


def commande_promote(_args) -> int:
    cartes = _cartes_disponibles()
    if not cartes:
        print("Aucun modèle entraîné localement : rien à promouvoir.")
        return 1

    for nom, carte in sorted(cartes.items()):
        rapport = evalue(carte, incumbent(nom))
        print(formate(rapport))
        if not rapport.autorisee:
            print(f"\n« {nom} » n'est pas promu. Le registre n'a pas été modifié.")
            return 1

    for nom, carte in sorted(cartes.items()):
        record(carte)
        print(f"Enregistré : {nom} → {carte.version}")
    _ecrit_cartes(cartes)
    print(f"Cartes écrites dans {CARTES_DIR.relative_to(RACINE)}/")
    return 0


def _ecrit_cartes(cartes: dict[str, ModelCard]) -> None:
    CARTES_DIR.mkdir(parents=True, exist_ok=True)
    for nom, carte in cartes.items():
        (CARTES_DIR / f"{nom}.md").write_text(rend_carte(carte), encoding="utf-8")


def commande_cards(_args) -> int:
    """Régénère les cartes depuis le REGISTRE, pas depuis le disque.

    C'est volontaire et ça compte : les cartes doivent décrire le modèle
    **promu**, pas celui qu'on vient d'entraîner sur son poste. Les régénérer
    depuis `models/` les ferait changer à chaque expérimentation locale, et la
    CI signalerait une dérive à chaque essai.
    """
    registre = load_registry()
    if not registre.models:
        print("Registre vide : rien à générer. Lance d'abord `promote`.")
        return 0
    _ecrit_cartes(registre.models)
    for nom in sorted(registre.models):
        print(f"docs/model_cards/{nom}.md")
    return 0


def commande_verify(_args) -> int:
    """Le modèle présent sur disque est-il celui dont on publie les chiffres ?"""
    problemes = check_integrity(MODEL_DIRS, DATASETS)
    if not problemes:
        registre = load_registry()
        if not registre.models:
            print("Registre vide : rien à vérifier.")
            return 0
        print(f"Registre cohérent avec le disque ({len(registre.models)} modèle(s)).")
        return 0
    for probleme in problemes:
        print(f"[{probleme.kind}] {probleme.model} : {probleme.message}")
    print(
        "\nUn manifeste cohérent ne suffit pas : il prouve qu'un artefact n'a pas été\n"
        "altéré depuis son écriture, pas que c'est l'artefact sur lequel les chiffres\n"
        "publiés ont été obtenus."
    )
    return 1


def _git_propre(chemin: Path) -> bool:
    resultat = subprocess.run(
        ["git", "status", "--porcelain", "--", str(chemin)],
        capture_output=True, text=True, cwd=RACINE, check=False,
    )
    return not resultat.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parseur = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sous = parseur.add_subparsers(dest="commande", required=True)
    sous.add_parser("check", help="porte de promotion, sans rien écrire").set_defaults(fn=commande_check)
    sous.add_parser("promote", help="passe la porte puis enregistre").set_defaults(fn=commande_promote)
    sous.add_parser("cards", help="régénère docs/model_cards/ depuis le registre").set_defaults(fn=commande_cards)
    sous.add_parser("verify", help="le disque correspond-il au registre ?").set_defaults(fn=commande_verify)
    args = parseur.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
