"""
Registre de modèles : quel modèle a été mesuré, avec quelles données, et quand.

Le trou que ça bouche
---------------------
Jusqu'ici, chaque détecteur écrivait ses mesures dans `models/<nom>/metrics.json`
— à côté de ses poids, dans un répertoire que `.gitignore` exclut. Deux
conséquences que personne n'avait tirées :

1. **Les chiffres publiés dans le README ne sont rattachés à rien.** « 86 %
   [60-96 %] de rappel » décrit *un* modèle, entraîné *un* jour, sur *un* jeu de
   données. Rien dans le dépôt ne dit lequel. Sur un clone frais, on réentraîne
   et on obtient d'autres chiffres, sans aucun moyen de constater l'écart.
2. **Rien ne relie un modèle sur disque à ses mesures.** Un `metrics.json` peut
   parfaitement décrire un modèle qui n'existe plus. Le `MANIFEST.json` de
   `model_io` vérifie qu'un artefact n'a pas été *altéré* ; il ne dit pas que
   c'est bien l'artefact sur lequel les chiffres ont été obtenus.

Le registre est donc **versionné dans git** (`model_registry.json`, à la racine),
contrairement aux poids. Il contient, par modèle promu : l'empreinte de
l'artefact, l'empreinte du jeu d'entraînement, le seuil calibré et les mesures
avec leurs intervalles. C'est le seul fichier qui permette de dire « les chiffres
du README décrivent CE modèle-là », et de le vérifier.

Ce que ça ne fait pas
---------------------
Ce n'est pas un stockage d'artefacts : les poids ne sont toujours pas versionnés
(volume), et le registre ne permet donc pas de *récupérer* un modèle passé, juste
de constater que celui qu'on a n'est pas celui qu'on croit. C'est un registre de
provenance, pas un dépôt binaire — et un dépôt binaire (MLflow, DVC, un bucket)
est ce qu'il faudrait pour un vrai cycle de vie. La limite est écrite plutôt que
sous-entendue.

Il n'est pas non plus signé. Comme le manifeste de `model_io`, il protège contre
la dérive accidentelle et contre un attaquant qui modifie un fichier sans pouvoir
réécrire le reste — pas contre quelqu'un qui a les droits d'écriture sur le
dépôt. La parade est la même que pour le journal d'audit : une signature dont
l'attaquant n'a pas la clé.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from aegis_core.model_io import sha256_file
from aegis_core.stats import Proportion

RACINE = Path(__file__).resolve().parent.parent
REGISTRY_PATH = RACINE / "model_registry.json"
REGISTRY_VERSION = 1


def sha256_files(paths: list[Path]) -> str:
    """Empreinte d'un ensemble de fichiers, stable quel que soit l'ordre d'appel.

    On hache les empreintes individuelles plutôt que la concaténation des
    contenus : ça évite de tout relire en mémoire, et surtout ça reste
    indépendant de l'ordre dans lequel l'appelant passe les chemins — deux
    scripts qui listent les mêmes fichiers autrement doivent obtenir la même
    valeur, sinon l'empreinte détecte une dérive qui n'existe pas.
    """
    import hashlib

    parts = sorted(f"{p.name}:{sha256_file(p)}" for p in paths if p.is_file())
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MetricEntry:
    """Une mesure publiée, avec ce qui permet de la juger.

    `direction` dit dans quel sens « mieux » va. Sans elle, une porte de
    promotion ne peut pas distinguer une amélioration d'une régression : 86 %
    de rappel qui passe à 92 % est une bonne nouvelle, 2 % de faux positifs qui
    passent à 8 % n'en est pas une, et les deux sont « une hausse ».
    """

    name: str
    successes: int
    total: int
    low: float
    high: float
    direction: str  # "plus_haut_est_mieux" | "plus_bas_est_mieux"

    @property
    def proportion(self) -> Proportion:
        return Proportion(
            successes=self.successes, total=self.total, low=self.low, high=self.high
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "successes": self.successes,
            "total": self.total,
            "low": self.low,
            "high": self.high,
            "direction": self.direction,
        }

    @classmethod
    def from_dict(cls, brut: dict) -> "MetricEntry":
        return cls(
            name=str(brut["name"]),
            successes=int(brut["successes"]),
            total=int(brut["total"]),
            low=float(brut["low"]),
            high=float(brut["high"]),
            direction=str(brut["direction"]),
        )


@dataclass(frozen=True)
class ModelCard:
    """Ce qu'on doit savoir d'un modèle avant de s'en servir.

    Le format suit l'esprit des *model cards* (Mitchell et al., 2019) : usage
    prévu, données, mesures, limites. La différence ici est qu'aucun champ n'est
    saisi à la main deux fois — tout est dérivé des artefacts de l'entraînement,
    pour la raison habituelle dans ce dépôt : ce qu'on recopie dérive.
    """

    name: str
    version: str
    created_at: str
    artifact_sha256: str
    dataset_sha256: str
    dataset_files: tuple[str, ...]
    threshold: float | None
    target_false_positive_rate: float | None
    metrics: tuple[MetricEntry, ...]
    intended_use: str
    known_failures: tuple[str, ...]
    training_command: str
    decision_role: str  # "bloquant" | "consultatif"
    notes: str = ""

    def metric(self, name: str) -> MetricEntry | None:
        return next((m for m in self.metrics if m.name == name), None)

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at,
            "artifact_sha256": self.artifact_sha256,
            "dataset_sha256": self.dataset_sha256,
            "dataset_files": list(self.dataset_files),
            "threshold": self.threshold,
            "target_false_positive_rate": self.target_false_positive_rate,
            "metrics": [m.as_dict() for m in self.metrics],
            "intended_use": self.intended_use,
            "known_failures": list(self.known_failures),
            "training_command": self.training_command,
            "decision_role": self.decision_role,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, brut: dict) -> "ModelCard":
        return cls(
            name=str(brut["name"]),
            version=str(brut["version"]),
            created_at=str(brut["created_at"]),
            artifact_sha256=str(brut["artifact_sha256"]),
            dataset_sha256=str(brut["dataset_sha256"]),
            dataset_files=tuple(brut.get("dataset_files", ())),
            threshold=brut.get("threshold"),
            target_false_positive_rate=brut.get("target_false_positive_rate"),
            metrics=tuple(MetricEntry.from_dict(m) for m in brut.get("metrics", ())),
            intended_use=str(brut.get("intended_use", "")),
            known_failures=tuple(brut.get("known_failures", ())),
            training_command=str(brut.get("training_command", "")),
            decision_role=str(brut.get("decision_role", "consultatif")),
            notes=str(brut.get("notes", "")),
        )


@dataclass
class Registry:
    """Contenu de `model_registry.json`."""

    models: dict[str, ModelCard] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "registry_version": REGISTRY_VERSION,
            # Tri par nom : un fichier versionné dont l'ordre bouge à chaque
            # écriture produit des diffs illisibles, et un diff illisible est un
            # diff que personne ne relit.
            "models": {nom: self.models[nom].as_dict() for nom in sorted(self.models)},
        }

    def dump(self, path: Path = REGISTRY_PATH) -> None:
        path.write_text(
            json.dumps(self.as_dict(), indent=2, ensure_ascii=False, sort_keys=False) + "\n",
            encoding="utf-8",
        )


def load_registry(path: Path = REGISTRY_PATH) -> Registry:
    """Lit le registre. Un fichier absent est un registre vide, pas une erreur :
    c'est l'état d'un dépôt qui n'a encore rien promu."""
    if not path.is_file():
        return Registry()
    brut = json.loads(path.read_text(encoding="utf-8"))
    return Registry(
        models={
            nom: ModelCard.from_dict(carte)
            for nom, carte in brut.get("models", {}).items()
        }
    )


def incumbent(name: str, path: Path = REGISTRY_PATH) -> ModelCard | None:
    """Modèle actuellement enregistré sous ce nom, ou None."""
    return load_registry(path).models.get(name)


def record(card: ModelCard, path: Path = REGISTRY_PATH) -> None:
    """Enregistre (ou remplace) l'entrée d'un modèle."""
    registre = load_registry(path)
    registre.models[card.name] = card
    registre.dump(path)


@dataclass(frozen=True)
class IntegrityIssue:
    model: str
    kind: str  # "artefact" | "donnees" | "absent"
    message: str


def check_integrity(
    model_dirs: dict[str, Path],
    dataset_files: dict[str, list[Path]],
    path: Path = REGISTRY_PATH,
) -> list[IntegrityIssue]:
    """Le modèle sur disque est-il celui dont on publie les chiffres ?

    C'est la question que ni `metrics.json` ni `MANIFEST.json` ne posaient. Le
    manifeste vérifie qu'un artefact n'a pas été altéré *depuis son écriture* ;
    il ne dit rien du fait que ce soit bien l'artefact mesuré. Réentraîner sans
    republier produit exactement ce cas : manifeste cohérent, chiffres périmés.

    Un modèle absent du disque n'est pas signalé : sur un clone frais, `models/`
    est vide et c'est normal (les poids ne sont pas versionnés). Ce qui est
    signalé, c'est un modèle PRÉSENT qui ne correspond pas à son entrée.
    """
    registre = load_registry(path)
    problemes: list[IntegrityIssue] = []

    for nom, carte in registre.models.items():
        dossier = model_dirs.get(nom)
        if dossier is None or not dossier.is_dir():
            continue  # non entraîné localement : rien à comparer

        fichiers = sorted(p for p in dossier.iterdir() if p.is_file() and p.name != "MANIFEST.json")
        empreinte = sha256_files(fichiers)
        if empreinte != carte.artifact_sha256:
            problemes.append(
                IntegrityIssue(
                    model=nom,
                    kind="artefact",
                    message=(
                        f"le modèle présent dans {dossier} n'est pas celui enregistré "
                        f"(attendu {carte.artifact_sha256[:12]}…, trouvé {empreinte[:12]}…). "
                        "Les mesures publiées décrivent un autre modèle : réentraîne puis "
                        "republie, ou restaure l'artefact mesuré."
                    ),
                )
            )

        donnees = dataset_files.get(nom)
        if donnees and all(p.is_file() for p in donnees):
            empreinte_donnees = sha256_files(donnees)
            if empreinte_donnees != carte.dataset_sha256:
                problemes.append(
                    IntegrityIssue(
                        model=nom,
                        kind="donnees",
                        message=(
                            f"le jeu d'entraînement de « {nom} » a changé depuis "
                            f"l'enregistrement (attendu {carte.dataset_sha256[:12]}…, "
                            f"trouvé {empreinte_donnees[:12]}…). Un seuil calibré sur "
                            "d'autres données ne garantit plus le taux annoncé."
                        ),
                    )
                )

    return problemes
