"""
Découpage des jeux de données et détection de fuite (correctif P1-M2).

Ce qu'on mesurait vraiment
--------------------------
Trois défauts cumulés rendaient les chiffres publiés ininterprétables. Aucun
n'était visible en lisant le README ; tous se voient en lisant le code.

**Le seuil était calibré sur le jeu de test.** `train_rag_outlier_detector.py`
calculait `seuil = moyenne(normaux du jeu d'éval) + 2σ`, puis annonçait le taux
de faux positifs *sur ces mêmes normaux*. Un seuil à deux écarts-types d'un
échantillon laisse par construction ~2 % de cet échantillon au-dessus : sur 30
documents, ça fait 0 ou 1. Le « 0 % de faux positifs » n'était pas une mesure,
c'était une conséquence arithmétique du choix de seuil. Le VAE comportemental
faisait pire encore -- `seuil = max(erreurs normales du jeu d'éval)` garantit
exactement 0 faux positif, toujours.

**Le coefficient aussi.** Le commentaire du code disait la chose sans la
nommer : « k=2 (pas 3) choisi après comparaison sur le jeu d'évaluation : passe
de 33 % à 89 % de rappel ». C'est un hyperparamètre optimisé sur le jeu de test.

**Les jeux se recouvraient.** Les documents « normaux » d'entraînement et
d'évaluation sortaient des mêmes douze gabarits, remplis avec des nombres
aléatoires : 4 lignes d'évaluation sur 39 étaient *identiques au caractère près*
à une ligne d'entraînement, et 12 des 13 gabarits d'évaluation étaient présents à
l'entraînement. Mesurer là-dessus revient à demander au modèle s'il reconnaît des
phrases qu'il a déjà lues -- ce qui n'est pas la question.

La discipline
-------------
Trois jeux, jamais deux :

* **train** -- ajuste le modèle. Rien d'autre.
* **calibration** -- choisit les seuils et les hyperparamètres. Jamais mesuré.
* **test** -- mesuré une fois, ne décide de rien.

Le découpage est fait **par gabarit**, pas par ligne : deux phrases issues du même
patron ne sont pas deux observations indépendantes, et les répartir au hasard
remet la même formulation des deux côtés de la cloison. Ce que ça mesure change
de nature -- « le détecteur reconnaît-il une phrase déjà vue » devient « le
détecteur généralise-t-il à une formulation qu'il n'a jamais vue ». La seconde
est la seule qui prédise quoi que ce soit en production.

`assert_no_leakage` refuse de laisser passer un recouvrement exact. Le
recouvrement *approché* (même gabarit, nombres différents) est mesuré et
rapporté plutôt que bloqué : à zéro il ne coûte rien, au-dessus de zéro il borne
ce que la mesure signifie, et il vaut mieux le lire dans le rapport que le
découvrir en production.
"""
from __future__ import annotations

import hashlib
import random
import re
import unicodedata
from dataclasses import dataclass, field

DEFAULT_RATIOS = (0.6, 0.2, 0.2)  # train / calibration / test
SPLIT_NAMES = ("train", "calibration", "test")


class DatasetLeakageError(RuntimeError):
    """Levée quand un jeu de test partage des exemples avec un autre jeu.

    Volontairement fatale : une mesure produite sur un jeu contaminé est pire
    qu'une absence de mesure, parce qu'elle inspire confiance.
    """


def canonical_form(text: str) -> str:
    """Forme canonique servant à repérer les quasi-doublons.

    Deux phrases qui ne diffèrent que par un numéro de ticket, un montant ou une
    casse sont la même observation. On neutralise donc ce qui varie sans porter
    d'information : chiffres, accents, ponctuation, espaces.
    """
    lowered = unicodedata.normalize("NFKD", text.casefold())
    stripped = "".join(c for c in lowered if not unicodedata.combining(c))
    digits_folded = re.sub(r"\d+([.,]\d+)?", "#", stripped)
    words = re.findall(r"[^\W_]+", digits_folded)
    return " ".join(words)


def fingerprint(text: str) -> str:
    return hashlib.sha256(canonical_form(text).encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Overlap:
    left: str
    right: str
    exact: int
    near: int
    examples: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class LeakageReport:
    """Ce que les jeux partagent, exactement, avec de quoi le corriger."""

    overlaps: tuple[Overlap, ...]
    sizes: dict[str, int]

    @property
    def exact_total(self) -> int:
        return sum(o.exact for o in self.overlaps)

    @property
    def near_total(self) -> int:
        return sum(o.near for o in self.overlaps)

    @property
    def ok(self) -> bool:
        return self.exact_total == 0

    def as_dict(self) -> dict[str, object]:
        return {
            "sizes": dict(self.sizes),
            "exact_overlaps": self.exact_total,
            "near_duplicate_overlaps": self.near_total,
            "clean": self.ok,
            "pairs": [
                {"between": f"{o.left}/{o.right}", "exact": o.exact, "near": o.near}
                for o in self.overlaps
                if o.exact or o.near
            ],
        }

    def describe(self) -> str:
        lines = [
            "Contrôle de fuite entre jeux :",
            "  tailles : " + ", ".join(f"{name}={n}" for name, n in self.sizes.items()),
        ]
        for o in self.overlaps:
            verdict = "OK" if not (o.exact or o.near) else ("FUITE" if o.exact else "quasi-doublons")
            lines.append(f"  [{verdict}] {o.left} ∩ {o.right} : {o.exact} exact(s), {o.near} quasi-doublon(s)")
            for example in o.examples:
                lines.append(f"        ex. « {example[:70]}… »")
        return "\n".join(lines)


def leakage_report(splits: dict[str, list[str]]) -> LeakageReport:
    """Compare chaque paire de jeux, à l'identique et à la forme canonique près."""
    exact_sets = {name: {t for t in texts} for name, texts in splits.items()}
    canon_sets = {name: {canonical_form(t) for t in texts} for name, texts in splits.items()}

    names = list(splits)
    overlaps: list[Overlap] = []
    for i, left in enumerate(names):
        for right in names[i + 1:]:
            shared_exact = exact_sets[left] & exact_sets[right]
            shared_canon = canon_sets[left] & canon_sets[right]
            # Un doublon exact est aussi un quasi-doublon : on ne le compte
            # qu'une fois, dans la catégorie la plus grave.
            near_only = len(shared_canon) - len({canonical_form(t) for t in shared_exact})
            overlaps.append(Overlap(
                left=left, right=right,
                exact=len(shared_exact),
                near=max(0, near_only),
                examples=tuple(sorted(shared_exact))[:3],
            ))
    return LeakageReport(
        overlaps=tuple(overlaps),
        sizes={name: len(texts) for name, texts in splits.items()},
    )


def assert_no_leakage(splits: dict[str, list[str]], *, verbose: bool = True) -> LeakageReport:
    """Contrôle bloquant, à appeler avant tout entraînement.

    Raises:
        DatasetLeakageError: dès qu'un exemple apparaît à l'identique dans deux
            jeux. Les quasi-doublons sont rapportés, pas bloqués -- voir la
            docstring du module.
    """
    report = leakage_report(splits)
    if verbose:
        print(report.describe())
    if not report.ok:
        raise DatasetLeakageError(
            f"{report.exact_total} exemple(s) partagé(s) entre jeux. Toute mesure "
            "produite dans cet état surestime le modèle : elle vérifie qu'il "
            "reconnaît des exemples déjà vus.\n" + report.describe()
        )
    return report


def split_by_group(
    items: list[tuple[str, object]],
    ratios: tuple[float, float, float] = DEFAULT_RATIOS,
    seed: int = 42,
) -> dict[str, list[object]]:
    """Répartit des éléments en train/calibration/test **par groupe**.

    `items` est une liste de `(groupe, valeur)`. Tous les éléments d'un même
    groupe -- typiquement un gabarit de phrase, une source, un auteur --
    atterrissent dans le même jeu. C'est ce qui rend le jeu de test réellement
    tenu à l'écart : sans ça, la même formulation se retrouve des deux côtés et
    la mesure évalue de la mémorisation.

    Le tirage est déterministe (`seed`) pour que deux exécutions produisent le
    même découpage -- une mesure non reproductible n'est pas une mesure.
    """
    if len(ratios) != 3 or abs(sum(ratios) - 1.0) > 1e-9:
        raise ValueError("ratios doit contenir trois valeurs de somme 1.")

    groups: dict[str, list[object]] = {}
    for group, value in items:
        groups.setdefault(group, []).append(value)

    names = sorted(groups)
    if len(names) < 3:
        raise ValueError(
            f"{len(names)} groupe(s) seulement : impossible de constituer trois jeux "
            "disjoints. Diversifie le corpus avant de le mesurer."
        )
    random.Random(seed).shuffle(names)

    n = len(names)
    n_train = max(1, round(n * ratios[0]))
    n_calib = max(1, round(n * ratios[1]))
    # Le test garde le reste, et au moins un groupe : c'est le jeu dont la taille
    # ne doit jamais être sacrifiée aux arrondis.
    if n_train + n_calib >= n:
        n_train = max(1, n - 2)
        n_calib = 1

    bounds = {
        "train": names[:n_train],
        "calibration": names[n_train:n_train + n_calib],
        "test": names[n_train + n_calib:],
    }
    return {split: [v for g in group_names for v in groups[g]] for split, group_names in bounds.items()}
