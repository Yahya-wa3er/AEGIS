"""
Mesure l'enveloppe du rapport type/token (TTR) de la prose française réelle.

Produit les constantes `_TTR_ENVELOPE` de `aegis_core/retrieval_integrity.py`.
Sans ce script, ces six couples de nombres seraient des seuils tombés du ciel --
exactement le reproche fait aux anciens seuils des détecteurs ML (lot 5A).

Méthode
-------
Le TTR dépend de la longueur (loi de Heaps) : plus un texte est long, plus les
mots se répètent, plus le TTR baisse. Une bande constante signalerait donc tout
document long comme suspect. On mesure l'enveloppe **par taille de fenêtre**, sur
des extraits tirés au hasard dans le français réel du dépôt (README, docstrings
des modules) -- de la prose technique écrite par un humain, pas générée.

On retient les percentiles 5 et 95, élargis d'une marge : l'objectif est de
signaler ce qui sort franchement de la distribution, pas d'alerter sur ses queues.

    python -m scripts.measure_ttr_envelope

Limite assumée : le corpus de calibration est le français **de ce dépôt**. Un
déploiement dont les documents ont un autre registre (juridique dense, tableaux,
listes de références) doit relancer ce script sur SES documents. C'est écrit ici
plutôt que découvert en production.
"""
from __future__ import annotations

import argparse
import pathlib
import random
import statistics

from aegis_core.retrieval_integrity import tokenize

WINDOW_SIZES = (60, 100, 150, 250, 450, 800)
SAMPLES_PER_SIZE = 200
MARGIN = 0.05
SEED = 42

# Uniquement de la PROSE, jamais du code source.
#
# Deux raisons. La première est de fond : ce détecteur mesure des documents
# récupérés, et du code Python n'a ni la redondance ni la distribution d'un
# document. La seconde est méthodologique -- inclure `aegis_core/*.py` faisait
# entrer dans le corpus de calibration le fichier qui CONTIENT les constantes
# calibrées : deux exécutions séparées par une simple édition de commentaire ne
# donnaient plus les mêmes seuils. Une mesure qui dépend de son propre résultat
# n'est pas une mesure.
SOURCES = ("README.md", "victim/documents/*.txt")


def load_corpus(root: pathlib.Path) -> list[str]:
    tokens: list[str] = []
    for pattern in SOURCES:
        if "*" in pattern:
            paths = sorted(root.glob(pattern))
        else:
            paths = [root / pattern] if (root / pattern).is_file() else []
        for path in paths:
            tokens.extend(tokenize(path.read_text(encoding="utf-8")))
    return tokens


def envelope(tokens: list[str], margin: float = MARGIN) -> list[tuple[int, float, float]]:
    rng = random.Random(SEED)
    rows = []
    for size in WINDOW_SIZES:
        if len(tokens) <= size:
            continue
        values = []
        for _ in range(SAMPLES_PER_SIZE):
            start = rng.randrange(0, len(tokens) - size)
            window = tokens[start:start + size]
            values.append(len(set(window)) / len(window))
        values.sort()
        p05 = values[int(0.05 * len(values))]
        p95 = values[int(0.95 * len(values))]
        rows.append((size, round(max(0.0, p05 - margin), 3), round(min(1.0, p95 + margin), 3)))
        print(f"  n={size:4d}  n_ech={len(values)}  min={values[0]:.3f}  p05={p05:.3f} "
              f" med={statistics.median(values):.3f}  p95={p95:.3f}  max={values[-1]:.3f}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("."))
    args = parser.parse_args()

    tokens = load_corpus(args.root)
    print(f"Corpus de calibration : {len(tokens)} mots de français réel.")
    rows = envelope(tokens)

    print("\nÀ recopier dans aegis_core/retrieval_integrity.py :\n")
    print("_TTR_ENVELOPE: tuple[tuple[int, float, float], ...] = (")
    print("    #  n     bas    haut")
    for size, low, high in rows:
        print(f"    ({size:<4d}, {low:.3f}, {high:.3f}),")
    print(")")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
