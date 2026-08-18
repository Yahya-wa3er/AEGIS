"""
Contrôle des contrastes de la console (WCAG 2.1 AA).

Pourquoi un script et pas un commentaire
----------------------------------------
La première version de `frontend/src/app/globals.css` annonçait des ratios que
personne n'avait calculés. Quatre échouaient, dont le texte blanc de la pilule
de navigation active à **2,3:1** — l'élément le plus cliqué de l'interface.

C'est exactement la faute que ce projet passe son temps à corriger ailleurs :
publier un chiffre sans l'avoir mesuré. Un jeu de couleurs se vérifie, comme un
taux de détection.

Le script lit les variables directement dans la feuille de style — pas une copie
recopiée à la main qui dériverait au premier ajustement — et échoue si une paire
descend sous son seuil.

    python -m scripts.check_contrast

Seuils WCAG 2.1 AA : 4,5:1 pour du texte courant, 3:1 pour un élément graphique
porteur de sens (icône dans un chip plein, par exemple).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

CSS = Path("frontend/src/app/globals.css")

# (description, variable de premier plan, variable de fond, seuil)
# Chaque paire correspond à une combinaison qui existe réellement à l'écran ;
# vérifier des paires qu'on n'utilise pas donnerait une fausse assurance.
PAIRES: tuple[tuple[str, str, str, float], ...] = (
    ("texte courant", "text", "bg", 4.5),
    ("texte courant sur la zone de travail", "text", "canvas", 4.5),
    ("texte secondaire", "muted", "bg", 4.5),
    ("libellés discrets", "faint", "bg", 4.5),
    ("libellés discrets sur la zone de travail", "faint", "canvas", 4.5),
    ("texte blanc sur la navigation active", "WHITE", "accent-ink", 4.5),
    ("icône blanche dans un chip", "WHITE", "accent", 3.0),
    ("texte d'accent sur surface d'accent", "accent-strong", "accent-soft", 4.5),
    ("texte d'accent sur blanc", "accent-strong", "bg", 4.5),
    ("verdict sûr sur sa surface", "ok", "ok-soft", 4.5),
    ("verdict consultatif sur sa surface", "warn", "warn-soft", 4.5),
    ("verdict bloqué sur sa surface", "danger", "danger-soft", 4.5),
)

WHITE = "#ffffff"


def _luminance(hex_color: str) -> float:
    value = hex_color.lstrip("#")
    channels = (int(value[i:i + 2], 16) for i in (0, 2, 4))
    linear = []
    for c in channels:
        srgb = c / 255
        linear.append(srgb / 12.92 if srgb <= 0.03928 else ((srgb + 0.055) / 1.055) ** 2.4)
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(a: str, b: str) -> float:
    la, lb = _luminance(a), _luminance(b)
    high, low = max(la, lb), min(la, lb)
    return (high + 0.05) / (low + 0.05)


def read_tokens(css_path: Path) -> dict[str, str]:
    """Extrait les variables `--nom: #rrggbb;` de la feuille de style."""
    text = css_path.read_text(encoding="utf-8")
    return {
        name: color
        for name, color in re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;", text)
    }


def main() -> int:
    if not CSS.is_file():
        print(f"Feuille de style introuvable : {CSS}")
        return 2

    tokens = read_tokens(CSS)
    tokens["WHITE"] = WHITE

    print(f"Contrastes de {CSS} (WCAG 2.1 AA)")
    print("-" * 78)

    echecs = []
    for description, avant, arriere, seuil in PAIRES:
        if avant not in tokens or arriere not in tokens:
            echecs.append(f"variable manquante : {avant if avant not in tokens else arriere}")
            print(f"  MANQUE  {description}")
            continue
        ratio = contrast(tokens[avant], tokens[arriere])
        ok = ratio >= seuil
        if not ok:
            echecs.append(f"{description} : {ratio:.2f}:1 < {seuil}")
        marque = "OK    " if ok else "ÉCHEC "
        print(f"  {marque}{description:44s} {ratio:5.2f}:1  (seuil {seuil})")

    print("-" * 78)
    if echecs:
        for raison in echecs:
            print(f"ÉCHEC : {raison}")
        print(
            "\nUne couleur illisible n'est pas un détail d'esthétique : sur une console\n"
            "de sécurité, c'est une information que l'opérateur ne recevra pas."
        )
        return 1
    print(f"SUCCÈS : {len(PAIRES)} paires conformes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
