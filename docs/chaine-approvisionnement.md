# Sécurité de la chaîne d'approvisionnement

Un choix transversal mérite d'être vu comme un principe unique plutôt que trois corrections séparées : le projet a délibérément abandonné `torch.load()` et `joblib.load()` sans garde-fou, au profit de formats de stockage « données pures » (JSON + `.npz` avec `allow_pickle=False`, `torch.load(..., weights_only=True)` explicite).

!!! danger "La raison"
    Désérialiser un pickle **exécute le contenu du fichier**. Quiconque peut écrire dans `models/` — un chemin de déploiement, un volume partagé mal configuré, une dépendance compromise — obtenait sinon l'exécution de code arbitraire dans le processus AEGIS lui-même, c'est-à-dire dans la couche censée protéger contre les attaques.

Ce principe traverse trois modules décrits en détail dans [Les composants, un par un](composants.md) :

<div class="grid cards" markdown>

-   :material-brain: **Beta-VAE comportemental**

    ---

    Poids chargés via `torch.load(..., weights_only=True)`.

-   :material-vector-triangle: **Détecteur d'outliers RAG**

    ---

    Vectoriseur TF-IDF stocké en JSON + `.npz`, réimplémenté à la main plutôt que désérialisé via `joblib.load()`.

-   :material-database-check-outline: **Registre de modèles**

    ---

    Chaque artefact vérifié par empreinte SHA-256 plutôt que fait confiance sur la seule présence d'un fichier.

</div>

C'est un exemple concret de LLM04 (Supply Chain) appliqué à l'infrastructure ML elle-même, pas seulement aux dépendances Python classiques.

## Ce qui existe déjà

- Manifeste SHA-256 par artefact de modèle (`MANIFEST.json`), vérifié à chaque chargement.
- Dépendances figées et générées (`requirements*.txt` via `pip-compile`), jamais éditées à la main.
- CI qui installe le noyau seul dans un environnement vierge, pour vérifier que la séparation des dépendances optionnelles (ML, démo) est réellement respectée.

!!! bug "Cette séparation était annoncée mais fausse jusqu'au lot 4B"
    `injection_detector.py` importait `torch` au niveau du module et cassait l'import du noyau sans lui — corrigé, et désormais vérifié à chaque push.

## Ce qui n'existe pas encore

Un SBOM, et une signature du bundle de modèles distribué — voir la liste complète dans [Limites connues](limites.md) et les chantiers correspondants dans la [Feuille de route](feuille-de-route.md).
