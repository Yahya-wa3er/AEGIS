# Feuille de route priorisée

En partant de l'idée que chaque amélioration doit fermer un angle mort **mesuré** (voir [Limites connues](limites.md)), plutôt qu'ajouter une fonctionnalité pour elle-même, voici un ordre de priorité défendable.

## Priorité 1 — un corpus bénin français large et diversifié

C'est le levier le plus rentable : le classifieur ML et le détecteur d'outliers RAG ne peuvent pas être recalibrés, ni leur promotion au rang de signal bloquant envisagée, tant que leur taux de faux positifs n'est mesuré que sur dix contrôles. Ce chantier ne demande aucune nouvelle architecture, seulement du travail de constitution de données — c'est pour ça qu'il vient en premier.

## Priorité 2 — externaliser les politiques (`DEFAULT_POLICIES`) en YAML

Aujourd'hui codées en dur dans `policy_engine.py`. Les sortir vers un fichier de configuration versionné séparément du code permettrait à un opérateur de définir la politique de son propre agent sans toucher au moteur — condition nécessaire pour que le Policy Engine serve à autre chose que la démo.

## Priorité 3 — calibration croisée des scores

Les quatre familles de score (règles, ML, outliers, comportemental) ne sont pas commensurables : un « risque 0,8 » ne veut pas dire la même chose selon le détecteur qui l'a produit, et un `max()` entre eux masque celui qui parle vraiment. Une calibration (Platt scaling ou régression isotonique) sur un jeu de validation commun, avec un diagramme de fiabilité pour vérifier que les scores calibrés correspondent à de vraies fréquences, rendrait les scores agrégables plutôt que juste comparables à l'œil.

## Priorité 4 — état partagé pour le rate limiting et les sessions

Techniquement simple (l'interface existe déjà), mais bloquant dès qu'il y a plus d'une réplique — détaillé dans [Chemin vers un déploiement de production](deploiement.md).

## Priorité 5 — plafonner la part d'un document unique dans le contexte récupéré

C'est la vraie défense structurelle contre la manipulation de classement (`MAX_SHARE_PER_DOCUMENT`, jamais implémentée) : elle ne cherche pas à détecter le bourrage, elle rend inutile de gagner le classement en empêchant qu'un seul document occupe tout le contexte.

## Priorité 6 (plus ambitieuse) — un modèle d'inférence sémantique (NLI) léger

Pour l'ancrage et la détection de fuite de contexte. Fermerait à la fois la limite de `grounding.py` (accepte deux réponses contradictoires portant les mêmes chiffres) et celle d'`output_guard.py` (la paraphrase du prompt système). C'est le seul chantier de cette liste qui change la *nature* du contrôle (lexical → sémantique) plutôt que son périmètre — donc le plus coûteux, et le seul qui justifierait probablement l'ajout d'un modèle supplémentaire au pipeline.
