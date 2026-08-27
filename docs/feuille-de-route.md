# Feuille de route priorisée

En partant de l'idée que chaque amélioration doit fermer un angle mort **mesuré** (voir [Limites connues](limites.md)), plutôt qu'ajouter une fonctionnalité pour elle-même, voici un ordre de priorité défendable — du plus rentable au plus coûteux.

<div class="grid cards" markdown>

-   :material-numeric-1-box:{ .lg .middle } **Un corpus bénin français large et diversifié**

    ---

    Le levier le plus rentable : le classifieur ML et le détecteur d'outliers RAG ne peuvent pas être recalibrés, ni leur promotion au rang de signal bloquant envisagée, tant que leur taux de faux positifs n'est mesuré que sur dix contrôles. Aucune nouvelle architecture, seulement du travail de constitution de données — c'est pour ça qu'il vient en premier.

-   :material-numeric-2-box:{ .lg .middle } **Externaliser les politiques en YAML**

    ---

    `DEFAULT_POLICIES` est aujourd'hui codé en dur dans `policy_engine.py`. Le sortir vers un fichier de configuration versionné séparément du code permettrait à un opérateur de définir la politique de son propre agent sans toucher au moteur — condition nécessaire pour que le Policy Engine serve à autre chose que la démo.

-   :material-numeric-3-box:{ .lg .middle } **Calibration croisée des scores**

    ---

    Les quatre familles de score (règles, ML, outliers, comportemental) ne sont pas commensurables : un « risque 0,8 » ne veut pas dire la même chose selon le détecteur qui l'a produit, et un `max()` entre eux masque celui qui parle vraiment. Une calibration (Platt scaling ou régression isotonique) sur un jeu de validation commun rendrait les scores agrégables.

-   :material-numeric-4-box:{ .lg .middle } **État partagé pour rate limiting et sessions**

    ---

    Techniquement simple (l'interface existe déjà), mais bloquant dès qu'il y a plus d'une réplique — détaillé dans [Chemin vers un déploiement de production](deploiement.md).

-   :material-numeric-5-box:{ .lg .middle } **Plafonner la part d'un document unique**

    ---

    La vraie défense structurelle contre la manipulation de classement (`MAX_SHARE_PER_DOCUMENT`, jamais implémentée) : elle ne cherche pas à détecter le bourrage, elle rend inutile de gagner le classement en empêchant qu'un seul document occupe tout le contexte.

-   :material-numeric-6-box:{ .lg .middle } **Un modèle NLI léger** *(le plus ambitieux)*

    ---

    Fermerait à la fois la limite de `grounding.py` (accepte deux réponses contradictoires portant les mêmes chiffres) et celle d'`output_guard.py` (la paraphrase du prompt système). Le seul chantier qui change la *nature* du contrôle (lexical → sémantique) plutôt que son périmètre — donc le plus coûteux.

</div>
