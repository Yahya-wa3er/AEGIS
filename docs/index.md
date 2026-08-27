---
title: AEGIS
---

<div class="aegis-hero" markdown>

# :material-shield-lock-outline: AEGIS

Une couche de sécurité **zero-trust**, indépendante du modèle, pour les agents LLM et les pipelines RAG — couverture mesurée des 10 catégories de l'**OWASP GenAI LLM Top 10** (édition 2026).

[:material-rocket-launch-outline: Démarrage rapide](#demarrage-rapide){ .md-button .md-button--primary }
[:material-source-repository: Voir le code](https://github.com/Yahya-wa3er/AEGIS){ .md-button }

</div>

!!! warning "Statut du projet"
    Projet de recherche / démonstration, pas un produit audité pour la production tel quel. Chaque chiffre publié dans cette documentation est mesuré et reproductible, et chaque limite connue est documentée **et testée**, pas seulement mentionnée. Voir [Limites connues](limites.md) et [Chemin vers un déploiement de production](deploiement.md) avant tout usage réel.

## En une phrase

AEGIS s'intercale entre un agent LLM et le monde extérieur : les documents qu'il récupère, les outils qu'il appelle, ce que ces outils renvoient, et la réponse qu'il produit finalement. Cinq points d'interception, une frontière de confiance à chaque fois.

<div class="aegis-stats" markdown>

<div class="aegis-stat"><strong>10/10</strong><span>catégories OWASP couvertes</span></div>
<div class="aegis-stat"><strong>410</strong><span>tests automatisés</span></div>
<div class="aegis-stat"><strong>10 lots</strong><span>de développement mesurés</span></div>
<div class="aegis-stat"><strong>0</strong><span>désérialisation pickle</span></div>

</div>

*Détail de ces chiffres dans [Statistiques du projet](statistiques.md) — chacun avec son intervalle de confiance, pas juste le total.*

## Pourquoi une couche externe

Un agent LLM naïf ne distingue pas, au niveau du modèle, une instruction légitime d'une instruction glissée dans un document ou dans le résultat d'un outil : tout ce qui entre dans son contexte est du même texte. Corriger ça *dans* le modèle n'est pas fiable — c'est un système probabiliste. La seule défense structurelle est une frontière de confiance externe.

??? note "Le problème classique du confused deputy, appliqué aux agents LLM"
    Un acteur qui détient des privilèges légitimes (appeler des outils, envoyer des emails, faire des virements) se retrouve à les exercer sous l'influence d'un tiers non autorisé, parce qu'il ne peut pas distinguer la source de l'instruction qu'il exécute. Développé dans [Modèle de menace et architecture](architecture.md).

## Explorer la documentation

<div class="grid cards" markdown>

-   :material-lightbulb-on-outline:{ .lg .middle } **Comprendre AEGIS**

    ---

    Le modèle de menace, les cinq points d'interception, et le mécanisme exact de chaque composant.

    [:octicons-arrow-right-24: Architecture](architecture.md) · [Composants](composants.md) · [Couverture OWASP](owasp.md)

-   :material-chart-line:{ .lg .middle } **Preuves et rigueur**

    ---

    Comment les chiffres publiés sont mesurés, le cycle de vie des modèles, et ce qui reste ouvert — sans détour.

    [:octicons-arrow-right-24: Méthodologie](mesure.md) · [MLOps](mlops.md) · [Limites connues](limites.md)

-   :material-rocket-launch-outline:{ .lg .middle } **Passer à l'action**

    ---

    Ce qu'il manque pour un vrai déploiement, l'ordre des chantiers, et comment brancher AEGIS sur un agent déjà construit.

    [:octicons-arrow-right-24: Déploiement](deploiement.md) · [Feuille de route](feuille-de-route.md) · [Intégration](integration.md)

-   :material-brain:{ .lg .middle } **Cartes de modèles**

    ---

    Les modèles ML entraînés, leurs mesures et leur seuil calibré, générés automatiquement depuis le registre.

    [:octicons-arrow-right-24: Vue d'ensemble](model_cards/index.md)

</div>

## Démarrage rapide

=== "Environnement complet"

    ```bash
    python3 -m venv venv
    source venv/bin/activate

    pip install -r requirements.txt              # noyau + API + démo web
    pip install -r requirements-ml.txt           # + entraînement et classifieur ML (torch, transformers…)

    cp .env.example .env   # puis renseigne ta clé OpenRouter dans .env
    ```

    Les dépendances ML sont séparées à dessein : elles pèsent plusieurs centaines de Mo, et un déploiement qui n'utilise que le Policy Engine, le journal d'audit et les règles regex n'a aucune raison de les embarquer.

=== "Comme bibliothèque"

    ```bash
    pip install -e .              # noyau seul : règles, Policy Engine, journal signé
    pip install -e ".[ml]"        # + classifieur d'injection et détecteur comportemental
    pip install -e ".[demo]"      # + agent de démonstration et tableau de bord
    pip install -e ".[dev]"       # tout, plus les outils de test
    ```

    Le noyau ne dépend que de `cryptography`, `jsonschema` et `numpy` — quelques mégaoctets. Voir [Brancher AEGIS sur un agent existant](integration.md) pour l'intégrer sans réécrire un agent déjà construit.
