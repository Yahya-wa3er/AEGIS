# AEGIS

*Zero-Trust Security Layer pour agents LLM et pipelines RAG — couverture OWASP GenAI LLM Top 10, édition 2026*

!!! warning "Statut"
    Projet de recherche / démonstration. Pas un produit audité pour la production — voir [Limites connues](limites.md) et [Chemin vers un déploiement de production](deploiement.md) avant tout usage réel.

## En une phrase

AEGIS est une couche de sécurité externe, indépendante du modèle, qui s'intercale entre un agent LLM et le monde extérieur : les documents qu'il récupère (RAG), les outils qu'il appelle, ce que ces outils renvoient, et la réponse qu'il produit finalement.

## Pourquoi

Un agent LLM naïf ne distingue pas, au niveau du modèle, une instruction légitime d'une instruction glissée dans un document ou dans le résultat d'un outil. Corriger ça *dans* le modèle n'est pas fiable — c'est un système probabiliste. La seule défense structurelle est une frontière de confiance externe. C'est le problème classique du **confused deputy** appliqué aux agents LLM, détaillé dans [Modèle de menace et architecture](architecture.md).

## Ce qui a été construit

Dix lots de développement ont construit, dans l'ordre, un moteur de politique (allow-list par agent), une détection d'injection à deux couches (règles + ML), un journal d'audit chaîné et signé, une isolation de l'état par session, un classement BM25 avec plafond de bourrage, une détection d'anomalies comportementales (Beta-VAE), un assistant de sécurité ancré, une couche MLOps complète (registre de modèles, porte de promotion, dérive), et un filtre de sortie qui protège ce que le client reçoit (secrets, prompt système, balisage actif).

Les dix catégories de l'OWASP GenAI LLM Top 10 2026 ont désormais toutes une couverture réelle et mesurée — voir [Couverture OWASP](owasp.md). Aucune n'est complète, et le projet le documente lui-même plutôt que de le cacher : voir [Limites connues](limites.md).

## Démarrage rapide

```bash
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt              # noyau + API + démo web
pip install -r requirements-ml.txt           # + entraînement et classifieur ML (torch, transformers…)

cp .env.example .env   # puis renseigne ta clé OpenRouter dans .env
```

Les dépendances ML sont séparées à dessein : elles pèsent plusieurs centaines de Mo, et un déploiement qui n'utilise que le Policy Engine, le journal d'audit et les règles regex n'a aucune raison de les embarquer.

Pour utiliser AEGIS comme bibliothèque dans un projet existant :

```bash
pip install -e .              # noyau seul : règles, Policy Engine, journal signé
pip install -e ".[ml]"        # + classifieur d'injection et détecteur comportemental
pip install -e ".[demo]"      # + agent de démonstration et tableau de bord
pip install -e ".[dev]"       # tout, plus les outils de test
```

Le noyau ne dépend que de `cryptography`, `jsonschema` et `numpy` — quelques mégaoctets. Voir [Brancher AEGIS sur un agent existant](integration.md) pour l'intégrer sans réécrire un agent déjà construit.

## Où aller ensuite

Pour comprendre le mécanisme de chaque composant : [Les composants, un par un](composants.md). Pour la méthodologie derrière les chiffres publiés : [Méthodologie de mesure](mesure.md). Pour l'état des modèles et leur cycle de vie : [MLOps](mlops.md). Pour ce qui manque avant un vrai déploiement : [Chemin vers un déploiement de production](deploiement.md).
