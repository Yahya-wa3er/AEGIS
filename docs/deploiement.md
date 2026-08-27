# Chemin vers un déploiement de production

Le fossé entre « ça marche en démo locale » et « ça tient en production » n'est caché nulle part dans ce projet — c'est même son argument central appliqué à lui-même. Voici, dans l'ordre où ils deviennent bloquants à mesure que le trafic et le nombre de répliques augmentent, les chantiers réels.

## État partagé

Le rate limiting et les fenêtres de session vivent en mémoire de processus. Derrière plusieurs répliques, chaque instance compte pour elle seule : le plafond réel se multiplie par le nombre de répliques, et un redémarrage remet tout à zéro. La correction standard est un magasin partagé à faible latence (Redis, ou une extension Postgres) derrière l'interface déjà existante (`RateLimiter`, `SessionStore`) — l'interface ne change pas, seule l'implémentation du stockage change.

## Durabilité et gestion de la clé du journal d'audit

`audit_db_path=":memory:"` est le défaut assumé pour la démo. Un déploiement réel a besoin d'un SQLite (ou équivalent transactionnel) sur disque persistant, sauvegardé, répliqué. La clé privée Ed25519 mérite un HSM ou un service de signature séparé (KMS cloud, par exemple) plutôt qu'un fichier sur disque : c'est explicitement la limite documentée dans `signing.py` — un attaquant qui compromet le processus au moment où il écrit signe ses propres entrées avec la clé légitime.

## Gestion de secrets

`OPENROUTER_API_KEY` (et toute future clé de fournisseur LLM) passe aujourd'hui par une variable d'environnement classique. Un déploiement réel la sort vers un gestionnaire de secrets dédié (Vault, AWS Secrets Manager, etc.), avec rotation.

## Ancrage anti-troncature du journal

Publier périodiquement le hash de tête dans un registre externe append-only (même un simple commit signé dans un dépôt séparé, ou une ancre blockchain légère) ferme le dernier trou documenté du journal d'audit.

## Observabilité et alerting

La console actuelle est un tableau de bord de démonstration interactif, pas un système d'alerte. Les signaux consultatifs (ML, outliers, comportement, dérive) doivent être exportés vers un pipeline d'observabilité standard (Prometheus/Grafana, ou un SIEM) pour qu'un opérateur soit notifié plutôt que de devoir ouvrir la console.

## Isolation réseau

Le processus AEGIS a besoin d'un accès sortant contrôlé (allow-list de destinations pour les appels LLM), et d'aucun accès entrant non authentifié sur les endpoints qui déclenchent de vrais appels LLM — le jeton partagé (`AEGIS_DEMO_TOKEN`) existe déjà comme mécanisme, il doit simplement être activé et non laissé en mode démonstration ouverte.

## CI/CD, déjà largement en place

Ce chantier-là est fait, et vaut la peine d'être noté comme un acquis plutôt qu'un manque : suite de tests complète avec clé factice pour empêcher tout appel réseau accidentel, porte de non-régression du red-teaming, porte de promotion de modèles, vérification que les corpus versionnés correspondent à leur générateur, contrôle de contraste WCAG de l'interface, build de la roue distribuable. Un pipeline de déploiement réel n'a qu'à ajouter le déploiement lui-même (image de conteneur, migration de schéma) après ces portes.

---

Pour la question complémentaire — à partir de quel niveau chaque composant est-il « suffisant » pour un déploiement donné — voir [Seuil de suffisance et intégration](integration.md#seuil-de-suffisance). Pour les chantiers d'amélioration au-delà de la production (précision des détecteurs, calibration), voir [Feuille de route](feuille-de-route.md).
