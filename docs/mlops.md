# MLOps — registre, promotion, dérive

Un registre versionné (`model_registry.json`) associe à chaque modèle une **empreinte SHA-256 de son artefact et de son jeu d'entraînement**, ses mesures avec intervalles de Wilson (voir [Méthodologie de mesure](mesure.md)), et son seuil calibré. Ça bouche un trou que le manifeste d'intégrité existant (`model_io.py`) ne couvre pas : ce manifeste prouve qu'un artefact n'a pas été altéré *depuis son écriture*, pas que c'est l'artefact sur lequel les chiffres publiés ont réellement été mesurés. Réentraîner un modèle sans republier le laisse cohérent avec son propre manifeste tout en décrivant des chiffres périmés.

## La porte de promotion

`aegis_core/promotion.py` refuse un nouveau modèle dont une métrique montre une régression **prouvée** (intervalles de Wilson disjoints, dans le mauvais sens), accepte une amélioration prouvée, et **autorise mais interdit d'annoncer un progrès** en cas de recouvrement d'intervalles — le recouvrement est **conservateur** : il ne prouve pas l'absence de différence, il constate qu'on ne peut rien conclure à ce volume. Une métrique qui *disparaît* entre deux versions compte comme une régression, pour empêcher que « cesser de publier le chiffre gênant » ne devienne un moyen de franchir la porte.

## La dérive

`aegis_core/drift.py` compare les quantiles de distance réellement observés en production aux quantiles mesurés à la calibration, et **refuse explicitement de conclure** sous 50 observations — « pas assez vu » n'est pas « rien à signaler ». Le module documente sans détour que ce dépôt a zéro trafic de production : aucun seuil d'alerte n'est proposé, parce qu'il faudrait des données réelles pour savoir quel décalage est tolérable.

## Cartes de modèles

Chaque modèle entraîné (détecteur d'outliers RAG, VAE comportemental) a une carte générée automatiquement par `scripts/model_registry_cli cards` — voir [Vue d'ensemble des cartes de modèles](model_cards/index.md). Ces pages sont **générées, pas éditées à la main** : la CI vérifie que `git status --porcelain -- docs/model_cards/` est vide après régénération.

## Ce qui a été trouvé en le vérifiant sur ce projet lui-même

`python -m scripts.model_registry_cli verify` a détecté, sur la machine de développement de ce projet, que les artefacts sur disque pour `behavior_vae` et `rag_outlier` ne correspondaient plus à ce qu'enregistrait le registre — exactement le type d'écart que cet outil existe pour attraper. Un tel écart est bénin s'il vient d'un réentraînement local non republié (`promote` non relancé), et redevient un vrai problème de reproductibilité sinon. C'est un contrôle qui n'existe aujourd'hui **qu'en CI/en exécution manuelle**, pas au démarrage du service — voir [Limites connues](limites.md).
