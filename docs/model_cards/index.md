# Cartes de modèles — vue d'ensemble

Deux modèles ML sont entraînables en local dans ce dépôt. Chaque carte ci-dessous est **générée automatiquement** par `python -m scripts.model_registry_cli cards` à partir du registre de modèles (`model_registry.json`) — voir [MLOps](../mlops.md) pour le mécanisme complet (empreintes SHA-256, porte de promotion, dérive). Elles ne sont jamais éditées à la main : la CI vérifie qu'elles correspondent exactement à leur générateur.

- [`rag_outlier`](rag_outlier.md) — détecteur d'outliers sémantiques RAG (TF-IDF + distance au centroïde), consultatif. Mécanique détaillée dans [Les composants, un par un](../composants.md#detecteur-doutliers-semantiques-rag).
- [`behavior_vae`](behavior_vae.md) — détecteur d'anomalies comportementales (Beta-VAE), consultatif. Mécanique détaillée dans [Les composants, un par un](../composants.md#detecteur-comportemental-beta-vae).

Un troisième modèle, un classifieur DistilBERT fine-tuné pour la détection d'injection, est optionnel et plus lourd (~800 Mo) — il n'a pas de carte générée dans le registre au même titre que les deux ci-dessus, mais son fonctionnement est documenté dans [Les composants, un par un](../composants.md#detection-dinjection-regles-classifieur-ml).

Chaque taux publié dans ces cartes suit la même méthodologie — intervalle de Wilson, effectif explicite — décrite dans [Méthodologie de mesure](../mesure.md).
