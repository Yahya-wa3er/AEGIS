# Statistiques du projet

Dix lots de développement (6.1 à 10), chacun livré avec sa suite de tests, ses mesures et son README mis à jour.

À la livraison du lot 10 :

- **410 tests automatisés** (383 avant ce lot, 27 nouveaux pour le filtre de sortie), passant à la fois avec et sans clé LLM réelle configurée.
- **12 scénarios de red-teaming** sur les 5 points d'interception (voir [Modèle de menace et architecture](architecture.md)).
- **10 attaques arrêtées sur 10**, **0 faux positif** sur les 10 contrôles bénins du banc de red-teaming — avec les intervalles de Wilson correspondants, larges à ce volume (méthodologie détaillée dans [Méthodologie de mesure](mesure.md)).
- **12 paires de contraste WCAG 2.1 AA** conformes sur l'interface.
- **Deux modèles légers** entraînables en local (détecteur d'outliers RAG, VAE comportemental — voir [Cartes de modèles](model_cards/index.md)), un troisième optionnel plus lourd (classifieur DistilBERT d'injection).

Pour le filtre de sortie du lot 10 spécifiquement, mesuré séparément sur un corpus adversarial-mais-légitime de 30 cas : taux de détection 100 % [76-100 %] (12/12), taux de neutralisation effective 100 % [65-100 %] (7/7), taux de modification injustifiée d'une réponse légitime 0 % (porte bloquante en CI), taux de signalement injustifié 0 % (toléré). Détail des trois faux positifs trouvés et corrigés pendant la construction dans [Les composants, un par un](composants.md#filtre-de-sortie-le-composant-le-plus-recent).

Ces chiffres ne remplacent pas une lecture du tableau de couverture par catégorie OWASP ([Couverture OWASP](owasp.md)) ni de la liste consolidée des angles morts ([Limites connues](limites.md)) — un compte de tests qui passent ne dit rien, seul, sur ce qu'ils couvrent réellement.
