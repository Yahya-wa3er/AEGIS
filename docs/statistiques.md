# Statistiques du projet

Dix lots de développement (6.1 à 10), chacun livré avec sa suite de tests, ses mesures et son README mis à jour.

<div class="aegis-stats" markdown>

<div class="aegis-stat"><strong>410</strong><span>tests automatisés (27 nouveaux au lot 10)</span></div>
<div class="aegis-stat"><strong>12</strong><span>scénarios de red-teaming, 5 points d'interception</span></div>
<div class="aegis-stat"><strong>10/10</strong><span>attaques arrêtées, 0 faux positif</span></div>
<div class="aegis-stat"><strong>12/12</strong><span>paires de contraste WCAG 2.1 AA</span></div>

</div>

Les 410 tests passent à la fois avec et sans clé LLM réelle configurée. Deux modèles légers sont entraînables en local (détecteur d'outliers RAG, VAE comportemental — voir [Cartes de modèles](model_cards/index.md)), un troisième optionnel plus lourd (classifieur DistilBERT d'injection).

## Filtre de sortie (lot 10) — mesuré séparément

!!! example "Corpus adversarial-mais-légitime, 30 cas"
    | Taux | Résultat |
    |---|---|
    | Détection | 100 % [76-100 %] (12/12) |
    | Neutralisation effective | 100 % [65-100 %] (7/7) |
    | Modification injustifiée d'une réponse légitime | **0 %** — porte bloquante en CI |
    | Signalement injustifié | 0 % (toléré) |

Détail des trois faux positifs trouvés et corrigés pendant la construction dans [Les composants, un par un](composants.md#filtre-de-sortie-le-composant-le-plus-recent).

---

Ces chiffres ne remplacent pas une lecture du tableau de couverture par catégorie OWASP ([Couverture OWASP](owasp.md)) ni de la liste consolidée des angles morts ([Limites connues](limites.md)) — un compte de tests qui passent ne dit rien, seul, sur ce qu'ils couvrent réellement.
