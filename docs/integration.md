# Brancher AEGIS sur un agent existant

## Seuil de suffisance

Quand est-ce « suffisant » ? La bonne réponse n'est pas un pourcentage global, parce que le tableau de [Couverture OWASP](owasp.md) montre que les dix catégories n'ont pas la même maturité ni la même nature de contrôle. Le seuil de suffisance se pose composant par composant, et dépend directement de ce qu'un déploiement risque de perdre.

=== "Agent qui agit"

    Pour un agent qui **exécute des actions à conséquence réelle** (virement, email, modification de compte), le Policy Engine avec `required_detectors` non vide (mode fail-closed) et un vrai `approval_hook` humain sur les outils sensibles est la barre minimale non négociable — c'est le seul composant dont l'absence transforme une faille en incident financier direct.

=== "Agent qui répond"

    Pour un agent qui **ne fait que répondre** (support, assistant documentaire), le filtre de sortie et l'assainissement des documents suffisent probablement à couvrir le risque principal (fuite de données), à condition d'avoir mesuré le taux de modification injustifiée sur son propre corpus, pas seulement celui du dépôt.

!!! danger "Deux garde-fous qui s'appliquent quel que soit le type d'agent"
    - Le journal d'audit signé n'est « suffisant » que si sa clé privée n'est pas un simple fichier à côté du code — sinon la preuve qu'il produit n'a de valeur qu'en interne, pas face à un tiers.
    - Aucun déploiement ne devrait se contenter de la porte de non-régression du red-teaming telle quelle : les intervalles de Wilson sur 12 attaques et 10 contrôles disent explicitement qu'on ne peut rien garantir en dessous de 76 % de blocage réel (voir [Méthodologie de mesure](mesure.md)). « Suffisant » commence quand ce corpus reflète le trafic et les attaques réellement attendues du déploiement visé, pas celui du dépôt de démonstration.

## Brancher AEGIS sur un agent déjà construit

C'est précisément ce que l'architecture en cinq hooks (voir [Modèle de menace et architecture](architecture.md)) a été conçue pour permettre sans réécrire l'agent existant. `AegisGuard` ne dépend que d'objets porteurs de `.id` et `.content` pour les documents, et de fonctions de rappel pour le reste :

1. Où l'agent reçoit la requête utilisateur, appeler `guard.on_prompt(texte, ctx)` et respecter son verdict avant d'appeler le modèle.
2. Où l'agent récupère des documents (RAG), faire passer la liste récupérée par `guard.on_retrieval(chunks, ctx)` et utiliser la liste retournée (potentiellement neutralisée/assainie) plutôt que l'originale.
3. Où l'agent s'apprête à exécuter un appel d'outil demandé par le modèle, appeler `guard.on_tool_call(nom_agent, nom_outil, params, ctx)` et n'exécuter que si la décision est `"allow"`.
4. Où l'agent reçoit le résultat d'un outil, le faire passer par `guard.on_tool_result(nom_outil, resultat, ctx)` avant de le réinjecter dans le contexte du modèle.
5. Où l'agent produit sa réponse finale, appeler `guard.on_response(texte, doc_ids, ctx)` et **rendre le texte retourné**, pas le texte d'origine — c'est le contrat depuis le lot 10.

!!! tip "Sur un framework existant (LangChain, LlamaIndex, orchestrateur maison)"
    Ces cinq points correspondent respectivement aux callbacks ou hooks d'entrée de requête, de retrieval, de tool-calling (avant exécution), de tool-result (après exécution), et de post-traitement de la réponse — la plupart des frameworks d'agents modernes exposent déjà ces points d'extension sous une forme ou une autre. Le travail d'intégration consiste à câbler `AegisGuard` sur ces points d'extension plutôt qu'à modifier la logique métier de l'agent.

    Un `AegisConfig(hidden_context=(prompt_systeme_reel,))` doit être fourni explicitement par l'intégrateur — `aegis_core` ne connaît pas le prompt système de l'agent qu'il protège, et ne peut pas le deviner sans revenir à une détection par mots-clés plutôt que par comparaison à la source réelle.

## Ce qui ne se transpose pas automatiquement

!!! warning "À redéfinir pour tout nouvel agent"
    Les politiques du Policy Engine (`DEFAULT_POLICIES`) sont écrites pour `SupportAgent` et doivent être redéfinies pour tout autre agent ; les modèles ML (classifieur d'injection, détecteur d'outliers, VAE comportemental) sont entraînés sur les corpus et le domaine de ce dépôt et devraient, idéalement, être réentraînés sur le trafic et le domaine réels du nouvel agent avant d'être promus au rang de signal bloquant — sans quoi ils dégraderaient probablement leurs performances hors du domaine sur lequel ils ont été calibrés (voir [MLOps](mlops.md) pour le cycle de promotion).
