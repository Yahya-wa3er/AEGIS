# AEGIS — Zero-Trust Security Layer pour Systèmes IA Agentiques & RAG

Preuve de concept fonctionnelle : un agent de support client (`victim/`) volontairement naïf, piloté par un vrai LLM (via OpenRouter), et une couche de sécurité (`aegis_core/`) qui l'intercepte pour neutraliser les injections de prompt, appliquer le principe du moindre privilège sur les appels d'outils, et repérer les comportements d'agent statistiquement anormaux — le tout journalisé dans un log infalsifiable.

## Le problème

Un agent IA agentique combine trois surfaces de faiblesse : les documents qu'il récupère (RAG), les outils qu'il peut appeler, et son comportement dans la durée. Un document contenant une instruction cachée peut détourner l'agent pour lui faire exécuter des actions non désirées (virement, fuite de données...) sans que l'utilisateur ne s'en aperçoive. C'est le risque "Prompt Injection" (indirecte) de l'OWASP Top 10 pour applications LLM (édition 2025).

## L'architecture

`victim` et `aegis_core` ne se connaissent pas directement : `VictimAgent` accepte des fonctions (`on_retrieval`, `on_tool_call`, `on_response`) que `AegisGuard` vient brancher depuis l'extérieur. Sans AEGIS, ces hooks laissent tout passer -- avec AEGIS, ils scannent et bloquent. Deux d'entre eux, `on_session_event` (comportement, section 4.4) et `on_response` (citation de la source, section 4.5), ne bloquent rien : ils journalisent un score, car leur signal est probabiliste plutôt qu'une règle certaine. Ce découplage permet de brancher AEGIS sur n'importe quel autre agent, pas seulement `victim/`.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt              # noyau + API + démo web
pip install -r requirements-ml.txt           # + entraînement et classifieur ML (torch, transformers…)

cp .env.example .env   # puis renseigne ta clé OpenRouter dans .env
```

Les dépendances ML sont séparées à dessein : elles pèsent plusieurs centaines de Mo, et un déploiement qui n'utilise que le Policy Engine, le journal d'audit et les règles regex n'a aucune raison de les embarquer. Depuis le durcissement du chargement d'artefacts, `scikit-learn` n'est plus nécessaire à l'**exécution** du détecteur d'outliers RAG — seulement à son entraînement.

Les deux fichiers `requirements*.txt` sont **générés** et ne doivent pas être édités à la main : ils figent les versions exactes de toutes les dépendances, directes et transitives. Pour les régénérer après avoir modifié un `.in` :

```bash
pip install pip-tools
pip-compile requirements.in    -o requirements.txt
pip-compile requirements-ml.in -o requirements-ml.txt
```

### Intégrité des artefacts de modèle

Les répertoires sous `models/` contiennent un `MANIFEST.json` listant le SHA-256 de chaque artefact, écrit par les scripts d'entraînement et vérifié à chaque chargement. Un artefact modifié après l'entraînement fait échouer le chargement plutôt que de produire des scores silencieusement faux. Aucun artefact n'est chargé via `pickle` : le vectoriseur TF-IDF est du JSON + `.npz` (`allow_pickle=False`) et les poids du VAE passent par `torch.load(..., weights_only=True)`.

Limite connue : le manifeste protège contre la modification d'un artefact, pas contre un attaquant qui réécrit *aussi* le manifeste — c'est la même limite structurelle que la chaîne du journal d'audit, et elle se lève de la même façon (signature Ed25519).

## Configuration du modèle LLM

AEGIS utilise OpenRouter (API compatible OpenAI) pour interroger un LLM.

| Variable | Rôle | Exemple |
|---|---|---|
| `OPENROUTER_API_KEY` | Ta clé OpenRouter | `sk-or-...` |
| `OPENROUTER_MODEL` | Le modèle à utiliser | `openai/gpt-4o-mini` |
| `OPENROUTER_BASE_URL` | Endpoint (rarement à changer) | `https://openrouter.ai/api/v1` |

Modèles recommandés :
- `openai/gpt-4o-mini` — rapide et très peu coûteux, suffisant pour la démo.
- `anthropic/claude-3.5-sonnet` — meilleur raisonnement ; utile pour comparer la résistance native de différents modèles face à l'injection.

Changer de modèle ne nécessite aucune modification de code.

## Entraîner le classifieur ML d'injection

Le détecteur (`aegis_core/injection_detector.py`) combine des règles regex (rapides, déterministes) avec un classifieur DistilBERT multilingue fine-tuné (généralise à des formulations non prévues par le regex). Le modèle entraîné n'est pas versionné dans le dépôt (poids trop volumineux) ; pour le reproduire :

```bash
python scripts/generate_french_examples.py --n-per-style 20   # génère data/french_injection_examples.jsonl via un LLM réel (OpenRouter)
python scripts/train_injection_classifier.py                   # fine-tune sur deepset/prompt-injections + les exemples français, sauvegarde dans models/
```

Sans modèle entraîné, `InjectionDetector` bascule automatiquement en mode regex seul (voir "Limites connues" ci-dessous).

## Entraîner le détecteur d'anomalies comportementales (Beta-VAE)

Le détecteur (`aegis_core/behavior_detector.py`) surveille les 5 dernières actions d'un agent (rien / clôture de ticket / email / virement, + montant) et signale les enchaînements statistiquement éloignés de tout ce qu'il a vu à l'entraînement -- y compris des cas que le Policy Engine ne peut pas voir, comme une fréquence d'actions anormale (voir "Limites connues"). Contrairement au classifieur d'injection, il n'y a pas de repli par règles : sans modèle entraîné, il renvoie un risque nul (fail-safe, avec un WARNING).

```bash
python -m scripts.generate_behavior_sessions   # génère des sessions synthétiques normales + anormales (data/)
python -m scripts.train_behavior_vae            # entraîne le Beta-VAE, sauvegarde dans models/behavior_vae/
```

Seed fixée (42) : reproductible à l'identique d'une machine à l'autre.

## Entraîner le détecteur d'outliers RAG (section 4.5)

Le détecteur (`aegis_core/rag_outlier_detector.py`) compare le sens d'un document récupéré au "centre" du domaine documentaire normal (support client), pour repérer un document empoisonné ou hors-sujet -- un signal indépendant du contenu textuel précis analysé par `injection_detector.py`. Simplification assumée : TF-IDF (scikit-learn, déjà une dépendance) plutôt que de vrais embeddings de phrases (voir "Limites connues").

```bash
python -m scripts.generate_rag_corpus            # documents synthétiques normaux + jeu d'évaluation
python -m scripts.train_rag_outlier_detector      # entraîne le vectoriseur, sauvegarde dans models/rag_outlier/
```

## Citation obligatoire de la source (section 4.5)

Le system prompt de `VictimAgent` exige que chaque réponse cite le document utilisé (`[source: <id>]`). `AegisGuard.on_response` vérifie cette citation et journalise un signal (sans bloquer) si elle est absente ou incorrecte -- une réponse sans source rend une instruction injectée bien plus difficile à repérer pour un humain qui relit. Ne nécessite aucun entraînement, mais dépend du LLM configuré (`OPENROUTER_MODEL`) pour effectivement suivre l'instruction -- à vérifier en lançant `demo.py` avec une vraie clé API.

## Assainissement des documents (données personnelles / secrets, section 4.5)

`aegis_core/pii_detector.py` masque, dans chaque document RÉCUPÉRÉ ET NON NEUTRALISÉ, les données qui n'ont rien à faire dans un contexte envoyé à un LLM tiers : emails, IBAN, numéros de carte bancaire, numéros de téléphone français, clés d'API. C'est un troisième signal, indépendant des deux autres (`injection_detector.py`, `rag_outlier_detector.py`) : un document parfaitement légitime peut très bien contenir une donnée sensible laissée par erreur -- ce n'est pas une question de confiance envers le document, mais d'hygiène. Uniquement des règles regex, aucun entraînement nécessaire.

## Lancer la démo

```bash
python demo.py
```

Scénario : un client interroge son ticket de support (#48291), dont le document contient une injection cachée. Sans AEGIS, le LLM exécute réellement le virement et la fuite de données tout en répondant normalement au client. Avec AEGIS, le document est neutralisé avant même d'atteindre le LLM -- l'agent reste utile (il peut toujours clôturer le ticket, une action autorisée) mais l'attaque échoue. Le scan comportemental de cette requête est affiché en fin de scénario protégé.

## Lancer le dashboard web

```bash
cd frontend && npm install && npm run build && cd ..
python -m web.app
```

Ouvre `http://127.0.0.1:8000` : un seul processus sert à la fois l'interface (export statique Next.js) et l'API qui pilote une vraie simulation d'attaque. Le bouton "Lancer la démonstration" rejoue le scénario du ticket #48291 en direct (sans/avec AEGIS), avec le score de robustesse, le journal d'audit traduit en langage clair, et le détail des 5 couches de protection (injection/outliers RAG, permissions, comportement, citation, assainissement PII).

Le dashboard inclut aussi "Testez avec votre propre document" : collez un texte ou importez un fichier (`.txt`, `.md`, `.csv`, `.log`), et AEGIS l'analyse en direct via `/api/analyze-document` avec les trois détecteurs de contenu utilisés sur chaque document RAG (injection de prompt, éloignement du domaine normal, données personnelles/secrets) -- y compris un aperçu de la version assainie qu'AEGIS transmettrait à la place si une donnée sensible est trouvée. Cet endpoint n'appelle aucun LLM -- c'est un scan instantané, gratuit et sans clé API, pensé pour qu'un visiteur de la démo puisse tester ses propres exemples plutôt que de se limiter au scénario pré-écrit. Le texte soumis est tronqué à 20 000 caractères par sécurité (voir `MAX_DOCUMENT_CHARS` dans `web/app.py`).

Troisième outil interactif : le "Laboratoire de robustesse". Contrairement à `/api/analyze-document` (scan hors ligne, aucun LLM), `/api/test-document` fait RÉELLEMENT traverser l'agent par un document choisi -- vrai appel au LLM configuré, décision réelle de tool-calling, vraie neutralisation ou non par `on_retrieval`. On choisit un type de document (piégé, avec ou sans catégorie OWASP précise, ou légitime) tiré du même corpus catégorisé que la suite de red-teaming (`redteam/payloads.py`) ; le document est ensuite testé une fois sans AEGIS puis une fois avec (même document exact les deux fois, via `document_id`, pour une comparaison équitable). Ceci consomme un vrai appel API à chaque test (donc ta clé `OPENROUTER_API_KEY` et quelques secondes) -- c'est le prix à payer pour montrer ce qui se passe *réellement*, pas ce qu'un détecteur prédirait hors ligne.

Si le frontend n'a pas été buildé (`npm run build`), l'API reste utilisable (tous les endpoints `/api/...` fonctionnent, y compris pour les tests) -- seule la route qui sert les pages web renvoie une erreur 503 explicite plutôt que de planter.

## Lancer la suite de red-teaming

```bash
python -m redteam.run_redteam
```

Rejoue un corpus de payloads catégorisés OWASP LLM Top 10 et calcule un score de robustesse. Pensé pour être branché en CI/CD (exit code 1 si le taux de blocage descend sous le seuil).

## Lancer les tests

```bash
python -m pytest -q
```

## Limites connues

### Classifieur ML d'injection (section 4.2)

Le classifieur ML (DistilBERT multilingue fine-tuné) apprend une corrélation de surface : le ton formel/impératif en français est associé au risque d'injection, car le corpus d'entraînement synthétique n'a exposé le modèle qu'à des messages client conversationnels comme exemples bénins -- jamais à du texte formel bénin (RGPD, documentation technique, notes internes).

Mesure empirique (corpus de red-teaming, 10 contrôles bénins variés) :
- Taux de faux positifs sur le registre "support client" (le cas d'usage réel de l'agent victime) : 0% (5/5)
- Taux de faux positifs hors registre (RGPD, doc API, rapports, RH) : 100% (5/5)
- Taux de faux positifs global : 50%

Conclusion : le classifieur est fiable dans son domaine d'entraînement, mais ne généralise pas hors de ce registre. Trois cycles d'entraînement ciblés (modèle multilingue, ajout d'exemples français, diversification du registre) ont été tentés ; chacun a soit échoué à corriger le biais, soit dégradé la performance globale -- signe que le vrai correctif nécessite un volume de données d'entraînement bien supérieur à l'échelle de ce projet, pas un ajustement ponctuel. Piste retenue pour la Phase 2.1 : élargir le corpus d'entraînement à la diversité de registre réelle des documents RAG ciblés, ou pondérer le score ML comme signal d'aide à la décision plutôt que comme déclencheur de blocage automatique isolé.

### Détecteur d'anomalies comportementales (section 4.4)

Le Beta-VAE encode une session comme 5 événements traités indépendamment. Un premier entraînement, où chaque position de la session était tirée sans aucune contrainte sur le total, a produit un modèle incapable de détecter le cas "5 clôtures de ticket d'affilée" : chaque clôture prise isolément est un événement fréquent et banal à l'entraînement, donc rien ne signalait qu'une répétition inhabituelle sur toute la session soit suspecte. Correction appliquée : les sessions normales d'entraînement plafonnent désormais à 2 clôtures sur 5, forçant le modèle à apprendre cette régularité de fréquence.

Mesure empirique (jeu d'évaluation synthétique, 60 sessions normales + 60 anormales réparties en 3 catégories) :
- Anomalies évidentes (rafale d'outils sensibles mêlés) : détectées à 100% (20/20), très nettement séparées du normal.
- Anomalies de fréquence (clôtures en rafale) et de permission (virement isolé) : détection partielle, environ 45% (18/40) -- les cas les plus extrêmes (montant très élevé, répétition totale) sont bien repérés, les cas proches de la frontière normal/anormal sont parfois manqués.
- Faux positifs sur sessions normales tenues à l'écart de l'entraînement : 0% (0/60).

Conclusion : le signal fonctionne et démontre la valeur ajoutée par rapport au Policy Engine seul (qui ne verrait aucune de ces 3 catégories), mais son rappel sur les cas limites reste à améliorer -- attendu pour un modèle non supervisé entraîné sur un jeu synthétique de taille modeste, pas un signe de conception erronée. C'est pourquoi `on_session_event` journalise un score plutôt que de bloquer automatiquement (voir architecture) : un faux négatif occasionnel sur un cas limite ne doit pas donner une fausse impression de sécurité si le signal était traité comme une barrière absolue.

### Détecteur d'outliers RAG (section 4.5)

Simplification assumée dès la conception : TF-IDF (comptage de mots pondéré) plutôt que de vrais embeddings de phrases (sentence-transformers, prévu section 5 du blueprint) -- une notion de "sens" plus grossière, mais qui ne nécessite aucun téléchargement de modèle et reste entièrement testable sans accès réseau.

Mesure empirique (30 documents normaux tenus à l'écart + 9 documents anormaux : 4 attaques réelles du corpus de red-teaming, 5 documents hors-registre mais légitimes) :
- Un premier seuil (moyenne + 3 écarts-types, par cohérence avec le VAE comportemental) ne détectait que 3/9 cas anormaux. Resserré à 2 écarts-types après comparaison sur le même jeu d'évaluation : 8/9 détectés, toujours 0 faux positif sur le normal.
- Les documents hors-registre mais légitimes (RGPD, doc API...) ressortent également comme outliers -- attendu, puisqu'ils sont sémantiquement loin du domaine "support client" appris, mais à garder en tête : ce détecteur signale "inhabituel", pas "malveillant". Les deux ne sont pas synonymes.

Conclusion : comme les deux autres détecteurs ML du projet, la valeur du signal a été mesurée plutôt que supposée, et le compromis retenu (seuil, sensibilité) est documenté plutôt qu'arbitraire.

Conséquence visible dans le laboratoire de robustesse du dashboard (`/api/test-document`) : certains documents "légitimes" du corpus de red-teaming (ex. bulletin météo, rapport financier -- volontairement hors du registre support client, voir `redteam/payloads.py`) peuvent ressortir comme neutralisés même en choisissant "Document légitime". Ce n'est pas un faux positif au sens attaque/pas-attaque, mais l'illustration directe de la limite ci-dessus.

### Citation obligatoire de la source (section 4.5)

Ce mécanisme dépend entièrement du LLM configuré pour suivre l'instruction du system prompt -- contrairement aux trois détecteurs ML, il n'y a rien à entraîner ni à mesurer hors ligne : sa fiabilité doit être vérifiée avec un vrai modèle (voir `demo.py`). Un modèle qui ignore l'instruction de citation rendrait ce signal muet (aucune citation à vérifier), sans pour autant désactiver les trois autres couches de protection.

Cas limite découvert en conditions réelles (première exécution de `demo.py` avec une vraie clé API) : quand `on_retrieval` neutralise le seul document récupéré (injection détectée), le LLM ne reçoit jamais le vrai contenu -- seulement le message `[CONTENU NEUTRALISÉ PAR AEGIS...]`. Il répond alors honnêtement `[source: aucune]`, ce qui est la bonne réponse, pas une source manquante. La première version de `on_response` comptait quand même ce cas comme `missing_citations` (elle ne comparait `cited` qu'à la liste brute `doc_ids`). Corrigé en faisant retenir à `AegisGuard` les ids neutralisés par le dernier `on_retrieval` (`_last_neutralized_ids`) et en les retirant de `doc_ids` avant de juger la citation dans `on_response` -- un document neutralisé ne compte plus comme une source que le LLM aurait pu citer. Un vrai document non neutralisé mais non cité reste, lui, correctement signalé (voir `tests/test_middleware.py`).

### Assainissement des documents / PII (section 4.5)

Uniquement des règles regex (comme la V0 du détecteur d'injection) : rapide et explicable, mais ça manque forcément ce qu'un regex ne peut pas anticiper par construction -- une donnée déguisée (espaces insérés dans un numéro de carte, IBAN écrit avec des mots), un format non couvert (numéro de téléphone étranger hors format français), ou un identifiant sensible métier qui ne ressemble à aucun des motifs codés en dur (`PII_PATTERNS` dans `aegis_core/pii_detector.py`). Un classifieur ML entraîné sur des exemples annotés (type NER pour données personnelles) généraliserait mieux, au prix d'un entraînement -- même compromis que la V0 du détecteur d'injection avant sa Phase 2. Le motif "carte bancaire" (13 à 16 chiffres consécutifs) peut aussi produire un faux positif sur une longue suite de chiffres qui n'est pas une carte (ex. un identifiant de commande à 14 chiffres) -- assumé : mieux vaut masquer par excès dans ce cas précis qu'oublier une vraie donnée sensible.

## État par rapport au blueprint complet

| Module | Statut |
|---|---|
| Policy Engine & Tool Sandbox | ✅ V0 (allow-list Python) |
| Détection d'injection | ✅ V0 heuristique (regex) + Phase 2 ML (DistilBERT multilingue fine-tuné, ensemble regex+ML) -- voir "Limites connues" |
| Journal d'audit signé | ✅ SQLite + chaînage SHA-256 -- Postgres + signatures Ed25519 en V1 |
| Détection d'anomalies comportementales (VAE) | ✅ Phase 2 (Beta-VAE, détection partielle sur cas limites -- voir "Limites connues") |
| Durcissement RAG (filtre PII/secrets, outliers embeddings) | ✅ Phase 3 : outliers d'embeddings (TF-IDF, voir limites) + citation obligatoire + assainissement PII/secrets par regex (voir limites) |
| Red-teaming automatisé | ✅ V0 fonctionnelle, corpus enrichi (10 contrôles bénins diversifiés) |
| Dashboard SOC | ✅ V1 (dashboard Next.js interactif, comparaison protégé/non-protégé) -- alerting et historique en Phase 5 |

## En une phrase

AEGIS est une couche de sécurité qui s'intercale entre un agent IA et le monde extérieur (données récupérées, outils) : elle détecte et neutralise les instructions cachées avant qu'elles n'atteignent le modèle, applique le principe du moindre privilège sur les actions, repère les comportements d'agent statistiquement anormaux, et garde une preuve infalsifiable de chaque décision.
