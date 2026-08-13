# AEGIS — Zero-Trust Security Layer pour Systèmes IA Agentiques & RAG

Preuve de concept fonctionnelle : un agent de support client (`victim/`) volontairement naïf, piloté par un vrai LLM (via OpenRouter), et une couche de sécurité (`aegis_core/`) qui l'intercepte pour neutraliser les injections de prompt, appliquer le principe du moindre privilège sur les appels d'outils, et repérer les comportements d'agent statistiquement anormaux — le tout journalisé dans un log chaîné et signé (Ed25519), vérifiable par un tiers.

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

Limite connue : le manifeste protège contre la modification d'un artefact, pas contre un attaquant qui réécrit *aussi* le manifeste. La correction est la même que pour le journal d'audit — une signature dont l'attaquant n'a pas la clé.

## Journal d'audit signé (Ed25519)

```bash
python -m scripts.generate_audit_key    # une seule fois, écrit keys/
```

Sans cette étape, AEGIS fonctionne mais le journal est **non signé**, et il le dit — dans les logs au démarrage, et dans `robustness_report()["audit_integrity"]["is_signed"]`.

**Pourquoi la signature est nécessaire.** Une chaîne de hachage SHA-256 sans clé ne protège que contre quelqu'un qui modifie une entrée *sans recalculer les hachages suivants*. Un attaquant qui a l'accès en écriture à la base — le même accès qu'il lui faut pour falsifier quoi que ce soit — recalcule toute la chaîne avec le même `hashlib`, et la vérification ne peut pas voir la différence puisqu'elle recalcule à l'identique.

Ce n'est pas théorique : `tests/test_audit_log.py::test_forged_chain_slips_past_an_unsigned_log` exécute l'attaque et vérifie qu'elle passe. Le test suivant vérifie que la signature l'arrête.

**Pourquoi Ed25519 plutôt que HMAC.** HMAC casserait l'attaque aussi bien, sans dépendance nouvelle. Mais il faut la clé secrète pour *vérifier* : un auditeur externe ne peut pas contrôler le journal sans recevoir de quoi le forger. Ed25519 sépare les deux rôles — la clé privée signe, la clé publique vérifie. Tu peux publier la clé publique, un client ou un commissaire aux comptes vérifie lui-même, et personne d'autre que le détenteur de la clé privée ne peut écrire une ligne crédible.

Vérifier un journal sans détenir la clé privée :

```python
from aegis_core.audit_log import AuditLog
from aegis_core.signing import load_signer

log = AuditLog("audit.db", signer=load_signer(public_key_path="audit_ed25519.pub"))
print(log.verify_integrity())   # ok / entrée fautive / motif / nombre de signatures vérifiées
```

Trois couches, du plus faible au plus fort : le **chaînage de hachage** attrape la modification naïve ; les **triggers SQLite append-only** font refuser `UPDATE` et `DELETE` par le moteur lui-même (ce qui arrête un bug ou une injection SQL, pas un attaquant qui supprime le trigger) ; la **signature** arrête la reforge.

**Ce qui reste non couvert**, et qu'il faut dire : un attaquant qui compromet le processus *pendant* qu'il écrit signera ses propres entrées avec la clé légitime ; et la troncature — supprimer les N dernières entrées — reste indétectable sans ancrage externe du hash de tête. Le premier cas relève de l'isolation de la clé (KMS/HSM), le second d'un ancrage périodique dans un stockage append-only. Aucun des deux n'est fait ici.

La clé privée est exclue du dépôt par `.gitignore`. Ne la regénère pas sans archiver le journal qu'elle signait : toutes les signatures existantes deviendraient invalides, ce qui est indiscernable d'une falsification.

## Mode de défaillance : fail-open par défaut, fail-closed sur demande

Quand un détecteur ML n'a pas de modèle entraîné, il renvoie `risk=0.0` sur tout, avec un WARNING. C'est un comportement **fail-open** — la version précédente de ce README l'appelait « fail-safe », ce qui est l'exact opposé.

Sur un clone frais du dépôt, trois couches sur cinq sont donc inertes tant que les scripts d'entraînement n'ont pas tourné. Ce n'est pas un bug, mais ça doit être visible :

```python
from aegis_core.config import AegisConfig
from aegis_core.middleware import AegisGuard

# Par défaut : rien n'est exigé, rien ne bloque, mais l'état est rapporté.
guard = AegisGuard()
guard.detector_status()
# {'injection_ml': {'available': False, 'required': False, 'reason': 'classifieur non entraîné…'}, …}

# Fail-closed : AEGIS refuse de DÉMARRER si ces détecteurs manquent.
guard = AegisGuard(config=AegisConfig(
    required_detectors=frozenset({"rag_outlier", "behavior"}),
    audit_db_path="/var/lib/aegis/audit.db",
    require_signed_audit=True,
))
```

Le refus intervient au démarrage, pas à la première requête — découvrir qu'un détecteur exigé est absent au moment où un document hostile arrive, c'est le découvrir trop tard.

`required_detectors` est **vide par défaut** : à l'opérateur de déclarer ce qui est indispensable à *son* déploiement. AEGIS ne peut pas le deviner, et prétendre le deviner serait une autre forme de mensonge.

Tout est configurable par l'environnement :

```bash
export AEGIS_REQUIRED_DETECTORS=rag_outlier,behavior
export AEGIS_AUDIT_DB=/var/lib/aegis/audit.db
export AEGIS_REQUIRE_SIGNED_AUDIT=1
```

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

Le détecteur (`aegis_core/behavior_detector.py`) surveille les 5 dernières actions d'un agent (rien / clôture de ticket / email / virement, + montant) et signale les enchaînements statistiquement éloignés de tout ce qu'il a vu à l'entraînement -- y compris des cas que le Policy Engine ne peut pas voir, comme une fréquence d'actions anormale (voir "Limites connues"). Contrairement au classifieur d'injection, il n'y a pas de repli par règles : sans modèle entraîné, il renvoie un risque nul. C'est un comportement **fail-open**, pas « fail-safe » — un composant qui laisse tout passer quand il défaille est l'inverse de sûr. Le mode est nommé, rapporté dans `robustness_report()`, et peut être rendu bloquant via `AegisConfig.required_detectors` (voir « Mode de défaillance » ci-dessous).

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

## Analyse de la requête utilisateur et des retours d'outils

Deux points d'interception ajoutés au lot 3C, qui ferment les deux dernières surfaces non couvertes.

**`on_prompt` — l'injection directe.** Jusqu'ici, seuls les documents récupérés étaient analysés : une instruction tapée par l'utilisateur lui-même n'était scannée nulle part dans le pipeline. Le détecteur savait pourtant la reconnaître — `run_redteam` l'appelait à la main sur les mêmes payloads, ce qui donnait une impression de couverture que le produit assemblé n'avait pas. Une requête refusée n'atteint jamais le modèle : bloquer après l'appel LLM aurait déjà coûté un aller-retour, et le modèle aurait déjà lu l'injection.

**Seules les règles bloquent une requête ; le score ML est journalisé sans bloquer.** Ce n'est pas de la timidité, c'est ce que disent les mesures : les règles obtiennent 100 % de blocage pour 0 % de faux positifs, le classifieur signale un document légitime sur deux. Un faux positif sur un document coûte un bout de contexte ; un faux positif sur la requête coûte un refus opposé à quelqu'un qui posait une question normale. On bloque sur le signal déterministe dont le taux d'erreur est mesuré à zéro, on observe l'autre. Le journal enregistre `ml_would_have_blocked` : c'est ce chiffre qui permettra de rediscuter le choix, avec des données plutôt que des intentions.

**`on_tool_result` — l'injection de second ordre.** Ce qu'un outil renvoie est une **donnée**, pas une instruction — au même titre qu'un document récupéré. Tant que les outils sont des mocks, c'est sans conséquence ; dès qu'un outil lit une base, appelle une API ou récupère une page, son retour est du contenu contrôlable par un attaquant, réinjecté tel quel dans le contexte. C'est aujourd'hui le vecteur le plus exploité contre les agents réels, et le plus négligé — parce que « c'est notre propre outil qui répond ». Même politique que pour les documents : neutralisation par un texte neutre, puis masquage des données personnelles.

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

### Détection d'injection : ce qui est couvert, et ce qui ne l'est pas

**Règles (couche 1).** Bilingues français/anglais, appliquées à un texte normalisé (`aegis_core/normalization.py`) : suppression des caractères invisibles et des contrôles bidi, NFKC, repliement des homoglyphes cyrilliques et grecs, recollage de l'espacement, décodage des blocs base64, extraction du contenu des commentaires de balisage.

Mesure sur les dix contournements identifiés lors de l'audit du 12/08/2026, **couche de règles seule, sans classifieur ML** (l'état d'un clone frais) :

| | Avant | Après |
|---|---|---|
| Contournements détectés | 0/10 | **10/10** |
| Faux positifs sur 10 documents bénins variés | 2/10 | **0/10** |
| Taux de blocage du corpus de red-teaming | 67 % (2/3) | **100 % (12/12)** |

Les deux faux positifs venaient de la règle `<!--.*-->`, qui signalait *tout* commentaire HTML — intenable dès qu'un corpus RAG contient du HTML ou du Markdown exporté. Le commentaire n'est plus le signal : son **contenu** est analysé comme une vue à part, et la dissimulation devient une méta-règle (`evasion.hidden_in_markup`) qui s'ajoute à l'instruction détectée. Un texte anodin ne s'obfusque pas : le fait de cacher est souvent un signal plus fiable que ce qui est caché.

**Ce que les règles ne feront jamais.** Une paraphrase qu'aucun motif n'anticipe reste invisible, par construction. C'est le rôle du classifieur ML, et c'est pourquoi les deux couches coexistent plutôt que de se remplacer.

**Le seuil de recollage de l'espacement** (trois lettres) a été vérifié sur 413 textes français réels du dépôt : zéro recollage indésirable. Une normalisation qui abîme le texte légitime déplacerait le problème au lieu de le résoudre.

**Précaution de méthode.** Les neuf variantes d'obfuscation ont été ajoutées au corpus de red-teaming *après* le correctif. Un corpus construit sur les cas qu'on vient de faire passer ne mesure plus rien — ici le correctif est une normalisation générique, aucune règle ne cible un payload en particulier, et leur rôle est d'empêcher la régression. Le score sur 12 attaques reste par ailleurs statistiquement faible : voir la limite ci-dessous.

**Sur une machine où le classifieur ML est entraîné, le tableau change.** Les règles restent à 100 % / 0 %, mais l'ensemble tombe à **50 % de faux positifs** — cinq documents légitimes sur dix signalés à tort, tous par le classifieur (`matched_rules` vide, `ml_score` entre 0,95 et 0,99). `run_redteam` affiche désormais les deux configurations côte à côte, précisément pour que ce coût soit visible :

```
Comparaison par couche (blocage / faux positifs) :
  Règles seules      : 100% / 0%
  Règles + ML        : 100% / 50%
  --> Les faux positifs viennent du classifieur ML, pas des règles.
```

Conséquence pratique : `InjectionDetector(use_ml=False)` est un mode de déploiement légitime, pas seulement une commodité de test. La couche de règles est déterministe, explicable et mesurée ; le classifieur, dans son état actuel, coûte plus qu'il ne rapporte sur du texte hors de son registre d'entraînement.

**La porte CI vérifie maintenant les deux bouts.** Un seuil de blocage seul se satisfait d'un détecteur qui bloque tout : 100 % de recall, 100 % de faux positifs, exit 0. `MAX_FALSE_POSITIVE_RATE` ferme cette porte. Sa valeur (55 %) est un **cliquet** calé sur la mesure du jour, pas une cible — il est là pour empêcher que ça empire.

**Ce corpus est trop petit.** Douze attaques, dix contrôles. Chaque payload pèse 8 points de recall. Un vrai benchmark demande des centaines de cas issus de corpus publics (AgentDojo, garak, PyRIT, `deepset/prompt-injections`) — c'est le prochain chantier de mesure, et tant qu'il n'est pas fait, le « Robustness Score » doit être lu comme un garde-fou de non-régression, pas comme une mesure de robustesse.

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

## Couverture OWASP GenAI LLM Top 10 — édition 2026

L'édition 2026 est parue le 6 août 2026. Sa méthodologie combine le vote d'experts (75 %) et l'analyse de 7 714 incidents réels (25 %), ce qui a redistribué le classement : *Excessive Agency* passe 6ᵉ → **3ᵉ**, *Unbounded Consumption* 10ᵉ → **6ᵉ**, *System Prompt Leakage* est élargi et renommé *Hidden Context Exposure*.

Le tableau ci-dessous est une évaluation honnête de ce qui est réellement couvert. Il n'y a **aucun ✅** : aucune catégorie n'est traitée de bout en bout, et prétendre le contraire serait le genre d'écart promesse/réalité que ce projet a précisément vocation à mesurer chez les autres.

| # | Risque 2026 | Couverture | Ce qui manque |
|---|---|---|---|
| LLM01 | Prompt Injection *(étendu au cross-modal)* | ⚠️ partielle | Indirecte via documents seulement. Règles francophones, contournées par l'anglais, l'Unicode et l'encodage. La requête utilisateur et les retours d'outils ne sont pas scannés. Rien en cross-modal. |
| LLM02 | Sensitive Information Disclosure | ⚠️ entrée seulement | PII masquée dans les documents récupérés. **Aucun filtre de sortie.** |
| LLM03 | **Excessive Agency** *(6ᵉ → 3ᵉ)* | ⚠️ partielle | Allow-list deny-by-default : la bonne base, et l'atout principal du projet. Manque : `sensitive_tools` sans effet, plafond de montant contournable par typage, pas de liste blanche de destinataires, pas de validation humaine, pas de quota. |
| LLM04 | Supply Chain *(3ᵉ → 4ᵉ)* | ⚠️ partielle | Plus de chargement pickle, dépendances figées, artefacts vérifiés par SHA-256. Manque : SBOM, signature du bundle de modèles, provenance. |
| LLM05 | Data and Model Poisoning | ⚠️ partielle | Détection d'outliers à la récupération. Rien à l'indexation, aucune provenance ni signature de document. |
| LLM06 | **Unbounded Consumption** *(10ᵉ → 6ᵉ)* | 🔴 absente | Pas de budget de jetons, pas de plafond de coût, pas de limitation de débit, pas de borne sur les boucles d'agent. Les endpoints de démo déclenchent de vrais appels LLM sans authentification. |
| LLM07 | Misinformation *(9ᵉ → 7ᵉ)* | ⚠️ amorce | La vérification de citation est la bonne intuition. Manque la vérification d'ancrage : la réponse est-elle réellement *soutenue* par la source citée ? |
| LLM08 | **Hidden Context Exposure** *(ex-System Prompt Leakage)* | 🔴 absente | Rien ne détecte que le modèle restitue son prompt système. |
| LLM09 | Vector and Embedding Weaknesses | ⚠️ partielle | Détection d'outliers TF-IDF. Pas de contrôle d'accès sur l'index, pas d'isolation multi-locataires. |
| LLM10 | Improper Output Handling *(5ᵉ → 10ᵉ)* | 🔴 absente | Les retours d'outils et la réponse finale traversent sans validation. Le frontend échappe correctement (React, pas de `dangerouslySetInnerHTML`), mais c'est le seul rempart et il est côté client. |

Note de lecture : les identifiants utilisés jusqu'ici dans `redteam/payloads.py` étaient ceux de l'édition **2023** sous un en-tête « 2025 » (`LLM06 Sensitive Information Disclosure`, `LLM08 Excessive Agency`). Corrigé — voir la table de correspondance en tête de ce fichier.

## État par rapport au blueprint complet

| Module | Statut |
|---|---|
| Policy Engine & Tool Sandbox | ✅ V0 (allow-list Python) |
| Analyse de la requête utilisateur (`on_prompt`) | ✅ Lot 3C — règles bloquantes, ML observé |
| Analyse des retours d'outils (`on_tool_result`) | ✅ Lot 3C — neutralisation + masquage PII |
| Détection d'injection | ✅ V0 heuristique (regex) + Phase 2 ML (DistilBERT multilingue fine-tuné, ensemble regex+ML) -- voir "Limites connues" |
| Journal d'audit signé | ✅ SQLite + chaînage SHA-256 -- Postgres + signatures Ed25519 en V1 |
| Détection d'anomalies comportementales (VAE) | ✅ Phase 2 (Beta-VAE, détection partielle sur cas limites -- voir "Limites connues") |
| Durcissement RAG (filtre PII/secrets, outliers embeddings) | ✅ Phase 3 : outliers d'embeddings (TF-IDF, voir limites) + citation obligatoire + assainissement PII/secrets par regex (voir limites) |
| Red-teaming automatisé | ✅ V0 fonctionnelle, corpus enrichi (10 contrôles bénins diversifiés) |
| Dashboard SOC | ✅ V1 (dashboard Next.js interactif, comparaison protégé/non-protégé) -- alerting et historique en Phase 5 |

## En une phrase

AEGIS est une couche de sécurité qui s'intercale entre un agent IA et le monde extérieur (données récupérées, outils) : elle détecte et neutralise les instructions cachées avant qu'elles n'atteignent le modèle, applique le principe du moindre privilège sur les actions, repère les comportements d'agent statistiquement anormaux, et garde de chaque décision une trace signée qu'un tiers peut vérifier sans pouvoir la falsifier.
