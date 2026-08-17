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

## Installer AEGIS comme bibliothèque

```bash
pip install -e .              # noyau seul : règles, Policy Engine, journal signé
pip install -e ".[ml]"        # + classifieur d'injection et détecteur comportemental
pip install -e ".[demo]"      # + agent de démonstration et tableau de bord
pip install -e ".[dev]"       # tout, plus les outils de test
```

Le noyau ne dépend que de `cryptography`, `jsonschema` et `numpy` — soit quelques mégaoctets. Un déploiement qui n'utilise que les règles, le Policy Engine et le journal d'audit n'embarque ni torch ni transformers.

Cette séparation était **annoncée mais fausse** jusqu'au lot 4B : `injection_detector.py` importait torch au niveau du module, donc `import aegis_core.middleware` échouait sans lui. La CI le vérifie désormais à chaque push, en installant le noyau seul dans un environnement vierge — une promesse d'architecture qu'on ne teste pas finit toujours par devenir fausse.

Seul `aegis_core` est distribué. `victim/`, `web/` et `redteam/` restent dans le dépôt : ce sont la démonstration et le banc de mesure, pas le produit. Les livrer ensemble obligerait tout utilisateur à installer FastAPI et le client OpenAI pour se servir d'un Policy Engine.

## Intégration continue

`.github/workflows/ci.yml` tourne à chaque push et chaque pull request :

| Étape | Ce qu'elle attrape |
|---|---|
| Import du noyau sans les dépendances ML | Une dépendance ML qui se réintroduit dans le noyau |
| Entraînement des détecteurs légers | Un script d'entraînement cassé, une parité rompue |
| `pytest` | Les régressions fonctionnelles — dont chaque contournement fermé |
| Red-teaming | Une baisse du taux de blocage **ou** une hausse des faux positifs |
| `tsc`, `eslint`, `npm run build` | Une rupture du contrat d'API entre backend et frontend |
| `python -m build` | Un `pyproject.toml` cassé |

Le README annonçait depuis le début que le red-teaming était « pensé pour être branché en CI/CD ». Il ne l'était pas — et il échouait sur `main` sans que personne ne le voie. C'est ce qui rend les mesures durables plutôt que photographiques.

Limite assumée : `requirements-ml.txt` a été généré sur une machine compatible CUDA et épingle 15 paquets `nvidia-*` (~2,5 Go de roues GPU). La CI installe donc la variante **CPU** de torch au lieu d'utiliser ce lock — elle ne le vérifie pas tel quel. La correction propre est un second lock CPU ; elle attendra que quelqu'un d'autre installe le projet, parce que c'est ce moment-là qui dira lequel des deux locks est le bon défaut.

Note sur les tests sautés : dix tests dépendent de modèles entraînés que le dépôt ne versionne pas. Sur un poste de développement ils sont **sautés** avec un message qui dit quoi lancer — un `pytest` rouge au premier clone n'apprend rien à personne. En CI les modèles sont entraînés d'abord, donc rien n'est sauté.

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

## Quels signaux ont le droit de bloquer

Les trois signaux de contenu n'ont pas la même nature, et les traiter à l'identique par un `or` était une erreur mesurable : le maillon le plus bruyant décidait pour tout le monde.

| Signal | Nature | Blocage | Faux positifs |
|---|---|---|---|
| Règles | déterministe, explicable | **100 % [76 %-100 %]** (12/12) | **0 % [0 %-28 %]** (0/10) |
| Classifieur ML | probabiliste | 100 % [76 %-100 %] (12/12) | **50 % [24 %-76 %]** (5/10) |
| Outliers RAG | probabiliste | 86 % [60 %-96 %] (12/14) | **50 % [19 %-81 %]** (3/6) hors-domaine |

Les crochets sont l'intervalle de confiance à 95 % — voir « Comment les chiffres de ce README sont produits ». Ils sont larges, et c'est l'information principale : à ces volumes, aucun de ces taux n'est établi à mieux que ±25 points.

Les 50 % du classifieur ne sont pas une estimation : cinq des dix documents de contrôle du corpus de red-teaming sont signalés à tort — un rapport financier, un bulletin météo, de la documentation d'API, une note RH, une mention RGPD. Ceux du détecteur d'outliers sont mesurés sur son jeu de test, sur des documents légitimes d'un registre non appris.

`AegisConfig.blocking_signals` ne contient donc que `rules` par défaut. Les deux autres continuent de tourner, leur score est journalisé et affiché, et le journal compte les cas où ils **auraient** bloqué :

```
Détail par détecteur, pris isolément :
  Règles seules      blocage  100% [76%-100%] (12/12)   faux positifs   0% [0%-28%] (0/10)
  Règles + ML        blocage  100% [76%-100%] (12/12)   faux positifs  50% [24%-76%] (5/10)
  Pipeline réel      blocage  100% [76%-100%] (12/12)   faux positifs   0% [0%-28%] (0/10)   <-- ce que le produit fait
```

**Ce n'est pas une mise au rebut.** Le corpus actuel ne peut pas mesurer ce que le classifieur apporte vraiment : sa valeur est de généraliser à des formulations qu'aucune règle n'anticipe, et douze payloads calibrés sur les règles ne testent pas cela. Le compteur `would_have_blocked` est précisément ce qui permettra de lui rendre le pouvoir de bloquer — le jour où il montrera des détections que les règles ratent, avec des chiffres plutôt qu'une intuition.

Un opérateur qui a mesuré son propre taux de faux positifs sur *son* corpus décide autrement s'il le souhaite :

```python
AegisConfig(blocking_signals=frozenset({"rules", "rag_outlier"}))
```

```bash
export AEGIS_BLOCKING_SIGNALS=rules,rag_outlier
```

### Une mesure qui disait l'inverse de ce qu'elle semblait dire

Le README annonçait *« 0 faux positif sur le normal (0/30) »* pour le détecteur d'outliers. Ce n'était pas faux, c'était mal mesuré, et de trois façons à la fois : les trente documents « normaux » venaient du **même générateur que le corpus d'entraînement** (le détecteur était évalué sur sa propre distribution) ; le **seuil était calculé sur ces trente documents** ; et les documents légitimes hors-domaine portaient le label `anomalous`, si bien que les signaler comptait comme une réussite. Sur un jeu de test réellement tenu à l'écart et correctement étiqueté, le détecteur se trompe une fois sur deux sur le hors-domaine — 50 % [19 %-81 %]. Le détail est dans « Comment les chiffres de ce README sont produits ».

Un test le disait aussi, dans l'autre sens : `test_on_retrieval_neutralizes_outlier_even_without_injection_pattern` vérifiait qu'une mention RGPD parfaitement légitime était neutralisée, sous le titre « démontre l'apport du détecteur d'outliers ». Ce n'était pas une détection, c'était un faux positif célébré comme une fonctionnalité. Le test a été réécrit pour vérifier l'inverse.

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
python -m scripts.generate_behavior_sessions  # train (1000) / calibration (200) / test (320)
python -m scripts.train_behavior_vae           # ajuste, calibre, mesure, écrit models/behavior_vae/
```

Seed fixée (42) : reproductible à l'identique d'une machine à l'autre.

## Entraîner le détecteur d'outliers RAG (section 4.5)

Le détecteur (`aegis_core/rag_outlier_detector.py`) compare le sens d'un document récupéré au "centre" du domaine documentaire normal (support client), pour repérer un document empoisonné ou hors-sujet -- un signal indépendant du contenu textuel précis analysé par `injection_detector.py`. Simplification assumée : TF-IDF (scikit-learn, déjà une dépendance) plutôt que de vrais embeddings de phrases (voir "Limites connues").

```bash
python -m scripts.generate_rag_corpus        # train / calibration / test, découpés par gabarit
python -m scripts.train_rag_outlier_detector  # ajuste, calibre, mesure, écrit models/rag_outlier/
```

Le script refuse de démarrer si les trois jeux se recouvrent, calibre son seuil sur `calibration` et n'ouvre `test` qu'une fois, à la fin. Les mesures partent dans `models/rag_outlier/metrics.json`, à côté du modèle : un seuil sans le taux qu'il produit n'est pas interprétable six mois plus tard.

## Analyse de la requête utilisateur et des retours d'outils

Deux points d'interception ajoutés au lot 3C, qui ferment les deux dernières surfaces non couvertes.

**`on_prompt` — l'injection directe.** Jusqu'ici, seuls les documents récupérés étaient analysés : une instruction tapée par l'utilisateur lui-même n'était scannée nulle part dans le pipeline. Le détecteur savait pourtant la reconnaître — `run_redteam` l'appelait à la main sur les mêmes payloads, ce qui donnait une impression de couverture que le produit assemblé n'avait pas. Une requête refusée n'atteint jamais le modèle : bloquer après l'appel LLM aurait déjà coûté un aller-retour, et le modèle aurait déjà lu l'injection.

**Seules les règles bloquent une requête ; le score ML est journalisé sans bloquer.** Ce n'est pas de la timidité, c'est ce que disent les mesures : les règles obtiennent 100 % [76 %-100 %] de blocage pour 0 % [0 %-28 %] de faux positifs, le classifieur signale un document légitime sur deux (50 % [24 %-76 %]). Un faux positif sur un document coûte un bout de contexte ; un faux positif sur la requête coûte un refus opposé à quelqu'un qui posait une question normale. On bloque sur le signal déterministe dont le taux d'erreur est mesuré à zéro, on observe l'autre. Le journal enregistre `ml_would_have_blocked` : c'est ce chiffre qui permettra de rediscuter le choix, avec des données plutôt que des intentions.

**`on_tool_result` — l'injection de second ordre.** Ce qu'un outil renvoie est une **donnée**, pas une instruction — au même titre qu'un document récupéré. Tant que les outils sont des mocks, c'est sans conséquence ; dès qu'un outil lit une base, appelle une API ou récupère une page, son retour est du contenu contrôlable par un attaquant, réinjecté tel quel dans le contexte. C'est aujourd'hui le vecteur le plus exploité contre les agents réels, et le plus négligé — parce que « c'est notre propre outil qui répond ». Même politique que pour les documents : neutralisation par un texte neutre, puis masquage des données personnelles.

## Citation obligatoire de la source (section 4.5)

Le system prompt de `VictimAgent` exige que chaque réponse cite le document utilisé (`[source: <id>]`). `AegisGuard.on_response` vérifie cette citation et journalise un signal (sans bloquer) si elle est absente ou incorrecte -- une réponse sans source rend une instruction injectée bien plus difficile à repérer pour un humain qui relit. Ne nécessite aucun entraînement, mais dépend du LLM configuré (`OPENROUTER_MODEL`) pour effectivement suivre l'instruction -- à vérifier en lançant `demo.py` avec une vraie clé API.

## Assainissement des documents (données personnelles / secrets, section 4.5)

`aegis_core/pii_detector.py` masque, dans chaque document RÉCUPÉRÉ ET NON NEUTRALISÉ, les données qui n'ont rien à faire dans un contexte envoyé à un LLM tiers : emails, IBAN, numéros de carte bancaire, numéros de téléphone français, clés d'API. C'est un troisième signal, indépendant des deux autres (`injection_detector.py`, `rag_outlier_detector.py`) : un document parfaitement légitime peut très bien contenir une donnée sensible laissée par erreur -- ce n'est pas une question de confiance envers le document, mais d'hygiène. Uniquement des règles regex, aucun entraînement nécessaire.

## Manipulation du classement : la faille que la démo exposait sans le dire

Le retrieval de démonstration classait les documents par **nombre brut de mots communs** avec la requête, sans normalisation par la longueur :

```python
scored = [(len(query_tokens & _tokenize(doc.content)), doc) for doc in documents]
```

Un document long a mécaniquement plus de vocabulaire, donc plus de recouvrement avec n'importe quelle requête. Sur les deux documents d'origine, `doc2_poisoned.txt` (113 mots distincts) l'emportait sur `doc1_clean.txt` (73) pour le seul mot « Bonjour ». Ce n'est pas un travers d'affichage — c'est la raison pour laquelle la démonstration jouait toujours la même scène.

**Un attaquant qui ne contrôle que le contenu d'un document contrôle aussi sa sélection.** Mesuré : un document piégé rembourré de vingt-quatre mots de support client remontait en tête sur quatre requêtes sur cinq, y compris sur des sujets qu'il ne traitait pas. AEGIS le neutralise ensuite, donc l'injection ne passe pas — mais l'attaquant a gagné le droit d'**occuper tout le contexte**, et donc d'évincer les documents légitimes. C'est un déni de service sur la pertinence, et c'est le volet « classement » d'OWASP LLM09, distinct du contrôle d'accès à l'index.

### Ce qui a été corrigé, et ce qui ne l'est pas

`victim/rag.py` passe à **BM25** : saturation de la fréquence (`k1`) et normalisation par la longueur (`b`). Répéter un mot dix fois ne vaut plus dix occurrences, et un document deux fois plus long doit être deux fois plus pertinent pour obtenir le même score.

Une mesure intermédiaire mérite d'être racontée, parce qu'elle a failli me faire livrer l'inverse d'un correctif. Sur le corpus d'origine — **deux documents** — BM25 faisait *gagner* l'attaquant 5 requêtes sur 7 là où l'ancien classement lui en faisait gagner 0. À trois documents, l'IDF est dégénérée : tout terme est rare, donc tout terme pèse. La conclusion s'inverse sur un corpus de taille réaliste (14 documents) : BM25 y est meilleur en pertinence (7/10 contre 5/10) et comparable en robustesse. **Mesurer sur un corpus trop petit produit une conclusion fausse avec la même assurance qu'une vraie mesure** — c'est la même erreur que la fuite du jeu de test, sous un autre habit.

Le corpus de démonstration compte donc désormais **quatorze documents légitimes** de registres variés, et les attaques n'y vivent plus : elles sont plantées à la demande par les scénarios, comme un ticket hostile qui arrive.

### Un sixième signal : l'intégrité du classement

`aegis_core/retrieval_integrity.py` détecte les documents fabriqués pour *être récupérés*. Le principe est une régularité du langage : la prose française a une redondance caractéristique, mesurée par le rapport type/token (TTR = mots distincts / mots au total). Un texte écrit pour le classement en sort dans un sens ou dans l'autre.

La bande est **interpolée par longueur** (loi de Heaps — un extrait de 60 mots a mécaniquement un TTR plus haut qu'un extrait de 800), calibrée sur 10 281 mots de prose française réelle du dépôt, 200 fenêtres par taille. Reproductible : `python -m scripts.measure_ttr_envelope`.

| population | TTR | verdict |
|---|---|---|
| 14 documents légitimes du corpus | 0,679 – 0,847 | **0 faux positif** |
| bourrage en profondeur (répétitions) | 0,143 | détecté |
| bourrage en largeur (mots tous distincts) | 1,000 | détecté |
| **bourrage hybride** | **0,535** | **non détecté** |

La dernière ligne est le résultat, pas une note de bas de page. Un attaquant qui a lu ce module mélange les deux techniques : assez de répétitions pour gagner le classement, assez de termes nouveaux pour rester dans la bande. À 437 mots, la prose réelle va de 0,474 à 0,684 — le document est rigoureusement indistinguable. `tests/test_retrieval_integrity.py::test_hybrid_stuffing_evades_detection` **fige cette évasion** : le jour où quelqu'un annonce l'avoir corrigée, le test dira le contraire.

Ce signal est donc **consultatif**, comme le classifieur ML et le détecteur d'outliers : un contrôle contournable par quiconque l'a lu n'a pas à décider seul. La charge utile du document hybride, elle, reste bloquée par les règles déterministes — l'évasion porte sur le classement, pas sur l'injection.

La vraie défense n'est d'ailleurs pas statistique : c'est de faire en sorte que gagner le classement ne donne pas tout le contexte (plafonner la part d'un document unique dans le contexte récupéré). Ce n'est pas fait, et c'est écrit dans les limites connues.

## Le banc de scénarios

```bash
python -m redteam.run_scenarios
python -m redteam.run_scenarios --scenario bourrage-classement-hybride
```

Douze situations jouables, couvrant les cinq points d'interception, **sans aucun appel LLM** — la partie du produit qui décide ne dépend d'aucun service externe, et la démonstration doit pouvoir le montrer.

```
Injection de second ordre
  [OK   ] injection-second-ordre    LLM01  on_tool_result   retour d'outil neutralisé

Manipulation du classement
  [OK   ] bourrage-classement-hybride  LLM09  on_retrieval  document neutralisé

Attaques arrêtées : 10/10    Contrôles bloqués à tort : 0/2    Scénarios non conformes : 0/12
```

Chaque scénario porte sa famille, sa référence OWASP, ce qui devrait se passer et **où regarder** — un banc d'essai qui montre un résultat sans dire quoi observer ne démontre rien. Il vérifie aussi les **signaux**, pas seulement le verdict : un blocage obtenu par le mauvais détecteur est un coup de chance, pas une défense. C'est ce mécanisme qui permet au scénario d'évasion d'affirmer « ce signal ne doit PAS tirer » et de le prouver.

Différence avec `run_redteam` : celui-ci mesure un taux et sert de porte de non-régression ; le banc de scénarios explique. Les deux tournent en CI.

## Comment les chiffres de ce README sont produits

Tous les taux publiés ici viennent d'un jeu de **test**, mesuré une fois, avec un seuil figé avant la mesure. Ça n'a pas toujours été le cas, et la différence n'est pas cosmétique.

### Ce qui n'allait pas (lot 5A)

**Le seuil était calibré sur le jeu de test.** `train_rag_outlier_detector.py` calculait `seuil = moyenne(normaux du jeu d'éval) + 2σ`, puis annonçait le taux de faux positifs *sur ces mêmes normaux*. Un seuil à deux écarts-types laisse par construction ~2 % de l'échantillon au-dessus : sur 30 documents, 0 ou 1. Le « 0 % de faux positifs » ne mesurait pas le détecteur, il décrivait le seuil. Le VAE comportemental faisait pire — `seuil = moyenne + 3σ` sur son propre jeu d'évaluation garantit 0 faux positif à peu près toujours.

**Le coefficient aussi.** Le commentaire du code le disait sans le nommer : « k=2 (pas 3) choisi après comparaison sur le jeu d'évaluation : passe de 33 % à 89 % de rappel ». C'est un hyperparamètre optimisé sur le jeu de test.

**Les jeux se recouvraient.** Documents d'entraînement et d'évaluation sortaient des douze mêmes gabarits remplis au hasard : **4 lignes d'évaluation sur 39 étaient identiques au caractère près** à une ligne d'entraînement, et 12 des 13 gabarits d'évaluation figuraient à l'entraînement.

**Le corpus avait dérivé de son générateur.** `data/rag_corpus_eval.jsonl` contenait 4 payloads empoisonnés là où le générateur en produisait 14 : les chiffres publiés portaient sur un corpus que relancer le script ne reproduisait plus.

**Et les faux positifs comptaient comme des réussites.** Les documents légitimes hors-domaine (note RGPD, doc d'API, planning RH) portaient le label `anomalous`. Les neutraliser était donc comptabilisé dans le « 89 % de rappel ». C'est ce qui expliquait la contradiction que le laboratoire de robustesse montrait depuis le début : 0 % de faux positifs annoncés, et des documents légitimes visiblement neutralisés à l'écran.

### La discipline appliquée

Trois jeux, un rôle chacun, et jamais deux :

| jeu | rôle | ce qu'il ne fait jamais |
|---|---|---|
| `train` | ajuste le modèle | rien d'autre |
| `calibration` | choisit seuils et hyperparamètres | n'est jamais mesuré |
| `test` | produit les chiffres publiés | ne décide de rien |

Le découpage se fait **par gabarit** (`scripts/dataset_split.py`), pas par ligne : deux phrases issues du même patron ne sont pas deux observations indépendantes. La question posée au détecteur change de nature — « reconnais-tu cette phrase ? » devient « généralises-tu à une tournure jamais vue ? ». `assert_no_leakage` refuse tout recouvrement exact et rapporte les quasi-doublons ; les scripts d'entraînement l'appellent avant d'apprendre quoi que ce soit, et la CI vérifie en plus que `data/` correspond toujours à son générateur.

Les seuils ne sortent plus d'une formule dont personne ne connaît le taux : ce sont des **quantiles du jeu de calibration**, dérivés d'une cible explicite (`TARGET_FALSE_POSITIVE_RATE`). « Je tolère au plus 5 % de faux positifs sur des documents légitimes » est une décision d'exploitation ; elle se prend en clair.

### Les intervalles de confiance

Chaque taux est publié avec son intervalle de Wilson à 95 % (`aegis_core/stats.py`) :

```
100% [76%-100%] (12/12)        0% [0%-28%] (0/10)
```

Ces deux lignes disent ce que « 100 % / 0 % » laissait croire faux. Douze succès sur douze restent compatibles avec un système qui échoue une fois sur cinq. L'intervalle ne se resserre pas en améliorant le détecteur : il se resserre en agrandissant le corpus — il faudrait 16 attaques toutes bloquées, ou 33 en tolérant deux ratés, pour garantir statistiquement le seuil de 80 %. `run_redteam` l'affiche à chaque exécution.

Wilson plutôt que l'intervalle normal parce que ce dernier donne `[0 ; 0]` pour 0/10 et `[100 % ; 100 %]` pour 12/12 : il affirme une certitude absolue exactement là où il n'y en a aucune, et c'est le cas le plus fréquent ici. L'implémentation est vérifiée contre `statsmodels` (identique à 1e-6 près, voir `tests/test_stats.py`).

Un intervalle quantifie l'incertitude d'**échantillonnage**. Il ne dit rien du biais de sélection : si les payloads ont été écrits en regardant les règles, l'intervalle sera étroit et le chiffre restera faux. C'est un problème de corpus, pas de statistique.

## Latence

Mesurée par `python -m scripts.benchmark_latency` (300 itérations, 5 de chauffe, conteneur Linux 2 vCPU ; ces chiffres se comparent entre eux, pas dans l'absolu). La dernière colonne rapporte le p95 à un aller-retour LLM de 500 ms.

| point de mesure | p50 | p95 | p99 | part d'un appel LLM |
|---|---|---|---|---|
| règles seules — document court | 0,16 ms | 0,19 ms | 0,23 ms | 0,04 % |
| règles seules — document long (3,6 ko) | 5,9 ms | 6,4 ms | 6,7 ms | 1,3 % |
| **règles seules — document au plafond (100 ko)** | **161 ms** | **167 ms** | **171 ms** | **33 %** |
| `on_prompt` | 0,16 ms | 0,25 ms | 0,28 ms | 0,05 % |
| `on_retrieval` — 1 chunk propre | 0,34 ms | 0,47 ms | 0,52 ms | 0,09 % |
| `on_retrieval` — 1 chunk piégé | 0,48 ms | 0,70 ms | 0,79 ms | 0,14 % |
| `on_tool_call` — autorisé | 1,02 ms | 1,21 ms | 1,35 ms | 0,24 % |
| `on_tool_call` — bloqué | 0,11 ms | 0,17 ms | 0,19 ms | 0,03 % |
| `on_tool_result` | 0,29 ms | 0,35 ms | 0,38 ms | 0,07 % |
| journal d'audit — 1 entrée (hash + signature Ed25519 + pseudonymisation) | 0,08 ms | 0,13 ms | 0,17 ms | 0,03 % |

Sur un parcours normal, le coût d'AEGIS est du bruit devant un appel LLM. **La ligne à retenir est la troisième.** Le scan par règles est linéaire, à environ 1,6 µs par caractère : un document à la taille maximale acceptée (`MAX_SCAN_CHARS = 100 000`) coûte 167 ms de CPU, soit un tiers d'un appel LLM — et la taille d'un document récupéré est contrôlée par celui qui l'a écrit, donc potentiellement par l'attaquant. Dix chunks rembourrés suffisent à consommer 1,7 seconde de CPU avant même le premier appel au modèle. C'est un vecteur d'épuisement de ressources (OWASP LLM06) que la troncature seule ne ferme pas ; il faudrait un budget par requête, qui n'existe pas encore.

Le classifieur ML n'apparaît pas dans ce tableau : il n'était pas entraîné sur la machine de mesure. Le banc ajoute automatiquement les lignes correspondantes quand il l'est, et refuse de publier une ligne « avec ML » alimentée par le mode dégradé.

## Isolation de l'état par session

La fenêtre comportementale (section 4.4) mémorise les cinq dernières actions pour repérer une séquence anormale. Elle était indexée par **nom d'agent** : tous les utilisateurs de `SupportAgent` partageaient la même. Deux conséquences, ni l'une ni l'autre théorique :

- **dilution** — un attaquant fait passer sa séquence sensible pendant que le trafic légitime remplit la fenêtre ; la suite observée par le détecteur n'est celle de personne, donc rien ne ressort ;
- **contamination** — symétriquement, les actions d'un utilisateur font monter le score d'un autre. Un signal qui accuse la mauvaise personne coûte plus cher qu'un signal absent.

La clé est désormais `(tenant, agent, session_id)`, lue dans le contexte de la requête (`aegis_core/session.py`) :

```python
result = agent.handle_request(question, session_id=session, tenant="acme")
guard.on_session_event(agent.name, trace, result.ctx)
```

Quand le contexte ne porte pas de `session_id`, AEGIS **ne l'invente pas** — inventer un identifiant donnerait une isolation apparente et fausse, chaque requête ayant sa propre fenêtre et le détecteur n'observant plus jamais de séquence. La clé est marquée anonyme, un avertissement est émis une fois, et `robustness_report()["session_isolation"]` remonte `degraded: true`. Le comportement dégradé est l'ancien, mais il est *visible* : le tableau de bord affiche « ▲ Partagée » au lieu de laisser croire à une isolation qui n'existe pas.

L'état par session est borné dans les deux dimensions : expiration après `ttl_seconds` d'inactivité (30 min par défaut) et plafond `max_sessions` (10 000) avec éviction de la session la moins récente. La clé venant de données contrôlées par le client, un dictionnaire non borné serait un vecteur d'épuisement de ressources — OWASP LLM06, *Unbounded Consumption* : il suffirait d'envoyer des `session_id` tous différents. Évictions et expirations sont comptées et remontées dans le rapport ; un pic d'évictions est un signal d'exploitation, pas une statistique de fonctionnement normal.

Même principe pour l'état **de requête** : les ids de documents neutralisés vivaient dans un attribut d'instance écrasé à chaque `on_retrieval`. Sous deux requêtes concurrentes, la seconde effaçait celui de la première et la vérification de citation portait sur les documents de quelqu'un d'autre. Ils voyagent désormais dans le `ctx` de la requête.

## Journal d'audit et droit à l'effacement (RGPD art. 17)

Le journal d'audit est immuable par construction — c'est ce qui fait sa valeur de preuve. Il journalisait aussi les paramètres d'outils **en clair** : adresses email, corps de messages, identifiants clients. Un registre immuable rempli de données personnelles est en tension directe avec le droit à l'effacement : on ne peut pas supprimer une entrée sans casser la chaîne, donc sans détruire la preuve, et on ne peut pas conserver la donnée sans manquer à l'obligation. C'est la première question que pose le DPO d'un client, et elle n'a pas de bonne réponse une fois le système en production : ça se conçoit au début, ça se rétrofitte très mal.

La séparation (`aegis_core/personal_data.py`) : le journal ne contient plus que des **jetons** — `[EMAIL:pd_3f9a…]` à la place de `m.durand@example.com` —, calculés en HMAC-SHA256 sous une clé dédiée. Les valeurs vivent dans un **coffre séparé** (`PersonalDataVault`, une base distincte), effaçable ligne par ligne.

```
{'type': 'tool_call', 'tool': 'send_email',
 'params': {'to': '[EMAIL:pd_dc4361a918f497c8]', 'body': 'IBAN [IBAN:pd_03637d913f09be9f]'},
 'decision': 'block', ...}
```

La pseudonymisation a lieu **avant** le calcul du hash : la chaîne ne couvre donc jamais que des jetons. Effacer une personne consiste à supprimer ses valeurs du coffre, ce qui ne touche pas une seule entrée du journal — les deux propriétés qui semblaient s'exclure tiennent ensemble :

```python
vault.erase_value("m.durand@example.com")   # 1 valeur effacée
log.verify_integrity().ok                   # True — la preuve survit
```

Le jeton est déterministe (même valeur → même jeton), ce qui permet de corréler des événements sans jamais lire la donnée, et c'est aussi ce qui rend l'effacement possible : on retrouve toutes les occurrences d'une personne à partir de sa valeur.

Configuration : `AEGIS_PERSONAL_DATA_KEY`. Sans elle, une clé éphémère est tirée et un WARNING l'annonce — les jetons ne sont alors pas stables d'une exécution à l'autre, et un effacement ne retrouve pas les occurrences passées. La pseudonymisation est **active par défaut** ; `AuditLog(pseudonymizer=False)` la désactive, avec un avertissement explicite.

Deux limites assumées. Un jeton déterministe reste vulnérable à une attaque par dictionnaire si la clé HMAC fuite (l'espace des adresses email est petit) : la clé doit être traitée comme la clé de signature, idéalement dans un KMS et pas sur le disque à côté du coffre. Et une donnée personnelle qu'aucun motif de `PII_PATTERNS` ne reconnaît — un identifiant métier, un nom propre — passe en clair : c'est la limite du détecteur regex, la même que pour l'assainissement des documents.

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

**Sur une machine où le classifieur ML est entraîné, le tableau change.** Les règles restent à 100 % [76 %-100 %] / 0 % [0 %-28 %], mais l'ensemble tombe à **50 % [24 %-76 %] de faux positifs** — cinq documents légitimes sur dix signalés à tort, tous par le classifieur (`matched_rules` vide, `ml_score` entre 0,95 et 0,99). `run_redteam` affiche désormais les deux configurations côte à côte, précisément pour que ce coût soit visible :

```
Détail par détecteur, pris isolément :
  Règles seules      blocage  100% [76%-100%] (12/12)   faux positifs   0% [0%-28%] (0/10)
  Règles + ML        blocage  100% [76%-100%] (12/12)   faux positifs  50% [24%-76%] (5/10)
  --> Les faux positifs viennent du classifieur ML, pas des règles.
```

Conséquence pratique : `InjectionDetector(use_ml=False)` est un mode de déploiement légitime, pas seulement une commodité de test. La couche de règles est déterministe, explicable et mesurée ; le classifieur, dans son état actuel, coûte plus qu'il ne rapporte sur du texte hors de son registre d'entraînement.

**La porte CI vérifie les deux bouts.** Un seuil de blocage seul se satisfait d'un détecteur qui bloque tout : 100 % de recall, 100 % de faux positifs, exit 0. `MAX_FALSE_POSITIVE_RATE` (0,20) ferme cette porte. C'est un **cliquet** calé au-dessus de la mesure du jour, pas une cible — il est là pour empêcher que ça empire.

**Ce corpus est trop petit, et le rapport le dit maintenant lui-même.** Douze attaques, dix contrôles : « 100 % de blocage » signifie en réalité *[76 % ; 100 %]*. `run_redteam` affiche à chaque exécution ce qu'il faudrait pour trancher — 16 attaques toutes bloquées, ou 33 en tolérant deux ratés, pour garantir statistiquement le plancher de 80 %. Un vrai benchmark demande des centaines de cas issus de corpus publics (AgentDojo, garak, PyRIT, `deepset/prompt-injections`) : c'est le chantier suivant, et tant qu'il n'est pas fait, le « Robustness Score » se lit comme un garde-fou de non-régression, pas comme une mesure de robustesse.

### Classifieur ML d'injection (section 4.2)

Le classifieur ML (DistilBERT multilingue fine-tuné) apprend une corrélation de surface : le ton formel/impératif en français est associé au risque d'injection, car le corpus d'entraînement synthétique n'a exposé le modèle qu'à des messages client conversationnels comme exemples bénins -- jamais à du texte formel bénin (RGPD, documentation technique, notes internes).

Mesure empirique (corpus de red-teaming, 10 contrôles bénins variés) :

| population | faux positifs |
|---|---|
| registre « support client » (le cas d'usage réel de l'agent) | **0 % [0 %-43 %]** (0/5) |
| hors registre (RGPD, doc API, rapports, RH) | **100 % [57 %-100 %]** (5/5) |
| ensemble | **50 % [24 %-76 %]** (5/10) |

Cinq contrôles par population : les intervalles sont énormes et il faut le lire ainsi. Ce que la mesure établit, c'est l'**écart** entre les deux registres, pas la valeur précise de chacun.

**Un défaut de méthode subsiste sur ce détecteur, et il n'est pas encore corrigé.** `train_injection_classifier.py` découpe train/test *par ligne* (`train_test_split(test_size=0.1)`). Or les 261 exemples français viennent de 13 appels LLM, un par style d'attaque ou thème bénin : vingt exemples issus d'une même consigne ne sont pas vingt observations indépendantes. Un découpage aléatoire place donc des tournures du même moule des deux côtés de la cloison, et la précision/rappel publiés par le script sont optimistes d'une marge inconnue.

Le préalable est posé — `generate_french_examples.py` enregistre désormais le `group` (style ou thème) de chaque exemple, ce qui rend un découpage par groupe possible. Le corpus versionné, lui, a été produit avant ce changement et ne porte pas de groupe : il faut le régénérer (une clé OpenRouter est nécessaire) avant que le correctif puisse être appliqué au script d'entraînement. C'est écrit ici plutôt que corrigé à moitié — un split par groupe branché sur un corpus sans groupes retomberait silencieusement sur un split par ligne, ce qui serait pire que l'état actuel puisque le README affirmerait le contraire.

Conclusion : le classifieur est fiable dans son domaine d'entraînement, mais ne généralise pas hors de ce registre. Trois cycles d'entraînement ciblés (modèle multilingue, ajout d'exemples français, diversification du registre) ont été tentés ; chacun a soit échoué à corriger le biais, soit dégradé la performance globale -- signe que le vrai correctif nécessite un volume de données d'entraînement bien supérieur à l'échelle de ce projet, pas un ajustement ponctuel. Piste retenue pour la Phase 2.1 : élargir le corpus d'entraînement à la diversité de registre réelle des documents RAG ciblés, ou pondérer le score ML comme signal d'aide à la décision plutôt que comme déclencheur de blocage automatique isolé.

### Détecteur d'anomalies comportementales (section 4.4)

Le Beta-VAE encode une session comme 5 événements traités indépendamment. Un premier entraînement, où chaque position de la session était tirée sans aucune contrainte sur le total, a produit un modèle incapable de détecter le cas "5 clôtures de ticket d'affilée" : chaque clôture prise isolément est un événement fréquent et banal à l'entraînement, donc rien ne signalait qu'une répétition inhabituelle sur toute la session soit suspecte. Correction appliquée : les sessions normales d'entraînement plafonnent désormais à 2 clôtures sur 5, forçant le modèle à apprendre cette régularité de fréquence.

Mesure sur le jeu de **test** (320 sessions : 200 normales, 120 anormales en 3 catégories), seuil calibré au préalable sur 200 sessions normales distinctes, cible 2 % de faux positifs :

| catégorie | mesure |
|---|---|
| rafale d'outils sensibles mêlés | rappel **100 % [91 %-100 %]** (40/40) |
| clôtures de tickets en rafale | rappel **100 % [91 %-100 %]** (40/40) |
| virement isolé (hijack) | rappel **88 % [74 %-95 %]** (35/40) |
| toutes anomalies | rappel **96 % [91 %-98 %]** (115/120) |
| sessions normales | faux positifs **2 % [1 %-4 %]** (3/200) |

Ces chiffres sont meilleurs que ceux publiés auparavant (« 45 % de rappel sur les cas de fréquence, 0 % de faux positifs »), et il faut dire pourquoi : l'ancien seuil était calculé sur le jeu d'évaluation lui-même, à trois écarts-types, ce qui le plaçait très haut — d'où le rappel médiocre ET le « 0 % » de faux positifs, deux conséquences du même artefact. Calibré à 2 % de faux positifs sur un jeu distinct, le même modèle attrape presque tout. Le gain vient de la méthode de mesure, pas d'un changement du modèle.

Le rappel reste imparfait sur le virement isolé, et c'est cohérent : un virement unique noyé dans quatre actions banales ressemble davantage à une session normale qu'une rafale. Le Policy Engine le bloque de toute façon en amont — le VAE est ici une couche de secours indépendante, pas la barrière principale. `on_session_event` journalise un score et ne bloque rien : à 2 % de faux positifs, bloquer reviendrait à refuser une session légitime sur cinquante.

### Détecteur d'outliers RAG (section 4.5)

Simplification assumée dès la conception : TF-IDF (comptage de mots pondéré) plutôt que de vrais embeddings de phrases (sentence-transformers, prévu section 5 du blueprint) -- une notion de "sens" plus grossière, mais qui ne nécessite aucun téléchargement de modèle et reste entièrement testable sans accès réseau.

Mesure sur le jeu de **test** (92 documents : 72 normaux du domaine, 6 légitimes hors-domaine, 14 attaques), seuil calibré sur 78 documents légitimes distincts, cible 5 % de faux positifs :

| population | mesure |
|---|---|
| attaques | rappel **86 % [60 %-96 %]** (12/14) |
| documents du domaine | faux positifs **0 % [0 %-5 %]** (0/72) |
| **documents légitimes hors-domaine** | faux positifs **50 % [19 %-81 %]** (3/6) |
| tous documents légitimes | faux positifs **4 % [1 %-11 %]** (3/78) |

**La troisième ligne est le vrai constat.** Ce détecteur mesure un écart de registre, pas une attaque : il signale la moitié des documents parfaitement légitimes qui ne relèvent pas du support client — un texte universitaire, une note logistique. C'est structurel, pas un réglage à affiner : un centroïde TF-IDF appris sur un seul domaine ne peut rien dire d'autre que « ceci ne ressemble pas à ce que j'ai vu ».

Ce constat était auparavant inversé dans le corpus lui-même : ces documents portaient le label `anomalous`, donc les neutraliser comptait comme une réussite et gonflait le « 89 % de rappel » annoncé. Corrigé au lot 5A — ils portent désormais le label `normal`, et entrent dans la calibration du seuil, ce qui l'a d'ailleurs remonté (la mention RGPD qui servait d'exemple n'est plus signalée).

C'est précisément pourquoi ce signal n'a pas le droit de bloquer seul (`AegisConfig.blocking_signals`). Il tire, il est journalisé, il alimente `would_have_blocked` — et le pipeline complet affiche 0 % de faux positifs là où ce détecteur seul en affiche 50 % sur le hors-domaine.

Conséquence visible dans le laboratoire de robustesse du dashboard (`/api/test-document`) : certains documents légitimes du corpus de red-teaming (bulletin météo, rapport financier) ressortent comme signalés par ce détecteur. C'est bien un faux positif — neutraliser un bulletin météo prive le client d'une réponse à laquelle il avait droit — et c'est l'illustration directe de la ligne ci-dessus.

### Citation obligatoire de la source (section 4.5)

Ce mécanisme dépend entièrement du LLM configuré pour suivre l'instruction du system prompt -- contrairement aux trois détecteurs ML, il n'y a rien à entraîner ni à mesurer hors ligne : sa fiabilité doit être vérifiée avec un vrai modèle (voir `demo.py`). Un modèle qui ignore l'instruction de citation rendrait ce signal muet (aucune citation à vérifier), sans pour autant désactiver les trois autres couches de protection.

Cas limite découvert en conditions réelles (première exécution de `demo.py` avec une vraie clé API) : quand `on_retrieval` neutralise le seul document récupéré (injection détectée), le LLM ne reçoit jamais le vrai contenu -- seulement le message `[CONTENU NEUTRALISÉ PAR AEGIS...]`. Il répond alors honnêtement `[source: aucune]`, ce qui est la bonne réponse, pas une source manquante. La première version de `on_response` comptait quand même ce cas comme `missing_citations` (elle ne comparait `cited` qu'à la liste brute `doc_ids`). Corrigé en faisant déposer par `on_retrieval` les ids neutralisés **dans le contexte de la requête** (`ctx["_aegis_neutralized_ids"]`), que `on_response` relit pour les retirer de `doc_ids` avant de juger la citation -- un document neutralisé ne compte plus comme une source que le LLM aurait pu citer. Un vrai document non neutralisé mais non cité reste, lui, correctement signalé (voir `tests/test_middleware.py`).

### Isolation par session (lot 4B)

L'isolation ne vaut que si l'orchestrateur fournit un `session_id`. AEGIS ne peut pas le déduire : sans lui, la fenêtre reste partagée entre tous les appelants du même agent. La seule chose qu'AEGIS garantit, c'est de le **dire** (`session_isolation.degraded`) plutôt que de laisser croire à une isolation qui n'existe pas.

Le plafond de sessions protège la mémoire, pas la détection : sous une charge d'identifiants jetables, les sessions légitimes les moins récentes sont évincées et leur fenêtre comportementale repart à zéro. Un attaquant qui sait cela peut donc, au prix d'un trafic soutenu, effacer la mémoire comportementale d'une session ciblée — le pic d'évictions est compté et remonté, mais rien ne le bloque aujourd'hui. Une limitation de débit par locataire (LLM06) est le vrai correctif ; elle n'existe pas encore.

Enfin, l'isolation porte sur l'état comportemental et l'état de requête. L'index RAG, lui, reste commun à tous les locataires (voir LLM09).

### Manipulation du classement (lot 6)

Trois limites, toutes mesurées.

**L'évasion hybride n'est pas couverte.** Détaillée plus haut : un bourrage qui mélange répétition et vocabulaire neuf reste dans la bande du français réel. Le test qui la fige est `test_hybrid_stuffing_evades_detection`.

**BM25 reste un sac de mots.** Un attaquant qui anticipe la requête exacte et rembourre avec ses mots peut encore remonter. La mesure retenue n'est d'ailleurs pas « l'attaquant ne gagne jamais » mais « il ne gagne pas toutes les requêtes » — c'est ce que le test vérifie, parce que c'est ce qui est vrai.

**Le contexte n'est pas plafonné.** La défense de fond contre la manipulation de classement n'est pas de détecter le bourrage, c'est de faire en sorte que gagner le premier rang ne donne pas la totalité du contexte : récupérer plusieurs documents et borner la part de chacun. `victim/agent.py` récupère toujours `top_k=1`. Tant que c'est le cas, un attaquant qui gagne le classement gagne tout le contexte, détecté ou non.

### Assainissement des documents / PII (section 4.5)

Uniquement des règles regex (comme la V0 du détecteur d'injection) : rapide et explicable, mais ça manque forcément ce qu'un regex ne peut pas anticiper par construction -- une donnée déguisée (espaces insérés dans un numéro de carte, IBAN écrit avec des mots), un format non couvert (numéro de téléphone étranger hors format français), ou un identifiant sensible métier qui ne ressemble à aucun des motifs codés en dur (`PII_PATTERNS` dans `aegis_core/pii_detector.py`). Un classifieur ML entraîné sur des exemples annotés (type NER pour données personnelles) généraliserait mieux, au prix d'un entraînement -- même compromis que la V0 du détecteur d'injection avant sa Phase 2. Le motif "carte bancaire" (13 à 16 chiffres consécutifs) peut aussi produire un faux positif sur une longue suite de chiffres qui n'est pas une carte (ex. un identifiant de commande à 14 chiffres) -- assumé : mieux vaut masquer par excès dans ce cas précis qu'oublier une vraie donnée sensible.

## Couverture OWASP GenAI LLM Top 10 — édition 2026

L'édition 2026 est parue le 6 août 2026. Sa méthodologie combine le vote d'experts (75 %) et l'analyse de 7 714 incidents réels (25 %), ce qui a redistribué le classement : *Excessive Agency* passe 6ᵉ → **3ᵉ**, *Unbounded Consumption* 10ᵉ → **6ᵉ**, *System Prompt Leakage* est élargi et renommé *Hidden Context Exposure*.

Le tableau ci-dessous est une évaluation honnête de ce qui est réellement couvert. Il n'y a **aucun ✅** : aucune catégorie n'est traitée de bout en bout, et prétendre le contraire serait le genre d'écart promesse/réalité que ce projet a précisément vocation à mesurer chez les autres.

| # | Risque 2026 | Couverture | Ce qui manque |
|---|---|---|---|
| LLM01 | Prompt Injection *(étendu au cross-modal)* | ⚠️ partielle | Directe (requête), indirecte (documents) et de second ordre (retours d'outils) désormais scannées, sur les vues normalisées (Unicode, encodage, balisage). Reste : règles francophones, contournables par l'anglais ; rien en cross-modal. |
| LLM02 | Sensitive Information Disclosure | ⚠️ entrée et journal | PII masquée dans les documents récupérés ; journal d'audit pseudonymisé avec coffre séparé et effaçable (RGPD art. 17). **Aucun filtre de sortie.** |
| LLM03 | **Excessive Agency** *(6ᵉ → 3ᵉ)* | ⚠️ partielle | Allow-list deny-by-default : la bonne base, et l'atout principal du projet. Manque : `sensitive_tools` sans effet, plafond de montant contournable par typage, pas de liste blanche de destinataires, pas de validation humaine, pas de quota. |
| LLM04 | Supply Chain *(3ᵉ → 4ᵉ)* | ⚠️ partielle | Plus de chargement pickle, dépendances figées, artefacts vérifiés par SHA-256. Manque : SBOM, signature du bundle de modèles, provenance. |
| LLM05 | Data and Model Poisoning | ⚠️ partielle | Détection d'outliers à la récupération. Rien à l'indexation, aucune provenance ni signature de document. |
| LLM06 | **Unbounded Consumption** *(10ᵉ → 6ᵉ)* | 🔴 quasi absente | Seul l'état par session est borné (expiration + plafond avec éviction), ce qui ferme un vecteur : des `session_id` jetables ne font plus croître la mémoire sans limite. Manque tout le reste : budget de jetons, plafond de coût, limitation de débit, borne sur les boucles d'agent. Les endpoints de démo déclenchent de vrais appels LLM sans authentification. |
| LLM07 | Misinformation *(9ᵉ → 7ᵉ)* | ⚠️ amorce | La vérification de citation est la bonne intuition. Manque la vérification d'ancrage : la réponse est-elle réellement *soutenue* par la source citée ? |
| LLM08 | **Hidden Context Exposure** *(ex-System Prompt Leakage)* | 🔴 absente | Rien ne détecte que le modèle restitue son prompt système. |
| LLM09 | Vector and Embedding Weaknesses | ⚠️ partielle | Détection d'outliers TF-IDF, classement BM25 (longueur normalisée) et détection de bourrage de classement — **évasion hybride mesurée et non couverte**. L'état comportemental est isolé par `(tenant, agent, session)`, mais **l'index ne l'est pas** : pas de contrôle d'accès, pas de partition par locataire, pas de plafond sur la part d'un document dans le contexte. |
| LLM10 | Improper Output Handling *(5ᵉ → 10ᵉ)* | 🔴 absente | Les retours d'outils et la réponse finale traversent sans validation. Le frontend échappe correctement (React, pas de `dangerouslySetInnerHTML`), mais c'est le seul rempart et il est côté client. |

Note de lecture : les identifiants utilisés jusqu'ici dans `redteam/payloads.py` étaient ceux de l'édition **2023** sous un en-tête « 2025 » (`LLM06 Sensitive Information Disclosure`, `LLM08 Excessive Agency`). Corrigé — voir la table de correspondance en tête de ce fichier.

## État par rapport au blueprint complet

| Module | Statut |
|---|---|
| Policy Engine & Tool Sandbox | ✅ V0 (allow-list Python) |
| Analyse de la requête utilisateur (`on_prompt`) | ✅ Lot 3C — règles bloquantes, ML observé |
| Analyse des retours d'outils (`on_tool_result`) | ✅ Lot 3C — neutralisation + masquage PII |
| Détection d'injection | ✅ V0 heuristique (regex) + Phase 2 ML (DistilBERT multilingue fine-tuné, ensemble regex+ML) -- voir "Limites connues" |
| Journal d'audit signé | ✅ SQLite + chaînage SHA-256 + signatures Ed25519 par entrée, triggers SQLite append-only, pseudonymisation et coffre effaçable (RGPD art. 17) -- Postgres en V1 |
| Discipline de mesure | ✅ Lot 5A — split train/calibration/test par gabarit, détection de fuite bloquante, seuils calibrés hors du test, intervalles de Wilson, latences publiées |
| Intégrité du classement | ✅ Lot 6 — BM25, corpus de 14 documents, détection de bourrage (évasion hybride figée par un test) |
| Banc de scénarios | ✅ Lot 6 — 12 scénarios sur 5 points d'interception, vérification des signaux et pas seulement du verdict |
| Isolation de l'état par session | ✅ Lot 4B — clé `(tenant, agent, session_id)`, bornée en taille et dans le temps, dégradation déclarée |
| Détection d'anomalies comportementales (VAE) | ✅ Phase 2 (Beta-VAE, détection partielle sur cas limites -- voir "Limites connues") |
| Durcissement RAG (filtre PII/secrets, outliers embeddings) | ✅ Phase 3 : outliers d'embeddings (TF-IDF, voir limites) + citation obligatoire + assainissement PII/secrets par regex (voir limites) |
| Red-teaming automatisé | ✅ V0 fonctionnelle, corpus enrichi (10 contrôles bénins diversifiés), taux publiés avec intervalle de confiance -- corpus encore trop petit pour conclure (voir limites) |
| Dashboard SOC | ✅ V1 (dashboard Next.js interactif, comparaison protégé/non-protégé) -- alerting et historique en Phase 5 |

## En une phrase

AEGIS est une couche de sécurité qui s'intercale entre un agent IA et le monde extérieur (données récupérées, outils) : elle détecte et neutralise les instructions cachées avant qu'elles n'atteignent le modèle, applique le principe du moindre privilège sur les actions, repère les comportements d'agent statistiquement anormaux, et garde de chaque décision une trace signée qu'un tiers peut vérifier sans pouvoir la falsifier.
