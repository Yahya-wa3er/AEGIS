# Les composants, un par un

Douze composants, chacun répondant à une question de sécurité précise. Aperçu d'abord — détail de chaque mécanisme ensuite, avec le raisonnement et les chiffres mesurés dans un encart séparé, et la mécanique interne repliée par défaut pour qui veut d'abord la vue d'ensemble.

| Composant | Rôle | Fichier |
|---|---|---|
| [Détection d'injection](#detection-dinjection-regles-classifieur-ml) | <span class="aegis-badge aegis-badge--mixed">mixte</span> règles bloquantes + ML consultatif | `injection_detector.py` |
| [Outliers sémantiques RAG](#detecteur-doutliers-semantiques-rag) | <span class="aegis-badge aegis-badge--advisory">consultatif</span> | `rag_outlier_detector.py` |
| [Intégrité du classement](#integrite-du-classement) | <span class="aegis-badge aegis-badge--advisory">consultatif</span> | `retrieval_integrity.py` |
| [Classement BM25](#le-classement-lui-meme-bm25) | <span class="aegis-badge aegis-badge--block">déterministe</span> | `victim/rag.py` |
| [Détecteur comportemental (Beta-VAE)](#detecteur-comportemental-beta-vae) | <span class="aegis-badge aegis-badge--advisory">consultatif</span> | `behavior_detector.py` |
| [Policy Engine](#policy-engine) | <span class="aegis-badge aegis-badge--block">bloquant</span> | `policy_engine.py` |
| [Protection des données](#protection-des-donnees) | <span class="aegis-badge aegis-badge--mixed">mixte</span> | `pii_detector.py`, `output_guard.py` |
| [Vérification d'ancrage](#verification-dancrage-et-assistant-de-securite) | <span class="aegis-badge aegis-badge--mixed">mixte</span> | `grounding.py` |
| [Journal d'audit signé](#journal-daudit-signe) | <span class="aegis-badge aegis-badge--block">preuve cryptographique</span> | `audit_log.py`, `signing.py` |
| [Isolation par session](#isolation-par-session) | <span class="aegis-badge aegis-badge--block">déterministe</span> | `session.py` |
| [Limitation de consommation](#limitation-de-consommation) | <span class="aegis-badge aegis-badge--block">déterministe</span> | `web/ratelimit.py` |
| [Filtre de sortie](#filtre-de-sortie-le-composant-le-plus-recent) | <span class="aegis-badge aegis-badge--mixed">mixte</span> | `output_guard.py` |

---

## Détection d'injection — règles + classifieur ML

`aegis_core/injection_detector.py` — Deux couches indépendantes, combinées par OR sur le drapeau et MAX sur le score de risque : une couche de **règles** qui peut bloquer seule, une couche de **ML** qui ne le peut pas.

La première couche est un jeu de règles regex bilingues (français/anglais), organisées par famille d'attaque : neutralisation d'instructions (« ignore les consignes précédentes »), fausse autorité système, changement de rôle, injonction d'agir immédiatement, exfiltration de configuration, dissimulation d'instruction. C'est la seule couche du projet qui a, par défaut, le droit de bloquer seule.

!!! example "Chiffre mesuré"
    100 % de blocage des attaques connues du corpus de contrôle, pour 0 % de faux positifs — d'où le droit de bloquer seule.

??? note "Mécanisme en détail — normalisation et méta-règle d'évasion"
    Un regex ne voit que l'orthographe qu'on a prévue. Avant toute comparaison, le texte passe par `aegis_core/normalization.py`, qui produit plusieurs **vues** du même document : la forme canonique (accents normalisés, caractères invisibles retirés — largeurs nulles, marques de direction bidi, sélecteurs de variante —, homoglyphes cyrilliques et grecs ramenés au latin), une vue « dé-leetée » (`1gn0r3` → `ignore`, appliquée séparément pour ne jamais écraser la forme canonique et éviter qu'un mot comme `R2D2` ne devienne un faux positif), le contenu décodé des blocs base64, et le texte dissimulé dans des commentaires de balisage. Chaque règle est évaluée sur chaque vue.

    Quand une règle ne se déclenche que sur une vue *dérivée* et pas sur le texte brut, une méta-règle d'évasion s'ajoute automatiquement — le fait qu'une instruction ait été dissimulée est un signal en soi, souvent plus fiable que l'instruction elle-même, parce qu'un texte innocent ne s'obfusque jamais.

    La deuxième couche est un **DistilBERT fine-tuné** sur le jeu de données public `deepset/prompt-injections`, dont le rôle est de généraliser à des formulations que les règles ne peuvent pas anticiper par construction (une paraphrase, par exemple). Le score ML est le **maximum** sur des fenêtres glissantes de 1000 caractères avec 250 de recouvrement (jusqu'à 16 fenêtres), et non une moyenne, ni les seuls 256 premiers tokens : un correctif a montré qu'il suffisait de faire précéder l'injection de deux pages de texte anodin pour la faire sortir de la fenêtre analysée par le classifieur.

    `torch` et `transformers` sont des dépendances **optionnelles**, chargées dans un `try/except ImportError` : un déploiement qui n'a besoin que des règles, du Policy Engine et du journal d'audit n'a aucune raison d'embarquer les ~800 Mo de poids du modèle.

!!! danger "Pourquoi le ML reste consultatif"
    Mesurée sur le corpus de contrôle, cette couche signale un document légitime sur deux dans certains registres (rapport financier, bulletin météo, documentation d'API) — lui donner un droit de blocage causerait plus de dégâts que les attaques qu'elle est censée arrêter. Le score est journalisé même quand il ne bloque rien (`would_have_blocked`), pour qu'un corpus plus large puisse un jour justifier, sur des chiffres, de lui rendre un pouvoir de blocage.

## Détecteur d'outliers sémantiques RAG

`aegis_core/rag_outlier_detector.py` — Répond à une question différente des règles : pas « y a-t-il un motif d'attaque connu ? » mais « ce document ressemble-t-il, sémantiquement, à ce que l'agent voit d'habitude ? ».

Un vectoriseur TF-IDF transforme le texte en vecteur, on mesure sa similarité cosinus au centroïde du corpus documentaire normal appris à l'entraînement, et la distance est écrasée dans [0, 1) pour rester sur la même échelle de risque que les autres détecteurs. Purement consultatif.

!!! danger "Limite mesurée"
    Le détecteur confond aujourd'hui « hors du domaine habituel » avec « attaque » : un document légitime mais dans un registre différent (technique, juridique) se fait signaler à peu près autant qu'un vrai document empoisonné (**50 %** de faux positifs hors domaine, contre **4 %** sur les documents légitimes du domaine).

??? note "Mécanisme en détail — pourquoi ce module ne charge plus de pickle"
    Détail d'implémentation qui compte pour la [chaîne d'approvisionnement](chaine-approvisionnement.md) : ce module **ne charge plus** de `vectorizer.joblib`. `joblib.load()` désérialise du pickle — donc **exécute le contenu du fichier** — et quiconque peut écrire dans `models/` obtenait ainsi l'exécution de code dans le processus AEGIS. Le vectoriseur est désormais stocké en données pures (vocabulaire en JSON, IDF et centroïde en `.npz` avec `allow_pickle=False`), et la transformation TF-IDF est **réimplémentée** à la main en une vingtaine de lignes, strictement équivalente à `TfidfVectorizer` de scikit-learn pour les paramètres utilisés — équivalence vérifiée à chaque entraînement par le script d'entraînement, qui refuse d'écrire les artefacts si les scores divergent. Effet de bord bienvenu : scikit-learn n'est plus nécessaire à l'exécution, seulement à l'entraînement.

## Intégrité du classement

`aegis_core/retrieval_integrity.py` — Détecte un document *fabriqué pour être récupéré*, indépendamment de son contenu sémantique.

La régularité exploitée : le rapport type/token (TTR = mots distincts / mots totaux) d'une prose française réelle tient dans une bande étroite, dépendante de la longueur (loi de Heaps). Un bourrage « en profondeur » (répéter les mots de la requête) fait chuter le TTR sous la bande ; un bourrage « en largeur » (empiler des mots tous différents) le pousse vers 1,0, ce qu'aucune prose n'atteint. Déterministe, mais délibérément consultatif.

!!! danger "Évasion testée et figée volontairement"
    Le README et les tests documentent un bourrage **hybride**, qui mélange les deux techniques et reste rigoureusement indiscernable de la vraie prose à isométrie de longueur (TTR mesuré à 0,535 pour 437 mots, quand la prose réelle de même longueur va de 0,474 à 0,684). `tests/test_retrieval_integrity.py::test_hybrid_stuffing_evades_detection` **fige cette évasion** explicitement : le jour où quelqu'un annoncera l'avoir corrigée, le test dira le contraire tant que le code n'aura pas changé.

## Le classement lui-même — BM25

`victim/rag.py` — Le retrieval initial classait les documents par nombre brut de mots communs avec la requête, sans normalisation par la longueur.

!!! example "Chiffre mesuré — la faille d'origine"
    Un document piégé de 113 mots distincts l'emportait sur un document légitime de 73 mots pour le seul mot « Bonjour ».

BM25 corrige ça par saturation de fréquence (`k1`) et normalisation par longueur (`b`). Ces deux corrections seules ne suffisaient pas : mesuré, BM25 seul laissait un attaquant remonter en tête sur 3 requêtes sur 40, contre 0 pour l'ancien classement — la saturation freine la répétition, elle ne la borne pas.

??? note "Le troisième garde-fou — le plafond de fréquence"
    D'où un troisième garde-fou mesuré et retenu : un **plafond de fréquence** à deux occurrences par terme, au-delà duquel les répétitions supplémentaires ne comptent plus. Résultat retenu : 8/10 de pertinence (contre 5/10 pour l'ancien classement) et 1/40 de bourrages réussis (contre 3/40 pour BM25 sans plafond). L'ancien classement (`overlap_score`) reste disponible dans le code, documenté comme vulnérable, pour rejouer l'attaque à la demande plutôt que la décrire dans un changelog.

## Détecteur comportemental — Beta-VAE

`aegis_core/behavior_detector.py`, `behavior_features.py` — Seul composant purement ML du projet : il n'existe pas de règle équivalente pour dire qu'une *séquence* d'actions est statistiquement inhabituelle.

??? note "Architecture du réseau"
    Un encodeur feedforward (`Linear → ReLU`) produit une moyenne et une log-variance, un vecteur latent est échantillonné par reparamétrisation (`mu + eps·exp(0.5·logvar)`), et un décodeur feedforward (`Linear → ReLU → Linear → Sigmoid`) tente de reconstruire le vecteur d'entrée — 4 dimensions latentes, 16 dimensions cachées, entrée encodant une fenêtre de 5 événements (one-hot de l'action + montant normalisé, toutes les features dans [0, 1]). La perte d'entraînement est `reconstruction_MSE + beta · divergence_KL`, moyennée sur le batch — le « Beta » du Beta-VAE pondère la régularisation de l'espace latent par rapport à la fidélité de reconstruction.

    À l'inférence, la fenêtre récente d'événements d'une session est encodée, passée dans le VAE complet, et l'**erreur de reconstruction** (MSE brute, non bornée) devient le signal : un enchaînement d'actions jamais observé à l'entraînement se reconstruit mal, donc l'erreur monte. Elle est ensuite écrasée dans [0, 1) par la même transformation exponentielle que le détecteur d'outliers RAG.

C'est un détecteur d'anomalies **non supervisé** (pas un classifieur), capable de repérer des séquences inédites sans exemples d'attaque étiquetés — mais structurellement consultatif, puisqu'une erreur de reconstruction élevée n'explique jamais *pourquoi* elle l'est.

!!! tip "Chargement des poids"
    `torch.load(..., weights_only=True)` explicitement, jamais par défaut — même logique anti-désérialisation-de-code que pour le vectoriseur TF-IDF (voir [Chaîne d'approvisionnement](chaine-approvisionnement.md)).

## Policy Engine

`aegis_core/policy_engine.py` — Le composant le plus solide du projet, et le seul qui gouverne des **actions** plutôt que du texte — cohérent avec le fait qu'OWASP a fait monter *Excessive Agency* à la 3ᵉ place mondiale en 2026, sur la base de 7 714 incidents réels.

Allow-list stricte, deny-by-default : un outil non explicitement listé dans `allowed_tools` est refusé. Entièrement déterministe, sans aucun ML : ce qu'on peut décider par une règle explicite, ce projet ne l'apprend pas.

!!! bug "Bug réel trouvé et corrigé"
    Un montant est converti en `float` de façon défensive — un booléen est explicitement exclu (`isinstance(True, int)` vaut `True` en Python, et `True > 1000.0` vaut `False`, donc un booléen contournait silencieusement un plafond numérique avant correction), et tout type qu'on ne sait pas interpréter est **bloqué**, jamais ignoré.

??? note "Schémas, allow-lists de paramètres et outils sensibles"
    Un `tool_schemas` (JSON Schema par outil) valide la forme des paramètres avant exécution ; un `param_allowlists` peut contraindre non seulement quel outil s'appelle mais la valeur exacte de certains paramètres (le destinataire d'un email, par exemple — contraindre l'outil sans contraindre sa cible ne sert à rien pour un outil qui envoie des données vers l'extérieur). Un outil marqué `sensitive_tools`, même autorisé, reste **bloqué par défaut** tant qu'aucun `approval_hook` de validation externe n'est branché — un défaut fail-closed assumé.

## Protection des données

Deux composants distincts, avec des politiques délibérément différentes selon le sens du flux.

=== "Documents entrants"

    `aegis_core/pii_detector.py` assainit les documents **récupérés** avant qu'ils n'entrent dans le contexte du modèle : emails, IBAN, cartes bancaires, téléphones français, clés d'API — uniquement du regex, aucun ML, aucune dépendance.

    !!! bug "Bug réel trouvé et corrigé (lot 10)"
        Les cartes bancaires sont désormais validées par une somme de contrôle de **Luhn**, pour ne pas confondre une référence de dossier avec un numéro de carte.

=== "Réponse sortante"

    `aegis_core/output_guard.py` (lot 10) filtre la réponse **sortante**, avec une politique assumée : les secrets sont masqués sans condition, les données personnelles sont seulement **signalées** par défaut (masquage activable). Le raisonnement : dans une *réponse*, un numéro de téléphone est le plus souvent celui du client lui-même ou du service demandé — le masquer ne protège personne et casse la réponse pour rien.

    `OutputGuard` détecte aussi la restitution verbatim d'un contexte caché (typiquement le prompt système) par **empreintes de n-grammes de mots**, en fusionnant les fragments qui se chevauchent en passages lisibles avant journalisation, et neutralise le balisage actif (scripts, iframes, gestionnaires d'événement scopés aux vraies balises, schémas d'URL exécutables, images distantes porteuses d'une requête).

Les deux composants partagent leurs validateurs (Luhn compris) pour ne jamais diverger sur ce qui compte comme une correspondance valide.

## Vérification d'ancrage et assistant de sécurité

`aegis_core/grounding.py` — Répond à LLM07 (Misinformation) sur la partie qui compte le plus dans ce projet précis : les chiffres.

!!! example "Règle brutale et vérifiable"
    Tout littéral numérique présent dans une réponse *générée* doit être présent dans les sources citées — pas d'arrondi, pas de calcul. Même contrôle sur les identifiants de code (snake_case, chemins de fichiers, attributs pointés). Une réponse qui échoue n'est pas corrigée, elle est **rejetée**, et l'appelant sert la réponse déterministe à la place.

!!! danger "Limite explicite"
    C'est un contrôle **lexical**, pas sémantique — « le détecteur bloque 100 % des attaques » et « le détecteur laisse passer 100 % des attaques » contiennent les mêmes littéraux et passent tous les deux ; fermer ce trou demanderait un modèle d'inférence (NLI), qui n'existe pas dans ce projet.

L'assistant de sécurité intégré à la console (lot 8) applique ce vérificateur à ses propres réponses : il compose des réponses à partir d'extraits réels (sections du README, scénarios, mesures relues dans `models/*/metrics.json`), et une reformulation par LLM n'est acceptée que si elle passe le contrôle d'ancrage — sinon elle est rejetée et la réponse extractive brute est servie à la place.

## Journal d'audit signé

`aegis_core/audit_log.py`, `signing.py` — Trois couches de défense, du plus faible au plus fort.

| Couche | Protège contre | Ne protège pas contre |
|---|---|---|
| Chaînage par hachage | Rien contre un attaquant avec accès en écriture | Recalcul complet de la chaîne avec le même `hashlib` |
| Triggers SQLite append-only | Un bug ou une injection SQL | Quelqu'un qui supprime le trigger |
| **Signature Ed25519** | Falsification *a posteriori*, sans la clé privée | Compromission du processus pendant l'écriture ; troncature des dernières entrées |

!!! danger "Démontré en conditions réelles, sur ce projet"
    Sans la signature, un virement de 50 000 € effacé du journal, chaîne reforgée, intégrité rapportée `OK` — le chaînage seul ne détecte rien parce qu'il recalcule exactement de la même façon que l'attaquant.

Le choix d'Ed25519 plutôt que HMAC est délibéré : une clé asymétrique permet à un tiers (client, commissaire aux comptes) de vérifier le journal avec la seule clé **publique**, sans jamais recevoir de quoi le forger — ce qui fait passer le journal de « trace technique » à **preuve opposable**.

## Isolation par session

`aegis_core/session.py` — La fenêtre comportementale était initialement indexée par nom d'agent seul. En production, tous les utilisateurs d'un même agent partageaient alors la même fenêtre, avec deux conséquences concrètes :

- **Dilution** — un attaquant fait passer sa séquence pendant que le trafic légitime remplit la fenêtre, et son comportement n'apparaît jamais comme anormal.
- **Contamination** — les actions d'un utilisateur font monter le score d'un autre, ce qui coûte plus cher qu'une simple absence de signal.

La clé retenue est `(tenant, agent, session_id)`. Quand le contexte ne porte pas de `session_id`, il n'est pas inventé : la clé est marquée **anonyme**, et le rapport de robustesse compte ces fenêtres séparément — le comportement dégradé redevient visible plutôt que silencieux. Une expiration (`ttl_seconds`) et un plafond (`max_sessions`, éviction LRU) empêchent qu'un flot de `session_id` toujours différents ne devienne lui-même un vecteur d'épuisement mémoire (LLM06).

## Limitation de consommation

`web/ratelimit.py` — Deux gardes indépendantes répondant à deux menaces différentes :

- Un **seau à jetons par client** (identifié par IP) protège la **disponibilité** entre visiteurs — rechargé en continu plutôt qu'en fenêtre fixe.
- Une **enveloppe globale sur fenêtre glissante**, partagée par tous les clients, protège le **portefeuille** : un seau par client borne ce que *chacun* consomme, jamais ce que la facture totalise.

!!! example "Chiffre illustratif"
    À 10 appels/minute et 100 adresses, un plafond par client seul donnerait un plafond réel de 1000 appels/minute — c'est-à-dire aucun plafond.

!!! danger "Limite documentée"
    L'état vit en **mémoire de processus** — un redémarrage remet les compteurs à zéro, et derrière plusieurs répliques, chaque instance compte pour elle seule (voir [Chemin vers un déploiement de production](deploiement.md)).

## Filtre de sortie — le composant le plus récent

`aegis_core/output_guard.py` (lot 10) — Détaillé plus haut pour la partie protection des données ; sa particularité architecturale mérite d'être répétée ici : c'est le **premier et seul** composant du projet qui modifie ce que l'utilisateur reçoit plutôt que ce que le modèle reçoit.

!!! example "Mesuré sur un corpus adversarial-mais-légitime de 30 cas"
    | Taux | Résultat |
    |---|---|
    | Détection | 100 % [76-100 %] (12/12) |
    | Neutralisation effective | 100 % [65-100 %] (7/7) |
    | Modification injustifiée d'une réponse légitime | **0 %** — porte bloquante en CI |
    | Signalement injustifié | 0 % (toléré) |

Cette différence de nature a dicté une tolérance de faux positifs quasiment nulle, mesurée séparément de la détection — la mesure de « modification injustifiée » fait échouer la CI si elle n'est pas nulle.

??? note "Trois faux positifs réels, trouvés et corrigés pendant la construction"
    Un extrait de code JavaScript (`bouton.onclick = ...`) neutralisé parce que la recherche de gestionnaires d'événement balayait tout le texte au lieu de se limiter à l'intérieur des vraies balises HTML ; une phrase « Le fichier data: 3 colonnes... » neutralisée parce que le motif d'URL exécutable acceptait `data:` nu au lieu d'exiger la structure `data:<type>/<sous-type>` d'une URI de données ; une image de documentation neutralisée parce que la première version supprimait toutes les images distantes plutôt que seulement celles portant une requête suspecte.

Voir la méthodologie détaillée derrière ces chiffres dans [Méthodologie de mesure](mesure.md).
