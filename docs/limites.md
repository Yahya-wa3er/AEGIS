# Limites connues, consolidées

Cette page rassemble, en un seul endroit, ce qui est dispersé dans les docstrings et le README — parce qu'un pair reviewer ou un futur contributeur doit pouvoir lire l'état réel des angles morts sans naviguer dix fichiers. Rien ici n'est caché ailleurs : c'est une consolidation, pas une nouvelle divulgation.

!!! danger "Évasions actives et testées"
    Le code contient, pour chacune, un test qui **échouerait** si l'évasion disparaissait sans que le mécanisme change — figées volontairement, pour qu'elles ne redeviennent jamais un mensonge silencieux :

    - le bourrage hybride du classement (`test_hybrid_stuffing_evades_detection`) ;
    - la paraphrase du prompt système face à la détection lexicale par n-grammes (`test_la_paraphrase_echappe_au_controle`) ;
    - l'exfiltration d'image encodée dans le chemin plutôt que la requête (`test_l_exfiltration_par_le_chemin_echappe_a_l_heuristique`) ;
    - les nombres écrits en toutes lettres face au vérificateur d'ancrage.

!!! warning "Faux positifs mesurés et non corrigés — choix assumé, pas oubli"
    - le classifieur ML d'injection signale un document légitime sur deux dans certains registres (rapport financier, bulletin météo, documentation d'API) ;
    - le détecteur d'outliers RAG confond hors-domaine et attaque (50 % de faux positifs hors domaine).

!!! info "Vérifié en CI, pas en runtime"
    L'intégrité du registre de modèles (`model_registry_cli verify`) — un modèle réentraîné localement sans republier n'est détecté qu'à la prochaine exécution manuelle de cette commande, pas au démarrage du service.

## Ce qui n'existe pas du tout

- Un SBOM.
- Une signature du bundle de modèles.
- Un contrôle d'accès ou une partition par locataire sur l'index RAG lui-même (l'état comportemental est isolé par session, l'index de récupération ne l'est pas).
- Une validation humaine réelle dans le Policy Engine (le `approval_hook` existe comme point d'extension, aucune implémentation n'est fournie).
- Un ancrage sémantique (NLI) pour la vérification d'ancrage et la détection de fuite de contexte.
- Une protection contre la troncature du journal d'audit (ancrage périodique externe du hash de tête).
- Un HSM ou un KMS pour la clé de signature Ed25519.

## Ce qui est en mémoire de processus

Donc ne survit pas à un redémarrage et ne se partage pas entre répliques : le seau à jetons et l'enveloppe globale de débit, l'état de session comportementale (avec bornes, mais locales).

---

Chacun de ces points a une contrepartie concrète : soit un chantier de production dans [Chemin vers un déploiement de production](deploiement.md), soit un chantier d'amélioration priorisé dans [Feuille de route](feuille-de-route.md). Le tableau de couverture par catégorie OWASP est dans [Couverture OWASP](owasp.md).
