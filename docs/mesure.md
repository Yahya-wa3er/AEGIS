# Méthodologie de mesure

Le projet publie des taux (blocage, faux positifs, détection) sur des corpus volontairement petits (souvent 10 à 40 exemples). `aegis_core/stats.py` implémente l'**intervalle de Wilson** pour éviter le mensonge que produirait la formule normale usuelle (`p ± 1.96·√(p(1-p)/n)`) à ces volumes : elle donne `[0%, 0%]` pour 0/10 et `[100%, 100%]` pour 12/12, c'est-à-dire une certitude absolue précisément là où il n'y en a aucune, parce que la variance estimée s'annule aux bornes. L'intervalle de Wilson (1927) ne s'effondre pas à p=0 ou p=1 et reste correct à petit n. Concrètement, « 12/12 = 100 % de blocage » se lit et se publie comme `100 % [76 %-100 %] (12/12)` — parfaitement compatible avec un système qui échouerait une fois sur cinq en réalité, simplement pas encore tombé sur le mauvais tirage.

Un module compagnon (`samples_needed_for_width`, `min_samples_for_lower_bound`) répond à la question qui suit naturellement : combien d'échantillons faudrait-il pour resserrer l'intervalle, ou pour garantir une borne basse donnée. Ça transforme « il faudrait un corpus plus grand » en objectif chiffré plutôt qu'en vœu pieux.

Ce que l'intervalle de confiance **ne fait pas**, et que le code documente explicitement : il quantifie l'incertitude d'échantillonnage, pas le biais de sélection. Si les payloads de test ont été écrits en regardant les règles de détection, l'intervalle sera étroit et le chiffre restera faux quand même — c'est un problème de méthodologie de corpus, qu'aucune formule statistique ne corrige.

La porte de non-régression du red-teaming (`redteam.run_redteam`) applique ce principe à la CI : elle échoue si le taux de blocage descend sous un plancher **ou** si les faux positifs dépassent un plafond — les deux comptent, un détecteur qui bloque tout satisfait le premier critère sans rien détecter.

À la livraison du lot 10 : 410 tests automatisés (383 avant ce lot, 27 nouveaux pour le filtre de sortie), passant à la fois avec et sans clé LLM réelle configurée ; 12 scénarios de red-teaming sur 5 points d'interception ; 10 attaques arrêtées sur 10, 0 faux positif sur les 10 contrôles bénins du banc de red-teaming (avec les intervalles de Wilson correspondants, larges à ce volume) ; 12 paires de contraste WCAG 2.1 AA conformes sur l'interface — chiffres détaillés dans [Statistiques du projet](statistiques.md).

Cette méthodologie s'applique aussi à l'évaluation des modèles ML lors de leur promotion — voir [MLOps](mlops.md).
