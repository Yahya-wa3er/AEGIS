# Méthodologie de mesure

Le projet publie des taux (blocage, faux positifs, détection) sur des corpus volontairement petits (souvent 10 à 40 exemples). À ce volume, la formule habituelle ment.

!!! danger "Ce que ferait la formule normale usuelle"
    `p ± 1.96·√(p(1-p)/n)` donne `[0 %, 0 %]` pour 0/10 et `[100 %, 100 %]` pour 12/12 — une certitude absolue précisément là où il n'y en a aucune, parce que la variance estimée s'annule aux bornes.

`aegis_core/stats.py` implémente l'**intervalle de Wilson** (1927) à la place, qui ne s'effondre pas à p=0 ou p=1 et reste correct à petit n.

!!! example "Comment ça se lit"
    « 12/12 = 100 % de blocage » se lit et se publie comme

    `100 % [76 %–100 %] (12/12)`

    — parfaitement compatible avec un système qui échouerait une fois sur cinq en réalité, simplement pas encore tombé sur le mauvais tirage. C'est l'intervalle, pas le pourcentage seul, qui dit ce que la mesure permet réellement d'affirmer.

Un module compagnon (`samples_needed_for_width`, `min_samples_for_lower_bound`) répond à la question qui suit naturellement : combien d'échantillons faudrait-il pour resserrer l'intervalle, ou pour garantir une borne basse donnée. Ça transforme « il faudrait un corpus plus grand » en objectif chiffré plutôt qu'en vœu pieux.

!!! warning "Ce que l'intervalle de confiance ne fait pas"
    Il quantifie l'incertitude d'échantillonnage, pas le biais de sélection. Si les payloads de test ont été écrits en regardant les règles de détection, l'intervalle sera étroit et le chiffre restera faux quand même — c'est un problème de méthodologie de corpus, qu'aucune formule statistique ne corrige.

## La porte de non-régression en CI

La porte de non-régression du red-teaming (`redteam.run_redteam`) applique ce principe à la CI : elle échoue si le taux de blocage descend sous un plancher **ou** si les faux positifs dépassent un plafond — les deux comptent, un détecteur qui bloque tout satisfait le premier critère sans rien détecter.

À la livraison du lot 10 :

<div class="aegis-stats" markdown>

<div class="aegis-stat"><strong>410</strong><span>tests automatisés</span></div>
<div class="aegis-stat"><strong>12</strong><span>scénarios de red-teaming</span></div>
<div class="aegis-stat"><strong>10/10</strong><span>attaques arrêtées</span></div>
<div class="aegis-stat"><strong>0</strong><span>faux positif sur les contrôles bénins</span></div>

</div>

Détail complet, et intervalles de Wilson associés, dans [Statistiques du projet](statistiques.md). Cette méthodologie s'applique aussi à l'évaluation des modèles ML lors de leur promotion — voir [MLOps](mlops.md).
