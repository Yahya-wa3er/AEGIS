# Carte de modèle — `rag_outlier`

> Fichier **généré** par `python -m scripts.model_registry_cli cards`.
> Ne pas l'éditer à la main : la CI vérifie qu'il correspond à son générateur,
> exactement comme pour `data/`. Un chiffre recopié dérive de sa source.

| | |
|---|---|
| Version | `20260818-4356a8e3` |
| Rôle dans la décision | **consultatif** |
| Empreinte de l'artefact | `4356a8e3dd317452…` |
| Empreinte du jeu de données | `bac7546f21ca6021…` |
| Fichiers de données | `rag_corpus_train.jsonl`, `rag_corpus_calibration.jsonl`, `rag_corpus_test.jsonl` |
| Seuil de décision calibré | `0.7813545381014075` |
| Taux de faux positifs visé à la calibration | `0.05` |

## Usage prévu

Signaler qu'un document récupéré s'éloigne du domaine documentaire sur lequel l'agent a été calibré. Signal **consultatif** : il est journalisé et compté, il ne neutralise rien par lui-même.

## Mesures

Chaque taux est donné avec son intervalle de Wilson à 95 % et l'effectif qui le
soutient. L'intervalle est l'information principale : à ces volumes, c'est lui
qui dit ce que la mesure permet réellement d'affirmer.

| Métrique | Sens de « mieux » | Mesure |
|---|---|---|
| `false_positive_rate_in_domain` | plus bas | 0% [0%-5%] (0/72) |
| `false_positive_rate_legitimate` | plus bas | 4% [1%-11%] (3/78) |
| `false_positive_rate_out_of_domain` | plus bas | 50% [19%-81%] (3/6) |
| `recall_attacks` | plus haut | 86% [60%-96%] (12/14) |

## Modes d'échec connus

- Tout texte légitime hors du registre du corpus (note juridique, bulletin météo, rapport financier) le fait réagir : c'est la cause directe du taux de faux positifs hors-domaine mesuré plus haut, et la raison pour laquelle ce détecteur n'a pas le droit de bloquer.
- Représentation TF-IDF : deux textes qui disent la même chose avec un autre vocabulaire sont vus comme éloignés. Aucune notion de sens.
- Le seuil est calibré sur un corpus de tickets de support en français. Déployé sur un autre domaine, il doit être recalibré — le réutiliser tel quel revient à publier un taux qui n'a pas été mesuré là où il sert.

## Reproduire

```bash
python -m scripts.generate_rag_corpus && python -m scripts.train_rag_outlier_detector
python -m scripts.model_registry_cli check
```

## Notes de méthode

Découpe train/calibration/test disjointe par gabarit : deux variantes d'un même modèle de document ne peuvent pas se retrouver de part et d'autre de la frontière. Le seuil est fixé sur la calibration, jamais sur le test.
