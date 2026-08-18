# Carte de modèle — `behavior_vae`

> Fichier **généré** par `python -m scripts.model_registry_cli cards`.
> Ne pas l'éditer à la main : la CI vérifie qu'il correspond à son générateur,
> exactement comme pour `data/`. Un chiffre recopié dérive de sa source.

| | |
|---|---|
| Version | `20260818-ac11f67b` |
| Rôle dans la décision | **consultatif** |
| Empreinte de l'artefact | `ac11f67b579c9d83…` |
| Empreinte du jeu de données | `86e473c085a9c0b7…` |
| Fichiers de données | `behavior_sessions_train.jsonl`, `behavior_sessions_calibration.jsonl`, `behavior_sessions_test.jsonl` |
| Seuil de décision calibré | `4.079637050628662` |
| Taux de faux positifs visé à la calibration | `0.02` |

## Usage prévu

Repérer une suite d'actions d'agent statistiquement anormale sur une fenêtre de session (rafale d'actions sensibles, clôture en masse, détournement). Signal **consultatif**.

## Mesures

Chaque taux est donné avec son intervalle de Wilson à 95 % et l'effectif qui le
soutient. L'intervalle est l'information principale : à ces volumes, c'est lui
qui dit ce que la mesure permet réellement d'affirmer.

| Métrique | Sens de « mieux » | Mesure |
|---|---|---|
| `recall_all_anomalies` | plus haut | 96% [91%-98%] (115/120) |

## Modes d'échec connus

- Un comportement légitime mais rare — une opération de maintenance groupée, par exemple — ressemble à une anomalie : le détecteur apprend l'habituel, pas le licite.
- La fenêtre est indexée par (tenant, agent, session). Sans identifiant de session fourni par l'orchestrateur, l'état se dégrade en fenêtre partagée, et le rapport de robustesse le signale.
- Un attaquant qui étale ses actions sur plusieurs sessions courtes reste sous le seuil, par construction.

## Reproduire

```bash
python -m scripts.generate_behavior_sessions && python -m scripts.train_behavior_vae
python -m scripts.model_registry_cli check
```

## Notes de méthode

Seuil calibré à un taux de faux positifs visé sur le jeu de calibration, puis mesuré sur un jeu de test tenu à l'écart.
