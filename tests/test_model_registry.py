"""
Registre de modèles : est-ce bien CE modèle-là dont on publie les chiffres ?

Le `MANIFEST.json` de `model_io` vérifie qu'un artefact n'a pas été altéré depuis
son écriture. Il ne dit rien du fait que ce soit l'artefact sur lequel les
mesures ont été obtenues. Réentraîner sans republier produit exactement ce cas :
manifeste cohérent, chiffres périmés, et rien qui l'indique.
"""
from __future__ import annotations

import json

import pytest

from aegis_core.model_registry import (
    MetricEntry,
    ModelCard,
    check_integrity,
    incumbent,
    load_registry,
    record,
    sha256_files,
)
from aegis_core.promotion import PLUS_HAUT


def _carte(nom: str = "essai", artefact: str = "a" * 64, donnees: str = "d" * 64) -> ModelCard:
    return ModelCard(
        name=nom,
        version="20260101-abcdef12",
        created_at="2026-01-01T00:00:00+00:00",
        artifact_sha256=artefact,
        dataset_sha256=donnees,
        dataset_files=("train.jsonl",),
        threshold=0.5,
        target_false_positive_rate=0.05,
        metrics=(
            MetricEntry(
                name="rappel", successes=12, total=14, low=0.6, high=0.96, direction=PLUS_HAUT
            ),
        ),
        intended_use="usage",
        known_failures=("un mode d'échec",),
        training_command="python -m scripts.rien",
        decision_role="consultatif",
    )


def test_un_registre_absent_est_vide_pas_une_erreur(tmp_path):
    """L'état normal d'un dépôt qui n'a encore rien promu."""
    assert load_registry(tmp_path / "absent.json").models == {}


def test_aller_retour_sur_disque(tmp_path):
    chemin = tmp_path / "registry.json"
    record(_carte(), chemin)
    relu = incumbent("essai", chemin)
    assert relu is not None
    assert relu.artifact_sha256 == "a" * 64
    assert relu.metric("rappel").proportion.format() == "86% [60%-96%] (12/14)"


def test_le_fichier_est_trie_pour_rester_relisible(tmp_path):
    """Un fichier versionné dont l'ordre bouge à chaque écriture produit des
    diffs illisibles, et un diff illisible est un diff que personne ne relit."""
    chemin = tmp_path / "registry.json"
    record(_carte("zebre"), chemin)
    record(_carte("alpha"), chemin)
    brut = json.loads(chemin.read_text(encoding="utf-8"))
    assert list(brut["models"]) == ["alpha", "zebre"]


def test_l_empreinte_d_un_ensemble_ne_depend_pas_de_l_ordre(tmp_path):
    """Deux scripts qui listent les mêmes fichiers autrement doivent obtenir la
    même valeur, sinon l'empreinte détecte une dérive qui n'existe pas."""
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("un", encoding="utf-8")
    b.write_text("deux", encoding="utf-8")
    assert sha256_files([a, b]) == sha256_files([b, a])


def test_l_empreinte_change_si_un_contenu_change(tmp_path):
    a = tmp_path / "a.txt"
    a.write_text("un", encoding="utf-8")
    avant = sha256_files([a])
    a.write_text("deux", encoding="utf-8")
    assert sha256_files([a]) != avant


# -- intégrité disque ↔ registre --------------------------------------------


@pytest.fixture
def modele(tmp_path):
    dossier = tmp_path / "models" / "essai"
    dossier.mkdir(parents=True)
    (dossier / "weights.json").write_text('{"poids": 1}', encoding="utf-8")
    donnees = tmp_path / "data" / "train.jsonl"
    donnees.parent.mkdir(parents=True)
    donnees.write_text('{"x": 1}\n', encoding="utf-8")
    return dossier, donnees


def test_un_modele_conforme_ne_signale_rien(tmp_path, modele):
    dossier, donnees = modele
    chemin = tmp_path / "registry.json"
    record(
        _carte(artefact=sha256_files([dossier / "weights.json"]), donnees=sha256_files([donnees])),
        chemin,
    )
    problemes = check_integrity({"essai": dossier}, {"essai": [donnees]}, chemin)
    assert problemes == []


def test_un_modele_reentraine_sans_republication_est_signale(tmp_path, modele):
    """Le cas exact que le manifeste ne voit pas.

    Les artefacts sont cohérents avec eux-mêmes ; ils ne sont simplement plus
    ceux sur lesquels les chiffres publiés ont été obtenus.
    """
    dossier, donnees = modele
    chemin = tmp_path / "registry.json"
    record(
        _carte(artefact=sha256_files([dossier / "weights.json"]), donnees=sha256_files([donnees])),
        chemin,
    )
    (dossier / "weights.json").write_text('{"poids": 2}', encoding="utf-8")

    problemes = check_integrity({"essai": dossier}, {"essai": [donnees]}, chemin)
    assert [p.kind for p in problemes] == ["artefact"]
    assert "décrivent un autre modèle" in problemes[0].message


def test_un_jeu_d_entrainement_modifie_est_signale(tmp_path, modele):
    dossier, donnees = modele
    chemin = tmp_path / "registry.json"
    record(
        _carte(artefact=sha256_files([dossier / "weights.json"]), donnees=sha256_files([donnees])),
        chemin,
    )
    donnees.write_text('{"x": 2}\n', encoding="utf-8")

    problemes = check_integrity({"essai": dossier}, {"essai": [donnees]}, chemin)
    assert [p.kind for p in problemes] == ["donnees"]
    assert "seuil calibré sur d'autres données" in problemes[0].message


def test_un_modele_absent_du_disque_n_est_pas_une_anomalie(tmp_path):
    """Sur un clone frais, `models/` est vide : les poids ne sont pas versionnés.
    Signaler ça noierait le vrai signal sous du bruit attendu."""
    chemin = tmp_path / "registry.json"
    record(_carte(), chemin)
    assert check_integrity({}, {}, chemin) == []


# -- le manifeste versionné du dépôt ----------------------------------------


def test_le_registre_du_depot_est_lisible_et_complet():
    """Le fichier réellement commité, pas un fixture.

    Il porte les chiffres que le README publie : s'il devient illisible ou perd
    ses métriques, les chiffres publiés ne sont plus rattachés à rien.
    """
    registre = load_registry()
    if not registre.models:
        pytest.skip("registre vide : aucun modèle n'a encore été promu")
    for nom, carte in registre.models.items():
        assert carte.name == nom
        assert len(carte.artifact_sha256) == 64
        assert len(carte.dataset_sha256) == 64
        assert carte.metrics, f"{nom} n'a aucune métrique enregistrée"
        assert carte.known_failures, f"{nom} ne déclare aucun mode d'échec connu"
        assert carte.intended_use
        assert carte.decision_role in {"bloquant", "consultatif"}
