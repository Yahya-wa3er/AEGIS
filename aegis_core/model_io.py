"""
Chargement d'artefacts de modèle **sans désérialisation de code** (correctif P0-5).

Pourquoi ce module existe
-------------------------
Les formats de sérialisation par défaut de l'écosystème Python -- `pickle`, et
tout ce qui repose dessus (`joblib.dump`, `torch.save`) -- ne sont pas des
formats de données : ce sont des **programmes**. Charger un fichier pickle
exécute le code qu'il contient. Quiconque peut écrire dans `models/` obtient
donc l'exécution de code dans le processus AEGIS, c'est-à-dire dans le
composant le plus privilégié de toute l'architecture. Et le jour où des poids
pré-entraînés seront distribués, c'est le canal de distribution qui devient le
vecteur.

C'est le risque **LLM04:2026 Supply Chain** de l'OWASP GenAI Top 10 -- une
catégorie qu'un produit de sécurité ne peut pas se permettre d'ignorer dans son
propre code.

Ce que ce module garantit
-------------------------
1. **Aucun `pickle`** : les artefacts sont du JSON (structure) et du `.npz`
   chargé avec `allow_pickle=False` (tableaux numériques). Un fichier corrompu
   ou malveillant produit une erreur de parsing, jamais une exécution.
2. **Intégrité vérifiée avant usage** : chaque répertoire de modèle contient un
   `MANIFEST.json` listant le SHA-256 de chaque artefact. Une empreinte qui ne
   correspond pas fait échouer le chargement -- bruyamment.

Le manifeste protège contre la substitution accidentelle et contre un
attaquant qui modifie un fichier sans pouvoir régénérer le manifeste. Il ne
protège pas contre quelqu'un qui réécrit *aussi* le manifeste : c'est la même
limite structurelle que la chaîne de hachage du journal d'audit, et elle se
lève de la même façon -- une signature (Ed25519) dont l'attaquant n'a pas la
clé. Prévu au lot suivant ; d'ici là, cette limite est documentée plutôt que
tue.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST_NAME = "MANIFEST.json"
MANIFEST_VERSION = 1
_CHUNK = 1 << 20  # 1 Mio


class ModelIntegrityError(RuntimeError):
    """Levée quand un artefact de modèle ne correspond pas à son empreinte."""


def sha256_file(path: Path) -> str:
    """Empreinte SHA-256 d'un fichier, lue par blocs (pas de chargement complet)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def write_manifest(model_dir: Path, filenames: list[str]) -> Path:
    """Écrit `MANIFEST.json` pour les artefacts listés. Appelé par les scripts d'entraînement."""
    model_dir = Path(model_dir)
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "files": {name: sha256_file(model_dir / name) for name in sorted(filenames)},
    }
    path = model_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    logger.info("Manifeste d'intégrité écrit : %s (%d artefact(s))", path, len(filenames))
    return path


def verify_manifest(model_dir: Path) -> bool:
    """Vérifie les empreintes du répertoire de modèle.

    Retourne True si le manifeste est présent et intégralement valide, False s'il
    est absent (modèle entraîné avant l'introduction du manifeste -- un WARNING est
    émis). Lève `ModelIntegrityError` si le manifeste est présent mais qu'un
    artefact ne correspond pas : dans ce cas, on refuse de charger.
    """
    model_dir = Path(model_dir)
    manifest_path = model_dir / MANIFEST_NAME

    if not manifest_path.is_file():
        logger.warning(
            "Aucun manifeste d'intégrité dans '%s' -- artefacts chargés sans vérification. "
            "Relance le script d'entraînement correspondant pour en générer un.",
            model_dir,
        )
        return False

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected: dict[str, str] = manifest["files"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ModelIntegrityError(f"Manifeste illisible dans '{model_dir}' : {exc}") from exc

    for name, expected_hash in sorted(expected.items()):
        artifact = model_dir / name
        if not artifact.is_file():
            raise ModelIntegrityError(f"Artefact '{name}' annoncé au manifeste mais absent de '{model_dir}'.")
        actual = sha256_file(artifact)
        if actual != expected_hash:
            raise ModelIntegrityError(
                f"Empreinte incorrecte pour '{model_dir / name}' : "
                f"attendu {expected_hash[:16]}…, obtenu {actual[:16]}…. "
                "Le fichier a été modifié depuis l'entraînement -- chargement refusé."
            )

    logger.debug("Intégrité vérifiée pour '%s' (%d artefact(s)).", model_dir, len(expected))
    return True


def load_json(path: Path) -> dict:
    """Charge un JSON en refusant tout ce qui n'est pas un objet (garde-fou de forme)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ModelIntegrityError(f"'{path}' devrait contenir un objet JSON, pas {type(data).__name__}.")
    return data
