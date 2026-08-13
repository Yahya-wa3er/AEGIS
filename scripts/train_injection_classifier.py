"""Fine-tuning d'un classifieur binaire de détection d'injection de prompt.

Ce script constitue le baseline de mesure du Phase 2 (section 4.2 du blueprint) :
on fine-tune un DistilBERT pré-entraîné (transfer learning) sur le dataset public
`deepset/prompt-injections`, et on mesure precision/recall/F1 réels sur un split
de test avant de décider si le dataset a besoin d'être enrichi.

Usage:
    python scripts/train_injection_classifier.py
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from datasets import ClassLabel, Dataset, DatasetDict, Value, concatenate_datasets, load_dataset
from sklearn.metrics import precision_recall_fscore_support
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    EvalPrediction,
    Trainer,
    TrainingArguments,
)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MODEL_NAME = "distilbert-base-multilingual-cased"
DATASET_NAME = "deepset/prompt-injections"
FRENCH_DATA_PATH = Path("data/french_injection_examples.jsonl")
OUTPUT_DIR = Path("models/injection_classifier")
CHECKPOINT_DIR = Path("checkpoints/injection_classifier")
MAX_SEQ_LENGTH = 256
DATASET_COLUMNS = ("text", "label")


@dataclass(frozen=True)
class TrainingMetrics:
    """Métriques de test, calculées une seule fois en fin d'entraînement."""

    precision: float
    recall: float
    f1: float
    accuracy: float

    def summary(self) -> str:
        return (
            f"precision={self.precision:.4f}  "
            f"recall={self.recall:.4f}  "
            f"f1={self.f1:.4f}  "
            f"accuracy={self.accuracy:.4f}"
        )


def load_and_split_dataset() -> DatasetDict:
    """Charge deepset/prompt-injections et garantit un split train/test.

    Le dataset publie nativement un split 'train' et un split 'test' ; on s'assure
    juste que les deux existent, sinon on découpe nous-mêmes (90/10, stratifié).
    """
    raw = load_dataset(DATASET_NAME)
    if "test" in raw:
        return raw

    logger.info("Pas de split 'test' fourni par le dataset, découpage 90/10 manuel.")
    split = raw["train"].train_test_split(test_size=0.1, seed=42, stratify_by_column="label")
    return DatasetDict(train=split["train"], test=split["test"])


def load_french_dataset(path: Path = FRENCH_DATA_PATH) -> DatasetDict | None:
    """Charge les exemples français générés par scripts/generate_french_examples.py.

    Retourne None si le fichier n'existe pas encore -- l'entraînement reste alors
    possible sur deepset/prompt-injections seul (mode dégradé, sans couverture
    française), avec un WARNING pour signaler la dégradation.
    """
    if not path.is_file():
        logger.warning(
            "Aucun exemple français trouvé dans '%s' -- entraînement sur '%s' seul "
            "(lance scripts/generate_french_examples.py pour enrichir en français).",
            path,
            DATASET_NAME,
        )
        return None

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    dataset = Dataset.from_list(records)
    # train_test_split(stratify_by_column=...) exige une colonne de type ClassLabel ;
    # Dataset.from_list() infère 'label' comme un simple entier (Value), d'où le cast.
    dataset = dataset.cast_column("label", ClassLabel(names=["benin", "injection"]))
    split = dataset.train_test_split(test_size=0.1, seed=42, stratify_by_column="label")
    return DatasetDict(train=split["train"], test=split["test"])


def load_combined_dataset() -> DatasetDict:
    """Fusionne deepset/prompt-injections (anglais/allemand) avec les exemples français.

    Les deux sources sont réduites aux mêmes colonnes ('text', 'label') avant fusion,
    et la colonne 'label' est ramenée à un type simple (int64) des deux côtés : les
    deux datasets utilisent des ClassLabel avec des noms différents, or
    `concatenate_datasets` exige un schéma strictement identique (y compris les noms
    de classes), pas seulement des types compatibles.
    """
    base = load_and_split_dataset()
    french = load_french_dataset()
    if french is None:
        return base

    columns = list(DATASET_COLUMNS)
    base = DatasetDict(
        train=base["train"].select_columns(columns).cast_column("label", Value("int64")),
        test=base["test"].select_columns(columns).cast_column("label", Value("int64")),
    )
    french = DatasetDict(
        train=french["train"].select_columns(columns).cast_column("label", Value("int64")),
        test=french["test"].select_columns(columns).cast_column("label", Value("int64")),
    )

    logger.info(
        "Fusion : %d exemples deepset + %d exemples français.",
        len(base["train"]) + len(base["test"]),
        len(french["train"]) + len(french["test"]),
    )
    combined_train = concatenate_datasets([base["train"], french["train"]]).shuffle(seed=42)
    combined_test = concatenate_datasets([base["test"], french["test"]]).shuffle(seed=42)
    return DatasetDict(train=combined_train, test=combined_test)


def tokenize_dataset(dataset: DatasetDict, tokenizer: AutoTokenizer) -> DatasetDict:
    """Tokenize les colonnes texte du dataset, en conservant la colonne 'label'."""

    def _tokenize(batch: dict[str, list[str]]) -> dict[str, list[int]]:
        return tokenizer(
            batch["text"],
            truncation=True,
            padding="max_length",
            max_length=MAX_SEQ_LENGTH,
        )

    tokenized = dataset.map(_tokenize, batched=True)
    if "label" in tokenized["train"].column_names and "labels" not in tokenized["train"].column_names:
        # Le Trainer HuggingFace attend une colonne 'labels' (avec 's') pour calculer
        # la loss automatiquement ; le dataset publie 'label' (sans 's').
        tokenized = tokenized.rename_column("label", "labels")
    return tokenized


def compute_metrics(eval_pred: EvalPrediction) -> dict[str, float]:
    """Calcule precision/recall/F1/accuracy binaires pour le Trainer HuggingFace."""
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary", zero_division=0
    )
    accuracy = float(np.mean(predictions == labels))
    return {"precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy}


def train() -> TrainingMetrics:
    """Lance le fine-tuning complet et retourne les métriques de test finales."""
    logger.info("Chargement du dataset '%s' + exemples français...", DATASET_NAME)
    dataset = load_combined_dataset()

    logger.info("Chargement du tokenizer et du modèle '%s'...", MODEL_NAME)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

    tokenized = tokenize_dataset(dataset, tokenizer)

    training_args = TrainingArguments(
        output_dir=str(CHECKPOINT_DIR),
        num_train_epochs=4,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        learning_rate=2e-5,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_steps=10,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["test"],
        compute_metrics=compute_metrics,
    )

    logger.info("Début du fine-tuning...")
    trainer.train()

    logger.info("Évaluation finale sur le split de test...")
    raw_metrics = trainer.evaluate()
    metrics = TrainingMetrics(
        precision=raw_metrics["eval_precision"],
        recall=raw_metrics["eval_recall"],
        f1=raw_metrics["eval_f1"],
        accuracy=raw_metrics["eval_accuracy"],
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))
    logger.info("Modèle sauvegardé dans '%s'.", OUTPUT_DIR)

    return metrics


def main() -> None:
    metrics = train()
    logger.info("Métriques finales -- %s", metrics.summary())
    print(f"\n=== Résultat baseline ===\n{metrics.summary()}\n")


if __name__ == "__main__":
    main()