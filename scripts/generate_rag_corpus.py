"""
Génère un corpus de documents synthétiques pour le détecteur d'outliers
d'embeddings (blueprint, section 4.5 - volet SentinelRAG).

Même démarche que pour le VAE comportemental : on génère une grande quantité
de documents "normaux" du domaine réel de l'agent (support client), pour
apprendre à quoi ressemble ce domaine, puis un jeu d'évaluation étiqueté
(normal tenu à l'écart, empoisonné, hors-domaine) pour MESURER le détecteur
après coup -- jamais pour l'entraîner.

Les documents "empoisonnés" de l'évaluation sont directement réutilisés du
corpus de red-teaming (`redteam/payloads.py`) plutôt que réinventés : c'est
le même corpus qui sert déjà à mesurer le classifieur d'injection, ce qui
permet de comparer les deux détecteurs sur des cas identiques.

Usage:
    python -m scripts.generate_rag_corpus
"""
from __future__ import annotations

import json
import random
from pathlib import Path

from redteam.payloads import PAYLOADS

SEED = 42
N_TRAIN_DOCS = 150
N_EVAL_NORMAL_HELDOUT = 30

TRAIN_PATH = Path("data/rag_corpus_train.jsonl")
EVAL_PATH = Path("data/rag_corpus_eval.jsonl")

# Gabarits représentatifs du VRAI domaine de doc1_clean.txt : des documents de
# contexte de support client. La variété lexicale (ticket, montant, produit,
# délai) suffit à donner au TF-IDF une notion de "à quoi ressemble ce domaine".
NORMAL_TEMPLATES = (
    "Merci pour votre commande {ticket}, elle sera livrée sous {days} jours ouvrés.",
    "Votre remboursement de {amount}€ a été traité et sera visible sous 3 à 5 jours sur votre compte.",
    "Le produit {product} dispose d'une autonomie de {hours} heures et d'un port USB-C pour la recharge.",
    "Bonjour, votre ticket {ticket} a bien été pris en compte, un conseiller vous répondra sous 24h.",
    "Nous avons bien reçu votre demande concernant la commande {ticket}, merci de votre patience.",
    "Le retard de livraison de votre colis {ticket} est dû à des conditions météorologiques exceptionnelles.",
    "Votre abonnement a été renouvelé automatiquement pour un montant de {amount}€.",
    "N'hésitez pas à nous contacter pour toute question concernant votre commande {ticket}.",
    "Le produit {product} est actuellement en rupture de stock, réapprovisionnement prévu sous {days} jours.",
    "Votre demande de retour pour la commande {ticket} a été acceptée, une étiquette prépayée vous a été envoyée.",
    "Le ticket {ticket} a été transféré à notre service technique, réponse attendue sous {days} jours.",
    "Votre carte de fidélité a été créditée de points suite à votre achat de {product}.",
)

PRODUCTS = ("XR-200", "casque BassPro", "montre FitTrack", "clavier NovaType", "enceinte SoundWave")

# Textes hors-domaine mais légitimes -- même registre que celui identifié comme
# "angle mort" du classifieur d'injection (RGPD, doc API, RH...). Intéressant à
# observer ici aussi : un document dans un registre différent MAIS bénin
# ressort-il comme outlier ? (Ce n'est pas forcément un défaut si oui -- voir
# limites connues -- mais c'est une mesure honnête à faire, pas une hypothèse.)
OUT_OF_DOMAIN_DOCS = (
    "Conformément au RGPD, vous pouvez demander la suppression de vos données personnelles à tout moment.",
    "L'API accepte des requêtes GET et POST au format JSON, avec une limite de 100 appels par minute.",
    "Le planning des congés de l'équipe sera communiqué par le service RH avant la fin du mois.",
    "Le rapport financier du Q2 montre une croissance de 4% par rapport au trimestre précédent.",
    "La réunion du comité de direction est reportée à la semaine prochaine, salle B.",
)


def _fill(template: str, rng: random.Random) -> str:
    return template.format(
        ticket=rng.randint(10000, 99999),
        days=rng.randint(2, 10),
        amount=round(rng.uniform(9.99, 499.99), 2),
        product=rng.choice(PRODUCTS),
        hours=rng.randint(4, 20),
    )


def generate_normal_docs(n: int, rng: random.Random) -> list[str]:
    return [_fill(rng.choice(NORMAL_TEMPLATES), rng) for _ in range(n)]


def main() -> None:
    rng = random.Random(SEED)
    TRAIN_PATH.parent.mkdir(parents=True, exist_ok=True)

    train_docs = generate_normal_docs(N_TRAIN_DOCS, rng)
    with TRAIN_PATH.open("w", encoding="utf-8") as f:
        for doc in train_docs:
            f.write(json.dumps({"text": doc}) + "\n")
    print(f"{len(train_docs)} documents normaux écrits dans '{TRAIN_PATH}'.")

    eval_rows = []
    for doc in generate_normal_docs(N_EVAL_NORMAL_HELDOUT, rng):
        eval_rows.append({"text": doc, "label": "normal", "category": "normal"})

    poisoned = [p for p in PAYLOADS if p.is_attack]
    for payload in poisoned:
        eval_rows.append({"text": payload.content, "label": "anomalous", "category": "poisoned"})

    for doc in OUT_OF_DOMAIN_DOCS:
        eval_rows.append({"text": doc, "label": "anomalous", "category": "out_of_domain"})

    rng.shuffle(eval_rows)
    with EVAL_PATH.open("w", encoding="utf-8") as f:
        for row in eval_rows:
            f.write(json.dumps(row) + "\n")
    print(f"{len(eval_rows)} documents étiquetés écrits dans '{EVAL_PATH}' (évaluation uniquement).")


if __name__ == "__main__":
    main()
