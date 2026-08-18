"""
Vérification d'ancrage (LLM07, partie « la réponse est-elle soutenue ? »).

Ce que ces tests protègent en une phrase : sur un projet dont l'argument central
est *un chiffre qu'on publie, on l'a mesuré*, un assistant qui invente une
métrique fait plus de dégâts qu'une panne.
"""
from __future__ import annotations

from aegis_core.grounding import (
    GroundingVerifier,
    identifiants,
    nombres,
)

SOURCES = [
    "Le red-teaming mesure 100 % [76-100 %] de blocage et 0 % [0-28 %] de faux "
    "positifs sur 12 attaques et 10 contrôles.",
    "Le classifieur ML se trompe une fois sur deux : 50 % de faux positifs. "
    "Voir AegisConfig.blocking_signals et scripts/train_rag_outlier_detector.py.",
]


def test_un_chiffre_present_dans_les_sources_passe():
    rapport = GroundingVerifier().check(
        "Le blocage mesuré atteint 100 % sur 12 attaques.", SOURCES
    )
    assert rapport.ok
    assert rapport.raison is None


def test_un_chiffre_invente_est_rejete():
    """Le cas qui justifie tout le module.

    « 97 % » est plausible, proche du vrai, et faux. C'est exactement la forme
    d'erreur qu'un modèle de langage produit le mieux.
    """
    rapport = GroundingVerifier().check("AEGIS bloque 97 % des injections.", SOURCES)
    assert not rapport.ok
    assert "97" in rapport.nombres_non_soutenus


def test_un_chiffre_recalcule_est_rejete_aussi():
    """Interdire le calcul, et pas seulement l'invention.

    12 attaques sur 12, c'est 100 % — un modèle qui écrit « 24 » en doublant, ou
    « 92 » en arrondissant autrement, produit un nombre défendable qui n'a
    jamais été mesuré. La règle est brutale exprès : recopier, pas dériver.
    """
    rapport = GroundingVerifier().check("Sur 24 essais, le taux tombe à 92 %.", SOURCES)
    assert not rapport.ok
    assert set(rapport.nombres_non_soutenus) == {"24", "92"}


def test_un_identifiant_invente_est_rejete():
    rapport = GroundingVerifier().check(
        "Active AegisConfig.strict_mode pour durcir la politique.", SOURCES
    )
    assert not rapport.ok
    assert "AegisConfig.strict_mode" in rapport.identifiants_non_soutenus


def test_un_identifiant_reel_passe():
    rapport = GroundingVerifier().check(
        "Regarde AegisConfig.blocking_signals, et le script "
        "scripts/train_rag_outlier_detector.py pour la calibration.",
        SOURCES,
    )
    assert rapport.ok


def test_la_casse_ne_fait_pas_echouer():
    """« aegisconfig » et « AegisConfig » désignent la même chose.

    Rejeter sur la casse produirait du bruit sans rien attraper de dangereux, et
    un vérificateur bruyant finit désactivé."""
    assert GroundingVerifier().check("Voir aegisconfig.blocking_signals.", SOURCES).ok


def test_les_typographies_de_nombre_sont_equivalentes():
    """`1,00`, `1.0` et `1` sont la même valeur.

    Sans cette normalisation, le vérificateur rejetterait une réponse pour une
    virgule décimale française face à un point anglais — un faux positif sur un
    détail de rendu."""
    assert nombres("1,00 et 1.0 et 1") == nombres("1")
    assert GroundingVerifier().check(
        "Le taux vaut 1,00.", ["Le taux vaut 1."]
    ).ok


def test_les_separateurs_de_milliers_sont_normalises():
    assert nombres("7 714 incidents") == nombres("7714")


def test_les_petits_nombres_ne_declenchent_rien():
    """« les 2 endpoints », « en 1 seconde » : exiger ces valeurs dans les
    sources ferait échouer des phrases correctes sans rien protéger."""
    assert GroundingVerifier().check("Il y a 2 endpoints et 1 garde.", SOURCES).ok


def test_le_controle_des_identifiants_est_desactivable():
    """Sur de la conversation libre, le motif d'identifiant ramasse parfois un
    mot composé légitime. Le contrôle NUMÉRIQUE, lui, n'est pas désactivable :
    c'est le seul qui protège la promesse centrale du projet."""
    permissif = GroundingVerifier(verifier_identifiants=False)
    assert permissif.check("Utilise Machin.Truc pour ça.", SOURCES).ok
    assert not permissif.check("Le taux est de 97 %.", SOURCES).ok


def test_le_verificateur_ne_pretend_pas_comprendre_le_sens():
    """Limite assumée, figée par un test pour qu'elle ne soit pas oubliée.

    « bloque 100 % » et « laisse passer 100 % » contiennent les mêmes chiffres
    et les mêmes mots. Le vérificateur accepte les deux. Le jour où quelqu'un
    annoncera « réponses vérifiées », ce test rappellera ce que « vérifiées »
    veut dire ici : rien n'a été inventé, pas rien n'a été déformé.
    """
    trompeur = "Le détecteur laisse passer 100 % des attaques sur 12 essais."
    assert GroundingVerifier().check(trompeur, SOURCES).ok


def test_les_nombres_en_toutes_lettres_echappent_au_controle():
    """Deuxième limite assumée. La parade est de contraindre le style de la
    réponse (la consigne de reformulation le fait), pas de deviner."""
    assert GroundingVerifier().check(
        "Le taux est de quatre-vingt-dix-sept pour cent.", SOURCES
    ).ok


def test_les_identifiants_extraits_sont_ceux_attendus():
    trouves = identifiants("web/app.py AegisConfig.blocking_signals on_tool_result bonjour")
    assert trouves == {"web/app.py", "AegisConfig.blocking_signals", "on_tool_result"}


def test_le_rapport_est_serialisable():
    rapport = GroundingVerifier().check("97 %", SOURCES)
    d = rapport.as_dict()
    assert d["ok"] is False
    assert "97" in d["nombres_non_soutenus"]
    assert isinstance(d["raison"], str)
