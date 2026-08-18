"""
Limitation de débit et jeton partagé (OWASP LLM06).

Ces tests protègent une facture autant qu'une API : sans plafond, l'URL de la
démonstration est un endpoint qui déclenche de vrais appels LLM pour quiconque
sait écrire une boucle.
"""
from __future__ import annotations

import pytest

from web import ratelimit
from web.ratelimit import RateLimiter


class Horloge:
    """Temps piloté : un test de débit qui dort vraiment est un test qu'on finit
    par désactiver parce qu'il ralentit la suite."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def avance(self, secondes: float) -> None:
        self.t += secondes


def _limiteur(**kw) -> tuple[RateLimiter, Horloge]:
    horloge = Horloge()
    return RateLimiter(clock=horloge, **kw), horloge


def test_la_rafale_passe_puis_le_rythme_sappplique():
    limiteur, _ = _limiteur(rate_per_minute=60, burst=3)
    assert [limiteur.check("1.2.3.4")[0] for _ in range(3)] == [True, True, True]
    autorise, attente = limiteur.check("1.2.3.4")
    assert autorise is False
    assert attente > 0


def test_le_seau_se_recharge_avec_le_temps():
    limiteur, horloge = _limiteur(rate_per_minute=60, burst=2)
    limiteur.check("1.2.3.4")
    limiteur.check("1.2.3.4")
    assert limiteur.check("1.2.3.4")[0] is False
    horloge.avance(1.0)  # 60/min => 1 jeton par seconde
    assert limiteur.check("1.2.3.4")[0] is True


def test_le_seau_ne_depasse_jamais_la_rafale():
    """Sans plafond, une longue inactivité permettrait une rafale illimitée —
    exactement ce qu'un seau à jetons doit empêcher."""
    limiteur, horloge = _limiteur(rate_per_minute=60, burst=2)
    horloge.avance(3600)
    assert [limiteur.check("1.2.3.4")[0] for _ in range(3)] == [True, True, False]


def test_les_clients_ont_des_seaux_distincts():
    """Sinon le premier visiteur ferme la démonstration à tous les autres."""
    limiteur, _ = _limiteur(rate_per_minute=60, burst=1)
    assert limiteur.check("1.1.1.1")[0] is True
    assert limiteur.check("2.2.2.2")[0] is True
    assert limiteur.check("1.1.1.1")[0] is False


def test_les_seaux_inactifs_sont_oublies():
    """La clé vient du client, donc le nombre de clés aussi : un dictionnaire
    non borné rejouerait le défaut corrigé sur l'état par session."""
    limiteur, horloge = _limiteur(rate_per_minute=60, burst=1, ttl_seconds=10)
    limiteur.check("1.1.1.1")
    horloge.avance(11)
    limiteur.check("2.2.2.2")
    assert limiteur.stats()["clients_suivis"] == 1


def test_le_plafond_de_seaux_est_respecte():
    limiteur, _ = _limiteur(rate_per_minute=60, burst=1, max_buckets=5, ttl_seconds=10_000)
    for i in range(50):
        limiteur.check(f"10.0.0.{i}")
    assert limiteur.stats()["clients_suivis"] <= 5


# -- configuration ---------------------------------------------------------


def test_les_valeurs_viennent_de_lenvironnement(monkeypatch):
    monkeypatch.setenv(ratelimit.ENV_RATE, "42")
    monkeypatch.setenv(ratelimit.ENV_BURST, "7")
    limiteur = ratelimit.from_env()
    assert (limiteur.rate_per_minute, limiteur.burst) == (42.0, 7)


def test_une_valeur_illisible_retombe_sur_le_defaut(monkeypatch):
    """Une faute de frappe ne doit ni faire planter le serveur ni désactiver la
    limite en silence — les deux échecs sont pires que la valeur par défaut."""
    monkeypatch.setenv(ratelimit.ENV_RATE, "beaucoup")
    monkeypatch.setenv(ratelimit.ENV_BURST, "-3")
    limiteur = ratelimit.from_env()
    assert limiteur.rate_per_minute == ratelimit.DEFAULT_RATE_PER_MINUTE
    assert limiteur.burst == ratelimit.DEFAULT_BURST


def test_la_demo_est_ouverte_par_defaut(monkeypatch):
    """Ouverte, mais par CHOIX : le jeton existe, il n'est simplement pas exigé
    tant que la variable n'est pas définie."""
    monkeypatch.delenv(ratelimit.ENV_TOKEN, raising=False)
    assert ratelimit.expected_token() is None


def test_un_jeton_configure_est_exige(monkeypatch):
    monkeypatch.setenv(ratelimit.ENV_TOKEN, "  secret  ")
    assert ratelimit.expected_token() == "secret"


# -- enveloppe globale ------------------------------------------------------


def test_le_seau_par_client_ne_borne_pas_la_facture():
    """Le défaut que `BudgetGlobal` existe pour corriger, écrit noir sur blanc.

    Cent clients respectant chacun scrupuleusement leur quota consomment cent
    fois le quota. Une limite par client mesure la politesse, pas la dépense.
    """
    limiteur, _ = _limiteur(rate_per_minute=60, burst=5)
    passes = sum(limiteur.check(f"10.0.0.{i}")[0] for i in range(100))
    assert passes == 100


def test_l_enveloppe_globale_coupe_tous_clients_confondus():
    horloge = Horloge()
    budget = ratelimit.BudgetGlobal(max_calls=3, clock=horloge)
    assert [budget.check()[0] for _ in range(3)] == [True, True, True]
    autorise, liberation = budget.check()
    assert autorise is False
    assert liberation > 0


def test_l_enveloppe_glisse_au_lieu_de_se_reinitialiser():
    """Fenêtre glissante, pas compteur remis à zéro à l'heure ronde.

    Un compteur par fenêtre fixe laisse passer deux fois l'enveloppe à cheval
    sur deux fenêtres : c'est la même faute que celle qu'évite le seau à jetons
    côté client, et elle coûterait ici le double de la facture prévue.
    """
    horloge = Horloge()
    budget = ratelimit.BudgetGlobal(max_calls=2, window_seconds=3600.0, clock=horloge)
    assert budget.check()[0] is True
    horloge.avance(3599)
    assert budget.check()[0] is True
    # L'enveloppe est pleine : le premier appel a encore une seconde à vivre.
    assert budget.check()[0] is False
    horloge.avance(2)
    # Seule la place du premier appel s'est libérée, pas les deux.
    assert budget.check()[0] is True
    assert budget.check()[0] is False


def test_l_enveloppe_desactivee_laisse_tout_passer():
    budget = ratelimit.BudgetGlobal(max_calls=0)
    assert all(budget.check()[0] for _ in range(50))
    assert budget.stats() == {"actif": False, "max_par_heure": 0}


def test_zero_dans_l_environnement_desactive_vraiment_le_budget(monkeypatch):
    """`from_env` remplace 0 par le défaut ; `budget_from_env` ne le fait pas.

    La différence est intentionnelle : désactiver l'enveloppe est un choix
    légitime (plafond de dépense côté fournisseur), et le réactiver en silence
    tromperait autant que le désactiver en silence.
    """
    monkeypatch.setenv(ratelimit.ENV_BUDGET, "0")
    assert ratelimit.budget_from_env().max_calls == 0
    monkeypatch.setenv(ratelimit.ENV_BUDGET, "n'importe quoi")
    assert ratelimit.budget_from_env().max_calls == ratelimit.DEFAULT_CALLS_PER_HOUR


def test_l_enveloppe_ne_retient_pas_les_appels_sortis_de_la_fenetre():
    """L'état est borné par la fenêtre, pas par le trafic.

    Sans purge, la file grandirait indéfiniment sur une instance qui tourne des
    semaines -- le défaut d'état non borné, à nouveau."""
    horloge = Horloge()
    budget = ratelimit.BudgetGlobal(max_calls=1000, window_seconds=60.0, clock=horloge)
    for _ in range(200):
        budget.check()
        horloge.avance(1)
    assert budget.stats()["consommes"] <= 61


# -- intégration sur l'API -------------------------------------------------


@pytest.fixture
def client(monkeypatch):
    """Remplace le limiteur de l'application, sans recharger le module.

    La première version faisait `importlib.reload(web.app)`. Ça marchait pour ce
    fichier et cassait un autre : `reload` réécrit le dictionnaire du module,
    partagé par toute la session pytest, donc le seau vidé ici restait vide pour
    `tests/test_web_app.py`, qui recevait 429 au lieu de 404. Un test qui laisse
    l'application dans un état différent de celui qu'il a trouvé ne teste plus
    seulement son sujet.

    `monkeypatch.setattr` sur `app.state` restaure l'objet d'origine en sortie
    de test -- l'isolation est garantie par la construction, pas par la
    discipline.

    Deux points que la première version avait ratés, et qui n'apparaissaient que
    sur une machine correctement configurée :

    **1. L'horloge est figée.** Le seau se recharge en temps réel. Sans clé
    d'API, chaque requête échouait en quelques millisecondes et le seau restait
    vide : le test passait. AVEC une clé, chaque requête déclenche un vrai
    aller-retour LLM d'une seconde ou plus, le seau se recharge entre deux
    appels, et les cinq passent. Le test ne mesurait donc pas la limitation mais
    la lenteur du réseau -- il passait chez qui ne pouvait pas s'en servir et
    échouait chez qui le pouvait. Une horloge figée rend l'arithmétique du seau
    déterministe, ce qui est le sujet ; le rechargement dans le temps est déjà
    couvert par les tests unitaires à horloge pilotée, plus haut.

    **2. Aucun appel LLM réel.** Corollaire du point précédent : sur la machine
    de Yahya, ces tests appelaient *effectivement* OpenRouter, une dizaine de
    fois par exécution de la suite. Une suite de tests qui dépense de l'argent
    est une suite qu'on finit par ne plus lancer -- et c'est particulièrement
    savoureux dans le fichier censé prouver qu'on a bouché *Unbounded
    Consumption*. `handle_request` est donc neutralisé : passer la garde donne
    un 500, être refusé donne 429 ou 503. La distinction est nette et gratuite.
    """
    from fastapi.testclient import TestClient
    from victim.agent import VictimAgent

    import web.app as module

    monkeypatch.delenv(ratelimit.ENV_TOKEN, raising=False)
    monkeypatch.setattr(
        module.app.state,
        "rate_limiter",
        ratelimit.RateLimiter(rate_per_minute=60, burst=2, clock=lambda: 1000.0),
    )
    monkeypatch.setattr(
        module.app.state, "llm_budget", ratelimit.BudgetGlobal(max_calls=1000)
    )

    def _pas_d_appel_reel(*_a, **_kw):
        raise RuntimeError("appel LLM interdit dans les tests de limitation")

    monkeypatch.setattr(VictimAgent, "handle_request", _pas_d_appel_reel)
    return TestClient(module.app, raise_server_exceptions=False)


def test_les_endpoints_llm_sont_limites(client):
    """Rafale de 2, puis refus -- et exactement ça, pas « au moins un 429 ».

    L'assertion d'origine était `429 in codes`. Trop lâche : elle acceptait
    aussi bien 4 refus sur 5 qu'un seul, donc elle n'aurait pas vu un seau mal
    dimensionné. Avec une horloge figée, le compte est déterministe et peut
    être écrit en toutes lettres.
    """
    codes = [client.post("/api/simulate/unprotected").status_code for _ in range(5)]
    # 500 = la garde a laissé passer et l'agent neutralisé a levé.
    assert codes == [500, 500, 429, 429, 429], codes


def test_les_endpoints_sans_llm_ne_sont_pas_limites(client):
    """Le banc de scénarios, l'analyse de document et le classement ne coûtent
    rien : les brider punirait l'usage qu'on veut encourager."""
    codes = {
        client.post("/api/analyze-document", json={"content": "bonjour", "filename": None}).status_code
        for _ in range(8)
    }
    assert codes == {200}


def test_le_message_429_oriente_vers_ce_qui_reste_disponible(client):
    client.post("/api/simulate/unprotected")
    client.post("/api/simulate/unprotected")
    reponse = client.post("/api/simulate/unprotected")
    assert reponse.status_code == 429
    assert "Retry-After" in reponse.headers
    assert "aucun" in reponse.json()["detail"]


def test_le_jeton_partage_est_verifie(client, monkeypatch):
    # Le jeton est relu à CHAQUE requête (`ratelimit.expected_token()`), pas
    # figé au démarrage : `monkeypatch.setenv` suffit donc, sans reload.
    monkeypatch.setenv(ratelimit.ENV_TOKEN, "secret-de-demo")

    assert client.post("/api/simulate/unprotected").status_code == 401
    assert client.post(
        "/api/simulate/unprotected", headers={ratelimit.HEADER_TOKEN: "faux"}
    ).status_code == 401
    # Avec le bon jeton, la garde laisse passer -- et l'agent neutralisé lève,
    # d'où le 500. C'est ce 500 qui prouve qu'on est allé PLUS LOIN que
    # l'authentification : un 401 de plus ne l'aurait pas montré.
    assert client.post(
        "/api/simulate/unprotected", headers={ratelimit.HEADER_TOKEN: "secret-de-demo"}
    ).status_code == 500


def test_un_refus_d_authentification_ne_coute_rien_a_personne(client, monkeypatch):
    """Le jeton refusé ne doit consommer ni le seau, ni l'enveloppe.

    Sinon une boucle sans jeton -- gratuite pour l'attaquant, aucun appel LLM
    déclenché -- suffirait à faire refuser les visiteurs légitimes et à épuiser
    le budget de tous. Le contrôle d'authentification est placé AVANT les deux
    compteurs pour cette raison, et rien ne figeait cet ordre.
    """
    import web.app as module

    monkeypatch.setenv(ratelimit.ENV_TOKEN, "secret-de-demo")
    budget = ratelimit.BudgetGlobal(max_calls=1000)
    module.app.state.llm_budget = budget

    for _ in range(10):
        assert client.post("/api/simulate/unprotected").status_code == 401

    assert budget.stats()["consommes"] == 0
    assert module.app.state.rate_limiter.stats()["clients_suivis"] == 0


def test_la_garde_lit_le_limiteur_de_l_application(client):
    """Pin de conception : le limiteur doit être remplaçable par requête d'app.

    Ce test existe à cause d'une vraie régression. Tant que le limiteur était
    une variable de module, le reconfigurer imposait `importlib.reload`, qui
    contaminait les autres fichiers de tests (429 au lieu de 404 ailleurs). Si
    quelqu'un revient à un singleton de module, la garde cessera de consulter
    `app.state` et ce test tombera avant que la contamination ne réapparaisse.
    """
    import web.app as module

    class _Refuse:
        appels = 0

        def check(self, _client):
            _Refuse.appels += 1
            return False, 42.0

    module.app.state.rate_limiter = _Refuse()
    reponse = client.post("/api/simulate/unprotected")
    assert reponse.status_code == 429
    assert _Refuse.appels == 1
    assert reponse.headers["Retry-After"] == "42"


def test_l_enveloppe_epuisee_repond_503_et_oriente(client):
    """503 et non 429 : ce n'est pas « ralentis », c'est « l'instance ne peut
    plus servir cet écran ». Confondre les deux enverrait le client réessayer."""
    import web.app as module

    # Enveloppe d'une seule unité, déjà consommée : la requête suivante tombe
    # sur le budget et non sur le seau (burst=2, intact).
    epuise = ratelimit.BudgetGlobal(max_calls=1)
    epuise.check()
    module.app.state.llm_budget = epuise

    reponse = client.post("/api/simulate/unprotected")
    assert reponse.status_code == 503
    assert "Retry-After" in reponse.headers
    assert "aucun de ces écrans n'appelle de modèle" in reponse.json()["detail"]


def test_le_budget_n_est_entame_que_par_un_appel_qui_serait_parti(client):
    """Ordre des gardes : un client bridé ne doit pas consommer l'enveloppe des
    autres. Sinon une boucle `curl` refusée en 429 épuiserait quand même le
    budget global -- un déni de service sur le portefeuille sans dépenser un
    centime."""
    import web.app as module

    budget = ratelimit.BudgetGlobal(max_calls=1000)
    module.app.state.llm_budget = budget
    # burst=2 et horloge figée dans le fixture : sur 6 appels, exactement 2
    # passent la garde. Sans horloge figée, le nombre dépendrait de la durée
    # des requêtes -- c'est-à-dire de la latence du réseau.
    for _ in range(6):
        client.post("/api/simulate/unprotected")
    assert budget.stats()["consommes"] == 2
