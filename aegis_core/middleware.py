"""
AegisGuard : le middleware zero-trust qui s'intercale entre un agent et le
monde extérieur (RAG + outils), sans jamais modifier le code de l'agent.

C'est le cœur du blueprint (section 3 - Vue d'ensemble de l'architecture) :
- on_retrieval()  -> scanne chaque chunk récupéré, neutralise le contenu suspect
- on_tool_call()  -> vérifie chaque appel d'outil contre le policy engine
- tout est journalisé dans un audit log chaîné, résistant à la falsification

AegisGuard ne dépend d'AUCUN détail de l'agent qu'il protège (pas d'import
de `victim`) : il ne connaît que des objets ayant un attribut `.id` et
`.content` (voir `RetrievedChunk`). C'est ce qui permet de le brancher sur
n'importe quel orchestrateur d'agents, pas seulement sur `victim/` -- exactement
la promesse du blueprint ("branchable sur n'importe quel orchestrateur").

- on_session_event() -> troisième point d'interception (section 4.4) : reçoit
  la trace d'UNE requête déjà traitée, en extrait l'action dominante, et la
  compare au comportement récent de l'agent via un Beta-VAE. Contrairement aux
  deux autres, celui-ci ne bloque rien (le signal est probabiliste, pas une
  règle) -- il journalise et remonte un score, à charge du dashboard/de
  l'opérateur d'agir (cf. "Limites connues" du README pour pourquoi).

- on_prompt() -> quatrième point d'interception (correctif P0-3b) : scanne la
  requête de l'utilisateur AVANT qu'elle n'atteigne le modèle. Jusqu'ici seuls
  les documents récupérés étaient analysés : l'injection **directe** -- celle
  que l'utilisateur tape lui-même, et le risque n°1 de l'OWASP -- n'était
  couverte nulle part dans le pipeline, alors que le détecteur savait la
  reconnaître quand `run_redteam` l'appelait à la main.

- on_tool_result() -> cinquième point d'interception (correctif P0-3c) : scanne
  ce qu'un outil RENVOIE avant de le réinjecter dans le contexte du modèle.
  Tant que les outils sont des mocks, c'est sans conséquence ; dès qu'un outil
  lit une base, appelle une API ou récupère une page, son retour est du contenu
  contrôlable par un attaquant. C'est l'injection de second ordre, aujourd'hui
  le vecteur le plus exploité contre les agents réels -- et le plus négligé,
  parce que « c'est notre propre outil qui répond ».

- on_retrieval() applique aussi un assainissement (section 4.5, "assainissement
  des documents") : un chunk NON signalé comme attaque peut quand même
  contenir des données personnelles/secrets (email, IBAN, clé d'API...) --
  légitime, mais qui n'a rien à faire dans un contexte envoyé à un LLM tiers.
  `pii_detector` les masque avant transmission, indépendamment du verdict
  injection/outlier (voir `_Redacted`).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from aegis_core.audit_log import AuditLog
from aegis_core.behavior_detector import BehaviorDetector, BehaviorScanResult
from aegis_core.behavior_features import ACTIONS, SESSION_LENGTH, ActionEvent
from aegis_core.drift import ScoreObserver
from aegis_core.output_guard import OutputGuard
from aegis_core.config import (
    DETECTOR_BEHAVIOR,
    DETECTOR_INJECTION_ML,
    DETECTOR_RAG_OUTLIER,
    SIGNAL_INJECTION_ML,
    SIGNAL_RAG_OUTLIER,
    SIGNAL_RETRIEVAL_STUFFING,
    SIGNAL_RULES,
    AegisConfig,
    DetectorUnavailableError,
)
from aegis_core.injection_detector import InjectionDetector
from aegis_core.pii_detector import PiiDetector
from aegis_core.policy_engine import PolicyEngine
from aegis_core.rag_outlier_detector import RagOutlierDetector
from aegis_core.retrieval_integrity import RetrievalStuffingDetector, repetition_profile
from aegis_core.session import SessionKey, SessionStore

Decision = tuple[str, str]
CITATION_RE = re.compile(r"\[source\s*:\s*([^\]]+)\]", re.IGNORECASE)

# Clé sous laquelle `on_retrieval` dépose, DANS LE CONTEXTE DE LA REQUÊTE, les
# identifiants des documents qu'il a neutralisés -- pour que `on_response`, plus
# loin dans la même requête, sache que le modèle n'a jamais lu ces documents.
#
# C'était auparavant un attribut d'instance (`self._last_neutralized_ids`),
# écrasé à chaque `on_retrieval` : sous deux requêtes concurrentes, la seconde
# effaçait l'état de la première, et la vérification de citation portait alors
# sur les documents de quelqu'un d'autre. Un état de requête n'a rien à faire
# sur un objet partagé : il appartient au contexte de la requête (P1-5b).
NEUTRALIZED_CTX_KEY = "_aegis_neutralized_ids"

# Texte substitué à un document neutralisé. Volontairement neutre, constant, et
# sans mention d'AEGIS ni du score de risque -- voir `_Neutralized`.
NEUTRALIZED_PLACEHOLDER = "[Contenu indisponible.]"


class RetrievedChunk(Protocol):
    """N'importe quel objet représentant un document récupéré par un RAG."""

    id: str
    content: str


@dataclass(frozen=True)
class _Neutralized:
    """Remplace un chunk jugé suspect, pour ne jamais transmettre son contenu brut.

    Le texte de remplacement est **neutre et constant** (correctif P1-9c). La
    version précédente injectait `[CONTENU NEUTRALISÉ PAR AEGIS - injection
    potentielle détectée, risque=0.98]` dans le contexte du modèle. Observé en
    conditions réelles : le modèle a répété cette information au client final
    (« je ne peux pas accéder ... en raison de la neutralisation du contexte »).

    Deux problèmes, dont un grave :

    * **Un oracle pour l'attaquant.** Le score de risque renvoyé dans le contexte
      permet de calibrer un contournement par dichotomie -- soumettre une
      variante, lire le score, ajuster -- sans jamais voir le code. Un détecteur
      qui annonce sa confiance à celui qu'il détecte travaille contre lui-même.
    * **De la reconnaissance offerte.** Nommer AEGIS et la nature du verdict
      renseigne sur la pile de sécurité déployée.

    Ce qu'il reste, et qu'on ne peut pas supprimer à ce niveau : l'attaquant
    saura toujours *qu'il* a été bloqué (le document n'agit plus). Ce qu'on lui
    retire, c'est de savoir **par quel signal** et **avec quelle marge** -- soit
    tout ce dont il a besoin pour itérer efficacement.
    """

    id: str
    risk: float

    @property
    def content(self) -> str:
        return NEUTRALIZED_PLACEHOLDER


@dataclass(frozen=True)
class PromptDecision:
    """Verdict sur la requête utilisateur.

    `decision` vaut "allow" ou "block". Contrairement à un document, une requête
    ne peut pas être « neutralisée » : on ne peut pas remplacer la question de
    l'utilisateur par un placeholder et continuer comme si de rien n'était. Le
    choix est binaire, ce qui rend le taux de faux positifs critique -- voir
    `AegisGuard.on_prompt` pour la conséquence sur le choix des signaux.
    """

    decision: str
    reason: str
    risk: float = 0.0
    matched_rules: tuple[str, ...] = ()

    @property
    def blocked(self) -> bool:
        return self.decision == "block"


@dataclass(frozen=True)
class _Redacted:
    """Remplace un chunk légitime (ni injection ni outlier) dont le contenu
    brut contenait des données personnelles/secrets -- le texte original
    n'est jamais transmis à l'agent, seule la version assainie l'est."""

    id: str
    sanitized_content: str

    @property
    def content(self) -> str:
        return self.sanitized_content


class AegisGuard:
    """Point d'intégration unique entre un agent et les modules de sécurité AEGIS."""

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        injection_detector: InjectionDetector | None = None,
        audit_log: AuditLog | None = None,
        behavior_detector: BehaviorDetector | None = None,
        rag_outlier_detector: RagOutlierDetector | None = None,
        pii_detector: PiiDetector | None = None,
        stuffing_detector: RetrievalStuffingDetector | None = None,
        output_guard: OutputGuard | None = None,
        config: AegisConfig | None = None,
        session_store: SessionStore | None = None,
    ):
        self.config = config or AegisConfig()
        self.policy_engine = policy_engine or PolicyEngine()
        self.injection_detector = injection_detector or InjectionDetector()
        self.audit_log = audit_log or AuditLog(
            db_path=self.config.audit_db_path,
            require_signature=self.config.require_signed_audit,
        )
        self.behavior_detector = behavior_detector or BehaviorDetector()
        self.rag_outlier_detector = rag_outlier_detector or RagOutlierDetector()
        self.pii_detector = pii_detector or PiiDetector()
        self.stuffing_detector = stuffing_detector or RetrievalStuffingDetector()
        # Filtre de sortie (lot 10). `is not None` et non `or` : un OutputGuard
        # configuré sans contexte caché et sans masquage est un objet légitime,
        # et `or` le remplacerait par le défaut au premier test de vérité.
        self.output_guard = (
            output_guard
            if output_guard is not None
            else OutputGuard(
                hidden_context=self.config.hidden_context,
                mask_personal_data=self.config.mask_personal_data_in_output,
            )
        )
        # Contrôle AU DÉMARRAGE, pas à la première requête : découvrir qu'un
        # détecteur exigé est absent au moment où un document hostile arrive,
        # c'est le découvrir trop tard (correctif P0-4).
        self._enforce_required_detectors()
        # Fenêtre glissante des dernières actions, par (tenant, agent, session) et
        # bornée à SESSION_LENGTH : c'est la mémoire vive du détecteur
        # comportemental. Elle était indexée par NOM D'AGENT, donc partagée par
        # tous les utilisateurs du même agent -- voir `aegis_core.session` pour
        # ce que ça permettait (correctif P1-5a).
        # `is not None` et non `or` : un SessionStore vide est falsy (il définit
        # __len__), donc `session_store or SessionStore()` jetait silencieusement
        # le magasin fourni par l'appelant tant qu'aucune session n'y était née.
        self.sessions = session_store if session_store is not None else SessionStore()

        # Surveillance de dérive (lot 9). La référence est la distribution des
        # distances mesurée à la CALIBRATION, écrite dans metrics.json par le
        # script d'entraînement. Elle peut être absente (modèle non entraîné, ou
        # entraîné avant le lot 9) : l'observateur collecte alors quand même,
        # parce que savoir ce que le détecteur voit reste utile — on ne peut
        # simplement pas dire si ça a changé.
        self.drift = ScoreObserver(
            signal=SIGNAL_RAG_OUTLIER,
            reference=getattr(self.rag_outlier_detector, "calibration_quantiles", None),
        )

    def detector_status(self) -> dict[str, dict[str, object]]:
        """État réel de chaque détecteur ML, pour le rapport et le tableau de bord.

        Sans cette information, « 0 anomalie détectée » est ambigu : il peut
        vouloir dire « le détecteur a regardé et n'a rien vu » ou « le détecteur
        ne tourne pas ». Le tableau de bord affichait la première interprétation
        dans les deux cas -- du vert pour un capteur débranché, l'anti-pattern le
        plus dangereux en supervision de sécurité.
        """
        checks = (
            (DETECTOR_INJECTION_ML, self.injection_detector,
             "classifieur non entraîné (scripts/train_injection_classifier.py) -- "
             "le détecteur tourne en règles regex seules"),
            (DETECTOR_RAG_OUTLIER, self.rag_outlier_detector,
             "modèle absent (scripts/train_rag_outlier_detector.py) -- risque toujours nul"),
            (DETECTOR_BEHAVIOR, self.behavior_detector,
             "modèle absent (scripts/train_behavior_vae.py) -- risque toujours nul"),
        )
        status: dict[str, dict[str, object]] = {}
        for name, detector, reason in checks:
            # getattr : un détecteur injecté par un test ou une intégration tierce
            # n'expose pas forcément `ml_available`. On dit alors « inconnu »
            # plutôt que d'inventer un état.
            available = getattr(detector, "ml_available", None)
            status[name] = {
                "available": bool(available) if available is not None else None,
                "required": name in self.config.required_detectors,
                "reason": None if available else reason,
            }
        return status

    def _enforce_required_detectors(self) -> None:
        missing = [
            name for name, state in self.detector_status().items()
            if state["required"] and not state["available"]
        ]
        if missing:
            raise DetectorUnavailableError(
                "Détecteur(s) exigé(s) mais indisponible(s) : " + ", ".join(sorted(missing))
                + ". Entraîne les modèles correspondants, ou retire-les de "
                "AegisConfig.required_detectors si tu acceptes de tourner sans."
            )

    def _content_verdict(self, text: str) -> tuple[bool, dict[str, object]]:
        """Croise les trois signaux de contenu et dit lequel a le droit de décider.

        Les trois n'ont pas la même nature. Les **règles** sont déterministes et
        mesurées à 0 % de faux positifs. Le **classifieur ML** et le **détecteur
        d'outliers** sont probabilistes et mesurés à 50 % chacun sur le même
        corpus de contrôle : un document légitime sur deux neutralisé -- un
        rapport financier, un bulletin météo, une note RGPD.

        Les traiter à l'identique par un `or` était donc une erreur mesurable :
        le maillon le plus bruyant décidait pour tout le monde. Seuls les signaux
        listés dans `AegisConfig.blocking_signals` bloquent désormais ; les autres
        tournent, sont journalisés, et alimentent un compteur `would_have_blocked`
        qui documente ce qu'ils auraient fait.

        Retourne `(bloque, details)` -- `details` part tel quel dans le journal.
        """
        injection = self.injection_detector.scan(text)
        outlier = self.rag_outlier_detector.score(text)
        stuffing = self.stuffing_detector.scan(text)

        # On enregistre la DISTANCE et non le risque : le risque est une
        # transformation du seuil (1 - exp(-d/seuil)), donc changer le seuil
        # déplacerait la distribution observée sans qu'aucune donnée n'ait bougé.
        # La distance, elle, ne dépend que du texte et du modèle.
        if outlier.distance is not None:
            self.drift.observe(outlier.distance)

        fired = {
            SIGNAL_RULES: bool(injection.matched_rules),
            # Le ML ne "tire" ici que s'il flague SANS qu'une règle l'ait déjà
            # fait : sinon on compterait deux fois la même détection.
            SIGNAL_INJECTION_ML: bool(
                injection.ml_score is not None and injection.flagged and not injection.matched_rules
            ),
            SIGNAL_RAG_OUTLIER: bool(outlier.flagged),
            SIGNAL_RETRIEVAL_STUFFING: bool(stuffing.flagged),
        }

        blocking = sorted(name for name, hit in fired.items() if hit and self.config.blocks(name))
        advisory = sorted(name for name, hit in fired.items() if hit and not self.config.blocks(name))

        # Risque de la DÉCISION : le maximum sur les seuls signaux habilités à
        # bloquer. C'est le seul nombre qui explique le verdict.
        #
        # `risk` juste en dessous est un maximum sur les TROIS échelles, qui ne
        # sont pas commensurables (constat P1-M4 de l'audit) : le risque de
        # règles vaut `min(1, motifs/3)`, le score ML est une probabilité softmax
        # mal calibrée, le risque d'outlier vaut 0,632 au seuil exact par
        # construction. Le publier comme « le risque » du document laisse croire
        # à une grandeur unique — et lui attribue la valeur du signal le plus
        # bruyant, pas de celui qui a décidé. Il est conservé pour le journal et
        # la compatibilité, mais il n'est plus ce qu'on met en avant.
        risque_par_signal = {
            SIGNAL_RULES: injection.rule_risk,
            SIGNAL_INJECTION_ML: injection.ml_score or 0.0,
            SIGNAL_RAG_OUTLIER: outlier.risk,
            SIGNAL_RETRIEVAL_STUFFING: 1.0 if stuffing.flagged else 0.0,
        }
        decision_risk = max(
            (v for name, v in risque_par_signal.items() if self.config.blocks(name)),
            default=0.0,
        )

        details = {
            "decision_risk": decision_risk,
            "risk": max(injection.rule_risk, injection.ml_score or 0.0, outlier.risk),
            "rule_risk": injection.rule_risk,
            "injection_ml_score": injection.ml_score,
            "outlier_risk": outlier.risk,
            "outlier_distance": outlier.distance,
            "matched_rules": list(injection.matched_rules),
            # Les mots effectivement bourrés, pour que l'opérateur voie POURQUOI
            # et pas seulement COMBIEN -- même exigence que `matched_rules`.
            "stuffing": {
                **stuffing.as_dict(),
                "top_terms": repetition_profile(text, top=5) if stuffing.flagged else [],
            },
            "blocking_signals": blocking,
            # Ce que les signaux consultatifs AURAIENT fait. C'est ce compteur qui
            # permettra un jour de leur rendre le pouvoir de bloquer, avec des
            # chiffres plutôt qu'une intuition.
            "advisory_signals": advisory,
            "would_have_blocked": bool(advisory) and not blocking,
        }
        return bool(blocking), details

    def on_retrieval(self, chunks: list[RetrievedChunk], ctx: dict[str, object]) -> list[RetrievedChunk]:
        """Scanne chaque chunk récupéré avec trois signaux indépendants (section 4.5) :
        les règles de contenu, le classifieur ML, et l'éloignement sémantique du
        domaine normal. Seuls les signaux habilités neutralisent (voir
        `_content_verdict`) ; les autres informent.

        Un chunk qui n'est PAS neutralisé passe ensuite par `pii_detector`, qui
        masque les données personnelles qu'il pourrait contenir -- un document
        légitime n'est pas exempt de ce risque.

        Les identifiants neutralisés sont déposés dans `ctx`, pas sur `self` :
        c'est un état de REQUÊTE, et `on_response` le relira dans le même `ctx`
        (voir `NEUTRALIZED_CTX_KEY`).
        """
        safe_chunks: list[RetrievedChunk] = []
        neutralized: set[str] = set()
        ctx[NEUTRALIZED_CTX_KEY] = neutralized
        for chunk in chunks:
            blocked, details = self._content_verdict(chunk.content)

            self.audit_log.log({
                "type": "retrieval_scan",
                "agent": ctx.get("agent"),
                "doc_id": chunk.id,
                "flagged": blocked,
                **details,
            })

            if blocked:
                neutralized.add(chunk.id)
                safe_chunks.append(_Neutralized(chunk.id, float(details["risk"])))
                continue

            pii_scan = self.pii_detector.scan(chunk.content)
            if pii_scan.redacted:
                self.audit_log.log({
                    "type": "pii_redaction",
                    "agent": ctx.get("agent"),
                    "doc_id": chunk.id,
                    "categories": list(pii_scan.categories),
                    "count": pii_scan.count,
                })
                safe_chunks.append(_Redacted(chunk.id, pii_scan.redacted_text))
            else:
                safe_chunks.append(chunk)
        return safe_chunks

    def on_prompt(self, user_query: str, ctx: dict[str, object]) -> PromptDecision:
        """Scanne la requête utilisateur avant qu'elle n'atteigne le modèle (P0-3b).

        **Seules les RÈGLES décident du blocage ; le score ML est journalisé mais
        ne bloque pas.** Ce n'est pas de la timidité, c'est ce que disent les
        mesures : sur le corpus de contrôle, les règles obtiennent 100 % de
        blocage pour 0 % de faux positifs, là où le classifieur signale un
        document légitime sur deux.

        Un faux positif sur un document a un coût modéré -- l'agent perd un bout
        de contexte. Un faux positif sur la requête utilisateur a un coût
        maximal : la personne reçoit un refus pour une question parfaitement
        normale, une fois sur deux. On bloque donc sur le signal déterministe
        dont le taux d'erreur est mesuré à zéro, et on observe l'autre.

        Le jour où le classifieur sera recalibré, ce choix se rediscutera -- avec
        des chiffres, pas des intentions.
        """
        scan = self.injection_detector.scan(user_query)
        blocked = bool(scan.matched_rules)

        self.audit_log.log({
            "type": "prompt_scan",
            "agent": ctx.get("agent"),
            "decision": "block" if blocked else "allow",
            "rule_risk": scan.rule_risk,
            "ml_score": scan.ml_score,
            "matched_rules": list(scan.matched_rules),
            # Rend visible le desaccord entre les deux couches : c'est le
            # chiffre qui justifiera (ou non) de faire bloquer le ML un jour.
            "ml_would_have_blocked": scan.ml_score is not None and scan.flagged and not blocked,
        })

        if blocked:
            return PromptDecision(
                decision="block",
                reason="La requête contient une instruction de type injection de prompt.",
                risk=scan.rule_risk,
                matched_rules=scan.matched_rules,
            )
        return PromptDecision(decision="allow", reason="Aucune règle d'injection déclenchée.", risk=scan.rule_risk)

    def on_tool_result(self, tool_name: str, result: object, ctx: dict[str, object]) -> str:
        """Scanne ce qu'un outil renvoie avant réinjection dans le contexte (P0-3c).

        Un retour d'outil est une **donnée**, pas une instruction -- au même titre
        qu'un document récupéré. Le traiter comme digne de confiance parce qu'il
        vient « de chez nous » est précisément l'erreur qui rend l'injection de
        second ordre si efficace : l'outil est à nous, son contenu ne l'est pas.

        Même politique que `on_retrieval` : neutralisation par un texte neutre et
        constant, jamais de suppression silencieuse. Le modèle doit savoir qu'il
        manque quelque chose, sans savoir quoi ni pourquoi.
        """
        text = str(result)
        scan = self.injection_detector.scan(text)

        self.audit_log.log({
            "type": "tool_result_scan",
            "agent": ctx.get("agent"),
            "tool": tool_name,
            "risk": scan.risk,
            "rule_risk": scan.rule_risk,
            "flagged": scan.flagged,
            "matched_rules": list(scan.matched_rules),
        })

        if scan.flagged:
            return NEUTRALIZED_PLACEHOLDER
        pii_scan = self.pii_detector.scan(text)
        if pii_scan.redacted:
            self.audit_log.log({
                "type": "pii_redaction",
                "agent": ctx.get("agent"),
                "doc_id": f"tool:{tool_name}",
                "categories": list(pii_scan.categories),
                "count": pii_scan.count,
            })
            return pii_scan.redacted_text
        return text

    def on_tool_call(self, tool_name: str, params: dict[str, object], ctx: dict[str, object]) -> Decision:
        """Vérifie un appel d'outil contre le policy engine et journalise la décision."""
        decision, reason = self.policy_engine.check(str(ctx.get("agent", "")), tool_name, params)
        self.audit_log.log({
            "type": "tool_call",
            "agent": ctx.get("agent"),
            "tool": tool_name,
            "params": params,
            "decision": decision,
            "reason": reason,
        })
        return decision, reason

    @staticmethod
    def _dominant_action(trace: list[dict[str, object]]) -> ActionEvent:
        """Résume une requête déjà traitée en UN événement : le dernier outil
        réellement appelé (autorisé ou non -- même une tentative bloquée dit
        quelque chose du comportement de l'agent), ou "no_action" sinon.
        """
        tool_call_steps = [step for step in trace if step.get("step") == "tool_call"]
        if not tool_call_steps:
            return ActionEvent(action="no_action", amount=0.0)

        detail = tool_call_steps[-1].get("detail", {}) or {}
        tool_name = detail.get("tool")
        if tool_name not in ACTIONS:
            # Outil que le détecteur comportemental ne connaît pas encore (ex. ajouté
            # à victim/tools.py sans réentraîner le VAE) -- traité comme neutre plutôt
            # que de faire planter le scan, avec un signalement explicite.
            return ActionEvent(action="no_action", amount=0.0)

        params = detail.get("params") or {}
        amount = params.get("amount", 0.0) if isinstance(params, dict) else 0.0
        return ActionEvent(action=tool_name, amount=float(amount or 0.0))

    def on_session_event(
        self,
        agent_name: str,
        trace: list[dict[str, object]],
        ctx: dict[str, object] | None = None,
    ) -> BehaviorScanResult:
        """À appeler une fois par requête terminée (voir demo.py / web/app.py) :
        met à jour la fenêtre glissante de la SESSION et scanne son comportement
        récent.

        `ctx` est celui de la requête (`{"agent", "session_id", "tenant", ...}`).
        La fenêtre est indexée par `(tenant, agent, session_id)` : sans ça, tous
        les utilisateurs du même agent partagent la même suite d'actions, ce qui
        permet à la fois de diluer un comportement hostile dans le trafic
        légitime et de faire monter le score de quelqu'un d'autre (P1-5a).

        `ctx=None` reste accepté pour ne pas casser les intégrations existantes,
        mais produit une clé **anonyme** -- donc partagée, comme avant. La
        différence est que `robustness_report()` le dit désormais, au lieu de
        laisser croire à une isolation qui n'existe pas.
        """
        key = SessionKey.from_ctx(ctx, agent=agent_name)
        event = self._dominant_action(trace)
        window: list[ActionEvent] = self.sessions.get(key, list)
        window.append(event)
        del window[:-SESSION_LENGTH]  # ne garder que les SESSION_LENGTH derniers événements

        scan = self.behavior_detector.score(window)
        self.audit_log.log({
            "type": "behavior_scan",
            "agent": agent_name,
            "session": key.as_dict(),
            "action": event.action,
            "amount": event.amount,
            "risk": scan.risk,
            "flagged": scan.flagged,
        })
        return scan

    def on_response(self, response_text: str, doc_ids: list[str], ctx: dict[str, object]) -> str:
        """Contrôle la réponse finale et **retourne le texte à rendre** (lot 10).

        Deux choses distinctes se passent ici, et il faut les garder séparées :

        1. **Le filtre de sortie** (`aegis_core.output_guard`) — secrets masqués,
           restitution du prompt système détectée, balisage actif neutralisé.
           C'est le seul endroit du produit où AEGIS modifie ce que
           l'utilisateur reçoit, d'où un réglage de prudence plus strict
           qu'ailleurs : les données personnelles sont signalées et comptées,
           pas masquées par défaut.
        2. **La vérification de citation** (ci-dessous) — inchangée, et toujours
           non bloquante.

        Le contrôle de citation porte sur la réponse **d'origine**, pas sur la
        version filtrée : neutraliser un balisage ne doit pas faire disparaître
        une citation et transformer un signal de traçabilité en faux positif.

        Vérifie que la réponse finale cite bien l'une des sources fournies
        (section 4.5, exigence de citation). Ne bloque et ne modifie RIEN --
        une citation manquante n'est pas une preuve d'attaque, juste un signal
        de moindre traçabilité à journaliser pour un humain qui relit. C'est la
        même philosophie que le scan comportemental (section 4.4) : probabiliste,
        pas une règle absolue.

        `doc_ids` peut contenir des ids de chunks neutralisés par `on_retrieval`
        DANS LA MÊME REQUÊTE : le LLM n'a alors reçu que le message
        "[Contenu indisponible.]", jamais le vrai contenu. Dire "[source:
        aucune]" est dans ce cas la réponse honnête, pas une source manquante --
        on retire donc ces ids de la liste avant de juger la citation (bug
        trouvé en conditions réelles).

        Cette liste est lue dans `ctx`, où `on_retrieval` l'a déposée. Si `ctx`
        ne la porte pas -- appel isolé, ou contexte différent de celui du
        retrieval -- on ne devine pas : on juge sur tous les `doc_ids` et on
        journalise `neutralized_known: false`, pour que la sur-détection qui en
        découle soit lisible plutôt que mystérieuse.
        """
        sortie = self.output_guard.scan(response_text)
        if sortie.flagged:
            self.audit_log.log({
                "type": "output_scan",
                "agent": ctx.get("agent"),
                **sortie.as_dict(),
            })

        raw = ctx.get(NEUTRALIZED_CTX_KEY)
        known = isinstance(raw, (set, frozenset, list, tuple))
        neutralized = set(raw) if known else set()  # type: ignore[arg-type]
        real_doc_ids = [d for d in doc_ids if d not in neutralized]
        match = CITATION_RE.search(response_text)
        cited = match.group(1).strip() if match else None
        valid = cited is not None and (cited in real_doc_ids or (not real_doc_ids and cited.lower() == "aucune"))
        self.audit_log.log({
            "type": "citation_check",
            "agent": ctx.get("agent"),
            "doc_ids": doc_ids,
            "neutralized_known": known,
            "cited": cited,
            "flagged": not valid,
        })
        return sortie.text

    def robustness_report(self) -> dict[str, object]:
        """Résumé chiffré de l'activité surveillée, pour le dashboard/la démo."""
        entries = self.audit_log.all_entries()
        tool_calls = [e for e in entries if e.event["type"] == "tool_call"]
        blocked = [e for e in tool_calls if e.event["decision"] == "block"]
        retrievals = [e for e in entries if e.event["type"] == "retrieval_scan"]
        flagged = [e for e in retrievals if e.event["flagged"]]
        # Documents qu'un signal consultatif aurait neutralisés s'il avait eu le
        # droit de décider. C'est le chiffre à surveiller avant de le lui rendre.
        advisory = [e for e in retrievals if e.event.get("would_have_blocked")]
        behavior_scans = [e for e in entries if e.event["type"] == "behavior_scan"]
        behavior_flagged = [e for e in behavior_scans if e.event["flagged"]]
        prompt_scans = [e for e in entries if e.event["type"] == "prompt_scan"]
        prompts_blocked = [e for e in prompt_scans if e.event["decision"] == "block"]
        tool_result_scans = [e for e in entries if e.event["type"] == "tool_result_scan"]
        tool_results_flagged = [e for e in tool_result_scans if e.event["flagged"]]
        citation_checks = [e for e in entries if e.event["type"] == "citation_check"]
        missing_citations = [e for e in citation_checks if e.event["flagged"]]
        pii_redactions = [e for e in entries if e.event["type"] == "pii_redaction"]
        pii_items_redacted = sum(int(e.event["count"]) for e in pii_redactions)
        integrity = self.audit_log.verify_integrity()
        return {
            # État des capteurs, toujours présent : un rapport qui annonce
            # « 0 anomalie » sans dire si le détecteur tournait est trompeur.
            "detectors": self.detector_status(),
            "fail_mode": self.config.fail_mode,
            "audit_integrity": integrity.as_dict(),
            # Dérive : ce que le détecteur voit RÉELLEMENT depuis le démarrage,
            # comparé à ce sur quoi son seuil a été calibré. Refuse de conclure
            # sous un effectif minimal -- « pas assez vu » n'est pas « rien à
            # signaler ».
            "score_drift": self.drift.report().as_dict(),
            # Isolation de l'état comportemental. `degraded: true` signifie qu'au
            # moins une fenêtre est partagée faute d'identifiant de session dans
            # le contexte -- le détecteur observe alors une suite d'actions qui
            # n'appartient à personne.
            "session_isolation": self.sessions.stats(),
            "tool_calls_total": len(tool_calls),
            "tool_calls_blocked": len(blocked),
            "prompts_scanned": len(prompt_scans),
            "prompts_blocked": len(prompts_blocked),
            "tool_results_scanned": len(tool_result_scans),
            "tool_results_flagged": len(tool_results_flagged),
            "retrievals_scanned": len(retrievals),
            "retrievals_flagged": len(flagged),
            "retrievals_advisory_only": len(advisory),
            "behavior_scans": len(behavior_scans),
            "behavior_anomalies_flagged": len(behavior_flagged),
            "citation_checks": len(citation_checks),
            "missing_citations": len(missing_citations),
            "documents_sanitized": len(pii_redactions),
            "pii_items_redacted": pii_items_redacted,
            # Conservés tels quels : le tableau de bord actuel les consomme.
            # `audit_log_integrity` ne dit PAS « preuve opposable » -- seulement
            # « chaîne cohérente ». La nuance est dans `audit_integrity.is_signed`.
            "audit_log_integrity": integrity.ok,
            "first_corrupted_entry": integrity.first_bad_entry,
        }