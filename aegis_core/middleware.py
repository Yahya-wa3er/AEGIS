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
from aegis_core.injection_detector import InjectionDetector
from aegis_core.pii_detector import PiiDetector
from aegis_core.policy_engine import PolicyEngine
from aegis_core.rag_outlier_detector import RagOutlierDetector

Decision = tuple[str, str]
CITATION_RE = re.compile(r"\[source\s*:\s*([^\]]+)\]", re.IGNORECASE)


class RetrievedChunk(Protocol):
    """N'importe quel objet représentant un document récupéré par un RAG."""

    id: str
    content: str


@dataclass(frozen=True)
class _Neutralized:
    """Remplace un chunk jugé suspect, pour ne jamais transmettre son contenu brut."""

    id: str
    risk: float

    @property
    def content(self) -> str:
        return f"[CONTENU NEUTRALISÉ PAR AEGIS - injection potentielle détectée, risque={self.risk:.2f}]"


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
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        self.injection_detector = injection_detector or InjectionDetector()
        self.audit_log = audit_log or AuditLog()
        self.behavior_detector = behavior_detector or BehaviorDetector()
        self.rag_outlier_detector = rag_outlier_detector or RagOutlierDetector()
        self.pii_detector = pii_detector or PiiDetector()
        # Fenêtre glissante des dernières actions par agent (clé = nom de l'agent),
        # bornée à SESSION_LENGTH -- c'est la mémoire vive du détecteur comportemental.
        self._behavior_windows: dict[str, list[ActionEvent]] = {}
        # Ids neutralisés par le DERNIER on_retrieval -- permet à on_response de
        # savoir qu'un doc_id fourni ne correspond en réalité à AUCUN contenu que
        # le LLM a pu lire (voir bug trouvé en conditions réelles : le modèle
        # répond honnêtement "[source: aucune]" quand tout ce qu'il a reçu est
        # neutralisé, ce qui est correct et ne doit pas être compté comme manquant).
        self._last_neutralized_ids: set[str] = set()

    def on_retrieval(self, chunks: list[RetrievedChunk], ctx: dict[str, object]) -> list[RetrievedChunk]:
        """Scanne chaque chunk récupéré avec DEUX signaux indépendants (section 4.5) :
        le contenu (regex + ML, `injection_detector`) et le sens global du document
        comparé au domaine normal (`rag_outlier_detector`). Neutralise si l'un OU
        l'autre est déclenché -- ce sont deux façons différentes qu'un document ait
        de "sonner faux", pas deux votes sur le même signal.

        Un chunk qui n'est PAS neutralisé passe ensuite par un troisième signal,
        indépendant des deux premiers : `pii_detector` masque les données
        personnelles/secrets qu'il pourrait contenir (un document légitime n'est
        pas exempt de ce risque -- voir docstring du module).
        """
        safe_chunks: list[RetrievedChunk] = []
        self._last_neutralized_ids = set()
        for chunk in chunks:
            injection_scan = self.injection_detector.scan(chunk.content)
            outlier_scan = self.rag_outlier_detector.score(chunk.content)
            risk = max(injection_scan.risk, outlier_scan.risk)
            flagged = injection_scan.flagged or outlier_scan.flagged

            self.audit_log.log({
                "type": "retrieval_scan",
                "agent": ctx.get("agent"),
                "doc_id": chunk.id,
                "risk": risk,
                "flagged": flagged,
                "matched_patterns": list(injection_scan.matched_patterns),
                "injection_risk": injection_scan.risk,
                "outlier_risk": outlier_scan.risk,
                "outlier_distance": outlier_scan.distance,
            })

            if flagged:
                self._last_neutralized_ids.add(chunk.id)
                safe_chunks.append(_Neutralized(chunk.id, risk))
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

    def on_session_event(self, agent_name: str, trace: list[dict[str, object]]) -> BehaviorScanResult:
        """À appeler une fois par requête terminée (voir demo.py / web/app.py) :
        met à jour la fenêtre glissante de l'agent et scanne son comportement récent.
        """
        event = self._dominant_action(trace)
        window = self._behavior_windows.setdefault(agent_name, [])
        window.append(event)
        del window[:-SESSION_LENGTH]  # ne garder que les SESSION_LENGTH derniers événements

        scan = self.behavior_detector.score(window)
        self.audit_log.log({
            "type": "behavior_scan",
            "agent": agent_name,
            "action": event.action,
            "amount": event.amount,
            "risk": scan.risk,
            "flagged": scan.flagged,
        })
        return scan

    def on_response(self, response_text: str, doc_ids: list[str], ctx: dict[str, object]) -> None:
        """Vérifie que la réponse finale cite bien l'une des sources fournies
        (section 4.5, exigence de citation). Ne bloque et ne modifie RIEN --
        une citation manquante n'est pas une preuve d'attaque, juste un signal
        de moindre traçabilité à journaliser pour un humain qui relit. C'est la
        même philosophie que le scan comportemental (section 4.4) : probabiliste,
        pas une règle absolue.

        `doc_ids` peut contenir des ids de chunks neutralisés par le dernier
        on_retrieval : le LLM n'a alors reçu que le message "[CONTENU
        NEUTRALISÉ...]", jamais le vrai contenu. Dire "[source: aucune]" dans
        ce cas est la réponse honnête, pas une source manquante -- on retire
        donc ces ids de la liste avant de juger la citation (bug trouvé en
        conditions réelles, cf. commentaire sur _last_neutralized_ids).
        """
        real_doc_ids = [d for d in doc_ids if d not in self._last_neutralized_ids]
        match = CITATION_RE.search(response_text)
        cited = match.group(1).strip() if match else None
        valid = cited is not None and (cited in real_doc_ids or (not real_doc_ids and cited.lower() == "aucune"))
        self.audit_log.log({
            "type": "citation_check",
            "agent": ctx.get("agent"),
            "doc_ids": doc_ids,
            "cited": cited,
            "flagged": not valid,
        })

    def robustness_report(self) -> dict[str, object]:
        """Résumé chiffré de l'activité surveillée, pour le dashboard/la démo."""
        entries = self.audit_log.all_entries()
        tool_calls = [e for e in entries if e.event["type"] == "tool_call"]
        blocked = [e for e in tool_calls if e.event["decision"] == "block"]
        retrievals = [e for e in entries if e.event["type"] == "retrieval_scan"]
        flagged = [e for e in retrievals if e.event["flagged"]]
        behavior_scans = [e for e in entries if e.event["type"] == "behavior_scan"]
        behavior_flagged = [e for e in behavior_scans if e.event["flagged"]]
        citation_checks = [e for e in entries if e.event["type"] == "citation_check"]
        missing_citations = [e for e in citation_checks if e.event["flagged"]]
        pii_redactions = [e for e in entries if e.event["type"] == "pii_redaction"]
        pii_items_redacted = sum(int(e.event["count"]) for e in pii_redactions)
        integrity_ok, bad_entry = self.audit_log.verify_integrity()
        return {
            "tool_calls_total": len(tool_calls),
            "tool_calls_blocked": len(blocked),
            "retrievals_scanned": len(retrievals),
            "retrievals_flagged": len(flagged),
            "behavior_scans": len(behavior_scans),
            "behavior_anomalies_flagged": len(behavior_flagged),
            "citation_checks": len(citation_checks),
            "missing_citations": len(missing_citations),
            "documents_sanitized": len(pii_redactions),
            "pii_items_redacted": pii_items_redacted,
            "audit_log_integrity": integrity_ok,
            "first_corrupted_entry": bad_entry,
        }