/**
 * Traduction des données brutes en phrases lisibles.
 *
 * Un journal d'audit est illisible pour qui n'a pas écrit le code. Cette
 * couche existe pour qu'un spectateur non technique comprenne ce qui s'est
 * passé — c'est la moitié de l'intérêt d'une démonstration.
 */
import type { AuditEntry, Verdict } from "./types";

export const STEP_LABELS: Record<string, string> = {
  prompt_scan: "Analyse de la requête",
  retrieval: "Récupération",
  llm_response: "Réponse LLM",
  tool_call: "Appel d'outil",
  tool_result: "Retour d'outil",
  final_response: "Réponse finale",
};

export const SENSITIVE_TOOLS = ["transfer_funds", "send_email"];

/** Nom lisible de chaque signal, et ce que sa présence signifie. */
export const SIGNAL_LABELS: Record<string, { nom: string; quoi: string }> = {
  rules: {
    nom: "Règles déterministes",
    quoi: "Motifs d'injection sur les vues normalisées. Seul signal habilité à bloquer.",
  },
  injection_ml: {
    nom: "Classifieur ML",
    quoi: "DistilBERT fine-tuné. Consultatif : 50 % [24-76 %] de faux positifs mesurés.",
  },
  rag_outlier: {
    nom: "Outliers RAG",
    quoi: "Distance au domaine documentaire. Consultatif : signale la moitié du légitime hors-domaine.",
  },
  retrieval_stuffing: {
    nom: "Intégrité du classement",
    quoi: "Redondance lexicale anormale : document fabriqué pour être récupéré. Consultatif.",
  },
};

export type VerdictTone = "ok" | "warn" | "danger" | "muted";

export const VERDICT_TONE: Record<Verdict["kind"], VerdictTone> = {
  attack_succeeded: "danger",
  attack_neutralized: "ok",
  // Ni une attaque réussie ni un succès : un agent qui a fait quelque chose
  // qu'il ne devait pas, sans attaquant.
  excessive_agency: "warn",
  nominal: "ok",
};

export const TONE_CLASS: Record<VerdictTone, string> = {
  ok: "text-[var(--ok)] border-[var(--ok)]/35 bg-[var(--ok)]/10",
  warn: "text-[var(--warn)] border-[var(--warn)]/35 bg-[var(--warn)]/10",
  danger: "text-[var(--danger)] border-[var(--danger)]/35 bg-[var(--danger)]/10",
  muted: "text-[var(--muted)] border-[var(--line)] bg-white/[0.03]",
};

/** Verdict du banc de scénarios → ton visuel. */
export function toneForScenarioVerdict(verdict: string): VerdictTone {
  if (verdict.includes("bloqué") || verdict.includes("neutralisé") || verdict.includes("refusé")) {
    return "ok";
  }
  return "muted";
}

export function describeEvent(event: Record<string, unknown>): { text: string; ok: boolean } {
  const type = String(event.type);

  if (type === "retrieval_scan") {
    const flagged = Boolean(event.flagged);
    const risk = Number(event.risk ?? 0).toFixed(2);
    return {
      text: `Document « ${event.doc_id} » analysé (risque ${risk}) → ${flagged ? "neutralisé, contenu suspect" : "jugé sûr"}`,
      ok: !flagged,
    };
  }
  if (type === "tool_call") {
    const blocked = event.decision === "block";
    return {
      text: `Demande d'action « ${event.tool} » → ${blocked ? `bloquée (${event.reason ?? "hors politique"})` : "autorisée"}`,
      ok: !blocked,
    };
  }
  if (type === "behavior_scan") {
    const flagged = Boolean(event.flagged);
    const session = event.session as { session_id?: string } | undefined;
    const portee = session?.session_id ? ` [session ${session.session_id}]` : "";
    return {
      text: `Comportement observé : « ${event.action} »${portee} → ${flagged ? "enchaînement inhabituel détecté" : "cohérent avec l'historique"}`,
      ok: !flagged,
    };
  }
  if (type === "prompt_scan") {
    const blocked = event.decision === "block";
    return {
      text: `Requête de l'utilisateur analysée → ${blocked ? "bloquée, instruction d'injection détectée" : "jugée sûre"}`,
      ok: !blocked,
    };
  }
  if (type === "tool_result_scan") {
    const flagged = Boolean(event.flagged);
    return {
      text: `Retour de l'outil « ${event.tool} » analysé → ${flagged ? "neutralisé, contenu suspect" : "jugé sûr"}`,
      ok: !flagged,
    };
  }
  if (type === "citation_check") {
    const flagged = Boolean(event.flagged);
    return {
      text: `Réponse de l'agent → source citée : « ${event.cited ?? "aucune"} » ${flagged ? "(source manquante ou incorrecte)" : "(citation valide)"}`,
      ok: !flagged,
    };
  }
  if (type === "pii_redaction") {
    const categories = Array.isArray(event.categories) ? (event.categories as string[]).join(", ") : "";
    return {
      text: `Document « ${event.doc_id} » → ${event.count} donnée(s) personnelle(s) masquée(s) avant transmission (${categories})`,
      ok: true,
    };
  }
  return { text: JSON.stringify(event), ok: true };
}

export const entryLabel = (entry: AuditEntry) => describeEvent(entry.event);

export const pct = (value: number, digits = 0) => `${(value * 100).toFixed(digits)} %`;
export const num = (value: number, digits = 2) => value.toFixed(digits);
