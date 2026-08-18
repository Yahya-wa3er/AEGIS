/**
 * Couche d'accès à l'API, isolée du rendu.
 *
 * Un seul endroit qui sait parler au serveur, et un seul endroit à corriger le
 * jour où une route change. Les erreurs remontent avec le détail renvoyé par
 * FastAPI plutôt qu'un « Erreur API (500) » opaque : sur un produit de
 * sécurité, un message d'erreur muet est le meilleur moyen de faire passer une
 * panne pour un fonctionnement normal.
 */
import type {
  DocumentAnalysis,
  RankingComparison,
  ScenarioCatalogue,
  ScenarioRun,
  SimulationResult,
  StatusReport,
  TestDocumentResult,
} from "./types";

async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    let detail = "";
    try {
      const body = await res.json();
      detail = typeof body?.detail === "string" ? ` — ${body.detail}` : "";
    } catch {
      /* corps non-JSON : on garde le code seul */
    }
    throw new Error(`Erreur API ${res.status}${detail}`);
  }
  return res.json() as Promise<T>;
}

const postJson = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const runSimulation = (mode: "protected" | "unprotected") =>
  call<SimulationResult>(`/api/simulate/${mode}`, { method: "POST" });

export const analyzeDocument = (content: string, filename: string | null) =>
  call<DocumentAnalysis>("/api/analyze-document", postJson({ content, filename }));

export const fetchAttackCategories = async (): Promise<string[]> =>
  (await call<{ categories?: string[] }>("/api/test-document/categories")).categories ?? [];

export const testDocument = (opts: {
  documentType?: "poisoned" | "clean";
  category?: string | null;
  documentId?: string | null;
  protectedMode: boolean;
}) =>
  call<TestDocumentResult>(
    "/api/test-document",
    postJson({
      document_type: opts.documentType,
      category: opts.category ?? null,
      document_id: opts.documentId ?? null,
      protected: opts.protectedMode,
    }),
  );

export const fetchStatus = () => call<StatusReport>("/api/status");

export const fetchScenarios = () => call<ScenarioCatalogue>("/api/scenarios");

export const runScenario = (id: string) =>
  call<ScenarioRun>(`/api/scenarios/${encodeURIComponent(id)}/run`, { method: "POST" });

export const compareRanking = (
  requete: string,
  injecte?: string,
  corpus: "complet" | "origine" = "complet",
) => {
  const params = new URLSearchParams({ requete, corpus });
  if (injecte) params.set("injecte", injecte);
  return call<RankingComparison>(`/api/ranking?${params.toString()}`);
};
