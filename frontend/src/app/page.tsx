"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";

type TraceStep = { step: string; detail: Record<string, unknown> };
type ExecutedAction = { tool: string; params: Record<string, unknown> };

// État réel d'un détecteur. `available: null` = le détecteur ne sait pas se
// décrire (intégration tierce) -- on affiche « inconnu » plutôt que d'inventer.
type DetectorState = { available: boolean | null; required: boolean; reason: string | null };

// Verdict détaillé du journal d'audit. `ok` seul ne suffit pas : « chaîne
// cohérente » et « preuve signée vérifiable » ne sont pas la même affirmation.
type AuditIntegrity = {
  ok: boolean;
  first_bad_entry: number | null;
  reason: string | null;
  entries_checked: number;
  signature_mode: string;
  signatures_verified: number;
  unsigned_entries: number;
  is_signed: boolean;
};

type RobustnessReport = {
  detectors: Record<string, DetectorState>;
  fail_mode: string;
  audit_integrity: AuditIntegrity;
  tool_calls_total: number;
  tool_calls_blocked: number;
  prompts_scanned: number;
  prompts_blocked: number;
  tool_results_scanned: number;
  tool_results_flagged: number;
  retrievals_scanned: number;
  retrievals_flagged: number;
  behavior_scans: number;
  behavior_anomalies_flagged: number;
  citation_checks: number;
  missing_citations: number;
  documents_sanitized: number;
  pii_items_redacted: number;
  audit_log_integrity: boolean;
  first_corrupted_entry: number | null;
};
type BehaviorScan = { risk: number; flagged: boolean; raw_error: number };
type AuditEntry = { id: number; hash: string; event: Record<string, unknown> };
// Le verdict distingue « une attaque a réussi » de « l'agent a fait quelque
// chose qu'il ne devait pas ». L'ancien booléen unique confondait les deux, et
// affichait donc « attaque » sur un document parfaitement légitime.
type Verdict = {
  kind: "attack_succeeded" | "attack_neutralized" | "excessive_agency" | "nominal";
  label: string;
  explanation: string;
  sensitive_actions: string[];
  attack_expected: boolean;
};

type SimulationResult = {
  mode: string;
  trace: TraceStep[];
  response: string;
  executed_actions: ExecutedAction[];
  verdict: Verdict;
  audit_log: AuditEntry[] | null;
  robustness_report: RobustnessReport | null;
  behavior_scan: BehaviorScan | null;
};

// Traduit un événement brut du journal d'audit en une phrase compréhensible
// sans background technique -- c'est ce qui rend la démo lisible par un
// spectateur non-tech (voir README, section "à qui s'adresse ce projet").
function describeEvent(event: Record<string, unknown>): { text: string; ok: boolean } {
  const type = String(event.type);
  if (type === "retrieval_scan") {
    const flagged = Boolean(event.flagged);
    const risk = Number(event.risk ?? 0).toFixed(2);
    return {
      text: `Document "${event.doc_id}" analysé (risque ${risk}) → ${flagged ? "neutralisé, contenu suspect" : "jugé sûr"}`,
      ok: !flagged,
    };
  }
  if (type === "tool_call") {
    const blocked = event.decision === "block";
    return {
      text: `Demande d'action "${event.tool}" → ${blocked ? `bloquée (${event.reason ?? "hors politique"})` : "autorisée"}`,
      ok: !blocked,
    };
  }
  if (type === "behavior_scan") {
    const flagged = Boolean(event.flagged);
    return {
      text: `Comportement observé : "${event.action}" → ${flagged ? "enchaînement inhabituel détecté" : "cohérent avec l'historique"}`,
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
      text: `Retour de l'outil "${event.tool}" analysé → ${flagged ? "neutralisé, contenu suspect" : "jugé sûr"}`,
      ok: !flagged,
    };
  }
  if (type === "citation_check") {
    const flagged = Boolean(event.flagged);
    return {
      text: `Réponse de l'agent → source citée : "${event.cited ?? "aucune"}" ${flagged ? "(source manquante ou incorrecte)" : "(citation valide)"}`,
      ok: !flagged,
    };
  }
  if (type === "pii_redaction") {
    const categories = Array.isArray(event.categories) ? (event.categories as string[]).join(", ") : "";
    return {
      text: `Document "${event.doc_id}" → ${event.count} donnée(s) personnelle(s) masquée(s) avant transmission (${categories})`,
      ok: true,
    };
  }
  return { text: JSON.stringify(event), ok: true };
}

type DocumentAnalysis = {
  filename: string | null;
  content_preview: string;
  truncated: boolean;
  injection_risk: number;
  injection_flagged: boolean;
  // Identifiants de règles + libellés lisibles. L'API n'expose plus les
  // expressions régulières : les publier revenait à donner la liste exacte de
  // ce qu'il faut éviter d'écrire pour passer au travers.
  matched_rules: string[];
  matched_descriptions: string[];
  outlier_risk: number;
  outlier_flagged: boolean;
  outlier_distance: number | null;
  overall_risk: number;
  neutralized: boolean;
  pii_redacted: boolean;
  pii_categories: string[];
  pii_count: number;
  sanitized_preview: string;
};

async function analyzeDocument(content: string, filename: string | null): Promise<DocumentAnalysis> {
  const res = await fetch("/api/analyze-document", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content, filename }),
  });
  if (!res.ok) throw new Error(`Erreur API (${res.status})`);
  return res.json();
}

type TestDocumentResult = SimulationResult & {
  document_id: string;
  document_category: string;
  document_content: string;
};

async function testDocument(opts: {
  documentType?: "poisoned" | "clean";
  category?: string | null;
  documentId?: string;
  protected: boolean;
}): Promise<TestDocumentResult> {
  const res = await fetch("/api/test-document", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      document_type: opts.documentType,
      category: opts.category ?? null,
      document_id: opts.documentId ?? null,
      protected: opts.protected,
    }),
  });
  if (!res.ok) throw new Error(`Erreur API (${res.status})`);
  return res.json();
}

async function fetchAttackCategories(): Promise<string[]> {
  const res = await fetch("/api/test-document/categories");
  if (!res.ok) throw new Error(`Erreur API (${res.status})`);
  const body = await res.json();
  return body.categories ?? [];
}

const SENSITIVE_TOOLS = ["transfer_funds", "send_email"];
const STEP_LABELS: Record<string, string> = {
  prompt_scan: "Analyse de la requête",
  retrieval: "Récupération",
  llm_response: "Réponse LLM",
  tool_call: "Appel d'outil",
  final_response: "Réponse finale",
};

async function runSimulation(mode: "protected" | "unprotected"): Promise<SimulationResult> {
  const res = await fetch(`/api/simulate/${mode}`, { method: "POST" });
  if (!res.ok) throw new Error(`Erreur API (${res.status})`);
  return res.json();
}

function Robot() {
  return (
    <div className="h-[150px] flex items-end justify-center mb-1">
      <motion.svg
        width="88"
        height="110"
        viewBox="0 0 88 110"
        fill="none"
        animate={{ y: [0, -16, 0] }}
        transition={{ duration: 3.4, repeat: Infinity, ease: "easeInOut" }}
        style={{ filter: "drop-shadow(0 14px 18px rgba(42,120,214,0.18))" }}
      >
        <circle cx="44" cy="10" r="5" fill="#2a78d6" />
        <line x1="44" y1="15" x2="44" y2="26" stroke="#a9c4e8" strokeWidth="3" strokeLinecap="round" />
        <rect x="14" y="26" width="60" height="46" rx="18" fill="url(#headGrad)" stroke="#dfe9f7" strokeWidth="1.5" />
        <motion.circle
          cx="32" cy="49" r="6.5" fill="#2a78d6"
          animate={{ opacity: [1, 1, 0.15, 1] }}
          transition={{ duration: 4.2, repeat: Infinity, times: [0, 0.92, 0.95, 1] }}
        />
        <motion.circle
          cx="56" cy="49" r="6.5" fill="#1baf7a"
          animate={{ opacity: [1, 1, 0.15, 1] }}
          transition={{ duration: 4.2, repeat: Infinity, times: [0, 0.92, 0.95, 1] }}
        />
        <rect x="22" y="76" width="44" height="30" rx="14" fill="url(#bodyGrad)" stroke="#dfe9f7" strokeWidth="1.5" />
        <rect x="34" y="86" width="20" height="6" rx="3" fill="#cfe0f7" />
        <defs>
          <linearGradient id="headGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#ffffff" />
            <stop offset="1" stopColor="#eef4fc" />
          </linearGradient>
          <linearGradient id="bodyGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#ffffff" />
            <stop offset="1" stopColor="#eaf7f1" />
          </linearGradient>
        </defs>
      </motion.svg>
    </div>
  );
}

function Header() {
  return (
    <header className="flex items-center justify-between py-1.5">
      <div className="flex items-center gap-2.5">
        <div className="w-[34px] h-[34px] rounded-[10px] bg-gradient-to-br from-[#2a78d6] to-[#1baf7a] shadow-[0_10px_40px_rgba(23,60,110,0.08)]" />
        <div>
          <div className="font-bold text-lg tracking-wide">AEGIS</div>
          <div className="text-[#898781] text-xs">Zero-Trust Security Console</div>
        </div>
      </div>
      <nav className="flex gap-2">
        <span className="text-xs px-2.5 py-1 rounded-full bg-white border border-black/[0.08] text-[#52514e]">Next.js · export statique</span>
        <span className="text-xs px-2.5 py-1 rounded-full bg-white border border-black/[0.08] text-[#52514e]">OWASP LLM Top 10</span>
      </nav>
    </header>
  );
}

function Hero({ onLaunch, onReset, loading }: { onLaunch: () => void; onReset: () => void; loading: boolean }) {
  return (
    <section className="relative mt-6 px-10 py-14 rounded-[28px] bg-gradient-to-b from-white to-[#fbfdff] border border-black/[0.08] shadow-[0_10px_40px_rgba(23,60,110,0.08)] text-center overflow-hidden">
      <Robot />
      <div className="w-[74px] h-[14px] mx-auto rounded-full bg-[radial-gradient(closest-side,rgba(23,60,110,0.18),transparent)] mb-2" />
      <h1 className="text-4xl font-extrabold tracking-tight mb-3 bg-gradient-to-r from-[#184f95] to-[#1baf7a] bg-clip-text text-transparent">
        Une couche zero-trust pour vos agents IA
      </h1>
      <p className="text-[#52514e] max-w-xl mx-auto mb-8">
        Lancez une vraie tentative d&apos;injection de prompt contre un agent de support
        piloté par un LLM — avec, puis sans protection AEGIS — et observez la différence en direct.
      </p>
      <div className="flex gap-3 justify-center flex-wrap">
        <motion.button
          whileHover={{ y: -2 }}
          whileTap={{ scale: 0.97 }}
          disabled={loading}
          onClick={onLaunch}
          className="px-7 py-3.5 rounded-2xl font-semibold text-white bg-gradient-to-br from-[#2a78d6] to-[#184f95] shadow-[0_12px_28px_rgba(42,120,214,0.28)] disabled:opacity-50 disabled:cursor-progress"
        >
          {loading ? "Simulation en cours…" : "▶ Lancer la démonstration"}
        </motion.button>
        <button
          onClick={onReset}
          className="px-6 py-3.5 rounded-2xl font-semibold text-[#52514e] bg-white border border-black/[0.08]"
        >
          Réinitialiser
        </button>
      </div>
    </section>
  );
}

// Quatre verdicts, quatre couleurs. `excessive_agency` mérite son propre
// traitement : ce n'est ni une attaque réussie (rouge vif) ni un succès (vert),
// c'est un agent qui a fait quelque chose qu'il ne devait pas, sans attaquant.
const VERDICT_STYLE: Record<Verdict["kind"], string> = {
  attack_succeeded:   "text-[#d03b3b] bg-[#d03b3b]/10",
  attack_neutralized: "text-[#0ca30c] bg-[#0ca30c]/10",
  excessive_agency:   "text-[#8a6100] bg-[#fab219]/20",
  nominal:            "text-[#0d8f63] bg-[#0ca30c]/10",
};

function StatusPill({ verdict, hasRun, ranProtected }: { verdict: Verdict | null; hasRun: boolean; ranProtected: boolean }) {
  if (!hasRun || !verdict) {
    return <span className="ml-auto text-xs font-semibold px-3 py-1 rounded-full text-[#898781] bg-[#fcfcfb]">En attente</span>;
  }
  // Sans AEGIS, une attaque neutralisée l'a été par le modèle lui-même, pas par
  // nous : le dire évite de s'attribuer un mérite qui ne nous revient pas.
  const label =
    verdict.kind === "attack_neutralized" && !ranProtected ? "✔ Résistance native du modèle" : verdict.label;
  return (
    <span className={`ml-auto text-xs font-semibold px-3 py-1 rounded-full ${VERDICT_STYLE[verdict.kind]}`}>
      {label}
    </span>
  );
}

function TraceList({ trace }: { trace: TraceStep[] }) {
  if (trace.length === 0) {
    return <p className="text-[#898781] text-sm">Lance la démonstration pour voir le scénario se dérouler.</p>;
  }
  return (
    <div>
      {trace.map((step, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: i * 0.12 }}
          className="flex gap-2.5 text-sm text-[#52514e] py-2 border-b border-dashed border-black/[0.08] last:border-none"
        >
          <span className="font-bold text-[#0b0b0b] min-w-[118px]">{STEP_LABELS[step.step] ?? step.step}</span>
          <span className="break-all">{JSON.stringify(step.detail)}</span>
        </motion.div>
      ))}
    </div>
  );
}

function ActionChips({ actions }: { actions: ExecutedAction[] }) {
  return (
    <div className="mt-3.5 p-4 rounded-2xl bg-[#fcfcfb] border border-black/[0.08] text-sm text-[#52514e]">
      {actions.length === 0 ? (
        <span className="text-[#898781]">Aucune action exécutée.</span>
      ) : (
        actions.map((a, i) => {
          const dangerous = SENSITIVE_TOOLS.includes(a.tool);
          return (
            <span
              key={i}
              className={`inline-flex items-center gap-1.5 mr-2 mt-1 text-xs font-semibold px-2.5 py-1 rounded-full ${
                dangerous ? "bg-[#d03b3b]/10 text-[#d03b3b]" : "bg-[#1baf7a]/10 text-[#0d8f63]"
              }`}
            >
              {dangerous ? "⚠" : "✓"} {a.tool}
            </span>
          );
        })
      )}
    </div>
  );
}

function DocumentVerdict({ result }: { result: DocumentAnalysis }) {
  return (
    <div className="mt-4 p-4 rounded-2xl border border-black/[0.08] bg-[#fcfcfb]">
      <div className="flex items-center gap-2.5 mb-3.5 flex-wrap">
        <span
          className={`text-xs font-semibold px-3 py-1 rounded-full ${
            result.neutralized ? "text-[#d03b3b] bg-[#d03b3b]/10" : "text-[#0ca30c] bg-[#0ca30c]/10"
          }`}
        >
          {result.neutralized ? "⚠ Aurait été neutralisé par AEGIS" : "✔ Jugé sûr par AEGIS"}
        </span>
        {result.truncated && (
          <span className="text-xs text-[#898781]">(texte tronqué à 20 000 caractères pour l&apos;analyse)</span>
        )}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
        <div>
          <div className="text-[#898781] text-xs uppercase tracking-wide mb-1">Détection d&apos;injection de prompt</div>
          <div className={result.injection_flagged ? "text-[#d03b3b] font-semibold" : "text-[#0d8f63] font-semibold"}>
            risque {result.injection_risk.toFixed(2)} — {result.injection_flagged ? "motif suspect trouvé" : "rien détecté"}
          </div>
          {result.matched_descriptions.length > 0 && (
            <ul className="mt-1.5 list-disc list-inside text-[#898781] space-y-0.5">
              {result.matched_descriptions.map((label, i) => (
                <li key={i} className="text-xs">{label}</li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <div className="text-[#898781] text-xs uppercase tracking-wide mb-1">Éloignement du domaine normal</div>
          <div className={result.outlier_flagged ? "text-[#d03b3b] font-semibold" : "text-[#0d8f63] font-semibold"}>
            risque {result.outlier_risk.toFixed(2)} — {result.outlier_flagged ? "hors du domaine appris" : "cohérent avec le domaine"}
          </div>
        </div>
        <div>
          <div className="text-[#898781] text-xs uppercase tracking-wide mb-1">Données personnelles / secrets</div>
          <div className={result.pii_redacted ? "text-[#d03b3b] font-semibold" : "text-[#0d8f63] font-semibold"}>
            {result.pii_redacted
              ? `${result.pii_count} élément(s) masqué(s) (${result.pii_categories.join(", ")})`
              : "aucune donnée sensible trouvée"}
          </div>
        </div>
      </div>
      <p className="text-xs text-[#898781] mt-3.5 border-t border-black/[0.08] pt-3">
        Aperçu du texte analysé : « {result.content_preview.slice(0, 140)}
        {result.content_preview.length > 140 ? "…" : ""} »
      </p>
      {result.pii_redacted && (
        <p className="text-xs text-[#0d8f63] mt-1.5">
          Version assainie qu&apos;AEGIS transmettrait à la place : « {result.sanitized_preview.slice(0, 140)}
          {result.sanitized_preview.length > 140 ? "…" : ""} »
        </p>
      )}
    </div>
  );
}

function DocumentAnalyzer() {
  const [text, setText] = useState("");
  const [filename, setFilename] = useState<string | null>(null);
  const [result, setResult] = useState<DocumentAnalysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    setResult(null);
    const reader = new FileReader();
    reader.onload = () => setText(String(reader.result ?? ""));
    reader.readAsText(file);
  }

  async function handleAnalyze() {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    try {
      setResult(await analyzeDocument(text, filename));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erreur inconnue");
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="mt-8 bg-white border border-black/[0.08] rounded-[20px] shadow-[0_10px_40px_rgba(23,60,110,0.08)] p-5">
      <h3 className="font-bold mb-1.5">Testez avec votre propre document</h3>
      <p className="text-sm text-[#898781] mb-3.5 max-w-3xl">
        Collez un texte ou importez un fichier (.txt, .md) — AEGIS l&apos;analyse en direct avec les trois mêmes
        détecteurs appliqués à chaque document récupéré par le RAG (injection de prompt, éloignement du domaine
        normal, données personnelles/secrets). Aucun LLM n&apos;est appelé ici : c&apos;est un scan de contenu
        instantané, gratuit et sans clé API.
      </p>
      <textarea
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          setFilename(null);
          setResult(null);
        }}
        placeholder="Collez ici le contenu d'un document à tester (ou importez un fichier ci-dessous)…"
        rows={5}
        className="w-full rounded-2xl border border-black/[0.08] p-3.5 text-sm bg-[#fcfcfb] resize-y focus:outline-none focus:ring-2 focus:ring-[#2a78d6]/30"
      />
      <div className="flex items-center gap-3 mt-3.5 flex-wrap">
        <label className="px-4 py-2.5 rounded-2xl font-semibold text-sm text-[#52514e] bg-white border border-black/[0.08] cursor-pointer">
          Importer un fichier…
          <input type="file" accept=".txt,.md,.csv,.log" className="hidden" onChange={handleFile} />
        </label>
        {filename && <span className="text-xs text-[#898781]">{filename}</span>}
        <motion.button
          whileHover={{ y: -2 }}
          whileTap={{ scale: 0.97 }}
          disabled={loading || !text.trim()}
          onClick={handleAnalyze}
          className="px-6 py-2.5 rounded-2xl font-semibold text-white bg-gradient-to-br from-[#2a78d6] to-[#184f95] shadow-[0_12px_28px_rgba(42,120,214,0.28)] disabled:opacity-50 disabled:cursor-progress"
        >
          {loading ? "Analyse…" : "Analyser avec AEGIS"}
        </motion.button>
      </div>
      {error && <p className="mt-3 text-[#d03b3b] text-sm">{error}</p>}
      {result && <DocumentVerdict result={result} />}
    </section>
  );
}

function MiniVerdict({ title, result }: { title: string; result: TestDocumentResult | null }) {
  const verdict = result?.verdict ?? null;
  return (
    <div className="bg-white rounded-[20px] border border-black/[0.08] shadow-[0_10px_40px_rgba(23,60,110,0.08)] p-5">
      <div className="flex items-center gap-2.5 mb-3">
        <span className="font-bold">{title}</span>
        {verdict && (
          <span className={`ml-auto text-xs font-semibold px-3 py-1 rounded-full ${VERDICT_STYLE[verdict.kind]}`}>
            {verdict.label}
          </span>
        )}
      </div>
      {!result || !verdict ? (
        <p className="text-[#898781] text-sm">En attente.</p>
      ) : (
        <>
          {/* L'explication porte la nuance que le badge seul ne peut pas dire :
              une action sensible sur un document légitime n'est pas une attaque. */}
          <p className="text-xs text-[#898781] mb-2.5">{verdict.explanation}</p>
          <p className="text-sm text-[#52514e] mb-2">{result.response}</p>
          <ActionChips actions={result.executed_actions} />
        </>
      )}
    </div>
  );
}

function RobustnessLab() {
  const [documentType, setDocumentType] = useState<"poisoned" | "clean">("poisoned");
  const [category, setCategory] = useState<string>("");
  const [categories, setCategories] = useState<string[]>([]);
  const [unprotected, setUnprotected] = useState<TestDocumentResult | null>(null);
  const [protectedRun, setProtectedRun] = useState<TestDocumentResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAttackCategories()
      .then(setCategories)
      .catch(() => setCategories([]));
  }, []);

  async function runTest() {
    setLoading(true);
    setError(null);
    try {
      const first = await testDocument({
        documentType,
        category: documentType === "poisoned" ? category || null : null,
        protected: false,
      });
      setUnprotected(first);
      const second = await testDocument({ documentId: first.document_id, protected: true });
      setProtectedRun(second);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erreur inconnue");
    } finally {
      setLoading(false);
    }
  }

  const testedDoc = unprotected ?? protectedRun;

  return (
    <section className="mt-8 bg-white border border-black/[0.08] rounded-[20px] shadow-[0_10px_40px_rgba(23,60,110,0.08)] p-5">
      <h3 className="font-bold mb-1.5">Laboratoire de robustesse : testez un document généré contre le vrai modèle</h3>
      <p className="text-sm text-[#898781] mb-3.5 max-w-3xl">
        Choisis un type de document (piégé ou légitime, tiré du même corpus catégorisé OWASP LLM Top 10 que la
        suite de red-teaming), puis lance un VRAI appel au LLM configuré -- contrairement à l&apos;outil ci-dessus,
        ceci consomme ta clé API et prend quelques secondes, mais montre ce qui se passe réellement, pas seulement
        ce qu&apos;un détecteur aurait prédit.
      </p>
      <div className="flex items-center gap-3 flex-wrap">
        <label className="flex items-center gap-1.5 text-sm">
          <input
            type="radio"
            checked={documentType === "poisoned"}
            onChange={() => setDocumentType("poisoned")}
          />
          Document piégé (attaque)
        </label>
        <label className="flex items-center gap-1.5 text-sm">
          <input
            type="radio"
            checked={documentType === "clean"}
            onChange={() => setDocumentType("clean")}
          />
          Document légitime
        </label>
        {documentType === "poisoned" && (
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="text-sm rounded-xl border border-black/[0.08] px-3 py-1.5 bg-[#fcfcfb]"
          >
            <option value="">Catégorie aléatoire</option>
            {categories.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        )}
        <motion.button
          whileHover={{ y: -2 }}
          whileTap={{ scale: 0.97 }}
          disabled={loading}
          onClick={runTest}
          className="ml-auto px-6 py-2.5 rounded-2xl font-semibold text-white bg-gradient-to-br from-[#2a78d6] to-[#184f95] shadow-[0_12px_28px_rgba(42,120,214,0.28)] disabled:opacity-50 disabled:cursor-progress"
        >
          {loading ? "Test en cours…" : "▶ Générer et tester avec le modèle"}
        </motion.button>
      </div>
      {error && <p className="mt-3 text-[#d03b3b] text-sm">{error}</p>}
      {testedDoc && (
        <div className="mt-4 p-4 rounded-2xl bg-[#fcfcfb] border border-black/[0.08]">
          <div className="text-xs text-[#898781] uppercase tracking-wide mb-1">
            Document testé — {testedDoc.document_category}
          </div>
          <p className="text-sm text-[#52514e] font-mono break-all whitespace-pre-wrap">
            {testedDoc.document_content.slice(0, 400)}
            {testedDoc.document_content.length > 400 ? "…" : ""}
          </p>
        </div>
      )}
      {(unprotected || protectedRun) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-4">
          <MiniVerdict title="Sans AEGIS" result={unprotected} />
          <MiniVerdict title="Avec AEGIS" result={protectedRun} />
        </div>
      )}
    </section>
  );
}

function BehaviorBadge({ scan }: { scan: BehaviorScan | null | undefined }) {
  if (!scan) return null;
  return (
    <div
      className={`mt-3.5 p-3 rounded-2xl border text-sm flex items-center gap-2 ${
        scan.flagged
          ? "bg-[#d03b3b]/5 border-[#d03b3b]/20 text-[#d03b3b]"
          : "bg-[#0ca30c]/5 border-[#0ca30c]/20 text-[#0d8f63]"
      }`}
    >
      <span>{scan.flagged ? "⚠" : "✔"}</span>
      <span>
        Analyse comportementale : {scan.flagged ? "enchaînement d'actions inhabituel" : "comportement cohérent"} (score {scan.risk.toFixed(2)})
      </span>
    </div>
  );
}

function Panel({ title, result, ranProtected }: { title: string; result: SimulationResult | null; ranProtected: boolean }) {
  return (
    <div className="bg-white rounded-[20px] border border-black/[0.08] shadow-[0_10px_40px_rgba(23,60,110,0.08)] p-5 min-h-[220px]">
      <div className="flex items-center gap-2.5 mb-3.5">
        <span className="font-bold">{title}</span>
        <StatusPill verdict={result?.verdict ?? null} hasRun={!!result} ranProtected={ranProtected} />
      </div>
      <TraceList trace={result?.trace ?? []} />
      {result && <ActionChips actions={result.executed_actions} />}
      {ranProtected && <BehaviorBadge scan={result?.behavior_scan} />}
    </div>
  );
}

// Une couche peut être dans CINQ états, pas deux (correctif P0-6).
//
// La version précédente ne connaissait que « a détecté » (rouge) et « n'a rien
// détecté » (vert). Sur un clone frais du dépôt, où le VAE comportemental et le
// détecteur d'outliers n'ont pas de modèle entraîné et renvoient un risque nul
// sur tout, elle affichait donc « ✔ Comportement jugé normal » pour un capteur
// éteint. En supervision de sécurité, c'est l'anti-pattern le plus dangereux
// qui existe : un opérateur qui voit du vert arrête de regarder.
type LayerStatus = "pending" | "unavailable" | "degraded" | "alert" | "ok";

const LAYER_STYLE: Record<LayerStatus, { icon: string; box: string; label: string }> = {
  pending:     { icon: "…", box: "bg-[#fcfcfb] border-black/[0.08] text-[#898781]", label: "En attente de simulation" },
  unavailable: { icon: "⊘", box: "bg-[#898781]/10 border-[#898781]/30 text-[#52514e]", label: "" },
  degraded:    { icon: "▲", box: "bg-[#fab219]/15 border-[#fab219]/40 text-[#8a6100]", label: "" },
  alert:       { icon: "⚠", box: "bg-[#d03b3b]/5 border-[#d03b3b]/20 text-[#d03b3b]", label: "" },
  ok:          { icon: "✔", box: "bg-[#0ca30c]/5 border-[#0ca30c]/20 text-[#0d8f63]", label: "" },
};

function ProtectionLayers({ report }: { report: RobustnessReport | null }) {
  // `tone: "info"` = une action de routine qui n'indique aucune attaque, juste
  // de l'hygiène de données -- verte quand active, jamais rouge (contrairement
  // aux autres couches, un document assaini n'est pas une mauvaise nouvelle).
  //
  // `dependsOn` = les détecteurs ML dont la couche a besoin. `hasFallback` = il
  // existe un repli non-ML (les règles regex) : la couche est alors DÉGRADÉE, pas
  // aveugle. Sans repli, un détecteur absent rend la couche muette.
  const layers: {
    label: string;
    tone: "alert" | "info";
    active: boolean;
    idle: string;
    hit: string;
    dependsOn: string[];
    hasFallback: boolean;
  }[] = [
    {
      label: "Détection d'injection & outliers RAG",
      tone: "alert",
      active: !!report && report.retrievals_flagged > 0,
      idle: "Aucun document suspect reçu",
      hit: `${report?.retrievals_flagged ?? 0} document(s) neutralisé(s)`,
      dependsOn: ["injection_ml", "rag_outlier"],
      hasFallback: true, // les règles regex tournent toujours
    },
    {
      label: "Analyse de la requête utilisateur",
      tone: "alert",
      active: !!report && report.prompts_blocked > 0,
      idle: "Aucune injection directe détectée",
      hit: `${report?.prompts_blocked ?? 0} requête(s) bloquée(s)`,
      dependsOn: [],
      hasFallback: false,
    },
    {
      label: "Analyse des retours d'outils",
      tone: "alert",
      active: !!report && report.tool_results_flagged > 0,
      idle: "Aucun retour d'outil suspect",
      hit: `${report?.tool_results_flagged ?? 0} retour(s) neutralisé(s)`,
      dependsOn: [],
      hasFallback: false,
    },
    {
      label: "Contrôle des permissions (Policy Engine)",
      tone: "alert",
      active: !!report && report.tool_calls_blocked > 0,
      idle: "Aucune action hors politique tentée",
      hit: `${report?.tool_calls_blocked ?? 0} action(s) bloquée(s)`,
      dependsOn: [],
      hasFallback: false, // aucune dépendance ML : cette couche marche toujours
    },
    {
      label: "Détection d'anomalies comportementales",
      tone: "alert",
      active: !!report && report.behavior_anomalies_flagged > 0,
      idle: "Comportement jugé normal",
      hit: `${report?.behavior_anomalies_flagged ?? 0} anomalie(s) détectée(s)`,
      dependsOn: ["behavior"],
      hasFallback: false, // purement ML : sans modèle, la couche ne voit rien
    },
    {
      label: "Vérification de la citation de source",
      tone: "alert",
      active: !!report && report.missing_citations > 0,
      idle: "Sources correctement citées",
      hit: `${report?.missing_citations ?? 0} citation(s) manquante(s)`,
      dependsOn: [],
      hasFallback: false,
    },
    {
      label: "Assainissement (données personnelles / secrets)",
      tone: "info",
      active: !!report && report.documents_sanitized > 0,
      idle: "Aucune donnée personnelle rencontrée",
      hit: `${report?.pii_items_redacted ?? 0} élément(s) masqué(s) dans ${report?.documents_sanitized ?? 0} document(s)`,
      dependsOn: [],
      hasFallback: false,
    },
  ];

  const missingFor = (names: string[]) =>
    report ? names.filter((name) => report.detectors?.[name]?.available === false) : [];

  return (
    <section className="mt-7 bg-white border border-black/[0.08] rounded-[20px] shadow-[0_10px_40px_rgba(23,60,110,0.08)] p-5">
      <h3 className="font-bold mb-1.5">Les 7 couches de protection AEGIS</h3>
      <p className="text-xs text-[#898781] mb-3.5">
        Une couche grisée n&apos;a rien laissé passer : elle n&apos;a rien regardé. Le modèle
        correspondant n&apos;est pas entraîné, le détecteur renvoie un risque nul sur tout.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {layers.map((layer) => {
          const missing = missingFor(layer.dependsOn);
          let status: LayerStatus;
          let detail: string;

          if (!report) {
            status = "pending";
            detail = LAYER_STYLE.pending.label;
          } else if (missing.length > 0 && !layer.hasFallback) {
            status = "unavailable";
            detail = `Détecteur non chargé (${missing.join(", ")}) — cette couche ne voit rien`;
          } else if (missing.length > 0) {
            status = "degraded";
            detail = `Dégradée : ${missing.join(", ")} non chargé(s), seules les règles déterministes tournent`;
          } else if (layer.active && layer.tone === "alert") {
            status = "alert";
            detail = layer.hit;
          } else {
            status = "ok";
            detail = layer.active ? layer.hit : layer.idle;
          }

          const style = LAYER_STYLE[status];
          return (
            <div key={layer.label} className={`flex items-start gap-3 p-3.5 rounded-2xl border text-sm ${style.box}`}>
              <span className="text-lg leading-tight">{style.icon}</span>
              <div>
                <div className="font-semibold text-[#0b0b0b]">{layer.label}</div>
                <div>{detail}</div>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function Kpi({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="bg-white border border-black/[0.08] rounded-2xl p-4 shadow-[0_10px_40px_rgba(23,60,110,0.08)]">
      <div className="text-xs text-[#898781] uppercase tracking-wide">{label}</div>
      <div className="text-3xl font-extrabold mt-1.5">{value}</div>
    </div>
  );
}

function AuditIntegrityValue({ report }: { report: RobustnessReport | null }) {
  if (!report) return <>—</>;
  const audit = report.audit_integrity;

  if (!audit?.ok) {
    return <span className="text-[#d03b3b]">✖ Compromise</span>;
  }
  // Distinction essentielle : « la chaîne est cohérente » n'est PAS « la preuve
  // est opposable ». Sans signature, un attaquant disposant d'un accès en
  // écriture recalcule la chaîne et cet indicateur reste au vert.
  if (!audit.is_signed) {
    return (
      <span className="text-[#8a6100] text-xl leading-tight whitespace-nowrap">
        ▲ Non signée
        <span className="block text-[11px] font-normal normal-case tracking-normal">
          chaîne cohérente, mais reforgeable
        </span>
      </span>
    );
  }
  return (
    <span className="text-[#0ca30c] text-xl leading-tight whitespace-nowrap">
      ✔ Signée
      <span className="block text-[11px] font-normal normal-case tracking-normal text-[#52514e]">
        {audit.signatures_verified} signature(s) Ed25519 vérifiée(s)
      </span>
    </span>
  );
}

function Kpis({ report }: { report: RobustnessReport | null }) {
  // Le « Robustness Score » affiché ici était une valeur BINAIRE (100 ou 0),
  // habillée en pourcentage avec une barre de progression animée qui suggérait
  // un continuum -- et sans aucun rapport avec le score de `run_redteam.py`
  // (block_rate x (1 - fp_rate)), qui vaut 67 % aujourd'hui. Sur le scénario de
  // démo il affichait 100 % en permanence (correctif P1-F1).
  //
  // Une simulation ne produit pas un score : elle produit un verdict. On dit
  // donc ce qu'on sait, et rien de plus.
  const verdict = !report
    ? null
    : report.retrievals_flagged > 0 || report.tool_calls_blocked > 0
    ? { text: "Attaque neutralisée", color: "text-[#0ca30c]", note: "sur cette simulation" }
    : { text: "Rien à signaler", color: "text-[#52514e]", note: "aucune attaque sur cette simulation" };

  return (
    <section className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-4 mt-7">
      <div className="bg-white border border-black/[0.08] rounded-2xl p-4 shadow-[0_10px_40px_rgba(23,60,110,0.08)] col-span-2">
        <div className="text-xs text-[#898781] uppercase tracking-wide">Verdict de la simulation</div>
        <div className={`text-2xl font-extrabold mt-1.5 ${verdict?.color ?? ""}`}>{verdict?.text ?? "—"}</div>
        <div className="text-xs text-[#898781] mt-1">
          {verdict?.note ?? "Lance la démonstration"}
          {report ? ` · mode de défaillance : ${report.fail_mode}` : ""}
        </div>
        <div className="text-[11px] text-[#898781] mt-2 border-t border-black/[0.08] pt-2">
          Le taux de blocage mesuré sur le corpus de red-teaming complet s&apos;obtient avec{" "}
          <code className="font-mono">python -m redteam.run_redteam</code> — une simulation isolée
          n&apos;est pas une mesure.
        </div>
      </div>
      <Kpi label="Intégrité du journal" value={<AuditIntegrityValue report={report} />} />
      <Kpi label="Appels d'outils bloqués" value={report ? report.tool_calls_blocked : "—"} />
      <Kpi label="Documents suspects détectés" value={report ? report.retrievals_flagged : "—"} />
      <Kpi label="Anomalies comportementales" value={report ? report.behavior_anomalies_flagged : "—"} />
      <Kpi label="Citations manquantes" value={report ? report.missing_citations : "—"} />
      <Kpi label="Données personnelles masquées" value={report ? report.pii_items_redacted : "—"} />
    </section>
  );
}

function AuditTable({ entries }: { entries: AuditEntry[] | null }) {
  return (
    <section className="mt-7 bg-white border border-black/[0.08] rounded-[20px] shadow-[0_10px_40px_rgba(23,60,110,0.08)] p-5">
      <h3 className="font-bold mb-3">Journal d&apos;audit (agent protégé)</h3>
      {/*
        L'ancien texte affirmait ici que « modifier une entrée après coup casse la
        chaîne et devient détectable », et renvoyait vers « la démo d'intégrité plus
        bas » qui n'a jamais existé dans cette page. Les deux étaient faux
        (correctif P1-F2) : un chaînage de hachage sans clé se recalcule, et
        l'audit l'a démontré en effaçant un virement de 50 000 EUR sans détection.
      */}
      <p className="text-xs text-[#898781] mb-3 -mt-1">
        Chaque ligne est chaînée par hachage à la précédente <strong>et signée</strong> (Ed25519).
        Le chaînage seul ne suffirait pas : un attaquant disposant d&apos;un accès en écriture le
        recalcule. C&apos;est la signature qui rend la falsification détectable — et la clé publique
        permet à un tiers de vérifier ce journal sans pouvoir y écrire. Sans clé générée
        (<code className="font-mono">python -m scripts.generate_audit_key</code>), le journal
        fonctionne mais reste <strong>non signé</strong>, et l&apos;indicateur ci-dessus le signale.
      </p>
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="text-[#898781] text-left">
            <th className="py-2 px-2">#</th>
            <th className="py-2 px-2">Hash</th>
            <th className="py-2 px-2">Ce qui s&apos;est passé</th>
          </tr>
        </thead>
        <tbody>
          {!entries || entries.length === 0 ? (
            <tr><td colSpan={3} className="py-2 px-2 text-[#898781]">Aucune entrée pour l&apos;instant.</td></tr>
          ) : (
            entries.map((e) => {
              const { text, ok } = describeEvent(e.event);
              return (
                <tr key={e.id} className="border-t border-black/[0.08]">
                  <td className="py-2 px-2 align-top">{e.id}</td>
                  <td className="py-2 px-2 font-mono text-[#898781] align-top">{e.hash}…</td>
                  <td className={`py-2 px-2 ${ok ? "text-[#52514e]" : "text-[#d03b3b] font-medium"}`}>{text}</td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </section>
  );
}

export default function Home() {
  const [unprotected, setUnprotected] = useState<SimulationResult | null>(null);
  const [protectedResult, setProtectedResult] = useState<SimulationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function launchDemo() {
    setLoading(true);
    setError(null);
    try {
      setUnprotected(await runSimulation("unprotected"));
      setProtectedResult(await runSimulation("protected"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erreur inconnue");
    } finally {
      setLoading(false);
    }
  }

  function reset() {
    setUnprotected(null);
    setProtectedResult(null);
    setError(null);
  }

  return (
    <main className="min-h-screen bg-[#f9f9f7] text-[#0b0b0b]">
      <div className="max-w-[1180px] mx-auto px-6 pb-20 pt-7">
        <Header />
        <Hero onLaunch={launchDemo} onReset={reset} loading={loading} />
        {error && <p className="mt-4 text-center text-[#d03b3b] text-sm">{error}</p>}
        <DocumentAnalyzer />
        <RobustnessLab />
        <section className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
          <Panel title="Sans AEGIS" result={unprotected} ranProtected={false} />
          <Panel title="Avec AEGIS" result={protectedResult} ranProtected={true} />
        </section>
        <Kpis report={protectedResult?.robustness_report ?? null} />
        <ProtectionLayers report={protectedResult?.robustness_report ?? null} />
        <AuditTable entries={protectedResult?.audit_log ?? null} />
        <footer className="text-center text-[#898781] text-sm mt-10">
          AEGIS — Zero-Trust Security Layer pour Systèmes IA Agentiques &amp; RAG
        </footer>
      </div>
    </main>
  );
}