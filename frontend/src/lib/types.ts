/**
 * Types partagés de la console.
 *
 * Ils étaient déclarés en tête de `page.tsx`, au milieu du rendu. Les isoler
 * n'est pas de la cosmétique : c'est ce qui permet de voir d'un coup d'œil ce
 * que l'API promet, et de constater qu'un champ a disparu côté serveur au lieu
 * de l'apprendre par un `undefined` affiché à l'écran — le bug exact qui avait
 * fait afficher « ✓ Résistance native » sur une simulation où deux outils
 * sensibles s'étaient exécutés.
 */

export type TraceStep = { step: string; detail: Record<string, unknown> };
export type ExecutedAction = { tool: string; params: Record<string, unknown> };

/** `available: null` = le détecteur ne sait pas se décrire (intégration tierce).
 *  On affiche « inconnu » plutôt que d'inventer un état. */
export type DetectorState = {
  available: boolean | null;
  required: boolean;
  reason: string | null;
};

/** « Chaîne cohérente » et « preuve signée vérifiable » ne sont pas la même
 *  affirmation : `ok` seul ne suffit donc pas. */
export type AuditIntegrity = {
  ok: boolean;
  first_bad_entry: number | null;
  reason: string | null;
  entries_checked: number;
  signature_mode: string;
  signatures_verified: number;
  unsigned_entries: number;
  is_signed: boolean;
};

/** `degraded` vaut vrai quand au moins une fenêtre comportementale est partagée
 *  faute d'identifiant de session. */
export type SessionIsolation = {
  keyed_by: string[];
  active: number;
  anonymous: number;
  identified: number;
  degraded: boolean;
  evicted: number;
  expired: number;
  max_sessions: number;
  ttl_seconds: number;
};

export type RobustnessReport = {
  detectors: Record<string, DetectorState>;
  fail_mode: string;
  audit_integrity: AuditIntegrity;
  session_isolation: SessionIsolation;
  tool_calls_total: number;
  tool_calls_blocked: number;
  prompts_scanned: number;
  prompts_blocked: number;
  tool_results_scanned: number;
  tool_results_flagged: number;
  retrievals_scanned: number;
  retrievals_flagged: number;
  retrievals_advisory_only: number;
  behavior_scans: number;
  behavior_anomalies_flagged: number;
  citation_checks: number;
  missing_citations: number;
  documents_sanitized: number;
  pii_items_redacted: number;
  audit_log_integrity: boolean;
  first_corrupted_entry: number | null;
};

export type BehaviorScan = { risk: number; flagged: boolean; raw_error: number };
export type AuditEntry = { id: number; hash: string; event: Record<string, unknown> };

/** Quatre verdicts, pas un booléen : « une attaque a réussi » et « l'agent a
 *  fait quelque chose qu'il ne devait pas » sont deux constats différents. */
export type Verdict = {
  kind: "attack_succeeded" | "attack_neutralized" | "excessive_agency" | "nominal";
  label: string;
  explanation: string;
  sensitive_actions: string[];
  attack_expected: boolean;
};

export type SimulationResult = {
  mode: string;
  trace: TraceStep[];
  response: string;
  executed_actions: ExecutedAction[];
  verdict: Verdict;
  audit_log: AuditEntry[] | null;
  robustness_report: RobustnessReport | null;
  behavior_scan: BehaviorScan | null;
};

export type TestDocumentResult = SimulationResult & {
  document_id: string;
  document_category: string;
  document_content: string;
};

export type StuffingDetail = {
  flagged: boolean;
  reason: string | null;
  ttr: number;
  tokens: number;
  expected_range: [number, number];
  top_terms: [string, number][];
};

export type DocumentAnalysis = {
  filename: string | null;
  content_preview: string;
  truncated: boolean;
  /** Décomposition par signal (P1-M4). Le champ combiné `injection_risk` a été
   *  supprimé : il valait `max(règles, ML)`, ce qui attribuait à la couche
   *  déterministe — mesurée à 0 % de faux positifs — le score du classifieur,
   *  mesuré à 50 %. Les trois échelles ci-dessous ne sont pas comparables. */
  rule_risk: number;
  injection_ml_score: number | null;
  injection_flagged: boolean;
  /** Identifiants de règles + libellés lisibles. L'API n'expose pas les
   *  expressions régulières : les publier reviendrait à donner la liste de ce
   *  qu'il faut éviter d'écrire pour passer au travers. */
  matched_rules: string[];
  matched_descriptions: string[];
  outlier_risk: number;
  outlier_flagged: boolean;
  outlier_distance: number | null;
  stuffing: StuffingDetail | null;
  /** Maximum sur les seuls signaux habilités à décider : le nombre qui explique
   *  le verdict. */
  decision_risk: number;
  /** Maximum sur les trois échelles. Conservé pour le journal, jamais présenté
   *  comme « le risque » du document. */
  observed_max_risk: number;
  neutralized: boolean;
  advisory_signals: string[];
  blocking_signals: string[];
  pii_redacted: boolean;
  pii_categories: string[];
  pii_count: number;
  sanitized_preview: string;
};

// -- banc de scénarios (lot 6) ---------------------------------------------

export type ScenarioSummary = {
  id: string;
  titre: string;
  famille: string;
  owasp: string;
  requete: string;
  attendu: string;
  regarder: string;
  est_attaque: boolean;
  tags: string[];
};

export type VerdictDetails = {
  risk: number;
  rule_risk: number;
  injection_ml_score: number | null;
  outlier_risk: number;
  outlier_distance: number | null;
  matched_rules: string[];
  stuffing: StuffingDetail;
  blocking_signals: string[];
  advisory_signals: string[];
  would_have_blocked: boolean;
};

export type ScenarioRun = {
  scenario: ScenarioSummary & { document: string | null; document_id: string };
  point: string;
  verdict: string;
  prompt: { decision: string; reason: string; matched_rules: string[] };
  document: { id: string; taille: number } | null;
  outil: Record<string, unknown> | null;
  details: Partial<VerdictDetails>;
  /** Vide = le scénario s'est comporté comme il l'annonce, signaux compris. */
  ecarts: string[];
};

export type ScenarioCatalogue = { familles: string[]; scenarios: ScenarioSummary[] };

// -- laboratoire de classement (lot 6.1) -----------------------------------

export type RankedDocument = {
  id: string;
  score: number;
  apercu: string;
  rang: number;
  injecte: boolean;
};

export type RankingComparison = {
  requete: string;
  corpus: "complet" | "origine";
  taille_corpus: number;
  bm25: RankedDocument[];
  overlap: RankedDocument[];
  document_injecte: string | null;
};

// -- vue d'ensemble (lot 7.1) ----------------------------------------------

/** État du produit au repos. Construit sur un garde neuf : ce qu'on montre est
 *  ce que reçoit un déploiement au démarrage, pas l'état d'une démonstration
 *  déjà chauffée. */
export type StatusReport = {
  detectors: Record<string, DetectorState>;
  fail_mode: string;
  audit_integrity: AuditIntegrity;
  session_isolation: SessionIsolation;
  blocking_signals: string[];
  signals: { id: string; mesure: string }[];
  consommation: ConsommationReport;
};

/** Gardes LLM06 appliqués à la démonstration elle-même.
 *
 *  Les deux compteurs répondent à deux menaces distinctes : le débit par client
 *  protège la disponibilité entre visiteurs, l'enveloppe globale protège la
 *  facture. Une limite par client ne borne pas la dépense — cent clients
 *  respectant chacun leur quota consomment cent fois le quota. */
export type ConsommationReport = {
  debit_par_client: {
    clients_suivis: number;
    rate_per_minute: number;
    burst: number;
    portee: string;
  };
  enveloppe_globale:
    | { actif: false; max_par_heure: 0 }
    | { actif: true; consommes: number; max_par_heure: number; portee: string };
  endpoints_limites: string[];
  jeton_partage: boolean;
};

// -- assistant sécurité ancré (lot 8) --------------------------------------

/** Un passage réel du dépôt, cité à l'appui d'une réponse.
 *
 *  L'assistant ne « sait » rien : il retrouve et cite. C'est ce qui rend une
 *  réponse vérifiable par le lecteur au lieu d'être à croire sur parole. */
export type AssistantSource = {
  titre: string;
  source: string;
  origine: string;
  score: number;
  extrait: string;
};

/** Rapport du vérificateur d'ancrage sur une reformulation par un modèle.
 *
 *  Le contrôle est lexical : il empêche d'inventer un chiffre, pas de mal
 *  l'employer. Cette nuance est affichée à l'écran, pas seulement documentée. */
export type AncrageReport = {
  ok: boolean;
  raison: string | null;
  nombres_non_soutenus: string[];
  identifiants_non_soutenus: string[];
  nombres_verifies: number;
  identifiants_verifies: number;
};

export type AssistantResult = {
  reponse: string;
  a_repondu: boolean;
  /** "ancree" | "reformulee" | "ancree_apres_rejet" | "ancree_requete_bloquee" */
  mode_reponse: string;
  sources: AssistantSource[];
  llm_disponible: boolean;
  ancrage: AncrageReport | null;
  requete_bloquee: boolean;
  regles_declenchees: string[];
  note: string;
};

export type SignalVu = {
  id: string;
  role: string;
  tire: boolean;
  valeur: number | null;
  echelle: string;
};

export type AttaqueResult = {
  message_preview: string;
  requete_bloquee: boolean;
  regles_declenchees: string[];
  descriptions: string[];
  decision_risk: number;
  observed_max_risk: number;
  signaux: SignalVu[];
  neutralise: boolean;
  contenu_neutralise: string;
  reponse: AssistantResult;
  verdict: string;
  explication: string;
};
