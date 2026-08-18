"use client";

/**
 * Simulation de bout en bout : l'agent réel, appels de modèle compris.
 *
 * C'est le seul écran qui dépende d'une clé d'API. Il vaut pour ce que les
 * autres ne peuvent pas montrer : ce que le client final reçoit, et quelles
 * actions se sont réellement exécutées.
 *
 * Deux colonnes, protégé et non protégé, parce que la seule comparaison qui
 * compte est celle-là. Et un verdict à quatre valeurs plutôt qu'un booléen :
 * « une attaque a réussi » et « l'agent a fait quelque chose qu'il ne devait
 * pas » ne se confondent pas.
 */
import { useState } from "react";
import { runSimulation } from "@/lib/api";
import { SENSITIVE_TOOLS, STEP_LABELS, VERDICT_TONE, describeEvent } from "@/lib/format";
import type { SimulationResult } from "@/lib/types";
import { Button, Empty, Loading, Panel, Pill, Stat } from "./ui";

export function SimulationPanel() {
  const [protege, setProtege] = useState<SimulationResult | null>(null);
  const [nonProtege, setNonProtege] = useState<SimulationResult | null>(null);
  const [chargement, setChargement] = useState(false);
  const [erreur, setErreur] = useState<string | null>(null);

  async function lancer() {
    setChargement(true);
    setErreur(null);
    try {
      // En série : les deux exécutions partagent l'état des outils mockés.
      const sans = await runSimulation("unprotected");
      setNonProtege(sans);
      const avec = await runSimulation("protected");
      setProtege(avec);
    } catch (e) {
      setErreur((e as Error).message);
    } finally {
      setChargement(false);
    }
  }

  const report = protege?.robustness_report ?? null;

  return (
    <div className="space-y-4">
      <Panel
        title="Simulation complète"
        subtitle="Le même ticket piégé, avec puis sans AEGIS. Appels LLM réels — nécessite OPENROUTER_API_KEY."
        right={
          <Button variant="primary" onClick={lancer} disabled={chargement}>
            {chargement ? "Simulation…" : "▶ Lancer"}
          </Button>
        }
      >
        {chargement && <Loading label="Exécution de l'agent, avec et sans protection…" />}
        {erreur && (
          <div className="rounded-lg border border-[var(--danger-line)] bg-[var(--danger-soft)] px-3.5 py-3 text-[13px] text-[var(--danger)]">
            {erreur}
            <p className="mt-1 text-[12px] text-[var(--muted)]">
              Cet écran est le seul à dépendre d&apos;un service externe. Le banc de scénarios et le
              laboratoire fonctionnent sans clé.
            </p>
          </div>
        )}
        {!chargement && !erreur && !protege && (
          <Empty>Lance la simulation pour comparer les deux exécutions.</Empty>
        )}

        {protege && !chargement && report && (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Stat
              label="Documents neutralisés"
              value={report.retrievals_flagged}
              hint={`${report.retrievals_scanned} analysé(s)`}
              tone={report.retrievals_flagged ? "ok" : "muted"}
            />
            <Stat
              label="Actions bloquées"
              value={report.tool_calls_blocked}
              hint={`${report.tool_calls_total} demandée(s)`}
              tone={report.tool_calls_blocked ? "ok" : "muted"}
            />
            <Stat
              label="Journal d'audit"
              value={report.audit_integrity.is_signed ? "signé" : "non signé"}
              hint={
                report.audit_integrity.is_signed
                  ? `${report.audit_integrity.signatures_verified} signature(s) Ed25519 vérifiée(s)`
                  : "chaîne cohérente, mais reforgeable"
              }
              tone={report.audit_integrity.ok ? (report.audit_integrity.is_signed ? "ok" : "warn") : "danger"}
            />
            <Stat
              label="Isolation des sessions"
              value={report.session_isolation.degraded ? "partagée" : "par session"}
              hint={
                report.session_isolation.degraded
                  ? `${report.session_isolation.anonymous} fenêtre(s) sans identifiant`
                  : report.session_isolation.keyed_by.join(" / ")
              }
              tone={report.session_isolation.degraded ? "warn" : "ok"}
            />
          </div>
        )}
      </Panel>

      {(protege || nonProtege) && !chargement && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Colonne titre="Sans AEGIS" resultat={nonProtege} protege={false} />
          <Colonne titre="Avec AEGIS" resultat={protege} protege />
        </div>
      )}

      {protege?.audit_log && !chargement && (
        <Panel
          title="Journal d'audit"
          subtitle="Chaîné, signé, append-only. Les données personnelles y sont pseudonymisées avant hachage."
          right={<Pill tone="ok">{protege.audit_log.length} entrées</Pill>}
        >
          <ol className="space-y-1">
            {protege.audit_log.map((entree) => {
              const { text, ok } = describeEvent(entree.event);
              return (
                <li
                  key={entree.id}
                  className="flex items-start gap-3 rounded-lg border border-[var(--line)] bg-[var(--surface-2)] px-3 py-2"
                >
                  <span className="tabular text-[11px] text-[var(--faint)]">#{entree.id}</span>
                  <span className={`flex-1 text-[13px] leading-snug ${ok ? "" : "text-[var(--warn)]"}`}>
                    {text}
                  </span>
                  <span className="tabular text-[11px] text-[var(--faint)]">{entree.hash}</span>
                </li>
              );
            })}
          </ol>
        </Panel>
      )}
    </div>
  );
}

function Colonne({
  titre,
  resultat,
  protege,
}: {
  titre: string;
  resultat: SimulationResult | null;
  protege: boolean;
}) {
  if (!resultat) return <Panel title={titre}><Empty>Aucune exécution.</Empty></Panel>;

  const verdict = resultat.verdict;
  // Sans AEGIS, une attaque neutralisée l'a été par le modèle lui-même : le dire
  // évite de s'attribuer un mérite qui ne nous revient pas.
  const label =
    verdict.kind === "attack_neutralized" && !protege
      ? "Résistance native du modèle"
      : verdict.label;

  const executees = resultat.executed_actions;
  const sensibles = executees.filter((a) => SENSITIVE_TOOLS.includes(a.tool));

  return (
    <Panel
      title={titre}
      right={<Pill tone={VERDICT_TONE[verdict.kind]}>{label}</Pill>}
    >
      <div className="space-y-3">
        <p className="text-[12px] leading-relaxed text-[var(--muted)]">{verdict.explanation}</p>

        <div>
          <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--faint)]">
            Actions réellement exécutées
          </div>
          {executees.length === 0 ? (
            <p className="mt-1 text-[13px] text-[var(--ok)]">Aucune.</p>
          ) : (
            <ul className="mt-1 space-y-1">
              {executees.map((a, i) => (
                <li
                  key={i}
                  className={`tabular rounded-md border px-2 py-1 text-[12px] ${
                    SENSITIVE_TOOLS.includes(a.tool)
                      ? "border-[var(--danger-line)] bg-[var(--danger-soft)] text-[var(--danger)]"
                      : "border-[var(--line)] bg-[var(--surface-2)] text-[var(--muted)]"
                  }`}
                >
                  {a.tool}({JSON.stringify(a.params)})
                </li>
              ))}
            </ul>
          )}
          {sensibles.length > 0 && (
            <p className="mt-1.5 text-[12px] text-[var(--danger)]">
              {sensibles.length} action(s) sensible(s) exécutée(s).
            </p>
          )}
        </div>

        <div>
          <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--faint)]">Trace</div>
          <ol className="mt-1 space-y-1">
            {resultat.trace.map((step, i) => (
              <li key={i} className="flex items-start gap-2 text-[12px]">
                <span className="tabular w-4 text-[var(--faint)]">{i + 1}</span>
                <span className="w-40 shrink-0 font-medium text-[var(--accent-strong)]">
                  {STEP_LABELS[step.step] ?? step.step}
                </span>
                <span className="tabular min-w-0 flex-1 break-all text-[var(--faint)]">
                  {JSON.stringify(step.detail).slice(0, 160)}
                </span>
              </li>
            ))}
          </ol>
        </div>

        <div>
          <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--faint)]">
            Réponse au client
          </div>
          <p className="mt-1 rounded-lg border border-[var(--line)] bg-[var(--surface-2)] px-3 py-2 text-[13px] leading-relaxed">
            {resultat.response || "—"}
          </p>
        </div>

        {resultat.output_scan && (
          <div>
            <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--faint)]">
              Filtre de sortie
            </div>
            {resultat.output_scan.modified ? (
              <div className="mt-1 space-y-1.5">
                <p className="rounded-lg border border-[var(--line)] px-3 py-2 text-[12px] leading-relaxed text-[var(--faint)] line-through">
                  {resultat.output_scan.avant}
                </p>
                <p className="rounded-lg border border-[var(--danger-line)] bg-[var(--danger-soft)] px-3 py-2 text-[13px] leading-relaxed">
                  {resultat.output_scan.apres}
                </p>
                <p className="text-[12px] text-[var(--danger)]">
                  Réponse modifiée avant remise au client.
                </p>
              </div>
            ) : resultat.output_scan.flagged ? (
              <p className="mt-1 text-[12px] text-[var(--warn)]">
                Vu et journalisé, mais rien n&apos;a été changé dans la réponse.
              </p>
            ) : (
              <p className="mt-1 text-[12px] text-[var(--ok)]">Rien à signaler.</p>
            )}
            {(resultat.output_scan.secrets_masques.length > 0 ||
              resultat.output_scan.donnees_personnelles.length > 0 ||
              resultat.output_scan.contexte_restitue.length > 0 ||
              resultat.output_scan.balisage_neutralise.length > 0) && (
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {resultat.output_scan.secrets_masques.map((s) => (
                  <Pill key={`secret-${s}`} tone="danger">
                    secret masqué : {s}
                  </Pill>
                ))}
                {resultat.output_scan.donnees_personnelles.map((s) => (
                  <Pill key={`donnee-${s}`} tone="warn">
                    donnée personnelle {resultat.output_scan!.donnees_personnelles_masquees ? "masquée" : "signalée"} : {s}
                  </Pill>
                ))}
                {resultat.output_scan.contexte_restitue.length > 0 && (
                  <Pill tone="danger">prompt système restitué</Pill>
                )}
                {resultat.output_scan.balisage_neutralise.map((b) => (
                  <Pill key={`balisage-${b}`} tone="warn">
                    balisage neutralisé : {b}
                  </Pill>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </Panel>
  );
}
