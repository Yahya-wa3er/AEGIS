"use client";

/**
 * Banc de scénarios — la pièce centrale de la console.
 *
 * Douze situations jouables, réparties sur les cinq points d'interception, et
 * **aucun appel LLM** : la partie du produit qui décide ne dépend d'aucun
 * service externe, et une démonstration doit pouvoir le montrer plutôt que
 * l'affirmer.
 *
 * Chaque exécution affiche quel point a traité la requête, quel signal a tiré,
 * lequel avait le droit de décider — et l'écart éventuel avec ce que le
 * scénario annonce. Un blocage obtenu par le mauvais signal est un coup de
 * chance, pas une défense : la console le dit.
 */
import { useEffect, useState } from "react";
import { fetchScenarios, runScenario } from "@/lib/api";
import { toneForScenarioVerdict } from "@/lib/format";
import type { ScenarioRun, ScenarioSummary } from "@/lib/types";
import { SignalGrid } from "./SignalGrid";
import { Button, Code, Empty, Loading, LookHere, Meter, Panel, Pill } from "./ui";

const POINT_LABELS: Record<string, string> = {
  on_prompt: "on_prompt · requête utilisateur",
  on_retrieval: "on_retrieval · document récupéré",
  on_tool_call: "on_tool_call · appel d'outil",
  on_tool_result: "on_tool_result · retour d'outil",
};

export function ScenarioBench() {
  const [catalogue, setCatalogue] = useState<ScenarioSummary[] | null>(null);
  const [familles, setFamilles] = useState<string[]>([]);
  const [actif, setActif] = useState<string | null>(null);
  const [run, setRun] = useState<ScenarioRun | null>(null);
  const [chargement, setChargement] = useState(false);
  const [erreur, setErreur] = useState<string | null>(null);

  // On joue le premier scénario dès l'arrivée. Un tableau de bord de sécurité
  // qui s'ouvre sur un panneau vide demande au visiteur de deviner par où
  // commencer — et la plupart repartent sans avoir rien vu.
  useEffect(() => {
    let annule = false;
    fetchScenarios()
      .then((c) => {
        if (annule) return;
        setCatalogue(c.scenarios);
        setFamilles(c.familles);
        if (c.scenarios.length) void jouer(c.scenarios[0].id);
      })
      .catch((e: Error) => !annule && setErreur(e.message));
    return () => {
      annule = true;
    };
  }, []);

  async function jouer(id: string) {
    setActif(id);
    setChargement(true);
    setErreur(null);
    try {
      setRun(await runScenario(id));
    } catch (e) {
      setErreur((e as Error).message);
      setRun(null);
    } finally {
      setChargement(false);
    }
  }

  if (erreur && !catalogue) return <Panel title="Banc de scénarios"><Empty>{erreur}</Empty></Panel>;
  if (!catalogue) return <Panel title="Banc de scénarios"><Loading label="Chargement du catalogue…" /></Panel>;

  const scenario = catalogue.find((s) => s.id === actif) ?? null;

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,340px)_minmax(0,1fr)]">
      <Panel
        title="Scénarios"
        subtitle={`${catalogue.length} situations · aucun appel LLM`}
        className="h-fit lg:sticky lg:top-4"
      >
        <div className="max-h-[70vh] space-y-3 overflow-y-auto pr-1">
          {familles.map((famille) => (
            <div key={famille}>
              <div className="mb-1 text-[10px] uppercase tracking-[0.14em] text-[var(--faint)]">
                {famille}
              </div>
              <ul className="space-y-0.5">
                {catalogue
                  .filter((s) => s.famille === famille)
                  .map((s) => (
                    <li key={s.id}>
                      <button
                        onClick={() => jouer(s.id)}
                        className={`flex w-full items-baseline gap-2 rounded-md border px-2.5 py-1.5 text-left transition-colors ${
                          actif === s.id
                            ? "border-[var(--accent)]/50 bg-[var(--accent)]/10"
                            : "border-transparent hover:border-[var(--line)] hover:bg-white/[0.03]"
                        }`}
                      >
                        <span className="tabular w-11 shrink-0 text-[10px] text-[var(--faint)]">
                          {s.est_attaque ? s.owasp : "ctrl"}
                        </span>
                        <span className="min-w-0 flex-1 text-[12.5px] leading-snug">{s.titre}</span>
                      </button>
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </div>
      </Panel>

      <div className="space-y-4">
        {!scenario && (
          <Panel title="Résultat">
            <Empty>Choisis un scénario à gauche pour le rejouer contre l&apos;arbitrage complet.</Empty>
          </Panel>
        )}

        {scenario && (
          <Panel
            title={scenario.titre}
            subtitle={`${scenario.famille} · ${scenario.owasp}`}
            right={
              run && !chargement ? (
                <Pill tone={run.ecarts.length ? "danger" : toneForScenarioVerdict(run.verdict)}>
                  {run.ecarts.length ? `écart : ${run.ecarts.join(", ")}` : run.verdict}
                </Pill>
              ) : null
            }
          >
            {chargement && <Loading label="Exécution du scénario…" />}

            {!chargement && run && (
              <div className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label="Requête de l'utilisateur">
                    <span className="text-[13px]">{scenario.requete}</span>
                  </Field>
                  <Field label="Point d'interception">
                    <Code>{POINT_LABELS[run.point] ?? run.point}</Code>
                  </Field>
                </div>

                <Field label="Attendu">
                  <span className="text-[13px] text-[var(--muted)]">{scenario.attendu}</span>
                </Field>

                {run.details?.matched_rules && run.details.matched_rules.length > 0 && (
                  <Field label="Règles déclenchées">
                    <div className="flex flex-wrap gap-1.5">
                      {run.details.matched_rules.map((r) => (
                        <Pill key={r} tone="danger">{r}</Pill>
                      ))}
                    </div>
                  </Field>
                )}

                {run.details?.stuffing && <StuffingCard stuffing={run.details.stuffing} />}

                <LookHere>{scenario.regarder}</LookHere>
              </div>
            )}

            {!chargement && !run && erreur && <Empty>{erreur}</Empty>}
            {!chargement && !run && !erreur && (
              <Button variant="primary" onClick={() => jouer(scenario.id)}>
                ▶ Rejouer ce scénario
              </Button>
            )}
          </Panel>
        )}

        {run && !chargement && <SignalGrid details={run.details} />}
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--faint)]">{label}</div>
      <div className="mt-1">{children}</div>
    </div>
  );
}

/**
 * Détail du signal d'intégrité du classement.
 *
 * On affiche le TTR **avec sa bande attendue**, jamais seul : « 0,535 » ne veut
 * rien dire, « 0,535 pour une bande [0,474 ; 0,684] » explique le verdict — y
 * compris quand ce verdict est « je n'ai rien vu ».
 */
function StuffingCard({
  stuffing,
}: {
  stuffing: NonNullable<ScenarioRun["details"]["stuffing"]>;
}) {
  const [bas, haut] = stuffing.expected_range;
  return (
    <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-2)]/50 p-3">
      <div className="flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-[0.12em] text-[var(--faint)]">
          Intégrité du classement
        </span>
        <Pill tone={stuffing.flagged ? "warn" : "muted"}>
          {stuffing.flagged ? "bourrage détecté" : "dans la bande du français réel"}
        </Pill>
      </div>

      <div className="tabular mt-2 flex items-baseline gap-4 text-sm">
        <span>
          TTR <span className="text-[var(--accent)]">{stuffing.ttr.toFixed(3)}</span>
        </span>
        <span className="text-[var(--faint)]">
          bande [{bas.toFixed(3)} ; {haut.toFixed(3)}] · {stuffing.tokens} mots
        </span>
      </div>

      <div className="relative mt-2">
        <Meter value={stuffing.ttr} tone={stuffing.flagged ? "warn" : "ok"} />
        <div
          className="absolute top-0 h-1.5 rounded-full bg-white/[0.14]"
          style={{ left: `${bas * 100}%`, width: `${(haut - bas) * 100}%` }}
          title="bande attendue pour cette longueur"
        />
      </div>

      {stuffing.reason && (
        <p className="mt-2 text-[12px] leading-snug text-[var(--warn)]">{stuffing.reason}</p>
      )}

      {stuffing.top_terms?.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {stuffing.top_terms.slice(0, 5).map(([mot, n]) => (
            <span
              key={mot}
              className="tabular rounded border border-[var(--line)] px-1.5 py-0.5 text-[11px] text-[var(--muted)]"
            >
              {mot} ×{n}
            </span>
          ))}
        </div>
      )}

      {!stuffing.flagged && stuffing.tokens > 200 && (
        <p className="mt-2 text-[12px] leading-relaxed text-[var(--faint)]">
          Le document est long et le TTR reste dans la bande : c&apos;est exactement l&apos;évasion
          hybride documentée. Ce signal ne voit pas ce cas, et un test le fige pour que personne
          ne prétende le contraire.
        </p>
      )}
    </div>
  );
}
