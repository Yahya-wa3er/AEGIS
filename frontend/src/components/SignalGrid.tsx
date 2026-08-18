"use client";

/**
 * État des signaux et des capteurs.
 *
 * Ce panneau existe à cause d'un anti-pattern précis : l'ancien tableau de bord
 * affichait « ✔ Comportement jugé normal » pour un détecteur dont le modèle
 * n'était pas entraîné. Du vert pour un capteur débranché, c'est ce qu'on peut
 * faire de pire en supervision de sécurité.
 *
 * Ici, trois états distincts et jamais confondus : le capteur tourne, le
 * capteur est éteint, le capteur ne sait pas se décrire.
 */
import { SIGNAL_LABELS } from "@/lib/format";
import type { RobustnessReport, VerdictDetails } from "@/lib/types";
import { Dot, Panel, Pill } from "./ui";

const ORDRE = ["rules", "injection_ml", "rag_outlier", "retrieval_stuffing"] as const;

export function SignalGrid({
  details,
  report,
}: {
  details?: Partial<VerdictDetails>;
  report?: RobustnessReport | null;
}) {
  const bloquants = new Set(details?.blocking_signals ?? []);
  const consultatifs = new Set(details?.advisory_signals ?? []);

  // Le détecteur ML porte le même nom côté signal et côté capteur : on peut
  // donc dire non seulement « il n'a pas tiré » mais « il ne tournait pas ».
  const capteur = (signal: string) => report?.detectors?.[signal];

  return (
    <Panel
      title="Signaux de contenu"
      subtitle="Un seul a le droit de décider. Les autres observent, et le journal compte ce qu'ils auraient fait."
    >
      <ul className="space-y-2">
        {ORDRE.map((signal) => {
          const meta = SIGNAL_LABELS[signal];
          const etat = capteur(signal);
          const eteint = etat?.available === false;
          const inconnu = etat?.available === null;

          // Le point dit ce que le signal A FAIT, pas si la nouvelle est bonne.
          // Vert sur un signal muet laisserait croire à une vérification ; il n'a
          // fait que se taire. Rouge sur la règle qui vient d'arrêter une attaque
          // dirait l'inverse de ce qui s'est passé.
          const tire = bloquants.has(signal) || consultatifs.has(signal);
          const tone = bloquants.has(signal) ? "accent" : consultatifs.has(signal) ? "warn" : "muted";

          return (
            <li
              key={signal}
              className="flex items-start gap-3 rounded-lg border border-[var(--line)] bg-[var(--surface-2)] px-3 py-2.5"
            >
              <span className="mt-1.5">
                <Dot
                  tone={eteint ? "danger" : tire ? tone : "muted"}
                  title={
                    eteint
                      ? "capteur éteint — ce silence ne veut pas dire « rien à signaler »"
                      : tire
                        ? "a tiré sur ce contenu"
                        : "a regardé, n'a rien signalé"
                  }
                />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{meta.nom}</span>
                  {signal === "rules" ? (
                    <Pill tone="accent">bloquant</Pill>
                  ) : (
                    <Pill tone="muted">consultatif</Pill>
                  )}
                  {bloquants.has(signal) && <Pill tone="accent">a décidé le blocage</Pill>}
                  {consultatifs.has(signal) && <Pill tone="warn">aurait bloqué</Pill>}
                  {eteint && <Pill tone="danger">capteur éteint</Pill>}
                  {inconnu && <Pill tone="muted">état inconnu</Pill>}
                </div>
                <p className="mt-1 text-[12px] leading-snug text-[var(--faint)]">{meta.quoi}</p>
                {eteint && etat?.reason && (
                  <p className="mt-1 text-[12px] leading-snug text-[var(--warn)]">{etat.reason}</p>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      {details?.would_have_blocked && (
        <p className="mt-3 rounded-lg border border-[var(--warn-line)] bg-[var(--warn-soft)] px-3 py-2.5 text-[12px] leading-relaxed text-[var(--warn)]">
          Un signal consultatif aurait neutralisé ce contenu s&apos;il en avait eu le droit. C&apos;est
          ce compteur qui permettra de le lui rendre — avec des chiffres plutôt qu&apos;une intuition.
        </p>
      )}
    </Panel>
  );
}
