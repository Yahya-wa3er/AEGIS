"use client";

/**
 * Primitives de la console.
 *
 * Elles existent pour qu'un panneau se déclare plutôt que se dessine : sans
 * elles, chaque bloc réinvente ses bordures et ses espacements, et l'ensemble
 * cesse d'avoir l'air d'un seul produit. C'est le défaut principal du fichier
 * de 1052 lignes que ce lot remplace.
 */
import type { ReactNode } from "react";
import { TONE_CLASS, type VerdictTone } from "@/lib/format";

export function Panel({
  title,
  subtitle,
  right,
  children,
  className = "",
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-[var(--line)] bg-[var(--surface)]/80 backdrop-blur-sm ${className}`}
    >
      {(title || right) && (
        <header className="flex items-start gap-3 px-4 py-3 border-b border-[var(--line)]">
          <div className="min-w-0">
            {title && (
              <h2 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--muted)]">
                {title}
              </h2>
            )}
            {subtitle && <p className="text-xs text-[var(--faint)] mt-1">{subtitle}</p>}
          </div>
          {right && <div className="ml-auto shrink-0">{right}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Pill({
  tone = "muted",
  children,
  title,
}: {
  tone?: VerdictTone;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium ${TONE_CLASS[tone]}`}
    >
      {children}
    </span>
  );
}

/** Point d'état. Le titre porte l'explication : une pastille de couleur seule
 *  n'est pas accessible, et n'apprend rien à qui la découvre. */
export function Dot({ tone, title }: { tone: VerdictTone; title: string }) {
  const color = {
    ok: "bg-[var(--ok)]",
    warn: "bg-[var(--warn)]",
    danger: "bg-[var(--danger)]",
    muted: "bg-[var(--faint)]",
  }[tone];
  return <span title={title} aria-label={title} className={`inline-block h-2 w-2 rounded-full ${color}`} />;
}

export function Stat({
  label,
  value,
  hint,
  tone = "muted",
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: VerdictTone;
}) {
  const color = {
    ok: "text-[var(--ok)]",
    warn: "text-[var(--warn)]",
    danger: "text-[var(--danger)]",
    muted: "text-[var(--text)]",
  }[tone];
  return (
    <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-2)]/60 px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--faint)]">{label}</div>
      <div className={`tabular mt-1 text-xl leading-none ${color}`}>{value}</div>
      {hint && <div className="mt-1.5 text-[11px] leading-snug text-[var(--faint)]">{hint}</div>}
    </div>
  );
}

/** Barre de score. `reference` trace le seuil : un score sans son seuil ne dit
 *  rien — c'est la différence entre « 0,78 » et « 0,78 pour un seuil à 0,74 ». */
export function Meter({
  value,
  max = 1,
  reference,
  tone = "muted",
}: {
  value: number;
  max?: number;
  reference?: number;
  tone?: VerdictTone;
}) {
  const clamp = (v: number) => Math.max(0, Math.min(1, v / max));
  const bg = {
    ok: "bg-[var(--ok)]",
    warn: "bg-[var(--warn)]",
    danger: "bg-[var(--danger)]",
    muted: "bg-[var(--accent)]",
  }[tone];
  return (
    <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]">
      <div className={`h-full rounded-full ${bg}`} style={{ width: `${clamp(value) * 100}%` }} />
      {reference !== undefined && (
        <div
          className="absolute top-0 h-full w-px bg-[var(--text)]/60"
          style={{ left: `${clamp(reference) * 100}%` }}
          title={`seuil ${reference.toFixed(3)}`}
        />
      )}
    </div>
  );
}

export function Button({
  children,
  onClick,
  disabled,
  variant = "ghost",
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "primary" | "ghost" | "danger";
  type?: "button" | "submit";
}) {
  const styles = {
    primary:
      "bg-[var(--accent)]/15 text-[var(--accent)] border-[var(--accent)]/40 hover:bg-[var(--accent)]/25",
    ghost:
      "bg-white/[0.03] text-[var(--text)] border-[var(--line)] hover:bg-white/[0.07]",
    danger:
      "bg-[var(--danger)]/12 text-[var(--danger)] border-[var(--danger)]/35 hover:bg-[var(--danger)]/20",
  }[variant];
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`rounded-lg border px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${styles}`}
    >
      {children}
    </button>
  );
}

export function Loading({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3 py-6 text-sm text-[var(--muted)]">
      <div className="sweep relative h-0.5 w-28 overflow-hidden rounded-full bg-white/[0.06]" />
      {label}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <p className="py-8 text-center text-sm text-[var(--faint)]">{children}</p>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return (
    <code className="tabular rounded bg-white/[0.05] px-1.5 py-0.5 text-[12px] text-[var(--accent)]">
      {children}
    </code>
  );
}

/** Encadré « à regarder ». Un banc d'essai qui montre un résultat sans dire
 *  quoi observer ne démontre rien. */
export function LookHere({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border-l-2 border-[var(--accent)]/50 bg-[var(--accent)]/[0.06] px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--accent)]">À regarder</div>
      <p className="mt-1 text-[13px] leading-relaxed text-[var(--muted)]">{children}</p>
    </div>
  );
}
