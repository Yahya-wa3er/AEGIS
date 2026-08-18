"use client";

/**
 * Primitives de la console, alignées sur la charte FLUGIA.
 *
 * Elles existent pour qu'un panneau se déclare plutôt que se dessine : sans
 * elles, chaque bloc réinvente ses bordures et ses espacements, et l'ensemble
 * cesse d'avoir l'air d'un seul produit. C'est le défaut principal du fichier
 * de 1052 lignes que la refonte a remplacé.
 *
 * Trois formes reprises de la charte, et une seule fois chacune :
 * la **carte** (fond blanc, bordure fine, coins 12px, ombre à peine posée),
 * le **badge en pilule** (bordure claire, point de couleur, texte petit),
 * et le **chip d'icône** (carré arrondi rempli d'une teinte pleine).
 */
import type { ReactNode } from "react";

export type Tone = "accent" | "ok" | "warn" | "danger" | "muted";

/** Un ton = trois variables. Les garder ensemble évite les combinaisons
 *  bancales (texte ambre sur fond rouge) qu'on finit toujours par écrire quand
 *  chaque couleur se choisit à la main. */
const TONE: Record<Tone, { text: string; soft: string; line: string; solid: string }> = {
  accent: {
    text: "text-[var(--accent-strong)]",
    soft: "bg-[var(--accent-soft)]",
    line: "border-[var(--accent-line)]",
    solid: "bg-[var(--accent)]",
  },
  ok: {
    text: "text-[var(--ok)]",
    soft: "bg-[var(--ok-soft)]",
    line: "border-[var(--ok-line)]",
    solid: "bg-[var(--ok)]",
  },
  warn: {
    text: "text-[var(--warn)]",
    soft: "bg-[var(--warn-soft)]",
    line: "border-[var(--warn-line)]",
    solid: "bg-[var(--warn)]",
  },
  danger: {
    text: "text-[var(--danger)]",
    soft: "bg-[var(--danger-soft)]",
    line: "border-[var(--danger-line)]",
    solid: "bg-[var(--danger)]",
  },
  muted: {
    text: "text-[var(--muted)]",
    soft: "bg-[var(--surface-2)]",
    line: "border-[var(--line)]",
    solid: "bg-[var(--faint)]",
  },
};

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
      className={`rounded-xl border border-[var(--line)] bg-[var(--surface)] shadow-[var(--shadow-card)] ${className}`}
    >
      {(title || right) && (
        <header className="flex items-start gap-3 border-b border-[var(--line)] px-4 py-3">
          <div className="min-w-0">
            {title && (
              <h2 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--muted)]">
                {title}
              </h2>
            )}
            {subtitle && <p className="mt-1 text-xs text-[var(--faint)]">{subtitle}</p>}
          </div>
          {right && <div className="ml-auto shrink-0">{right}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

/** Badge en pilule de la charte : fond blanc, bordure teintée, point de couleur.
 *  `solid` remplit la pilule — réservé au fait marquant d'un écran. */
export function Pill({
  tone = "muted",
  children,
  title,
  dot = true,
  solid = false,
}: {
  tone?: Tone;
  children: ReactNode;
  title?: string;
  dot?: boolean;
  solid?: boolean;
}) {
  const t = TONE[tone];
  return (
    <span
      title={title}
      className={
        solid
          ? `inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium text-white ${t.solid}`
          : `inline-flex items-center gap-1.5 rounded-full border bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium ${t.line} ${t.text}`
      }
    >
      {dot && !solid && <span className={`h-1.5 w-1.5 rounded-full ${t.solid}`} />}
      {children}
    </span>
  );
}

/** Point d'état. Le titre porte l'explication : une pastille de couleur seule
 *  n'est pas accessible, et n'apprend rien à qui la découvre. */
export function Dot({ tone, title }: { tone: Tone; title: string }) {
  return (
    <span
      title={title}
      aria-label={title}
      className={`inline-block h-2 w-2 rounded-full ${TONE[tone].solid}`}
    />
  );
}

/** Chip d'icône de la charte : carré arrondi rempli, posé en tête de carte. */
export function IconChip({ tone = "accent", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-[10px] text-white ${TONE[tone].solid}`}
    >
      {children}
    </span>
  );
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
  tone?: Tone;
}) {
  return (
    <div className="rounded-xl border border-[var(--line)] bg-[var(--surface)] px-3.5 py-3 shadow-[var(--shadow-card)]">
      <div className="text-[10px] font-medium uppercase tracking-[0.12em] text-[var(--faint)]">
        {label}
      </div>
      <div className={`tabular mt-1.5 text-2xl font-semibold leading-none ${TONE[tone].text}`}>
        {value}
      </div>
      {hint && <div className="mt-2 text-[11px] leading-snug text-[var(--faint)]">{hint}</div>}
    </div>
  );
}

/** Barre de score. `reference` trace le seuil : un score sans son seuil ne dit
 *  rien — c'est la différence entre « 0,78 » et « 0,78 pour un seuil à 0,74 ». */
export function Meter({
  value,
  max = 1,
  reference,
  tone = "accent",
}: {
  value: number;
  max?: number;
  reference?: number;
  tone?: Tone;
}) {
  const clamp = (v: number) => Math.max(0, Math.min(1, v / max));
  return (
    <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-[var(--surface-3)]">
      <div
        className={`h-full rounded-full ${TONE[tone].solid}`}
        style={{ width: `${clamp(value) * 100}%` }}
      />
      {reference !== undefined && (
        <div
          className="absolute top-0 h-full w-px bg-[var(--text)]/50"
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
      "bg-[var(--accent-ink)] text-white border-transparent shadow-[0_1px_2px_rgba(16,126,166,0.35)] hover:bg-[var(--accent-strong)]",
    ghost:
      "bg-[var(--surface)] text-[var(--text)] border-[var(--line-strong)] hover:bg-[var(--surface-2)]",
    danger:
      "bg-[var(--danger-soft)] text-[var(--danger)] border-[var(--danger-line)] hover:bg-[#fbe0e0]",
  }[variant];
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`rounded-lg border px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-45 ${styles}`}
    >
      {children}
    </button>
  );
}

export function Loading({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3 py-6 text-sm text-[var(--muted)]">
      <div className="sweep relative h-0.5 w-28 overflow-hidden rounded-full bg-[var(--surface-3)]" />
      {label}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-10 text-center text-sm text-[var(--faint)]">{children}</p>;
}

export function Code({ children }: { children: ReactNode }) {
  return (
    <code className="tabular rounded-md border border-[var(--accent-line)] bg-[var(--accent-soft)] px-1.5 py-0.5 text-[12px] text-[var(--accent-strong)]">
      {children}
    </code>
  );
}

/** Encadré « à regarder ». Un banc d'essai qui montre un résultat sans dire
 *  quoi observer ne démontre rien. */
export function LookHere({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-[var(--accent-line)] bg-[var(--accent-soft)] px-3.5 py-3">
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[var(--accent-strong)]">
        À regarder
      </div>
      <p className="mt-1.5 text-[13px] leading-relaxed text-[var(--text)]/80">{children}</p>
    </div>
  );
}

/** Champ étiqueté, réutilisé par tous les panneaux de résultat. */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-medium uppercase tracking-[0.12em] text-[var(--faint)]">
        {label}
      </div>
      <div className="mt-1">{children}</div>
    </div>
  );
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={`w-full rounded-lg border border-[var(--line-strong)] bg-[var(--surface)] px-3 py-2 text-sm outline-none transition-colors placeholder:text-[var(--faint)] focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/15 ${props.className ?? ""}`}
    />
  );
}

export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      className={`tabular w-full resize-y rounded-lg border border-[var(--line-strong)] bg-[var(--surface-2)] px-3 py-2 text-[12px] leading-relaxed outline-none transition-colors placeholder:text-[var(--faint)] focus:border-[var(--accent)] focus:bg-[var(--surface)] focus:ring-2 focus:ring-[var(--accent)]/15 ${props.className ?? ""}`}
    />
  );
}

/** Bouton d'exemple / de préréglage — la petite pilule cliquable de la charte. */
export function Chip({
  children,
  onClick,
  active = false,
}: {
  children: ReactNode;
  onClick?: () => void;
  active?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-3 py-1 text-[12px] transition-colors ${
        active
          ? "border-[var(--accent-line)] bg-[var(--accent-soft)] text-[var(--accent-strong)]"
          : "border-[var(--line-strong)] bg-[var(--surface)] text-[var(--muted)] hover:border-[var(--accent-line)] hover:text-[var(--text)]"
      }`}
    >
      {children}
    </button>
  );
}
