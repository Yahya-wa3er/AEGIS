"use client";

/**
 * Coquille de l'application — barre latérale et barre supérieure.
 *
 * Le pattern est celui de la charte FLUGIA : logo en haut à gauche, sections en
 * capitales espacées, entrée active en pilule bleue pleine, barre supérieure
 * fine avec recherche à gauche et état à droite.
 *
 * L'ORGANISATION, elle, est celle de notre produit et pas celle d'un tableau de
 * bord de départements : quatre bancs d'essai et une vue d'ensemble. Reprendre
 * la structure d'un autre produit aurait donné une console jolie et
 * inutilisable.
 *
 * La recherche n'est pas décorative : elle filtre réellement les bancs et les
 * scénarios, et sélectionner un résultat navigue. Une barre de recherche qui ne
 * cherche rien est le premier signe qu'une interface a été copiée plutôt que
 * conçue.
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import type { ScenarioSummary } from "@/lib/types";

export type VueId =
  | "apercu"
  | "scenarios"
  | "document"
  | "classement"
  | "simulation";

export const VUES: {
  id: VueId;
  /** Libellé court de la barre latérale : elle fait 248px, un texte tronqué
   *  par « … » y est moins lisible qu'un nom court choisi exprès. */
  label: string;
  /** Titre de l'en-tête de page, où la place ne manque pas. */
  titreLong?: string;
  section: "PANORAMA" | "BANCS D'ESSAI";
  icone: ReactNode;
  hint: string;
  sansLlm: boolean;
}[] = [
  {
    id: "apercu",
    label: "Vue d'ensemble",
    section: "PANORAMA",
    icone: <IconGrid />,
    hint: "Les quatre signaux de contenu, ce que chacun a le droit de décider, et les propriétés du système",
    sansLlm: true,
  },
  {
    id: "scenarios",
    label: "Banc de scénarios",
    section: "BANCS D'ESSAI",
    icone: <IconTarget />,
    hint: "12 situations sur les 5 points d'interception",
    sansLlm: true,
  },
  {
    id: "document",
    label: "Analyse de document",
    titreLong: "Analyse de document",
    section: "BANCS D'ESSAI",
    icone: <IconDoc />,
    hint: "Colle ce que tu veux, vois la décision et les signaux qui l'ont prise",
    sansLlm: true,
  },
  {
    id: "classement",
    label: "Classement",
    titreLong: "Laboratoire de classement",
    section: "BANCS D'ESSAI",
    icone: <IconRank />,
    hint: "L'attaque sur la sélection des documents, rejouable à volonté",
    sansLlm: true,
  },
  {
    id: "simulation",
    label: "Simulation",
    titreLong: "Simulation complète",
    section: "BANCS D'ESSAI",
    icone: <IconPlay />,
    hint: "L'agent réel, avec et sans protection — seul écran qui appelle un LLM",
    sansLlm: false,
  },
];

const SECTIONS = ["PANORAMA", "BANCS D'ESSAI"] as const;

export function AppShell({
  vue,
  onVue,
  scenarios,
  onScenario,
  children,
}: {
  vue: VueId;
  onVue: (v: VueId) => void;
  scenarios: ScenarioSummary[];
  onScenario: (id: string) => void;
  children: ReactNode;
}) {
  const active = VUES.find((v) => v.id === vue) ?? VUES[0];

  return (
    <div className="flex min-h-screen bg-[var(--bg)]">
      <aside className="hidden w-[248px] shrink-0 border-r border-[var(--line)] bg-[var(--surface)] lg:block">
        <div className="sticky top-0 flex h-screen flex-col">
          <div className="flex items-center gap-2.5 px-5 py-5">
            <Logo />
          </div>

          <nav className="flex-1 overflow-y-auto px-3 pb-4">
            {SECTIONS.map((section) => (
              <div key={section} className="mb-5">
                <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--faint)]">
                  {section}
                </div>
                <ul className="space-y-1">
                  {VUES.filter((v) => v.section === section).map((v) => (
                    <li key={v.id}>
                      <button
                        onClick={() => onVue(v.id)}
                        aria-current={vue === v.id ? "page" : undefined}
                        className={`flex w-full items-center gap-3 rounded-[10px] px-3 py-2.5 text-left text-[13.5px] font-medium transition-colors ${
                          vue === v.id
                            ? "bg-[var(--accent-ink)] text-white shadow-[0_1px_2px_rgba(16,126,166,0.35)]"
                            : "text-[var(--text)] hover:bg-[var(--surface-2)]"
                        }`}
                      >
                        <span className={vue === v.id ? "text-white" : "text-[var(--muted)]"}>
                          {v.icone}
                        </span>
                        <span className="min-w-0 flex-1 truncate">{v.label}</span>
                        {!v.sansLlm && (
                          <span
                            title="Cet écran appelle un LLM : il lui faut une clé d'API."
                            className={`text-[10px] ${vue === v.id ? "text-white/80" : "text-[var(--faint)]"}`}
                          >
                            LLM
                          </span>
                        )}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>

          <div className="border-t border-[var(--line)] px-5 py-4 text-[11px] leading-relaxed text-[var(--faint)]">
            Quatre écrans sur cinq fonctionnent sans clé d&apos;API.
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          vue={vue}
          onVue={onVue}
          scenarios={scenarios}
          onScenario={onScenario}
        />
        <main className="flex-1 bg-[var(--canvas)] px-5 pb-16 pt-6 lg:px-8">
          <header className="mb-6">
            <h1 className="text-[26px] font-bold tracking-tight">{active.titreLong ?? active.label}</h1>
            <p className="mt-1 text-[13px] text-[var(--muted)]">{active.hint}</p>
          </header>
          {children}
        </main>
      </div>
    </div>
  );
}

/** Barre supérieure : recherche réelle à gauche, état du produit à droite. */
function TopBar({
  vue,
  onVue,
  scenarios,
  onScenario,
}: {
  vue: VueId;
  onVue: (v: VueId) => void;
  scenarios: ScenarioSummary[];
  onScenario: (id: string) => void;
}) {
  const [q, setQ] = useState("");
  const [ouvert, setOuvert] = useState(false);
  const champ = useRef<HTMLInputElement>(null);
  const zone = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const raccourci = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        champ.current?.focus();
      }
      if (e.key === "Escape") setOuvert(false);
    };
    const dehors = (e: MouseEvent) => {
      if (zone.current && !zone.current.contains(e.target as Node)) setOuvert(false);
    };
    window.addEventListener("keydown", raccourci);
    window.addEventListener("mousedown", dehors);
    return () => {
      window.removeEventListener("keydown", raccourci);
      window.removeEventListener("mousedown", dehors);
    };
  }, []);

  const terme = q.trim().toLowerCase();
  const vues = terme ? VUES.filter((v) => v.label.toLowerCase().includes(terme)) : [];
  // On cherche aussi dans l'attendu et les tags : un visiteur tape « hybride »
  // ou « évasion », pas le titre exact d'un scénario qu'il n'a pas encore lu.
  const scenarioTrouves = terme
    ? scenarios
        .filter((s) =>
          [s.titre, s.famille, s.owasp, s.attendu, ...s.tags]
            .join(" ")
            .toLowerCase()
            .includes(terme),
        )
        .slice(0, 6)
    : [];
  const rien = terme.length > 0 && vues.length === 0 && scenarioTrouves.length === 0;

  return (
    <div className="sticky top-0 z-20 flex items-center gap-4 border-b border-[var(--line)] bg-[var(--surface)]/95 px-5 py-3 backdrop-blur lg:px-8">
      <div ref={zone} className="relative w-full max-w-[420px]">
        <div className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--faint)]">
          <IconSearch />
        </div>
        <input
          ref={champ}
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setOuvert(true);
          }}
          onFocus={() => setOuvert(true)}
          placeholder="Chercher un banc, un scénario…"
          className="w-full rounded-full border border-[var(--line-strong)] bg-[var(--surface)] py-2 pl-9 pr-16 text-[13px] outline-none transition-colors placeholder:text-[var(--faint)] focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/15"
        />
        <kbd className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-[var(--line-strong)] bg-[var(--surface-2)] px-1.5 py-0.5 text-[10px] text-[var(--faint)]">
          ⌘K
        </kbd>

        {ouvert && terme.length > 0 && (
          <div className="absolute left-0 right-0 top-[calc(100%+6px)] overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--surface)] shadow-[var(--shadow-lift)]">
            {rien && (
              <p className="px-4 py-3 text-[12px] text-[var(--faint)]">Aucun résultat.</p>
            )}
            {vues.length > 0 && (
              <Groupe titre="Bancs">
                {vues.map((v) => (
                  <Resultat
                    key={v.id}
                    onClick={() => {
                      onVue(v.id);
                      setQ("");
                      setOuvert(false);
                    }}
                  >
                    <span className="text-[var(--muted)]">{v.icone}</span>
                    {v.label}
                  </Resultat>
                ))}
              </Groupe>
            )}
            {scenarioTrouves.length > 0 && (
              <Groupe titre="Scénarios">
                {scenarioTrouves.map((s) => (
                  <Resultat
                    key={s.id}
                    onClick={() => {
                      onScenario(s.id);
                      setQ("");
                      setOuvert(false);
                    }}
                  >
                    <span className="tabular w-11 shrink-0 text-[10px] text-[var(--faint)]">
                      {s.est_attaque ? s.owasp : "ctrl"}
                    </span>
                    <span className="min-w-0 flex-1 truncate">{s.titre}</span>
                  </Resultat>
                ))}
              </Groupe>
            )}
          </div>
        )}
      </div>

      <div className="ml-auto flex items-center gap-2">
        <span className="hidden items-center gap-1.5 rounded-full border border-[var(--line)] px-3 py-1.5 text-[11px] text-[var(--muted)] sm:inline-flex">
          OWASP LLM Top 10 · 2026
        </span>
        <MobileNav vue={vue} onVue={onVue} />
      </div>
    </div>
  );
}

function Groupe({ titre, children }: { titre: string; children: ReactNode }) {
  return (
    <div className="border-b border-[var(--line)] last:border-b-0">
      <div className="px-4 pb-1 pt-2.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--faint)]">
        {titre}
      </div>
      <ul className="pb-1.5">{children}</ul>
    </div>
  );
}

function Resultat({ children, onClick }: { children: ReactNode; onClick: () => void }) {
  return (
    <li>
      <button
        onClick={onClick}
        className="flex w-full items-center gap-2.5 px-4 py-2 text-left text-[13px] hover:bg-[var(--surface-2)]"
      >
        {children}
      </button>
    </li>
  );
}

/** La barre latérale disparaît sous 1024px : il faut bien naviguer quand même. */
function MobileNav({ vue, onVue }: { vue: VueId; onVue: (v: VueId) => void }) {
  return (
    <select
      value={vue}
      onChange={(e) => onVue(e.target.value as VueId)}
      aria-label="Naviguer"
      className="rounded-lg border border-[var(--line-strong)] bg-[var(--surface)] px-2.5 py-1.5 text-[12px] lg:hidden"
    >
      {VUES.map((v) => (
        <option key={v.id} value={v.id}>
          {v.label}
        </option>
      ))}
    </select>
  );
}

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <svg width="26" height="30" viewBox="0 0 34 38" aria-hidden="true">
        <path
          d="M17 2 L31 8 V19 C31 27 24.5 33.5 17 36 C9.5 33.5 3 27 3 19 V8 Z"
          fill="var(--accent-soft)"
          stroke="var(--accent)"
          strokeWidth="1.6"
        />
        <path d="M17 11 V27 M10 19 H24" stroke="var(--accent)" strokeWidth="1.4" />
      </svg>
      <div>
        <div className="text-[17px] font-bold tracking-[0.14em] leading-none">AEGIS</div>
        <div className="mt-1 text-[10px] leading-none text-[var(--faint)]">
          Console zero-trust
        </div>
      </div>
    </div>
  );
}

// -- icônes, trait de 1,6px pour rester lisibles à 18px ---------------------

const svg = {
  width: 18,
  height: 18,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

function IconGrid() {
  return (
    <svg {...svg}>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </svg>
  );
}

function IconTarget() {
  return (
    <svg {...svg}>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3.4" />
    </svg>
  );
}

function IconDoc() {
  return (
    <svg {...svg}>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <path d="M14 3v5h5M9 13h6M9 17h4" />
    </svg>
  );
}

function IconRank() {
  return (
    <svg {...svg}>
      <path d="M4 18h4V9H4zM10 18h4V4h-4zM16 18h4v-6h-4z" />
    </svg>
  );
}

function IconPlay() {
  return (
    <svg {...svg}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M10.2 9.2 15 12l-4.8 2.8z" />
    </svg>
  );
}

function IconSearch() {
  return (
    <svg {...svg} width={15} height={15}>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m20 20-3.5-3.5" />
    </svg>
  );
}
