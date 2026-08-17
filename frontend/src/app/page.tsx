"use client";

/**
 * Console AEGIS — coquille et navigation.
 *
 * Ce fichier faisait 1052 lignes : types, appels réseau, formatage, robot
 * animé et rendu, tout au même endroit. Chaque ajout y coûtait de plus en plus
 * cher, et deux bugs d'affichage y avaient survécu longtemps parce que la
 * logique était noyée dans le balisage.
 *
 * Il ne fait plus que trois choses : choisir l'onglet, afficher l'en-tête, et
 * déléguer. Tout le reste vit dans `components/` et `lib/`.
 */
import { useState } from "react";
import { DocumentLab } from "@/components/DocumentLab";
import { RankingLab } from "@/components/RankingLab";
import { ScenarioBench } from "@/components/ScenarioBench";
import { SimulationPanel } from "@/components/SimulationPanel";

const ONGLETS = [
  {
    id: "scenarios",
    label: "Banc de scénarios",
    hint: "12 situations, 5 points d'interception, aucun appel LLM",
  },
  {
    id: "document",
    label: "Analyse de document",
    hint: "Colle ce que tu veux, vois la décision et les signaux qui l'ont prise",
  },
  {
    id: "classement",
    label: "Laboratoire de classement",
    hint: "L'attaque sur la sélection des documents, rejouable à volonté",
  },
  {
    id: "simulation",
    label: "Simulation complète",
    hint: "L'agent réel, avec et sans protection — seul écran qui appelle un LLM",
  },
] as const;

type OngletId = (typeof ONGLETS)[number]["id"];

export default function Console() {
  const [onglet, setOnglet] = useState<OngletId>("scenarios");
  const actif = ONGLETS.find((o) => o.id === onglet) ?? ONGLETS[0];

  return (
    <main className="mx-auto w-full max-w-[1400px] flex-1 px-5 pb-16 pt-6">
      <Header />

      <nav className="mt-6 flex flex-wrap gap-1 border-b border-[var(--line)]">
        {ONGLETS.map((o) => (
          <button
            key={o.id}
            onClick={() => setOnglet(o.id)}
            aria-current={onglet === o.id ? "page" : undefined}
            className={`-mb-px border-b-2 px-4 py-2.5 text-sm transition-colors ${
              onglet === o.id
                ? "border-[var(--accent)] text-[var(--text)]"
                : "border-transparent text-[var(--muted)] hover:text-[var(--text)]"
            }`}
          >
            {o.label}
          </button>
        ))}
      </nav>

      <p className="mt-3 mb-5 text-[12px] text-[var(--faint)]">{actif.hint}</p>

      {onglet === "scenarios" && <ScenarioBench />}
      {onglet === "document" && <DocumentLab />}
      {onglet === "classement" && <RankingLab />}
      {onglet === "simulation" && <SimulationPanel />}

      <Footer />
    </main>
  );
}

function Header() {
  return (
    <header className="flex flex-wrap items-center gap-4">
      <div className="flex items-center gap-3">
        <Sigil />
        <div>
          <div className="text-lg font-semibold tracking-[0.18em]">AEGIS</div>
          <div className="text-[11px] text-[var(--faint)]">
            Couche zero-trust pour agents IA et RAG
          </div>
        </div>
      </div>

      <div className="ml-auto flex flex-wrap items-center gap-2 text-[11px]">
        <span className="rounded-md border border-[var(--line)] px-2 py-1 text-[var(--muted)]">
          OWASP LLM Top 10 · 2026
        </span>
        <span className="rounded-md border border-[var(--line)] px-2 py-1 text-[var(--muted)]">
          Journal signé Ed25519
        </span>
      </div>
    </header>
  );
}

/** Emblème géométrique : un bouclier réduit à ses arêtes. Pas de mascotte —
 *  l'écran doit avoir l'air d'un instrument, pas d'un jouet. */
function Sigil() {
  return (
    <svg width="34" height="38" viewBox="0 0 34 38" aria-hidden="true">
      <path
        d="M17 2 L31 8 V19 C31 27 24.5 33.5 17 36 C9.5 33.5 3 27 3 19 V8 Z"
        fill="none"
        stroke="var(--accent)"
        strokeWidth="1.4"
        opacity="0.85"
      />
      <path d="M17 11 V27 M10 19 H24" stroke="var(--accent)" strokeWidth="1.2" opacity="0.5" />
      <circle cx="17" cy="19" r="3" fill="var(--accent)" opacity="0.22" />
    </svg>
  );
}

function Footer() {
  return (
    <footer className="mt-10 border-t border-[var(--line)] pt-4 text-[11px] leading-relaxed text-[var(--faint)]">
      Les taux affichés dans cette console sont ceux mesurés sur le jeu de test, seuils calibrés au
      préalable sur un jeu distinct. Le README publie les intervalles de confiance et les limites
      connues — y compris celles qui ne sont pas corrigées.
    </footer>
  );
}
