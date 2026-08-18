"use client";

/**
 * Console AEGIS — orchestration.
 *
 * Ce fichier faisait 1052 lignes : types, appels réseau, formatage, mascotte
 * animée et rendu, tout au même endroit. Chaque ajout y coûtait de plus en plus
 * cher, et deux bugs d'affichage y avaient survécu longtemps parce que la
 * logique était noyée dans le balisage.
 *
 * Il ne fait plus que trois choses : tenir la vue courante, charger le
 * catalogue de scénarios pour la recherche globale, et déléguer.
 */
import { useEffect, useState } from "react";
import { AppShell, type VueId } from "@/components/AppShell";
import { DocumentLab } from "@/components/DocumentLab";
import { Overview } from "@/components/Overview";
import { RankingLab } from "@/components/RankingLab";
import { ScenarioBench } from "@/components/ScenarioBench";
import { SimulationPanel } from "@/components/SimulationPanel";
import { fetchScenarios } from "@/lib/api";
import type { ScenarioSummary } from "@/lib/types";

export default function Console() {
  const [vue, setVue] = useState<VueId>("apercu");
  const [scenarios, setScenarios] = useState<ScenarioSummary[]>([]);
  // Scénario demandé depuis la recherche globale : le banc s'y positionne au
  // lieu de rouvrir sur le premier de la liste.
  const [scenarioDemande, setScenarioDemande] = useState<string | null>(null);

  // Le catalogue est chargé ici, une fois, parce que la recherche de la barre
  // supérieure doit pouvoir trouver un scénario depuis n'importe quel écran.
  useEffect(() => {
    fetchScenarios()
      .then((c) => setScenarios(c.scenarios))
      .catch(() => setScenarios([]));
  }, []);

  return (
    <AppShell
      vue={vue}
      onVue={setVue}
      scenarios={scenarios}
      onScenario={(id) => {
        setScenarioDemande(id);
        setVue("scenarios");
      }}
    >
      {vue === "apercu" && <Overview onVue={setVue} />}
      {vue === "scenarios" && (
        <ScenarioBench
          scenarioDemande={scenarioDemande}
          onScenarioJoue={() => setScenarioDemande(null)}
        />
      )}
      {vue === "document" && <DocumentLab />}
      {vue === "classement" && <RankingLab />}
      {vue === "simulation" && <SimulationPanel />}
    </AppShell>
  );
}
