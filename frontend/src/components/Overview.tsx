"use client";

/**
 * Vue d'ensemble — l'état des signaux, en grille de cartes.
 *
 * La forme est celle de la charte : une carte par entité, chip d'icône coloré
 * en haut à gauche, badge d'état en haut à droite, teinte douce pour ce qui est
 * actif et gris pour ce qui ne l'est pas.
 *
 * Le fond, lui, est celui d'une console de sécurité, et il obéit à une règle
 * qu'aucune charte ne donne : **une carte ne peut pas être verte parce qu'elle
 * existe**. Un signal affiche ce qu'il a le droit de faire, s'il tourne
 * réellement, et son taux d'erreur mesuré. Sans le taux, « actif » laisse
 * croire à une garantie ; avec lui, le lecteur sait ce qu'il achète.
 *
 * Deux cartes ne sont pas des signaux mais des propriétés du système — le
 * journal et l'isolation des sessions. Elles sont dans la même grille parce
 * qu'elles se dégradent de la même façon : silencieusement.
 */
import { useEffect, useState, type ReactNode } from "react";
import { fetchStatus } from "@/lib/api";
import { SIGNAL_LABELS } from "@/lib/format";
import type { StatusReport } from "@/lib/types";
import type { VueId } from "./AppShell";
import { Empty, IconChip, Loading, Panel, Pill, type Tone } from "./ui";

export function Overview({ onVue }: { onVue: (v: VueId) => void }) {
  const [status, setStatus] = useState<StatusReport | null>(null);
  const [erreur, setErreur] = useState<string | null>(null);

  useEffect(() => {
    fetchStatus()
      .then(setStatus)
      .catch((e: Error) => setErreur(e.message));
  }, []);

  if (erreur) return <Panel title="État du système"><Empty>{erreur}</Empty></Panel>;
  if (!status) return <Panel title="État du système"><Loading label="Lecture de l'état…" /></Panel>;

  const mesure = (id: string) => status.signals.find((s) => s.id === id)?.mesure ?? "";
  const bloquant = (id: string) => status.blocking_signals.includes(id);
  const capteur = (id: string) => status.detectors[id];
  const enveloppe = status.consommation.enveloppe_globale;

  return (
    <div className="space-y-6">
      <section>
        <SectionTitle>Signaux de contenu</SectionTitle>
        <p className="mb-3 text-[13px] text-[var(--muted)]">
          Quatre signaux regardent chaque document. Un seul a le droit de décider — les trois
          autres sont journalisés et alimentent un compteur de ce qu&apos;ils auraient fait.
        </p>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {(["rules", "injection_ml", "rag_outlier", "retrieval_stuffing"] as const).map((id) => {
            const etat = capteur(id);
            const eteint = etat?.available === false;
            return (
              <SignalCard
                key={id}
                nom={SIGNAL_LABELS[id].nom}
                role={bloquant(id) ? "bloquant" : "consultatif"}
                description={SIGNAL_LABELS[id].quoi}
                mesure={mesure(id)}
                eteint={eteint}
                raison={etat?.reason ?? null}
              />
            );
          })}
        </div>
      </section>

      <section>
        <SectionTitle>Propriétés du système</SectionTitle>
        <p className="mb-3 text-[13px] text-[var(--muted)]">
          Elles ne détectent rien. Elles décident de ce que vaut une preuve, et de qui répond
          d&apos;un comportement — et elles se dégradent en silence, d&apos;où leur place ici.
        </p>
        <div className="grid gap-4 sm:grid-cols-2">
          <SystemCard
            titre="Journal d'audit"
            tone={status.audit_integrity.ok ? (status.audit_integrity.is_signed ? "ok" : "warn") : "danger"}
            badge={status.audit_integrity.is_signed ? "signé Ed25519" : "non signé"}
            valeur={status.audit_integrity.is_signed ? "Preuve opposable" : "Chaîne cohérente"}
            detail={
              status.audit_integrity.is_signed
                ? "Chaque entrée porte une signature vérifiable par un tiers, et les données personnelles sont pseudonymisées avant hachage : effacer une personne ne casse pas la preuve."
                : "La chaîne est cohérente, mais reforgeable par qui a un accès en écriture. « Cohérent » n'est pas « opposable » — lance scripts/generate_audit_key."
            }
            icone={<IconShield />}
          />
          <SystemCard
            titre="Isolation des sessions"
            tone={status.session_isolation.degraded ? "warn" : "ok"}
            badge={status.session_isolation.degraded ? "partagée" : "par session"}
            valeur={status.session_isolation.degraded ? "Dégradée" : status.session_isolation.keyed_by.join(" / ")}
            detail={
              status.session_isolation.degraded
                ? `${status.session_isolation.anonymous} fenêtre(s) comportementale(s) sans identifiant de session : la suite d'actions observée n'appartient à personne en particulier.`
                : "La fenêtre comportementale est indexée par tenant, agent et session. Un attaquant ne peut ni diluer son profil dans le trafic légitime, ni faire monter le score d'un autre."
            }
            icone={<IconUsers />}
          />
          <SystemCard
            titre="Mode de défaillance"
            tone={status.fail_mode === "closed" ? "ok" : "warn"}
            badge={status.fail_mode === "closed" ? "fail-closed" : "fail-open"}
            valeur={status.fail_mode === "closed" ? "Refuse de démarrer" : "Laisse passer"}
            detail={
              status.fail_mode === "closed"
                ? "Des détecteurs sont exigés : AEGIS refuse de démarrer si l'un manque, plutôt que de tourner amputé sans le dire."
                : "Aucun détecteur n'est exigé. Un modèle absent donne un risque nul, et le silence ressemble à « rien à signaler ». C'est un choix défendable — il doit être choisi, via AegisConfig.required_detectors."
            }
            icone={<IconFail />}
          />
          <SystemCard
            titre="Consommation (LLM06)"
            tone={enveloppe.actif ? "ok" : "warn"}
            badge={status.consommation.jeton_partage ? "jeton exigé" : "démo ouverte"}
            valeur={
              enveloppe.actif
                ? `${enveloppe.consommes} / ${enveloppe.max_par_heure} appels · 1 h`
                : "Enveloppe désactivée"
            }
            detail={
              enveloppe.actif
                ? `Deux gardes, deux menaces : ${status.consommation.debit_par_client.rate_per_minute}/min par client protège la disponibilité entre visiteurs, l'enveloppe glissante protège la facture. Une limite par client ne borne pas la dépense — cent clients respectant chacun leur quota consomment cent fois le quota. Seuls ${status.consommation.endpoints_limites.length} endpoints sont concernés : ceux qui appellent réellement un modèle.`
                : "Aucune enveloppe globale : le débit par client borne chaque visiteur, jamais le total. Défendable si un plafond de dépense existe côté fournisseur — sinon l'URL publique est une facture ouverte (AEGIS_LLM_CALLS_PER_HOUR)."
            }
            icone={<IconGauge />}
          />
        </div>
      </section>

      <Panel title="Par où commencer">
        <div className="grid gap-2 sm:grid-cols-2">
          <Raccourci
            onClick={() => onVue("scenarios")}
            titre="Rejouer une attaque"
            texte="12 scénarios sur les 5 points d'interception, sans aucun appel LLM."
          />
          <Raccourci
            onClick={() => onVue("classement")}
            titre="Manipuler le classement"
            texte="Fabrique un document qui remonte en tête et regarde les deux classements réagir."
          />
        </div>
      </Panel>
    </div>
  );
}

function SectionTitle({ children }: { children: ReactNode }) {
  return (
    <h2 className="mb-1 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--muted)]">
      <IconChipSmall />
      {children}
    </h2>
  );
}

/**
 * Carte d'un signal.
 *
 * Le badge dit le RÔLE (bloquant / consultatif), pas la santé — c'est
 * l'information qui manque partout ailleurs et celle qui explique les verdicts.
 * Un capteur éteint bascule la carte en gris et le dit franchement : c'est le
 * seul cas où l'absence de couleur est une information.
 */
function SignalCard({
  nom,
  role,
  description,
  mesure,
  eteint,
  raison,
}: {
  nom: string;
  role: "bloquant" | "consultatif";
  description: string;
  mesure: string;
  eteint: boolean;
  raison: string | null;
}) {
  const tone: Tone = eteint ? "muted" : role === "bloquant" ? "accent" : "warn";
  const fond = eteint
    ? "border-[var(--line)] bg-[var(--surface-3)]"
    : role === "bloquant"
      ? "border-[var(--accent-line)] bg-[var(--accent-soft)]"
      : "border-[var(--line)] bg-[var(--surface)]";

  return (
    <article
      className={`flex h-full flex-col rounded-xl border p-4 shadow-[var(--shadow-card)] ${fond}`}
    >
      <div className="flex items-start gap-3">
        <IconChip tone={tone}>{role === "bloquant" ? <IconLock /> : <IconEye />}</IconChip>
        <div className="ml-auto">
          {eteint ? (
            <Pill tone="muted">capteur éteint</Pill>
          ) : (
            <Pill tone={role === "bloquant" ? "accent" : "warn"}>{role}</Pill>
          )}
        </div>
      </div>

      <h3 className={`mt-3 text-[15px] font-semibold ${eteint ? "text-[var(--muted)]" : ""}`}>
        {nom}
      </h3>
      <p className="mt-1.5 text-[12px] leading-relaxed text-[var(--muted)]">{description}</p>

      <div className="mt-auto pt-3">
        <div className="text-[10px] font-medium uppercase tracking-[0.12em] text-[var(--faint)]">
          Mesuré
        </div>
        <p className="tabular mt-1 text-[11.5px] leading-relaxed text-[var(--text)]/75">{mesure}</p>
        {eteint && raison && (
          <p className="mt-2 text-[11.5px] leading-relaxed text-[var(--warn)]">{raison}</p>
        )}
      </div>
    </article>
  );
}

function SystemCard({
  titre,
  tone,
  badge,
  valeur,
  detail,
  icone,
}: {
  titre: string;
  tone: Tone;
  badge: string;
  valeur: string;
  detail: string;
  icone: ReactNode;
}) {
  const fond =
    tone === "ok"
      ? "border-[var(--ok-line)] bg-[var(--ok-soft)]"
      : tone === "warn"
        ? "border-[var(--warn-line)] bg-[var(--warn-soft)]"
        : tone === "danger"
          ? "border-[var(--danger-line)] bg-[var(--danger-soft)]"
          : "border-[var(--line)] bg-[var(--surface)]";

  return (
    <article className={`rounded-xl border p-4 shadow-[var(--shadow-card)] ${fond}`}>
      <div className="flex items-start gap-3">
        <IconChip tone={tone}>{icone}</IconChip>
        <div className="ml-auto">
          <Pill tone={tone}>{badge}</Pill>
        </div>
      </div>
      <h3 className="mt-3 text-[15px] font-semibold">{titre}</h3>
      <div className="mt-0.5 text-[13px] font-medium text-[var(--text)]/70">{valeur}</div>
      <p className="mt-2 text-[12px] leading-relaxed text-[var(--muted)]">{detail}</p>
    </article>
  );
}

function Raccourci({
  titre,
  texte,
  onClick,
}: {
  titre: string;
  texte: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="group flex items-start gap-3 rounded-lg border border-[var(--line)] bg-[var(--surface)] p-3.5 text-left transition-colors hover:border-[var(--accent-line)] hover:bg-[var(--accent-soft)]"
    >
      <div className="min-w-0">
        <div className="text-[13.5px] font-medium">{titre}</div>
        <p className="mt-1 text-[12px] leading-relaxed text-[var(--muted)]">{texte}</p>
      </div>
      <span className="ml-auto mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[var(--accent-ink)] text-white opacity-0 transition-opacity group-hover:opacity-100">
        <IconArrow />
      </span>
    </button>
  );
}

// -- icônes -----------------------------------------------------------------

const s = {
  width: 15,
  height: 15,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.8,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

const IconLock = () => (
  <svg {...s}>
    <rect x="4.5" y="10.5" width="15" height="9.5" rx="2" />
    <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
  </svg>
);
const IconEye = () => (
  <svg {...s}>
    <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12" />
    <circle cx="12" cy="12" r="2.8" />
  </svg>
);
const IconShield = () => (
  <svg {...s}>
    <path d="M12 3l7.5 3v6c0 4.5-3.4 7.9-7.5 9-4.1-1.1-7.5-4.5-7.5-9V6z" />
    <path d="m9 12 2.2 2.2L15.5 10" />
  </svg>
);
const IconUsers = () => (
  <svg {...s}>
    <circle cx="9" cy="8.5" r="3.2" />
    <path d="M3.5 19.5a5.5 5.5 0 0 1 11 0M16 6.2a3.2 3.2 0 0 1 0 6.1M17.5 14.6a5.5 5.5 0 0 1 3 4.9" />
  </svg>
);
const IconFail = () => (
  <svg {...s}>
    <path d="M12 4.5 21 19.5H3z" />
    <path d="M12 10v4M12 16.6v.2" />
  </svg>
);
const IconGauge = () => (
  <svg {...s}>
    <path d="M4 18a8 8 0 1 1 16 0" />
    <path d="m12 18 4.2-5.4" />
  </svg>
);
const IconArrow = () => (
  <svg {...s} width={13} height={13}>
    <path d="M6 18 18 6M9 6h9v9" />
  </svg>
);
const IconChipSmall = () => (
  <svg {...s} width={13} height={13} className="text-[var(--faint)]">
    <rect x="3" y="3" width="7" height="7" rx="1.5" />
    <rect x="14" y="3" width="7" height="7" rx="1.5" />
    <rect x="3" y="14" width="7" height="7" rx="1.5" />
    <rect x="14" y="14" width="7" height="7" rx="1.5" />
  </svg>
);
