import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AEGIS — Console Zero-Trust",
  description:
    "Couche de sécurité zero-trust pour agents IA et RAG : neutralisation des injections de prompt, moindre privilège sur les appels d'outils, journal d'audit signé.",
};

// Aucune police distante. `next/font/google` téléchargeait Geist au build :
// hors ligne — ou derrière un proxy, comme en CI — la construction échouait sur
// « Failed to fetch Geist from Google Fonts ». Les piles système déclarées dans
// globals.css rendent le build hermétique et le premier rendu instantané.
export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="fr" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
