# Couverture OWASP GenAI LLM Top 10 — 2026

L'édition 2026 (parue le 6 août 2026) combine vote d'experts (75 %) et analyse de 7 714 incidents réels (25 %), ce qui a redistribué le classement : *Excessive Agency* passe de la 6ᵉ à la **3ᵉ** place, *Unbounded Consumption* de la 10ᵉ à la **6ᵉ**, et *System Prompt Leakage* est élargi et renommé *Hidden Context Exposure*.

| # | Risque | Nature du contrôle | Composant(s) | Limite principale |
|---|---|---|---|---|
| **LLM01** | Prompt Injection (cross-modal) | <span class="aegis-badge aegis-badge--block">bloquant</span> | Règles + normalisation | Règles FR/EN seulement ; rien en cross-modal |
| **LLM02** | Sensitive Information Disclosure | <span class="aegis-badge aegis-badge--mixed">mixte</span> | `pii_detector`, `output_guard`, `audit_log` | Texte seulement, aucune image/pièce jointe |
| **LLM03** | Excessive Agency *(le plus solide)* | <span class="aegis-badge aegis-badge--block">bloquant</span> | `policy_engine` | Pas de quota, pas de validation humaine réelle |
| **LLM04** | Supply Chain | <span class="aegis-badge aegis-badge--block">vérification CI</span> | SHA-256, pas de pickle, deps figées | Pas de SBOM, pas de signature du bundle |
| **LLM05** | Data and Model Poisoning | <span class="aegis-badge aegis-badge--advisory">consultatif</span> | `rag_outlier_detector` | Rien à l'indexation, aucune provenance |
| **LLM06** | Unbounded Consumption | <span class="aegis-badge aegis-badge--block">bloquant</span> | `ratelimit`, `session` (bornes) | État en mémoire de process |
| **LLM07** | Misinformation | <span class="aegis-badge aegis-badge--mixed">mixte</span> | Citation + `grounding` | Pas d'ancrage sémantique (NLI) |
| **LLM08** | Hidden Context Exposure | <span class="aegis-badge aegis-badge--advisory">consultatif</span> | `output_guard` (n-grammes) | Lexical seulement — la paraphrase échappe |
| **LLM09** | Vector and Embedding Weaknesses | <span class="aegis-badge aegis-badge--mixed">mixte</span> | BM25+plafond, outliers/TTR | Bourrage hybride indétectable |
| **LLM10** | Improper Output Handling | <span class="aegis-badge aegis-badge--block">bloquant</span> | `output_guard` (balisage, URL) | Exfiltration par chemin d'image échappe |

Aucune des dix catégories n'est « complète ». Toutes les dix ont, depuis le lot 10, au moins un signal réel et mesuré — avant ce lot, LLM08 et LLM10 étaient à zéro. Ce qui les distingue désormais n'est plus « y a-t-il quelque chose », mais la **maturité et la nature du contrôle** : LLM03 est la catégorie la plus solide parce qu'elle repose sur une allow-list déterministe bloquante — la classe de contrôle la plus fiable qui existe en sécurité. LLM05, LLM08 et LLM09 restent fondamentalement des signaux consultatifs avec des angles morts documentés et **testés** (paraphrase, bourrage hybride), non pas parce qu'on n'a pas essayé, mais parce que fermer ces angles morts demanderait un modèle d'inférence sémantique — un changement de nature du contrôle, pas un ajustement de règle.

Le détail mécanique de chaque composant cité dans ce tableau est dans [Les composants, un par un](composants.md). Les angles morts testés et volontairement non corrigés sont recensés dans [Limites connues](limites.md).
