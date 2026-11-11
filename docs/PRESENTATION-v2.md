# Plan de présentation v2 — soutenance (support visuel)

Deck PowerPoint ~16 diapositives, 15–20 min.
**Principe : 80 % visuel** — captures d'écran réelles de la plateforme web
(`web/`) et graphiques natifs construits sur les métriques archivées
(`reports/**/metrics.json`) ; texte réduit à des titres, légendes et
chiffres-clés.

## Thème = thème du frontend (`web/static/style.css`)

| Rôle | Couleur | Usage deck |
|---|---|---|
| Fond clair | `F5F5F5` | fond des diapos de contenu |
| Surface | `FFFFFF` + bordure 2px `0A0A0A` | cartes, cadres de captures |
| Accent principal | `FF3D3D` (rouge) | logo `secauto●`, mots-clés, chiffres-chocs |
| Positif | `00C853` / fond `E8FFF0` | TP, « corrigé », réussites |
| Info | `2979FF` / fond `E8F0FF` | rappel, barres, flèches |
| Attention | `FF9100` / fond `FFF8E1` | FP, « persistant », limites |
| Encre | `1A1A1A`, muted `666666` | textes |
| Typo | Arial gras 900 (titres 36–44pt), Arial (corps 14–16pt), Courier New (run-ids, commandes) | |

Motif récurrent : pastilles/emojis dans des carrés arrondis à bordure 2px
(comme les cartes cibles du web UI) + badges monospace pour les outils.
Diapos sombres (`0A0A0A`, texte blanc, rouge accent) en ouverture et
conclusion uniquement (« sandwich »).

Captures à prendre sur `http://localhost:5000` (web UI) et
`reports/<cible>/<run>/report.html`, encadrées d'un bord noir 2px + ombre
portée, comme les surfaces du frontend.

---

## Diapo 1 — Titre (sombre)

- Fond `0A0A0A`. Logo typographique : **secauto●** (blanc, point rouge),
  même typographie que la topbar du web UI.
- Titre : *Conception et évaluation d'une plateforme automatisée de
  détection de vulnérabilités des applications web*.
- Nom, module, date. Bandeau mono en bas : `juice-shop · crapi · roundcube`.

## Diapo 2 — Le problème : trois angles morts (graphique)

- 3 cartes blanches bord noir côte à côte : **SAST 🔍 / DAST 🌐 / SCA 📦**
  (même style que les cartes outils du web UI).
- Sous chaque carte : ligne verte « ce qu'il voit » / ligne rouge
  « ce qu'il rate » (2 lignes max chacune).
- Phrase-clé en bas, accent rouge : *« Quelle approche détecte quoi, et avec
  quelle efficacité ? »*

## Diapo 3 — Du cahier des charges aux fonctionnalités (capture/visuel)

- Tableau 2 colonnes stylisé : exigence → implémentation (extrait de la
  table « Correspondance » du README, 8 lignes max, icônes ✓ vertes).
- Chiffres-clés en pastilles : `6 types d'analyse` · `3 cibles` ·
  `1 format normalisé`.

## Diapo 4 — Architecture (graphique)

- Redessin du schéma README §1 dans le thème : CLI → 6 runners (cartes
  blanches bord noir) → **Finding normalisé** (pastille rouge) →
  `reports/<cible>/<run>/`.
- 2 annotations encadrées (fond `E8F0FF`) : *un seul modèle de données* ·
  *ajouter un outil = une classe Runner*.

## Diapo 5 — Les 3 cibles déployées (capture)

- Capture : section « Choisir les cibles » de la page d'accueil du web UI
  (cartes 🛒 Juice Shop / 🚗 crAPI / 📧 Roundcube — déjà dans le thème).
- Petite ligne mono : `docker compose -f targets/compose/juice-shop.yml up -d`
  (+ `deploy-crapi.sh` pour crAPI).

## Diapo 6 — Lancer une analyse (capture)

- Capture : page **scan en cours** du web UI (cibles, étapes d'outils avec
  pastilles ✓, journal live).
- Légende : *une commande = une campagne complète, chaque sortie brute
  conservée dans `raw/`*.

## Diapo 7 — Résultats normalisés (capture)

- Capture : page **Résultats** — rangée de KPI (constats, sévérités, TP) en
  haut + extrait du tableau des constats avec badges d'outils.
- En marge (mono) : `findings.json` · `metrics.json` · `report.html` ·
  `summary.md` · `secauto.sarif`.

## Diapo 8 — Comparaison des approches, en un écran (capture)

- Capture : carte **« Comparaison des approches »** de la page résultats
  (barres précision/rappel par outil + 🏆 Meilleur).
- Message : *la comparaison n'est pas un tableau annexe — elle fait partie
  de l'interface.*

## Diapo 9 — Vérité terrain & métriques (graphique)

- 3 grandes formules en cartes : `Précision = TP/(TP+FP)` (vert),
  `Rappel = TP/(TP+FN)` (bleu), `F1` (ambre).
- Mini-capture ou extrait mono : `metrics/ground_truth/juice-shop.yaml`
  (1–2 entrées). Message : *évaluation reproductible, versionnée, par outil
  et par catégorie*.

## Diapo 10 — Résultats mesurés (graphique natif)

- Graphique en barres **précision/rappel par outil** (données réelles
  `metrics.json` de `baseline`) : semgrep 17 %/23 %, trivy 20 %/8 %,
  zap 6 %/8 %, custom (crAPI) 33 %/43 %.
- Callout géant rouge : **100 %** — précision des règles Semgrep maison
  seules vs **6 %** pour ZAP baseline.

## Diapo 11 — DAST seul vs détection maison sur crAPI (graphique + capture)

- Comparaison 2 colonnes : ZAP = 28 constats / **0 TP** (carte rouge) vs
  custom = 9 constats / **3 TP** (carte verte).
- Capture : constat BOLA de `idor_probe.py` avec sa **preuve** (endpoint
  `/identity/api/v2/vehicle/...`, autre utilisateur) depuis `report.html`.
- Message : *BOLA/BFLA = logique métier — le vide que comblent les scripts
  maison.*

## Diapo 12 — Mécanisme complémentaire (grille d'icônes)

- Grille 2×3 de cartes : 5 règles Semgrep maison (résumées), 3 détecteurs
  Python, **script ZAP maison** (`--hook`, sondes `.env` / `.git` /
  actuator / stack trace, IDs 990001–990004).
- Bandeau mono en bas : `{"findings": [...]}` — *le même contrat pour tous,
  industriels et maison*.

## Diapo 13 — Avant / après correctif (capture + graphique)

- 3 mini-captures ou 1 capture de la page **Comparaison** (before-fix vs
  after-fix) : KPI 🆕 0 / ✅ 1 / ♻ 2.
- Callout : **1 vulnérabilité corrigée prouvée** (SQLi login Juice Shop,
  `scripts/demo-juiceshop-fix.sh`) — *la plateforme prouve l'effet du
  correctif, elle ne le présume pas*.

## Diapo 14 — Historique : comparer en deux clics (capture)

- Capture : page **Historique** avec une ligne grisée (1ʳᵉ sélection) et les
  autres lignes sélectionnables + flèche vers la page de diff.
- Message : *diff avant/après intégré à l'interface, tous les runs archivés
  (`reports/index.json`, 27+ exécutions).*

## Diapo 15 — CI/CD et alertes (graphique + visuel)

- Frise du pipeline (thème) : push/PR → job `sast-sca` (SARIF → code
  scanning) ; lundi 03:00 → `dast` (ZAP) ; agrégation → artefact 30 j.
- Carte **alertes** : `secauto alert --threshold high` → job summary →
  issue GitHub automatique (visuel du rendu `alerts.md` : tableau rouge 🔴).
- Badge mono : `--fail-on high` = barrière de merge.

## Diapo 16 — Limites et perspectives (cartes)

- 4 cartes courtes (fond ambre léger) : vérité terrain partielle (rappel
  minorant) · ZAP non authentifié · heuristiques à confirmer ·
  npm audit dépend du registre.
- 2 cartes perspectives (fond bleu léger) : authentification ZAP ·
  corrélation SAST↔DAST par empreinte.

## Diapo 17 — Conclusion (sombre)

- Fond `0A0A0A`, 3 grands points en cartes bordées blanc :
  1. **Orchestré & normalisé** — 3 approches + détection maison, 1 format.
  2. **Mesuré** — précision/rappel contre une vérité terrain versionnée.
  3. **Reproductible** — 1 commande, runs archivés, comparaisons dans l'UI.
- Chiffres en pastilles rouges : `3 cibles` · `27+ runs archivés` ·
  `6 runners` · `100 % précision (règles maison)`.

---

## Captures à produire (checklist build)

| # | Capture | Source |
|---|---|---|
| C1 | Accueil — cartes cibles + types d'analyse | `/` |
| C2 | Scan en cours (journal live, étapes ✓) | `/scan/<id>` pendant un run |
| C3 | Résultats — KPI + tableau constats | `/results/baseline` |
| C4 | Carte « Comparaison des approches » (zoom) | `/results/baseline` |
| C5 | Page Comparaison before-fix → after-fix | `/compare?before=before-fix&after=after-fix` |
| C6 | Historique avec sélection grisée | `/history` (2 clics) |
| C7 | Constat BOLA + preuve | `reports/crapi/custom-crapi/report.html` |
| C8 | Rendu `alerts.md` / issue GitHub | statique ou mock du résumé CI |
| C9 | (bonus) `docker ps` des 3 cibles | terminal |

## Graphiques natifs pptxgenjs à construire

- G1 : barres précision/rappel par outil (diapo 10).
- G2 : barres TP — ZAP vs custom sur crAPI (diapo 11).
- G3 : schéma d'architecture (formes, diapo 4).
- G4 : frise pipeline CI (diapo 15).
- G5 : formules métriques (diapo 9).

## Données à citer (issues des runs réels archivés)

- Juice Shop `baseline` : 41 constats, 7 TP, précision 17 %, rappel 23 %.
- Semgrep règles maison seules : 3 constats, 100 % / 23 %.
- ZAP baseline Juice Shop : 51 constats, 6 % / 8 %.
- crAPI custom : 9 constats, 3 TP, 33 % / 43 % (BOLA/BFLA/JWT 100 %).
- crAPI DAST : 28 constats, 0 TP.
- Roundcube DAST : 52 constats, 4 TP, 8 % / 33 %.
- Avant/après : 1 corrigée, 2 persistantes.
- Archivage : `reports/index.json` — 27 exécutions.
