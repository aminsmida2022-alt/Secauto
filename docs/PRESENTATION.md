# Plan de présentation (soutenance)

Support de 12–14 diapositives, aligné sur `docs/DEMO.md`.
Les chiffres cités proviennent des exécutions réelles archivées dans `reports/juice-shop/`.

---

## Diapo 1 — Titre

**Conception et évaluation d'une plateforme automatisée de détection de
vulnérabilités des applications web**

Nom, module, date.

---

## Diapo 2 — Problème

Trois familles d'outils, trois angles morts :

| Approche | Ce qu'elle voit | Ce qu'elle ne voit pas |
|---|---|---|
| SAST | le code, la source → sink | le comportement réel, la configuration |
| DAST | l'application en marche | le code, les dépendances |
| SCA | les composants et leurs CVE | la logique métier |

La question posée : **quelle approche détecte quoi, et avec quelle efficacité ?**
Pas « quel outil est le meilleur », mais « comment le mesurer ».

---

## Diapo 3 — Objectifs du projet

- déployer un environnement de test reproductible (3 cibles) ;
- exécuter SAST, DAST, SCA et une détection complémentaire maison ;
- normaliser tous les résultats dans un format unique ;
- mesurer la détection (TP / FP / FN, précision, rappel, F1) ;
- automatiser (CI/CD) et archiver ;
- comparer **avant / après** correctif.

---

## Diapo 4 — Architecture

Schéma de `README.md` §1 : CLI → runners (Semgrep/SonarQube, ZAP, Trivy/npm audit,
détecteurs Python) → `Finding` normalisé → `reports/<cible>/<run-id>/`.

Insister sur deux points :

1. **un seul modèle de données** en sortie (`tool`, `category`, `severity`,
   `cwe`, `owasp`, `file`/`endpoint`, `evidence`, `fingerprint`) ;
2. **séparation orchestration / outils** : ajouter un outil = ajouter une classe
   `Runner`, rien d'autre à modifier.

---

## Diapo 5 — Environnement déployé

| Cible | Type | Port | Intérêt pédagogique |
|---|---|---|---|
| OWASP Juice Shop | SPA Node/Angular | 3000 | SQLi, XSS, JWT, paniers |
| OWASP crAPI | API microservices | 8888 | BOLA, BFLA, mass assignment |
| Roundcube | PHP | 8080 | application réelle, en-têtes, CSRF |

Déploiement : Docker Compose versionné (`targets/compose/`, `scripts/deploy-crapi.sh`).
Installation Docker : `scripts/install-docker.sh`.

---

## Diapo 6 — Chaîne d'analyse

Une commande :

```bash
python3 -m secauto run --target crapi
```

- SAST : Semgrep (packs OWASP/JS + 5 règles maison) ;
- SCA : Trivy (`vuln,secret,misconfig`) + `npm audit` ;
- DAST : ZAP baseline / full / api-scan ;
- CUSTOM : `check_headers.py`, `idor_probe.py`, `check_jwt.py`.

Chaque outil écrit sa sortie brute dans `raw/` : rien n'est perdu, tout est
auditable.

---

## Diapo 7 — Mécanisme complémentaire (exigence clé)

**Règles Semgrep maison** (`scanners/semgrep/rules/secauto-rules.yaml`) :
SQLi par template literal, SQLi par concaténation, injection de commande,
secret JWT en dur, endpoint Spring sans autorisation.

**Détecteurs Python** (`scanners/custom/`) :

| Script | Méthode | Ce que les outils industriels manquent |
|---|---|---|
| `idor_probe.py` | crée 2 comptes, échange les IDs d'objets | BOLA/BFLA = logique métier |
| `check_jwt.py` | altère la signature et rejoue | test actif de la vérification |
| `check_headers.py` | requête HTTP + analyse en-têtes/cookies/CORS | configuration déployée |

Ils respectent le même contrat `{"findings": [...]}` : interchangeables avec les
outils industriels.

---

## Diapo 8 — Résultats mesurés (Juice Shop v20.2.0)

Exécution `baseline` : SAST + Trivy + npm audit.

| Outil | Constats | TP | FP | Précision | Rappel |
|---|---:|---:|---:|---:|---:|
| Semgrep (règles maison, hors ligne) | 3 | 3 | 0 | 100 % | 23 % |
| Trivy fs | 52 | 1 | 51 | 2 % | 8 % |
| npm audit | 97 | 4 | 93 | 4 % | 31 % |
| **Global** | **55** | **4** | **51** | **7 %** | **23 %** |

Lecture honnête :

- Semgrep est **précis** mais ne couvre que ce que ses règles décrivent ;
- Trivy et npm audit sont **bruyants** car ils remontent des dépendances de
  développement transitives — c'est un résultat sur la cible, pas un bug ;
- le **rappel global** reste un minorant : la vérité terrain est partielle.

*(Les chiffres « par outil » dépendent de la version ; les commandes de
reproduction sont dans `README.md`.)*

---

## Diapo 9 — Avant / après correctif

```bash
python3 -m secauto run --target juice-shop --tools sast --offline --run-id before-fix
bash scripts/demo-juiceshop-fix.sh
python3 -m secauto run --target juice-shop --tools sast --offline --run-id after-fix
python3 -m secauto compare --target juice-shop --before before-fix --after after-fix
```

Résultat : **1 corrigée, 2 persistantes**.

Le correctif (requête paramétrée `bind` dans `routes/login.ts`) fait disparaître
le constat `secauto-sqli-sequelize-template`, sans toucher aux autres : la
plateforme **prouve** l'effet du correctif.

---

## Diapo 10 — Exploitation des résultats

`reports/<cible>/<run-id>/` :

```
raw/            sorties brutes de chaque outil
findings.json   format normalisé (exploitable SIEM / dashboard)
metrics.json    TP/FP/FN, précision, rappel, F1, non détectées
report.html     rapport lisible (synthèse, tableau par outil, preuves)
summary.md      résumé pour la CI
```

Plus : `secauto.sarif` → GitHub code scanning (`scripts/to_sarif.py`).

---

## Diapo 11 — CI/CD

`.github/workflows/security.yml` :

1. **push / PR** → job `sast-sca` en matrice (juice-shop, crapi) : Semgrep +
   Trivy + npm audit, SARIF, artefacts 30 jours ;
2. **lundi 03:00 UTC** ou manuel → job `dast` : démarre Juice Shop, lance ZAP,
   archive le rapport ;
3. **agrégation** : artefact unique + résumé dans le job summary.

`--fail-on high` transforme les constats en barrière de merge.

---

## Diapo 12 — Limites et perspectives

- vérité terrain partielle → rappel minorant ;
- ZAP baseline non authentifié → zones privées couvertes par les détecteurs
  custom ;
- heuristiques Semgrep à confiance faible → confirmation manuelle ;
- perspectives : authentification ZAP, SonarQube en CI, corrélation SAST↔DAST
  par empreinte, tableau de bord historique.

---

## Diapo 13 — Conclusion

1. les trois approches sont **orchestrées et normalisées** ;
2. la détection est **mesurée** contre une vérité terrain versionnée ;
3. le processus est **reproductible et automatisé** (une commande, un run-id,
   des rapports archivés).
