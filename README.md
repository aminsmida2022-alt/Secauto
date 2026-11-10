# secauto — plateforme automatisée de détection de vulnérabilités web

Projet : *Conception et évaluation d'une plateforme automatisée de détection de
vulnérabilités des applications web*.

`secauto` orchestre **SAST**, **DAST**, **SCA** et des **détecteurs
complémentaires** sur trois cibles vulnérables par conception, normalise les
résultats dans un format unique, les confronte à une **vérité terrain** pour
mesurer précision et rappel, puis produit des rapports HTML/Markdown/JSON et
un diff avant/après.

---

## 1. Architecture

```
                        ┌──────────────────────────────┐
                        │        secauto (CLI)         │
                        │  orchestration + rapports    │
                        └──────────────┬───────────────┘
                                       │
        ┌──────────────┬───────────────┼────────────────┬──────────────┐
        │              │               │                │              │
   ┌────▼────┐   ┌─────▼─────┐   ┌─────▼─────┐   ┌──────▼──────┐  ┌────▼─────┐
   │  SAST   │   │    SCA    │   │   DAST    │   │   CUSTOM    │  │ METRICS  │
   │ Semgrep │   │   Trivy   │   │    ZAP    │   │ BOLA/BFLA   │  │ TP/FP/FN │
   │SonarQube│   │ npm audit │   │ baseline  │   │ JWT/headers │  │ P/R/F1   │
   └────┬────┘   └─────┬─────┘   └─────┬─────┘   └──────┬──────┘  └────┬─────┘
        │              │               │                │              │
        └──────────────┴───────┬───────┴────────────────┘              │
                               ▼                                       │
                    ┌─────────────────────┐                            │
                    │  Finding normalisé  │◄───────────────────────────┘
                    │ (CWE, OWASP, sévé.) │
                    └──────────┬──────────┘
                               ▼
              reports/<cible>/<run-id>/
                ├── raw/            sorties brutes des outils
                ├── findings.json   résultats normalisés
                ├── metrics.json    TP/FP/FN, précision, rappel
                ├── report.html     rapport lisible
                └── summary.md      résumé pour la CI

Cibles : OWASP Juice Shop (Node/Angular), OWASP crAPI (microservices),
Roundcube (PHP) — déployées via Docker Compose.
CI/CD  : GitHub Actions (push/PR → SAST+SCA, nightly → DAST, artefacts + SARIF).
```

### Correspondance avec les fonctionnalités demandées

| Exigence | Implémentation |
|---|---|
| Déploiement de l'environnement de test | `targets/compose/*.yml`, `scripts/deploy-crapi.sh` |
| SAST | `secauto/runners.py` → Semgrep (+ SonarQube via API) |
| DAST | ZAP baseline / full / api-scan |
| SCA | Trivy (vulnérabilités, secrets) + `npm audit` |
| Conservation des résultats de chaque outil | `reports/<cible>/<run>/raw/` |
| Mécanisme complémentaire | 5 règles Semgrep maison + 3 détecteurs Python (headers, BOLA/BFLA, JWT) |
| Automatisation | `Makefile`, CLI `secauto`, workflow GitHub Actions |
| Archivage | artefacts CI 30 jours + `reports/index.json` |
| Exploitation | HTML, Markdown, JSON normalisé, SARIF, diff avant/après |
| Métriques | `metrics/ground_truth/*.yaml` → TP/FP/FN, précision, rappel, F1 |

---

## 2. Prérequis

- Docker Engine ≥ 24 + plugin Compose ≥ 2.20
- Python ≥ 3.10, `pip`
- Semgrep (`pipx install semgrep`), Trivy, Node.js/npm pour le SCA
- 8 Go de RAM recommandés (crAPI + Juice Shop + ZAP)

---

## 3. Démarrage rapide

```bash
# 0. Docker (une seule fois)
sudo bash scripts/install-docker.sh
# puis rouvrir la session, ou : newgrp docker
# (les commandes `make` passent par scripts/dk : pas besoin de reconnexion)

# 1. Dépendances Python
make install

# 2. Déployer les cibles
make up          # Juice Shop :3000, crAPI :8888, Roundcube :8080
# ou individuellement : make up-juice / make up-crapi / make up-roundcube

# 3. Récupérer les codes source (SAST/SCA)
make sources

# 4. Lancer une campagne complète
make scan TARGET=juice-shop
python3 -m secauto run --target crapi --tools sast,sca,dast,custom

# 5. Consulter le rapport
xdg-open reports/crapi/<run-id>/report.html
```

SonarQube (optionnel, SAST complémentaire) :

```bash
make up-sonar                                   # http://localhost:9000 (admin/admin)
export SONAR_HOST_URL=http://localhost:9000
export SONAR_TOKEN=<jeton généré dans My Account > Security>
make sonar TARGET=juice-shop
python3 -m secauto run --target juice-shop --tools sonar
```

Vérifications utiles :

```bash
bash scripts/doctor.sh          # état de l'environnement
python3 -m secauto list-targets
python3 -m secauto list-tools
```

Le scénario de soutenance est détaillé dans [`docs/DEMO.md`](docs/DEMO.md) et
le plan de présentation dans [`docs/PRESENTATION.md`](docs/PRESENTATION.md).

---

## 4. Commandes

| Commande | Rôle |
|---|---|
| `make scan TARGET=crapi` | campagne complète sur une cible |
| `make scan TARGET=crapi TOOLS=sast,sca` | sélection d'outils |
| `make ci TARGET=juice-shop` | échoue si un résultat ≥ high |
| `make compare TARGET=juice-shop BEFORE=… AFTER=…` | diff avant/après |
| `python3 -m secauto compare --target … --before … --after …` | idem sans Make |
| `make down-all` | arrête toutes les cibles |

Codes de sortie : `0` succès, `1` seuil `--fail-on` atteint, `2` erreur de configuration.

---

## 5. Métriques d'évaluation

`metrics/ground_truth/<cible>.yaml` liste les vulnérabilités **réellement
présentes** dans la cible. Chaque entrée est reliée aux constats par :

- le **CWE** (obligatoire si renseigné) ;
- une **localisation** : `match.endpoint` (regex sur l'endpoint, pour DAST) ou
  `match.file` (regex sur le fichier, pour SAST) — les deux sont des alternatives ;
- éventuellement `match.rule` ou `match.title`.

Calculs :

```
TP = constats correspondant à une entrée de la vérité terrain
FP = constats ne correspondant à aucune entrée
FN = entrées de la vérité terrain sans aucun constat
Précision = TP / (TP + FP)
Rappel    = TP / (TP + FN) = (GT - FN) / GT
F1        = 2·TP / (2·TP + FP + FN)
```

Les métriques sont produites **par outil** et **par catégorie**, ce qui permet
de comparer objectivement Semgrep, ZAP, Trivy et les détecteurs maison.

> La vérité terrain doit rester factuelle et versionnée : c'est elle qui rend
> l'évaluation reproductible. Complète les fichiers au fur et à mesure de tes
> vérifications manuelles (Burp, Postman).

### Exemple de résultats obtenus (Juice Shop v20.2.0)

| Configuration | Constats | Précision | Rappel |
|---|---:|---:|---:|
| Semgrep, règles maison seules (`--offline`) | 3 | 100 % | 23 % |
| Semgrep, packs OWASP + JavaScript + règles maison | 36 | 17 % | 23 % |
| Trivy fs (vulnérabilités + secrets) | 5 | 20 % | 8 % |
| **Campagne `baseline` (SAST + Trivy)** | **41** | **17 %** | **23 %** |

Enseignements : les règles maison sont précises et suffisent à couvrir la
vérité terrain SAST ; les packs génériques ajoutent surtout du bruit (règles
AWS / GitHub Actions / npm hors sujet) sans gain de rappel ; le SCA remonte ici
surtout des secrets (clés privées, jetons JWT), avec un vrai positif sur cinq.
`npm audit` dépend du registre et d'un lockfile : lors des premières campagnes
il a remonté 97 constats (4 % de précision, 31 % de rappel), mais lors de la
dernière exécution il a expiré — la campagne a continué et l'erreur est
consignée dans le rapport. Ces valeurs proviennent d'exécutions réelles
archivées dans `reports/juice-shop/` (l'exécution `baseline` correspond à la
dernière ligne).

### Exemple de résultats obtenus (crAPI, détecteurs maison)

Commande : `python3 -m secauto run --target crapi --tools custom --run-id custom-crapi`.

| Détecteur | Constats | TP | FP | Précision | Rappel |
|---|---:|---:|---:|---:|---:|
| `custom:idor-api` (BOLA + BFLA) | 2 | 2 | 0 | 100 % | 29 % |
| `custom:jwt` | 1 | 1 | 0 | 100 % | 14 % |
| `custom:headers` | 6 | 0 | 6 | 0 % | 0 % |
| **Total** | **9** | **3** | **6** | **33 %** | **43 %** |

Les trois vulnérabilités de la vérité terrain couvertes sont vérifiées
manuellement avant d'être automatisées :

- **BOLA** — `GET /identity/api/v2/vehicle/{id}/location` renvoie le nom,
  l'email et les coordonnées GPS du véhicule d'un autre utilisateur ;
- **BFLA** — `DELETE /identity/api/v2/admin/videos/{id}` répond `200` pour un
  compte standard alors que la route `/user/videos/{id}` refuse l'opération ;
- **JWT** — un jeton dont la signature a été altérée est accepté sur
  `/identity/api/v2/user/dashboard`.

Les six constats d'en-têtes sont réels mais **hors vérité terrain** (celle-ci
suit la liste officielle des challenges crAPI) : ils sont donc comptés comme
faux positifs. C'est le comportement attendu d'une métrique dont la référence
est explicite — et non un défaut du détecteur.

---

## 6. Mécanisme de détection complémentaire

### Règles Semgrep (`scanners/semgrep/rules/secauto-rules.yaml`)

| Règle | CWE | Cible typique |
|---|---|---|
| `secauto-sqli-sequelize-template` | CWE-89 | Juice Shop (`models.sequelize.query`) |
| `secauto-sqli-string-concat` | CWE-89 | code Node générique |
| `secauto-command-injection` | CWE-78 | mini-lab du TP2 (`exec`) |
| `secauto-jwt-hardcoded-secret` | CWE-798 | Juice Shop (`lib/insecurity`) |
| `secauto-java-endpoint-without-authz` | CWE-862 | crAPI (Spring Boot) |

### Détecteurs Python (`scanners/custom/`)

| Script | Ce qu'il détecte | Méthode |
|---|---|---|
| `check_headers.py` | en-têtes manquants, cookies non durcis, CORS permissif | requête HTTP + analyse |
| `idor_probe.py` | **BOLA** et **BFLA** | crée 2 comptes, collecte les objets exposés côté forum, rejoue l'accès avec le jeton d'un autre compte, puis appelle une fonction `/admin` avec un compte standard |
| `check_jwt.py` | signature non vérifiée, absence d'`exp`, données sensibles | altère la signature et rejoue la requête |

Ces scripts respectent le contrat `{"findings": [...]}` et sont donc
interchangeables avec les outils industriels dans le pipeline.

---

## 7. CI/CD

`.github/workflows/security.yml` :

1. **push / PR** → job `sast-sca` (matrice `juice-shop`, `crapi`) :
   Semgrep + Trivy + npm audit, conversion SARIF, upload dans *code scanning*.
2. **lundi 03:00 UTC** ou manuel → job `dast` : démarre Juice Shop, lance ZAP,
   archive le rapport HTML.
3. **agrégation** : un artefact unique `reports-all` + résumé dans le job summary.

Chaque exécution est identifiée par `ci-<numéro>` et archivée 30 jours.

---

## 8. Arborescence

```
config/                 targets.yaml, idor-crapi.yaml
secauto/                package Python (CLI, runners, metrics, report)
scanners/semgrep/rules/ règles personnalisées
scanners/custom/        détecteurs Python autonomes
targets/compose/        Juice Shop, Roundcube
scripts/                install-docker, deploy-crapi, fetch-sources, to_sarif
metrics/ground_truth/   vérité terrain par cible
reports/                résultats générés (non versionnés)
.github/workflows/      pipeline CI/CD
```

---

## 9. Limites connues

- La vérité terrain est **partielle** : elle couvre les vulnérabilités documentées
  et vérifiées, pas l'intégralité de la surface d'attaque. Le rappel est donc un
  minorant.
- ZAP baseline ne réalise pas d'authentification : les zones authentifiées ne
  sont couvertes que par les détecteurs custom.
- Les heuristiques Semgrep maison (`secauto-java-endpoint-without-authz`) ont une
  confiance faible et doivent être confirmées manuellement.
- Roundcube n'est pas fourni avec un serveur mail complet : seules les pages
  publiques sont couvertes par le DAST par défaut.
- `npm audit` dépend du registre npm : sans réseau il ne renvoie rien (le runner
  le signale, la campagne continue). Trivy a besoin de télécharger sa base de
  vulnérabilités au premier lancement.
