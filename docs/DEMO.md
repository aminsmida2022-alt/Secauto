# Scénario de démonstration

Durée cible : **12 minutes** + questions.
Objectif : montrer le déploiement, l'exécution automatisée, la collecte et
l'exploitation des résultats — dans cet ordre.

---

## 0. Avant la séance (à faire une fois)

```bash
sudo bash scripts/install-docker.sh   # puis rouvrir la session
make install
make up
make sources
bash scripts/doctor.sh                # doit afficher 0 erreur
```

Prévoir ~10 minutes de téléchargement la première fois (images Docker + bases
Trivy + packs Semgrep).

---

## 1. Ouverture — le problème (1 min)

> « Trois familles d'outils existent : SAST lit le code, DAST attaque
> l'application en marche, SCA analyse les dépendances. Chacune a des angles
> morts. La question du projet n'est pas *quel outil utiliser* mais *comment
> mesurer ce que chacun détecte réellement*. »

Annoncer le plan : environnement → exécution → résultats → évaluation.

---

## 2. Environnement déployé (2 min)

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

Montrer les trois cibles :

| Cible | URL | Intérêt |
|---|---|---|
| Juice Shop | http://localhost:3000 | SPA Node, SQLi/XSS documentés |
| crAPI | http://localhost:8888 | API microservices, BOLA/BFLA |
| Roundcube | http://localhost:8080 | application PHP réelle |

Ouvrir crAPI et se connecter avec un compte de test (créé par le détecteur
BOLA, ou manuellement).

> « L'environnement est entièrement reproductible : `make up` recrée les trois
> cibles, versions épinglées dans `targets/compose/` et `scripts/deploy-crapi.sh`. »

---

## 3. Exécution automatisée (3 min)

Une seule commande déclenche les quatre familles d'analyse :

```bash
python3 -m secauto run --target crapi
```

Détailler ce qui se passe à l'écran :

1. **SAST** — Semgrep applique les packs OWASP + 5 règles maison.
2. **SCA** — Trivy (CVE, secrets, misconfigurations) + `npm audit`.
3. **DAST** — ZAP baseline contre l'application démarrée.
4. **CUSTOM** — trois scripts Python :
   - `idor_probe.py` crée deux comptes et tente d'accéder au véhicule de l'autre ;
   - `check_jwt.py` altère la signature d'un jeton et vérifie si le serveur l'accepte ;
   - `check_headers.py` contrôle en-têtes, cookies et CORS.

Montrer l'arborescence produite :

```bash
find reports/crapi/<run-id> -maxdepth 2 -type f | sort
```

> « Chaque outil garde sa sortie brute (`raw/`). Rien n'est perdu : on peut
> rejouer l'analyse, comparer, ou auditer la façon dont un constat a été produit. »

---

## 4. Exploitation des résultats (3 min)

Ouvrir `reports/crapi/<run-id>/report.html`.

Points à montrer :

- **cartes de synthèse** : nombre de constats par sévérité ;
- **tableau par outil** : TP, FP, précision ;
- **sections SAST / DAST / SCA / CUSTOM** : chaque constat avec CWE, endpoint,
  preuve ;
- **bloc JSON** repliable : le format normalisé, exploitable par un SIEM ou un
  tableau de bord.

Puis le JSON et les métriques :

```bash
jq '.overall' reports/crapi/<run-id>/metrics.json
jq '.findings[0]' reports/crapi/<run-id>/findings.json
```

> « Le format normalisé est la pièce centrale : Semgrep, ZAP, Trivy et nos
> scripts produisent des sorties totalement différentes, mais une seule
> structure en sortie. C'est ce qui rend la comparaison possible. »

---

## 5. Évaluation de la détection (2 min)

```bash
jq '{overall, per_tool, missed}' reports/crapi/<run-id>/metrics.json
```

Expliquer la vérité terrain :

- `metrics/ground_truth/crapi.yaml` liste les vulnérabilités **vérifiées
  manuellement** (BOLA véhicule, BFLA admin, retour de commande, JWT…) ;
- un constat est un **TP** s'il correspond à une entrée (CWE + localisation) ;
- sans correspondance → **FP** ; entrée sans constat → **FN**.

> « C'est le point qui distingue ce projet d'un simple lancement d'outils :
> on ne dit pas "ZAP a trouvé 42 alertes", on dit "ZAP a un rappel de X % et une
> précision de Y % sur cette cible". »

---

## 6. Avant / après correctif (2 min)

C'est la démonstration la plus parlante. Juice Shop est corrigé en direct :

```bash
# 1. analyse initiale
python3 -m secauto run --target juice-shop --tools sast --offline --run-id before-fix

# 2. application du correctif (requête paramétrée dans routes/login.ts)
bash scripts/demo-juiceshop-fix.sh

# 3. nouvelle analyse
python3 -m secauto run --target juice-shop --tools sast --offline --run-id after-fix

# 4. comparaison
python3 -m secauto compare --target juice-shop --before before-fix --after after-fix
```

Résultat attendu : `Corrigées : 1` — le constat `secauto-sqli-sequelize-template`
sur `routes/login.ts` disparaît, les autres persistent.

> « La plateforme ne se contente pas de lister : elle prouve qu'un correctif
> supprime effectivement le défaut, et elle conserve la trace des deux états. »

Restaurer ensuite :

```bash
bash scripts/demo-juiceshop-fix.sh --restore
```

---

## 7. CI/CD et conclusion (1 min)

Montrer `.github/workflows/security.yml` :

- push/PR → SAST + SCA + upload SARIF dans l'onglet *Security* ;
- lundi 03:00 → DAST (ZAP) sur l'application démarrée ;
- artefacts conservés 30 jours, résumé dans le job summary.

Conclusion en trois phrases :

1. les trois approches sont orchestrées et **normalisées** ;
2. la détection est **mesurée** (TP/FP/FN, précision, rappel) contre une vérité
   terrain versionnée ;
3. le tout est **reproductible** : une commande, un identifiant d'exécution, des
   rapports archivés.

---

## Questions probables et réponses courtes

**Pourquoi ne pas utiliser seulement SonarQube ?**
SonarQube est excellent en SAST mais ne voit ni le comportement à l'exécution
(DAST) ni les dépendances vulnérables (SCA). Les trois approches couvrent des
surfaces différentes ; le projet mesure justement leur complémentarité.

**Comment évitez-vous les faux positifs ?**
Trois leviers : packs de règles éprouvés (Semgrep OWASP), exclusion des fixtures
pédagogiques (`sast.exclude`), et surtout mesure de la précision par outil. Un
outil bruyant est identifié comme tel, pas masqué.

**La vérité terrain n'est-elle pas subjective ?**
Elle est versionnée et justifiée : chaque entrée cite un CWE et une localisation
vérifiable. Elle reste partielle — le rappel calculé est donc un minorant, ce qui
est assumé dans les limites du rapport.

**Pourquoi crAPI en plus de Juice Shop ?**
Juice Shop est une application web classique. crAPI est une API microservices :
elle permet de tester BOLA/BFLA, que ZAP seul détecte mal — d'où les détecteurs
complémentaires.

**Que se passe-t-il si un outil tombe ?**
Le runner capture l'erreur, la consigne dans `errors`, et poursuit la campagne.
Un outil indisponible ne bloque pas les autres (voir la colonne « Outils en
erreur » du rapport).

---

## Plan B (sans réseau / sans Docker le jour J)

Les rapports déjà générés dans `reports/` restent consultables :

```bash
xdg-open reports/juice-shop/<run-id>/report.html
```

Le dépôt contient aussi les sorties brutes (`raw/`) et les métriques
(`metrics.json`), ce qui permet de dérouler tout le discours d'exploitation sans
relancer les outils.
