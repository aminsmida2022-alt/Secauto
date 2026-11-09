#!/usr/bin/env bash
#
# Analyse SAST avec SonarQube.
#
# Prérequis :
#   make up-sonar                 # SonarQube + PostgreSQL sur :9000 (admin/admin)
#   sonar-scanner installé        # https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/scanners/
#   export SONAR_HOST_URL=http://localhost:9000
#   export SONAR_TOKEN=<jeton généré dans My Account > Security>
#
# Usage :
#   bash scripts/run-sonar.sh juice-shop
#
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

TARGET="${1:-juice-shop}"
SOURCE="$("$(command -v python3)" -c "import yaml;print(yaml.safe_load(open('config/targets.yaml'))['targets']['${TARGET}']['source'])")"
PROJECT="$("$(command -v python3)" -c "import yaml;print(yaml.safe_load(open('config/targets.yaml'))['targets']['${TARGET}'].get('sonar_key','${TARGET}'))")"

if ! command -v sonar-scanner >/dev/null 2>&1; then
  echo "sonar-scanner introuvable." >&2
  echo "Téléchargement : https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/scanners/sonarscanner/" >&2
  exit 1
fi
if [ -z "${SONAR_HOST_URL:-}" ]; then
  echo "SONAR_HOST_URL non défini (ex. http://localhost:9000)" >&2
  exit 1
fi
if [ ! -d "${SOURCE}" ]; then
  echo "Source introuvable : ${SOURCE} — lance : make sources" >&2
  exit 1
fi

echo "==> Analyse SonarQube : projet=${PROJECT} source=${SOURCE}"
sonar-scanner \
  -Dsonar.projectKey="${PROJECT}" \
  -Dsonar.projectName="secauto-${TARGET}" \
  -Dsonar.sources="${ROOT}/${SOURCE}" \
  -Dsonar.sourceEncoding=UTF-8 \
  -Dsonar.host.url="${SONAR_HOST_URL}" \
  ${SONAR_TOKEN:+-Dsonar.token="${SONAR_TOKEN}"}

echo
echo "Résultats : ${SONAR_HOST_URL}/dashboard?id=${PROJECT}"
echo "Pour intégrer SonarQube à secauto :"
echo "  export SONAR_HOST_URL SONAR_TOKEN"
echo "  python3 -m secauto run --target ${TARGET} --tools sonar"
