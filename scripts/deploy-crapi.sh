#!/usr/bin/env bash
#
# Déploiement de crAPI (OWASP) — procédure officielle du dépôt, branche develop.
# https://github.com/OWASP/crAPI/tree/develop
#
# Usage :
#   bash scripts/deploy-crapi.sh          # démarrage
#   bash scripts/deploy-crapi.sh stop     # arrêt
#   bash scripts/deploy-crapi.sh reset    # arrêt + suppression des volumes
#
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
SRC="${ROOT}/targets/crapi"
ACTION="${1:-start}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker n'est pas installé. Lance d'abord : sudo bash scripts/install-docker.sh" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Le démon Docker n'est pas accessible." >&2
  echo "Ouvre une nouvelle session, ou lance : newgrp docker" >&2
  exit 1
fi

case "$ACTION" in
  stop)
    echo "==> Arrêt de crAPI"
    ( cd "${SRC}/deploy/docker" && docker compose down )
    exit 0
    ;;
  reset)
    echo "==> Arrêt de crAPI + suppression des volumes"
    ( cd "${SRC}/deploy/docker" && docker compose down -v )
    exit 0
    ;;
esac

if [ ! -d "${SRC}/deploy/docker" ]; then
  echo "==> Récupération du dépôt crAPI (branche develop)"
  mkdir -p "${ROOT}/targets"
  git clone --depth 1 --branch develop https://github.com/OWASP/crAPI.git "${SRC}"
else
  echo "==> Dépôt crAPI déjà présent dans ${SRC}"
fi

cd "${SRC}/deploy/docker"

# Le README demande un Compose >= 1.27 pour la syntaxe d'interpolation du .env
echo "==> Version de Docker Compose"
docker compose version

echo "==> Téléchargement des images"
docker compose pull

echo "==> Démarrage (les premiers démarrages peuvent prendre 2-3 minutes)"
docker compose -f docker-compose.yml --compatibility up -d

echo
echo "==> Attente de la disponibilité de l'interface web..."
for i in $(seq 1 60); do
  if curl -fsS -o /dev/null http://localhost:8888/; then
    echo "   crAPI répond sur http://localhost:8888 (après ${i}s)"
    break
  fi
  sleep 2
done

echo
docker compose ps
echo
echo "=============================================================="
echo " crAPI     : http://localhost:8888"
echo " MailHog   : http://localhost:8025   (emails de l'app)"
echo " Arrêt     : bash scripts/deploy-crapi.sh stop"
echo " Reset     : bash scripts/deploy-crapi.sh reset"
echo "=============================================================="
