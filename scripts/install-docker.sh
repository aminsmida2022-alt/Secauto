#!/usr/bin/env bash
#
# Installation de Docker Engine + plugin Compose sur Ubuntu (24.04 noble).
# Source : https://docs.docker.com/engine/install/ubuntu/
#
# Usage :
#   sudo bash scripts/install-docker.sh
#
# Le script tolère les dépôts APT tiers cassés (Stripe, Warp, ...) : ils font
# échouer `apt-get update` globalement mais n'empêchent pas d'installer Docker.
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Ce script doit être lancé avec sudo : sudo bash $0" >&2
  exit 1
fi

TARGET_USER="${SUDO_USER:-root}"
if [ "$TARGET_USER" = "root" ]; then
  echo "Impossible de déterminer l'utilisateur non-root (SUDO_USER vide)." >&2
  echo "Lance-le via 'sudo bash $0' depuis ton compte habituel." >&2
  exit 1
fi

# Met à jour les index sans interrompre le script si un dépôt tiers est cassé.
apt_update() {
  local output
  if ! output="$(apt-get update -qq 2>&1)"; then
    echo "   [!] apt-get update a signalé des erreurs (dépôts tiers non signés) :"
    echo "$output" | grep -E '^(W|E):' | sed 's/^/       /' || true
    echo "       Poursuite de l'installation de Docker."
  fi
}

echo "==> Utilisateur à ajouter au groupe docker : ${TARGET_USER}"

echo "==> Suppression des paquets Docker en conflit (s'il y en a)"
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
  apt-get remove -y "$pkg" >/dev/null 2>&1 || true
done

echo "==> Mise à jour des index APT"
apt_update

echo "==> Installation des prérequis"
apt-get install -y ca-certificates curl gnupg unzip

echo "==> Ajout de la clé GPG officielle Docker"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo "==> Ajout du dépôt Docker"
# shellcheck disable=SC1091
. /etc/os-release
ARCH="$(dpkg --print-architecture)"
echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list

apt_update

# Garantit que l'index du dépôt Docker est bien présent, même si apt-get update
# a échoué à cause d'un autre dépôt.
if ! ls /var/lib/apt/lists/download.docker.com* >/dev/null 2>&1; then
  echo "==> Index Docker absent — mise à jour ciblée du dépôt Docker"
  apt-get update \
    -o Dir::Etc::sourceparts="-" \
    -o Dir::Etc::sourcelist="/etc/apt/sources.list.d/docker.list" \
    -o APT::Get::List-Cleanup="0"
fi

echo "==> Installation de Docker Engine, Buildx et Compose"
if ! apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
  echo
  echo "Échec de l'installation des paquets Docker." >&2
  echo "Vérifie l'accès à https://download.docker.com puis relance :" >&2
  echo "  sudo apt-get update" >&2
  echo "  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin" >&2
  exit 1
fi

echo "==> Activation du service"
systemctl enable --now docker

echo "==> Ajout de ${TARGET_USER} au groupe docker"
usermod -aG docker "$TARGET_USER"

echo
echo "==> Versions installées"
docker --version
docker compose version

echo
echo "=============================================================="
echo " Installation terminée."
echo " IMPORTANT : pour utiliser docker SANS sudo, ouvre une nouvelle"
echo " session (déconnexion/reconnexion) ou lance : newgrp docker"
echo "=============================================================="
