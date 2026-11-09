#!/usr/bin/env bash
#
# Installation de Docker Engine + plugin Compose sur Ubuntu 24.04 (noble).
# Source : https://docs.docker.com/engine/install/ubuntu/
#
# Usage :
#   sudo bash scripts/install-docker.sh
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

echo "==> Utilisateur à ajouter au groupe docker : ${TARGET_USER}"

echo "==> Suppression des paquets Docker en conflit (s'il y en a)"
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
  apt-get remove -y "$pkg" >/dev/null 2>&1 || true
done

echo "==> Installation des prérequis"
apt-get update -qq
apt-get install -y ca-certificates curl gnupg unzip

echo "==> Ajout de la clé GPG officielle Docker"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo "==> Ajout du dépôt Docker"
. /etc/os-release
ARCH="$(dpkg --print-architecture)"
echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -qq

echo "==> Installation de Docker Engine, Buildx et Compose"
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

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
