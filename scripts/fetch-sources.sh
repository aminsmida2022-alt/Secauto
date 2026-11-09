#!/usr/bin/env bash
#
# Récupère les codes source des cibles utilisées par SAST / SCA.
# crAPI est cloné par scripts/deploy-crapi.sh (structure imposée par son compose).
#
# Usage :
#   bash scripts/fetch-sources.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
mkdir -p targets/sources

fetch() {
  local name="$1" url="$2" ref="$3" dest="$4"
  if [ -d "${dest}/.git" ]; then
    echo "==> ${name} déjà présent (${dest})"
    return
  fi
  echo "==> Clonage de ${name} (${ref})"
  git clone --depth 1 --branch "${ref}" "${url}" "${dest}"
}

fetch "OWASP Juice Shop" \
  "https://github.com/juice-shop/juice-shop.git" \
  "v20.2.0" \
  "${ROOT}/targets/sources/juice-shop"

fetch "Roundcube Webmail" \
  "https://github.com/roundcube/roundcubemail.git" \
  "1.6.7" \
  "${ROOT}/targets/sources/roundcube"

echo
echo "Sources disponibles :"
ls -1 targets/sources
