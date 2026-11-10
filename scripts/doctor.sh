#!/usr/bin/env bash
#
# Vérifie que l'environnement est prêt pour une campagne secauto.
# À lancer avant la séance : bash scripts/doctor.sh
#
set -uo pipefail
cd "$(dirname "$0")/.."

OK=0
KO=0
WARN=0

ok()   { printf "  \033[32m✓\033[0m %s\n" "$1"; OK=$((OK + 1)); }
ko()   { printf "  \033[31m✗\033[0m %s\n" "$1"; KO=$((KO + 1)); }
warn() { printf "  \033[33m!\033[0m %s\n" "$1"; WARN=$((WARN + 1)); }

echo
echo "=== Outils ==============================================="

if command -v docker >/dev/null 2>&1; then
  ok "docker : $(docker --version)"
  if docker info >/dev/null 2>&1; then
    ok "démon Docker accessible"
  elif ./scripts/dk info >/dev/null 2>&1; then
    warn "démon accessible via « sg docker » — ouvre une nouvelle session pour l'utiliser directement"
  else
    ko "démon Docker inaccessible (service démarré ? sudo systemctl start docker)"
  fi
  if docker compose version >/dev/null 2>&1; then
    ok "docker compose : $(docker compose version --short)"
  else
    ko "plugin docker compose absent"
  fi
else
  ko "docker absent — lancer : sudo bash scripts/install-docker.sh"
fi

command -v python3 >/dev/null 2>&1 && ok "python3 : $(python3 --version)" || ko "python3 absent"

if python3 -c "import yaml" >/dev/null 2>&1; then
  ok "PyYAML installé"
else
  ko "PyYAML absent — lancer : make install"
fi

command -v semgrep >/dev/null 2>&1 \
  && ok "semgrep : $(semgrep --version 2>/dev/null)" \
  || warn "semgrep absent — les analyses SAST seront ignorées"

command -v trivy >/dev/null 2>&1 \
  && ok "trivy : $(trivy --version 2>/dev/null | head -1)" \
  || warn "trivy absent — les analyses SCA seront ignorées"

command -v npm >/dev/null 2>&1 \
  && ok "npm : $(npm --version)" \
  || warn "npm absent — npm audit sera ignoré"

echo
echo "=== Cibles ==============================================="

check_url() {
  local label="$1" url="$2"
  if curl -fsS -m 5 -o /dev/null "$url" 2>/dev/null; then
    ok "$label joignable ($url)"
  else
    warn "$label injoignable ($url)"
  fi
}

check_url "Juice Shop" "http://localhost:3000/"
check_url "crAPI"      "http://localhost:8888/"
check_url "Roundcube"  "http://localhost:8080/"

echo
echo "=== Sources (SAST / SCA) ================================="

[ -d "targets/sources/juice-shop" ] && ok "source juice-shop présente" || warn "source juice-shop absente — make sources"
[ -d "targets/sources/roundcube" ]  && ok "source roundcube présente"  || warn "source roundcube absente — make sources"
[ -d "targets/crapi" ]              && ok "source crAPI présente"      || warn "source crAPI absente — make up-crapi"

echo
echo "=== Résumé ==============================================="
echo "  $OK OK · $WARN avertissement(s) · $KO erreur(s)"
echo
[ "$KO" -eq 0 ] || exit 1
