#!/usr/bin/env bash
#
# Démonstration « avant / après correctif » sur Juice Shop.
#
# Applique (ou restaure) le correctif par requête paramétrée sur
# routes/login.ts, afin de montrer que la plateforme détecte la vulnérabilité
# avant correction, puis ne la remonte plus après.
#
# Usage :
#   bash scripts/demo-juiceshop-fix.sh            # appliquer le correctif
#   bash scripts/demo-juiceshop-fix.sh --restore  # revenir au code vulnérable
#
set -euo pipefail
cd "$(dirname "$0")/.."

FILE="targets/sources/juice-shop/routes/login.ts"
BACKUP="${FILE}.vulnerable.bak"

if [ ! -f "$FILE" ]; then
  echo "Source introuvable : $FILE" >&2
  echo "Lance d'abord : bash scripts/fetch-sources.sh" >&2
  exit 1
fi

if [ "${1:-}" = "--restore" ]; then
  if [ -f "$BACKUP" ]; then
    cp "$BACKUP" "$FILE"
    echo "Code vulnérable restauré depuis $BACKUP"
  else
    echo "Aucune sauvegarde trouvée : rien à restaurer."
  fi
  exit 0
fi

[ -f "$BACKUP" ] || cp "$FILE" "$BACKUP"

python3 - "$FILE" <<'PY'
import sys

path = sys.argv[1]
lines = open(path, encoding="utf-8").read().split("\n")
marker = "SELECT * FROM Users WHERE email = '"
changed = False

for index, line in enumerate(lines):
    if marker not in line or "sequelize.query" not in line:
        continue

    start = line.index("models.sequelize.query(")
    end = line.index("plain: true })") + len("plain: true })")
    suffix = line[end:]
    replacement = (
        "models.sequelize.query('SELECT * FROM Users WHERE email = $1 "
        "AND password = $2 AND deletedAt IS NULL', "
        "{ bind: [req.body.email || '', security.hash(req.body.password || '')], "
        "model: UserModel, plain: true })"
    )
    lines[index] = line[:start] + replacement + suffix
    changed = True
    break

if not changed:
    print("Motif vulnérable introuvable — le code a peut-être déjà été corrigé.")
    sys.exit(0)

open(path, "w", encoding="utf-8").write("\n".join(lines))
print(f"Correctif appliqué dans {path}")
PY

echo
echo "Étapes suivantes :"
echo "  1. python3 -m secauto run --target juice-shop --tools sast --offline --run-id after-fix"
echo "  2. python3 -m secauto compare --target juice-shop --before <run-avant> --after after-fix"
echo
echo "Pour revenir au code vulnérable : bash scripts/demo-juiceshop-fix.sh --restore"
