#!/usr/bin/env bash
# Verifies that every vaultwarden table in sql/schema.sql matches vaultwarden's real SQLite schema
# (built from ../migrations/sqlite) column-by-column: name, type, notnull, default, pk, plus
# foreign keys and unique indexes. Extra Workers-only tables are allowed and listed.
set -euo pipefail
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
VW="$TMP/vw.sqlite"; OURS="$TMP/ours.sqlite"
for d in ../migrations/sqlite/*/; do sqlite3 "$VW" < "${d}up.sql"; done
sqlite3 "$OURS" < sql/schema.sql

tables() { sqlite3 "$1" "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"; }
describe() { # db table -> normalized description
  sqlite3 "$1" "SELECT 'col', name, upper(type), \"notnull\", ifnull(dflt_value,''), pk FROM pragma_table_info('$2') ORDER BY cid;
                SELECT 'fk', \"from\", \"table\", \"to\" FROM pragma_foreign_key_list('$2') ORDER BY \"from\";
                SELECT 'uniq', group_concat(ii.name, ',') FROM pragma_index_list('$2') il, pragma_index_info(il.name) ii
                  WHERE il.\"unique\" = 1 GROUP BY il.name ORDER BY 2;"
}

fail=0
for t in $(tables "$VW"); do
  if ! tables "$OURS" | grep -qx "$t"; then echo "MISSING table: $t"; fail=1; continue; fi
  if ! diff <(describe "$VW" "$t") <(describe "$OURS" "$t") > "$TMP/diff"; then
    echo "DIFF in $t (< vaultwarden, > ours):"; cat "$TMP/diff"; fail=1
  fi
done
extra="$(comm -13 <(tables "$VW") <(tables "$OURS") | tr '\n' ' ')"
echo "vaultwarden tables checked: $(tables "$VW" | wc -l | tr -d ' '); Workers-only tables: ${extra:-none}"
[ "$fail" = 0 ] && echo "schema_check: PASS" || { echo "schema_check: FAIL"; exit 1; }
