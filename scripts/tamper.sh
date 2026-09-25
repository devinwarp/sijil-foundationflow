#!/usr/bin/env bash
# Demo helper: edits the record store directly with the sqlite3 CLI, from outside
# the application. Uses nothing from Sijill: only sqlite3 and shasum.
#
#   tamper.sh backup        copy the store aside (run before the demo)
#   tamper.sh alter 17      change seq 17's output_hash      -> verifier: content altered
#   tamper.sh forge 17      change seq 17 and recompute its record_hash with the
#                           canonical algorithm, no private key -> verifier: signature invalid
#   tamper.sh restore       put every record that differs from the backup back
set -euo pipefail

DB="${DATABASE_PATH:-sijill.db}"
BAK="${DB}.bak"

die() { printf 'tamper: %s\n' "$*" >&2; exit 1; }
sha() { printf '%s' "$1" | shasum -a 256 | cut -c1-64; }
q() { sqlite3 "$DB" "$1"; }

[ -f "$DB" ] || die "no database at $DB"

seq_arg() {
  [[ "${1:-}" =~ ^[0-9]+$ ]] || die "usage: tamper.sh $CMD <seq>"
  [ "$(q "SELECT count(*) FROM records WHERE seq=$1;")" = 1 ] || die "no record with seq $1"
  [ -f "$BAK" ] || q ".backup '$BAK'"
}

CMD="${1:-}"
case "$CMD" in
  backup)
    q ".backup '$BAK'"
    printf 'backup   %s records copied to %s\n' "$(q 'SELECT count(*) FROM records;')" "$BAK"
    ;;
  alter)
    seq_arg "${2:-}"; S="$2"
    q "UPDATE records SET output_hash='$(sha "a different answer")' WHERE seq=$S;"
    printf 'alter    seq %s: output_hash rewritten, record_hash untouched\n' "$S"
    ;;
  forge)
    seq_arg "${2:-}"; S="$2"
    q "UPDATE records SET output_hash='$(sha "a forged answer")' WHERE seq=$S;"
    # Canonical form: every field except record_hash and signature, keys sorted, no whitespace.
    CANON=$(q "SELECT json_object(
      'approval_ref',approval_ref,'decision',decision,'input_hash',input_hash,'mode',mode,
      'model_digest',model_digest,'model_id',model_id,'node_id',node_id,'node_region',node_region,
      'output_hash',output_hash,'policy_hash',policy_hash,'policy_id',policy_id,'prev_hash',prev_hash,
      'rule_hits',rule_hits,'seq',seq,'ts',ts,'type',type) FROM records WHERE seq=$S;")
    H=$(sha "$CANON")
    q "UPDATE records SET record_hash='$H' WHERE seq=$S;"
    printf 'forge    seq %s: content changed, record_hash recomputed (%s…), no private key\n' "$S" "${H:0:12}"
    ;;
  restore)
    [ -f "$BAK" ] || die "no backup at $BAK, run: tamper.sh backup"
    N=$(q "ATTACH '$BAK' AS b;
      CREATE TEMP TABLE d AS SELECT * FROM b.records EXCEPT SELECT * FROM main.records;
      INSERT OR REPLACE INTO main.records SELECT * FROM temp.d;
      SELECT count(*) FROM temp.d;")
    printf 'restore  %s record(s) returned to their sealed state\n' "$N"
    ;;
  *)
    die "usage: tamper.sh backup | alter <seq> | forge <seq> | restore"
    ;;
esac
