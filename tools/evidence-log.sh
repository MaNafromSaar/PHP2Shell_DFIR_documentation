#!/usr/bin/env bash
# evidence-log.sh: add hashed evidence to the evidence log and verify it later.
#
#   evidence-log.sh add FILE --site SITE --desc TEXT --source TEXT [options]
#   evidence-log.sh verify
#   evidence-log.sh next-id
#
# The log is a Markdown table (documentation/evidence-log.md). The script never
# modifies evidence files; it only reads them and edits the log atomically.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${EVIDENCE_PROJECT_ROOT:-$(dirname "$SCRIPT_DIR")}"
LOG="${EVIDENCE_LOG:-$PROJECT_ROOT/documentation/evidence-log.md}"
SEP=$'\x1f'

usage() {
  cat <<'EOF'
Usage:
  evidence-log.sh add FILE --site SITE --desc TEXT --source TEXT [options]
  evidence-log.sh verify
  evidence-log.sh next-id

Options for add:
  --id E-007           use this ID; if the row exists and has no hash yet, it is filled in
  --stored-at PATH     path recorded in the log (default: FILE relative to the project root)
  --collector NAME     default: $USER
  --time "TEXT"        default: current local time with UTC offset
  --allow-duplicate    allow a hash that is already in the log

Environment:
  EVIDENCE_LOG           path to the log (default: documentation/evidence-log.md)
  EVIDENCE_PROJECT_ROOT  base for relative "Stored at" paths (default: parent of tools/)

verify re-hashes every logged file and exits 1 on a mismatch or a missing file.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

# Table cells must be single-line and must not contain unescaped pipes.
esc() { printf '%s' "$1" | tr '\n\r' '  ' | sed 's/|/\\|/g'; }

require_log() { [[ -f "$LOG" ]] || die "evidence log not found: $LOG"; }

max_id_number() {
  { grep -oE '^\| E-[0-9]+ ' "$LOG" || true; } | grep -oE '[0-9]+' | sed 's/^0*//' | sort -n | tail -n1
}

next_id() {
  local max
  max="$(max_id_number)"
  printf 'E-%03d\n' "$(( ${max:-0} + 1 ))"
}

# Prints "line<TAB>hash" for a row with the given ID, or nothing.
find_row() {
  local id="$1"
  awk -F'|' -v id="$id" '
    /^\| E-[0-9]+ / {
      line = $0; gsub(/\\\|/, "\001", line)
      n = split(line, f, "|")
      cell = f[2]; gsub(/^ +| +$/, "", cell)
      h = f[7]; gsub(/^ +| +$/, "", h)
      if (cell == id) { print NR "\t" h; exit }
    }' "$LOG"
}

cmd_add() {
  local file="" id="" site="" desc="" source="" stored="" collector="${USER:-unknown}" when="" dup=0
  [[ $# -ge 1 ]] || { usage; exit 2; }
  file="$1"; shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --id) id="${2:?}"; shift 2 ;;
      --site) site="${2:?}"; shift 2 ;;
      --desc) desc="${2:?}"; shift 2 ;;
      --source) source="${2:?}"; shift 2 ;;
      --stored-at) stored="${2:?}"; shift 2 ;;
      --collector) collector="${2:?}"; shift 2 ;;
      --time) when="${2:?}"; shift 2 ;;
      --allow-duplicate) dup=1; shift ;;
      *) die "unknown option: $1" ;;
    esac
  done
  [[ -n "$site" && -n "$desc" && -n "$source" ]] || die "--site, --desc and --source are required"
  [[ -f "$file" && -r "$file" ]] || die "not a readable regular file: $file"
  require_log

  local hash
  hash="$(sha256sum -- "$file" | awk '{print $1}')"

  if [[ $dup -eq 0 ]] && grep -qi -- "| $hash |" "$LOG"; then
    die "this hash is already in the log (use --allow-duplicate to add it anyway)"
  fi

  if [[ -z "$stored" ]]; then
    local abs root
    abs="$(realpath -- "$file")"
    root="$(realpath -- "$PROJECT_ROOT")"
    if [[ "$abs" == "$root"/* ]]; then stored="${abs#"$root"/}"; else stored="$abs"; fi
  fi
  [[ -n "$when" ]] || when="$(date +'%Y-%m-%d %H:%M (%:z)')"

  local fill_line=""
  if [[ -n "$id" ]]; then
    local existing
    existing="$(find_row "$id")"
    if [[ -n "$existing" ]]; then
      [[ -z "${existing#*$'\t'}" ]] || die "$id already has a hash; refusing to overwrite"
      fill_line="${existing%%$'\t'*}"
    fi
  else
    id="$(next_id)"
  fi

  local row
  row="| $id | $(esc "$when") | $(esc "$site") | $(esc "$desc") | $(esc "$source") | $hash | \`$(esc "$stored")\` | $(esc "$collector") |"

  local tmp
  tmp="$(mktemp "${LOG}.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT
  if [[ -n "$fill_line" ]]; then
    ROW="$row" awk -v n="$fill_line" 'NR==n { print ENVIRON["ROW"]; next } { print }' "$LOG" > "$tmp"
  else
    local last
    last="$(grep -nE '^\| E-[0-9]+ ' "$LOG" | tail -n1 | cut -d: -f1 || true)"
    [[ -n "$last" ]] || die "no evidence table rows found in $LOG"
    ROW="$row" awk -v n="$last" '{ print } NR==n { print ENVIRON["ROW"] }' "$LOG" > "$tmp"
  fi
  mv -- "$tmp" "$LOG"
  trap - EXIT
  printf 'logged %s  sha256=%s\n' "$id" "$hash"
}

cmd_verify() {
  require_log
  local ok=0 bad=0 skipped=0 id hash path abs
  while IFS="$SEP" read -r id hash path; do
    path="${path//\`/}"
    if [[ ! "$hash" =~ ^[0-9a-fA-F]{64}$ ]]; then
      printf 'SKIP      %s (no hash recorded)\n' "$id"; skipped=$((skipped + 1)); continue
    fi
    if [[ "$path" == /* ]]; then abs="$path"; else abs="$PROJECT_ROOT/$path"; fi
    if [[ ! -f "$abs" ]]; then
      printf 'MISSING   %s %s\n' "$id" "$path"; bad=$((bad + 1)); continue
    fi
    if [[ "$(sha256sum -- "$abs" | awk '{print $1}')" == "${hash,,}" ]]; then
      printf 'OK        %s %s\n' "$id" "$path"; ok=$((ok + 1))
    else
      printf 'MISMATCH  %s %s\n' "$id" "$path"; bad=$((bad + 1))
    fi
  done < <(awk -F'|' -v sep="$SEP" '
    /^\| E-[0-9]+ / {
      line = $0; gsub(/\\\|/, "\001", line)
      split(line, f, "|")
      for (i = 2; i <= 8; i++) gsub(/^ +| +$/, "", f[i])
      print f[2] sep f[7] sep f[8]
    }' "$LOG")
  printf '\n%d ok, %d problem(s), %d skipped\n' "$ok" "$bad" "$skipped"
  [[ $bad -eq 0 ]]
}

case "${1:-}" in
  add) shift; cmd_add "$@" ;;
  verify) cmd_verify ;;
  next-id) require_log; next_id ;;
  -h|--help|help|"") usage ;;
  *) usage; exit 2 ;;
esac
