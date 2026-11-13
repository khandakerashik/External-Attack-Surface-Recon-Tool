#!/usr/bin/env bash
# Shared helpers for easm-recon. Sourced by easm-recon.sh.

ts()   { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
log()  { printf '[%s] %s\n' "$(ts)" "$*"; }
warn() { printf '[%s] [WARN] %s\n' "$(ts)" "$*" >&2; }
die()  { printf '[%s] [ERROR] %s\n' "$(ts)" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

PHASE_NO=0
phase() {
  PHASE_NO=$((PHASE_NO + 1))
  printf '\n'
  log "==== [$PHASE_NO] $* ===="
}

# Count non-empty lines of a file (0 if missing).
lines() { if [[ -s "$1" ]]; then grep -cve '^[[:space:]]*$' "$1" 2>/dev/null || true; else echo 0; fi; }

# Run a command under `timeout` when available. Usage: tmo SECONDS cmd args...
tmo() {
  local secs="$1"; shift
  if have timeout; then
    timeout --kill-after=30 "$secs" "$@"
  else
    "$@"
  fi
}

# Python engine (isolated mode: ignores PYTHONPATH/user site and the CWD).
engine() { python3 -I "$EASM_HOME/engine/easm.py" "$@"; }

# Append KEY=VALUE to run metadata consumed by the report.
meta() { printf '%s=%s\n' "$1" "$2" >> "$OUTDIR/report/run-meta.txt"; }

# Merge text files into one sorted unique list.
merge_unique() {
  local out="$1"; shift
  cat "$@" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//; s/\.$//' | sort -u > "$out" || true
}

# Detect ProjectDiscovery httpx (Kali ships it as httpx-toolkit; python-httpx also installs 'httpx').
detect_httpx() {
  if have httpx-toolkit; then echo httpx-toolkit; return; fi
  if have httpx && httpx -h 2>&1 | grep -q -- '-status-code'; then echo httpx; return; fi
  echo ""
}
