#!/usr/bin/env bash
# easm-recon - External Attack Surface Management & vulnerability recon.
#
# Passive discovery, DNS/e-mail posture, enrichment and CVE intelligence run automatically.
# Any traffic to target systems (ports, HTTP, TLS, nuclei, AXFR) requires an explicit,
# reviewed allowlist and an authorisation confirmation.

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

EASM_HOME="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
VERSION="2.0.0"
SCRIPT_NAME="${0##*/}"

# shellcheck source=lib/common.sh
source "$EASM_HOME/lib/common.sh"
# shellcheck source=lib/passive.sh
source "$EASM_HOME/lib/passive.sh"
# shellcheck source=lib/resolve.sh
source "$EASM_HOME/lib/resolve.sh"
# shellcheck source=lib/active.sh
source "$EASM_HOME/lib/active.sh"

usage() {
  cat <<EOF
easm-recon $VERSION - external attack surface & vulnerability recon

Usage:
  ./$SCRIPT_NAME [options] "example.com,example.org"
  ./$SCRIPT_NAME [options] domains.txt
  ./$SCRIPT_NAME                          (prompts for input)
  ./$SCRIPT_NAME --report-only RUN_DIR    (re-analyse + re-render an existing run)

Scope & safety:
  --passive-only          Never send traffic to target systems.
  --allowlist FILE        Pre-approved active scope (skips interactive review).
  --auth-ref REF          Authorisation / ticket reference (required with --allowlist;
                          asked interactively otherwise). Recorded in the report.

Profiles & tuning:
  --profile NAME          quick | standard (default) | deep
  -c, --config FILE       Config file (default: config/easm.conf if present)
  --top-ports N           100 | 1000 | full
  --dns-brute WORDLIST    Enable DNS brute force via public resolvers
  --permutations          Enable alterx permutation discovery
  --crawl                 Enable katana crawling (active)
  --no-nuclei             Skip nuclei templates
  --no-web-inventory      Skip the httpx web asset inventory (findings/web-assets.csv)
  --no-internetdb         Skip Shodan InternetDB enrichment
  --no-cve                Skip NVD/KEV/EPSS correlation
  --offline-intel         Use cached NVD/KEV/EPSS/InternetDB data only

Output:
  -o, --output DIR        Output directory (default: ./easm_<first-root>_<UTC>)
  --compare DIR           Previous run directory: report new/resolved hosts & findings
  -h, --help | --version

Environment:
  NVD_API_KEY             Recommended (free). Speeds up CVE correlation ~10x.

Output layout: roots.txt candidates.txt passive/ dns/ enrich/ urls/ authorized/ scan/
               ports/ http/ tls/ crawl/ vuln/ analysis/ findings/ report/index.html logs/
EOF
}

# ------------------------------------------------------------------------- defaults
apply_profile() {
  case "$1" in
    quick)    TOP_PORTS=100;  NUCLEI_SEVERITY="medium,high,critical"; ENABLE_AMASS=0; SUBFINDER_ALL=0; ENABLE_CRAWL=0 ;;
    standard) TOP_PORTS=1000; NUCLEI_SEVERITY="low,medium,high,critical" ;;
    deep)     TOP_PORTS=full; NUCLEI_SEVERITY="info,low,medium,high,critical"; ENABLE_CRAWL=1; ENABLE_PERMUTATIONS=1
              AMASS_TIMEOUT_MIN=30 ;;
    *) die "Unknown profile: $1 (quick|standard|deep)" ;;
  esac
}

SUBFINDER_ALL=1; SUBFINDER_PROVIDER_CONFIG=""; ENABLE_AMASS=1; AMASS_TIMEOUT_MIN=15
ENABLE_ARCHIVES=1; GAU_THREADS=3; ARCHIVE_TIMEOUT=1800; ENABLE_WHOIS=1; CERTSPOTTER_API_KEY="${CERTSPOTTER_API_KEY:-}"
PASSIVE_TOOL_TIMEOUT=2400; DNSX_RATE=50; RESOLVERS_FILE=""; DNS_RESOLVER=""; DNS_WORDLIST=""
ENABLE_PERMUTATIONS=0; PERMUTATION_LIMIT=20000; ENABLE_INTERNETDB=1; INTERNETDB_MAX_IPS=750
OFFLINE_INTEL=0; ENABLE_CVE_MAPPING=1; ENABLE_AXFR=1; TOP_PORTS=1000; NAABU_RATE=150; NMAP_MAX_RATE=100
PORTSCAN_TIMEOUT=7200; ENABLE_SERVICE_DETECTION=1; NMAP_VERSION_INTENSITY=7; NMAP_HOST_TIMEOUT_SEC=900
HTTPX_RATE=5; HTTPX_THREADS=10; HTTP_TIMEOUT=3600; ENABLE_WEB_INVENTORY=1; WEB_INVENTORY_RATE=2; WEB_INVENTORY_THREADS=2; ENABLE_TLS=1; TLS_WORKERS=4; ENABLE_CRAWL=0
KATANA_DEPTH=2; KATANA_RATE=5; CRAWL_TIMEOUT=3600; ENABLE_NUCLEI=1; NUCLEI_RATE=10; NUCLEI_CONCURRENCY=5
NUCLEI_BULK=10; NUCLEI_SEVERITY="low,medium,high,critical"
NUCLEI_EXCLUDE_TAGS="dos,fuzz,fuzzing,intrusive,bruteforce,brute-force,default-login,osint,headless"
NUCLEI_TEMPLATES=""; NUCLEI_TIMEOUT=10800; REPORT_TITLE="External Attack Surface & Vulnerability Report"

PASSIVE_ONLY=0; INPUT_VALUE=""; CONFIG_FILE=""; PROFILE="standard"; OUTDIR=""; COMPARE_DIR=""
ALLOWLIST_FILE=""; AUTH_REF=""; REPORT_ONLY=""; ACTIVE_OK=0
declare -a OVERRIDES=()

# ------------------------------------------------------------------------- arguments
while (($#)); do
  case "$1" in
    --passive-only)   PASSIVE_ONLY=1 ;;
    --allowlist)      ALLOWLIST_FILE="$(readlink -f "${2:?}")"; shift ;;
    --auth-ref)       AUTH_REF="${2:?}"; shift ;;
    --profile)        PROFILE="${2:?}"; shift ;;
    -c|--config)      CONFIG_FILE="$(readlink -f "${2:?}")"; shift ;;
    --top-ports)      OVERRIDES+=("TOP_PORTS=${2:?}"); shift ;;
    --dns-brute)      OVERRIDES+=("DNS_WORDLIST=$(readlink -f "${2:?}")"); shift ;;
    --permutations)   OVERRIDES+=("ENABLE_PERMUTATIONS=1") ;;
    --crawl)          OVERRIDES+=("ENABLE_CRAWL=1") ;;
    --no-nuclei)      OVERRIDES+=("ENABLE_NUCLEI=0") ;;
    --no-web-inventory) OVERRIDES+=("ENABLE_WEB_INVENTORY=0") ;;
    --no-internetdb)  OVERRIDES+=("ENABLE_INTERNETDB=0") ;;
    --no-cve)         OVERRIDES+=("ENABLE_CVE_MAPPING=0") ;;
    --offline-intel)  OVERRIDES+=("OFFLINE_INTEL=1") ;;
    -o|--output)      OUTDIR="${2:?}"; shift ;;
    --compare)        COMPARE_DIR="$(readlink -f "${2:?}")"; shift ;;
    --report-only)    REPORT_ONLY="$(readlink -f "${2:?}")"; shift ;;
    -h|--help)        usage; exit 0 ;;
    --version)        echo "$VERSION"; exit 0 ;;
    --)               shift; break ;;
    -*)               die "Unknown option: $1 (see --help)" ;;
    *)  [[ -z "$INPUT_VALUE" ]] || die "Provide only one input argument."; INPUT_VALUE="$1" ;;
  esac
  shift
done
if (($#)); then
  [[ -z "$INPUT_VALUE" ]] || die "Provide only one input argument."
  INPUT_VALUE="$1"; shift
fi
(($# == 0)) || die "Too many arguments."

apply_profile "$PROFILE"
[[ -z "$CONFIG_FILE" && -f "$EASM_HOME/config/easm.conf" ]] && CONFIG_FILE="$EASM_HOME/config/easm.conf"
if [[ -n "$CONFIG_FILE" ]]; then
  [[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"
  # shellcheck source=/dev/null
  source "$CONFIG_FILE"
fi
for kv in "${OVERRIDES[@]}"; do
  printf -v "${kv%%=*}" '%s' "${kv#*=}"
done
[[ "$TOP_PORTS" =~ ^(100|1000|full)$ ]] || die "--top-ports must be 100, 1000 or full"
if [[ -n "$ALLOWLIST_FILE" ]]; then
  [[ -f "$ALLOWLIST_FILE" ]] || die "Allowlist file not found: $ALLOWLIST_FILE"
  [[ -n "${AUTH_REF// /}" ]] || die "--allowlist requires --auth-ref (ticket / engagement reference)."
  ((PASSIVE_ONLY)) && die "--allowlist and --passive-only are mutually exclusive."
fi

command -v python3 >/dev/null 2>&1 || die "python3 (3.9+) is required."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "python3 3.9+ is required."

finalize() {
  phase "Correlation & CVE intelligence (NVD + CISA KEV + FIRST EPSS)"
  local aflags=()
  ((ENABLE_CVE_MAPPING)) || aflags+=(--no-cve)
  ((OFFLINE_INTEL)) && aflags+=(--offline)
  [[ -z "${NVD_API_KEY:-}" ]] && ((ENABLE_CVE_MAPPING)) && warn "NVD_API_KEY not set: NVD queries are throttled to 5 per 30s (results are cached)."
  engine analyze --run-dir . "${aflags[@]}" || warn "Analysis failed; report may be incomplete."

  phase "Reporting"
  local rflags=(--title "$REPORT_TITLE")
  [[ -n "$COMPARE_DIR" ]] && rflags+=(--compare "$COMPARE_DIR")
  engine report --run-dir . "${rflags[@]}" >/dev/null || warn "Report rendering failed."
  meta RUN_FINISHED "$(ts)"

  if have sha256sum; then
    find . -type f ! -path './report/SHA256SUMS.txt' ! -path './logs/*' -print0 | sort -z \
      | xargs -0 -r sha256sum > report/SHA256SUMS.txt 2>/dev/null || true
  else
    warn "sha256sum not installed; evidence checksums not generated."
  fi
}

# ------------------------------------------------------------------------- report-only
if [[ -n "$REPORT_ONLY" ]]; then
  [[ -f "$REPORT_ONLY/roots.txt" ]] || die "$REPORT_ONLY does not look like an easm-recon run directory."
  OUTDIR="$REPORT_ONLY"
  cd "$OUTDIR"
  mkdir -p analysis findings report logs
  log "Re-analysing existing run: $OUTDIR"
  finalize
  log "Report: $OUTDIR/report/index.html"
  exit 0
fi

# ------------------------------------------------------------------------- input
if [[ -z "$INPUT_VALUE" ]]; then
  printf 'Enter domains (comma-separated) OR a .txt file path: '
  IFS= read -r INPUT_VALUE || die "No input received."
fi
[[ -n "${INPUT_VALUE//[[:space:]]/}" ]] || die "Input cannot be empty."
if [[ -f "$INPUT_VALUE" ]]; then INPUT_MODE="file"; INPUT_VALUE="$(readlink -f "$INPUT_VALUE")"; else INPUT_MODE="string"; fi

TMP_ROOTS="$(mktemp)"
trap 'rm -f "$TMP_ROOTS"' EXIT
engine parse-input "$INPUT_MODE" "$INPUT_VALUE" > "$TMP_ROOTS" \
  || die "Input validation failed. Use bare DNS domains (no https://, paths, ports or wildcards)."
ROOT_COUNT="$(lines "$TMP_ROOTS")"
[[ "$ROOT_COUNT" -gt 0 ]] || die "No valid domains found in the input."

RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FIRST_ROOT="$(head -n1 "$TMP_ROOTS")"
OUTDIR="${OUTDIR:-$PWD/easm_${FIRST_ROOT}_${RUN_STAMP}}"
OUTDIR="$(readlink -m "$OUTDIR")"
[[ -e "$OUTDIR" && -n "$(ls -A "$OUTDIR" 2>/dev/null)" ]] && die "Output directory exists and is not empty: $OUTDIR"
mkdir -p "$OUTDIR"/{passive,dns,enrich,urls,authorized,scan,ports/services,http,tls,crawl,vuln,analysis,findings,report,logs}
cp "$TMP_ROOTS" "$OUTDIR/roots.txt"
cd "$OUTDIR"
exec > >(tee -a "$OUTDIR/logs/run.log") 2>&1

: > report/run-meta.txt
meta VERSION "$VERSION"; meta RUN_STARTED "$(ts)"; meta PROFILE "$PROFILE"; meta OPERATOR "${USER:-unknown}"
meta HOST "$(hostname 2>/dev/null || echo unknown)"; meta ROOTS "$(paste -sd, roots.txt)"
meta PASSIVE_ONLY "$PASSIVE_ONLY"; meta TOP_PORTS "$TOP_PORTS"; meta NUCLEI_SEVERITY "$NUCLEI_SEVERITY"

log "easm-recon $VERSION | profile=$PROFILE | roots=$ROOT_COUNT | output=$OUTDIR"

{
  echo "Run started UTC: $(ts)"
  echo ""
  for tool in subfinder amass assetfinder findomain dnsx alterx gau waybackurls naabu nmap httpx-toolkit httpx katana nuclei dig whois curl jq python3 sha256sum; do
    if have "$tool"; then
      printf '%-14s %s  ' "$tool" "$(command -v "$tool")"
      case "$tool" in
        subfinder|dnsx|naabu|nuclei|katana|alterx|httpx-toolkit) "$tool" -version 2>&1 | grep -iEo 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true ;;
        httpx) [[ "$(detect_httpx)" == httpx ]] && { httpx -version 2>&1 | grep -iEo 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true; } || echo "(not ProjectDiscovery httpx)" ;;
        nmap) nmap --version 2>/dev/null | head -n1 ;;
        amass) amass -version 2>&1 | head -n1 || true ;;
        python3) python3 --version 2>&1 ;;
        *) echo ;;
      esac
    else
      printf '%-14s %s\n' "$tool" "NOT INSTALLED"
    fi
  done
  if have nuclei; then echo; echo "nuclei templates: $(nuclei -tv 2>&1 | grep -Eo 'v[0-9.]+' | tail -n1 || true)"; fi
} > report/tool-inventory.txt 2>&1

have subfinder || warn "subfinder not installed - discovery coverage will be limited (run ./install.sh)."

passive_discovery
resolution_and_enrichment
active_checks
[[ -f report/.active_ran ]] && meta ACTIVE_RAN 1 || meta ACTIVE_RAN 0
finalize

summary() {
  printf '\n'
  log "================ RUN COMPLETE ================"
  log "Hostnames discovered : $(lines candidates.txt)"
  log "Resolving            : $(lines dns/dnsx.jsonl)"
  log "Active checks        : $([[ -f report/.active_ran ]] && echo "yes (ref: $AUTH_REF)" || echo no)"
  python3 -I - <<'PY' || true
import json
try:
    f = json.load(open("analysis/findings.json"))
    c = json.load(open("analysis/cves.json"))
except Exception:
    raise SystemExit
sev = {}
for x in f:
    sev[x["severity"]] = sev.get(x["severity"], 0) + 1
order = ["critical", "high", "medium", "low", "info"]
print("[i] Findings            : " + ", ".join(f"{k}={sev.get(k, 0)}" for k in order))
print(f"[i] CVEs correlated     : {len(c)} (CISA KEV: {sum(1 for x in c if x.get('kev'))})")
PY
  log "HTML report          : $OUTDIR/report/index.html"
  log "CSV / JSON / MD      : $OUTDIR/report/{findings,assets,cves}.csv, findings.json, summary.md"
  [[ -s findings/web-assets.csv ]] && log "Web asset inventory  : $OUTDIR/findings/web-assets.csv"
  log "Note: 'authorized_hosts.txt' is a working file; authorisation comes from the written scope approval."
}
summary
