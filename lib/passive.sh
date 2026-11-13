#!/usr/bin/env bash
# Passive discovery: no packets are sent to target infrastructure (only to public
# data sources / resolvers). Sourced by easm-recon.sh.

run_subfinder() {
  : > passive/subfinder.txt
  if ! have subfinder; then warn "subfinder not installed; skipping."; return 0; fi
  local args=(-dL roots.txt -silent -o passive/subfinder.txt)
  ((SUBFINDER_ALL)) && args+=(-all)
  [[ -n "${SUBFINDER_PROVIDER_CONFIG:-}" && -f "$SUBFINDER_PROVIDER_CONFIG" ]] && args+=(-pc "$SUBFINDER_PROVIDER_CONFIG")
  log "subfinder (all sources=${SUBFINDER_ALL})"
  tmo "$PASSIVE_TOOL_TIMEOUT" subfinder "${args[@]}" || warn "subfinder returned an error/timeout; keeping partial output."
  log "subfinder: $(lines passive/subfinder.txt) names"
}

run_amass() {
  : > passive/amass.txt
  ((ENABLE_AMASS)) || { log "amass disabled in config."; return 0; }
  if ! have amass; then warn "amass not installed; skipping."; return 0; fi
  log "amass enum -passive (timeout ${AMASS_TIMEOUT_MIN}m)"
  tmo $((AMASS_TIMEOUT_MIN * 60 + 120)) amass enum -passive -df roots.txt -timeout "$AMASS_TIMEOUT_MIN" -o passive/amass.txt \
    >/dev/null 2>>logs/amass.err || warn "amass returned an error (see logs/amass.err); continuing."
  log "amass: $(lines passive/amass.txt) lines"
}

run_assetfinder_findomain() {
  : > passive/assetfinder.txt
  : > passive/findomain.txt
  if have assetfinder; then
    log "assetfinder"
    while IFS= read -r d; do
      tmo 300 assetfinder --subs-only "$d" >> passive/assetfinder.txt 2>/dev/null || true
    done < roots.txt
  fi
  if have findomain; then
    log "findomain"
    tmo "$PASSIVE_TOOL_TIMEOUT" findomain -f roots.txt -q -u passive/findomain.txt >/dev/null 2>&1 || warn "findomain returned an error."
  fi
}

# Parse a JSON array from stdin and print selected name fields (jq optional).
_json_names() {
  python3 -I -c '
import json, sys
field = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for item in data if isinstance(data, list) else []:
    v = item.get(field)
    vals = v if isinstance(v, list) else str(v or "").split("\n")
    for x in vals:
        x = x.strip().lower().removeprefix("*.")
        if x:
            print(x)
' "$1"
}

run_ct_logs() {
  : > passive/crtsh.txt
  : > passive/certspotter.txt
  if ! have curl; then warn "curl not installed; skipping Certificate Transparency."; return 0; fi
  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    log "crt.sh: $domain"
    curl -fsS --retry 2 --retry-delay 3 --connect-timeout 10 --max-time 90 \
      "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | _json_names name_value >> passive/crtsh.txt \
      || warn "crt.sh lookup failed for $domain (service is often overloaded)."
    local auth=()
    [[ -n "${CERTSPOTTER_API_KEY:-}" ]] && auth=(-H "Authorization: Bearer ${CERTSPOTTER_API_KEY}")
    curl -fsS --connect-timeout 10 --max-time 60 "${auth[@]}" \
      "https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names" 2>/dev/null \
      | _json_names dns_names >> passive/certspotter.txt || warn "Cert Spotter lookup failed for $domain (rate limit?)."
    sleep 1
  done < roots.txt
  sort -u passive/crtsh.txt -o passive/crtsh.txt
  sort -u passive/certspotter.txt -o passive/certspotter.txt
  log "CT logs: crt.sh $(lines passive/crtsh.txt), certspotter $(lines passive/certspotter.txt)"
}

run_archives() {
  : > urls/archived-urls.txt
  ((ENABLE_ARCHIVES)) || { log "Archive URL collection disabled."; return 0; }
  if have gau; then
    log "gau (wayback, commoncrawl, otx, urlscan) threads=$GAU_THREADS"
    tmo "$ARCHIVE_TIMEOUT" gau --threads "$GAU_THREADS" --subs --blacklist png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css,mp4,webp \
      < roots.txt > urls/archived-urls.txt 2>>logs/gau.err || warn "gau returned an error/timeout; keeping partial output."
  elif have waybackurls; then
    log "waybackurls"
    tmo "$ARCHIVE_TIMEOUT" waybackurls < roots.txt > urls/archived-urls.txt 2>>logs/gau.err || warn "waybackurls error."
  else
    warn "gau/waybackurls not installed; skipping historical URLs."
  fi
  sort -u urls/archived-urls.txt -o urls/archived-urls.txt
  # Hostnames seen in archives feed discovery too.
  sed -E 's#^[a-zA-Z]+://([^/:?]+).*#\1#' urls/archived-urls.txt | sort -u > passive/archive-hosts.txt
  log "Archived URLs: $(lines urls/archived-urls.txt) ($(lines passive/archive-hosts.txt) hostnames)"
}

# Optional (semi-passive): wordlist brute force via public resolvers. Off by default.
run_dns_bruteforce() {
  : > passive/bruteforce.txt
  [[ -n "$DNS_WORDLIST" ]] || return 0
  [[ -f "$DNS_WORDLIST" ]] || { warn "Wordlist not found: $DNS_WORDLIST"; return 0; }
  have dnsx || { warn "dnsx required for --dns-brute; skipping."; return 0; }
  local rargs=()
  [[ -n "$RESOLVERS_FILE" ]] && rargs=(-r "$RESOLVERS_FILE")
  while IFS= read -r d; do
    log "DNS brute force: $d ($(lines "$DNS_WORDLIST") words, rate $DNSX_RATE/s)"
    tmo "$PASSIVE_TOOL_TIMEOUT" dnsx -silent -d "$d" -w "$DNS_WORDLIST" -wd "$d" -rl "$DNSX_RATE" "${rargs[@]}" \
      >> passive/bruteforce.txt 2>/dev/null || warn "dnsx brute force error for $d"
  done < roots.txt
  log "Brute force: $(lines passive/bruteforce.txt) names"
}

run_permutations() {
  : > passive/permutations.txt
  ((ENABLE_PERMUTATIONS)) || return 0
  if ! have alterx || ! have dnsx; then warn "alterx + dnsx required for permutations; skipping."; return 0; fi
  local rargs=()
  [[ -n "$RESOLVERS_FILE" ]] && rargs=(-r "$RESOLVERS_FILE")
  log "Permutation discovery (alterx, limit $PERMUTATION_LIMIT)"
  tmo "$PASSIVE_TOOL_TIMEOUT" bash -c 'alterx -l "$1" -silent -limit "$2" | dnsx -silent -rl "$3" "${@:4}"' _ \
    candidates.txt "$PERMUTATION_LIMIT" "$DNSX_RATE" "${rargs[@]}" > passive/permutations.txt 2>/dev/null \
    || warn "permutation run error/timeout."
  log "Permutations: $(lines passive/permutations.txt) resolving names"
}

passive_discovery() {
  phase "Passive subdomain discovery"
  run_subfinder
  run_amass
  run_assetfinder_findomain
  run_ct_logs
  phase "Historical URL collection"
  run_archives
}
