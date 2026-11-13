#!/usr/bin/env bash
# Authorised active checks. Nothing in this file runs unless the operator has
# reviewed the allowlist and confirmed written authorisation (or supplied
# --allowlist + --auth-ref for non-interactive, pre-approved runs).

ALLOW=authorized/authorized_hosts.txt

open_editor() {
  local f="$1" ed="${EDITOR:-}"
  if [[ -z "$ed" ]]; then
    if have nano; then ed="nano"; elif have vi; then ed="vi"; fi
  fi
  if [[ -n "$ed" && -r /dev/tty && -w /dev/tty ]]; then
    # Editors must bypass the tee'd stdout/stderr and attach to the real terminal.
    "$ed" "$f" </dev/tty >/dev/tty 2>&1 || warn "$ed exited non-zero; continuing to validation."
    return 0
  fi
  warn "No usable editor/terminal. Edit $OUTDIR/$f in another terminal."
  read -r -p "Press Enter when the file is saved, or type SKIP: " ans </dev/tty || ans=SKIP
  [[ "$ans" != "SKIP" ]]
}

authorization_gate() {
  ACTIVE_OK=0
  if ((PASSIVE_ONLY)); then
    log "--passive-only: all active checks skipped."
    return 0
  fi

  # Non-interactive, pre-approved scope (CI / scheduled runs).
  if [[ -n "$ALLOWLIST_FILE" ]]; then
    [[ -n "$AUTH_REF" ]] || die "--allowlist requires --auth-ref (ticket / engagement reference)."
    cp "$ALLOWLIST_FILE" "$ALLOW"
    if engine validate-allowlist --roots roots.txt --allowlist "$ALLOW"; then
      log "Pre-approved allowlist accepted ($(lines "$ALLOW") hosts). Authorisation reference: $AUTH_REF"
      ACTIVE_OK=1
    else
      warn "Allowlist failed validation; active checks skipped."
    fi
    return 0
  fi

  if [[ ! -t 0 || ! -r /dev/tty ]]; then
    warn "No interactive terminal and no --allowlist/--auth-ref: active checks skipped (safe default)."
    return 0
  fi

  engine stage-allowlist --run-dir . --out "$ALLOW" >/dev/null
  printf '\n============================================================\n'
  printf ' HOSTNAME SCOPE REVIEW REQUIRED\n'
  printf ' %s\n' "$OUTDIR/$ALLOW"
  printf ' Hosts in this file are NOT automatically authorised.\n'
  printf ' Remove everything not covered by written authorisation\n'
  printf ' (third-party SaaS, CDN, shared hosting, vendor-managed).\n'
  printf '============================================================\n\n'
  read -r -p "Open the review file now? [Y/n/skip]: " ans </dev/tty || ans=skip
  case "${ans,,}" in
    skip|s|n|no) log "Operator skipped active checks."; return 0 ;;
  esac
  open_editor "$ALLOW" || { log "Operator skipped active checks."; return 0; }

  if ! engine validate-allowlist --roots roots.txt --allowlist "$ALLOW"; then
    warn "Allowlist failed validation; active checks skipped."
    return 0
  fi
  printf '\nApproved targets (%s):\n' "$(lines "$ALLOW")"
  sed -n '1,40p' "$ALLOW"
  (( $(lines "$ALLOW") > 40 )) && printf '... (%s more)\n' $(( $(lines "$ALLOW") - 40 ))
  printf '\nActive checks: port scan (top %s, %s pps), service detection, HTTP/TLS probing,\n' "$TOP_PORTS" "$NAABU_RATE"
  printf 'nuclei (non-intrusive, %s req/s)%s.\n' "$NUCLEI_RATE" "$( ((ENABLE_CRAWL)) && echo ', crawling')"
  if [[ -z "$AUTH_REF" ]]; then
    read -r -p "Authorisation / ticket reference (required): " AUTH_REF </dev/tty || AUTH_REF=""
  fi
  [[ -n "${AUTH_REF// /}" ]] || { warn "No authorisation reference given; active checks skipped."; return 0; }
  read -r -p "Type AUTHORIZED to confirm every host above is covered by written authorisation: " c </dev/tty || c=""
  if [[ "$c" == "AUTHORIZED" ]]; then
    ACTIVE_OK=1
    log "Operator confirmed authorisation (ref: $AUTH_REF)."
  else
    log "Confirmation phrase not provided; active checks skipped."
  fi
}

port_scan() {
  : > ports/naabu.jsonl
  if have naabu; then
    log "naabu: top-ports=$TOP_PORTS rate=$NAABU_RATE (CDN IPs limited to 80/443)"
    tmo "$PORTSCAN_TIMEOUT" naabu -list scan/hosts.txt -top-ports "$TOP_PORTS" -rate "$NAABU_RATE" -c 25 -retries 1 \
      -ec -json -silent -o ports/naabu.jsonl >/dev/null 2>>logs/naabu.err || warn "naabu error/timeout (see logs/naabu.err)."
  elif have nmap; then
    local pspec=(--top-ports "$TOP_PORTS")
    [[ "$TOP_PORTS" == "full" ]] && pspec=(-p-)
    if [[ -s scan/ip-targets.txt ]]; then
      log "nmap TCP connect discovery on $(lines scan/ip-targets.txt) IPs (max-rate $NMAP_MAX_RATE)"
      tmo "$PORTSCAN_TIMEOUT" nmap -Pn -sT -n --open -T3 --max-rate "$NMAP_MAX_RATE" "${pspec[@]}" \
        -iL scan/ip-targets.txt -oX ports/nmap-discovery.xml >/dev/null 2>>logs/nmap.err || warn "nmap discovery error."
    fi
    if [[ -s scan/cdn-ips.txt ]]; then
      tmo 1800 nmap -Pn -sT -n --open -p 80,443 --max-rate "$NMAP_MAX_RATE" -iL scan/cdn-ips.txt \
        -oX ports/nmap-cdn.xml >/dev/null 2>>logs/nmap.err || true
    fi
  else
    warn "Neither naabu nor nmap installed; port scan skipped (httpx will still probe 80/443)."
  fi
}

service_detection() {
  ((ENABLE_SERVICE_DETECTION)) || return 0
  have nmap || { warn "nmap not installed; service/version detection skipped (CVE mapping will rely on HTTP data)."; return 0; }
  mkdir -p ports/services
  local ip ports n=0
  while IFS=$'\t' read -r ip ports; do
    [[ -n "$ip" && -n "$ports" ]] || continue
    n=$((n + 1))
    log "nmap -sV $ip ports $ports"
    tmo "$NMAP_HOST_TIMEOUT_SEC" nmap -Pn -sV -n --version-intensity "$NMAP_VERSION_INTENSITY" --max-rate "$NMAP_MAX_RATE" \
      --host-timeout "$((NMAP_HOST_TIMEOUT_SEC - 30))s" -p "$ports" "$ip" -oX "ports/services/${ip//:/_}.xml" \
      >/dev/null 2>>logs/nmap.err || warn "nmap -sV failed for $ip"
  done < <(engine extract ports-by-ip --run-dir .)
  log "Service detection completed for $n IP(s)."
}

http_probe() {
  : > http/httpx.jsonl
  local bin; bin="$(detect_httpx)"
  if [[ -z "$bin" ]]; then warn "ProjectDiscovery httpx not found; HTTP probing skipped."; return 0; fi
  engine extract http-targets --run-dir . --out http/targets.txt >/dev/null
  local extra=()
  "$bin" -h 2>&1 | grep -q -- 'include-response-header' && extra+=(-irh) || warn "httpx lacks -irh; header checks limited (update httpx)."
  log "$bin on $(lines http/targets.txt) targets (rate $HTTPX_RATE/s, threads $HTTPX_THREADS)"
  tmo "$HTTP_TIMEOUT" "$bin" -l http/targets.txt -nf -sc -title -td -server -ip -cname -cdn -location -ct -cl -favicon \
    -rl "$HTTPX_RATE" -t "$HTTPX_THREADS" -timeout 10 -retries 1 -j -silent -nc "${extra[@]}" -o http/httpx.jsonl \
    >/dev/null 2>>logs/httpx.err || warn "httpx error/timeout (see logs/httpx.err)."
  engine extract live-urls --run-dir . --out http/live-urls.txt >/dev/null
  log "Live web endpoints: $(lines http/live-urls.txt)"
}

# Low-rate web asset inventory of the approved hostnames (status, title, tech, IP, CNAME,
# redirect). Raw CSV stays in authorized/; the report step copies it to findings/.
web_inventory() {
  rm -f authorized/web-assets.csv
  ((ENABLE_WEB_INVENTORY)) || return 0
  local bin; bin="$(detect_httpx)"
  if [[ -z "$bin" ]]; then warn "ProjectDiscovery httpx not found; web asset inventory skipped."; return 0; fi
  log "$bin web asset inventory on $(lines "$ALLOW") approved hosts (rate $WEB_INVENTORY_RATE/s, threads $WEB_INVENTORY_THREADS)"
  tmo "$HTTP_TIMEOUT" "$bin" -l "$ALLOW" \
    -sc -title -td -ip -cname -location \
    -rl "$WEB_INVENTORY_RATE" -t "$WEB_INVENTORY_THREADS" -timeout 10 \
    -csv -o authorized/web-assets.csv -silent -nc >/dev/null 2>>logs/httpx-inventory.err \
    || warn "httpx inventory error/timeout (see logs/httpx-inventory.err)."
  local n; n="$(lines authorized/web-assets.csv)"
  log "Web asset inventory: $(( n > 0 ? n - 1 : 0 )) live endpoint(s) -> authorized/web-assets.csv"
}

tls_checks() {
  ((ENABLE_TLS)) || return 0
  engine tls --run-dir . --workers "$TLS_WORKERS" || warn "TLS checks failed."
}

crawl() {
  : > crawl/katana.txt
  ((ENABLE_CRAWL)) || return 0
  have katana || { warn "katana not installed; crawling skipped."; return 0; }
  [[ -s http/live-urls.txt ]] || return 0
  log "katana crawl depth=$KATANA_DEPTH rate=$KATANA_RATE/s (scope: same FQDN)"
  tmo "$CRAWL_TIMEOUT" katana -list http/live-urls.txt -d "$KATANA_DEPTH" -jc -kf robotstxt,sitemapxml -fs fqdn \
    -rl "$KATANA_RATE" -c 5 -p 2 -timeout 10 -silent -nc -o crawl/katana.txt >/dev/null 2>>logs/katana.err \
    || warn "katana error/timeout."
  log "Crawled URLs: $(lines crawl/katana.txt)"
}

vuln_scan() {
  : > vuln/nuclei.jsonl
  ((ENABLE_NUCLEI)) || return 0
  have nuclei || { warn "nuclei not installed; template-based vulnerability checks skipped."; return 0; }
  local common=(-rl "$NUCLEI_RATE" -c "$NUCLEI_CONCURRENCY" -bs "$NUCLEI_BULK" -timeout 10 -retries 1
                -severity "$NUCLEI_SEVERITY" -etags "$NUCLEI_EXCLUDE_TAGS" -ni -duc -nc -silent -stats -si 120)
  [[ -n "${NUCLEI_TEMPLATES:-}" ]] && common+=(-t "$NUCLEI_TEMPLATES")
  if [[ -s http/live-urls.txt ]]; then
    log "nuclei (web) on $(lines http/live-urls.txt) URLs | severity=$NUCLEI_SEVERITY | excluded tags=$NUCLEI_EXCLUDE_TAGS"
    tmo "$NUCLEI_TIMEOUT" nuclei -l http/live-urls.txt -pt http,ssl "${common[@]}" -j -o vuln/nuclei-web.jsonl \
      2>>logs/nuclei.err || warn "nuclei (web) error/timeout (see logs/nuclei.err)."
  fi
  engine extract service-targets --run-dir . --out vuln/service-targets.txt >/dev/null
  if [[ -s vuln/service-targets.txt ]]; then
    log "nuclei (network services) on $(lines vuln/service-targets.txt) host:port targets"
    tmo "$NUCLEI_TIMEOUT" nuclei -l vuln/service-targets.txt -pt tcp,ssl,javascript "${common[@]}" -j -o vuln/nuclei-net.jsonl \
      2>>logs/nuclei.err || warn "nuclei (network) error/timeout."
  fi
  cat vuln/nuclei-web.jsonl vuln/nuclei-net.jsonl > vuln/nuclei.jsonl 2>/dev/null || true
  log "nuclei results: $(lines vuln/nuclei.jsonl)"
}

active_checks() {
  phase "Authorisation gate"
  authorization_gate
  ((ACTIVE_OK)) || return 0
  meta AUTH_REF "$AUTH_REF"
  meta ACTIVE_STARTED "$(ts)"
  touch report/.active_ran

  phase "Active: target preparation & DNS zone-transfer test"
  engine targets --run-dir . --allowlist "$ALLOW" || warn "target preparation failed"
  ((ENABLE_AXFR)) && engine axfr --root-dns dns/root-dns.json --allowlist "$ALLOW"

  phase "Active: port discovery"
  port_scan
  phase "Active: service & version detection"
  service_detection
  phase "Active: HTTP probing & technology fingerprinting"
  http_probe
  phase "Active: web asset inventory (httpx CSV)"
  web_inventory
  phase "Active: TLS posture"
  tls_checks
  phase "Active: crawling (optional)"
  crawl
  phase "Active: nuclei vulnerability templates (non-intrusive)"
  vuln_scan
  meta ACTIVE_FINISHED "$(ts)"
}
