#!/usr/bin/env bash
# Scope filtering, resolution, DNS/e-mail posture and passive enrichment.

build_candidates() {
  local n
  n="$(engine scope-filter --roots roots.txt --out candidates.txt passive/*.txt)"
  log "Candidate inventory (in-scope, deduplicated): $n hostnames"
}

resolve_candidates() {
  : > dns/dnsx.jsonl
  if have dnsx; then
    local rargs=()
    [[ -n "$RESOLVERS_FILE" ]] && rargs=(-r "$RESOLVERS_FILE")
    log "dnsx: A/AAAA/CNAME for $(lines candidates.txt) names (rate $DNSX_RATE/s)"
    tmo "$PASSIVE_TOOL_TIMEOUT" dnsx -l candidates.txt -a -aaaa -cname -json -silent -rl "$DNSX_RATE" "${rargs[@]}" \
      -o dns/dnsx.jsonl >/dev/null 2>>logs/dnsx.err || warn "dnsx error (see logs/dnsx.err)."
  elif have dig; then
    engine resolve --run-dir . --candidates candidates.txt --out dns/dnsx.jsonl
  else
    warn "Neither dnsx nor dig available; resolution skipped."
  fi
  log "Resolving hostnames: $(lines dns/dnsx.jsonl)"
}

resolution_and_enrichment() {
  phase "Scope filtering"
  build_candidates
  if ((ENABLE_PERMUTATIONS)) || [[ -n "$DNS_WORDLIST" ]]; then
    phase "Optional DNS brute force / permutations"
    run_dns_bruteforce
    run_permutations
    build_candidates
  fi

  phase "DNS resolution"
  resolve_candidates

  phase "Root DNS & e-mail security posture"
  local rflag=()
  [[ -n "$DNS_RESOLVER" ]] && rflag=(--resolver "$DNS_RESOLVER")
  engine dns-posture --roots roots.txt --out dns/root-dns.json "${rflag[@]}" || warn "DNS posture collection failed."

  if have whois && ((ENABLE_WHOIS)); then
    while IFS= read -r d; do
      tmo 25 whois "$d" > "dns/whois_${d//./_}.txt" 2>&1 || true
      sleep 1
    done < roots.txt
  fi

  phase "Passive enrichment (ASN, CDN, Shodan InternetDB)"
  local eflags=()
  ((ENABLE_INTERNETDB)) || eflags+=(--no-internetdb)
  ((OFFLINE_INTEL)) && eflags+=(--offline)
  engine enrich --run-dir . --max-ips "$INTERNETDB_MAX_IPS" "${eflags[@]}" || warn "Enrichment failed; continuing."
}
