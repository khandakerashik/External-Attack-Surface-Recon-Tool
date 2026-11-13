"""Passive enrichment: resolution map, ASN/org (Team Cymru DNS), CDN tagging,
Shodan InternetDB (ports / CPEs / CVEs, no API key, no packets to target),
and active-stage target preparation."""
import concurrent.futures as cf
import re
import socket
import time

from .dnsinfo import dig
from .util import (cache_get, cache_put, http_get_json, is_ip, is_public_ip, log,
                   read_json, read_jsonl, read_lines, warn, write_json, write_lines)

CDN_ASN_RE = re.compile(
    r"CLOUDFLARE|AKAMAI|FASTLY|INCAPSULA|IMPERVA|SUCURI|STACKPATH|HIGHWINDS|EDGECAST|EDGIO|"
    r"LIMELIGHT|CDN77|CDNETWORKS|BUNNY|CACHEFLY|GCORE|ZENLAYER|QRATOR|DDOS-GUARD|ARVANCLOUD", re.I)
CDN_CNAME_RE = {
    "CloudFront": r"\.cloudfront\.net$", "Akamai": r"\.(akamaiedge|akamai|edgekey|edgesuite|akamaized)\.net$",
    "Fastly": r"\.fastly(lb)?\.net$", "Cloudflare": r"\.cdn\.cloudflare\.net$",
    "Azure Front Door/CDN": r"\.(azureedge|azurefd)\.net$", "Imperva": r"\.incapdns\.net$",
    "Sucuri": r"\.sucuri\.net$", "StackPath": r"\.stackpathdns\.com$", "Google": r"\.googlehosted\.com$",
}


# ----------------------------------------------------------------------------- ASN

def cymru_asn(ip):
    cached = cache_get("asn", ip, 7 * 86400)
    if cached is not None:
        return cached
    res = {}
    try:
        if ":" in ip:
            import ipaddress
            nibbles = ipaddress.ip_address(ip).exploded.replace(":", "")[::-1]
            q = ".".join(nibbles) + ".origin6.asn.cymru.com"
        else:
            q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        ans = dig(q, "TXT")
        if ans:
            parts = [p.strip() for p in ans[0].strip('"').split("|")]
            asn = parts[0].split()[0] if parts and parts[0] else ""
            res = {"asn": asn, "prefix": parts[1] if len(parts) > 1 else "",
                   "cc": parts[2] if len(parts) > 2 else "", "registry": parts[3] if len(parts) > 3 else ""}
            if asn:
                name = dig(f"AS{asn}.asn.cymru.com", "TXT")
                if name:
                    np = [p.strip() for p in name[0].strip('"').split("|")]
                    res["as_name"] = np[-1] if np else ""
    except Exception as exc:  # pragma: no cover
        warn(f"ASN lookup failed for {ip}: {exc}")
    cache_put("asn", ip, res)
    return res


# ------------------------------------------------------------------------ InternetDB

def internetdb(ip, offline=False):
    obj, _ = http_get_json(f"https://internetdb.shodan.io/{ip}", "internetdb", key=ip,
                           ttl=86400, offline=offline, retries=1, timeout=15)
    if not obj or obj.get("_not_found") or obj.get("detail"):
        return None
    return {k: obj.get(k, []) for k in ("ports", "cpes", "hostnames", "tags", "vulns")}


# ---------------------------------------------------------------------------- main

def _cdn_for(cnames, asn_name):
    for name, pat in CDN_CNAME_RE.items():
        if any(re.search(pat, c) for c in cnames):
            return name
    if asn_name and CDN_ASN_RE.search(asn_name):
        return asn_name.split(",")[0].split(" - ")[0].strip()
    return ""


def run(run_dir, use_internetdb=True, use_asn=True, offline=False, max_ips=750):
    dnsx = read_jsonl(f"{run_dir}/dns/dnsx.jsonl")
    hosts = {}
    for row in dnsx:
        h = (row.get("host") or "").lower().rstrip(".")
        if not h:
            continue
        e = hosts.setdefault(h, {"ips": [], "cnames": [], "status": row.get("status_code", "")})
        for ip in (row.get("a") or []) + (row.get("aaaa") or []):
            if ip not in e["ips"]:
                e["ips"].append(ip)
        for c in row.get("cname") or []:
            c = c.lower().rstrip(".")
            if c not in e["cnames"]:
                e["cnames"].append(c)

    all_ips = sorted({ip for e in hosts.values() for ip in e["ips"]})
    public_ips = [ip for ip in all_ips if is_public_ip(ip)]
    log(f"Enrichment: {len(hosts)} resolved hosts, {len(all_ips)} IPs ({len(public_ips)} public)")

    asn = {}
    if use_asn and public_ips:
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            for ip, res in zip(public_ips, ex.map(cymru_asn, public_ips)):
                asn[ip] = res

    idb = {}
    if use_internetdb and public_ips:
        # Skip CDN/edge IPs: their banners/CVEs belong to the CDN provider, not the target.
        non_cdn = [ip for ip in public_ips if not CDN_ASN_RE.search(asn.get(ip, {}).get("as_name", "") or "")]
        targets = non_cdn[:max_ips]
        if len(non_cdn) < len(public_ips):
            log(f"InternetDB: skipping {len(public_ips) - len(non_cdn)} CDN/edge IPs")
        if len(non_cdn) > max_ips:
            warn(f"InternetDB: limiting lookups to first {max_ips} IPs")
        log(f"Shodan InternetDB lookups for {len(targets)} IPs (passive, cached 24h)")
        for i, ip in enumerate(targets, 1):
            cached = cache_get("internetdb", ip, 86400)
            res = internetdb(ip, offline=offline)
            if res:
                idb[ip] = res
            if cached is None and not offline:
                time.sleep(0.35)
            if i % 50 == 0:
                log(f"  InternetDB {i}/{len(targets)}")

    for h, e in hosts.items():
        e["private_ips"] = [ip for ip in e["ips"] if is_ip(ip) and not is_public_ip(ip)]
        names = [asn.get(ip, {}).get("as_name", "") for ip in e["ips"]]
        e["asn"] = sorted({f"AS{asn[ip]['asn']} {asn[ip].get('as_name', '')}".strip()
                           for ip in e["ips"] if asn.get(ip, {}).get("asn")})
        e["cdn"] = _cdn_for(e["cnames"], " ".join(names))

    write_json(f"{run_dir}/enrich/hosts.json", hosts)
    write_json(f"{run_dir}/enrich/asn.json", asn)
    write_json(f"{run_dir}/enrich/internetdb.json", idb)
    return 0


def prepare_targets(run_dir, allowlist):
    """Resolve allowlisted hosts; write scan target files used by the active stage."""
    hosts_info = read_json(f"{run_dir}/enrich/hosts.json", {}) or {}
    asn = read_json(f"{run_dir}/enrich/asn.json", {}) or {}
    allow = read_lines(allowlist)
    ip_map, cdn_ips = {}, set()
    for h in allow:
        info = hosts_info.get(h)
        ips = list(info["ips"]) if info else []
        if not ips:
            try:
                ips = sorted({ai[4][0] for ai in socket.getaddrinfo(h, None)})
            except OSError:
                ips = []
        for ip in ips:
            if not is_public_ip(ip):
                continue
            ip_map.setdefault(ip, set()).add(h)
            if (info and info.get("cdn")) or CDN_ASN_RE.search(asn.get(ip, {}).get("as_name", "") or ""):
                cdn_ips.add(ip)
    write_lines(f"{run_dir}/scan/hosts.txt", allow)
    write_lines(f"{run_dir}/scan/ip-targets.txt", sorted(ip for ip in ip_map if ip not in cdn_ips))
    write_lines(f"{run_dir}/scan/cdn-ips.txt", sorted(cdn_ips))
    write_json(f"{run_dir}/scan/ip-map.json", {ip: sorted(hs) for ip, hs in ip_map.items()})
    print(f"{len(allow)} hosts, {len(ip_map)} public IPs ({len(cdn_ips)} CDN/edge IPs excluded from full port scans)")
    return 0
