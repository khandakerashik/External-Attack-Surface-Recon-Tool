"""Small glue commands used by the shell orchestrator."""
import concurrent.futures as cf
import json
import re
from urllib.parse import urlparse

from .analyze import load_naabu, load_nmap
from .dnsinfo import dig
from .util import log, read_json, read_jsonl, read_lines, write_lines

WEB_PORTS = {80, 443}


def _open_ports_by_ip(run_dir):
    ports = {}
    for ip, ps in load_naabu(run_dir).items():
        if not ip.startswith("host:"):
            ports.setdefault(ip, set()).update(ps)
    for ip, svcs in load_nmap(run_dir).items():
        ports.setdefault(ip, set()).update(svcs.keys())
    return ports


def ports_by_ip(run_dir):
    """Print 'ip<TAB>p1,p2' for non-CDN IPs (input for nmap -sV)."""
    cdn = set(read_lines(f"{run_dir}/scan/cdn-ips.txt"))
    for ip, ps in sorted(_open_ports_by_ip(run_dir).items()):
        if ip in cdn or not ps:
            continue
        print(f"{ip}\t{','.join(str(p) for p in sorted(ps))}")
    return 0


def http_targets(run_dir, out):
    """Allowlisted hosts plus host:port for every non-standard open port."""
    hosts = read_lines(f"{run_dir}/scan/hosts.txt")
    ip_map = read_json(f"{run_dir}/scan/ip-map.json", {}) or {}
    targets = set(hosts)
    by_ip = _open_ports_by_ip(run_dir)
    for row in read_jsonl(f"{run_dir}/ports/naabu.jsonl"):
        h, p = row.get("host"), row.get("port")
        if isinstance(p, dict):
            p = p.get("Port") or p.get("port")
        if h and p and int(p) not in WEB_PORTS and not re.match(r"^[\d.:]+$", h):
            targets.add(f"{h}:{p}")
    for ip, ps in by_ip.items():
        for h in ip_map.get(ip, []):
            for p in ps:
                if p not in WEB_PORTS:
                    targets.add(f"{h}:{p}")
    write_lines(out, sorted(targets))
    print(len(targets))
    return 0


def live_urls(run_dir, out):
    urls = sorted({r["url"] for r in read_jsonl(f"{run_dir}/http/httpx.jsonl") if r.get("url") and not r.get("failed")})
    write_lines(out, urls)
    print(len(urls))
    return 0


def service_targets(run_dir, out):
    """host:port for open non-web services (nuclei network/ssl/javascript templates)."""
    ip_map = read_json(f"{run_dir}/scan/ip-map.json", {}) or {}
    web = set()
    for r in read_jsonl(f"{run_dir}/http/httpx.jsonl"):
        u = urlparse(r.get("url", ""))
        if u.hostname:
            web.add((u.hostname, u.port or (443 if u.scheme == "https" else 80)))
    out_set = set()
    for ip, ps in _open_ports_by_ip(run_dir).items():
        for h in ip_map.get(ip, [ip]):
            for p in ps:
                if (h, p) not in web:
                    out_set.add(f"{h}:{p}")
    write_lines(out, sorted(out_set))
    print(len(out_set))
    return 0


def resolve_fallback(run_dir, candidates, out):
    """dnsx replacement using dig: writes dnsx-compatible JSONL."""
    hosts = read_lines(candidates)
    log(f"Resolving {len(hosts)} candidates with dig (dnsx not installed)")

    def one(h):
        cn = [c.rstrip(".") for c in dig(h, "CNAME")]
        a = [x for x in dig(h, "A") if re.match(r"^\d+\.\d+\.\d+\.\d+$", x)]
        aaaa = [x for x in dig(h, "AAAA") if ":" in x and not x.endswith(".")]
        return {"host": h, "a": a, "aaaa": aaaa, "cname": cn}
    with cf.ThreadPoolExecutor(max_workers=10) as ex, open(out, "w", encoding="utf-8") as fh:
        for row in ex.map(one, hosts):
            if row["a"] or row["aaaa"] or row["cname"]:
                fh.write(json.dumps(row) + "\n")
    return 0
