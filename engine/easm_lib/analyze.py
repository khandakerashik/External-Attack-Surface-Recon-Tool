"""Correlate every collected artefact into assets, findings and CVE intelligence."""
import concurrent.futures as cf
import glob
import os
import re
import socket
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from . import cvemap
from .util import (SEV_ORDER, cvss_to_sev, data_file, log, max_sev, read_json,
                   read_jsonl, read_lines, root_of, short_hash, write_json)

SEV_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}
OS_HINT_RE = re.compile(r"\b(ubuntu|debian|centos|red ?hat|rhel|rocky|almalinux|amazon linux|suse|fedora)\b", re.I)
PANEL_RE = re.compile(r"(phpmyadmin|jenkins|grafana|kibana|gitlab|sonarqube|rabbitmq|portainer|webmin|cpanel|plesk|"
                      r"wp-admin|wordpress.*log ?in|admin(istrator)? (panel|console|login)|sign ?in|log ?in|outlook web|"
                      r"citrix|fortinet|fortigate|globalprotect|pulse secure|ivanti|f5 big-ip|vpn|router|"
                      r"tomcat.*manager|weblogic|swagger ui|api docs|graphql playground)", re.I)


class Findings:
    def __init__(self):
        self.items = {}

    def add(self, rule, title, severity, category, asset, description, remediation, evidence="",
            confidence="firm", source="", references=None, cves=None, group=False, extra=None):
        key = (rule, "" if group else asset)
        fid = "EASM-" + short_hash(rule, "" if group else asset, n=8).upper()
        f = self.items.get(key)
        if f is None:
            f = {"id": fid, "rule": rule, "title": title, "severity": severity, "category": category,
                 "assets": [], "description": description, "remediation": remediation, "evidence": [],
                 "confidence": confidence, "source": source, "references": references or [],
                 "cves": cves or [], "kev": False, "epss": None, "cvss": None}
            if extra:
                f.update(extra)
            self.items[key] = f
        if asset and asset not in f["assets"]:
            f["assets"].append(asset)
        if evidence:
            ev = evidence if not group else f"{asset}: {evidence}"
            if ev not in f["evidence"] and len(f["evidence"]) < 200:
                f["evidence"].append(ev)
        f["severity"] = max_sev(f["severity"], severity)
        return f

    def finalise(self):
        out = []
        for f in self.items.values():
            if len(f["assets"]) > 1:
                f["title"] = f["title"].replace("{n}", str(len(f["assets"])))
            else:
                f["title"] = re.sub(r" \(\{n\} \w+\)", "", f["title"]).replace("{n}", str(len(f["assets"])))
            out.append(f)
        out.sort(key=lambda f: (-int(f.get("kev", False)), -SEV_ORDER.get(f["severity"], 0),
                                -(f.get("cvss") or 0), f["title"]))
        return out


# =============================================================================== loaders

def _host_from(value):
    if not value:
        return ""
    if "://" in value:
        return (urlparse(value).hostname or "").lower()
    return value.split("/", 1)[0].rsplit(":", 1)[0].lower() if value.count(":") == 1 else value.lower()


def _norm_headers(h):
    out = {}
    for k, v in (h or {}).items():
        key = k.lower().replace("_", "-")
        out[key] = ", ".join(map(str, v)) if isinstance(v, list) else str(v)
    return out


def load_nmap(run_dir):
    """Return {ip: {port: service_dict}} from all nmap XML files in the run."""
    services = {}
    files = glob.glob(f"{run_dir}/ports/services/*.xml") + glob.glob(f"{run_dir}/ports/nmap-*.xml")
    for path in files:
        try:
            root = ET.parse(path).getroot()
        except (ET.ParseError, OSError):
            continue
        for host in root.findall("host"):
            addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
            if not addr:
                continue
            for p in host.findall("./ports/port"):
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc = p.find("service")
                port = int(p.get("portid"))
                d = services.setdefault(addr, {}).get(port, {})
                d.update({"port": port, "proto": p.get("protocol", "tcp"), "source": "nmap"})
                if svc is not None:
                    for k in ("name", "product", "version", "extrainfo", "ostype", "tunnel"):
                        if svc.get(k):
                            d[k] = svc.get(k)
                    cpes = [c.text for c in svc.findall("cpe") if c.text]
                    if cpes:
                        d["cpe"] = cpes
                services[addr][port] = d
    return services


def load_naabu(run_dir):
    ports = {}
    for row in read_jsonl(f"{run_dir}/ports/naabu.jsonl"):
        ip = row.get("ip") or row.get("host")
        port = row.get("port")
        if isinstance(port, dict):
            port = port.get("Port") or port.get("port")
        if ip and port:
            ports.setdefault(ip, set()).add(int(port))
            if row.get("host") and row.get("host") != ip:
                ports.setdefault(f"host:{row['host'].lower()}", set()).add(int(port))
    return ports


# ============================================================================== assets

def build_assets(run_dir, roots):
    hosts_enrich = read_json(f"{run_dir}/enrich/hosts.json", {}) or {}
    idb = read_json(f"{run_dir}/enrich/internetdb.json", {}) or {}
    allow = set(read_lines(f"{run_dir}/authorized/authorized_hosts.txt")) if os.path.exists(f"{run_dir}/report/.active_ran") else set()
    assets = {}

    def get(h):
        return assets.setdefault(h, {
            "host": h, "root": root_of(h, roots), "sources": [], "resolved": False, "ips": [], "cnames": [],
            "asn": [], "cdn": "", "private_ips": [], "ports": {}, "web": [], "tech": [], "tls": [],
            "internetdb": {}, "in_active_scope": h in allow, "risk": 0, "finding_count": 0})

    # discovery sources
    for path in sorted(glob.glob(f"{run_dir}/passive/*.txt")):
        src = os.path.basename(path)[:-4]
        if src in ("all-candidates-raw",):
            continue
        for line in read_lines(path):
            h = line.lower().removeprefix("*.").rstrip(".")
            if "://" in h:
                h = _host_from(h)
            if any(h == r or h.endswith("." + r) for r in roots):
                a = get(h)
                if src not in a["sources"]:
                    a["sources"].append(src)
    for h in read_lines(f"{run_dir}/candidates.txt"):
        get(h)
    for r in roots:
        a = get(r)
        if "input" not in a["sources"]:
            a["sources"].append("input")

    for h, e in hosts_enrich.items():
        a = get(h)
        a["resolved"] = bool(e.get("ips") or e.get("cnames"))
        a["ips"], a["cnames"] = e.get("ips", []), e.get("cnames", [])
        a["asn"], a["cdn"], a["private_ips"] = e.get("asn", []), e.get("cdn", ""), e.get("private_ips", [])

    ip_hosts = {}
    for h, a in assets.items():
        for ip in a["ips"]:
            ip_hosts.setdefault(ip, set()).add(h)
    ip_map = read_json(f"{run_dir}/scan/ip-map.json", {}) or {}
    for ip, hs in ip_map.items():
        for h in hs:
            ip_hosts.setdefault(ip, set()).add(h)
            a = get(h)
            if ip not in a["ips"]:
                a["ips"].append(ip)

    # InternetDB (passive)
    for ip, d in idb.items():
        for h in ip_hosts.get(ip, ()):
            assets[h]["internetdb"][ip] = d
            for port in d.get("ports", []):
                assets[h]["ports"].setdefault(str(port), {"port": port, "proto": "tcp", "source": "shodan-internetdb", "ip": ip})

    # Active port data (naabu + nmap)
    naabu = load_naabu(run_dir)
    nmap = load_nmap(run_dir)
    for ip, ports in naabu.items():
        targets = {ip[5:]} if ip.startswith("host:") else ip_hosts.get(ip, set())
        for h in targets:
            if h not in assets:
                continue
            for port in ports:
                p = assets[h]["ports"].setdefault(str(port), {"port": port, "proto": "tcp"})
                p["source"] = "naabu"
                p["ip"] = ip if not ip.startswith("host:") else p.get("ip", "")
    for ip, svcs in nmap.items():
        for h in ip_hosts.get(ip, set()):
            for port, svc in svcs.items():
                p = assets[h]["ports"].setdefault(str(port), {"port": port, "proto": "tcp"})
                p.update(svc)
                p["ip"] = ip

    # HTTP
    for row in read_jsonl(f"{run_dir}/http/httpx.jsonl"):
        url = row.get("url", "")
        h = (urlparse(url).hostname or _host_from(row.get("input", ""))).lower()
        if not h:
            continue
        a = get(h)
        headers = _norm_headers(row.get("header") or row.get("headers") or {})
        web = {"url": url, "status": row.get("status_code") or row.get("status-code"), "title": (row.get("title") or "")[:200],
               "webserver": row.get("webserver", ""), "tech": row.get("tech", []) or [], "content_type": row.get("content_type", ""),
               "content_length": row.get("content_length"), "location": row.get("location", ""), "cdn": row.get("cdn_name", ""),
               "final_url": row.get("final_url", ""), "headers": headers, "favicon": row.get("favicon", ""),
               "screenshot": row.get("screenshot_path_rel") or row.get("screenshot_path") or ""}
        a["web"].append(web)
        for t in web["tech"]:
            if t not in a["tech"]:
                a["tech"].append(t)
        if row.get("cdn_name") and not a["cdn"]:
            a["cdn"] = row["cdn_name"]

    for t in read_json(f"{run_dir}/tls/tls.json", []) or []:
        get(t["host"])["tls"].append(t)
    return assets, ip_hosts


# ============================================================================ rules

def rules_email_dns(F, root_dns):
    for d, info in root_dns.items():
        mx = info.get("records", {}).get("MX", [])
        spf, dmarc = info.get("spf", []), info.get("dmarc", [])
        if not spf:
            sev = "medium"
            F.add("EMAIL-SPF-MISSING", "SPF record missing", sev, "Email security", d,
                  "No SPF (v=spf1) TXT record was found. Attackers can more easily spoof e-mail from this domain."
                  + ("" if mx else " The domain has no MX record; non-mail domains should still publish 'v=spf1 -all'."),
                  "Publish an SPF record listing authorised senders and ending in '-all' (or 'v=spf1 -all' for non-sending domains).",
                  source="dns", references=["https://www.rfc-editor.org/rfc/rfc7208"])
        elif len(spf) > 1:
            F.add("EMAIL-SPF-MULTIPLE", "Multiple SPF records (SPF permerror)", "medium", "Email security", d,
                  "More than one v=spf1 record exists; receivers treat this as a permanent error and SPF fails.",
                  "Merge all mechanisms into a single SPF record.", evidence=" | ".join(spf), source="dns")
        if spf:
            rec = spf[0].lower()
            allm = re.search(r"([+?~-]?)all\b", rec)
            if not allm and "redirect=" not in rec:
                F.add("EMAIL-SPF-NOALL", "SPF record has no 'all' mechanism", "medium", "Email security", d,
                      "Without a terminating 'all' mechanism the SPF policy defaults to neutral for unlisted senders.",
                      "End the SPF record with '-all' (fail) or '~all' combined with DMARC enforcement.", evidence=spf[0], source="dns")
            elif allm and allm.group(1) in ("", "+"):
                F.add("EMAIL-SPF-PASSALL", "SPF record allows any sender (+all)", "high", "Email security", d,
                      "'+all' authorises every host on the internet to send mail for this domain.",
                      "Replace '+all' with '-all'.", evidence=spf[0], source="dns")
            elif allm and allm.group(1) == "?":
                F.add("EMAIL-SPF-NEUTRAL", "SPF record uses neutral '?all'", "medium", "Email security", d,
                      "'?all' provides no protection against spoofing.", "Use '-all' or '~all' with an enforced DMARC policy.",
                      evidence=spf[0], source="dns")
            lookups = len(re.findall(r"\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", rec))
            if lookups > 10:
                F.add("EMAIL-SPF-LOOKUPS", "SPF record exceeds 10 DNS lookups", "medium", "Email security", d,
                      f"The top-level record already contains {lookups} lookup mechanisms; SPF evaluation will permerror.",
                      "Flatten or consolidate includes so total lookups stay at or below 10.", evidence=spf[0], source="dns")
        if not dmarc:
            F.add("EMAIL-DMARC-MISSING", "DMARC record missing", "medium", "Email security", d,
                  "No _dmarc TXT record exists, so receivers have no policy for handling spoofed mail and you receive no reports.",
                  "Publish 'v=DMARC1; p=none; rua=mailto:...' to start monitoring, then move to p=quarantine/reject.",
                  source="dns", references=["https://www.rfc-editor.org/rfc/rfc7489"])
        else:
            rec = dmarc[0]
            tags = dict(t.strip().split("=", 1) for t in rec.split(";") if "=" in t)
            tags = {k.strip().lower(): v.strip() for k, v in tags.items()}
            p = tags.get("p", "").lower()
            if p == "none":
                F.add("EMAIL-DMARC-NONE", "DMARC policy is monitoring-only (p=none)", "medium", "Email security", d,
                      "p=none does not instruct receivers to quarantine or reject spoofed messages.",
                      "After reviewing aggregate reports, move to p=quarantine and then p=reject.", evidence=rec, source="dns")
            if tags.get("pct") and tags["pct"] != "100" and p in ("quarantine", "reject"):
                F.add("EMAIL-DMARC-PCT", "DMARC policy applied to a subset of mail (pct<100)", "low", "Email security", d,
                      "Only part of failing mail is subject to the DMARC policy.", "Set pct=100 once rollout is complete.",
                      evidence=rec, source="dns")
            if tags.get("sp", "").lower() == "none" and p in ("quarantine", "reject"):
                F.add("EMAIL-DMARC-SP-NONE", "DMARC subdomain policy is none (sp=none)", "low", "Email security", d,
                      "Subdomains can be spoofed even though the organisational domain is protected.",
                      "Set sp=quarantine or sp=reject.", evidence=rec, source="dns")
            if "rua" not in tags:
                F.add("EMAIL-DMARC-NORUA", "DMARC aggregate reporting not configured", "info", "Email security", d,
                      "Without rua= you get no visibility into who is sending mail as this domain.",
                      "Add rua=mailto:<collector> to the DMARC record.", evidence=rec, source="dns")
        if mx and not info.get("dkim"):
            F.add("EMAIL-DKIM-UNKNOWN", "No DKIM key found at common selectors", "info", "Email security", d,
                  "No DKIM public key was found under common selector names. DKIM may still exist under a custom selector.",
                  "Confirm DKIM signing is enabled for all outbound mail streams.", source="dns", confidence="tentative")
        if mx and not info.get("mta_sts"):
            F.add("EMAIL-MTASTS-MISSING", "MTA-STS not deployed", "low", "Email security", d,
                  "Inbound SMTP TLS can be downgraded by an on-path attacker without MTA-STS.",
                  "Publish an _mta-sts TXT record and an mta-sts policy file; add TLS-RPT reporting.", source="dns",
                  references=["https://www.rfc-editor.org/rfc/rfc8461"])
        if not info.get("records", {}).get("DS"):
            F.add("DNS-DNSSEC-OFF", "DNSSEC not enabled", "low", "DNS", d,
                  "No DS record at the parent zone; DNS responses for this domain cannot be validated.",
                  "Sign the zone with DNSSEC and publish the DS record at the registrar.", source="dns")
        if not info.get("records", {}).get("CAA"):
            F.add("DNS-CAA-MISSING", "No CAA record", "info", "DNS", d,
                  "Any public CA may issue certificates for this domain.",
                  "Publish CAA records naming the CAs you use (and an iodef contact).", source="dns",
                  references=["https://www.rfc-editor.org/rfc/rfc8659"])
        wc = info.get("wildcard") or {}
        if wc.get("enabled"):
            F.add("DNS-WILDCARD", "Wildcard DNS record in place", "info", "DNS", d,
                  "Random subdomains resolve. This inflates discovery results and can aid phishing or takeover of unused names.",
                  "Remove the wildcard record unless it is required.", evidence=", ".join(wc.get("ips", [])), source="dns")
        for ns, r in (info.get("axfr") or {}).items():
            if r.get("allowed"):
                F.add("DNS-AXFR", "DNS zone transfer (AXFR) allowed", "high", "DNS", d,
                      f"Name server {ns} returned the full zone to an unauthenticated client, disclosing every record.",
                      "Restrict AXFR to secondary name servers by IP / TSIG.", evidence=f"{ns}: {r.get('record_count')} records",
                      confidence="confirmed", source="dig")


def rules_hosts(F, assets, active_ran, allow):
    fps = data_file("takeover-fingerprints.json").get("services", [])
    compiled = [(s, [re.compile(p, re.I) for p in s["cname"]]) for s in fps]
    candidates = []
    for h, a in assets.items():
        if a["private_ips"]:
            F.add("DNS-PRIVATE-IP", "Internal IP addresses published in public DNS ({n} assets)", "low", "DNS", h,
                  "Public DNS names resolve to RFC1918/internal addresses, disclosing internal network layout.",
                  "Move internal records to split-horizon / internal DNS.", evidence=", ".join(a["private_ips"]),
                  source="dnsx", group=True)
        for c in a["cnames"]:
            for svc, pats in compiled:
                if any(p.search(c) for p in pats):
                    candidates.append((h, c, svc))
                    break

    def resolves(name):
        try:
            socket.getaddrinfo(name, None)
            return True
        except socket.gaierror as exc:
            return exc.errno not in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5))
        except OSError:
            return True

    def fetch(h):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for scheme in ("https", "http"):
            try:
                req = urllib.request.Request(f"{scheme}://{h}/", headers={"User-Agent": "easm-recon/2.0"})
                with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                    return r.read(200000).decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                try:
                    return e.read(200000).decode("utf-8", "replace")
                except Exception:
                    return ""
            except Exception:
                continue
        return ""

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(lambda c: resolves(c[1]), candidates))
    for (h, c, svc), ok in zip(candidates, res):
        body_hit = ""
        if active_ran and h in allow and svc.get("http"):
            body = fetch(h)
            body_hit = next((fp for fp in svc["http"] if fp in body), "")
        if body_hit:
            F.add("TAKEOVER-CONFIRMED", f"Subdomain takeover fingerprint matched ({svc['service']})", "high", "Subdomain takeover", h,
                  f"{h} is a CNAME to {c} and the response contains the {svc['service']} 'unclaimed resource' fingerprint.",
                  "Remove the DNS record or re-claim the resource at the provider immediately.",
                  evidence=f"CNAME {c}; fingerprint: '{body_hit}'", confidence="firm", source="http",
                  references=["https://github.com/EdOverflow/can-i-take-over-xyz"])
        elif not ok:
            sev = "high" if svc.get("nxdomain") else "medium"
            F.add("TAKEOVER-DANGLING", f"Dangling CNAME to {svc['service']}", sev, "Subdomain takeover", h,
                  f"{h} points to {c}, which does not resolve. If the resource name can be registered by anyone, the subdomain can be taken over.",
                  "Delete the stale CNAME or re-create the target resource under your account.",
                  evidence=f"CNAME {c} -> NXDOMAIN", confidence="potential", source="dns",
                  references=["https://github.com/EdOverflow/can-i-take-over-xyz"])


def rules_ports(F, assets):
    risky = data_file("risky-ports.json").get("ports", {})
    for h, a in assets.items():
        for key, p in a["ports"].items():
            r = risky.get(str(p["port"]))
            if not r:
                continue
            passive = p.get("source") == "shodan-internetdb"
            label = f"{p['port']}/{p.get('proto', 'tcp')}"
            svc = " ".join(x for x in (p.get("product"), p.get("version")) if x)
            F.add(f"PORT-{p['port']}", f"Exposed {r['service']} service ({label})", r["severity"], "Network exposure", h,
                  r["reason"] + (" Observed by Shodan InternetDB (passive, may be stale)." if passive else ""),
                  "Restrict the service to VPN / allow-listed management networks or disable it.",
                  evidence=f"{p.get('ip', '')}:{p['port']} {svc}".strip(),
                  confidence="potential" if passive else "confirmed",
                  source="shodan-internetdb" if passive else p.get("source", "scan"))


def rules_http(F, assets):
    for h, a in assets.items():
        for w in a["web"]:
            url, hd, st = w["url"], w["headers"], w.get("status") or 0
            is_https = url.startswith("https://")
            html = "html" in (w.get("content_type") or hd.get("content-type", "")).lower()
            if not hd:
                continue
            if url.startswith("http://") and not (300 <= int(st) < 400 and str(w.get("location", "")).startswith("https://")):
                if 200 <= int(st) < 300:
                    F.add("WEB-NO-HTTPS-REDIRECT", "HTTP content served without redirect to HTTPS ({n} endpoints)", "medium",
                          "Web security", h, "Content is reachable over cleartext HTTP, exposing users to interception and session theft.",
                          "Redirect all HTTP requests to HTTPS (301) and enable HSTS.", evidence=f"{url} -> {st}", source="httpx", group=True)
            if is_https and 200 <= int(st) < 400 and "strict-transport-security" not in hd:
                F.add("WEB-HSTS-MISSING", "HSTS header missing ({n} endpoints)", "low", "Web security", h,
                      "Without Strict-Transport-Security browsers may be downgraded to HTTP (SSL stripping).",
                      "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", evidence=url, source="httpx", group=True)
            if html and 200 <= int(st) < 300:
                if "content-security-policy" not in hd:
                    F.add("WEB-CSP-MISSING", "Content-Security-Policy missing ({n} endpoints)", "low", "Web security", h,
                          "No CSP header; XSS impact is not mitigated by the browser.", "Define a restrictive Content-Security-Policy.",
                          evidence=url, source="httpx", group=True)
                csp = hd.get("content-security-policy", "")
                if "x-frame-options" not in hd and "frame-ancestors" not in csp:
                    F.add("WEB-CLICKJACK", "Clickjacking protection missing ({n} endpoints)", "low", "Web security", h,
                          "Neither X-Frame-Options nor CSP frame-ancestors is set; pages can be framed by other sites.",
                          "Send 'X-Frame-Options: DENY' or CSP 'frame-ancestors 'none''.", evidence=url, source="httpx", group=True)
            if "x-content-type-options" not in hd and 200 <= int(st) < 300:
                F.add("WEB-XCTO-MISSING", "X-Content-Type-Options missing ({n} endpoints)", "info", "Web security", h,
                      "Browsers may MIME-sniff responses.", "Send 'X-Content-Type-Options: nosniff'.", evidence=url, source="httpx", group=True)
            server = hd.get("server", "") or w.get("webserver", "")
            if re.search(r"/\d", server):
                F.add("WEB-VERSION-DISCLOSURE", "Server version disclosed in HTTP headers ({n} endpoints)", "low", "Information disclosure", h,
                      "Precise version banners help attackers match public exploits.",
                      "Suppress version details (e.g. nginx server_tokens off; Apache ServerTokens Prod).",
                      evidence=f"{url} Server: {server}", source="httpx", group=True)
            xpb = hd.get("x-powered-by", "") or hd.get("x-aspnet-version", "")
            if xpb:
                F.add("WEB-POWEREDBY", "Technology stack disclosed via X-Powered-By ({n} endpoints)", "info", "Information disclosure", h,
                      "Framework/runtime banners reveal technology and versions.", "Remove X-Powered-By / X-AspNet-Version headers.",
                      evidence=f"{url} X-Powered-By: {xpb}", source="httpx", group=True)
            cookies = hd.get("set-cookie", "")
            if cookies:
                for ck in re.split(r",\s*(?=[^;,=\s]+=)", cookies):
                    name = ck.split("=", 1)[0].strip()
                    low = ck.lower()
                    missing = [f for f, ok in (("Secure", "secure" in low or not is_https), ("HttpOnly", "httponly" in low),
                                               ("SameSite", "samesite" in low)) if not ok]
                    if missing and name:
                        F.add("WEB-COOKIE-FLAGS", "Cookies missing security attributes ({n} endpoints)", "low", "Web security", h,
                              "Session cookies without Secure/HttpOnly/SameSite are easier to steal or abuse via XSS/CSRF.",
                              "Set Secure, HttpOnly and SameSite on all session cookies.",
                              evidence=f"{url} cookie '{name}' missing {', '.join(missing)}", source="httpx", group=True)
            acao = hd.get("access-control-allow-origin", "")
            if acao == "*" and hd.get("access-control-allow-credentials", "").lower() == "true":
                F.add("WEB-CORS", "Permissive CORS with credentials", "medium", "Web security", h,
                      "Wildcard origin combined with Allow-Credentials indicates a misconfigured CORS policy.",
                      "Restrict allowed origins to an explicit list.", evidence=url, source="httpx")
            title = w.get("title", "")
            if title and PANEL_RE.search(title):
                F.add("WEB-LOGIN-PANEL", "Login / administrative interface exposed ({n} endpoints)", "low", "Attack surface", h,
                      "Authentication or management interfaces are reachable from the internet and are prime targets for credential attacks.",
                      "Place admin interfaces behind VPN/SSO with MFA; restrict by source IP.",
                      evidence=f"{url} title: {title}", source="httpx", group=True, confidence="tentative")


def rules_tls(F, assets):
    for h, a in assets.items():
        for t in a["tls"]:
            ep = f"{t['host']}:{t['port']}"
            if t.get("error"):
                continue
            days = t.get("days_to_expiry")
            if days is not None and days < 0:
                F.add("TLS-EXPIRED", "Expired TLS certificate", "high", "TLS", h, "The certificate has expired; clients will show errors and users may be trained to click through warnings.",
                      "Renew the certificate and automate renewal.", evidence=f"{ep} notAfter={t.get('not_after')}", confidence="confirmed", source="tls")
            elif days is not None and days <= 30:
                F.add("TLS-EXPIRING", "TLS certificate expires within 30 days", "medium", "TLS", h, "Certificate expiry is imminent.",
                      "Renew the certificate; consider ACME automation.", evidence=f"{ep} expires in {days} days", confidence="confirmed", source="tls")
            if t.get("self_signed"):
                F.add("TLS-SELF-SIGNED", "Self-signed TLS certificate", "medium", "TLS", h, "Self-signed certificates cannot be validated by clients and enable MITM.",
                      "Use a certificate from a trusted CA.", evidence=f"{ep} CN={t.get('subject_cn')}", confidence="confirmed", source="tls")
            elif t.get("trusted") is False and t.get("hostname_match") is False:
                F.add("TLS-HOSTNAME-MISMATCH", "TLS certificate does not match hostname", "medium", "TLS", h, "The presented certificate is not valid for this hostname.",
                      "Install a certificate whose SAN includes this hostname.", evidence=f"{ep} {t.get('verify_error', '')}", confidence="confirmed", source="tls")
            elif t.get("trusted") is False:
                F.add("TLS-UNTRUSTED", "TLS certificate chain not trusted", "medium", "TLS", h, "The certificate chain could not be validated (missing intermediate or untrusted issuer).",
                      "Serve the full chain from a publicly trusted CA.", evidence=f"{ep} {t.get('verify_error', '')}", confidence="confirmed", source="tls")
            legacy = [p for p in ("TLSv1.0", "TLSv1.1") if (t.get("protocols") or {}).get(p) is True]
            if legacy:
                F.add("TLS-LEGACY-PROTO", "Deprecated TLS protocol versions enabled ({n} endpoints)", "medium", "TLS", h,
                      "TLS 1.0/1.1 are deprecated (RFC 8996) and fail PCI DSS requirements.", "Disable TLS 1.0 and 1.1; support TLS 1.2 and 1.3 only.",
                      evidence=f"{ep} accepts {', '.join(legacy)}", confidence="confirmed", source="tls", group=True)


def rules_nuclei(F, run_dir, roots):
    for r in read_jsonl(f"{run_dir}/vuln/nuclei.jsonl"):
        info = r.get("info", {}) or {}
        cls = info.get("classification", {}) or {}
        cves = [c.upper() for c in (cls.get("cve-id") or []) if c]
        sev = (info.get("severity") or "info").lower()
        if sev not in SEV_ORDER:
            sev = "info"
        host = _host_from(r.get("host") or r.get("matched-at") or "")
        refs = info.get("reference") or []
        refs = refs if isinstance(refs, list) else [refs]
        ev = r.get("matched-at", "")
        if r.get("extracted-results"):
            ev += " | " + ", ".join(map(str, r["extracted-results"][:5]))
        if r.get("matcher-name"):
            ev += f" [{r['matcher-name']}]"
        tags = info.get("tags") or []
        tags = tags if isinstance(tags, list) else str(tags).split(",")
        cat = "Vulnerability" if cves or "cve" in tags else ("Subdomain takeover" if "takeover" in tags else
              ("Exposure" if "exposure" in tags else ("Misconfiguration" if "misconfig" in tags else "Template finding")))
        f = F.add(f"NUCLEI-{r.get('template-id')}", info.get("name") or r.get("template-id"), sev, cat, host,
                  (info.get("description") or "").strip()[:1500] or "Detected by a nuclei template.",
                  (info.get("remediation") or "Validate the finding manually and apply the vendor fix or configuration change.").strip()[:1500],
                  evidence=ev[:500], confidence="firm", source=f"nuclei:{r.get('template-id')}", references=refs[:6], cves=cves)
        if cls.get("cvss-score"):
            try:
                f["cvss"] = max(f.get("cvss") or 0, float(cls["cvss-score"]))
            except (TypeError, ValueError):
                pass


def rules_urls(F, run_dir, roots):
    urls = read_lines(f"{run_dir}/urls/archived-urls.txt") + read_lines(f"{run_dir}/crawl/katana.txt")
    cats = {
        "sensitive_files": re.compile(r"\.(env|bak|backup|old|orig|sql|sqlite3?|db|mdb|tar|tgz|gz|zip|7z|rar|log|conf|cfg|ini|ya?ml|pem|key|p12|pfx|jks|swp|DS_Store|git/|svn/)(\?|$|/)", re.I),
        "admin_auth": re.compile(r"/(admin|administrator|wp-admin|wp-login|login|signin|sso|oauth|cpanel|phpmyadmin|manager/html|console|dashboard)(/|\?|$|\.)", re.I),
        "api_docs": re.compile(r"(swagger|openapi|api-docs|graphql|graphiql|/v[0-9]+/api|/api/|\.wsdl|\?wsdl)", re.I),
        "javascript": re.compile(r"\.(js|mjs|map)(\?|$)", re.I),
        "redirect_params": re.compile(r"[?&](url|uri|redirect|redirect_uri|next|return|returnurl|return_to|dest|destination|continue|goto)=", re.I),
        "file_params": re.compile(r"[?&](file|path|page|template|include|dir|folder|doc|document|filename)=", re.I),
        "secret_params": re.compile(r"[?&](api_?key|apikey|access_?token|auth_?token|token|secret|client_secret|password|passwd|pwd|session_?id|sig|signature|key)=[^&]{6,}", re.I),
    }
    buckets = {k: [] for k in cats}
    seen = set()
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        for k, rx in cats.items():
            if rx.search(u) and len(buckets[k]) < 500:
                buckets[k].append(u)
    out = {"total_urls": len(seen), "categories": {k: {"count": len(v), "samples": v[:100]} for k, v in buckets.items()}}
    write_json(f"{run_dir}/analysis/urls.json", out)
    if buckets["secret_params"]:
        hosts = sorted({_host_from(u) for u in buckets["secret_params"]})
        for h in hosts[:50]:
            F.add("URL-SECRET-PARAMS", "Credential-like parameters in archived/crawled URLs ({n} assets)", "medium", "Information disclosure", h,
                  "Historical URLs contain tokens, keys or passwords in query strings. These may still be valid and are publicly archived.",
                  "Rotate any exposed secrets, stop passing secrets in URLs, request removal from web archives.",
                  evidence=next(u for u in buckets["secret_params"] if _host_from(u) == h)[:300],
                  source="archive", group=True, confidence="potential")
    if buckets["sensitive_files"]:
        for u in buckets["sensitive_files"][:200]:
            F.add("URL-SENSITIVE-FILES", "References to sensitive file types in archived/crawled URLs ({n} assets)", "low", "Information disclosure",
                  _host_from(u), "Backups, configs, keys or archives were referenced historically. Verify they are no longer reachable.",
                  "Remove the files from web roots and block these extensions at the web server/WAF.",
                  evidence=u[:300], source="archive", group=True, confidence="potential")


def rules_internetdb_vulns(F, assets):
    per_ip = {}
    for h, a in assets.items():
        for ip, d in a["internetdb"].items():
            if d.get("vulns"):
                per_ip.setdefault(ip, {"hosts": set(), "vulns": d["vulns"]})["hosts"].add(h)
    return per_ip


# ======================================================================== components

def extract_components(assets, pmap):
    comps = {}

    def add(raw_name, raw_version, h, evidence, source, banner=""):
        entry = pmap.identify(raw_name)
        version = cvemap.clean_version(raw_version)
        if not entry or not version:
            return
        key = f"{entry['name']}|{version}"
        c = comps.setdefault(key, {"key": key, "name": entry["name"], "version": version, "entry": entry,
                                   "assets": set(), "evidence": [], "sources": set(), "backport": False})
        c["assets"].add(h)
        c["sources"].add(source)
        if len(c["evidence"]) < 20 and evidence not in c["evidence"]:
            c["evidence"].append(evidence)
        if OS_HINT_RE.search(banner or "") or OS_HINT_RE.search(raw_version or ""):
            c["backport"] = True

    for h, a in assets.items():
        os_hint = " ".join(a["tech"])
        for w in a["web"]:
            for t in w["tech"]:
                if ":" in t:
                    n, v = t.rsplit(":", 1)
                    add(n, v, h, f"{w['url']} tech={t}", "httpx-tech", os_hint)
            for hdr in ("server", "x-powered-by"):
                val = w["headers"].get(hdr, "") or (w.get("webserver", "") if hdr == "server" else "")
                for n, v in re.findall(r"([A-Za-z][\w\-. ]*?)/(\d[\w.\-]*)", val):
                    add(n.strip().replace("Microsoft-IIS", "Microsoft IIS"), v, h, f"{w['url']} {hdr}: {val}", "http-header", val)
        for p in a["ports"].values():
            if p.get("product") and p.get("version"):
                banner = " ".join(str(p.get(k, "")) for k in ("product", "version", "extrainfo", "ostype"))
                add(p["product"], p["version"], h, f"{p.get('ip', '')}:{p['port']} {banner.strip()}", "nmap", banner)
            for cpe in p.get("cpe", []) or []:
                parts = cpe.replace("cpe:/", "").split(":")
                if len(parts) >= 4:
                    add(f"{parts[1]}:{parts[2]}", parts[3], h, f"{p.get('ip', '')}:{p['port']} {cpe}", "nmap-cpe",
                        " ".join(str(p.get(k, "")) for k in ("version", "extrainfo", "ostype")))
        for ip, d in a["internetdb"].items():
            for cpe in d.get("cpes", []):
                parts = cpe.replace("cpe:2.3:", "").replace("cpe:/", "").split(":")
                if len(parts) >= 4:
                    add(f"{parts[1]}:{parts[2]}", parts[3], h, f"{ip} Shodan CPE {cpe}", "shodan-internetdb", " ".join(d.get("cpes", [])))
    return list(comps.values())


# ============================================================================== main

def run(run_dir, offline=False, no_cve=False, nvd_detail_limit=None, max_products=60):
    os.makedirs(f"{run_dir}/analysis", exist_ok=True)
    roots = read_lines(f"{run_dir}/roots.txt")
    active_ran = os.path.exists(f"{run_dir}/report/.active_ran")
    allow = set(read_lines(f"{run_dir}/authorized/authorized_hosts.txt")) if active_ran else set()
    assets, ip_hosts = build_assets(run_dir, roots)
    log(f"Correlated {len(assets)} assets")
    root_dns = read_json(f"{run_dir}/dns/root-dns.json", {}) or {}

    F = Findings()
    rules_email_dns(F, root_dns)
    rules_hosts(F, assets, active_ran, allow)
    rules_ports(F, assets)
    rules_http(F, assets)
    rules_tls(F, assets)
    rules_nuclei(F, run_dir, roots)
    rules_urls(F, run_dir, roots)

    # ----------------------------------------------------------- CVE intelligence
    cve_index = {}  # id -> record

    def cve_rec(cid):
        return cve_index.setdefault(cid, {"id": cid, "cvss": None, "severity": "", "vector": "", "description": "",
                                          "published": "", "cwe": [], "references": [], "sources": set(),
                                          "components": set(), "assets": set(), "kev": None, "epss": None,
                                          "percentile": None, "confidence": "potential"})

    pmap = cvemap.ProductMap()
    components = extract_components(assets, pmap)
    comp_matches = {}
    nvd = cvemap.NVD(offline=offline)
    if not no_cve and components:
        log(f"CVE mapping for {len(components)} versioned component(s)")
        comp_matches = cvemap.map_components(components, nvd, max_products=max_products)
    for c in components:
        for cv in comp_matches.get(c["key"], []):
            r = cve_rec(cv["id"])
            r.update({k: cv[k] for k in ("description", "published", "cwe", "references")})
            r["cvss"], r["severity"], r["vector"] = cv["cvss"]["score"], cv["cvss"]["severity"], cv["cvss"]["vector"]
            r["sources"].add("version-match")
            r["components"].add(f"{c['name']} {c['version']}")
            r["assets"].update(c["assets"])

    idb_vulns = rules_internetdb_vulns(F, assets)
    for ip, d in idb_vulns.items():
        for cid in d["vulns"]:
            r = cve_rec(cid.upper())
            r["sources"].add("shodan-internetdb")
            r["assets"].update(d["hosts"])
    for f in F.items.values():
        for cid in f.get("cves", []):
            r = cve_rec(cid)
            r["sources"].add("nuclei")
            r["assets"].update(f["assets"])
            r["confidence"] = "firm"

    kev, epss = {}, {}
    if not no_cve and cve_index:
        kev = cvemap.load_kev(offline=offline)
        epss = cvemap.load_epss(list(cve_index), offline=offline)
        for cid, r in cve_index.items():
            if cid in kev:
                r["kev"] = kev[cid]
            e = epss.get(cid) or {}
            r["epss"], r["percentile"] = e.get("epss"), e.get("percentile")
        # Fill CVSS for CVEs that came only from InternetDB / nuclei (rate-limited)
        limit = nvd_detail_limit if nvd_detail_limit is not None else (400 if nvd.api_key else 60)
        need = [r for r in cve_index.values() if r["cvss"] is None]
        need.sort(key=lambda r: (-int(bool(r["kev"])), -(r["epss"] or 0)))
        if need and not offline and not nvd.failed:
            log(f"NVD: fetching details for {min(len(need), limit)} of {len(need)} CVEs lacking CVSS")
        for r in need[:limit]:
            d = nvd.cve(r["id"])
            if d:
                r.update({k: d[k] for k in ("description", "published", "cwe", "references")})
                r["cvss"], r["severity"], r["vector"] = d["cvss"]["score"], d["cvss"]["severity"], d["cvss"]["vector"]

    for r in cve_index.values():
        r["severity"] = (r["severity"] or cvss_to_sev(r["cvss"]) or "unknown").lower()
        r["priority"] = cvemap.priority(r["cvss"], r["epss"], r["kev"])

    # findings for version-matched components
    for c in components:
        matches = comp_matches.get(c["key"], [])
        if not matches:
            continue
        ids = [m["id"] for m in matches]
        kev_ids = [i for i in ids if i in kev]
        top = max((m["cvss"]["score"] or 0) for m in matches)
        sev = cvss_to_sev(top) if top else "medium"
        if kev_ids:
            sev = max_sev(sev, "high")
        conf = "tentative" if c["backport"] else "potential"
        if c["backport"]:
            sev = {"critical": "high", "high": "medium"}.get(sev, sev)
        top_list = sorted(matches, key=lambda m: (-int(m["id"] in kev), -(m["cvss"]["score"] or 0)))[:15]
        desc = (f"{c['name']} {c['version']} was identified on {len(c['assets'])} asset(s). NVD lists {len(ids)} CVE(s) whose "
                f"affected-version ranges include this version" + (f"; {len(kev_ids)} are in the CISA KEV catalogue (known exploited)." if kev_ids else ".")
                + (" The banner suggests a Linux distribution package; vendors often back-port fixes without changing the version string, so verify package patch level." if c["backport"] else
                   " Version detection is banner-based; confirm the running version before remediation."))
        for h in sorted(c["assets"]):
            f = F.add(f"CVE-COMP-{c['key']}", f"Vulnerable component: {c['name']} {c['version']} ({len(ids)} CVE{'s' if len(ids) != 1 else ''}{', ' + str(len(kev_ids)) + ' KEV' if kev_ids else ''})",
                      sev, "Vulnerable component", h, desc,
                      f"Upgrade {c['name']} to the latest supported release (or apply vendor/distribution security patches). Prioritise KEV-listed and high-EPSS CVEs.",
                      evidence="; ".join(c["evidence"][:3]), confidence=conf, source="nvd:" + ",".join(sorted(c["sources"])),
                      cves=[m["id"] for m in top_list], group=True,
                      references=[f"https://nvd.nist.gov/vuln/detail/{m['id']}" for m in top_list[:5]])
            f["cvss"] = top
            f["kev"] = bool(kev_ids)
            f["all_cves"] = ids

    for ip, d in idb_vulns.items():
        ids = [x.upper() for x in d["vulns"]]
        recs = [cve_index[i] for i in ids if i in cve_index]
        top = max([r["cvss"] or 0 for r in recs] + [0])
        kev_ids = [r["id"] for r in recs if r["kev"]]
        sev = cvss_to_sev(top) if top else "medium"
        if kev_ids:
            sev = max_sev(sev, "high")
        for h in sorted(d["hosts"]):
            f = F.add(f"SHODAN-VULNS-{ip}", f"Shodan reports {len(ids)} CVE{'s' if len(ids) != 1 else ''} for {ip}" + (f" ({len(kev_ids)} KEV)" if kev_ids else ""),
                      sev, "Vulnerable component", h,
                      "Shodan InternetDB associates these CVEs with banners it observed on this IP (passive, version-based, may be stale or affected by back-ports).",
                      "Validate the reported software versions on the host and patch confirmed vulnerabilities, prioritising KEV/EPSS.",
                      evidence=f"{ip}: " + ", ".join(sorted(ids, key=lambda i: -(cve_index.get(i, {}).get('priority') or 0))[:12]),
                      confidence="potential", source="shodan-internetdb",
                      cves=sorted(ids, key=lambda i: -(cve_index.get(i, {}).get('priority') or 0))[:15])
            f["cvss"] = top or None
            f["kev"] = bool(kev_ids)

    # Enrich nuclei findings with KEV/EPSS
    for f in F.items.values():
        recs = [cve_index[c] for c in f.get("cves", []) if c in cve_index]
        if recs:
            f["kev"] = f.get("kev") or any(r["kev"] for r in recs)
            ep = [r["epss"] for r in recs if r["epss"] is not None]
            f["epss"] = max(ep) if ep else None
            if f.get("cvss") is None:
                sc = [r["cvss"] for r in recs if r["cvss"] is not None]
                f["cvss"] = max(sc) if sc else None

    findings = F.finalise()

    # Asset risk scores
    for f in findings:
        for h in f["assets"]:
            if h in assets:
                a = assets[h]
                a["finding_count"] += 1
                a["risk"] = min(100, a["risk"] + SEV_WEIGHT.get(f["severity"], 0) + (15 if f.get("kev") else 0))
                a.setdefault("max_severity", "info")
                a["max_severity"] = max_sev(a["max_severity"], f["severity"])

    cves = sorted(cve_index.values(), key=lambda r: -r["priority"])
    for r in cves:
        r["sources"], r["components"], r["assets"] = sorted(r["sources"]), sorted(r["components"]), sorted(r["assets"])
    comp_out = [{"name": c["name"], "version": c["version"], "assets": sorted(c["assets"]), "sources": sorted(c["sources"]),
                 "backport_suspected": c["backport"], "cve_count": len(comp_matches.get(c["key"], [])),
                 "evidence": c["evidence"][:5]} for c in sorted(components, key=lambda c: c["key"])]

    for a in assets.values():
        for w in a["web"]:
            w["headers"] = {k: v[:300] for k, v in w["headers"].items()}
    write_json(f"{run_dir}/analysis/assets.json", sorted(assets.values(), key=lambda a: (-a["risk"], a["host"])))
    write_json(f"{run_dir}/analysis/findings.json", findings)
    write_json(f"{run_dir}/analysis/cves.json", cves)
    write_json(f"{run_dir}/analysis/components.json", comp_out)
    write_json(f"{run_dir}/analysis/meta.json", {"nvd_requests": nvd.requests, "nvd_api_key": bool(nvd.api_key),
                                                 "nvd_unreachable": nvd.failed, "kev_entries": len(kev),
                                                 "cve_mapping": not no_cve, "offline": offline})
    sev_counts = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    log(f"Findings: {len(findings)} {sev_counts} | CVEs: {len(cves)} ({sum(1 for c in cves if c['kev'])} KEV)")
    return 0
