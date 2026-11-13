#!/usr/bin/env python3
"""Build a synthetic run directory + intel cache so the analysis and report pipeline
can be tested offline. All data is fictional (example.com, RFC 5737 IPs, CVE-2099-*)."""
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "engine"))
RUN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "fixtures", "demo_run")
CACHE = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "fixtures", "cache")
os.environ["EASM_CACHE_DIR"] = CACHE

from easm_lib import util  # noqa: E402

util.CACHE_DIR = CACHE
shutil.rmtree(RUN, ignore_errors=True)
shutil.rmtree(CACHE, ignore_errors=True)
for d in ("passive", "dns", "enrich", "urls", "authorized", "scan", "ports/services", "http", "tls", "crawl", "vuln", "analysis", "report", "logs"):
    os.makedirs(os.path.join(RUN, d), exist_ok=True)


def w(path, text):
    with open(os.path.join(RUN, path), "w") as fh:
        fh.write(text)


def wj(path, obj):
    w(path, json.dumps(obj, indent=1))


w("roots.txt", "example.com\nexample.org\n")
w("passive/subfinder.txt", "www.example.com\nmail.example.com\nvpn.example.com\nlegacy.example.com\nshop.example.com\ndev.example.com\nintranet.example.com\n")
w("passive/crtsh.txt", "www.example.com\napi.example.com\nold-assets.example.com\nwww.example.org\n")
w("passive/amass.txt", "api.example.com\n")
w("candidates.txt", "\n".join(sorted({"example.com", "example.org", "www.example.com", "mail.example.com", "vpn.example.com", "legacy.example.com",
                                         "shop.example.com", "dev.example.com", "intranet.example.com", "api.example.com", "old-assets.example.com",
                                         "www.example.org", "gone.example.com"})) + "\n")
hosts = {
    "example.com": ["203.0.113.10"], "www.example.com": ["203.0.113.10"], "api.example.com": ["203.0.113.20"],
    "mail.example.com": ["203.0.113.30"], "vpn.example.com": ["203.0.113.40"], "legacy.example.com": ["198.51.100.7"],
    "dev.example.com": ["198.51.100.8"], "intranet.example.com": ["10.20.30.40"], "www.example.org": ["104.16.0.1"],
}
rows = [{"host": h, "a": ips, "status_code": "NOERROR"} for h, ips in hosts.items()]
rows.append({"host": "shop.example.com", "cname": ["examplecorp.myshopify.com"], "a": ["23.227.38.65"]})
rows.append({"host": "old-assets.example.com", "cname": ["example-old-assets.azurewebsites.net"], "status_code": "NXDOMAIN"})
w("dns/dnsx.jsonl", "\n".join(json.dumps(r) for r in rows) + "\n")

wj("dns/root-dns.json", {
    "example.com": {"domain": "example.com", "records": {"A": ["203.0.113.10"], "AAAA": [], "NS": ["ns1.example.com.", "ns2.example.com."],
                    "MX": ["10 mail.example.com."], "SOA": ["ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600"],
                    "CAA": [], "DS": [], "DNSKEY": [], "TXT": ["v=spf1 include:_spf.example.net ?all"]},
                    "spf": ["v=spf1 include:_spf.example.net ?all"], "dmarc": ["v=DMARC1; p=none"], "mta_sts": [], "tls_rpt": [], "bimi": [],
                    "dkim": {"selector1": "v=DKIM1; k=rsa; p=MIIB..."}, "wildcard": {"enabled": False, "ips": []},
                    "axfr": {"ns1.example.com": {"allowed": True, "record_count": 42, "sample": ["example.com. 3600 IN SOA ..."]},
                             "ns2.example.com": {"allowed": False, "record_count": 0, "sample": []}}},
    "example.org": {"domain": "example.org", "records": {"A": ["104.16.0.1"], "NS": ["a.ns.example.net."], "MX": [], "CAA": ["0 issue \"letsencrypt.org\""],
                    "DS": ["12345 13 2 ABCD"], "TXT": []}, "spf": [], "dmarc": [], "mta_sts": [], "tls_rpt": [], "dkim": {},
                    "wildcard": {"enabled": True, "ips": ["104.16.0.1"]}},
})

wj("enrich/hosts.json", {h: {"ips": ips, "cnames": [], "private_ips": [i for i in ips if i.startswith("10.")],
                             "asn": ["AS64500 EXAMPLE-NET"] if not ips[0].startswith("104.") else ["AS13335 CLOUDFLARENET"],
                             "cdn": "CLOUDFLARENET" if ips[0].startswith("104.") else ""} for h, ips in hosts.items()}
   | {"shop.example.com": {"ips": ["23.227.38.65"], "cnames": ["examplecorp.myshopify.com"], "private_ips": [], "asn": ["AS13335 CLOUDFLARENET"], "cdn": "CLOUDFLARENET"},
      "old-assets.example.com": {"ips": [], "cnames": ["example-old-assets.azurewebsites.net"], "private_ips": [], "asn": [], "cdn": ""}})
wj("enrich/asn.json", {"203.0.113.10": {"asn": "64500", "as_name": "EXAMPLE-NET"}})
wj("enrich/internetdb.json", {"198.51.100.7": {"ports": [21, 22, 80, 3389], "cpes": ["cpe:/a:openbsd:openssh:7.4", "cpe:/a:apache:http_server:2.4.29"],
                                               "hostnames": ["legacy.example.com"], "tags": ["eol-product"], "vulns": ["CVE-2099-1001", "CVE-2099-1004"]}})

w("authorized/authorized_hosts.txt", "api.example.com\nexample.com\nlegacy.example.com\nmail.example.com\nold-assets.example.com\nvpn.example.com\nwww.example.com\n")
# httpx -csv output of the web asset inventory (current httpx header; Go-style list fields)
w("authorized/web-assets.csv",
  "timestamp,asn,csp,tls,hash,extract_regex,cdn_name,cdn_type,sni,port,url,input,location,title,scheme,error,webserver,body,"
  "content_type,method,host,path,favicon,final_url,header,raw_header,request,time,jarm,chain_status_codes,a,aaaa,cname,tech,"
  "extracts,chain,words,lines,status_code,content_length,failed,vhost,websocket,cdn,http2,pipeline\n"
  "2026-11-13 06:00:00,<nil>,<nil>,<nil>,map[],[],,,,443,https://www.example.com,www.example.com,,Example Corp,https,,nginx/1.18.0,,"
  "text/html,GET,203.0.113.10,,,,map[],,,120ms,,[],[203.0.113.10],[],[],[Nginx:1.18.0 PHP:7.4.3 Google Font API],map[],[],100,10,200,5120,false,false,false,false,false,false\n"
  "2026-11-13 06:00:01,<nil>,<nil>,<nil>,map[],[],,,,80,http://legacy.example.com,legacy.example.com,https://legacy.example.com/login,"
  "\"<script>alert(1)</script>\",http,,Apache/2.4.29 (Ubuntu),,text/html,GET,198.51.100.7,,,,map[],,,90ms,,[],[198.51.100.7],[],[],"
  "[Apache HTTP Server:2.4.29 Ubuntu],map[],[],20,3,302,0,false,false,false,false,false,false\n"
  "2026-11-13 06:00:02,<nil>,<nil>,<nil>,map[],[],,,,443,https://shop.example.com,shop.example.com,,Sorry this shop is unavailable,https,,"
  "cloudflare,,text/html,GET,23.227.38.65,,,,map[],,,80ms,,[],[23.227.38.65],[],[examplecorp.myshopify.com],[Shopify Cloudflare],"
  "map[],[],50,8,404,1200,false,false,false,false,false,false\n")
w("report/.active_ran", "")
w("report/run-meta.txt", "VERSION=2.0.0\nPROFILE=standard\nROOTS=example.com,example.org\nAUTH_REF=SAMPLE-TICKET-001\nACTIVE_RAN=1\n")
w("report/tool-inventory.txt", "SAMPLE RUN - synthetic data generated by tests/make_fixture.py\n")
wj("scan/ip-map.json", {"203.0.113.10": ["example.com", "www.example.com"], "203.0.113.20": ["api.example.com"], "203.0.113.30": ["mail.example.com"],
                        "203.0.113.40": ["vpn.example.com"], "198.51.100.7": ["legacy.example.com"]})
w("ports/naabu.jsonl", "\n".join(json.dumps({"host": h, "ip": ip, "port": p}) for h, ip, p in [
    ("www.example.com", "203.0.113.10", 80), ("www.example.com", "203.0.113.10", 443), ("api.example.com", "203.0.113.20", 443),
    ("api.example.com", "203.0.113.20", 6379), ("mail.example.com", "203.0.113.30", 25), ("mail.example.com", "203.0.113.30", 443),
    ("vpn.example.com", "203.0.113.40", 443), ("legacy.example.com", "198.51.100.7", 22), ("legacy.example.com", "198.51.100.7", 3389),
    ("legacy.example.com", "198.51.100.7", 80)]) + "\n")
w("ports/services/203.0.113.10.xml", """<?xml version="1.0"?><nmaprun><host><address addr="203.0.113.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" version="1.18.0" tunnel="ssl"><cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port></ports></host></nmaprun>""")
w("ports/services/198.51.100.7.xml", """<?xml version="1.0"?><nmaprun><host><address addr="198.51.100.7" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0"/></port>
<port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server" product="Microsoft Terminal Services"/></port></ports></host></nmaprun>""")
w("ports/services/203.0.113.20.xml", """<?xml version="1.0"?><nmaprun><host><address addr="203.0.113.20" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis key-value store" version="5.0.7"/></port></ports></host></nmaprun>""")

http = [
    {"url": "https://www.example.com", "input": "www.example.com", "status_code": 200, "title": "Example Corp", "webserver": "nginx/1.18.0",
     "tech": ["Nginx:1.18.0", "jQuery:1.12.4", "PHP:7.4.3"], "content_type": "text/html",
     "header": {"server": "nginx/1.18.0", "x_powered_by": "PHP/7.4.3", "set_cookie": "PHPSESSID=abc123; path=/", "content_type": "text/html"}},
    {"url": "http://www.example.com", "input": "www.example.com", "status_code": 301, "location": "https://www.example.com/", "header": {"server": "nginx/1.18.0"}},
    {"url": "https://api.example.com", "input": "api.example.com", "status_code": 200, "title": "Swagger UI", "tech": ["Swagger UI"], "content_type": "text/html",
     "header": {"strict_transport_security": "max-age=31536000", "content_security_policy": "default-src 'self'; frame-ancestors 'none'", "x_content_type_options": "nosniff",
                "access_control_allow_origin": "*", "access_control_allow_credentials": "true"}},
    {"url": "https://vpn.example.com", "input": "vpn.example.com", "status_code": 200, "title": "GlobalProtect Portal", "content_type": "text/html", "header": {"server": "Apache"}},
    {"url": "http://legacy.example.com", "input": "legacy.example.com", "status_code": 200, "title": "Admin Login <script>alert(1)</script>",
     "webserver": "Apache/2.4.29 (Ubuntu)", "tech": ["Apache HTTP Server:2.4.29", "Ubuntu"], "content_type": "text/html", "header": {"server": "Apache/2.4.29 (Ubuntu)"}},
    {"url": "https://mail.example.com", "input": "mail.example.com", "status_code": 200, "title": "Outlook Web App", "tech": ["Microsoft IIS:10.0"], "content_type": "text/html",
     "header": {"server": "Microsoft-IIS/10.0", "x_aspnet_version": "4.0.30319", "strict_transport_security": "max-age=100"}},
]
w("http/httpx.jsonl", "\n".join(json.dumps(r) for r in http) + "\n")
now_days = 400
wj("tls/tls.json", [
    {"host": "www.example.com", "port": 443, "negotiated_protocol": "TLSv1.3", "subject_cn": "www.example.com", "issuer": "Example CA", "days_to_expiry": 18,
     "trusted": True, "hostname_match": True, "self_signed": False, "protocols": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.3": True}},
    {"host": "mail.example.com", "port": 443, "negotiated_protocol": "TLSv1.2", "subject_cn": "mail.example.com", "issuer": "Example CA", "days_to_expiry": now_days,
     "trusted": True, "hostname_match": True, "self_signed": False, "protocols": {"TLSv1.0": True, "TLSv1.1": True, "TLSv1.3": False}},
    {"host": "vpn.example.com", "port": 443, "negotiated_protocol": "TLSv1.2", "subject_cn": "localhost", "issuer": "localhost", "days_to_expiry": -40,
     "trusted": False, "hostname_match": False, "self_signed": True, "verify_error": "self-signed certificate", "protocols": {"TLSv1.0": None, "TLSv1.1": False, "TLSv1.3": False}},
])
w("vuln/nuclei.jsonl", json.dumps({"template-id": "synthetic-vpn-rce", "host": "https://vpn.example.com", "matched-at": "https://vpn.example.com/global-protect/login.esp",
                                   "type": "http", "info": {"name": "Synthetic VPN Pre-auth RCE (test template)", "severity": "critical", "tags": ["cve", "rce", "kev"],
                                                            "description": "Synthetic finding used for report testing.", "reference": ["https://example.com/advisory"],
                                                            "classification": {"cve-id": ["cve-2099-2001"], "cvss-score": 10.0}}}) + "\n" +
  json.dumps({"template-id": "git-config", "host": "https://www.example.com", "matched-at": "https://www.example.com/.git/config", "type": "http",
              "info": {"name": "Git Config - Exposure", "severity": "medium", "tags": ["exposure", "config", "git"], "description": "Git configuration file is publicly accessible."}}) + "\n")
w("urls/archived-urls.txt", "https://www.example.com/login\nhttps://www.example.com/backup.zip\nhttps://api.example.com/v1/users?api_key=SAMPLEKEY123456\n"
  "https://www.example.com/redirect?url=https://evil.example\nhttps://www.example.com/static/app.js\nhttps://api.example.com/swagger/index.html\n")

# -------------------------------------------------------------- intel cache (synthetic)


def prod(cid, crit, score, sev, **rng):
    m = {"criteria": crit}
    m.update(rng)
    return {"id": cid, "status": "Analyzed", "published": "2099-01-01", "description": f"Synthetic test vulnerability {cid}.",
            "cvss": {"score": score, "severity": sev, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "version": "3.1"},
            "cwe": ["CWE-787"], "references": [], "cpe_matches": [m]}


util.cache_put("nvd", "product-a-f5:nginx", [
    prod("CVE-2099-0001", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", 7.7, "HIGH", versionStartIncluding="0.6.18", versionEndExcluding="1.20.1"),
    prod("CVE-2099-0002", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", 5.3, "MEDIUM", versionEndExcluding="1.16.0"),  # must NOT match 1.18.0
])
util.cache_put("nvd", "product-a-nginx:nginx", [])
util.cache_put("nvd", "product-a-php:php", [prod("CVE-2099-0101", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", 9.8, "CRITICAL", versionStartIncluding="7.4.0", versionEndExcluding="7.4.21")])
util.cache_put("nvd", "product-a-jquery:jquery", [prod("CVE-2099-0201", "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*", 6.1, "MEDIUM", versionEndExcluding="3.5.0")])
util.cache_put("nvd", "product-a-openbsd:openssh", [prod("CVE-2099-1001", "cpe:2.3:a:openbsd:openssh:7.4:-:*:*:*:*:*:*", 7.5, "HIGH"),
                                                    prod("CVE-2099-1002", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", 8.1, "HIGH", versionStartIncluding="8.5", versionEndExcluding="9.8")])
util.cache_put("nvd", "product-a-apache:http_server", [prod("CVE-2099-1004", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", 9.8, "CRITICAL", versionStartIncluding="2.4.0", versionEndIncluding="2.4.48")])
util.cache_put("nvd", "product-a-redis:redis", [prod("CVE-2099-1101", "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*", 8.8, "HIGH", versionEndExcluding="6.0.0")])
for vp in ("microsoft:internet_information_services", "microsoft:iis"):
    util.cache_put("nvd", f"product-a-{vp}", [])
util.cache_put("nvd", "cve-CVE-2099-2001", {"id": "CVE-2099-2001", "status": "Analyzed", "published": "2099-02-01", "description": "Synthetic VPN RCE.",
                                           "cvss": {"score": 10.0, "severity": "CRITICAL", "vector": "", "version": "3.1"}, "cwe": [], "references": []})
util.cache_put("kev", "kev-catalog", {"vulnerabilities": [
    {"cveID": "CVE-2099-2001", "dateAdded": "2099-02-02", "vulnerabilityName": "Synthetic VPN RCE", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2099-1004", "dateAdded": "2099-03-01", "vulnerabilityName": "Synthetic Apache bug", "knownRansomwareCampaignUse": "Unknown"}]})
util.cache_put("epss", "epss-scores", {c: {"epss": e, "percentile": p, "_t": time.time()} for c, e, p in [
    ("CVE-2099-2001", 0.94, 0.999), ("CVE-2099-1004", 0.41, 0.97), ("CVE-2099-0101", 0.12, 0.93), ("CVE-2099-0001", 0.02, 0.8),
    ("CVE-2099-1001", 0.005, 0.5), ("CVE-2099-0201", 0.003, 0.4), ("CVE-2099-1101", 0.01, 0.6)]})
print(RUN)
