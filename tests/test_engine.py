#!/usr/bin/env python3
"""Offline tests: version matching, input/scope validation, full analyze+report on the fixture."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "engine"))

from easm_lib.cvemap import clean_version, vcmp, version_matches  # noqa: E402

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


# --- version comparison
check(vcmp("1.18.0", "1.20.1") < 0, "1.18.0 < 1.20.1")
check(vcmp("1.0.2k", "1.0.2") > 0, "openssl letter release > base")
check(vcmp("2.0.0-rc1", "2.0.0") < 0, "rc < release")
check(vcmp("8.2p1", "8.5") < 0, "8.2p1 < 8.5")
check(vcmp("1.10", "1.9") > 0, "numeric not lexical")
check(clean_version("8.2p1 Ubuntu 4ubuntu0.5") == "8.2p1", "clean openssh banner")
check(clean_version("v1.18.0") == "1.18.0", "strip v prefix")
check(clean_version("unknown") is None, "no version -> None")

# --- range matching
m = {"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "versionStartIncluding": "0.6.18", "versionEndExcluding": "1.20.1"}
check(version_matches("1.18.0", m), "nginx 1.18.0 in [0.6.18,1.20.1)")
check(not version_matches("1.20.1", m), "nginx 1.20.1 excluded (end-excluding)")
check(version_matches("8.2p1", {"criteria": "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*"}), "openssh version+update exact")
check(not version_matches("8.2p1", {"criteria": "cpe:2.3:a:openbsd:openssh:8.3:p1:*:*:*:*:*:*"}), "openssh other version")
check(not version_matches("1.0", {"criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}), "unbounded wildcard ignored")

# --- input validation
eng = [sys.executable, "-I", os.path.join(ROOT, "engine", "easm.py")]
r = subprocess.run(eng + ["parse-input", "string", "Example.COM, example.org.,example.com"], capture_output=True, text=True)
check(r.returncode == 0 and r.stdout.split() == ["example.com", "example.org"], "parse-input normalises & dedupes")
r = subprocess.run(eng + ["parse-input", "string", "https://example.com/x"], capture_output=True, text=True)
check(r.returncode == 2, "parse-input rejects URLs")

with tempfile.TemporaryDirectory() as td:
    open(f"{td}/roots", "w").write("example.com\n")
    open(f"{td}/allow", "w").write("# comment\nwww.example.com\nevil.com\n")
    r = subprocess.run(eng + ["validate-allowlist", "--roots", f"{td}/roots", "--allowlist", f"{td}/allow"], capture_output=True, text=True)
    check(r.returncode == 2 and "outside supplied root scope" in r.stderr, "allowlist rejects out-of-scope host")
    open(f"{td}/raw", "w").write("*.www.example.com\nhttps://api.example.com:8443/x\nexample.com.evil.net\nnotexample.com\n")
    subprocess.run(eng + ["scope-filter", "--roots", f"{td}/roots", "--out", f"{td}/out", f"{td}/raw"], capture_output=True, text=True)
    got = open(f"{td}/out").read().split()
    check(got == ["api.example.com", "example.com", "www.example.com"], f"scope-filter strict suffix match {got}")

# --- full pipeline on the synthetic fixture
with tempfile.TemporaryDirectory() as td:
    run, cache = f"{td}/run", f"{td}/cache"
    subprocess.run([sys.executable, os.path.join(HERE, "make_fixture.py"), run, cache], check=True, capture_output=True)
    env = dict(os.environ, EASM_CACHE_DIR=cache)
    r = subprocess.run(eng + ["analyze", "--run-dir", run, "--offline"], capture_output=True, text=True, env=env)
    check(r.returncode == 0, "analyze completes offline" + ("" if r.returncode == 0 else r.stderr[-2000:]))
    r = subprocess.run(eng + ["report", "--run-dir", run, "--compare", run], capture_output=True, text=True, env=env)
    check(r.returncode == 0, "report renders" + ("" if r.returncode == 0 else r.stderr[-2000:]))
    F = json.load(open(f"{run}/analysis/findings.json"))
    C = {c["id"]: c for c in json.load(open(f"{run}/analysis/cves.json"))}
    rules = {f["rule"] for f in F}
    for rule in ("DNS-AXFR", "EMAIL-SPF-NEUTRAL", "EMAIL-DMARC-NONE", "EMAIL-DMARC-MISSING", "TAKEOVER-DANGLING", "PORT-6379",
                 "PORT-3389", "TLS-EXPIRED", "TLS-SELF-SIGNED", "TLS-LEGACY-PROTO", "TLS-EXPIRING", "WEB-HSTS-MISSING", "WEB-CORS",
                 "WEB-NO-HTTPS-REDIRECT", "WEB-COOKIE-FLAGS", "DNS-PRIVATE-IP", "URL-SECRET-PARAMS", "NUCLEI-synthetic-vpn-rce"):
        check(rule in rules, f"finding rule {rule}")
    check("CVE-2099-0001" in C and "CVE-2099-0002" not in C, "nginx range match correct (0001 yes, 0002 no)")
    check("CVE-2099-1002" not in C, "openssh 7.4 not matched to 8.5-9.8 range")
    check(C.get("CVE-2099-2001", {}).get("kev"), "KEV flag applied")
    check(C.get("CVE-2099-0101", {}).get("epss") == 0.12, "EPSS applied")
    check(F[0].get("kev"), "KEV findings sorted first")
    html = open(f"{run}/report/index.html").read()
    check("<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)" in html, "report escapes untrusted titles")
    for f in ("findings.csv", "assets.csv", "cves.csv", "summary.md", "findings.json"):
        check(os.path.exists(f"{run}/report/{f}"), f"export {f}")
    # --- web asset inventory (httpx CSV)
    raw = open(f"{run}/authorized/web-assets.csv", "rb").read()
    check(os.path.exists(f"{run}/findings/web-assets.csv") and open(f"{run}/findings/web-assets.csv", "rb").read() == raw,
          "web inventory copied verbatim to findings/")
    check("id='webinv'" in html and "https://shop.example.com" in html and "examplecorp.myshopify.com" in html,
          "web inventory section rendered")
    check("Google Font API" in html and "198.51.100.7" in html, "web inventory tech/IP parsed")
    check("Web inventory" in open(f"{run}/report/summary.md").read(), "web inventory in summary.md")

# --- web inventory parser: legacy httpx header (status-code, technologies, cnames)
from easm_lib import webinv  # noqa: E402
with tempfile.TemporaryDirectory() as td:
    os.makedirs(f"{td}/authorized")
    open(f"{td}/authorized/web-assets.csv", "w").write(
        "timestamp,url,input,location,title,webserver,host,a,cnames,technologies,status-code,content-length,failed\n"
        "x,https://a.example.com,a.example.com,,Hi,nginx,203.0.113.5,[],[edge.example.net],[IIS:10.0 Microsoft ASP.NET],200,10,false\n")
    rows = webinv.load(td)
    check(rows and rows[0]["status"] == 200 and rows[0]["ips"] == ["203.0.113.5"] and rows[0]["cnames"] == ["edge.example.net"]
          and rows[0]["tech"] == "IIS:10.0 Microsoft ASP.NET", "web inventory parses legacy httpx CSV header")
    check(webinv.load(f"{td}/missing") is None, "web inventory absent -> None")

print(f"\n{'ALL TESTS PASSED' if not fails else str(fails) + ' FAILURE(S)'}")
sys.exit(1 if fails else 0)
