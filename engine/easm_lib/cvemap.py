"""CVE intelligence: product/version -> CPE -> NVD CVEs, enriched with CISA KEV and FIRST EPSS.

Strategy
--------
* One NVD query per vendor:product (virtualMatchString with wildcard version), cached
  for 7 days, then *local* version-range matching against each CVE's cpeMatch criteria.
  This keeps NVD traffic tiny (rate limit: 5 req/30 s without key, 50 with key).
* Results are version-based => "potential". Distro back-ports (Ubuntu/Debian/RHEL
  patched packages keep old version strings) are flagged with lower confidence.
"""
import os
import re
import time
from urllib.parse import quote

from .util import (cache_get, cache_put, cvss_to_sev, data_file, http_get_json, log, warn)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
BACKPORT_RE = re.compile(r"ubuntu|debian|deb\d|el\d|rhel|red ?hat|centos|rocky|alma|amzn|suse|fedora|\+deb|ubuntu\d", re.I)
PRE_WORDS = {"alpha", "beta", "rc", "pre", "preview", "dev", "snapshot", "m", "b", "milestone"}


# ------------------------------------------------------------------ version handling

def vkey(v):
    key = []
    for tok in re.findall(r"\d+|[a-z]+", (v or "").lower()):
        if tok.isdigit():
            key.append((2, int(tok), ""))
        elif tok in PRE_WORDS:
            key.append((-1, 0, tok))
        else:
            key.append((1, 0, tok))
    return key


def vcmp(a, b):
    ka, kb = vkey(a), vkey(b)
    n = max(len(ka), len(kb))
    pad = (0, 0, "")
    ka += [pad] * (n - len(ka))
    kb += [pad] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def clean_version(v):
    """'8.2p1 Ubuntu 4ubuntu0.5' -> '8.2p1';  'v1.18.0' -> '1.18.0'."""
    if not v:
        return None
    m = re.search(r"\d+(?:\.\d+)*(?:[a-z]+\d*)?(?:[-_.]?(?:rc|beta|alpha)\d*)?", str(v).lower().lstrip("v"))
    return m.group(0) if m else None


def version_matches(version, m):
    """Does `version` fall inside an NVD cpeMatch criterion?"""
    parts = m.get("criteria", "").split(":")
    if len(parts) < 7:
        return False
    cver, cupd = parts[5].replace("\\", ""), parts[6].replace("\\", "")
    rng = {k: m.get(k) for k in ("versionStartIncluding", "versionStartExcluding",
                                 "versionEndIncluding", "versionEndExcluding")}
    if cver not in ("*", "-", ""):
        if cupd not in ("*", "-", ""):
            return vcmp(version, cver + cupd) == 0
        if vcmp(version, cver) == 0:
            return True
        base = re.match(r"\d+(?:\.\d+)*", version)
        rest = version[base.end():] if base else ""
        return bool(base) and vcmp(base.group(0), cver) == 0 and bool(re.match(r"[a-z]", rest)) and cupd == "*"
    if not any(rng.values()):
        return False  # "all versions" criteria are too noisy for version-based mapping
    if rng["versionStartIncluding"] and vcmp(version, rng["versionStartIncluding"]) < 0:
        return False
    if rng["versionStartExcluding"] and vcmp(version, rng["versionStartExcluding"]) <= 0:
        return False
    if rng["versionEndIncluding"] and vcmp(version, rng["versionEndIncluding"]) > 0:
        return False
    if rng["versionEndExcluding"] and vcmp(version, rng["versionEndExcluding"]) >= 0:
        return False
    return True


# --------------------------------------------------------------------- product map

class ProductMap:
    def __init__(self):
        self.entries = []
        for e in data_file("cpe-map.json").get("products", []):
            self.entries.append((e, [re.compile(p, re.I) for p in e["match"]]))

    def identify(self, name):
        n = re.sub(r"\s+", " ", (name or "").strip().lower())
        if not n:
            return None
        for e, pats in self.entries:
            if any(p.search(n) for p in pats):
                return e
        return None


# ------------------------------------------------------------------------- NVD

def _metrics(cve):
    m = cve.get("metrics", {}) or {}
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        arr = m.get(key) or []
        if not arr:
            continue
        pick = next((x for x in arr if x.get("type") == "Primary"), arr[0])
        d = pick.get("cvssData", {})
        score = d.get("baseScore")
        sev = d.get("baseSeverity") or pick.get("baseSeverity") or cvss_to_sev(score)
        return {"score": score, "severity": (sev or "").lower(), "vector": d.get("vectorString", ""), "version": ver}
    return {"score": None, "severity": "", "vector": "", "version": ""}


def _minimise(vuln, vendor_product=None):
    cve = vuln.get("cve", vuln)
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    matches = []
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for cm in node.get("cpeMatch", []) or []:
                if not cm.get("vulnerable"):
                    continue
                if vendor_product and f":{vendor_product}:" not in cm.get("criteria", ""):
                    continue
                matches.append({k: cm[k] for k in ("criteria", "versionStartIncluding", "versionStartExcluding",
                                                    "versionEndIncluding", "versionEndExcluding") if k in cm})
    return {
        "id": cve.get("id"), "status": cve.get("vulnStatus", ""), "published": (cve.get("published") or "")[:10],
        "description": desc[:600], "cvss": _metrics(cve), "cwe": cwes,
        "references": [r.get("url") for r in (cve.get("references") or [])[:6]], "cpe_matches": matches,
    }


class NVD:
    def __init__(self, api_key=None, offline=False):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.offline = offline
        self.delay = 0.8 if self.api_key else 6.5
        self._last = 0.0
        self.requests = 0
        self.failed = False

    def _sleep(self):
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def _get(self, url, key, ttl):
        cached = cache_get("nvd", key, ttl)
        if cached is not None or self.offline or self.failed:
            return cached if cached is not None else cache_get("nvd", key, None)
        self._sleep()
        hdrs = {"apiKey": self.api_key} if self.api_key else None
        obj, _ = http_get_json(url, "nvd_raw", key=key, ttl=0, headers=hdrs, timeout=60, retries=3)
        self.requests += 1
        if obj is None:
            self.failed = True
            warn("NVD unreachable; continuing with cached data only.")
        return obj

    def product_cves(self, part, vendor, product):
        """All CVEs whose applicability statements mention vendor:product (minimised, cached 7d)."""
        vp = f"{vendor}:{product}"
        key = f"product-{part}-{vp}"
        cached = cache_get("nvd", key, 7 * 86400)
        if cached is not None:
            return cached
        if self.offline or self.failed:
            return cache_get("nvd", key, None) or []
        out, start, total = [], 0, None
        match = f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*"
        log(f"NVD: fetching CVEs for {vp}")
        while total is None or start < total:
            url = f"{NVD_URL}?virtualMatchString={quote(match, safe=':*')}&resultsPerPage=2000&startIndex={start}"
            hdrs = {"apiKey": self.api_key} if self.api_key else None
            self._sleep()
            obj, _ = http_get_json(url, "nvd_raw", key=f"{key}-{start}", ttl=0, headers=hdrs, timeout=90, retries=3)
            self.requests += 1
            if not obj or obj.get("_not_found"):
                if obj is None:
                    self.failed = True
                    warn("NVD unreachable; CVE mapping will use cached data only.")
                break
            total = obj.get("totalResults", 0)
            vulns = obj.get("vulnerabilities", [])
            out.extend(_minimise(v, vp) for v in vulns)
            start += len(vulns) or 2000
            if not vulns:
                break
        if total is not None:
            cache_put("nvd", key, out)
        return out

    def cve(self, cve_id):
        key = f"cve-{cve_id}"
        cached = cache_get("nvd", key, 7 * 86400)
        if cached is not None:
            return cached
        obj = self._get(f"{NVD_URL}?cveId={cve_id}", f"raw-{cve_id}", 7 * 86400)
        if not obj or not obj.get("vulnerabilities"):
            return None
        res = _minimise(obj["vulnerabilities"][0])
        res.pop("cpe_matches", None)
        cache_put("nvd", key, res)
        return res


# ---------------------------------------------------------------------- KEV / EPSS

def load_kev(offline=False):
    obj, _ = http_get_json(KEV_URL, "kev", key="kev-catalog", ttl=86400, offline=offline, timeout=60)
    out = {}
    for v in (obj or {}).get("vulnerabilities", []) or []:
        out[v.get("cveID")] = {
            "date_added": v.get("dateAdded"), "name": v.get("vulnerabilityName"),
            "ransomware": v.get("knownRansomwareCampaignUse"), "due": v.get("dueDate"),
            "action": v.get("requiredAction"),
        }
    if not out:
        warn("CISA KEV catalog unavailable; KEV flags will be missing.")
    return out


def load_epss(cve_ids, offline=False):
    ids = sorted({c for c in cve_ids if c and c.startswith("CVE-")})
    store = cache_get("epss", "epss-scores", None) or {}
    fresh_cut = time.time() - 86400
    need = [c for c in ids if c not in store or store[c].get("_t", 0) < fresh_cut]
    if need and not offline:
        for i in range(0, len(need), 80):
            batch = need[i:i + 80]
            obj, _ = http_get_json(f"{EPSS_URL}?cve={','.join(batch)}", "epss_raw", key=",".join(batch),
                                   ttl=86400, timeout=30)
            if obj is None:
                warn("EPSS API unavailable; EPSS scores will be missing or stale.")
                break
            got = {d["cve"]: d for d in obj.get("data", [])}
            for c in batch:
                d = got.get(c)
                store[c] = {"epss": float(d["epss"]) if d else None,
                            "percentile": float(d["percentile"]) if d else None, "_t": time.time()}
            time.sleep(0.5)
        cache_put("epss", "epss-scores", store)
    return {c: store[c] for c in ids if c in store}


# ---------------------------------------------------------------------- matching

def map_components(components, nvd, max_products=60):
    """components: list of dicts {name, version, cpe_entry, assets, evidence, backport}
    Returns {component_key: [cve_min,...]}"""
    results = {}
    fetched = set()
    limit_warned = False
    for comp in components:
        entry = comp["entry"]
        version = comp["version"]
        if not version:
            continue
        matched = {}
        for vp in entry["cpe"]:
            vendor, product = vp.split(":", 1)
            if vp not in fetched and len(fetched) >= max_products:
                if not limit_warned:
                    warn("CVE mapping: product limit reached; remaining products skipped.")
                    limit_warned = True
                continue
            fetched.add(vp)
            for cve in nvd.product_cves(entry.get("part", "a"), vendor, product):
                if cve.get("status", "").lower().startswith("reject"):
                    continue
                if any(version_matches(version, m) for m in cve.get("cpe_matches", [])):
                    matched[cve["id"]] = cve
        results[comp["key"]] = sorted(matched.values(), key=lambda c: -(c["cvss"]["score"] or 0))
    return results


def priority(cvss, epss, kev):
    return round((100 if kev else 0) + (cvss or 0) * 5 + (epss or 0) * 50, 2)
