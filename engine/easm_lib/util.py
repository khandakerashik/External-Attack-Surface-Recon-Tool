"""Shared helpers: file IO, logging, cached HTTP for public intel APIs."""
import datetime
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

UA = "easm-recon/2.0 (+https://github.com/khandakerashik/easm-recon)"
CACHE_DIR = os.environ.get("EASM_CACHE_DIR") or os.path.join(
    os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "easm-recon")
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")

HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def log(msg):
    print(f"[{now_iso()}] {msg}", file=sys.stderr, flush=True)


def warn(msg):
    print(f"[{now_iso()}] [WARN] {msg}", file=sys.stderr, flush=True)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_lines(path):
    """Non-empty, non-comment lines; missing file -> []."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            out = []
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(line)
            return out
    except OSError:
        return []


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def read_jsonl(path):
    rows = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return rows


def write_json(path, obj):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=False, default=str)
    os.replace(tmp, path)


def write_lines(path, lines):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(f"{line}\n")


def data_file(name):
    return read_json(os.path.join(DATA_DIR, name), {})


def short_hash(*parts, n=10):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:n]


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def in_scope(host, roots):
    host = host.lower().rstrip(".")
    return any(host == r or host.endswith("." + r) for r in roots)


def root_of(host, roots):
    best = ""
    for r in roots:
        if (host == r or host.endswith("." + r)) and len(r) > len(best):
            best = r
    return best


def max_sev(*sevs):
    sevs = [s for s in sevs if s]
    return max(sevs, key=lambda s: SEV_ORDER.get(s, -1)) if sevs else "info"


def cvss_to_sev(score):
    if score is None:
        return None
    score = float(score)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# --------------------------------------------------------------------------- HTTP

def _cache_path(namespace, key):
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", key)[:120]
    return os.path.join(CACHE_DIR, namespace, f"{safe}-{short_hash(key, n=8)}.json")


def cache_get(namespace, key, ttl):
    path = _cache_path(namespace, key)
    try:
        if ttl is None or (time.time() - os.path.getmtime(path)) < ttl:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
    except (OSError, ValueError):
        pass
    return None


def cache_put(namespace, key, obj):
    path = _cache_path(namespace, key)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


class HttpError(Exception):
    def __init__(self, status, msg=""):
        super().__init__(f"HTTP {status} {msg}")
        self.status = status


def http_get(url, headers=None, timeout=30, retries=2, backoff=6.0, max_bytes=60 * 1024 * 1024):
    """GET a URL and return bytes. Retries on 429/5xx/network errors."""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    last_exc = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(max_bytes)
        except urllib.error.HTTPError as exc:
            last_exc = HttpError(exc.code, url)
            if exc.code in (403, 429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(backoff * (attempt + 1))
                continue
            raise last_exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(backoff * (attempt + 1) / 2)
                continue
    raise last_exc  # type: ignore[misc]


def http_get_json(url, namespace, key=None, ttl=86400, headers=None, offline=False, timeout=30, retries=2):
    """Cached JSON GET. Returns (obj, from_cache). obj is None when unavailable."""
    key = key or url
    cached = cache_get(namespace, key, ttl)
    if cached is not None:
        return cached, True
    if offline:
        stale = cache_get(namespace, key, None)
        return stale, stale is not None
    try:
        raw = http_get(url, headers=headers, timeout=timeout, retries=retries)
        obj = json.loads(raw.decode("utf-8", errors="replace"))
    except HttpError as exc:
        if exc.status == 404:
            obj = {"_not_found": True}
            cache_put(namespace, key, obj)
            return obj, False
        warn(f"{namespace}: request failed ({exc})")
        stale = cache_get(namespace, key, None)
        return stale, stale is not None
    except Exception as exc:  # network down, proxy, JSON error
        warn(f"{namespace}: request failed ({exc.__class__.__name__}: {exc})")
        stale = cache_get(namespace, key, None)
        return stale, stale is not None
    cache_put(namespace, key, obj)
    return obj, False
