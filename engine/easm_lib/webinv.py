"""Web asset inventory: parse the httpx CSV produced by the active phase
(authorized/web-assets.csv) and publish it to findings/.

httpx CSV headers differ between releases (status_code vs status-code, tech vs
technologies, host vs host_ip ...) and list fields are printed Go-style ("[a b]"),
so parsing is deliberately tolerant.
"""
import csv
import json
import os
import shutil
from urllib.parse import urlsplit

from .util import is_ip

SRC = os.path.join("authorized", "web-assets.csv")
DST = os.path.join("findings", "web-assets.csv")

ALIASES = {
    "input": ("input",),
    "url": ("url",),
    "final_url": ("final_url",),
    "status": ("status_code", "status"),
    "title": ("title",),
    "tech": ("tech", "technologies"),
    "location": ("location",),
    "webserver": ("webserver", "web_server"),
    "content_length": ("content_length",),
    "cname": ("cname", "cnames"),
    "a": ("a", "host_ip", "ip"),
    "host": ("host",),
    "cdn_name": ("cdn_name",),
    "failed": ("failed",),
}


def _norm(key):
    return (key or "").strip().lower().replace("-", "_").replace(" ", "_")


def _list(value):
    """Turn '[a b]', '["a","b"]' or 'a,b' into a list of strings."""
    v = (value or "").strip()
    if not v or v in ("[]", "<nil>"):
        return []
    if v.startswith("[\""):
        try:
            return [str(x) for x in json.loads(v) if str(x).strip()]
        except ValueError:
            pass
    v = v.strip("[]")
    sep = "," if "," in v else None
    return [x.strip() for x in v.split(sep) if x.strip()]


def _tech(value):
    """Tech names can contain spaces, so only strip Go list brackets/JSON quoting."""
    v = (value or "").strip()
    if v.startswith("[\""):
        try:
            return ", ".join(str(x) for x in json.loads(v))
        except ValueError:
            pass
    return v.strip("[]").strip()


def load(run_dir):
    """Return a list of normalised rows, or None if no inventory exists."""
    path = os.path.join(run_dir, SRC)
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return None
    csv.field_size_limit(2 ** 31 - 1)
    rows = []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        header = None
        for rec in reader:
            if not rec or not any(c.strip() for c in rec):
                continue
            keys = [_norm(c) for c in rec]
            if header is None or ("url" in keys and "timestamp" in keys and keys == header):
                header = keys
                continue
            raw = dict(zip(header, rec))

            def g(name):
                for k in ALIASES[name]:
                    if raw.get(k, "").strip():
                        return raw[k].strip()
                return ""

            url = g("url")
            if not url:
                continue
            ips = [x for x in _list(g("a")) if is_ip(x)]
            if is_ip(g("host")) and g("host") not in ips:
                ips.insert(0, g("host"))
            status = g("status")
            rows.append({
                "host": (g("input") or urlsplit(url).hostname or "").lower(),
                "url": url,
                "status": int(status) if status.isdigit() else None,
                "title": g("title"),
                "tech": _tech(g("tech")),
                "ips": ips,
                "cnames": _list(g("cname")),
                "location": g("location") or (g("final_url") if g("final_url") != url else ""),
                "webserver": g("webserver"),
                "content_length": g("content_length"),
                "cdn": g("cdn_name"),
                "failed": g("failed").lower() == "true",
            })
    rows.sort(key=lambda r: (r["host"], r["url"]))
    return rows


def publish(run_dir):
    """Copy the raw httpx CSV into findings/ (verbatim). Returns the destination or None."""
    src = os.path.join(run_dir, SRC)
    if not os.path.isfile(src) or os.path.getsize(src) == 0:
        return None
    dst = os.path.join(run_dir, DST)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(src, dst)
    return dst
