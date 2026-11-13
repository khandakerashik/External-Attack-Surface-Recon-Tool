"""Input validation, scope filtering and allowlist handling."""
import pathlib
import re
import sys

from .util import HOST_RE, read_json, read_jsonl, read_lines, write_lines

ROOT_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


def _valid_host(domain):
    labels = domain.split(".")
    return (len(domain) <= 253 and len(labels) >= 2
            and all(1 <= len(lb) <= 63 for lb in labels)
            and ROOT_RE.fullmatch(domain) is not None)


def parse_input(mode, value):
    """Return sorted unique root domains or exit 2 with errors on stderr."""
    try:
        raw = pathlib.Path(value).read_text(encoding="utf-8", errors="replace") if mode == "file" else value
    except OSError as exc:
        print(f"Cannot read input file: {exc}", file=sys.stderr)
        return 2
    seen, invalid = set(), []
    for line_no, line in enumerate(raw.splitlines() or [raw], 1):
        line = line.split("#", 1)[0]
        for token in re.split(r"[\s,]+", line.strip()):
            if not token:
                continue
            domain = token.strip().lower().rstrip(".")
            if _valid_host(domain):
                seen.add(domain)
            else:
                invalid.append((line_no, token))
    if invalid:
        for line_no, token in invalid:
            print(f"Invalid domain on input line {line_no}: {token!r}", file=sys.stderr)
        return 2
    for d in sorted(seen):
        print(d)
    return 0


def scope_filter(roots_path, raw_paths, out_path):
    roots = read_lines(roots_path)
    out = set(roots)
    for p in raw_paths:
        try:
            text = pathlib.Path(p).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw in re.split(r"[\s,]+", text):
            host = raw.strip().lower().removeprefix("*.").rstrip(".")
            if host.startswith(("http://", "https://")):
                host = re.sub(r"^https?://", "", host).split("/", 1)[0].split(":", 1)[0]
            if HOST_RE.fullmatch(host) and any(host == r or host.endswith("." + r) for r in roots):
                out.add(host)
    write_lines(out_path, sorted(out))
    print(len(out))
    return 0


def validate_allowlist(roots_path, allow_path):
    roots = read_lines(roots_path)
    path = pathlib.Path(allow_path)
    try:
        raw = path.read_text(errors="replace")
    except OSError as exc:
        print(f"Cannot read allowlist: {exc}", file=sys.stderr)
        return 2
    hosts, errors = set(), []
    for line_no, line in enumerate(raw.splitlines(), 1):
        line = line.split("#", 1)[0]
        for token in re.split(r"[\s,]+", line.strip()):
            if not token:
                continue
            host = token.lower().rstrip(".")
            if not HOST_RE.fullmatch(host):
                errors.append(f"line {line_no}: invalid hostname {token!r}")
            elif not any(host == r or host.endswith("." + r) for r in roots):
                errors.append(f"line {line_no}: outside supplied root scope: {host}")
            else:
                hosts.add(host)
    if errors:
        print("Allowlist validation failed:", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 2
    if not hosts:
        print("Allowlist is empty; no active targets to check.", file=sys.stderr)
        return 3
    path.write_text("".join(h + "\n" for h in sorted(hosts)))
    print(f"Validated {len(hosts)} hostname(s), all under supplied roots.")
    return 0


def stage_allowlist(run_dir, out_path):
    """Write a review file: resolved in-scope hosts first, then unresolved (commented)."""
    run = pathlib.Path(run_dir)
    roots = read_lines(run / "roots.txt")
    resolved = set()
    for row in read_jsonl(run / "dns" / "dnsx.jsonl"):
        h = (row.get("host") or "").lower().rstrip(".")
        if h and (row.get("a") or row.get("aaaa") or row.get("cname")):
            resolved.add(h)
    enrich = read_json(run / "enrich" / "hosts.json", {}) or {}
    wildcard_ips = set()
    for root, info in (read_json(run / "dns" / "root-dns.json", {}) or {}).items():
        wildcard_ips.update((info.get("wildcard") or {}).get("ips", []))
    candidates = read_lines(run / "candidates.txt")
    lines = [
        "# ======================================================================",
        "# HOSTNAME SCOPE REVIEW  -  easm-recon",
        "# Every host below was found by PASSIVE discovery. It is NOT authorised.",
        "# Keep only hostnames explicitly covered by your written authorisation.",
        "# Delete or comment (#) everything else, including third-party SaaS/CDN.",
        "# Lines starting with # are ignored. Save and exit to continue.",
        "# ======================================================================",
        "",
        "# --- Resolving hostnames ---",
    ]
    for h in sorted(resolved):
        ips = (enrich.get(h) or {}).get("ips", [])
        note = []
        if ips and set(ips) <= wildcard_ips:
            note.append("matches wildcard DNS - may not be a real host")
        cdn = (enrich.get(h) or {}).get("cdn")
        if cdn:
            note.append(f"CDN/edge: {cdn}")
        lines.append(h + (f"    # {'; '.join(note)}" if note else ""))
    lines += ["", "# --- In-scope roots ---"] + [r for r in roots if r not in resolved]
    unresolved = [h for h in candidates if h not in resolved and h not in roots]
    if unresolved:
        lines += ["", "# --- Not resolving at discovery time (uncomment to include) ---"]
        lines += [f"# {h}" for h in unresolved[:5000]]
    write_lines(out_path, lines)
    print(len(resolved) + len([r for r in roots if r not in resolved]))
    return 0
