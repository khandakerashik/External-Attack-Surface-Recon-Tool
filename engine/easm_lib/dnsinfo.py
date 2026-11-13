"""Root-domain DNS, e-mail security posture, wildcard detection and (active) AXFR test.

Uses the system `dig` binary so results match what an operator would see manually.
"""
import concurrent.futures as cf
import random
import shutil
import string
import subprocess

from .util import log, read_lines, warn, write_json

DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "k1", "k2", "k3", "s1", "s2", "dkim",
    "mail", "smtp", "mx", "email", "everlytic", "mandrill", "mxvault", "zoho", "zmail",
    "sendgrid", "smtpapi", "amazonses", "pm", "mailjet", "sig1", "fm1", "fm2", "fm3",
    "protonmail", "protonmail2", "protonmail3", "cm", "dkim1", "key1", "mta", "m1",
]
RESOLVER = None  # set from CLI (e.g. 1.1.1.1)


def dig(name, rtype, server=None, short=True, timeout=3, extra=None):
    if not shutil.which("dig"):
        return []
    cmd = ["dig", f"+time={timeout}", "+tries=1"]
    if short:
        cmd.append("+short")
    else:
        cmd += ["+noall", "+answer"]
    if extra:
        cmd += extra
    srv = server or RESOLVER
    if srv:
        cmd.append(f"@{srv}")
    cmd += [name, rtype]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 3 + 5).stdout
    except (subprocess.SubprocessError, OSError):
        return []
    lines = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith(";")]
    return lines


def _txt_join(record):
    """dig +short TXT gives '"part1" "part2"' -> 'part1part2'."""
    parts = []
    buf, inq, esc = "", False, False
    for ch in record:
        if esc:
            buf += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            if inq:
                parts.append(buf)
                buf = ""
            inq = not inq
        elif inq:
            buf += ch
    return "".join(parts) if parts else record.strip('"')


def txt(name):
    return [_txt_join(r) for r in dig(name, "TXT")]


def _rand_label():
    return "easm-wc-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


def collect_root(domain, do_axfr=False):
    info = {"domain": domain, "records": {}}
    for rr in ("A", "AAAA", "NS", "MX", "SOA", "CAA", "DS", "DNSKEY"):
        info["records"][rr] = dig(domain, rr)
    info["records"]["TXT"] = txt(domain)

    spf = [t for t in info["records"]["TXT"] if t.lower().startswith("v=spf1")]
    info["spf"] = spf
    info["dmarc"] = [t for t in txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    info["mta_sts"] = [t for t in txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
    info["tls_rpt"] = [t for t in txt(f"_smtp._tls.{domain}") if t.lower().startswith("v=tlsrptv1")]
    info["bimi"] = [t for t in txt(f"default._bimi.{domain}") if t.lower().startswith("v=bimi1")]

    dkim = {}
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(txt, f"{sel}._domainkey.{domain}"): sel for sel in DKIM_SELECTORS}
        for fut in cf.as_completed(futs):
            vals = [v for v in fut.result() if "p=" in v.lower() or "v=dkim1" in v.lower()]
            if vals:
                dkim[futs[fut]] = vals[0][:300]
    info["dkim"] = dkim

    # Wildcard DNS detection (two random labels; both must resolve)
    wc_ips = set()
    hits = 0
    for _ in range(2):
        label = f"{_rand_label()}.{domain}"
        ans = dig(label, "A") + dig(label, "AAAA")
        if ans:
            hits += 1
            wc_ips.update(a for a in ans if a[0].isdigit() or ":" in a)
    info["wildcard"] = {"enabled": hits == 2, "ips": sorted(wc_ips)}

    if do_axfr:
        info["axfr"] = axfr(domain, info["records"]["NS"])
    return info


def axfr(domain, nameservers):
    results = {}
    for ns in nameservers:
        ns = ns.rstrip(".")
        lines = dig(domain, "AXFR", server=ns, short=False, timeout=5)
        records = [ln for ln in lines if "\t" in ln or " IN " in ln]
        failed = any("Transfer failed" in ln or "XFR size" in ln for ln in lines)
        results[ns] = {"allowed": (len(records) > 2 and not failed), "record_count": len(records),
                       "sample": records[:25]}
    return results


def axfr_update(root_dns_path, allowlist_path):
    """Active stage: test AXFR only for roots that are themselves in the allowlist."""
    from .util import read_json
    data = read_json(root_dns_path, {}) or {}
    allowed = set(read_lines(allowlist_path))
    for domain, info in data.items():
        if domain not in allowed:
            continue
        log(f"AXFR test: {domain}")
        info["axfr"] = axfr(domain, info.get("records", {}).get("NS", []))
    write_json(root_dns_path, data)
    return 0


def run(roots_path, out_path, do_axfr=False, axfr_roots=None):
    roots = read_lines(roots_path)
    if not shutil.which("dig"):
        warn("dig not installed; DNS/e-mail posture checks skipped.")
        write_json(out_path, {})
        return 0
    out = {}
    for domain in roots:
        log(f"DNS posture: {domain}")
        allow_axfr = do_axfr and (axfr_roots is None or domain in axfr_roots)
        out[domain] = collect_root(domain, do_axfr=allow_axfr)
    write_json(out_path, out)
    return 0
