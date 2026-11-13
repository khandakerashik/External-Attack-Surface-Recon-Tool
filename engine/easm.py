#!/usr/bin/env python3
"""easm-recon engine CLI. Called by easm-recon.sh; can also be run standalone to
re-analyse or re-render an existing run directory:

    python3 engine/easm.py analyze --run-dir osint-recon_20261113T060000Z
    python3 engine/easm.py report  --run-dir osint-recon_20261113T060000Z --compare old_run/
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from easm_lib import __version__  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(prog="easm.py", description="easm-recon analysis engine")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("parse-input", help="validate root domains")
    p.add_argument("mode", choices=["file", "string"])
    p.add_argument("value")

    p = sub.add_parser("scope-filter", help="merge discovery output and keep in-scope hostnames")
    p.add_argument("--roots", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("inputs", nargs="*")

    p = sub.add_parser("stage-allowlist", help="write the scope review file")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("validate-allowlist")
    p.add_argument("--roots", required=True)
    p.add_argument("--allowlist", required=True)

    p = sub.add_parser("dns-posture", help="root DNS + e-mail security records")
    p.add_argument("--roots", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--resolver", default=None)

    p = sub.add_parser("axfr", help="ACTIVE: zone-transfer test for allowlisted roots")
    p.add_argument("--root-dns", required=True)
    p.add_argument("--allowlist", required=True)

    p = sub.add_parser("enrich", help="ASN/CDN/InternetDB enrichment (passive)")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--no-internetdb", action="store_true")
    p.add_argument("--no-asn", action="store_true")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--max-ips", type=int, default=750)

    p = sub.add_parser("targets", help="prepare active scan targets from the allowlist")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--allowlist", required=True)

    p = sub.add_parser("tls", help="ACTIVE: TLS checks on HTTPS endpoints found by httpx")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--workers", type=int, default=4)

    p = sub.add_parser("analyze", help="correlate data, map CVEs, produce findings")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--offline", action="store_true", help="use cached NVD/KEV/EPSS data only")
    p.add_argument("--no-cve", action="store_true")
    p.add_argument("--nvd-detail-limit", type=int, default=None)
    p.add_argument("--max-products", type=int, default=60)

    p = sub.add_parser("report", help="render HTML/CSV/JSON/MD report")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--compare", default=None, help="previous run directory for change tracking")
    p.add_argument("--title", default=None)

    p = sub.add_parser("extract", help="glue helpers for the shell orchestrator")
    p.add_argument("what", choices=["ports-by-ip", "http-targets", "live-urls", "service-targets"])
    p.add_argument("--run-dir", required=True)
    p.add_argument("--out", default=None)

    p = sub.add_parser("resolve", help="dig-based fallback when dnsx is missing")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--candidates", required=True)
    p.add_argument("--out", required=True)

    a = ap.parse_args(argv)

    if a.cmd == "extract":
        from easm_lib import helpers
        if a.what == "ports-by-ip":
            return helpers.ports_by_ip(a.run_dir)
        fn = {"http-targets": helpers.http_targets, "live-urls": helpers.live_urls,
              "service-targets": helpers.service_targets}[a.what]
        return fn(a.run_dir, a.out)
    if a.cmd == "resolve":
        from easm_lib import helpers
        return helpers.resolve_fallback(a.run_dir, a.candidates, a.out)

    if a.cmd == "parse-input":
        from easm_lib import scope
        return scope.parse_input(a.mode, a.value)
    if a.cmd == "scope-filter":
        from easm_lib import scope
        return scope.scope_filter(a.roots, a.inputs, a.out)
    if a.cmd == "stage-allowlist":
        from easm_lib import scope
        return scope.stage_allowlist(a.run_dir, a.out)
    if a.cmd == "validate-allowlist":
        from easm_lib import scope
        return scope.validate_allowlist(a.roots, a.allowlist)
    if a.cmd == "dns-posture":
        from easm_lib import dnsinfo
        dnsinfo.RESOLVER = a.resolver
        return dnsinfo.run(a.roots, a.out)
    if a.cmd == "axfr":
        from easm_lib import dnsinfo
        return dnsinfo.axfr_update(a.root_dns, a.allowlist)
    if a.cmd == "enrich":
        from easm_lib import enrich
        return enrich.run(a.run_dir, use_internetdb=not a.no_internetdb, use_asn=not a.no_asn,
                          offline=a.offline, max_ips=a.max_ips)
    if a.cmd == "targets":
        from easm_lib import enrich
        return enrich.prepare_targets(a.run_dir, a.allowlist)
    if a.cmd == "tls":
        from easm_lib import tlscheck
        return tlscheck.run(a.run_dir, workers=a.workers)
    if a.cmd == "analyze":
        from easm_lib import analyze
        return analyze.run(a.run_dir, offline=a.offline, no_cve=a.no_cve,
                           nvd_detail_limit=a.nvd_detail_limit, max_products=a.max_products)
    if a.cmd == "report":
        from easm_lib import report
        return report.render(a.run_dir, prev_dir=a.compare, title=a.title)
    return 1


if __name__ == "__main__":
    sys.exit(main())
