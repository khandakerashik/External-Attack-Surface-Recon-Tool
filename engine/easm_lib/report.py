"""Self-contained HTML report + CSV/JSON/Markdown exports (no external assets, works offline)."""
import csv
import html
import os
import re

from . import webinv
from .util import SEV_ORDER, now_iso, read_json, read_lines, write_json

E = lambda v: html.escape("" if v is None else str(v), quote=True)  # noqa: E731
SEVS = ["critical", "high", "medium", "low", "info"]


def _badge(sev):
    s = (sev or "info").lower()
    return f'<span class="sev sev-{E(s)}">{E(s.upper())}</span>'


def _conf(c):
    return f'<span class="conf conf-{E(c)}">{E(c)}</span>'


def _meta(run_dir):
    meta = {}
    for line in read_lines(f"{run_dir}/report/run-meta.txt"):
        if "=" in line:
            k, v = line.split("=", 1)
            meta[k.strip()] = v.strip()
    return meta


def _compare(prev_dir, assets, findings):
    if not prev_dir:
        return None
    pa = read_json(os.path.join(prev_dir, "analysis", "assets.json"), None)
    pf = read_json(os.path.join(prev_dir, "analysis", "findings.json"), None)
    if pa is None or pf is None:
        return {"error": f"No analysis data found in {prev_dir}"}
    prev_hosts = {a["host"] for a in pa if a.get("resolved")}
    cur_hosts = {a["host"] for a in assets if a.get("resolved")}
    prev_ids = {f["id"] for f in pf}
    cur_ids = {f["id"] for f in findings}
    return {"prev_dir": prev_dir, "new_hosts": sorted(cur_hosts - prev_hosts), "gone_hosts": sorted(prev_hosts - cur_hosts),
            "new_findings": [f for f in findings if f["id"] not in prev_ids],
            "resolved_findings": [f for f in pf if f["id"] not in cur_ids]}


def _observations(findings, cves, assets, root_dns, comps):
    obs = []
    kev = [c for c in cves if c.get("kev")]
    if kev:
        obs.append(f"<b>{len(kev)}</b> CVE(s) mapped to internet-facing assets are listed in the CISA Known Exploited Vulnerabilities catalogue "
                   f"(e.g. {', '.join(E(c['id']) for c in kev[:3])}). Treat these as patch-now items after validating versions.")
    hi = [f for f in findings if f["severity"] in ("critical", "high")]
    if hi:
        obs.append(f"<b>{len(hi)}</b> critical/high finding(s) require prompt attention.")
    exposed = [f for f in findings if f["category"] == "Network exposure" and f["severity"] in ("critical", "high")]
    if exposed:
        svcs = sorted({re.sub(r"Exposed (.*) service.*", r"\1", f["title"]) for f in exposed})
        obs.append(f"High-risk services are reachable from the internet: {E(', '.join(svcs[:8]))}.")
    take = [f for f in findings if f["category"] == "Subdomain takeover"]
    if take:
        obs.append(f"<b>{sum(len(f['assets']) for f in take)}</b> subdomain(s) show takeover indicators (dangling CNAMEs or unclaimed-resource fingerprints).")
    weak_mail = [d for d, i in root_dns.items() if not i.get("dmarc") or any("p=none" in x.lower() for x in i.get("dmarc", []))]
    if weak_mail:
        obs.append(f"E-mail spoofing protection is weak (DMARC missing or p=none) on: {E(', '.join(weak_mail[:6]))}.")
    tls = [f for f in findings if f["category"] == "TLS" and f["severity"] in ("high", "medium")]
    if tls:
        obs.append(f"<b>{len(tls)}</b> TLS issue(s) found (expired/untrusted certificates or legacy protocols).")
    outdated = [c for c in comps if c.get("cve_count")]
    if outdated:
        obs.append(f"<b>{len(outdated)}</b> software component version(s) match published CVEs (banner/version based - verify back-ports).")
    if not obs:
        obs.append("No high-impact issues were identified with the checks performed. Review the limitations section for coverage gaps.")
    return obs


CSS = r"""
:root{--bg:#f6f7f9;--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--accent:#0f4c81;
--critical:#991b1b;--high:#dc2626;--medium:#d97706;--low:#2563eb;--info:#64748b}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink)}
a{color:var(--accent)}header.top{background:#0b1f33;color:#fff;padding:28px 40px}
header.top h1{margin:0 0 6px;font-size:24px}header.top .sub{color:#cbd5e1;font-size:13px}
nav{position:sticky;top:0;z-index:5;background:#fff;border-bottom:1px solid var(--line);padding:0 40px;display:flex;gap:4px;flex-wrap:wrap}
nav a{padding:12px 10px;text-decoration:none;color:var(--ink);font-weight:600;font-size:13px;border-bottom:2px solid transparent}
nav a:hover{border-color:var(--accent)}main{max-width:1400px;margin:0 auto;padding:24px 40px 80px}
section{margin-bottom:36px}h2{font-size:19px;margin:0 0 14px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:15px;margin:18px 0 8px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.kpi .v{font-size:26px;font-weight:700}.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.bar{display:flex;height:16px;border-radius:8px;overflow:hidden;background:var(--line);margin:8px 0 6px}
.bar span{display:block;height:100%}.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
.sev{display:inline-block;min-width:70px;text-align:center;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff;letter-spacing:.04em}
.sev-critical{background:var(--critical)}.sev-high{background:var(--high)}.sev-medium{background:var(--medium)}.sev-low{background:var(--low)}.sev-info,.sev-unknown{background:var(--info)}
.kev{display:inline-block;padding:1px 6px;border-radius:4px;background:#111827;color:#fde047;font-size:11px;font-weight:700}
.conf{font-size:11px;padding:1px 6px;border-radius:4px;border:1px solid var(--line);color:var(--muted)}
.conf-confirmed,.conf-firm{border-color:#16a34a;color:#15803d}.conf-potential{border-color:#d97706;color:#b45309}.conf-tentative{border-color:#94a3b8}
table{width:100%;border-collapse:collapse;background:var(--card);font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#f1f5f9;font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:#334155;cursor:pointer;user-select:none;white-space:nowrap}
th.nosort{cursor:default}tr:hover td{background:#f8fafc}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.muted{color:var(--muted)}.small{font-size:12px}.wrap{word-break:break-all}.tbl{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.controls input,.controls select{padding:7px 10px;border:1px solid var(--line);border-radius:6px;font-size:13px;min-width:220px}
.chip{border:1px solid var(--line);background:#fff;border-radius:16px;padding:5px 12px;font-size:12px;cursor:pointer;font-weight:600}
.chip.off{opacity:.35}details.f{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--info);border-radius:8px;margin-bottom:8px}
details.f[data-sev=critical]{border-left-color:var(--critical)}details.f[data-sev=high]{border-left-color:var(--high)}
details.f[data-sev=medium]{border-left-color:var(--medium)}details.f[data-sev=low]{border-left-color:var(--low)}
details.f summary{padding:10px 14px;cursor:pointer;display:grid;grid-template-columns:90px 1fr 170px 90px;gap:12px;align-items:center;list-style:none}
details.f summary::-webkit-details-marker{display:none}details.f .body{padding:4px 18px 16px;border-top:1px solid var(--line)}
.kv{display:grid;grid-template-columns:140px 1fr;gap:6px 14px;margin-top:10px}.kv b{color:#334155}
pre{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:320px}
ul.obs li{margin-bottom:6px}.ok{color:#15803d;font-weight:700}.bad{color:#b91c1c;font-weight:700}.warn{color:#b45309;font-weight:700}
.riskbar{width:90px;height:8px;background:var(--line);border-radius:4px;overflow:hidden;display:inline-block;vertical-align:middle;margin-right:6px}
.riskbar span{display:block;height:100%}.tag{display:inline-block;background:#eef2f7;border-radius:4px;padding:0 6px;margin:1px;font-size:11px}
.note{background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:10px 14px;font-size:13px}
footer{color:var(--muted);font-size:12px;text-align:center;padding:20px}
td.host{white-space:nowrap}
@media print{nav,.controls{display:none}details.f{break-inside:avoid}body{background:#fff}.tbl{overflow:visible}}
"""

JS = r"""
(function(){
 const chips=[...document.querySelectorAll('.chip[data-sev]')];
 const q=document.getElementById('fq'), cat=document.getElementById('fcat');
 function apply(){const on=new Set(chips.filter(c=>!c.classList.contains('off')).map(c=>c.dataset.sev));
  const t=(q.value||'').toLowerCase(), c=cat.value; let n=0;
  document.querySelectorAll('details.f').forEach(d=>{const ok=on.has(d.dataset.sev)&&(!c||d.dataset.cat===c)&&(!t||d.textContent.toLowerCase().includes(t));
   d.style.display=ok?'':'none'; if(ok)n++;});
  document.getElementById('fcount').textContent=n+' shown';}
 chips.forEach(c=>c.addEventListener('click',()=>{c.classList.toggle('off');apply();}));
 if(q){q.addEventListener('input',apply);cat.addEventListener('change',apply);apply();}
 document.getElementById('expand').addEventListener('click',()=>document.querySelectorAll('details.f').forEach(d=>{if(d.style.display!=='none')d.open=true;}));
 document.getElementById('collapse').addEventListener('click',()=>document.querySelectorAll('details.f').forEach(d=>d.open=false));
 document.querySelectorAll('input[data-filter]').forEach(inp=>inp.addEventListener('input',()=>{
  const t=inp.value.toLowerCase();document.querySelectorAll('#'+inp.dataset.filter+' tbody tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(t)?'':'none';});}));
 document.querySelectorAll('table.sortable th:not(.nosort)').forEach((th,i)=>th.addEventListener('click',()=>{
  const tb=th.closest('table').tBodies[0], rows=[...tb.rows], asc=th.dataset.asc!=='1'; th.dataset.asc=asc?'1':'0';
  const idx=[...th.parentNode.children].indexOf(th);
  rows.sort((a,b)=>{const x=a.cells[idx].dataset.v??a.cells[idx].textContent, y=b.cells[idx].dataset.v??b.cells[idx].textContent;
   const nx=parseFloat(x), ny=parseFloat(y); const r=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y); return asc?r:-r;});
  rows.forEach(r=>tb.appendChild(r));}));
})();
"""


def render(run_dir, prev_dir=None, title=None):
    assets = read_json(f"{run_dir}/analysis/assets.json", []) or []
    findings = read_json(f"{run_dir}/analysis/findings.json", []) or []
    cves = read_json(f"{run_dir}/analysis/cves.json", []) or []
    comps = read_json(f"{run_dir}/analysis/components.json", []) or []
    urls = read_json(f"{run_dir}/analysis/urls.json", {}) or {}
    amete = read_json(f"{run_dir}/analysis/meta.json", {}) or {}
    root_dns = read_json(f"{run_dir}/dns/root-dns.json", {}) or {}
    roots = read_lines(f"{run_dir}/roots.txt")
    meta = _meta(run_dir)
    cmp_ = _compare(prev_dir, assets, findings)
    webrows = webinv.load(run_dir)
    webinv.publish(run_dir)
    try:
        inventory = open(f"{run_dir}/report/tool-inventory.txt", encoding="utf-8", errors="replace").read()
    except OSError:
        inventory = "(not available)"

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVS}
    resolved = [a for a in assets if a.get("resolved")]
    live_web = sum(1 for a in assets if a.get("web"))
    open_ports = sum(len(a.get("ports", {})) for a in assets)
    kev_n = sum(1 for c in cves if c.get("kev"))
    active = meta.get("ACTIVE_RAN") == "1"
    title = title or "External Attack Surface & Vulnerability Report"

    P = []
    w = P.append
    w(f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
      f"<title>{E(title)} - {E(', '.join(roots[:3]))}</title><style>{CSS}</style></head><body>")
    w(f"<header class='top'><h1>{E(title)}</h1><div class='sub'>Scope roots: <b>{E(', '.join(roots))}</b> &nbsp;|&nbsp; "
      f"Generated {E(now_iso())} &nbsp;|&nbsp; Mode: <b>{'Passive + authorised active checks' if active else 'Passive only'}</b>"
      + (f" &nbsp;|&nbsp; Authorisation ref: <b>{E(meta.get('AUTH_REF'))}</b>" if meta.get("AUTH_REF") else "")
      + f" &nbsp;|&nbsp; easm-recon {E(meta.get('VERSION', ''))}</div></header>")
    nav = [("summary", "Summary"), ("findings", "Findings"), ("cves", "Vulnerability intel"), ("assets", "Assets"),
           ("webinv", "Web inventory"), ("email", "Email & DNS"), ("tls", "TLS"), ("components", "Components"), ("urls", "URL intel")]
    if cmp_:
        nav.append(("changes", "Changes"))
    nav.append(("method", "Methodology"))
    w("<nav>" + "".join(f"<a href='#{a}'>{E(b)}</a>" for a, b in nav) + "</nav><main>")

    # ------------------------------------------------------------------ summary
    w("<section id='summary'><h2>Executive summary</h2><div class='kpis'>")
    for v, l in ((len(assets), "Hostnames discovered"), (len(resolved), "Resolving hosts"), (live_web, "Hosts with web services"),
                 (open_ports, "Open ports observed"), (len(findings), "Findings"), (counts["critical"] + counts["high"], "Critical + High"),
                 (len(cves), "CVEs correlated"), (kev_n, "CISA KEV CVEs")):
        w(f"<div class='kpi'><div class='v'>{v}</div><div class='l'>{E(l)}</div></div>")
    w("</div><div class='card'><b>Findings by severity</b><div class='bar'>")
    tot = max(1, len(findings))
    for s in SEVS:
        if counts[s]:
            w(f"<span style='width:{counts[s] * 100 / tot:.2f}%;background:var(--{s})' title='{s}: {counts[s]}'></span>")
    w("</div><div class='legend'>" + "".join(f"<span><i style='background:var(--{s})'></i>{s.title()}: {counts[s]}</span>" for s in SEVS) + "</div>")
    w("<h3>Key observations</h3><ul class='obs'>" + "".join(f"<li>{o}</li>" for o in _observations(findings, cves, assets, root_dns, comps)) + "</ul>")
    top = [f for f in findings if f["severity"] in ("critical", "high", "medium")][:10]
    if top:
        w("<h3>Top priority items</h3><div class='tbl'><table><thead><tr><th class='nosort'>Severity</th><th class='nosort'>Finding</th>"
          "<th class='nosort'>Assets</th><th class='nosort'>Confidence</th></tr></thead><tbody>")
        for f in top:
            w(f"<tr><td>{_badge(f['severity'])}</td><td><a href='#{E(f['id'])}'>{E(f['title'])}</a>"
              f"{' <span class=kev>KEV</span>' if f.get('kev') else ''}</td><td class='small'>{E(', '.join(f['assets'][:3]))}"
              f"{' +' + str(len(f['assets']) - 3) if len(f['assets']) > 3 else ''}</td><td>{_conf(f['confidence'])}</td></tr>")
        w("</tbody></table></div>")
    if not active:
        w("<p class='note'>Only passive collection was performed. Port, service, web, TLS and template-based vulnerability checks "
          "were not executed; findings about services come from third-party passive data (Shodan InternetDB) and may be stale.</p>")
    w("</div></section>")

    # ------------------------------------------------------------------ findings
    cats = sorted({f["category"] for f in findings})
    w("<section id='findings'><h2>Findings</h2><div class='controls'>")
    for s in SEVS:
        w(f"<button class='chip' data-sev='{s}'>{s.title()} ({counts[s]})</button>")
    w("<input id='fq' placeholder='Search findings, hosts, CVEs...'><select id='fcat'><option value=''>All categories</option>"
      + "".join(f"<option>{E(c)}</option>" for c in cats) + "</select><button class='chip' id='expand'>Expand all</button>"
      "<button class='chip' id='collapse'>Collapse all</button><span class='muted small' id='fcount'></span></div>")
    if not findings:
        w("<p class='muted'>No findings.</p>")
    for f in findings:
        extra = []
        if f.get("cvss") is not None:
            extra.append(f"CVSS {f['cvss']}")
        if f.get("epss") is not None:
            extra.append(f"EPSS {f['epss'] * 100:.1f}%")
        w(f"<details class='f' id='{E(f['id'])}' data-sev='{E(f['severity'])}' data-cat='{E(f['category'])}'><summary>"
          f"{_badge(f['severity'])}<span><b>{E(f['title'])}</b>{' <span class=kev>KEV</span>' if f.get('kev') else ''}"
          f"<br><span class='muted small'>{E(f['id'])} &middot; {E(f['category'])}{' &middot; ' + E(' / '.join(extra)) if extra else ''}</span></span>"
          f"<span class='small muted'>{len(f['assets'])} asset(s)</span>{_conf(f['confidence'])}</summary><div class='body'>")
        w(f"<p>{E(f['description'])}</p><div class='kv'><b>Affected</b><span class='mono wrap'>{E(', '.join(f['assets'][:60]))}"
          f"{' ...' if len(f['assets']) > 60 else ''}</span><b>Remediation</b><span>{E(f['remediation'])}</span>"
          f"<b>Source</b><span class='mono'>{E(f.get('source'))}</span>")
        if f.get("cves"):
            w("<b>CVEs</b><span>" + " ".join(f"<a class='tag mono' href='https://nvd.nist.gov/vuln/detail/{E(c)}' target='_blank' rel='noopener'>{E(c)}</a>"
                                             for c in f["cves"][:25]) + (f" <span class='muted small'>(+{len(f.get('all_cves', [])) - 25} more)</span>" if len(f.get("all_cves", [])) > 25 else "") + "</span>")
        if f.get("references"):
            w("<b>References</b><span class='small'>" + "<br>".join(
                f"<a href='{E(r)}' target='_blank' rel='noopener noreferrer'>{E(r)}</a>" for r in f["references"][:6]
                if str(r).startswith(("http://", "https://"))) + "</span>")
        w("</div>")
        if f.get("evidence"):
            w("<h3>Evidence</h3><pre>" + E("\n".join(f["evidence"][:40])) + "</pre>")
        w("</div></details>")
    w("</section>")

    # ------------------------------------------------------------------ CVEs
    w("<section id='cves'><h2>Vulnerability intelligence</h2><p class='muted small'>CVEs correlated from version fingerprints (NVD), nuclei "
      "template matches and Shodan InternetDB. Ranked by priority = KEV, then CVSS and EPSS. Version-based matches are <i>potential</i> "
      "until confirmed; Linux distributions frequently back-port fixes without changing version strings.</p>")
    if cves:
        w("<div class='controls'><input data-filter='cvetbl' placeholder='Filter CVEs...'></div><div class='tbl'><table id='cvetbl' class='sortable'><thead><tr>"
          "<th>CVE</th><th>CVSS</th><th>Severity</th><th>EPSS</th><th>KEV</th><th>Component(s)</th><th>Assets</th><th>Source</th><th>Published</th>"
          "<th class='nosort'>Description</th></tr></thead><tbody>")
        for c in cves[:2000]:
            kev = c.get("kev") or {}
            w(f"<tr><td class='mono'><a href='https://nvd.nist.gov/vuln/detail/{E(c['id'])}' target='_blank' rel='noopener'>{E(c['id'])}</a></td>"
              f"<td data-v='{c.get('cvss') or 0}'>{E(c.get('cvss') if c.get('cvss') is not None else '-')}</td>"
              f"<td data-v='{SEV_ORDER.get(c.get('severity'), -1)}'>{_badge(c.get('severity'))}</td>"
              f"<td data-v='{c.get('epss') or 0}'>{(str(round(c['epss'] * 100, 2)) + '%') if c.get('epss') is not None else '-'}</td>"
              f"<td data-v='{1 if kev else 0}'>{('<span class=kev>KEV</span>' + (' <span class=small>ransomware</span>' if str(kev.get('ransomware', '')).lower() == 'known' else '')) if kev else ''}</td>"
              f"<td class='small'>{E(', '.join(c.get('components', [])))}</td>"
              f"<td class='small' data-v='{len(c.get('assets', []))}' title='{E(', '.join(c.get('assets', [])[:50]))}'>{len(c.get('assets', []))}: {E(', '.join(c.get('assets', [])[:3]))}</td>"
              f"<td class='small'>{E(', '.join(c.get('sources', [])))}</td><td class='small'>{E(c.get('published'))}</td>"
              f"<td class='small'>{E((c.get('description') or '')[:220])}</td></tr>")
        w("</tbody></table></div>")
    else:
        w("<p class='muted'>No CVEs correlated.</p>")
    w("</section>")

    # ------------------------------------------------------------------ assets
    w("<section id='assets'><h2>Asset inventory</h2><div class='controls'><input data-filter='assettbl' placeholder='Filter assets...'>"
      f"<span class='muted small'>{len(assets)} hostnames; risk score = weighted findings (0-100)</span></div>"
      "<div class='tbl'><table id='assettbl' class='sortable'><thead><tr><th>Host</th><th>Risk</th><th>Findings</th><th>IPs</th><th>ASN / CDN</th>"
      "<th>Ports</th><th class='nosort'>Web</th><th class='nosort'>Technology</th><th>Sources</th><th>Active scope</th></tr></thead><tbody>")
    for a in assets:
        risk = a.get("risk", 0)
        col = "var(--critical)" if risk >= 60 else "var(--high)" if risk >= 30 else "var(--medium)" if risk >= 10 else "var(--low)" if risk > 0 else "var(--line)"
        ports = sorted(a.get("ports", {}).values(), key=lambda p: p["port"])
        port_s = " ".join(f"<span class='tag mono' title='{E(' '.join(str(p.get(k, '')) for k in ('product', 'version', 'source')).strip())}'>{p['port']}</span>" for p in ports[:30])
        web_s = "<br>".join(f"<span class='mono small'>{E(x.get('status'))}</span> <a href='{E(x['url'])}' target='_blank' rel='noopener noreferrer'>{E(x['url'][:60])}</a> <span class='muted small'>{E(x.get('title', '')[:60])}</span>"
                            for x in a.get("web", [])[:4])
        tech_s = " ".join(f"<span class='tag'>{E(t)}</span>" for t in a.get("tech", [])[:12])
        w(f"<tr><td class='mono host'>{E(a['host'])}{'' if a.get('resolved') else ' <span class=muted small>(unresolved)</span>'}</td>"
          f"<td data-v='{risk}' style='white-space:nowrap'><span class='riskbar'><span style='width:{risk}%;background:{col}'></span></span>{risk}</td>"
          f"<td data-v='{a.get('finding_count', 0)}'>{a.get('finding_count', 0)}</td>"
          f"<td class='mono small'>{E(', '.join(a.get('ips', [])[:4]))}{' ...' if len(a.get('ips', [])) > 4 else ''}</td>"
          f"<td class='small'>{E('; '.join(a.get('asn', [])[:2]))}{'<br><b>' + E(a['cdn']) + '</b>' if a.get('cdn') else ''}</td>"
          f"<td data-v='{len(ports)}'>{port_s}</td><td>{web_s}</td><td>{tech_s}</td><td class='small'>{E(', '.join(a.get('sources', [])))}</td>"
          f"<td>{'<span class=ok>yes</span>' if a.get('in_active_scope') else '<span class=muted>no</span>'}</td></tr>")
    w("</tbody></table></div></section>")

    # ------------------------------------------------------------------ web inventory
    w("<section id='webinv'><h2>Web asset inventory</h2>")
    if webrows:
        sc = {}
        for r in webrows:
            k = f"{r['status'] // 100}xx" if r["status"] else "n/a"
            sc[k] = sc.get(k, 0) + 1
        w(f"<p class='muted small'>httpx probe of the approved hosts (status, title, technology, IP, CNAME, redirect). "
          f"{len(webrows)} live endpoint(s) on {len({r['host'] for r in webrows})} host(s): "
          f"{E(', '.join(f'{k}={v}' for k, v in sorted(sc.items())))}. Raw output: <span class='mono'>findings/web-assets.csv</span></p>"
          "<div class='controls'><input data-filter='webtbl' placeholder='Filter web assets...'></div>"
          "<div class='tbl'><table id='webtbl' class='sortable'><thead><tr><th>Host</th><th>URL</th><th>Status</th><th>Title</th>"
          "<th class='nosort'>Technology</th><th>IP</th><th>CNAME</th><th>Redirect</th><th>Server</th></tr></thead><tbody>")
        for r in webrows:
            st = r["status"]
            scls = "ok" if st and st < 300 else "warn" if st and st < 400 else "bad" if st else "muted"
            w(f"<tr><td class='mono host'>{E(r['host'])}</td>"
              f"<td class='small wrap'><a href='{E(r['url'])}' target='_blank' rel='noopener noreferrer'>{E(r['url'][:90])}</a></td>"
              f"<td data-v='{st or 0}'><span class='{scls}'>{E(st if st else '-')}</span></td>"
              f"<td class='small'>{E(r['title'][:120])}</td>"
              f"<td class='small'>{E(r['tech'][:200])}</td>"
              f"<td class='mono small'>{E(', '.join(r['ips'][:4]))}</td>"
              f"<td class='mono small wrap'>{E(', '.join(r['cnames'][:3]))}</td>"
              f"<td class='small wrap'>{E(r['location'][:120])}</td>"
              f"<td class='small'>{E(r['webserver'])}</td></tr>")
        w("</tbody></table></div>")
    elif webrows is not None:
        w("<p class='muted'>Web inventory ran but no live web endpoints were found on the approved hosts.</p>")
    else:
        w("<p class='muted'>No web inventory (active checks not run, or ENABLE_WEB_INVENTORY=0).</p>")
    w("</section>")

    # ------------------------------------------------------------------ email & DNS
    def yes(v, good="present", bad="missing"):
        return f"<span class='ok'>{good}</span>" if v else f"<span class='bad'>{bad}</span>"

    w("<section id='email'><h2>Email & DNS posture</h2>")
    if root_dns:
        w("<div class='tbl'><table><thead><tr><th class='nosort'>Domain</th><th class='nosort'>MX</th><th class='nosort'>SPF</th><th class='nosort'>DMARC</th>"
          "<th class='nosort'>DKIM (common selectors)</th><th class='nosort'>MTA-STS</th><th class='nosort'>TLS-RPT</th><th class='nosort'>DNSSEC</th>"
          "<th class='nosort'>CAA</th><th class='nosort'>Wildcard</th><th class='nosort'>AXFR</th></tr></thead><tbody>")
        for d, i in root_dns.items():
            rec = i.get("records", {})
            dm = (i.get("dmarc") or [""])[0]
            pol = re.search(r"p=(\w+)", dm or "")
            dm_s = (f"<span class='{'ok' if pol and pol.group(1).lower() in ('reject', 'quarantine') else 'warn'}'>p={E(pol.group(1))}</span>" if pol else yes(False))
            spf = (i.get("spf") or [""])[0]
            allm = re.search(r"([+?~-]?)all\b", spf or "")
            spf_s = yes(False) if not spf else (f"<span class='{'ok' if allm and allm.group(1) in ('-', '~') else 'warn'}'>{E((allm.group(0) if allm else 'no all'))}</span>")
            ax = i.get("axfr")
            ax_s = "<span class='muted'>not tested</span>" if ax is None else ("<span class='bad'>ALLOWED</span>" if any(v.get("allowed") for v in ax.values()) else "<span class='ok'>refused</span>")
            w(f"<tr><td class='mono'>{E(d)}</td><td class='small'>{E(', '.join(rec.get('MX', [])[:3])) or '<span class=muted>none</span>'}</td>"
              f"<td title='{E(spf)}'>{spf_s}</td><td title='{E(dm)}'>{dm_s}</td><td class='small'>{E(', '.join(i.get('dkim', {}).keys())) or '<span class=muted>not found</span>'}</td>"
              f"<td>{yes(i.get('mta_sts'))}</td><td>{yes(i.get('tls_rpt'))}</td><td>{yes(rec.get('DS'), 'signed', 'unsigned')}</td>"
              f"<td>{yes(rec.get('CAA'))}</td><td>{'<span class=warn>yes</span>' if (i.get('wildcard') or {}).get('enabled') else 'no'}</td><td>{ax_s}</td></tr>")
        w("</tbody></table></div>")
        w("<h3>Raw records</h3>")
        for d, i in root_dns.items():
            lines = [f"{rr}: {v}" for rr, vals in i.get("records", {}).items() for v in vals]
            lines += [f"DMARC: {v}" for v in i.get("dmarc", [])] + [f"MTA-STS: {v}" for v in i.get("mta_sts", [])] + [f"TLS-RPT: {v}" for v in i.get("tls_rpt", [])]
            w(f"<details><summary class='mono'>{E(d)}</summary><pre>{E(chr(10).join(lines)[:20000])}</pre></details>")
    else:
        w("<p class='muted'>DNS posture data not available (dig missing?).</p>")
    w("</section>")

    # ------------------------------------------------------------------ TLS
    tls_rows = [t for a in assets for t in a.get("tls", [])]
    w("<section id='tls'><h2>TLS certificates & protocols</h2>")
    if tls_rows:
        w("<div class='controls'><input data-filter='tlstbl' placeholder='Filter...'></div><div class='tbl'><table id='tlstbl' class='sortable'><thead><tr><th>Endpoint</th><th>Issuer</th><th>Subject CN</th>"
          "<th>Expires (days)</th><th>Trusted</th><th>Negotiated</th><th>TLS1.0</th><th>TLS1.1</th><th>TLS1.3</th></tr></thead><tbody>")

        def pv(v):
            return "<span class='muted'>n/a</span>" if v is None else ("<span class='bad'>yes</span>" if v else "<span class='ok'>no</span>")
        for t in sorted(tls_rows, key=lambda t: (t.get("days_to_expiry") if t.get("days_to_expiry") is not None else 9999)):
            if t.get("error"):
                w(f"<tr><td class='mono'>{E(t['host'])}:{t['port']}</td><td colspan='8' class='muted small'>{E(t['error'])}</td></tr>")
                continue
            d = t.get("days_to_expiry")
            dcls = "bad" if d is not None and d < 0 else "warn" if d is not None and d <= 30 else ""
            p = t.get("protocols") or {}
            w(f"<tr><td class='mono'>{E(t['host'])}:{t['port']}</td><td class='small'>{E(t.get('issuer'))}</td><td class='small mono'>{E(t.get('subject_cn'))}</td>"
              f"<td data-v='{d if d is not None else 9999}' class='{dcls}'>{E(d)}</td>"
              f"<td>{'<span class=ok>yes</span>' if t.get('trusted') else '<span class=bad>no</span>'}</td><td class='small'>{E(t.get('negotiated_protocol'))}</td>"
              f"<td>{pv(p.get('TLSv1.0'))}</td><td>{pv(p.get('TLSv1.1'))}</td><td>{'<span class=ok>yes</span>' if p.get('TLSv1.3') else ('<span class=muted>n/a</span>' if p.get('TLSv1.3') is None else 'no')}</td></tr>")
        w("</tbody></table></div>")
    else:
        w("<p class='muted'>No TLS data (active checks not run or no HTTPS services).</p>")
    w("</section>")

    # ------------------------------------------------------------------ components
    w("<section id='components'><h2>Software components</h2>")
    if comps:
        w("<div class='tbl'><table class='sortable'><thead><tr><th>Component</th><th>Version</th><th>CVEs</th><th>Assets</th><th>Detected by</th><th>Back-port suspected</th></tr></thead><tbody>")
        for c in sorted(comps, key=lambda c: -c.get("cve_count", 0)):
            w(f"<tr><td>{E(c['name'])}</td><td class='mono'>{E(c['version'])}</td><td data-v='{c.get('cve_count', 0)}'>{c.get('cve_count', 0)}</td>"
              f"<td class='small' title='{E(', '.join(c['assets']))}'>{len(c['assets'])}: {E(', '.join(c['assets'][:3]))}</td><td class='small'>{E(', '.join(c['sources']))}</td>"
              f"<td>{'<span class=warn>yes</span>' if c.get('backport_suspected') else 'no'}</td></tr>")
        w("</tbody></table></div>")
    else:
        w("<p class='muted'>No versioned components identified.</p>")
    w("</section>")

    # ------------------------------------------------------------------ URLs
    w(f"<section id='urls'><h2>URL intelligence</h2><p class='muted small'>{urls.get('total_urls', 0)} unique historical/crawled URLs analysed. "
      "Historical URLs may no longer exist; validate before acting.</p>")
    for k, v in (urls.get("categories") or {}).items():
        if v.get("count"):
            w(f"<details><summary><b>{E(k.replace('_', ' ').title())}</b> <span class='muted'>({v['count']})</span></summary><pre>{E(chr(10).join(v.get('samples', [])))}</pre></details>")
    w("</section>")

    # ------------------------------------------------------------------ changes
    if cmp_:
        w("<section id='changes'><h2>Changes since previous run</h2>")
        if cmp_.get("error"):
            w(f"<p class='muted'>{E(cmp_['error'])}</p>")
        else:
            w(f"<p class='muted small'>Compared with {E(cmp_['prev_dir'])}</p><div class='kpis'>"
              f"<div class='kpi'><div class='v'>{len(cmp_['new_hosts'])}</div><div class='l'>New hosts</div></div>"
              f"<div class='kpi'><div class='v'>{len(cmp_['gone_hosts'])}</div><div class='l'>Hosts gone</div></div>"
              f"<div class='kpi'><div class='v'>{len(cmp_['new_findings'])}</div><div class='l'>New findings</div></div>"
              f"<div class='kpi'><div class='v'>{len(cmp_['resolved_findings'])}</div><div class='l'>Resolved findings</div></div></div>")
            if cmp_["new_findings"]:
                w("<h3>New findings</h3><ul>" + "".join(f"<li>{_badge(f['severity'])} <a href='#{E(f['id'])}'>{E(f['title'])}</a></li>" for f in cmp_["new_findings"][:100]) + "</ul>")
            if cmp_["new_hosts"]:
                w("<h3>New hosts</h3><pre>" + E("\n".join(cmp_["new_hosts"][:500])) + "</pre>")
            if cmp_["resolved_findings"]:
                w("<h3>No longer observed</h3><ul>" + "".join(f"<li>{_badge(f['severity'])} {E(f['title'])}</li>" for f in cmp_["resolved_findings"][:100]) + "</ul>")
        w("</section>")

    # ------------------------------------------------------------------ methodology
    w("<section id='method'><h2>Methodology, confidence & limitations</h2><div class='card'>"
      "<h3>Workflow</h3><ol>"
      "<li><b>Passive discovery</b> - subfinder, amass (passive), assetfinder/findomain (if installed), Certificate Transparency (crt.sh, Cert Spotter), web-archive hostnames.</li>"
      "<li><b>Resolution & enrichment</b> - dnsx, Team Cymru ASN data, CDN identification, Shodan InternetDB (passive ports/CPEs/CVEs, CDN IPs skipped).</li>"
      "<li><b>DNS & e-mail posture</b> - SPF, DMARC, DKIM (common selectors), MTA-STS, TLS-RPT, DNSSEC, CAA, wildcard detection.</li>"
      "<li><b>Historical URLs</b> - gau / waybackurls classification (secrets in URLs, sensitive files, API docs, admin paths).</li>"
      "<li><b>Authorised active checks</b> (only after explicit scope review and confirmation) - rate-limited port scan (naabu/nmap), "
      "service fingerprinting (nmap -sV), HTTP probing and a low-rate web asset inventory of the approved hosts (httpx), TLS posture, optional crawling (katana), non-intrusive nuclei templates "
      "(dos/fuzz/intrusive/brute-force/default-login tags excluded, no out-of-band interactions), AXFR test for in-scope roots.</li>"
      "<li><b>Correlation</b> - versions mapped to NVD CPEs with local range matching, enriched with CISA KEV and FIRST EPSS.</li></ol>"
      "<h3>Confidence levels</h3><ul><li><span class='conf conf-confirmed'>confirmed</span> directly observed (e.g. open port, expired certificate, AXFR response).</li>"
      "<li><span class='conf conf-firm'>firm</span> matched by a specific detection (nuclei template, takeover fingerprint).</li>"
      "<li><span class='conf conf-potential'>potential</span> inferred from version banners or third-party passive data; requires validation.</li>"
      "<li><span class='conf conf-tentative'>tentative</span> heuristic signal (e.g. back-ported package, login page by title).</li></ul>"
      "<h3>Limitations</h3><ul><li>Passive sources are incomplete and can be stale; some sources need API keys (configure subfinder provider-config).</li>"
      "<li>Version-based CVE mapping cannot see vendor back-ports, compensating controls or non-default configurations.</li>"
      "<li>Hosts behind CDNs/WAFs receive reduced port coverage by design. Shared hosting IPs may carry data unrelated to the target.</li>"
      "<li>Absence of a finding is not evidence of absence of vulnerability; this is not a substitute for a full penetration test.</li></ul>")
    w(f"<h3>Run details</h3><pre>{E(chr(10).join(f'{k}={v}' for k, v in meta.items()))}\nNVD requests: {E(amete.get('nvd_requests'))}  API key: {E(amete.get('nvd_api_key'))}  "
      f"NVD unreachable: {E(amete.get('nvd_unreachable'))}  KEV entries loaded: {E(amete.get('kev_entries'))}</pre>")
    w(f"<h3>Tool inventory</h3><pre>{E(inventory[:20000])}</pre></div></section>")
    w(f"</main><footer>Generated by easm-recon. Contains sensitive security information - handle as CONFIDENTIAL. "
      f"Evidence integrity: see report/SHA256SUMS.txt</footer><script>{JS}</script></body></html>")

    os.makedirs(f"{run_dir}/report", exist_ok=True)
    with open(f"{run_dir}/report/index.html", "w", encoding="utf-8") as fh:
        fh.write("".join(P))
    _exports(run_dir, findings, assets, cves, counts, roots, meta, cmp_, webrows)
    print(f"{run_dir}/report/index.html")
    return 0


def _exports(run_dir, findings, assets, cves, counts, roots, meta, cmp_, webrows=None):
    with open(f"{run_dir}/report/findings.csv", "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["id", "severity", "title", "category", "confidence", "assets", "cvss", "epss", "kev", "cves", "source", "remediation"])
        for f in findings:
            wr.writerow([f["id"], f["severity"], f["title"], f["category"], f["confidence"], " ".join(f["assets"]), f.get("cvss") or "",
                         f.get("epss") if f.get("epss") is not None else "", "yes" if f.get("kev") else "", " ".join(f.get("cves", [])),
                         f.get("source", ""), f["remediation"]])
    with open(f"{run_dir}/report/assets.csv", "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["host", "root", "resolved", "ips", "cnames", "asn", "cdn", "ports", "web_urls", "tech", "risk", "findings", "sources"])
        for a in assets:
            wr.writerow([a["host"], a.get("root"), a.get("resolved"), " ".join(a.get("ips", [])), " ".join(a.get("cnames", [])),
                         "; ".join(a.get("asn", [])), a.get("cdn", ""), " ".join(str(p["port"]) for p in a.get("ports", {}).values()),
                         " ".join(x["url"] for x in a.get("web", [])), "; ".join(a.get("tech", [])), a.get("risk", 0),
                         a.get("finding_count", 0), " ".join(a.get("sources", []))])
    with open(f"{run_dir}/report/cves.csv", "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["cve", "cvss", "severity", "epss", "percentile", "kev", "kev_ransomware", "components", "assets", "sources", "published"])
        for c in cves:
            k = c.get("kev") or {}
            wr.writerow([c["id"], c.get("cvss") or "", c.get("severity"), c.get("epss") if c.get("epss") is not None else "",
                         c.get("percentile") if c.get("percentile") is not None else "", "yes" if k else "", k.get("ransomware", "") if k else "",
                         "; ".join(c.get("components", [])), " ".join(c.get("assets", [])), " ".join(c.get("sources", [])), c.get("published", "")])
    write_json(f"{run_dir}/report/findings.json", findings)
    md = [f"# EASM summary - {', '.join(roots)}", "", f"Generated: {now_iso()}  ", f"Mode: {'active+passive' if meta.get('ACTIVE_RAN') == '1' else 'passive'}", "",
          "| Severity | Count |", "|---|---|"] + [f"| {s} | {counts[s]} |" for s in SEVS] + [
          "", f"Hosts discovered: {len(assets)}  ", f"Resolving: {sum(1 for a in assets if a.get('resolved'))}  ",
          f"CVEs correlated: {len(cves)} (KEV: {sum(1 for c in cves if c.get('kev'))})", "", "## Top findings", ""]
    md += [f"- **{f['severity'].upper()}** {f['title']} - {', '.join(f['assets'][:3])}" for f in findings[:25]]
    if webrows is not None:
        md += ["", "## Web inventory", "", f"Live web endpoints: {len(webrows)} on {len({r['host'] for r in webrows})} host(s) "
               "(full httpx output: `findings/web-assets.csv`)", ""]
        if webrows:
            md += ["| Host | URL | Status | Title | Technology | IP |", "|---|---|---|---|---|---|"]
            cell = lambda v: str(v).replace("|", "\\|").replace("\n", " ")[:100]  # noqa: E731
            md += [f"| {cell(r['host'])} | {cell(r['url'])} | {r['status'] or ''} | {cell(r['title'])} | {cell(r['tech'])} | "
                   f"{cell(', '.join(r['ips'][:2]))} |" for r in webrows[:200]]
    if cmp_ and not cmp_.get("error"):
        md += ["", "## Changes", f"- New hosts: {len(cmp_['new_hosts'])}", f"- New findings: {len(cmp_['new_findings'])}",
               f"- Resolved findings: {len(cmp_['resolved_findings'])}"]
    with open(f"{run_dir}/report/summary.md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
