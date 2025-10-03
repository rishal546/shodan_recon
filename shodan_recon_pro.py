#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shodan Recon Pro - Fully working, content-rich Shodan recon tool for bug bounty hunters
File: shodan_recon_pro.py
Author: Mohammed Rishal 

Features (complete & robust):
- Passive subdomain enumeration (crt.sh) + optional local tools (subfinder/amass) if available
- Fast DNS resolution (dnsx if installed) with socket fallback
- Shodan domain search (manual limit handling compatible with older shodan packages)
- Parallel Shodan host lookups
- Extracts: ports, service banners, HTTP status/title/server headers, org, ASN, location (city/country/coords), tags
- CVE extraction from Shodan and optional enrichment from NVD (best-effort)
- Saves raw JSON (domain & per-host) + hosts.json + summary.json
- Generates a contentful HTML report with charts (Chart.js) and sortable tables
- CLI flags for tuning and safety (passive-only by default)

Requirements (pip):
  pip install shodan requests jinja2 tqdm python-dateutil

Optional system tools (recommended but not required):
  subfinder, amass, dnsx

Usage:
  python3 shodan_recon_pro.py --domains oklink.com --api-key YOUR_SHODAN_API_KEY --outdir out_oklink --html-report

Notes:
 - This tool performs passive reconnaissance only (Shodan + public sources). Do not perform active scanning unless permitted.
 - Keep your API key secret.
"""
import shodan
import argparse
import json
import os
import socket
import subprocess
import shlex
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import requests
from dateutil import parser as dateparser
from jinja2 import Template
from tqdm import tqdm

# ---------------------- Configuration ----------------------
NVD_CVE_URL_V2 = "https://services.nvd.nist.gov/rest/json/cve/2.0/{}"
USER_AGENT = "ShodanReconPro/2.0 (+https://example.invalid/)"

HTML_TEMPLATE = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Shodan Recon Pro Report - {{title}}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body{font-family: Inter, Arial, Helvetica, sans-serif;background:#0f172a;color:#e6eef8;margin:0;padding:20px}
    .container{max-width:1200px;margin:0 auto}
    .card{background:#0b1220;border-radius:12px;padding:18px;margin-bottom:12px;box-shadow:0 6px 18px rgba(2,6,23,.6)}
    h1,h2{margin:0 0 12px 0}
    table{width:100%;border-collapse:collapse}
    th,td{padding:8px;text-align:left;border-bottom:1px solid rgba(255,255,255,.04)}
    th{position:sticky;top:0;background:rgba(11,18,32,.9)}
    .muted{color:#94a3b8}
    code{background:#081022;padding:2px 6px;border-radius:6px}
    .small{font-size:0.9rem}
    .sev-critical{color:#ff6b6b;font-weight:700}
    .sev-high{color:#ffb86b}
    .sev-medium{color:#ffd86b}
    .sev-low{color:#9be6a8}
    .nowrap{white-space:nowrap}
    .flex{display:flex;gap:12px;align-items:center}
    .pill{background:#081022;padding:6px 10px;border-radius:999px;font-size:0.9rem}
    a{color:#7ee3c5}
    /* table sorting helper */
    table.sortable th{cursor:pointer}
  </style>
</head>
<body>
  <div class="container">
    <h1>Shodan Recon Pro — Report</h1>
    <p class="muted">Generated: {{ now }}</p>

    <div class="card">
      <h2>Summary</h2>
      <p class="small">Domains: {{ domain_list|join(', ') }} &nbsp;|&nbsp; Subdomains: {{ stats.subdomains }} &nbsp;|&nbsp; IPs: {{ stats.ips }} &nbsp;|&nbsp; Raw hosts: {{ stats.host_entries }} &nbsp;|&nbsp; CVEs: {{ stats.cves }}</p>
    </div>

    <div class="card">
      <h2>Top Charts</h2>
      <canvas id="chartPorts" width="800" height="250"></canvas>
      <canvas id="chartCVSSeverity" width="800" height="250" style="margin-top:12px"></canvas>
    </div>

    <div class="card">
      <h2>Hosts & Services</h2>
      <table class="sortable" id="hostsTable">
        <thead>
          <tr>
            <th>IP</th>
            <th>Port</th>
            <th>Hostnames</th>
            <th>Org / ASN</th>
            <th>Location</th>
            <th>Product / Version</th>
            <th>HTTP Title</th>
            <th>Status</th>
            <th>Server</th>
            <th>Tags</th>
            <th>Vulns</th>
          </tr>
        </thead>
        <tbody>
        {% for h in hosts %}
          <tr>
            <td><code>{{ h.ip }}</code></td>
            <td class="nowrap">{{ h.port }}</td>
            <td class="small">{{ h.hostnames|join(', ') }}</td>
            <td class="small">{{ h.org or '-' }}<br/><span class="muted">{{ h.asn or '-' }}</span></td>
            <td class="small">{{ h.city or '-' }}, {{ h.country or '-' }}<br/><span class="muted">{{ h.latitude or '' }} {{ h.longitude or '' }}</span></td>
            <td class="small">{{ h.product or '-' }} {{ h.version or '' }}</td>
            <td class="small">{{ h.http_title or '-' }}</td>
            <td class="small">{{ h.http_status or '-' }}</td>
            <td class="small">{{ h.server or '-' }}</td>
            <td class="small">{{ h.tags|join(', ') if h.tags else '-' }}</td>
            <td class="small">{% if h.vulns %}{% for v in h.vulns %}<a href="https://nvd.nist.gov/vuln/detail/{{ v.id }}" target="_blank">{{ v.id }}</a>{% if not loop.last %}, {% endif %}{% endfor %}{% else %}-{% endif %}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Raw JSON & Files</h2>
      <p class="muted">Raw JSON files were saved alongside this report in the output folder.</p>
    </div>

  </div>

  <!-- Charts (Chart.js CDN) -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    const portsLabels = {{ chart_ports.labels|tojson }};
    const portsCounts = {{ chart_ports.counts|tojson }};
    const ctx = document.getElementById('chartPorts').getContext('2d');
    new Chart(ctx, {type:'bar', data:{labels:portsLabels, datasets:[{label:'Top Ports',data:portsCounts}]}, options:{responsive:true}});

    const sevLabels = {{ chart_severity.labels|tojson }};
    const sevCounts = {{ chart_severity.counts|tojson }};
    const ctx2 = document.getElementById('chartCVSSeverity').getContext('2d');
    new Chart(ctx2, {type:'pie', data:{labels:sevLabels, datasets:[{data:sevCounts}]}, options:{responsive:true}});

    // Simple table sort (by clicking header) - lightweight
    document.querySelectorAll('table.sortable th').forEach((th, idx) => {
      th.addEventListener('click', () => {
        const table = th.closest('table');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const asc = !th.classList.contains('asc');
        rows.sort((a,b) => {
          const aText = a.children[idx].innerText.trim();
          const bText = b.children[idx].innerText.trim();
          return (aText> bText) ? (asc?1:-1) : (aText< bText ? (asc?-1:1) : 0);
        });
        th.classList.toggle('asc', asc);
        rows.forEach(r => tbody.appendChild(r));
      });
    });
  </script>
</body>
</html>
"""

# ---------------------- Helper utilities ----------------------

def run_cmd(cmd: List[str], timeout: int = 30) -> Optional[str]:
    """Run a command and return stdout (or None)."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout)
        return proc.stdout
    except Exception:
        return None


def check_tool(name: str) -> bool:
    return shutil_which(name) is not None


def shutil_which(cmd: str) -> Optional[str]:
    # fallback to shutil.which without importing shutil at top to reduce noise
    try:
        import shutil
        return shutil.which(cmd)
    except Exception:
        return None


def safe_get(d: Dict, *keys, default=None):
    cur = d
    try:
        for k in keys:
            cur = cur.get(k, {})
        if cur == {}:
            return default
        return cur
    except Exception:
        return default

# ---------------------- Core Class ----------------------

class ShodanRecon:
    def __init__(self, api_key: str, domains: List[str], outdir: str = 'shodan_recon_out', limit: int = 5000, parallel: int = 10, sleep: float = 0.5, use_system: bool = False, enrich_cve: bool = True):
        self.api_key = api_key
        self.domains = domains
        self.outdir = Path(outdir)
        self.limit = limit
        self.parallel = parallel
        self.sleep = sleep
        self.use_system = use_system
        self.enrich_cve_flag = enrich_cve

        self.client = shodan.Shodan(api_key)
        self.outdir.mkdir(parents=True, exist_ok=True)
        (self.outdir / 'raw').mkdir(exist_ok=True)

        self.subdomains: List[str] = []
        self.ip_map: Dict[str, List[str]] = {}  # ip -> list of subdomains
        self.host_entries: List[Dict[str, Any]] = []
        self.cve_store: Dict[str, Dict[str, Any]] = {}

    def validate(self):
        try:
            info = self.client.info()
            print(f"[+] Shodan API key validated. Plan: {info.get('plan')}, Queries left: {info.get('query_credits')}")
            return True
        except Exception as e:
            print(f"[!] Shodan API key validation failed: {e}")
            return False

    # ---------------- Subdomain enumeration ----------------
    def enum_subdomains(self, domain: str) -> List[str]:
        results = set()
        print(f"[+] Enumerating subdomains (crt.sh + optional local tools) for {domain}...")

        # crt.sh
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            r = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=20)
            if r.status_code == 200:
                js = r.json()
                for e in js:
                    name = e.get('name_value')
                    if not name:
                        continue
                    for n in str(name).split('\n'):
                        n = n.strip().lstrip('*.')
                        if n and n.endswith(domain):
                            results.add(n)
        except Exception:
            pass

        # optional: use subfinder/amass if requested
        if self.use_system:
            for tool in ('subfinder', 'amass'):
                if shutil_which(tool):
                    try:
                        if tool == 'subfinder':
                            out = run_cmd([tool, '-d', domain, '-silent'], timeout=40)
                        else:
                            out = run_cmd([tool, 'enum', '-passive', '-d', domain], timeout=60)
                        if out:
                            for line in out.splitlines():
                                line = line.strip()
                                if line:
                                    results.add(line)
                    except Exception:
                        pass

        res = sorted(results)
        print(f"    Found {len(res)} subdomains")
        return res

    # ---------------- DNS Resolution ----------------
    def resolve_ips(self, subdomains: List[str]) -> Dict[str, str]:
        ipmap = {}
        if not subdomains:
            return ipmap

        print(f"[+] Resolving {len(subdomains)} subdomains to IPs (dnsx if available)...")

        if self.use_system and shutil_which('dnsx'):
            # feed to dnsx to get faster resolution
            try:
                proc = subprocess.run(['dnsx', '-silent', '-a'], input='\n'.join(subdomains), text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
                out = proc.stdout
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        host = parts[0].strip()
                        ip = parts[1].strip()
                        ipmap[host] = ip
            except Exception:
                pass

        # fallback: socket.getaddrinfo
        for sub in subdomains:
            if sub in ipmap:
                continue
            try:
                addrs = socket.getaddrinfo(sub, None)
                if addrs:
                    # pick first IPv4
                    for a in addrs:
                        addr = a[4][0]
                        if addr.count('.') == 3:
                            ipmap[sub] = addr
                            break
            except Exception:
                continue

        print(f"    Resolved {len(ipmap)} subdomains to IPs")
        return ipmap

    # ---------------- Shodan domain search ----------------
    def shodan_domain_search(self, domain: str) -> List[Dict[str, Any]]:
        query = f"hostname:{domain}"
        print(f"[+] Performing Shodan domain search for {domain} (limit={self.limit})")
        results = []
        try:
            count = 0
            for r in self.client.search_cursor(query):
                results.append(r)
                count += 1
                if count >= self.limit:
                    break
        except Exception as e:
            print(f"    [!] Shodan search error: {e}")
        print(f"    Shodan domain search returned {len(results)} entries")
        return results

    # ---------------- Shodan host lookup ----------------
    def shodan_host_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            data = self.client.host(ip)
            return data
        except Exception:
            return None

    # ----------------- CVE enrichment ------------------
    def enrich_cve(self, cve_id: str) -> Dict[str, Any]:
        if cve_id in self.cve_store:
            return self.cve_store[cve_id]
        out = {'id': cve_id, 'cvss': None, 'summary': None}
        if not self.enrich_cve_flag:
            self.cve_store[cve_id] = out
            return out
        try:
            url = NVD_CVE_URL_V2.format(cve_id)
            r = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=12)
            if r.status_code == 200:
                js = r.json()
                vulns = js.get('vulnerabilities') or []
                if vulns:
                    # attempt to extract summary and score
                    try:
                        cve = vulns[0].get('cve', {})
                        descs = cve.get('descriptions', [])
                        if descs:
                            out['summary'] = descs[0].get('value')
                        metrics = vulns[0].get('cve', {}).get('metrics', {})
                        # try v3
                        if 'cvssMetricV31' in metrics:
                            out['cvss'] = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore')
                        elif 'cvssMetricV30' in metrics:
                            out['cvss'] = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore')
                    except Exception:
                        pass
        except Exception:
            pass
        self.cve_store[cve_id] = out
        return out

    # ---------------- Generate outputs ----------------
    def save_json(self, name: str, data: Any):
        path = self.outdir / name
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def run(self):
        # 1. enumerate subdomains for all domains
        all_subs = set()
        for d in self.domains:
            subs = self.enum_subdomains(d)
            for s in subs:
                all_subs.add(s)
        self.subdomains = sorted(all_subs)
        self.save_json('subdomains.json', self.subdomains)

        # 2. resolve ips
        ipmap = self.resolve_ips(self.subdomains)
        self.save_json('resolved.json', ipmap)

        # build set of IPs to lookup
        ip_set = set(ipmap.values())

        # 3. run domain-wide shodan searches (to capture entries not in subdomains list)
        domain_entries = []
        for d in self.domains:
            entries = self.shodan_domain_search(d)
            domain_entries.extend(entries)
            time.sleep(self.sleep)
        self.save_json('domain_search.json', domain_entries)

        # extract IPs from domain entries
        for e in domain_entries:
            ip = e.get('ip_str')
            if ip:
                ip_set.add(ip)

        ips = sorted(ip_set)
        print(f"[+] Total unique IPs to lookup via Shodan: {len(ips)}")

        # 4. Parallel host lookups
        hosts_parsed = []
        with ThreadPoolExecutor(max_workers=self.parallel) as exe:
            future_to_ip = {exe.submit(self.shodan_host_lookup, ip): ip for ip in ips}
            for fut in tqdm(as_completed(future_to_ip), total=len(future_to_ip), desc='Shodan host lookups'):
                ip = future_to_ip[fut]
                try:
                    data = fut.result()
                except Exception:
                    data = None
                if not data:
                    continue
                # save per-host raw
                raw_path = self.outdir / 'raw' / f"{ip}.json"
                with open(raw_path, 'w') as rf:
                    json.dump(data, rf, indent=2, default=str)

                # parse services
                host_common = {
                    'ip': data.get('ip_str'),
                    'org': data.get('org'),
                    'asn': data.get('asn'),
                    'country': data.get('country_name'),
                    'city': data.get('city'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'hostnames': data.get('hostnames') or [],
                    'tags': data.get('tags') or []
                }

                for s in data.get('data', []):
                    entry = host_common.copy()
                    entry.update({
                        'port': s.get('port'),
                        'transport': s.get('transport'),
                        'product': s.get('product'),
                        'version': s.get('version'),
                        'server': safe_extract_http(s, 'server'),
                        'http_status': safe_extract_http(s, 'status'),
                        'http_title': safe_extract_http(s, 'title'),
                        'data': s.get('data') or s.get('banner') or '',
                        'timestamp': s.get('timestamp')
                    })

                    # extract vulns for this service
                    vulns = s.get('vulns') or {}
                    if isinstance(vulns, dict):
                        vuln_keys = list(vulns.keys())
                    elif isinstance(vulns, list):
                        vuln_keys = vulns
                    else:
                        vuln_keys = []

                    entry['vulns'] = []
                    for v in vuln_keys:
                        try:
                            # normalize CVE id
                            vid = v.strip()
                            entry['vulns'].append({'id': vid})
                            # enrich
                            self.enrich_cve(vid)
                        except Exception:
                            continue

                    hosts_parsed.append(entry)

                time.sleep(self.sleep)

        self.host_entries = hosts_parsed
        # stats
        stats = {
            'domains': self.domains,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'subdomains': len(self.subdomains),
            'ips': len(ips),
            'host_entries': len(self.host_entries),
            'cves': len(self.cve_store)
        }

        # save outputs
        self.save_json('hosts.json', self.host_entries)
        self.save_json('summary.json', stats)
        self.save_json('cves.json', self.cve_store)

        # prepare chart data
        port_counts: Dict[int, int] = {}
        severity_counts = {'critical':0,'high':0,'medium':0,'low':0,'unknown':0}
        for h in self.host_entries:
            p = h.get('port')
            if p:
                port_counts[p] = port_counts.get(p,0)+1
            for v in h.get('vulns', []):
                vid = v.get('id')
                info = self.cve_store.get(vid) or {}
                score = info.get('cvss')
                label = score_to_label(score)
                severity_counts[label] = severity_counts.get(label,0)+1

        top_ports = sorted(port_counts.items(), key=lambda x: -x[1])[:12]
        chart_ports = {'labels':[str(p[0]) for p in top_ports], 'counts':[p[1] for p in top_ports]}
        chart_sev = {'labels': list(severity_counts.keys()), 'counts': list(severity_counts.values())}

        # generate html
        if True:
            tpl = Template(HTML_TEMPLATE)
            html = tpl.render(title=','.join(self.domains), now=datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'), domain_list=self.domains, stats=stats, hosts=self.host_entries, chart_ports=chart_ports, chart_severity=chart_sev)
            html_path = self.outdir / f"shodan_report_{int(time.time())}.html"
            with open(html_path, 'w') as hf:
                hf.write(html)
            print(f"[+] HTML report generated: {html_path}")

        print("[+] Done. All outputs saved in:", str(self.outdir))

# ---------------------- Helpers ----------------------

def safe_extract_http(s: Dict[str, Any], key: str) -> Optional[Any]:
    # many shodan service entries include an 'http' object
    try:
        http = s.get('http') or {}
        return http.get(key)
    except Exception:
        # fallback: attempt to parse 'data' for title (not perfect)
        if key == 'title' and s.get('data'):
            # naive title extraction
            try:
                text = s.get('data')
                start = text.find('<title>')
                if start != -1:
                    end = text.find('</title>', start)
                    if end != -1:
                        return text[start+7:end].strip()
            except Exception:
                return None
        return None


def score_to_label(score: Optional[float]) -> str:
    try:
        if score is None:
            return 'unknown'
        s = float(score)
        if s >= 9.0:
            return 'critical'
        if s >= 7.0:
            return 'high'
        if s >= 4.0:
            return 'medium'
        return 'low'
    except Exception:
        return 'unknown'

# ---------------------- CLI ----------------------

def parse_args():
    p = argparse.ArgumentParser(description='Shodan Recon Pro - passive Shodan recon')
    p.add_argument('--domains', required=True, help='Comma-separated target domains (e.g. oklink.com)')
    p.add_argument('--api-key', required=True, help='Shodan API key')
    p.add_argument('--outdir', default='shodan_recon_out', help='Output directory')
    p.add_argument('--limit', type=int, default=5000, help='Max results per domain from Shodan')
    p.add_argument('--parallel', type=int, default=10, help='Number of parallel host lookups')
    p.add_argument('--sleep', type=float, default=0.5, help='Sleep seconds between API hits')
    p.add_argument('--use-system-tools', action='store_true', help='Use local tools (subfinder/dnsx) if installed')
    p.add_argument('--no-cve-enrich', action='store_true', help='Skip NVD CVE enrichment (faster)')
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    domains = [d.strip() for d in args.domains.split(',') if d.strip()]

    tool = ShodanRecon(api_key=args.api_key, domains=domains, outdir=args.outdir, limit=args.limit, parallel=args.parallel, sleep=args.sleep, use_system=args.use_system_tools, enrich_cve=not args.no_cve_enrich)
    if not tool.validate():
        sys.exit(1)
    tool.run()
