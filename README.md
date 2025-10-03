# Shodan Recon Pro

**Shodan Recon Pro** — Advanced Shodan-based reconnaissance automation for bug bounty hunters and penetration testers.

**Author:** Mohammed Rishal

---

## Overview

Shodan Recon Pro is a Python CLI tool that automates passive reconnaissance using the Shodan API and public sources (crt.sh). It discovers subdomains, resolves IPs, fetches Shodan host data (ports, banners, CVEs, geolocation, ASN/org, HTTP titles/status), and generates a content-rich HTML + JSON report.

**Important:** This tool performs **passive** reconnaissance only (Shodan + public sources). Do **not** run active scanning on targets that are out of scope.

---

## Features

- Domain & subdomain enumeration (crt.sh + optional local tools)
- DNS resolution (socket or dnsx)
- Shodan domain and host lookups (parallel)
- Extracts: open ports, product/version, HTTP status/title/server, org/ASN, geolocation, tags, CVEs
- CVE enrichment (NVD) — optional
- Exports: HTML report, `hosts.json`, `cves.json`, `summary.json`, and per-IP raw JSON
- Resilient: timeouts, retries, failed_ips log
- CLI flags for tuning: `--parallel`, `--limit`, `--sleep`, `--use-system-tools`

---

## Quick start

> **Prerequisites**
> - Python 3.8+
> - A Shodan API key (create at https://shodan.io)
> - (optional) Go tools `subfinder`, `dnsx` for faster enumeration

### Install dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
--- 

## Usage 
```bash
export SHODAN_API_KEY="your_shodan_api_key_here"
```

## Basic scan
```bash
python3 shodan_recon_pro.py --domains DOMAIN_NAME --api-key YOUR_API_KEY
```

## Advanced scan with 10 parallel lookups and output folder
```bash
python3 shodan_recon_pro.py --domains DOMAIN_NAME,DOMAIN_NAME --api-key YOUR_API_KEY --parallel 10 --outdir scans_oklink
```

## Disable CVE enrichment
```bash
python3 shodan_recon_pro.py --domains DOMAIN_NAME --api-key YOUR_API_KEY --no-cve-enrich
```

## Common flags:

--domains: comma separated domains (required)

--api-key: Shodan API key (required)

--outdir: output directory (default shodan_recon_out)

--limit: max results per domain from Shodan (default 5000)

--parallel: simultaneous host lookups (default 10)

--sleep: delay between API hits (seconds)

--use-system-tools: use subfinder and dnsx if installed

--no-cve-enrich: skip NVD enrichment (faster)

