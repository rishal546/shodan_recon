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
