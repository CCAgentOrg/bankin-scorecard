# AGENTS.md

## Overview

.bank.in Security Scorecard — daily OSINT scanner rating 1,497 registered .bank.in domains on security posture. Project started 2026-06-15 after IDRBT portal data leak disclosure.

## Key Paths

| Path | Purpose |
|------|---------|
| `scanner/scan_v2.py` | Threaded scanner (200 workers, 15s timeout) |
| `scanner/export_json.py` | DuckDB → JSON for zo.space API |
| `scanner/http_scan.sh` | Legacy bash scanner (deprecated) |
| `data/scorecard.duckdb` | Database (ignored by git, regenerated) |
| `data/domains.txt` | All 1,497 .bank.in domains |
| `data/scorecard.json` | Per-domain results (git-committed) |
| `data/summary.json` | Aggregate stats (git-committed) |

## Daily Automation

Runs daily at 8:30 AM IST via Zo automation:
1. `scan_v2.py` — full scan → DuckDB
2. `export_json.py` — export JSON
3. JSON files served by zo.space API

## Domain Sources

- IDRBT portal unauthenticated billing endpoint (1,535 invoices, 1,497 unique domains)
- crt.sh Certificate Transparency logs (6,543 entries)
- Triangulated with IFSC codes and DICGC deposit insurance data

## Scoring Rubric

| Category | Max | Details |
|----------|-----|---------|
| HTTPS/TLS | 15 | 10 for HTTPS, +5 for TLS 1.3 |
| HSTS | 10 | 7 for HSTS present, +3 for preload |
| Security Headers | 15 | 5 each for X-Frame-Options, XCTO, CSP |
| Email Security | 20 | 12 for DMARC=reject, 8 for quarantine, +4 SPF, +4 MX |
| DNSSEC | 10 | DNSKEY record present |
| Exposure Checks | 20 | 5 each for no .git, no .env, no phpinfo, no cPanel |
| HTTP Reachability | 10 | 5 for 200/301/302, 5 for non-error |
| **Total** | **100** | |

## Grades

- **A** (80-100): Excellent — bank-grade security
- **B** (60-79): Good — minor gaps
- **C** (40-59): Fair — several gaps
- **D** (20-39): Poor — critical gaps
- **F** (0-19): Failing — fundamentally insecure
