# .bank.in Security Scorecard

Independent security ratings for India's banking domain ecosystem. Built by CashlessConsumer in response to the IDRBT portal data leak (June 2026) which exposed 26 unauthenticated API endpoints leaking 5,576 user records from India's exclusive .bank.in domain registrar.

Every .bank.in domain (1,497 registered) is scored daily on a 100-point rubric covering:

- **HTTPS/TLS (15 pts)** — Encryption strength, TLS version
- **HSTS (10 pts)** — Strict transport security, preload status
- **Security headers (15 pts)** — X-Frame-Options, X-Content-Type-Options, CSP
- **Email security (20 pts)** — DMARC policy (reject/quarantine/none), SPF, MX
- **DNSSEC (10 pts)** — DNS security extensions
- **Exposure checks (20 pts)** — No .git/.env/phpinfo leaks, no exposed cPanel
- **HTTP reachability (10 pts)** — Responsive web server

## Quick Start

```bash
# Full scan (1497 domains)
cd scanner
python3 scan_v2.py --domains ../data/domains.txt --output ../data/scorecard.duckdb

# Export for web
python3 export_json.py ../data/scorecard.duckdb ../data/
```

## Architecture

```
scanner/          Python scanner (asyncio + duckdb)
data/             DuckDB database + JSON exports
.github/workflows/  (planned) daily scan via GitHub Actions
```

## Dashboard

https://cashlessconsumer.zo.space/bankin-scorecard

API: https://cashlessconsumer.zo.space/api/bankin-scorecard

## License

Research purpose. Not for commercial use.
