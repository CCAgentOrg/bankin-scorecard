#!/usr/bin/env python3
"""
.bank.in Security Scorecard — Scanner
Runs OSINT security checks against all registered .bank.in domains.
Stores results in DuckDB.

Usage:
  python3 scan.py [--batch 50] [--output ../data/scorecard.duckdb]
"""

import asyncio, aiohttp, ssl, json, sys, os, time, re, dns.resolver, dns.name
import duckdb
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional

# ─── Schema ───────────────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS domains (
    domain          VARCHAR PRIMARY KEY,
    bank_name       VARCHAR,
    ifsc_code       VARCHAR,
    bank_type       VARCHAR,
    dicgc_category  VARCHAR
);

CREATE TABLE IF NOT EXISTS scans (
    domain              VARCHAR,
    scan_timestamp      TIMESTAMP,
    http_status         INTEGER,
    server_header       VARCHAR,
    title               VARCHAR,
    https               BOOLEAN,
    tls_version         VARCHAR,
    cert_issuer         VARCHAR,
    hsts                BOOLEAN,
    hsts_preload        BOOLEAN,
    x_frame_options     VARCHAR,
    x_content_type      VARCHAR,
    content_security    VARCHAR,
    dnssec              BOOLEAN,
    dmarc_policy        VARCHAR,
    spf_record          VARCHAR,
    has_mx              BOOLEAN,
    cpanel_detected     BOOLEAN,
    admin_panel_detected BOOLEAN,
    git_exposed         BOOLEAN,
    env_exposed         BOOLEAN,
    phpinfo_exposed     BOOLEAN,
    ip_address          VARCHAR,
    cloud_provider      VARCHAR,
    score               INTEGER,
    PRIMARY KEY (domain, scan_timestamp)
);

CREATE TABLE IF NOT EXISTS scan_meta (
    key   VARCHAR PRIMARY KEY,
    value VARCHAR
);
"""

# ─── Constants ──────────────────────────────────────────────────────────

BATCH_SIZE = int(os.environ.get("SCAN_BATCH", "50"))
CONCURRENCY = int(os.environ.get("SCAN_CONCURRENCY", "100"))
TIMEOUT_SEC = int(os.environ.get("SCAN_TIMEOUT", "15"))

SUSPICIOUS_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/cpanel", "/webmail",
    ".git/config", ".env", "phpinfo.php", "/backup", "/config",
    "/.well-known/security.txt",
]

# ─── Helpers ─────────────────────────────────────────────────────────────

def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

async def fetch(session: aiohttp.ClientSession, url: str, timeout: int = TIMEOUT_SEC) -> dict:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=True, ssl=make_ssl_context()) as resp:
            text = await resp.text()
            title = ""
            m = re.search(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()[:200]
            return {
                "status": resp.status,
                "server": resp.headers.get("Server", ""),
                "title": title,
                "headers": dict(resp.headers),
            }
    except asyncio.TimeoutError:
        return {"status": 0, "server": "", "title": "", "headers": {}}
    except aiohttp.ClientError:
        return {"status": 0, "server": "", "title": "", "headers": {}}

async def check_path(session: aiohttp.ClientSession, base: str, path: str) -> bool:
    url = f"https://{base}/{path}" if path.startswith(".well-known") else f"https://{base}/{path}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5),
                               allow_redirects=False, ssl=make_ssl_context()) as resp:
            return resp.status not in (404, 406)
    except:
        return False

def check_dmarc(domain: str) -> tuple[Optional[str], bool]:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for ans in answers:
            txt = "".join(ans.strings)
            if txt.startswith("v=DMARC1"):
                p = re.search(r'p=(\w+)', txt)
                if p:
                    return p.group(1), True
                return txt[:80], True
        return None, True
    except:
        return None, False

def check_spf(domain: str) -> tuple[Optional[str], bool]:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for ans in answers:
            txt = "".join(ans.strings)
            if txt.startswith("v=spf1"):
                return txt[:120], True
        return None, True
    except:
        return None, False

def check_dnssec(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=5)
        return True
    except:
        return False

def check_mx(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return len(answers) > 0
    except:
        return False

def resolve_ip(domain: str) -> Optional[str]:
    try:
        return str(dns.resolver.resolve(domain, "A", lifetime=5)[0])
    except:
        return None

def detect_cloud(ip: Optional[str]) -> str:
    if not ip:
        return ""
    # Basic cloud provider detection via known ranges
    cloud_patterns = {
        "AWS": r"^3\.",
        "Cloudflare": r"^104\.1[6-9]\.|^104\.2[0-9]\.|^104\.3[0-1]\.|^172\.64\.|^172\.65\.|^173\.245\.|^188\.114\.|^198\.41\.|^197\.234\.",
        "Azure": r"^13\.|^20\.|^40\.|^52\.|^168\.63\.|^191\.235\.",
        "GCP": r"^34\.|^35\.|^8\.34\.|^8\.35\.|^23\.236\.|^23\.251\.|^104\.154\.|^104\.155\.|^104\.196\.|^104\.197\.|^104\.198\.|^107\.167\.|^107\.178\.|^108\.59\.|^130\.211\.|^146\.148\.|^162\.222\.|^173\.255\.|^192\.158\.|^199\.192\.|^199\.223\.|^199\.23\.",
    }
    for provider, pattern in cloud_patterns.items():
        if re.search(pattern, ip):
            return provider
    return ""

# ─── Scoring Rubric ──────────────────────────────────────────────────────

def compute_score(data: dict) -> int:
    """Rubric-based scoring. 0-100 points."""
    score = 0

    # HTTPS/TLS (15 pts)
    if data.get("https"):
        score += 10
        if data.get("tls_version") in ("TLS 1.3", "TLSv1.3"):
            score += 5
        elif data.get("tls_version") in ("TLS 1.2", "TLSv1.2"):
            score += 3

    # HSTS (10 pts)
    if data.get("hsts"):
        score += 7
        if data.get("hsts_preload"):
            score += 3

    # Security Headers (15 pts)
    if data.get("x_frame_options"):
        score += 5
    if data.get("x_content_type") == "nosniff":
        score += 5
    if data.get("content_security"):
        score += 5

    # Email Security (20 pts)
    dmarc = data.get("dmarc_policy", "")
    if dmarc == "reject":
        score += 12
    elif dmarc == "quarantine":
        score += 8
    elif dmarc:
        score += 4
    if data.get("spf_record"):
        score += 4
    if data.get("has_mx"):
        score += 4

    # DNSSEC (10 pts)
    if data.get("dnssec"):
        score += 10

    # No Bad Exposures (20 pts)
    if not data.get("git_exposed"):
        score += 5
    if not data.get("env_exposed"):
        score += 5
    if not data.get("phpinfo_exposed"):
        score += 5
    if not data.get("cpanel_detected"):
        score += 5

    # HTTP access (10 pts)
    if data.get("http_status", 0) in (200, 301, 302):
        score += 5
    if data.get("http_status", 0) not in (0, 404, 406):
        score += 5

    return min(score, 100)

# ─── Scanner ─────────────────────────────────────────────────────────────

async def scan_domain(domain: str,
                      session: aiohttp.ClientSession,
                      sem: asyncio.Semaphore) -> dict:
    async with sem:
        result = {
            "domain": domain,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "http_status": 0, "server_header": "", "title": "",
            "https": False, "tls_version": "", "cert_issuer": "",
            "hsts": False, "hsts_preload": False,
            "x_frame_options": "", "x_content_type": "", "content_security": "",
            "dnssec": False, "dmarc_policy": "", "spf_record": "",
            "has_mx": False, "cpanel_detected": False,
            "admin_panel_detected": False, "git_exposed": False,
            "env_exposed": False, "phpinfo_exposed": False,
            "ip_address": "", "cloud_provider": "",
            "score": 0,
        }

        try:
            # HTTPS scan
            https_result = await fetch(session, f"https://{domain}")
            result["http_status"] = https_result["status"]
            result["server_header"] = https_result["server"]
            result["title"] = https_result["title"]

            if https_result["status"] > 0:
                result["https"] = True
                headers = https_result["headers"]
                result["hsts"] = "strict-transport-security" in headers
                if headers.get("strict-transport-security", "").startswith("max-age"):
                    result["hsts"] = True
                    if "preload" in headers.get("strict-transport-security", ""):
                        result["hsts_preload"] = True
                result["x_frame_options"] = headers.get("x-frame-options", "")
                xct = headers.get("x-content-type-options", "")
                if xct:
                    result["x_content_type"] = xct
                result["content_security"] = bool(headers.get("content-security-policy", ""))
                result["cert_issuer"] = https_result.get("cert_issuer", "")

                # TLS version check via raw socket
                tls_ver = ""
                try:
                    import socket as sock_mod
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with sock_mod.create_connection((domain, 443), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                            tls_ver = tls_sock.version() or ""
                except Exception:
                    pass
                result["tls_version"] = tls_ver

            # DNS checks
            result["ip_address"] = resolve_ip(domain) or ""
            result["cloud_provider"] = detect_cloud(result["ip_address"])
            result["dnssec"] = check_dnssec(domain)
            result["has_mx"] = check_mx(domain)
            dmarc_pol, _ = check_dmarc(domain)
            result["dmarc_policy"] = dmarc_pol or ""
            spf_val, _ = check_spf(domain)
            result["spf_record"] = spf_val or ""

            # Path checks (only if HTTPS resolves)
            if result["https"]:
                for path in SUSPICIOUS_PATHS:
                    found = await check_path(session, domain, path)
                    if path == ".git/config" and found:
                        result["git_exposed"] = True
                    elif path == ".env" and found:
                        result["env_exposed"] = True
                    elif path == "phpinfo.php" and found:
                        result["phpinfo_exposed"] = True
                    elif path in ("/admin", "/administrator", "/wp-admin") and found:
                        result["admin_panel_detected"] = True
                    elif path in ("/cpanel", "/webmail") and found:
                        if path in ("/cpanel", "/webmail") and found:
                            result["cpanel_detected"] = True

        except Exception as e:
            # Log but don't crash
            pass

        # Compute score
        result["score"] = compute_score(result)

        return result

# ─── Main ────────────────────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", default="/home/workspace/IDRBT/domains.txt")
    parser.add_argument("--triangulation", default="/home/workspace/IDRBT/triangulation/triangulation_data.json")
    parser.add_argument("--output", default="/home/workspace/Projects/bankin-scorecard/data/scorecard.duckdb")
    parser.add_argument("--batch", type=int, default=BATCH_SIZE)
    args = parser.parse_args()

    # Load domains
    with open(args.domains) as f:
        domains = [line.strip() for line in f if line.strip()]

    # Load triangulation data for bank names/IFSC
    bank_info = {}
    if os.path.exists(args.triangulation):
        with open(args.triangulation) as f:
            data = json.load(f)
            for d in data.get("domains", []):
                domain = d.get("domain", "")
                info = d.get("info") or {}
                ifsc = d.get("ifsc") or {}
                dicgc = d.get("dicgc") or {}
                bank_info[domain] = {
                    "bank_name": str(info.get("org") or dicgc.get("name") or "").strip(),
                    "ifsc_code": str(ifsc.get("code") if isinstance(ifsc, dict) else "").strip() if ifsc else "",
                    "bank_type": str(ifsc.get("type") if isinstance(ifsc, dict) else "").strip() if ifsc else "",
                    "dicgc_category": str(dicgc.get("category") if isinstance(dicgc, dict) else "").strip() if dicgc else "",
                }

    print(f"Loaded {len(domains)} domains, {len(bank_info)} with bank info")

    # Init DuckDB
    db = duckdb.connect(args.output)
    existing_tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    for stmt in SCHEMA_SQL.split(";"):
        s = stmt.strip()
        if s and s not in existing_tables:
            try:
                db.execute(s)
            except Exception as e:
                print(f"Schema: {e}")

    # Populate domain table
    db.execute("DELETE FROM domains")
    for domain in domains:
        info = bank_info.get(domain, {})
        db.execute("""
            INSERT OR REPLACE INTO domains (domain, bank_name, ifsc_code, bank_type, dicgc_category)
            VALUES (?, ?, ?, ?, ?)
        """, [
            domain,
            info.get("bank_name", ""),
            info.get("ifsc_code", ""),
            info.get("bank_type", ""),
            info.get("dicgc_category", ""),
        ])
    db.commit()
    print(f"Populated {len(domains)} domains in database")

    # Scan
    sem = asyncio.Semaphore(CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, force_close=True)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SEC + 5)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout,
                                      headers={"User-Agent": "CashlessConsumer/1.0 (Security Monitor)"}) as session:
        start = time.time()
        total = len(domains)
        scanned = 0
        insert_sql = """
            INSERT OR REPLACE INTO scans (
                domain, scan_timestamp, http_status, server_header, title,
                https, tls_version, cert_issuer, hsts, hsts_preload,
                x_frame_options, x_content_type, content_security, dnssec, dmarc_policy,
                spf_record, has_mx, cpanel_detected, admin_panel_detected, git_exposed,
                env_exposed, phpinfo_exposed, ip_address, cloud_provider, score
            ) VALUES (
                ?,?,?,?,?,
                ?,?,?,?,?,
                ?,?,?,?,?,
                ?,?,?,?,?,
                ?,?,?,?,?
            )
        """

        for i in range(0, total, args.batch):
            batch = domains[i:i+args.batch]
            tasks = [scan_domain(d, session, sem) for d in batch]
            results = await asyncio.gather(*tasks)

            # Insert batch
            for r in results:
                try:
                    db.execute(insert_sql, (
                        r["domain"], r["scan_timestamp"],
                        r["http_status"], r["server_header"], r["title"],
                        r["https"], r["tls_version"], r["cert_issuer"],
                        r["hsts"], r["hsts_preload"],
                        r["x_frame_options"], r["x_content_type"],
                        r["content_security"],
                        r["dnssec"], r["dmarc_policy"],
                        r["spf_record"], r["has_mx"],
                        r["cpanel_detected"], r["admin_panel_detected"],
                        r["git_exposed"], r["env_exposed"],
                        r["phpinfo_exposed"],
                        r["ip_address"], r["cloud_provider"],
                        r["score"],
                    ))
                except Exception as e:
                    print(f"Insert error for {r['domain']}: {e}")

            db.commit()
            scanned += len(batch)
            elapsed = time.time() - start
            rate = scanned / elapsed if elapsed > 0 else 0
            eta = (total - scanned) / rate if rate > 0 else 0
            print(f"  [{scanned}/{total}] {rate:.1f} dom/s, ETA {eta:.0f}s | "
                  f"Batch avg score: {sum(r['score'] for r in results)/len(results):.0f}")

    elapsed = time.time() - start
    print(f"\nScan complete: {scanned} domains in {elapsed:.0f}s ({scanned/elapsed:.1f} dom/s)")
    print(f"Database: {args.output}")

    # Summary stats
    stats = db.execute("""
        SELECT
            COUNT(*) as total,
            AVG(score) as avg_score,
            COUNT(CASE WHEN https THEN 1 END) as with_https,
            COUNT(CASE WHEN hsts THEN 1 END) as with_hsts,
            COUNT(CASE WHEN dnssec THEN 1 END) as with_dnssec,
            COUNT(CASE WHEN dmarc_policy = 'reject' THEN 1 END) as dmarc_reject
        FROM scans
        WHERE scan_timestamp = (SELECT MAX(scan_timestamp) FROM scans)
    """).fetchone()

    if stats:
        print(f"\nInitial Baseline:")
        print(f"  Total domains:     {stats[0]}")
        print(f"  Avg score:         {stats[1]:.1f}/100")
        print(f"  HTTPS:             {stats[2]}")
        print(f"  HSTS:              {stats[3]}")
        print(f"  DNSSEC:            {stats[4]}")
        print(f"  DMARC=reject:      {stats[5]}")

    # Store metadata
    db.execute("INSERT OR REPLACE INTO scan_meta VALUES ('last_scan', ?)", (datetime.now(timezone.utc).isoformat(),))
    db.execute("INSERT OR REPLACE INTO scan_meta VALUES ('version', '0.1')")
    db.execute("INSERT OR REPLACE INTO scan_meta VALUES ('domains_count', ?)", (str(total),))
    db.commit()
    db.close()

if __name__ == "__main__":
    asyncio.run(main())
