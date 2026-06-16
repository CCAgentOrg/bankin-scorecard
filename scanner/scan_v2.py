#!/usr/bin/env python3
""".bank.in Security Scorecard Scanner v3 - Fixed scoring rubric with proper validation"""

import subprocess, sys, os, time, json, re, socket, ssl, dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import duckdb

DB_PATH = os.environ.get("DB_PATH", "/home/workspace/Projects/bankin-scorecard/data/scorecard.duckdb")
DOMAINS_FILE = os.environ.get("DOMAINS_FILE", "/home/workspace/Projects/bankin-scorecard/data/domains.txt")
TRIANG_FILE = os.environ.get("TRIANG_FILE", "/home/workspace/IDRBT/triangulation/triangulation_data.json")
TIMEOUT = 10
MAX_WORKERS = 150

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS domains (
    domain VARCHAR PRIMARY KEY, bank_name VARCHAR, ifsc_code VARCHAR,
    bank_type VARCHAR, dicgc_category VARCHAR);
CREATE TABLE IF NOT EXISTS scans (
    domain VARCHAR, scan_timestamp TIMESTAMP,
    http_status INTEGER, https BOOLEAN, cert_valid BOOLEAN,
    tls_version VARCHAR, hsts BOOLEAN, hsts_max_age INTEGER,
    hsts_subdomains BOOLEAN, hsts_preload BOOLEAN,
    x_frame_options VARCHAR, x_content_type VARCHAR, content_security BOOLEAN,
    server_header VARCHAR, title VARCHAR,
    dnssec BOOLEAN, dmarc_policy VARCHAR, dmarc_subdomain VARCHAR, dmarc_pct INTEGER,
    spf_record VARCHAR, spf_hardfail BOOLEAN, has_mx BOOLEAN,
    cpanel_detected BOOLEAN, admin_panel_detected BOOLEAN,
    git_exposed BOOLEAN, env_exposed BOOLEAN, phpinfo_exposed BOOLEAN,
    ip_address VARCHAR, cloud_provider VARCHAR,
    score INTEGER, PRIMARY KEY (domain, scan_timestamp));
"""


def http_scan(domain):
    """Check HTTPS, TLS, headers, paths"""
    result = {
        "https": False, "http_status": 0, "cert_valid": False, "tls_version": "",
        "hsts": False, "hsts_max_age": 0, "hsts_subdomains": False, "hsts_preload": False,
        "x_frame_options": "", "x_content_type": "", "content_security": False,
        "server_header": "", "title": "",
        "cpanel_detected": False, "admin_panel_detected": False,
        "git_exposed": False, "env_exposed": False, "phpinfo_exposed": False,
        "ip_address": "", "cloud_provider": "",
    }
    try:
        # --- 1. Certificate validation (no -k) ---
        cert_check = subprocess.run(
            ["curl", "-sILo", "/dev/null", "-w", "%{ssl_verify_result}",
             "--max-time", "5", f"https://{domain}"],
            capture_output=True, text=True, timeout=7
        )
        result["cert_valid"] = (
            cert_check.returncode == 0
            and cert_check.stdout.strip().isdigit()
            and int(cert_check.stdout.strip()) == 0
        )

        # --- 2. HTTPS headers + status (with -k to still get info if cert bad) ---
        cmd = ["curl", "-skIL", "--max-time", str(TIMEOUT),
               "-o", "/dev/null", "-w",
               "%{http_code}\t%{content_type}\t%{remote_ip}",
               f"https://{domain}"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT + 2)
        parts = out.stdout.strip().split("\t")
        if len(parts) >= 3:
            result["http_status"] = int(parts[0]) if parts[0].isdigit() else 0
            result["https"] = result["http_status"] > 0
            result["ip_address"] = parts[2]

        # --- 3. TLS version ---
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ts:
                    result["tls_version"] = ts.version() or ""
        except:
            pass

        # --- 4. Full header parsing ---
        hdr = subprocess.run(
            ["curl", "-skIL", "--max-time", str(TIMEOUT), f"https://{domain}"],
            capture_output=True, text=True, timeout=TIMEOUT + 2
        ).stdout.lower()

        # Search full output for HSTS (curl -IL may have multiple responses in redirect chain)
        # Take the LAST HSTS value from the chain (final response wins)
        hsts_matches = re.findall(r'strict-transport-security:\s*([^\r\n]+)', hdr, re.I)
        if hsts_matches:
            hsts_val = hsts_matches[-1].strip()
            result["hsts"] = True
            ma = re.search(r'max-age\s*=\s*(\d+)', hsts_val, re.I)
            result["hsts_max_age"] = int(ma.group(1)) if ma else 0
            result["hsts_subdomains"] = "includesubdomains" in hsts_val.lower().replace(" ", "")
            result["hsts_preload"] = "preload" in hsts_val.lower()

        # Parse security headers from the final response section
        sections = [s.strip() for s in hdr.split("\n\n") if s.strip()]
        final_hdr = sections[-1] if sections else hdr
        for line in final_hdr.split("\n"):
            l = line.strip()
            if l.startswith("x-frame-options:"):
                result["x_frame_options"] = l.split(":", 1)[1].strip().upper()
            elif l.startswith("x-content-type-options:"):
                result["x_content_type"] = l.split(":", 1)[1].strip().lower()
            elif l.startswith("content-security-policy:"):
                result["content_security"] = True
            elif l.startswith("server:"):
                result["server_header"] = l.split(":", 1)[1].strip()[:60]

        # --- 5. Page title ---
        body = subprocess.run(
            ["curl", "-skL", "--max-time", "8", f"https://{domain}"],
            capture_output=True, text=True, timeout=10
        ).stdout
        m = re.search(r'<title[^>]*>([^<]+)', body, re.I)
        if m:
            result["title"] = m.group(1).strip()[:200]

        # --- 6. Path exposure checks ---
        for path, key in [
            ("/cpanel", "cpanel_detected"),
            ("/admin", "admin_panel_detected"),
            ("/.git/config", "git_exposed"),
            ("/.env", "env_exposed"),
            ("/phpinfo.php", "phpinfo_exposed"),
        ]:
            r = subprocess.run(
                ["curl", "-sk", "--max-time", "4",
                 "-o", "/dev/null", "-w", "%{http_code}",
                 f"https://{domain}{path}"],
                capture_output=True, text=True, timeout=6
            )
            code = r.stdout.strip()
            result[key] = code not in ("", "404", "000", "406") and code.isdigit()

        # --- 7. Cloud provider guess ---
        ip = result["ip_address"]
        if ip.startswith("3."):
            result["cloud_provider"] = "AWS"
        elif ip[:2] in ("13", "20", "40") or ip.startswith("52."):
            result["cloud_provider"] = "Azure"
        elif ip.startswith("34.") or ip.startswith("35."):
            result["cloud_provider"] = "GCP"
        elif ip.startswith("104.16") or ip.startswith("104.2") or \
             ip.startswith("172.64") or ip.startswith("172.65"):
            result["cloud_provider"] = "Cloudflare"
    except:
        pass
    return result


def dns_scan(domain):
    """DNS checks: DNSSEC, DMARC (+subdomain policy, pct), SPF (+hardfail), MX"""
    r = {"dnssec": False, "dmarc_policy": "", "dmarc_subdomain": "", "dmarc_pct": -1,
         "spf_record": "", "spf_hardfail": False, "has_mx": False}
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=3)
        r["dnssec"] = True
    except:
        pass
    try:
        ans = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=3)
        for a in ans:
            txt = "".join(a.strings)
            if txt.startswith("v=DMARC1"):
                p = re.search(r'p=(\w+)', txt)
                r["dmarc_policy"] = p.group(1) if p else ""
                sp = re.search(r'sp=(\w+)', txt)
                r["dmarc_subdomain"] = sp.group(1) if sp else ""
                pct = re.search(r'pct=(\d+)', txt)
                r["dmarc_pct"] = int(pct.group(1)) if pct else 100
    except:
        pass
    try:
        ans = dns.resolver.resolve(domain, "TXT", lifetime=3)
        for a in ans:
            txt = "".join(a.strings)
            if txt.startswith("v=spf1"):
                r["spf_record"] = txt[:200]
                r["spf_hardfail"] = " -all" in txt or txt.strip().endswith("-all")
    except:
        pass
    try:
        ans = dns.resolver.resolve(domain, "MX", lifetime=3)
        r["has_mx"] = len(ans) > 0
    except:
        pass
    return r


def compute_score(data):
    s = 0

    # HTTPS / TLS (15)
    if data.get("https"):
        s += 10 if data.get("cert_valid") else 5
    tls = data.get("tls_version", "")
    if tls.startswith("TLSv1.3"):
        s += 5
    elif tls.startswith("TLSv1.2"):
        s += 3

    # HSTS (10)
    if data.get("hsts") and data.get("hsts_max_age", 0) >= 31536000 and data.get("hsts_subdomains"):
        s += 7
    elif data.get("hsts"):
        s += 3
    if data.get("hsts_preload"):
        s += 3

    # Security Headers (15)
    xfo = data.get("x_frame_options", "")
    if xfo in ("DENY", "SAMEORIGIN"):
        s += 5
    if data.get("x_content_type") == "nosniff":
        s += 5
    if data.get("content_security"):
        s += 5

    # Email Security (20)
    dmarc = data.get("dmarc_policy", "")
    if dmarc == "reject":
        s += 12
    elif dmarc == "quarantine":
        s += 8
    elif dmarc:
        s += 4
    if data.get("spf_record"):
        s += 2
        if data.get("spf_hardfail"):
            s += 2  # +2 more for -all hardfail (total 4)
    if data.get("has_mx"):
        s += 4

    # DNSSEC (10)
    if data.get("dnssec"):
        s += 10

    # Exposure Checks (20)
    if not data.get("git_exposed"):
        s += 5
    if not data.get("env_exposed"):
        s += 5
    if not data.get("phpinfo_exposed"):
        s += 5
    if not data.get("cpanel_detected"):
        s += 5

    # HTTP Reachability (10)
    if data.get("http_status", 0) in (200, 301, 302):
        s += 5
    if data.get("http_status", 0) not in (0, 404, 406):
        s += 5

    return min(s, 100)


def scan_one(domain):
    http = http_scan(domain)
    dns = dns_scan(domain)
    merged = {**http, **dns}
    merged["domain"] = domain
    merged["score"] = compute_score(merged)
    merged["scan_timestamp"] = datetime.now(timezone.utc)
    return merged


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    db = duckdb.connect(DB_PATH)
    for s in SCHEMA_SQL.split(";"):
        s = s.strip()
        if s:
            try:
                db.execute(s)
            except:
                pass

    with open(DOMAINS_FILE) as f:
        domains = [line.strip() for line in f if line.strip()]

    # Load bank info
    bank_info = {}
    if os.path.exists(TRIANG_FILE):
        with open(TRIANG_FILE) as f:
            data = json.load(f)
            for d in data.get("domains", []):
                dm = d.get("domain", "")
                info = d.get("info") or {}
                ifsc = d.get("ifsc") or {}
                dicgc = d.get("dicgc") or {}
                bank_info[dm] = {
                    "bank_name": str(info.get("org") or dicgc.get("name") or ""),
                    "ifsc_code": str(ifsc.get("code") or ""),
                    "bank_type": str(ifsc.get("type") or ""),
                    "dicgc_category": str(dicgc.get("category") or ""),
                }

    db.execute("DELETE FROM domains")
    for dm in domains:
        info = bank_info.get(dm, {})
        db.execute("INSERT OR REPLACE INTO domains VALUES (?,?,?,?,?)",
                   [dm, info.get("bank_name", ""), info.get("ifsc_code", ""),
                    info.get("bank_type", ""), info.get("dicgc_category", "")])
    db.commit()

    total = len(domains)
    print(f"Starting scan: {total} domains, {MAX_WORKERS} workers", flush=True)
    start = time.time()
    scanned = 0

    db.execute("DELETE FROM scans")
    db.commit()

    insert_sql = """INSERT OR REPLACE INTO scans VALUES (
        ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(scan_one, d): d for d in domains}
        batch_results = []

        for i, future in enumerate(as_completed(futures)):
            try:
                r = future.result(timeout=TIMEOUT + 10)
                batch_results.append(r)
            except Exception as e:
                d = futures[future]
                batch_results.append({
                    "domain": d, "score": 0, "scan_timestamp": datetime.now(timezone.utc),
                    "http_status": 0, "https": False, "cert_valid": False, "tls_version": "",
                    "hsts": False, "hsts_max_age": 0, "hsts_subdomains": False, "hsts_preload": False,
                    "x_frame_options": "", "x_content_type": "", "content_security": False,
                    "server_header": "", "title": "",
                    "dnssec": False, "dmarc_policy": "", "dmarc_subdomain": "", "dmarc_pct": -1,
                    "spf_record": "", "spf_hardfail": False, "has_mx": False,
                    "cpanel_detected": False, "admin_panel_detected": False,
                    "git_exposed": False, "env_exposed": False, "phpinfo_exposed": False,
                    "ip_address": "", "cloud_provider": "",
                })

            scanned += 1

            if len(batch_results) >= 100:
                for r in batch_results:
                    try:
                        db.execute(insert_sql, (
                            r["domain"], r["scan_timestamp"],
                            r.get("http_status", 0), r.get("https", False), r.get("cert_valid", False),
                            r.get("tls_version", ""),
                            r.get("hsts", False), r.get("hsts_max_age", 0),
                            r.get("hsts_subdomains", False), r.get("hsts_preload", False),
                            r.get("x_frame_options", ""), r.get("x_content_type", ""),
                            r.get("content_security", False),
                            r.get("server_header", ""), r.get("title", ""),
                            r.get("dnssec", False), r.get("dmarc_policy", ""),
                            r.get("dmarc_subdomain", ""), r.get("dmarc_pct", -1),
                            r.get("spf_record", ""), r.get("spf_hardfail", False),
                            r.get("has_mx", False),
                            r.get("cpanel_detected", False), r.get("admin_panel_detected", False),
                            r.get("git_exposed", False), r.get("env_exposed", False),
                            r.get("phpinfo_exposed", False),
                            r.get("ip_address", ""), r.get("cloud_provider", ""),
                            r.get("score", 0),
                        ))
                    except Exception as e:
                        print(f"DB error {r['domain']}: {e}", flush=True)
                db.commit()
                batch_results = []
                elapsed = time.time() - start
                rate = scanned / elapsed if elapsed > 0 else 0
                avg = sum(r.get("score", 0) for r in batch_results) / len(batch_results) if batch_results else 0
                print(f"  [{scanned}/{total}] {rate:.0f} dom/s  avg_score:{avg:.0f}", flush=True)

        if batch_results:
            for r in batch_results:
                try:
                    db.execute(insert_sql, (
                        r["domain"], r["scan_timestamp"],
                        r.get("http_status", 0), r.get("https", False), r.get("cert_valid", False),
                        r.get("tls_version", ""),
                        r.get("hsts", False), r.get("hsts_max_age", 0),
                        r.get("hsts_subdomains", False), r.get("hsts_preload", False),
                        r.get("x_frame_options", ""), r.get("x_content_type", ""),
                        r.get("content_security", False),
                        r.get("server_header", ""), r.get("title", ""),
                        r.get("dnssec", False), r.get("dmarc_policy", ""),
                        r.get("dmarc_subdomain", ""), r.get("dmarc_pct", -1),
                        r.get("spf_record", ""), r.get("spf_hardfail", False),
                        r.get("has_mx", False),
                        r.get("cpanel_detected", False), r.get("admin_panel_detected", False),
                        r.get("git_exposed", False), r.get("env_exposed", False),
                        r.get("phpinfo_exposed", False),
                        r.get("ip_address", ""), r.get("cloud_provider", ""),
                        r.get("score", 0),
                    ))
                except:
                    pass
            db.commit()

    elapsed = time.time() - start
    print(f"\nComplete: {scanned} domains in {elapsed:.0f}s ({scanned / elapsed:.1f} dom/s)", flush=True)

    # Stats
    stats = db.execute("""SELECT COUNT(*) as total, ROUND(AVG(score),1) as avg_score,
        SUM(CASE WHEN https THEN 1 ELSE 0 END) as with_https,
        SUM(CASE WHEN cert_valid THEN 1 ELSE 0 END) as valid_certs,
        SUM(CASE WHEN hsts THEN 1 ELSE 0 END) as with_hsts,
        SUM(CASE WHEN dnssec THEN 1 ELSE 0 END) as with_dnssec,
        SUM(CASE WHEN dmarc_policy='reject' THEN 1 ELSE 0 END) as dmarc_reject
        FROM scans""").fetchone()
    print(f"  Total: {stats[0]} | Avg: {stats[1]} | HTTPS: {stats[2]} | ValidCerts: {stats[3]} | HSTS: {stats[4]} | DNSSEC: {stats[5]} | DMARC=R: {stats[6]}")
    db.close()


if __name__ == "__main__":
    main()
