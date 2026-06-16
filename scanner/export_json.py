#!/usr/bin/env python3
"""Export summary and scorecard JSON from DuckDB — full evidence fields"""
import json, os, sys
import duckdb

def main():
    db_path = "/home/workspace/Projects/bankin-scorecard/data/scorecard.duckdb"
    out_dir = os.path.dirname(db_path)
    
    db = duckdb.connect(db_path)
    
    # Summary — use latest scan per domain via window function
    summary = db.execute("""
        WITH latest AS (
            SELECT domain, score, https, hsts, dnssec, dmarc_policy,
                   git_exposed, env_exposed, cpanel_detected, admin_panel_detected,
                   http_status, cert_valid,
                   ROW_NUMBER() OVER (PARTITION BY domain ORDER BY scan_timestamp DESC) as rn
            FROM scans
        )
        SELECT 
            COUNT(*) as total,
            ROUND(AVG(score), 1) as avg_score,
            SUM(CASE WHEN https THEN 1 ELSE 0 END) as with_https,
            SUM(CASE WHEN https AND cert_valid THEN 1 ELSE 0 END) as with_valid_https,
            SUM(CASE WHEN https AND NOT cert_valid THEN 1 ELSE 0 END) as with_bad_cert,
            ROUND(AVG(CASE WHEN https THEN score ELSE NULL END), 1) as avg_https_score,
            SUM(CASE WHEN hsts THEN 1 ELSE 0 END) as with_hsts,
            SUM(CASE WHEN dnssec THEN 1 ELSE 0 END) as with_dnssec,
            SUM(CASE WHEN dmarc_policy = 'reject' THEN 1 ELSE 0 END) as dmarc_reject,
            SUM(CASE WHEN dmarc_policy = 'quarantine' THEN 1 ELSE 0 END) as dmarc_quarantine,
            SUM(CASE WHEN git_exposed THEN 1 ELSE 0 END) as git_exposed,
            SUM(CASE WHEN env_exposed THEN 1 ELSE 0 END) as env_exposed,
            SUM(CASE WHEN cpanel_detected THEN 1 ELSE 0 END) as cpanel,
            SUM(CASE WHEN admin_panel_detected THEN 1 ELSE 0 END) as admin_panels,
            SUM(CASE WHEN http_status = 0 THEN 1 ELSE 0 END) as unreachable,
            CAST(MAX((SELECT MAX(scan_timestamp) FROM scans)) AS VARCHAR) as last_scan
        FROM latest
        WHERE rn = 1
    """).fetchdf()
    summary.to_json(f"{out_dir}/summary.json", orient="records")
    
    # Scorecard — latest scan per domain with full evidence
    scorecard = db.execute("""
        WITH latest AS (
            SELECT *,
                   ROW_NUMBER() OVER (PARTITION BY domain ORDER BY scan_timestamp DESC) as rn
            FROM scans
        )
        SELECT 
            l.domain,
            d.bank_name, d.bank_type, d.dicgc_category,
            l.http_status, l.https, l.cert_valid,
            l.tls_version, l.hsts, l.hsts_max_age, l.hsts_subdomains, l.hsts_preload,
            l.x_frame_options, l.x_content_type, l.content_security,
            l.server_header, l.title,
            l.dnssec, l.dmarc_policy, l.dmarc_subdomain, l.dmarc_pct,
            l.spf_record, l.spf_hardfail, l.has_mx,
            l.git_exposed, l.env_exposed, l.phpinfo_exposed,
            l.cpanel_detected, l.admin_panel_detected,
            l.ip_address, l.cloud_provider,
            l.score,
            CAST(l.scan_timestamp AS VARCHAR) as scan_timestamp
        FROM latest l
        LEFT JOIN domains d ON l.domain = d.domain
        WHERE l.rn = 1
        ORDER BY l.score ASC
    """).fetchdf()
    scorecard.to_json(f"{out_dir}/scorecard.json", orient="records")
    
    s = summary.to_dict(orient="records")[0]
    c = len(scorecard)
    print(f"Exported: {c} domains, avg {s['avg_score']}, valid HTTPS {s['with_valid_https']}, HSTS {s['with_hsts']}, DNSSEC {s['with_dnssec']}")
    
    # Also compute and display grade distribution
    a = len([r for r in scorecard.to_dict(orient="records") if r["score"] >= 80])
    b = len([r for r in scorecard.to_dict(orient="records") if 60 <= r["score"] < 80])
    c_ = len([r for r in scorecard.to_dict(orient="records") if 40 <= r["score"] < 60])
    d = len([r for r in scorecard.to_dict(orient="records") if 20 <= r["score"] < 40])
    f = len([r for r in scorecard.to_dict(orient="records") if r["score"] < 20])
    print(f"  Grades: A={a} B={b} C={c_} D={d} F={f}")

if __name__ == "__main__":
    main()
