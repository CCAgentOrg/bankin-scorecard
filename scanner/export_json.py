#!/usr/bin/env python3
"""Export summary and scorecard JSON from DuckDB"""
import json, os, sys
import duckdb

def main():
    db_path = "/home/workspace/Projects/bankin-scorecard/data/scorecard.duckdb"
    out_dir = os.path.dirname(db_path)
    
    db = duckdb.connect(db_path)
    
    # Summary
    summary = db.execute("""
        SELECT 
            COUNT(*) as total,
            ROUND(AVG(score), 1) as avg_score,
            SUM(CASE WHEN https THEN 1 ELSE 0 END) as with_https,
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
            CAST(MAX(scan_timestamp) AS VARCHAR) as last_scan
        FROM scans
        WHERE scan_timestamp = (SELECT MAX(scan_timestamp) FROM scans)
    """).fetchdf()
    summary.to_json(f"{out_dir}/summary.json", orient="records")
    
    # Scorecard
    scorecard = db.execute("""
        SELECT 
            s.domain,
            d.bank_name,
            d.bank_type,
            d.dicgc_category,
            s.http_status,
            s.https,
            s.hsts,
            s.dnssec,
            s.dmarc_policy,
            s.tls_version,
            s.cert_issuer,
            s.git_exposed,
            s.env_exposed,
            s.cpanel_detected,
            s.admin_panel_detected,
            s.score,
            CAST(s.scan_timestamp AS VARCHAR) as scan_timestamp
        FROM scans s
        LEFT JOIN domains d ON s.domain = d.domain
        WHERE s.scan_timestamp = (SELECT MAX(scan_timestamp) FROM scans)
        ORDER BY s.score ASC
    """).fetchdf()
    scorecard.to_json(f"{out_dir}/scorecard.json", orient="records")
    
    s = summary.to_dict(orient="records")[0]
    c = len(scorecard)
    print(f"Exported: {c} domains, avg score {s['avg_score']}, HTTPS {s['with_https']}, HSTS {s['with_hsts']}, DNSSEC {s['with_dnssec']}")

if __name__ == "__main__":
    main()
