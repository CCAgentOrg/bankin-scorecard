#!/usr/bin/env python3
"""Export summary and scorecard JSON from DuckDB — includes all evidence fields"""
import json, os, sys
import duckdb

def main():
    db_path = "/home/workspace/Projects/bankin-scorecard/data/scorecard.duckdb"
    out_dir = os.path.dirname(db_path)

    db = duckdb.connect(db_path)

    # Temp view: latest scan per domain (fixes bug where each row has unique timestamp)
    db.execute("""
        CREATE OR REPLACE TEMP VIEW latest_scans AS
        SELECT domain, MAX(scan_timestamp) as max_ts
        FROM scans GROUP BY domain
    """)

    # Summary across all domains
    summary = db.execute("""
        SELECT
            COUNT(*) as total,
            ROUND(AVG(s.score), 1) as avg_score,
            SUM(CASE WHEN s.https THEN 1 ELSE 0 END) as with_https,
            SUM(CASE WHEN s.hsts THEN 1 ELSE 0 END) as with_hsts,
            SUM(CASE WHEN s.dnssec THEN 1 ELSE 0 END) as with_dnssec,
            SUM(CASE WHEN s.dmarc_policy = 'reject' THEN 1 ELSE 0 END) as dmarc_reject,
            SUM(CASE WHEN s.dmarc_policy = 'quarantine' THEN 1 ELSE 0 END) as dmarc_quarantine,
            SUM(CASE WHEN s.git_exposed THEN 1 ELSE 0 END) as git_exposed,
            SUM(CASE WHEN s.env_exposed THEN 1 ELSE 0 END) as env_exposed,
            SUM(CASE WHEN s.cpanel_detected THEN 1 ELSE 0 END) as cpanel,
            SUM(CASE WHEN s.admin_panel_detected THEN 1 ELSE 0 END) as admin_panels,
            SUM(CASE WHEN s.http_status = 0 THEN 1 ELSE 0 END) as unreachable,
            CAST(MAX(s.scan_timestamp) AS VARCHAR) as last_scan
        FROM scans s
        JOIN latest_scans l ON s.domain = l.domain AND s.scan_timestamp = l.max_ts
    """).fetchdf()
    summary.to_json(f"{out_dir}/summary.json", orient="records")

    # Full scorecard with all evidence fields
    scorecard = db.execute("""
        SELECT
            s.domain,
            d.bank_name,
            d.bank_type,
            d.dicgc_category,
            s.http_status,
            s.https,
            s.tls_version,
            s.hsts,
            s.hsts_preload,
            s.x_frame_options,
            s.x_content_type,
            s.content_security,
            s.dmarc_policy,
            s.spf_record,
            s.has_mx,
            s.dnssec,
            s.git_exposed,
            s.env_exposed,
            s.cpanel_detected,
            s.admin_panel_detected,
            s.server_header,
            s.title AS page_title,
            s.ip_address,
            s.cloud_provider,
            s.score,
            CAST(s.scan_timestamp AS VARCHAR) AS scan_timestamp
        FROM scans s
        JOIN latest_scans l ON s.domain = l.domain AND s.scan_timestamp = l.max_ts
        LEFT JOIN domains d ON s.domain = d.domain
        ORDER BY s.score ASC
    """).fetchdf()
    scorecard.to_json(f"{out_dir}/scorecard.json", orient="records")

    db.execute("DROP VIEW IF EXISTS latest_scans")

    s = summary.to_dict(orient="records")[0]
    c = len(scorecard)
    print(f"Exported: {c} domains, avg score {s['avg_score']}, HTTPS {s['with_https']}, HSTS {s['with_hsts']}, DNSSEC {s['with_dnssec']}")

if __name__ == "__main__":
    main()
