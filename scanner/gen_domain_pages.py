#!/usr/bin/env python3
"""Generate per-domain detail HTML pages with evidence from scorecard.json"""
import json, os, html

DATA_FILE = "/home/workspace/Projects/bankin-scorecard/data/scorecard.json"
OUT_DIR = "/home/workspace/Projects/bankin-scorecard/site/domains"

def esc(s):
    return html.escape(str(s or ""))

def grade_letter(score):
    if score >= 80: return "A"
    if score >= 60: return "B"
    if score >= 40: return "C"
    if score >= 20: return "D"
    return "F"

def grade_color(grade):
    return {"A": "#22c55e", "B": "#3b82f6", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}.get(grade, "#89847a")

def page_html(d):
    grade = grade_letter(d["score"])
    gcol = grade_color(grade)

    # Compute category points
    https_pts = 10 if d.get("https") else 0
    tls_pts = 5 if str(d.get("tls_version","")).startswith("TLSv1.3") else 3 if str(d.get("tls_version","")).startswith("TLSv1.2") else 0
    hsts_pts = 7 if d.get("hsts") else 0
    hsts_pre_pts = 3 if d.get("hsts_preload") else 0
    xfo_pts = 5 if d.get("x_frame_options") else 0
    xct_pts = 5 if d.get("x_content_type") == "nosniff" else 0
    csp_pts = 5 if d.get("content_security") else 0
    dmarc_p = str(d.get("dmarc_policy",""))
    dmarc_pts = 12 if dmarc_p == "reject" else 8 if dmarc_p == "quarantine" else 4 if dmarc_p else 0
    spf_pts = 4 if d.get("spf_record") else 0
    mx_pts = 4 if d.get("has_mx") else 0
    dnssec_pts = 10 if d.get("dnssec") else 0
    no_git_pts = 5 if not d.get("git_exposed") else 0
    no_env_pts = 5 if not d.get("env_exposed") else 0
    no_cp_pts = 5 if not d.get("cpanel_detected") else 0
    http_ok_pts = 5 if d.get("http_status", 0) in (200, 301, 302) else 0
    http_any_pts = 5 if d.get("http_status", 0) not in (0, 404, 406) else 0

    cat = [
        ("HTTPS / TLS", 15, https_pts + tls_pts, [
            ("HTTPS enabled", d.get("https"), https_pts),
            (str(d.get("tls_version","No TLS")), bool(d.get("tls_version")), tls_pts),
        ]),
        ("HSTS", 10, hsts_pts + hsts_pre_pts, [
            ("Strict-Transport-Security header", d.get("hsts"), hsts_pts),
            ("Preload ready", d.get("hsts_preload"), hsts_pre_pts),
        ]),
        ("Security Headers", 15, xfo_pts + xct_pts + csp_pts, [
            ("X-Frame-Options: " + esc(d.get("x_frame_options","") or "missing"), bool(d.get("x_frame_options")), xfo_pts),
            ("X-Content-Type-Options: " + esc(d.get("x_content_type","") or "missing"), d.get("x_content_type") == "nosniff", xct_pts),
            ("Content-Security-Policy present", d.get("content_security"), csp_pts),
        ]),
        ("Email Security", 20, dmarc_pts + spf_pts + mx_pts, [
            ("DMARC: " + (dmarc_p or "not set"), bool(dmarc_p), dmarc_pts),
            ("SPF record " + ("present" if d.get("spf_record") else "missing"), bool(d.get("spf_record")), spf_pts),
            ("MX record " + ("present" if d.get("has_mx") else "missing"), d.get("has_mx"), mx_pts),
        ]),
        ("DNSSEC", 10, dnssec_pts, [
            ("DNSSEC (DNSKEY record)", d.get("dnssec"), dnssec_pts),
        ]),
        ("Exposure Checks", 20, no_git_pts + no_env_pts + no_cp_pts, [
            ("/.git/config " + ("EXPOSED" if d.get("git_exposed") else "not exposed"), not d.get("git_exposed"), no_git_pts),
            ("/.env " + ("EXPOSED" if d.get("env_exposed") else "not exposed"), not d.get("env_exposed"), no_env_pts),
            ("cPanel " + ("DETECTED" if d.get("cpanel_detected") else "not detected"), not d.get("cpanel_detected"), no_cp_pts),
        ]),
        ("HTTP Reachability", 10, http_ok_pts + http_any_pts, [
            ("Status " + str(d.get("http_status",0)), d.get("http_status",0) in (200,301,302), http_ok_pts),
            ("Non-error response", d.get("http_status",0) not in (0,404,406), http_any_pts),
        ]),
    ]

    cat_html = ""
    for name, max_pts, earned, items in cat:
        bar_pct = (earned / max_pts * 100) if max_pts > 0 else 0
        bar_col = "#22c55e" if earned >= max_pts else "#f0b429" if earned > 0 else "rgba(255,255,255,0.12)"
        items_html = "".join(
            f'<div class="ev-item"><span class="ev-icon">{chr(10003) if ok else chr(10007)}</span><span>{esc(label)}</span><span class="ev-pts">{pts}</span></div>'
            for label, ok, pts in items
        )
        cat_html += f"""
        <div class="cat-card">
            <div class="cat-hdr"><h3>{esc(name)}</h3><span class="cat-score">{earned}/{max_pts}</span></div>
            <div class="cat-bar"><div class="cat-bar-fill" style="width:{bar_pct:.0f}%;background:{bar_col}"></div></div>
            <div class="ev-list">{items_html}</div>
        </div>"""

    dm = esc(d["domain"])
    bank = esc(d.get("bank_name","") or "")
    btype = esc(d.get("bank_type","") or "")
    ip = esc(d.get("ip_address","") or "N/A")
    cloud = esc(d.get("cloud_provider","") or "Unknown")
    title_text = esc(d.get("page_title","") or "")
    ts = esc(d.get("scan_timestamp","") or "")
    raw = json.dumps(d, indent=2)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{dm} — .bank.in Security Scorecard</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
body{{font-family:system-ui,sans-serif;background:#0a0a0f;color:#e8e6e3;min-height:100vh}}
.cat-card{{background:rgba(18,18,26,0.85);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:16px}}
.cat-hdr{{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}}
.cat-hdr h3{{font-size:14px;font-weight:600;color:#e8e6e3}}
.cat-score{{font-size:13px;font-family:monospace;color:{gcol}}}
.cat-bar{{width:100%;height:6px;background:rgba(255,255,255,0.06);border-radius:3px;margin-bottom:12px}}
.cat-bar-fill{{height:100%;border-radius:3px;transition:width .3s}}
.ev-list{{display:flex;flex-direction:column;gap:6px;font-size:13px;color:#89847a}}
.ev-item{{display:flex;align-items:center;gap:8px}}
.ev-icon{{font-weight:bold;width:16px;text-align:center}}
.ev-icon:has(:nth-child(1):first-letter) {{ }}
.ev-pts{{margin-left:auto;font-family:monospace;font-size:11px;opacity:0.7}}
.grade-badge{{width:64px;height:64px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:900;border:2px solid}}
</style>
</head>
<body>
<nav class="border-b border-zinc-800 px-6 py-4 flex items-center gap-4">
  <h1 class="text-lg font-bold">🔒 .bank.in Security Scorecard</h1>
  <span class="text-sm text-zinc-500">by CashlessConsumer</span>
  <a href="../" class="ml-auto text-sm text-emerald-500 hover:text-emerald-400">&larr; Dashboard</a>
  <a href="../about.html" class="text-sm text-zinc-500 hover:text-zinc-400">About</a>
</nav>
<main class="max-w-4xl mx-auto px-4 py-8">
  <div class="flex items-start gap-4 mb-8">
    <div class="grade-badge" style="background:{gcol}22;color:{gcol};border-color:{gcol}44">{grade}</div>
    <div>
      <h2 class="text-2xl font-bold">{dm}</h2>
      {f'<p class="text-zinc-400 text-lg">{bank}</p>' if bank else ''}
      <div class="flex flex-wrap gap-2 mt-2">
        {f'<span class="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">{esc(btype)}</span>' if btype else ''}
        <span class="text-xs px-2 py-0.5 rounded font-mono" style="background:rgba(255,255,255,0.06);color:{gcol}">Score: {d["score"]}/100</span>
      </div>
    </div>
  </div>
  <h3 class="text-lg font-semibold mb-4" style="color:#f0b429">Evidence Breakdown</h3>
  <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
    {cat_html}
  </div>
  <details class="mb-8">
    <summary class="text-sm font-semibold cursor-pointer" style="color:#f0b429">Raw Scan Data</summary>
    <div class="mt-3 p-4 rounded-lg overflow-x-auto" style="background:rgba(18,18,26,0.85);border:1px solid rgba(255,255,255,0.08)">
      <pre class="text-xs leading-relaxed font-mono text-zinc-500">{esc(raw)}</pre>
    </div>
  </details>
  <div class="text-xs text-zinc-600 space-y-1">
    <p>IP: {ip} | Cloud: {cloud}</p>
    {f'<p>Title: {title_text}</p>' if title_text else ''}
    {f'<p>Last scanned: {ts}</p>' if ts else ''}
  </div>
  <div class="mt-8 text-center text-xs text-zinc-700 border-t border-zinc-800 pt-4">
    Built by CashlessConsumer — independent OSINT-based security assessment.
  </div>
</main>
</body>
</html>"""

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(DATA_FILE) as f:
        data = json.load(f)
    
    count = 0
    for d in data:
        domain = d["domain"]
        html_content = page_html(d)
        path = os.path.join(OUT_DIR, domain + ".html")
        with open(path, "w") as f:
            f.write(html_content)
        count += 1
        if count % 200 == 0:
            print(f"  {count}/{len(data)}")
    
    print(f"Generated {count} domain pages → {OUT_DIR}/")

if __name__ == "__main__":
    main()