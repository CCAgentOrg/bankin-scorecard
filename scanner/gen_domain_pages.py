#!/usr/bin/env python3
"""Generate per-domain detail HTML pages with evidence + tooltip explanations"""
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

# Tooltip definitions per parameter
TOOLTIPS = {
    "HTTPS enabled": ("HTTPS / TLS", "Encrypts all traffic between the user's browser and the bank's server using TLS certificates.", "Without HTTPS, all data — passwords, transactions, session tokens — travels in plaintext. Attackers on the same network can intercept everything via man-in-the-middle attacks. RBI mandates HTTPS for all bank websites."),
    "TLSv1.3": ("TLS Version", "TLS 1.3 is the latest secure protocol version.", "Old TLS versions have exploitable flaws like POODLE and BEAST. Banking APIs often require TLS 1.2 minimum."),
    "TLSv1.2": ("TLS Version", "TLS 1.2 is acceptable but older than 1.3.", "Old TLS versions have exploitable flaws like POODLE and BEAST. Banking APIs often require TLS 1.2 minimum."),
    "TLS": ("TLS Version", "The TLS protocol version determines the encryption strength of the connection.", "Old TLS versions have exploitable flaws. Attackers can force downgrade and decrypt traffic."),
    "Strict-Transport-Security header": ("HSTS", "Tells browsers to always connect via HTTPS, even if the user types http://.", "Without HSTS, attackers can intercept the first HTTP request and redirect to a fake site (SSL stripping)."),
    "Preload ready": ("HSTS Preload", "Submits the domain to browser vendors' hardcoded HSTS list for HTTPS from the first connection.", "Without preload, a new user's very first visit is still vulnerable to SSL stripping."),
    "X-Frame-Options": ("X-Frame-Options", "Prevents the page from being embedded in frames/iframes on other sites.", "Without XFO, attackers can embed the bank's page in an invisible iframe on a malicious site (clickjacking) — users unknowingly authorize transactions."),
    "X-Content-Type-Options": ("X-Content-Type-Options", "Tells browsers not to MIME-sniff responses. Only valid value is 'nosniff'.", "Without nosniff, attackers can upload a .jpg that executes as JavaScript, enabling cross-site scripting."),
    "Content-Security-Policy present": ("Content-Security-Policy", "Controls which scripts/styles/images the browser is allowed to load.", "Without CSP, any XSS vulnerability lets attackers inject arbitrary scripts — steal cookies, exfiltrate data, redirect users."),
    "DMARC": ("DMARC", "Tells receiving mail servers what to do with unauthenticated emails from this domain.", "Without DMARC=reject, anyone can spoof the bank's domain and send phishing emails. This is the #1 vector for bank fraud."),
    "SPF record": ("SPF", "Lists which mail servers are authorized to send email for the domain.", "Without SPF, attackers can send from any server pretending to be the bank. SPF alone is not enough but is critical for email auth."),
    "MX record": ("MX Record", "Specifies the mail server handling email for the domain.", "Missing MX means the bank can't receive email. Confirming MX exists means there is mail infrastructure that must be secured."),
    "DNSSEC": ("DNSSEC", "Cryptographically signs DNS records to prevent spoofing and cache poisoning.", "Without DNSSEC, attackers can poison DNS and redirect users to fake bank sites. The user types the correct URL but lands on the attacker's server."),
    ".git/config": ("Git Exposure", "The /.git/config path is publicly accessible, leaking the entire source repository.", "Complete source code leak — database credentials, API keys, internal architecture. Attackers find zero-days by reading the code."),
    ".env": (".env Exposure", "The /.env file is publicly accessible, leaking environment variables with secrets.", "Direct credential leak — database passwords, API keys, encryption keys. Often enough for full system compromise within minutes."),
    "cPanel": ("Admin Exposure", "The hosting control panel (cPanel) or phpinfo page is publicly accessible.", "Public admin panels are targets for brute-force. A cPanel breach gives attackers full hosting account control. phpinfo leaks server config."),
    "HTTP Status": ("HTTP Status", "The HTTP response code from the bank's web server.", "Non-responsive or error-status domains indicate misconfigured or abandoned sites that can't serve customers or be monitored."),
    "Non-error response": ("Reachability", "Whether the domain responds with a meaningful status code vs timeout/error.", "Domains that time out or error may indicate server misconfiguration, DDoS vulnerability, or abandoned infrastructure."),
}

def help_tip_html(label, what, risk):
    return f'''<span class="help-wrap" tabindex="0">
      <span class="help-icon">ⓘ</span>
      <span class="help-box">
        <strong>{esc(label)}</strong><br>
        {esc(what)}<br>
        <span style="color:#da7756;font-weight:600">Risk: </span>{esc(risk)}
      </span>
    </span>'''

def find_tooltip(label, pts):
    """Find best tooltip match for a label"""
    for key, (l, w, r) in TOOLTIPS.items():
        if key in label or label in key:
            return help_tip_html(l, w, r)
    # Generic fallback
    if pts > 0:
        return help_tip_html("Check Passed", "This security check passed.", "Failing this check could expose the domain to specific attacks depending on the category.")
    return help_tip_html("Check Failed", "This security check did not pass.", "Each failed check contributes to the overall risk profile of this banking domain.")

def page_html(d):
    grade = grade_letter(d["score"])
    gcol = grade_color(grade)

    # Compute category points
    https_pts = 10 if d.get("https") else 0
    tls_ver = str(d.get("tls_version",""))
    tls_pts = 5 if tls_ver.startswith("TLSv1.3") else 3 if tls_ver.startswith("TLSv1.2") else 0
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
            (tls_ver or "No TLS", bool(d.get("tls_version")), tls_pts),
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
            ("HTTP Status: " + str(d.get("http_status",0)), d.get("http_status",0) in (200,301,302), http_ok_pts),
            ("Non-error response", d.get("http_status",0) not in (0,404,406), http_any_pts),
        ]),
    ]

    cat_html = ""
    for name, max_pts, earned, items in cat:
        bar_pct = (earned / max_pts * 100) if max_pts > 0 else 0
        bar_col = "#22c55e" if earned >= max_pts else "#f0b429" if earned > 0 else "rgba(255,255,255,0.12)"
        items_html = "".join(
            f'<div class="ev-item"><span class="ev-icon">{chr(10003) if ok else chr(10007)}</span><span>{esc(label)}</span>{find_tooltip(label, pts)}<span class="ev-pts">{pts}/{max_pts}</span></div>'
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
body{{font-family:system-ui,sans-serif;background:#0a0a0f;color:#e8e6e3;min-height:100vh;font-size:14px}}
nav{{border-bottom:1px solid #27272a;padding:16px 24px;display:flex;align-items:center;gap:16px}}
nav h1{{font-size:18px;font-weight:700}}
nav a{{text-decoration:none}}
nav .nav-links{{margin-left:auto;display:flex;gap:16px;font-size:13px}}
.cat-card{{background:rgba(18,18,26,0.85);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:16px}}
.cat-hdr{{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}}
.cat-hdr h3{{font-size:14px;font-weight:600;color:#e8e6e3}}
.cat-score{{font-size:13px;font-family:monospace;color:{gcol}}}
.cat-bar{{width:100%;height:6px;background:rgba(255,255,255,0.06);border-radius:3px;margin-bottom:12px}}
.cat-bar-fill{{height:100%;border-radius:3px;transition:width .3s}}
.ev-list{{display:flex;flex-direction:column;gap:6px;font-size:13px;color:#89847a}}
.ev-item{{display:flex;align-items:center;gap:6px;flex-wrap:wrap}}
.ev-icon{{font-weight:bold;width:16px;text-align:center;font-size:14px}}
.ev-icon:has(:nth-child(1):first-letter){{}}
.ev-pts{{margin-left:auto;font-family:monospace;font-size:11px;opacity:0.7;white-space:nowrap}}
.grade-badge{{width:64px;height:64px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:900;border:2px solid;flex-shrink:0}}
/* Tooltip */
.help-wrap{{position:relative;display:inline-flex;cursor:help;font-size:12px;color:#666}}
.help-icon{{font-size:13px;line-height:1}}
.help-box{{display:none;position:absolute;z-index:100;bottom:100%;left:50%;transform:translateX(-50%);margin-bottom:6px;width:280px;padding:10px 12px;border-radius:8px;font-size:12px;line-height:1.5;background:#1a1a2e;border:1px solid rgba(255,255,255,0.12);color:#89847a;box-shadow:0 8px 24px rgba(0,0,0,0.4);pointer-events:none}}
.help-box::after{{content:'';position:absolute;top:100%;left:50%;transform:translateX(-50%);width:0;height:0;border-left:5px solid transparent;border-right:5px solid transparent;border-top:5px solid #1a1a2e}}
.help-wrap:hover .help-box,.help-wrap:focus .help-box{{display:block}}
.help-box strong{{color:#e8e6e3;display:block;margin-bottom:4px;font-size:13px}}
</style>
</head>
<body>
<nav>
  <h1>🔒 .bank.in Security Scorecard</h1>
  <span style="font-size:13px;color:#71717a">by CashlessConsumer</span>
  <div class="nav-links">
    <a href="../" style="color:#22c55e">&larr; Dashboard</a>
    <a href="../about.html" style="color:#a1a1aa">About</a>
  </div>
</nav>
<main class="max-w-4xl mx-auto px-4 py-8">
  <div class="flex items-start gap-4 mb-8">
    <div class="grade-badge" style="background:{gcol}22;color:{gcol};border-color:{gcol}44">{grade}</div>
    <div>
      <h2 class="text-2xl font-bold">{dm}</h2>
      {f'<p class="text-lg" style="color:#a1a1aa">{bank}</p>' if bank else ''}
      <div class="flex flex-wrap gap-2 mt-2">
        {f'<span class="text-xs px-2 py-0.5 rounded" style="background:rgba(255,255,255,0.06);color:#89847a">{esc(btype)}</span>' if btype else ''}
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
      <pre class="text-xs leading-relaxed font-mono" style="color:#71717a">{esc(raw)}</pre>
    </div>
  </details>
  <div class="text-xs" style="color:#52525b;space-y:1">
    <p>IP: {ip} | Cloud: {cloud}</p>
    {f'<p>Title: {title_text}</p>' if title_text else ''}
    {f'<p>Last scanned: {ts}</p>' if ts else ''}
  </div>
  <div class="mt-8 text-center text-xs" style="color:#3f3f46;border-top:1px solid #27272a;padding-top:16px">
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