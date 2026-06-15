#!/usr/bin/env bash
# .bank.in Security Scorecard - Phase 1: HTTP Header Scanner
# Uses curl for each domain, outputs CSV
set -euo pipefail

DOMAINS_FILE="$1"
OUTPUT_DIR="${2:-../data}"
BATCH_SIZE=50
TMPDIR="$(mktemp -d)"

do_scan() {
  local domain="$1"
  local outfile="$2"
  
  # HTTP headers via curl
  local headers curl_rc hsts xfo xct csp server title status cert_issuer tls_ver
  
  headers=$(curl -skL --max-time 10 -o /dev/null -w "%{http_code}\t%{ssl_verify_result}\t%{content_type}\t" \
    "https://$domain" 2>/dev/null) || true
  
  # Get full headers for security check
  local full_headers
  full_headers=$(curl -skIL --max-time 10 "https://$domain" 2>/dev/null | grep -iE "^strict-transport-security|^x-frame-options|^x-content-type-options|^content-security-policy|^server:|^<title" | head -20) || true
  
  hsts=$(echo "$full_headers" | grep -ci "strict-transport-security" || echo "0")
  hsts_preload=$(echo "$full_headers" | grep -ci "preload" || echo "0")
  xfo=$(echo "$full_headers" | grep -i "x-frame-options" | head -1 | sed 's/.*: //' | tr -d '\r')
  xct=$(echo "$full_headers" | grep -i "x-content-type-options" | head -1 | sed 's/.*: //' | tr -d '\r')
  csp=$(echo "$full_headers" | grep -i "content-security-policy" | head -1 | sed 's/.*: //' | tr -d '\r')
  server=$(echo "$full_headers" | grep -i "^server:" | head -1 | sed 's/.*: //' | tr -d '\r')
  title=$(curl -skL --max-time 10 "https://$domain" 2>/dev/null | grep -oP '<title>[^<]+' | head -1 | sed 's/<title>//' | tr -d '\r\n' | cut -c1-200) || true
  
  # TLS version
  tls_ver=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | grep -oP 'TLSv\d+\.\d+' | head -1) || tls_ver=""
  
  # Path checks (admin panels, cPanel, git)
  cpanel=0; admin=0; git=0; env=0; phpinfo=0
  curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "https://$domain/cpanel" 2>/dev/null | grep -qv "^404$|^000$|^406$" && cpanel=1 || true
  curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "https://$domain/admin" 2>/dev/null | grep -qv "^404$|^000$|^406$" && admin=1 || true
  curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "https://$domain/.git/config" 2>/dev/null | grep -qv "^404$|^000$|^406$" && git=1 || true
  curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "https://$domain/.env" 2>/dev/null | grep -qv "^404$|^000$|^406$" && env=1 || true
  curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "https://$domain/phpinfo.php" 2>/dev/null | grep -qv "^404$|^000$|^406$" && phpinfo=1 || true
  
  # IP address
  ip=""
  ip=$(dig +short "$domain" A 2>/dev/null | head -1) || ip=""
  
  # Cloud provider
  cloud=""
  case "$ip" in
    3.*) cloud="AWS" ;;
    13.*|20.*|40.*|52.*) cloud="Azure" ;;
    34.*|35.*|104.1*) cloud="GCP" ;;
    104.1[6-9]*|104.2*|172.64*|172.65*) cloud="Cloudflare" ;;
  esac
  
  http_status=$(echo "$headers" | cut -f1)
  [ -z "$http_status" ] && http_status="0"
  
  # Write result: domain|http_status|https|hsts|hsts_preload|xfo|xct|csp|server|title|cpanel|admin|git|env|phpinfo|ip|cloud|tls_ver
  echo -e "$domain\t$http_status\t1\t$hsts\t$hsts_preload\t$xfo\t$xct\t$csp\t$server\t$title\t$cpanel\t$admin\t$git\t$env\t$phpinfo\t$ip\t$cloud\t$tls_ver"
}

export -f do_scan

# Process in batches
echo -e "domain\thttp_status\thttps\thsts\thsts_preload\tx_frame_options\tx_content_type\tcsp\t_server_title\tcpanel\tadmin\tgit\tenv\tphpinfo\tip\tcloud\ttls_ver" > "$OUTPUT_DIR/http_scan.tsv"
total=$(wc -l < "$DOMAINS_FILE")
count=0

# Split into batch files
mkdir -p "$TMPDIR/batches"
split -l "$BATCH_SIZE" "$DOMAINS_FILE" "$TMPDIR/batches/batch_"

for batch_file in "$TMPDIR/batches"/*; do
  while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    do_scan "$domain" >> "$OUTPUT_DIR/http_scan.tsv" 2>/dev/null || true
    count=$((count + 1))
    if [ $((count % 50)) -eq 0 ]; then
      echo "  HTTP: $count/$total domains" >&2
    fi
  done < "$batch_file"
done

rm -rf "$TMPDIR"
echo "HTTP scan complete: $total domains -> $OUTPUT_DIR/http_scan.tsv" >&2
