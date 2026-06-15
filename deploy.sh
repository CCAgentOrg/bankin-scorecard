#!/usr/bin/env bash
set -e
cd /tmp/bankin-site
CLOUDFLARE_API_TOKEN="f749649faff56990a80b87826f870675:tA1HivMu9T22rUtb:HzWPJBVGTWyvJ-FO15TVSCmboOhNFUZK" npx wrangler pages deploy . --project-name=bankin-scorecard --branch=main 2>&1
