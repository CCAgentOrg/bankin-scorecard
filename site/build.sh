#!/usr/bin/env bash
set -e
mkdir -p dist dist/about
cp index.html dist/
cp about.html dist/about/index.html
mkdir -p dist/data
cp data/scorecard.json data/summary.json dist/data/
echo "Build complete: $(ls dist/ | wc -l) top-level items"
