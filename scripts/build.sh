#!/usr/bin/env bash
# hal-id: #HAL-20261107-0020-PK-S2
# Downloads inputs (pinned versions) and builds dist/tools.zip + dist/samples/. Free; touches no cloud resources.
set -euo pipefail
cd "$(dirname "$0")/.."
PY_EMBED_URL="https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip"
VBA_URL="https://raw.githubusercontent.com/jmcnamara/XlsxWriter/main/examples/vbaProject.bin"
cache=".cache"
mkdir -p "$cache/wheels"

[[ -f $cache/python-embed.zip ]] || curl -fsSL -o "$cache/python-embed.zip" "$PY_EMBED_URL"
[[ -f $cache/vbaProject.bin ]] || curl -fsSL -o "$cache/vbaProject.bin" "$VBA_URL"
# Windows wheels only (never installed or run on this Mac).
python3 -m pip download -q --only-binary=:all: --platform win_amd64 --python-version 3.12 \
  --implementation cp "oletools==0.60.2" "pdfid==1.1.3" -d "$cache/wheels"

rm -rf dist
python3 -I scripts/build_artifacts.py "$cache/wheels" "$cache/python-embed.zip" \
  "$cache/vbaProject.bin" sandbox/analyze.ps1 dist
