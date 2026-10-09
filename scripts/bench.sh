#!/usr/bin/env bash
# Publish a fresh demo database and measure inbound and outbound throughput.
#
#   scripts/bench.sh rust|csharp|typescript [N] [CONCURRENCY]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LANG_=${1:?usage: $0 rust|csharp|typescript [N] [C]}
HTTP=${HTTP:-http://127.0.0.1:3000}
DB=wh-bench-$LANG_
cd "$ROOT"
[[ $LANG_ != typescript || -f demo/typescript/src/page.gen.ts ]] || node demo/dashboard/gen.mjs
WEBHOOK_SOURCES=$(node tests/fixtures.mjs sources) spacetime publish -s "${SERVER:-local}" -y "$DB" -p "demo/$LANG_" --delete-data >/dev/null
BASE="$HTTP/v1/database/$DB/route" N=${2:-500} C=${3:-16} npx tsx tests/bench.mts
