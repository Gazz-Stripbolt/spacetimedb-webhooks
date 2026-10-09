#!/usr/bin/env bash
# Publish a demo module with the test configuration and run the e2e suite against it.
#
#   scripts/e2e.sh rust|csharp|typescript
#
# Needs a local server that allows module HTTP to loopback (scripts/dev-server.sh), because the
# outbound tests deliver to a receiver on 127.0.0.1 and back into the module itself.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LANG_=${1:?usage: $0 rust|csharp|typescript}
SERVER=${SERVER:-local}
HTTP=${HTTP:-http://127.0.0.1:3000}
DB=${DB:-wh-$LANG_}

cd "$ROOT"
[[ $LANG_ != typescript || -f demo/typescript/src/page.gen.ts ]] || node demo/dashboard/gen.mjs
echo "== publish demo/$LANG_ as $DB"
WEBHOOK_SOURCES=$(node tests/fixtures.mjs sources) WEBHOOK_RETRY_SECS=0.3,0.6,1 \
  spacetime publish -s "$SERVER" -y "$DB" -p "demo/$LANG_" --delete-data >/dev/null
echo "== e2e"
BASE="$HTTP/v1/database/$DB/route" npx tsx tests/e2e.test.mts
