#!/usr/bin/env bash
# Crash test: kill -9 the server while a delivery is in flight, restart it from disk, and check the
# message is delivered again with no new traffic.
#
#   scripts/crash.sh rust|csharp|typescript
#
# The receiver holds the first delivery open, so the kill lands after the lease has committed and
# while the flush is waiting on HTTP. It starts its own on-disk dev server on PORT (default 3100),
# so it doesn't disturb the in-memory one the other tests use.
set -uo pipefail
cd "$(dirname "$0")/.."
LANG_=${1:?usage: $0 rust|csharp|typescript}
PORT=${PORT:-3100}
HTTP=http://127.0.0.1:$PORT
DB=wh-crash-$LANG_
BASE=$HTTP/v1/database/$DB/route
WAIT_SECS=${WAIT_SECS:-100}          # the lease is 60 s
DIR=$(mktemp -d)
LOG=$DIR/server.log
server=""
receiver=""

start() {
  PERSIST=1 LISTEN=127.0.0.1:$PORT scripts/dev-server.sh start >>"$LOG" 2>&1 &
  server=$!
  for _ in $(seq 120); do curl -sf -o /dev/null "$HTTP/v1/ping" && return 0; sleep 0.25; done
  echo "server didn't come up"; tail -20 "$LOG"; exit 1
}
crash() {
  pkill -9 -f -- "--data-dir $PWD/.dev-server/data-$PORT" 2>/dev/null
  [[ -n $server ]] && { kill -9 "$server" 2>/dev/null; wait "$server" 2>/dev/null; }
  server=""
}
cleanup() {
  crash
  [[ -n $receiver ]] && kill "$receiver" 2>/dev/null
  rm -rf ".dev-server/data-$PORT"
}
trap cleanup EXIT
hits() { [[ -f $DIR/hits ]] && wc -l <"$DIR/hits" || echo 0; }

rm -rf ".dev-server/data-$PORT"
start
npm run build -w typescript --silent >/dev/null
[[ $LANG_ != typescript || -f demo/typescript/src/page.gen.ts ]] || node demo/dashboard/gen.mjs
WEBHOOK_SOURCES=$(node tests/fixtures.mjs sources) WEBHOOK_RETRY_SECS=0.3,0.6,1 \
  spacetime publish -s "$HTTP" -y "$DB" -p "demo/$LANG_" >/dev/null 2>&1 || { echo "publish failed"; exit 1; }

node tests/crash-receiver.mjs "$DIR/port" "$DIR/hits" &
receiver=$!
for _ in $(seq 40); do [[ -s $DIR/port ]] && break; sleep 0.1; done

curl -sf -X POST "$BASE/demo/endpoint" -d "{\"name\":\"crash\",\"url\":\"http://127.0.0.1:$(cat "$DIR/port")/hook\",\"secret\":\"$(node -e "import('./tests/fixtures.mjs').then(m=>console.log(m.SECRETS.endpoint))")\",\"event_types\":[]}" >/dev/null \
  || { echo "couldn't add the endpoint"; exit 1; }
curl -sf -X POST "$BASE/demo/send" -d '{"event_type":"crash.test","data":{}}' >/dev/null \
  || { echo "couldn't queue the event"; exit 1; }

for _ in $(seq 150); do [[ $(hits) -ge 1 ]] && break; sleep 0.1; done
[[ $(hits) -ge 1 ]] || { echo "the first delivery never arrived"; exit 1; }
crash
echo "killed with a delivery in flight ($(sed -n 1p "$DIR/hits"))"
start

# A database loads on its first request, so keep asking: nothing runs on it until then.
t0=$SECONDS
while ((SECONDS - t0 < WAIT_SECS)); do
  curl -s -o "$DIR/state" "$BASE/api/state"
  [[ $(hits) -ge 2 ]] && break
  sleep 2
done
if [[ $(hits) -lt 2 ]]; then
  echo "STUCK: no redelivery within ${WAIT_SECS}s of the restart"
  head -c 1500 "$DIR/state"; echo
  exit 1
fi
[[ $(sed -n 1p "$DIR/hits") == "$(sed -n 2p "$DIR/hits")" ]] || { echo "redelivered a different message"; exit 1; }
echo "redelivered with the same webhook-id $((SECONDS - t0))s after the restart"
