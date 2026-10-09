# Demo

A module that accepts webhooks from six senders (`github`, `twitch`, `stripe`, `app` (Standard Webhooks), `discord`,
`custom` (generic HMAC)) and sends its own to any endpoints you add. It serves a live dashboard at `/route/`. The
same demo exists in Rust, C# and TypeScript.

```bash
scripts/dev-server.sh build && scripts/dev-server.sh start   # or `spacetime start`, if you won't deliver to localhost
WEBHOOK_SOURCES="$(node tests/fixtures.mjs sources)" spacetime publish -s local webhooks -p demo/rust
open http://127.0.0.1:3000/v1/database/webhooks/route/
```

`tests/fixtures.mjs` has the test secrets and signers, so you can sign requests by hand. `scripts/e2e.sh <lang>`
publishes a demo and runs the full suite against it. `scripts/bench.sh <lang>` measures throughput.

The demo's `/demo/send` and `/demo/endpoint` routes and the dashboard are open to anyone who can reach the module.
They're for trying it out; a real module would put its own auth in front.
