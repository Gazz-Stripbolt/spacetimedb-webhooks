# Findings

What we learned building webhooks on Spacetime 2.11.

## Numbers

Local, on a 2-vCPU VM shared with other builds, so treat them as rough. `scripts/bench.sh <lang> 500 16` on a fresh
database: 500 signed Standard Webhooks in, 16 at a time; then 500 events out to a local receiver.

| | Inbound (verify + dedupe + apply) | Outbound |
|---|---|---|
| Rust | ~1000-1500/s, p50 9-12 ms | ~170 sends/s, every one delivered within ~50 ms of the last send |
| C# (NativeAOT) | ~600-1350/s, p50 10-22 ms | ~95 sends/s, same |
| TypeScript | ~630/s, p50 20-24 ms | ~100 sends/s, same |

- **Push latency:** the receiver sees the POST 10-20 ms after the HTTP request that queued it (handler →
  commit → one-shot scheduled procedure → HTTP).
- Outbound throughput was bounded by how fast the bench could *queue* events (one HTTP round trip into the module
  per send). The flush procedure kept up the whole time.
- **A slow receiver doesn't stall the database.** With a receiver that took 3 s to answer, other routes and
  writes still took 5-30 ms while the delivery was in flight.

## Bug: the TypeScript SDK splits outbound header values on commas (reported: [#6123](https://github.com/clockworklabs/SpacetimeDB/issues/6123))

`ctx.http.fetch()` serializes headers with `headers-polyfill`'s `headersToList()`, which turns any value containing a
comma into **separate header lines**. The host then sends:

```http
webhook-signature: v1
webhook-signature: mf3NSumak46pFQ8AgeTg5fboQUCyeXw3TcawjLmuuSI=
```

and the receiver sees `v1, mf3NSum…`, which no Standard Webhooks verifier accepts. The same goes for any
single-valued header that contains a comma: `Stripe-Signature`-style schemes, HTTP Message Signatures, `Cookie`,
dates. (Inbound is fine, and so are Rust and C#.)

The submodule works around it by calling the same host function the SDK uses (`procedure_http_request` from
`spacetime:sys@2.0`) with headers it serializes itself (see `rawPost` in [`index.ts`](../typescript/src/index.ts)).
It reads the status code from the last two bytes of the response metadata, because the SDK's own `HttpResponse`
deserializer doesn't accept a `BinaryReader` from the main `spacetimedb` entry point ("Receiver must be an instance
of class"). The upstream fix is to stop splitting values in `serializeHeaders` (`http_shared.ts`).

A related quirk: the SDK's `fetch` throws on status codes the `statuses` package doesn't know (530 and similar), reported as [#6126](https://github.com/clockworklabs/SpacetimeDB/issues/6126).
The raw path doesn't care.

## Things worth knowing

- **Routes are static.** There are no path parameters or wildcards, and paths must be lowercase without dots.
  So the host registers one route per source name, all pointing at one handler that reads the last path segment.
- **HTTP handlers can read env vars, but submodules can't.** Rust and C# read `WEBHOOK_SOURCES` per request. The
  TypeScript consumer passes it in, and passes the retry schedule to `configure()` for the scheduled procedure.
- **Handlers can run several transactions.** The handler verifies outside any transaction, then runs dedupe +
  your code in one `with_tx`. Rejections are logged in a separate small transaction.
- **Auto-increment ids skip.** A rolled-back insert still uses up its id, so "delete row `id - 500`" log trimming
  (which [idc](https://github.com/Gazz-Stripbolt/spacetimedb-idc) uses) slowly leaks rows. These modules trim by
  `count()` instead.
- **Index the dead letters.** Scanning the whole outbox for due work gets slower as dead letters pile up, so
  `dead` is indexed and the flush only reads live rows.
- **Module RNGs are seeded from the timestamp**, so don't mint endpoint secrets inside the module. Generate
  them outside and pass them in.
- **GitHub signs no timestamp.** Replays within the 7-day dedupe window are caught by delivery id. Beyond that a
  captured request would verify again, so check `X-GitHub-Delivery` against your own records if it matters.
- **No crypto on wasi for C#.** `System.Security.Cryptography` isn't available, so `Webhooks.cs` carries a managed
  SHA-256, SHA-512 and an RFC 8032 Ed25519 verifier (BigInteger, not constant-time: fine for verifying public
  signatures). It passes the RFC 8032 vector and live Discord-style requests.

## Test vectors

The e2e suite first checks its own signers against published vectors, then sends real requests to each module:

- Standard Webhooks spec: secret `whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw`, id `msg_p5jXN8AQM9LWM0D4loKWxJek`,
  timestamp `1614265330`, body `{"test": 2432232314}` → `v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=`
- GitHub docs: secret `It's a Secret to Everybody`, body `Hello, World!` →
  `sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17`
- RFC 8032 test 1 (Ed25519, Discord): public key `d75a9801…511a`, empty message → signature `e5564300…7a100b`

Stripe and Twitch publish no fixed vectors. Their e2e tests sign with Node's crypto following each provider's
documented scheme.
