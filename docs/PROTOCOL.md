# Protocol

Everything the three implementations ([`webhooks.rs`](../rust/webhooks.rs), [`Webhooks.cs`](../csharp/Webhooks.cs),
the [TypeScript submodule](../typescript/src/index.ts)) do on the wire. They behave identically, and the same e2e
suite runs against each.

## Configuration

### `WEBHOOK_SOURCES` (env var, JSON)

An object keyed by source name. The name is the last path segment of the route (`POST /route/webhooks/<name>`), so
it must be lowercase without dots.

```jsonc
{
  "github":  { "kind": "github",   "secret": "..." },
  "twitch":  { "kind": "twitch",   "secret": "..." },
  "stripe":  { "kind": "stripe",   "secret": "whsec_..." },
  "app":     { "kind": "standard", "secrets": ["whsec_new...", "whsec_old..."] },   // rotation: any may match
  "discord": { "kind": "discord",  "public_key": "<64 hex chars>" },
  "custom":  { "kind": "hmac", "secret": "...", "header": "X-Signature", "prefix": "sha256=",
               "encoding": "hex", "id_header": "X-Request-Id", "type_header": "X-Event-Type" }
}
```

| Option | Applies to | Default |
|---|---|---|
| `secret` / `secrets` | all but `discord` | required (one or more) |
| `public_key` | `discord` | required |
| `header`, `prefix`, `encoding` (`hex` or `base64`) | `hmac` | `x-signature`, none, `hex` |
| `id_header`, `type_header` | `hmac` | none: the id is the body's SHA-256, the type is empty |
| `tolerance_secs` | timestamped kinds | 600 for `twitch`, 300 otherwise |

The TypeScript submodule can't read env vars, so the consumer passes the string to `inbox()`.

### `WEBHOOK_RETRY_SECS` (env var, optional)

Outbound retry delays in seconds, comma-separated. Default `5,30,120,600,1800,3600,7200,14400`: 9 attempts over
about 7.5 hours. After the last one, the message is a dead letter. (TypeScript: pass it to `configure()`.)

## Inbound

`POST /route/webhooks/<name>`. Headers are case-insensitive; repeated header lines are joined.

| Kind | Signed content | Signature | Key | Window | Delivery id | Event type |
|---|---|---|---|---|---|---|
| `standard` | `{webhook-id}.{webhook-timestamp}.{body}` | `webhook-signature`: space-separated `v1,<base64>` | base64-decoded part after `whsec_` | 300 s | `webhook-id` | body `type` |
| `github` | `{body}` | `X-Hub-Signature-256: sha256=<hex>` | the secret's bytes | none | `X-GitHub-Delivery` | `X-GitHub-Event` |
| `twitch` | `{message-id}{message-timestamp}{body}` | `Twitch-Eventsub-Message-Signature: sha256=<hex>` | the secret's bytes | 600 s (RFC 3339, nanoseconds OK) | `Twitch-Eventsub-Message-Id` | `Twitch-Eventsub-Subscription-Type`, or `revocation` |
| `stripe` | `{t}.{body}` | `Stripe-Signature: t=<unix>,v1=<hex>[,v1=…]` | the secret's bytes (`whsec_…` as-is) | 300 s | body `id` | body `type` |
| `discord` | `{X-Signature-Timestamp}{body}` | `X-Signature-Ed25519: <hex>` | `public_key` | 300 s | body `id` | `application_command`, `message_component`, `application_command_autocomplete`, `modal_submit` |
| `hmac` | `{body}` | `<header>: <prefix><hex or base64>` | the secret's bytes | none | `id_header`, else SHA-256 of the body | `type_header`, else empty |

All HMACs are HMAC-SHA256, compared in constant time. A missing id falls back to the body's SHA-256.

### Responses

| Situation | Status | Body |
|---|---|---|
| Applied | 200 | `{"ok":true}`, or your handler's JSON reply |
| Already applied (same source + delivery id within 7 days) | 200 | `{"ok":true,"duplicate":true}` |
| Twitch `webhook_callback_verification` (after verifying) | 200 | the `challenge`, as `text/plain` |
| Discord PING, type 1 (after verifying) | 200 | `{"type":1}` |
| Discord, handler returned no reply | 200 | `{"type":5}` (commands, modals), `{"type":6}` (components), `{"type":8,"data":{"choices":[]}}` (autocomplete) |
| Missing or bad signature, stale timestamp | 401 | `{"error": "..."}` |
| Route registered but source not configured | 404 | `{"error": "..."}` |
| Your handler failed | 500 | `{"error": "..."}`: nothing was recorded, so the sender's retry is applied fresh |

### Exactly once

The dedupe row (`source|id`) and your handler's writes are in **one transaction**. A duplicate never reaches your
handler, and a failed handler leaves no dedupe row behind. Dedupe rows are pruned after 7 days, which is longer
than any sender's retry window.

## Outbound

### Request

```http
POST <endpoint url>
content-type: application/json
user-agent: spacetimedb-webhooks/0.1
webhook-id: msg_<epoch>_<n>
webhook-timestamp: <unix seconds, this attempt>
webhook-signature: v1,<base64 HMAC-SHA256(key, "{webhook-id}.{webhook-timestamp}.{body}")>

{"type":"order.paid","timestamp":"2026-10-09T18:09:00.123456Z","data":{...}}
```

- `key` is the base64-decoded part of the endpoint's `whsec_…` secret (or the raw string, if it isn't `whsec_`).
- `webhook-id` is the same on every retry; the timestamp and signature are fresh per attempt.
- The body is fixed when the event is queued.

### Outcomes

| Receiver answers | Result |
|---|---|
| 2xx | delivered |
| 410 Gone | endpoint disabled (`disabled_reason`), its queued messages become dead letters |
| anything else, or a transport error / 15 s timeout | retry per `WEBHOOK_RETRY_SECS`, then a dead letter |

### Library API

| | Rust | C# | TypeScript |
|---|---|---|---|
| Setup | `init(ctx)` | `WebhooksInit(ctx)` | `configure(ctx.as.webhooks, { retrySecs })` |
| Routes | `router(&[..])` | `WebhookRoutes(router, ..)` | `routes(router, handler, [..])` |
| Endpoints | `add_endpoint`, `remove_endpoint`, `set_endpoint_enabled` | `WebhookAddEndpoint`, … | `addEndpoint`, … |
| Send | `send(ctx, type, data)`, `send_to(ctx, endpoint, type, data)` | `WebhookSend`, `WebhookSendTo` | `send`, `sendTo` |
| Dead letters | `redeliver_dead(ctx, endpoint)` | `WebhookRedeliverDead` | `redeliverDead` |
| Dashboard data | `state_json(ctx)` | `WebhookStateJson(tx)` | `stateJson(ctx)` |
| Re-run setup after an env-only publish | reducer `webhooks_kick` | reducer `webhooks_kick` | your own kick reducer calling `configure` |

## Tables

All private. Canonical names are the same in Rust and C#; the TypeScript submodule's live under its namespace
(`webhooks.outbox`, …).

| Table | Purpose |
|---|---|
| `webhook_seen` | `source\|id` → when; dedupe, pruned after 7 days |
| `webhook_endpoint` | outbound endpoints and secrets |
| `webhook_outbox` | queued, in-flight and dead messages |
| `webhook_log` | the last ~500 events in both directions, metadata only |
| `webhook_state` | epoch for message ids |
| `webhook_flush_job`, `webhook_prune_job` | schedules |
