# webhooks.rs: webhooks for Rust modules

One file. Copy [`webhooks.rs`](webhooks.rs) to your module's `src/webhooks.rs`.

```toml
# Cargo.toml (HTTP handlers need `unstable`)
spacetimedb = { version = "2.11.*", features = ["unstable"] }
http = "1"
serde_json = "1"
sha2 = "0.10"
hmac = "0.12"
base64 = "0.22"
ed25519-dalek = { version = "2", default-features = false, features = ["fast"] }
```

```rust
pub mod webhooks;
use spacetimedb::http::{Router, router};

#[spacetimedb::reducer(init)]
pub fn init(ctx: &ReducerContext) { webhooks::init(ctx); }

/// Verified, first-time deliveries, in the same transaction as the dedupe record.
/// Return Err to refuse (nothing is recorded; the sender retries). Return Some(json) to reply.
pub fn on_webhook(ctx: &ReducerContext, ev: &webhooks::WebhookEvent) -> Result<Option<String>, String> {
    match (ev.source.as_str(), ev.event_type.as_str()) {
        ("twitch", "channel.follow") => { /* ... */ }
        _ => {}
    }
    Ok(None)
}

#[router]
fn routes() -> Router {
    webhooks::router(&["github", "twitch", "stripe", "discord"])   // POST /route/webhooks/<name>
}
```

Configure sources with the `WEBHOOK_SOURCES` env var (see [PROTOCOL.md](../docs/PROTOCOL.md)). `webhooks.rs`
declares the module's `#[spacetimedb::env]` struct. If your module already has one, move the two fields into it.

Outbound, from any reducer:

```rust
webhooks::add_endpoint(ctx, "billing", "https://example.com/hooks", "whsec_...", &["order.*"])?;
webhooks::send(ctx, "order.paid", serde_json::json!({ "order": 42 }));
```

Also: `remove_endpoint`, `set_endpoint_enabled`, `send_to`, `redeliver_dead`, `state_json`, `sign_standard`,
`parse_sources`, and the `webhooks_kick` reducer (re-runs setup). A complete module is in
[`demo/rust`](../demo/rust/src/lib.rs).
