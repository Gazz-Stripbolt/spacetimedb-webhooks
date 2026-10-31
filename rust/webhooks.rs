//! # webhooks.rs: verified inbound and signed outbound webhooks for SpacetimeDB
//!
//! Copy this file to your module's `src/webhooks.rs`, add `pub mod webhooks;` to `lib.rs`,
//! enable the `unstable` feature on `spacetimedb` (HTTP handlers need it), and implement one
//! function in the crate root:
//!
//! ```ignore
//! pub fn on_webhook(ctx: &ReducerContext, event: &webhooks::WebhookEvent) -> Result<Option<String>, String>
//! ```
//!
//! **Inbound.** Register `webhooks::router(&["github", "twitch", ...])` and configure each source
//! in the `WEBHOOK_SOURCES` env var. Each request is verified (GitHub, Twitch EventSub, Stripe,
//! Standard Webhooks, Discord interactions or a generic HMAC), checked against a replay window,
//! deduplicated by its delivery id, and handed to `on_webhook` *in the same transaction* as the
//! dedupe record. If your handler fails, nothing is recorded and the sender's retry gets a clean
//! second chance.
//!
//! **Outbound.** [`add_endpoint`] registers a URL and its secret; [`send`] writes the event to a
//! transactional outbox, so it exists if and only if your change commits. A one-shot scheduled
//! procedure POSTs it right after the commit, signed per the Standard Webhooks spec, and retries
//! with backoff until it's delivered or dead.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use spacetimedb::http::{Body, HandlerContext, Request, Response, Router, Timeout, handler};
use spacetimedb::{ProcedureContext, ReducerContext, ScheduleAt, Table, TimeDuration, Timestamp};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Owner-set configuration. A module has one env declaration: if yours already has one,
/// move these fields into it and delete this struct.
#[spacetimedb::env]
pub struct Env {
    /// JSON object of inbound sources, e.g.
    /// `{"github":{"kind":"github","secret":"..."},"discord":{"kind":"discord","public_key":"<hex>"}}`.
    /// See docs/PROTOCOL.md for every kind and option.
    pub WEBHOOK_SOURCES: Option<String>,
    /// Outbound retry delays in seconds, comma-separated. Default `5,30,120,600,1800,3600,7200,14400`.
    pub WEBHOOK_RETRY_SECS: Option<String>,
}

const DEFAULT_RETRY_SECS: &[f64] = &[5.0, 30.0, 120.0, 600.0, 1800.0, 3600.0, 7200.0, 14400.0];
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const LEASE: Duration = Duration::from_secs(60);
const LOG_KEEP: u64 = 500;
const SEEN_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);

/// The kinds of inbound source this file can verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Standard,
    Github,
    Twitch,
    Stripe,
    Discord,
    Hmac,
}

impl Kind {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "standard" => Self::Standard,
            "github" => Self::Github,
            "twitch" => Self::Twitch,
            "stripe" => Self::Stripe,
            "discord" => Self::Discord,
            "hmac" => Self::Hmac,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Github => "github",
            Self::Twitch => "twitch",
            Self::Stripe => "stripe",
            Self::Discord => "discord",
            Self::Hmac => "hmac",
        }
    }

    fn default_tolerance(self) -> i64 {
        match self {
            Self::Twitch => 600,
            _ => 300,
        }
    }
}

/// One configured inbound source.
#[derive(Clone, Debug)]
pub struct Source {
    pub name: String,
    pub kind: Kind,
    /// Accepted secrets (more than one while you rotate).
    pub secrets: Vec<String>,
    /// Discord: the application's public key (hex).
    pub public_key: String,
    /// Generic HMAC: signature header, prefix and encoding (`hex` or `base64`).
    pub header: String,
    pub prefix: String,
    pub encoding: String,
    /// Generic HMAC: optional headers carrying a delivery id and an event type.
    pub id_header: String,
    pub type_header: String,
    /// Replay window in seconds (sources that sign a timestamp).
    pub tolerance_secs: i64,
}

/// Parse `WEBHOOK_SOURCES`.
pub fn parse_sources(raw: &str) -> Result<Vec<Source>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let v: Value =
        serde_json::from_str(raw).map_err(|e| format!("WEBHOOK_SOURCES is not JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or("WEBHOOK_SOURCES must be a JSON object")?;
    let mut out = Vec::new();
    for (name, cfg) in obj {
        let s = |k: &str| cfg[k].as_str().unwrap_or_default().to_string();
        let kind_str = s("kind");
        let kind = Kind::parse(&kind_str)
            .ok_or_else(|| format!("source `{name}`: unknown kind `{kind_str}`"))?;
        let mut secrets: Vec<String> = cfg["secrets"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(one) = cfg["secret"].as_str() {
            secrets.insert(0, one.to_string());
        }
        if kind == Kind::Discord && s("public_key").is_empty() {
            return Err(format!("source `{name}`: discord needs public_key"));
        }
        if kind != Kind::Discord && secrets.is_empty() {
            return Err(format!("source `{name}`: needs secret"));
        }
        out.push(Source {
            name: name.clone(),
            kind,
            secrets,
            public_key: s("public_key"),
            header: Some(s("header"))
                .filter(|h| !h.is_empty())
                .unwrap_or("x-signature".into())
                .to_lowercase(),
            prefix: s("prefix"),
            encoding: Some(s("encoding"))
                .filter(|h| !h.is_empty())
                .unwrap_or("hex".into()),
            id_header: s("id_header").to_lowercase(),
            type_header: s("type_header").to_lowercase(),
            tolerance_secs: cfg["tolerance_secs"]
                .as_i64()
                .unwrap_or(kind.default_tolerance()),
        });
    }
    Ok(out)
}

fn retry_schedule(raw: Option<String>) -> Vec<f64> {
    raw.map(|r| {
        r.split(',')
            .filter_map(|x| x.trim().parse::<f64>().ok())
            .filter(|x| x.is_finite() && *x >= 0.0)
            .collect::<Vec<_>>()
    })
    .filter(|v| !v.is_empty())
    .unwrap_or_else(|| DEFAULT_RETRY_SECS.to_vec())
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Delivery ids already applied, per source. Pruned after 7 days.
#[spacetimedb::table(accessor = webhook_seen)]
pub struct WebhookSeen {
    #[primary_key]
    pub key: String,
    #[index(btree)]
    pub at: Timestamp,
}

/// Outbound endpoints. Private: secrets never reach subscribers.
#[derive(Clone)]
#[spacetimedb::table(accessor = webhook_endpoint)]
pub struct WebhookEndpoint {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    #[unique]
    pub name: String,
    pub url: String,
    /// `whsec_<base64>` (Standard Webhooks). Raw strings work too.
    pub secret: String,
    /// Event types this endpoint wants: exact (`order.paid`), prefix (`order.*`) or `*`. Empty = all.
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub disabled_reason: String,
    pub created: Timestamp,
}

/// Events waiting to be delivered, one row per endpoint.
#[derive(Clone)]
#[spacetimedb::table(accessor = webhook_outbox)]
pub struct WebhookOutbox {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    #[index(btree)]
    pub endpoint_id: u64,
    /// The `webhook-id`: the same on every retry, so receivers can dedupe.
    pub msg_id: String,
    pub event_type: String,
    /// The exact JSON body, fixed at send time.
    pub body: String,
    pub created: Timestamp,
    pub attempts: u32,
    pub next_attempt: Timestamp,
    pub in_flight_until: Option<Timestamp>,
    /// Dead letters stay until you redeliver or remove them; indexed so the queue scan skips them.
    #[index(btree)]
    pub dead: bool,
    pub last_error: String,
}

/// Activity feed, both directions. Metadata only, never payloads or secrets.
#[spacetimedb::table(accessor = webhook_log)]
pub struct WebhookLog {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    pub at: Timestamp,
    /// `in` or `out`
    pub direction: String,
    /// The source (inbound) or endpoint (outbound) name.
    pub peer: String,
    pub event_type: String,
    pub msg_id: String,
    /// in: applied, duplicate, rejected, error, challenge, ping. out: queued, delivered, retry, dead, disabled.
    pub outcome: String,
    pub status: u16,
    pub detail: String,
    pub latency_us: i64,
}

#[spacetimedb::table(accessor = webhook_state)]
pub struct WebhookState {
    #[primary_key]
    pub key: u8,
    /// Makes message ids unique across database resets.
    pub epoch: String,
}

#[spacetimedb::table(accessor = webhook_flush_job, scheduled(webhook_flush))]
pub struct WebhookFlushJob {
    #[primary_key]
    #[auto_inc]
    pub scheduled_id: u64,
    pub scheduled_at: ScheduleAt,
}

#[spacetimedb::table(accessor = webhook_prune_job, scheduled(webhook_prune))]
pub struct WebhookPruneJob {
    #[primary_key]
    #[auto_inc]
    pub scheduled_id: u64,
    pub scheduled_at: ScheduleAt,
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

/// Call from your `init` reducer. Idempotent. Adding webhooks to a database that's already
/// published? Call the `webhooks_kick` reducer once instead.
pub fn init(ctx: &ReducerContext) {
    if ctx.db.webhook_state().key().find(0).is_none() {
        let epoch = format!("{:x}", ctx.timestamp.to_micros_since_unix_epoch());
        ctx.db
            .webhook_state()
            .insert(WebhookState { key: 0, epoch });
    }
    if ctx.db.webhook_prune_job().count() == 0 {
        ctx.db.webhook_prune_job().insert(WebhookPruneJob {
            scheduled_id: 0,
            scheduled_at: ScheduleAt::Interval(TimeDuration::from_duration(Duration::from_secs(
                3600,
            ))),
        });
    }
}

/// Re-run setup and flush the outbox. Safe for anyone to call.
#[spacetimedb::reducer]
pub fn webhooks_kick(ctx: &ReducerContext) {
    init(ctx);
    schedule_flush(ctx, ctx.timestamp);
}

/// The inbound routes, one per source name: `POST /webhooks/<name>`. Merge into your router.
/// Paths must be lowercase without dots (SpacetimeDB route rules).
pub fn router(sources: &[&str]) -> Router {
    sources.iter().fold(Router::new(), |r, name| {
        r.post(format!("/webhooks/{name}"), webhooks_inbox)
    })
}

// ---------------------------------------------------------------------------
// Inbound
// ---------------------------------------------------------------------------

/// A verified, not-yet-seen inbound webhook, handed to your `on_webhook`.
#[derive(Clone, Debug)]
pub struct WebhookEvent {
    /// The source name (the route segment).
    pub source: String,
    pub kind: Kind,
    /// The sender's delivery id (what dedupe uses).
    pub id: String,
    /// GitHub: `X-GitHub-Event`. Twitch: the subscription type, or `revocation`.
    /// Stripe/Standard: the body's `type`. Discord: `application_command`, `message_component`, ...
    pub event_type: String,
    /// The raw body (UTF-8).
    pub body: String,
}

enum Verified {
    /// Run the host handler.
    Event { id: String, event_type: String },
    /// Answer directly (Twitch challenge, Discord ping).
    Reply {
        outcome: &'static str,
        response: Response,
    },
}

type Reject = (StatusCode, String);

fn reject(msg: impl Into<String>) -> Reject {
    (StatusCode::UNAUTHORIZED, msg.into())
}

fn hdr(headers: &HeaderMap, name: &str) -> Option<String> {
    let parts: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    (!parts.is_empty()).then(|| parts.join(","))
}

fn need(headers: &HeaderMap, name: &str) -> Result<String, Reject> {
    hdr(headers, name).ok_or_else(|| reject(format!("missing {name} header")))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    s.len()
        .is_multiple_of(2)
        .then(|| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
                .collect()
        })
        .flatten()
}

fn mac(key: &[u8], parts: &[&[u8]]) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(key).expect("any key length works");
    for p in parts {
        m.update(p);
    }
    m
}

/// True if any candidate signature matches HMAC(key, parts), compared in constant time.
fn any_match(keys: &[Vec<u8>], parts: &[&[u8]], candidates: &[Vec<u8>]) -> bool {
    keys.iter().any(|k| {
        let m = mac(k, parts);
        candidates.iter().any(|c| m.clone().verify_slice(c).is_ok())
    })
}

/// Standard Webhooks secrets are `whsec_<base64>`; the key is the decoded bytes.
fn standard_key(secret: &str) -> Vec<u8> {
    let b = secret.strip_prefix("whsec_").unwrap_or(secret);
    B64.decode(b).unwrap_or_else(|_| secret.as_bytes().to_vec())
}

fn check_window(now: Timestamp, ts_secs: i64, tolerance: i64) -> Result<(), Reject> {
    let now_secs = now.to_micros_since_unix_epoch() / 1_000_000;
    if (now_secs - ts_secs).abs() > tolerance {
        return Err(reject("timestamp outside the allowed window"));
    }
    Ok(())
}

fn body_field(body: &[u8], key: &str) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| match &v[key] {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

fn verify(src: &Source, h: &HeaderMap, body: &[u8], now: Timestamp) -> Result<Verified, Reject> {
    let secrets: Vec<Vec<u8>> = src.secrets.iter().map(|s| s.as_bytes().to_vec()).collect();
    match src.kind {
        Kind::Standard => {
            let id = need(h, "webhook-id")?;
            let ts = need(h, "webhook-timestamp")?;
            let ts_secs: i64 = ts
                .trim()
                .parse()
                .map_err(|_| reject("bad webhook-timestamp"))?;
            check_window(now, ts_secs, src.tolerance_secs)?;
            // Space-separated `v1,<base64>` entries (several while the sender rotates keys).
            let sigs: Vec<Vec<u8>> = h
                .get_all("webhook-signature")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split_whitespace())
                .filter_map(|e| e.strip_prefix("v1,"))
                .filter_map(|b| B64.decode(b).ok())
                .collect();
            let keys: Vec<Vec<u8>> = src.secrets.iter().map(|s| standard_key(s)).collect();
            let prefix = format!("{id}.{ts_secs}.");
            if !any_match(&keys, &[prefix.as_bytes(), body], &sigs) {
                return Err(reject("bad signature"));
            }
            Ok(Verified::Event {
                id,
                event_type: body_field(body, "type"),
            })
        }
        Kind::Github => {
            let sig = need(h, "x-hub-signature-256")?;
            let sig = sig
                .strip_prefix("sha256=")
                .and_then(unhex)
                .ok_or_else(|| reject("malformed x-hub-signature-256"))?;
            if !any_match(&secrets, &[body], &[sig]) {
                return Err(reject("bad signature"));
            }
            // GitHub signs no timestamp: dedupe by delivery id is the only replay protection.
            let id = hdr(h, "x-github-delivery").unwrap_or_else(|| hex(&Sha256::digest(body)));
            Ok(Verified::Event {
                id,
                event_type: hdr(h, "x-github-event").unwrap_or_default(),
            })
        }
        Kind::Twitch => {
            let id = need(h, "twitch-eventsub-message-id")?;
            let ts = need(h, "twitch-eventsub-message-timestamp")?;
            let sig = need(h, "twitch-eventsub-message-signature")?;
            let sig = sig
                .strip_prefix("sha256=")
                .and_then(unhex)
                .ok_or_else(|| reject("malformed twitch-eventsub-message-signature"))?;
            if !any_match(&secrets, &[id.as_bytes(), ts.as_bytes(), body], &[sig]) {
                return Err(reject("bad signature"));
            }
            let at = Timestamp::parse_from_rfc3339(ts.trim())
                .map_err(|_| reject("bad message timestamp"))?;
            check_window(
                now,
                at.to_micros_since_unix_epoch() / 1_000_000,
                src.tolerance_secs,
            )?;
            match hdr(h, "twitch-eventsub-message-type")
                .unwrap_or_default()
                .as_str()
            {
                "webhook_callback_verification" => {
                    let challenge = body_field(body, "challenge");
                    Ok(Verified::Reply {
                        outcome: "challenge",
                        response: Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "text/plain")
                            .body(Body::from_bytes(challenge))
                            .expect("valid response"),
                    })
                }
                "revocation" => Ok(Verified::Event {
                    id,
                    event_type: "revocation".into(),
                }),
                _ => Ok(Verified::Event {
                    id,
                    event_type: hdr(h, "twitch-eventsub-subscription-type").unwrap_or_default(),
                }),
            }
        }
        Kind::Stripe => {
            let header_value = need(h, "stripe-signature")?;
            let mut t = None;
            let mut v1 = Vec::new();
            for part in header_value.split(',') {
                match part.trim().split_once('=') {
                    Some(("t", v)) => t = v.parse::<i64>().ok(),
                    Some(("v1", v)) => v1.extend(unhex(v)),
                    _ => {}
                }
            }
            let t = t.ok_or_else(|| reject("malformed stripe-signature"))?;
            check_window(now, t, src.tolerance_secs)?;
            let prefix = format!("{t}.");
            if !any_match(&secrets, &[prefix.as_bytes(), body], &v1) {
                return Err(reject("bad signature"));
            }
            Ok(Verified::Event {
                id: body_field(body, "id"),
                event_type: body_field(body, "type"),
            })
        }
        Kind::Hmac => {
            let sig = need(h, &src.header)?;
            let sig = sig
                .trim()
                .strip_prefix(src.prefix.as_str())
                .unwrap_or(sig.trim());
            let decoded = if src.encoding == "base64" {
                B64.decode(sig).ok()
            } else {
                unhex(sig)
            };
            let decoded = decoded.ok_or_else(|| reject("malformed signature"))?;
            if !any_match(&secrets, &[body], &[decoded]) {
                return Err(reject("bad signature"));
            }
            let id = (!src.id_header.is_empty())
                .then(|| hdr(h, &src.id_header))
                .flatten()
                .unwrap_or_else(|| hex(&Sha256::digest(body)));
            let event_type = (!src.type_header.is_empty())
                .then(|| hdr(h, &src.type_header))
                .flatten()
                .unwrap_or_default();
            Ok(Verified::Event { id, event_type })
        }
        Kind::Discord => {
            let sig = need(h, "x-signature-ed25519")?;
            let ts = need(h, "x-signature-timestamp")?;
            let key: [u8; 32] = unhex(&src.public_key)
                .and_then(|k| k.try_into().ok())
                .ok_or_else(|| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "bad discord public_key".to_string(),
                    )
                })?;
            let key = VerifyingKey::from_bytes(&key).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "bad discord public_key".to_string(),
                )
            })?;
            let sig: [u8; 64] = unhex(&sig)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| reject("malformed x-signature-ed25519"))?;
            let mut msg = ts.as_bytes().to_vec();
            msg.extend_from_slice(body);
            key.verify(&msg, &Signature::from_bytes(&sig))
                .map_err(|_| reject("bad signature"))?;
            let ts_secs: i64 = ts
                .trim()
                .parse()
                .map_err(|_| reject("bad x-signature-timestamp"))?;
            check_window(now, ts_secs, src.tolerance_secs)?;
            let kind = serde_json::from_slice::<Value>(body)
                .ok()
                .and_then(|v| v["type"].as_i64())
                .unwrap_or(0);
            if kind == 1 {
                return Ok(Verified::Reply {
                    outcome: "ping",
                    response: json_response(StatusCode::OK, json!({ "type": 1 })),
                });
            }
            Ok(Verified::Event {
                id: body_field(body, "id"),
                event_type: discord_type(kind).into(),
            })
        }
    }
}

fn discord_type(kind: i64) -> &'static str {
    match kind {
        2 => "application_command",
        3 => "message_component",
        4 => "application_command_autocomplete",
        5 => "modal_submit",
        _ => "unknown",
    }
}

/// What Discord gets when your handler returns no reply: "thinking…" for commands and modals,
/// a silent acknowledgement for components, no choices for autocomplete.
fn discord_default_reply(event_type: &str) -> Value {
    match event_type {
        "message_component" => json!({ "type": 6 }),
        "application_command_autocomplete" => json!({ "type": 8, "data": { "choices": [] } }),
        _ => json!({ "type": 5 }),
    }
}

fn json_response(status: StatusCode, value: Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_bytes(value.to_string()))
        .expect("valid response")
}

enum Applied {
    Duplicate,
    Done(Option<String>),
}

/// Dedupe, then run the host's handler, all in one transaction.
fn apply(ctx: &ReducerContext, event: &WebhookEvent) -> Result<Applied, String> {
    let key = format!("{}|{}", event.source, event.id);
    if ctx.db.webhook_seen().key().find(&key).is_some() {
        log(
            ctx,
            "in",
            &event.source,
            &event.event_type,
            &event.id,
            "duplicate",
            200,
            "already applied",
            0,
        );
        return Ok(Applied::Duplicate);
    }
    ctx.db.webhook_seen().insert(WebhookSeen {
        key,
        at: ctx.timestamp,
    });
    let reply = crate::on_webhook(ctx, event)?;
    log(
        ctx,
        "in",
        &event.source,
        &event.event_type,
        &event.id,
        "applied",
        200,
        "",
        0,
    );
    Ok(Applied::Done(reply))
}

/// Every inbound route lands here; the last path segment names the source.
#[handler]
pub fn webhooks_inbox(ctx: &mut HandlerContext, req: Request) -> Response {
    let name = req
        .uri()
        .path()
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string();
    let sources = match parse_sources(&ctx.env.WEBHOOK_SOURCES().unwrap_or_default()) {
        Ok(s) => s,
        Err(e) => return json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": e })),
    };
    let Some(src) = sources.into_iter().find(|s| s.name == name) else {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": format!("no webhook source `{name}` configured") }),
        );
    };
    let headers = req.headers().clone();
    let body = req.into_body().into_bytes();
    let now = ctx.timestamp;
    let verified = verify(&src, &headers, &body, now);
    let (id, event_type) = match verified {
        Err((status, msg)) => {
            ctx.with_tx(|tx| {
                log(
                    tx,
                    "in",
                    &src.name,
                    "",
                    "",
                    "rejected",
                    status.as_u16(),
                    &msg,
                    0,
                )
            });
            return json_response(status, json!({ "error": msg }));
        }
        Ok(Verified::Reply { outcome, response }) => {
            ctx.with_tx(|tx| log(tx, "in", &src.name, "", "", outcome, 200, "", 0));
            return response;
        }
        Ok(Verified::Event { id, event_type }) => (id, event_type),
    };
    let event = WebhookEvent {
        source: src.name.clone(),
        kind: src.kind,
        id: if id.is_empty() {
            hex(&Sha256::digest(&body))
        } else {
            id
        },
        event_type,
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    match ctx.try_with_tx(|tx| apply(tx, &event)) {
        Ok(Applied::Duplicate) => {
            json_response(StatusCode::OK, json!({ "ok": true, "duplicate": true }))
        }
        Ok(Applied::Done(Some(reply))) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from_bytes(reply))
            .expect("valid response"),
        Ok(Applied::Done(None)) if src.kind == Kind::Discord => {
            json_response(StatusCode::OK, discord_default_reply(&event.event_type))
        }
        Ok(Applied::Done(None)) => json_response(StatusCode::OK, json!({ "ok": true })),
        Err(e) => {
            // The dedupe record rolled back with the handler, so the sender's retry is applied fresh.
            ctx.with_tx(|tx| {
                log(
                    tx,
                    "in",
                    &event.source,
                    &event.event_type,
                    &event.id,
                    "error",
                    500,
                    &e,
                    0,
                )
            });
            json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": e }))
        }
    }
}

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

/// Register (or replace) an endpoint. `secret` should be `whsec_` + base64 of 24-64 random bytes,
/// generated outside the module: `ctx.rng()` is seeded from the timestamp, so it's guessable.
pub fn add_endpoint(
    ctx: &ReducerContext,
    name: &str,
    url: &str,
    secret: &str,
    event_types: &[&str],
) -> Result<u64, String> {
    if name.trim().is_empty() || !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("endpoint needs a name and an http(s) URL".into());
    }
    if secret.len() < 16 {
        return Err("endpoint secret is too short".into());
    }
    let row = WebhookEndpoint {
        id: 0,
        name: name.trim().to_string(),
        url: url.to_string(),
        secret: secret.to_string(),
        event_types: event_types.iter().map(|s| s.to_string()).collect(),
        enabled: true,
        disabled_reason: String::new(),
        created: ctx.timestamp,
    };
    if let Some(old) = ctx.db.webhook_endpoint().name().find(&row.name) {
        ctx.db.webhook_endpoint().id().update(WebhookEndpoint {
            id: old.id,
            created: old.created,
            ..row
        });
        return Ok(old.id);
    }
    Ok(ctx.db.webhook_endpoint().insert(row).id)
}

/// Remove an endpoint and drop its queued messages.
pub fn remove_endpoint(ctx: &ReducerContext, name: &str) {
    if let Some(ep) = ctx.db.webhook_endpoint().name().find(name.to_string()) {
        for row in ctx
            .db
            .webhook_outbox()
            .endpoint_id()
            .filter(ep.id)
            .collect::<Vec<_>>()
        {
            ctx.db.webhook_outbox().id().delete(row.id);
        }
        ctx.db.webhook_endpoint().id().delete(ep.id);
    }
}

pub fn set_endpoint_enabled(ctx: &ReducerContext, name: &str, enabled: bool) -> Result<(), String> {
    let ep = ctx
        .db
        .webhook_endpoint()
        .name()
        .find(name.to_string())
        .ok_or("no such endpoint")?;
    ctx.db.webhook_endpoint().id().update(WebhookEndpoint {
        enabled,
        disabled_reason: if enabled {
            String::new()
        } else {
            "disabled by the module".into()
        },
        ..ep
    });
    Ok(())
}

fn wants(ep: &WebhookEndpoint, event_type: &str) -> bool {
    ep.event_types.is_empty()
        || ep.event_types.iter().any(|p| {
            p == "*"
                || p == event_type
                || p.strip_suffix('*')
                    .is_some_and(|pre| event_type.starts_with(pre))
        })
}

/// Queue `data` for every enabled endpoint that wants `event_type`, in the current transaction.
/// Returns the message ids. Delivery starts as soon as the transaction commits.
pub fn send(ctx: &ReducerContext, event_type: &str, data: Value) -> Vec<String> {
    let endpoints: Vec<WebhookEndpoint> = ctx
        .db
        .webhook_endpoint()
        .iter()
        .filter(|e| e.enabled && wants(e, event_type))
        .collect();
    endpoints
        .iter()
        .map(|ep| enqueue(ctx, ep, event_type, &data))
        .collect()
}

/// Queue `data` for one endpoint (ignores its event-type filter).
pub fn send_to(
    ctx: &ReducerContext,
    endpoint: &str,
    event_type: &str,
    data: Value,
) -> Result<String, String> {
    let ep = ctx
        .db
        .webhook_endpoint()
        .name()
        .find(endpoint.to_string())
        .ok_or("no such endpoint")?;
    if !ep.enabled {
        return Err(format!("endpoint `{endpoint}` is disabled"));
    }
    Ok(enqueue(ctx, &ep, event_type, &data))
}

fn enqueue(ctx: &ReducerContext, ep: &WebhookEndpoint, event_type: &str, data: &Value) -> String {
    init(ctx);
    let body = json!({
        "type": event_type,
        "timestamp": ctx.timestamp.to_rfc3339().unwrap_or_default(),
        "data": data,
    })
    .to_string();
    let row = ctx.db.webhook_outbox().insert(WebhookOutbox {
        id: 0,
        endpoint_id: ep.id,
        msg_id: String::new(),
        event_type: event_type.to_string(),
        body,
        created: ctx.timestamp,
        attempts: 0,
        next_attempt: ctx.timestamp,
        in_flight_until: None,
        dead: false,
        last_error: String::new(),
    });
    let epoch = ctx
        .db
        .webhook_state()
        .key()
        .find(0)
        .map(|s| s.epoch)
        .unwrap_or_default();
    let msg_id = format!("msg_{epoch}_{}", row.id);
    ctx.db.webhook_outbox().id().update(WebhookOutbox {
        msg_id: msg_id.clone(),
        ..row
    });
    log(
        ctx, "out", &ep.name, event_type, &msg_id, "queued", 0, "", 0,
    );
    schedule_flush(ctx, ctx.timestamp);
    schedule_backstop(ctx);
    msg_id
}

/// Put an endpoint's dead messages back in the queue. Returns how many.
pub fn redeliver_dead(ctx: &ReducerContext, endpoint: &str) -> Result<usize, String> {
    let ep = ctx
        .db
        .webhook_endpoint()
        .name()
        .find(endpoint.to_string())
        .ok_or("no such endpoint")?;
    let dead: Vec<WebhookOutbox> = ctx
        .db
        .webhook_outbox()
        .endpoint_id()
        .filter(ep.id)
        .filter(|r| r.dead)
        .collect();
    let n = dead.len();
    for row in dead {
        ctx.db.webhook_outbox().id().update(WebhookOutbox {
            dead: false,
            attempts: 0,
            next_attempt: ctx.timestamp,
            in_flight_until: None,
            ..row
        });
    }
    schedule_flush(ctx, ctx.timestamp);
    schedule_backstop(ctx);
    Ok(n)
}

fn schedule_flush(ctx: &ReducerContext, at: Timestamp) {
    let covered = ctx
        .db
        .webhook_flush_job()
        .iter()
        .any(|j| matches!(j.scheduled_at, ScheduleAt::Time(t) if t <= at));
    if !covered {
        ctx.db.webhook_flush_job().insert(WebhookFlushJob {
            scheduled_id: 0,
            scheduled_at: ScheduleAt::Time(at),
        });
    }
}

/// When the outbox next needs a flush, if it has anything queued.
fn next_due(ctx: &ReducerContext) -> Option<Timestamp> {
    ctx.db
        .webhook_outbox()
        .dead()
        .filter(false)
        .map(|r| {
            r.in_flight_until
                .map_or(r.next_attempt, |t| t.max(r.next_attempt))
        })
        .min()
}

/// Keep a later flush on the books while anything is queued. A flush job is deleted before the
/// flush runs, so a crash part-way through would leave leased messages with nothing to pick them
/// up. This runs in the same transaction as the lease, so one can't be lost without the other.
/// It waits for the next due message rather than the lease alone, so a message in a long backoff
/// costs one job, not a flush every minute.
fn schedule_backstop(ctx: &ReducerContext) {
    let Some(next) = next_due(ctx) else { return };
    let soonest = ctx.timestamp + LEASE / 2;
    let at = next.max(ctx.timestamp + LEASE);
    let covered = ctx
        .db
        .webhook_flush_job()
        .iter()
        .any(|j| matches!(j.scheduled_at, ScheduleAt::Time(t) if t >= soonest && t <= at));
    if !covered {
        ctx.db.webhook_flush_job().insert(WebhookFlushJob {
            scheduled_id: 0,
            scheduled_at: ScheduleAt::Time(at),
        });
    }
}

struct Claim {
    row: WebhookOutbox,
    endpoint: WebhookEndpoint,
}

/// Lease the oldest due message, or None.
fn claim_next(ctx: &ReducerContext) -> Option<Claim> {
    schedule_backstop(ctx);
    let now = ctx.timestamp;
    let mut due: Vec<WebhookOutbox> = ctx
        .db
        .webhook_outbox()
        .dead()
        .filter(false)
        .filter(|r| r.next_attempt <= now && !r.in_flight_until.is_some_and(|t| t > now))
        .collect();
    due.sort_by_key(|r| r.id);
    for row in due {
        match ctx.db.webhook_endpoint().id().find(row.endpoint_id) {
            Some(ep) if ep.enabled => {
                let leased = WebhookOutbox {
                    in_flight_until: Some(now + LEASE),
                    ..row.clone()
                };
                ctx.db.webhook_outbox().id().update(leased);
                return Some(Claim { row, endpoint: ep });
            }
            other => {
                let why = other.map_or("endpoint removed".to_string(), |e| {
                    format!("endpoint disabled: {}", e.disabled_reason)
                });
                kill(ctx, row, "?", &why);
            }
        }
    }
    None
}

fn kill(ctx: &ReducerContext, row: WebhookOutbox, endpoint: &str, why: &str) {
    log(
        ctx,
        "out",
        endpoint,
        &row.event_type,
        &row.msg_id,
        "dead",
        0,
        why,
        0,
    );
    ctx.db.webhook_outbox().id().update(WebhookOutbox {
        dead: true,
        in_flight_until: None,
        last_error: why.to_string(),
        ..row
    });
}

/// Standard Webhooks signature: `v1,<base64 HMAC-SHA256(key, "<id>.<timestamp>.<body>")>`.
pub fn sign_standard(secret: &str, msg_id: &str, ts_secs: i64, body: &[u8]) -> String {
    let prefix = format!("{msg_id}.{ts_secs}.");
    let m = mac(&standard_key(secret), &[prefix.as_bytes(), body]);
    format!("v1,{}", B64.encode(m.finalize().into_bytes()))
}

/// Scheduled procedure: deliver everything that's due, then reschedule for the next retry.
#[spacetimedb::procedure]
pub fn webhook_flush(ctx: &mut ProcedureContext, _job: WebhookFlushJob) {
    for _ in 0..500 {
        let Some(claim) = ctx.with_tx(|tx| claim_next(tx)) else {
            break;
        };
        let now = ctx.with_tx(|tx| tx.timestamp);
        let ts_secs = now.to_micros_since_unix_epoch() / 1_000_000;
        let request = Request::builder()
            .method("POST")
            .uri(claim.endpoint.url.as_str())
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, "spacetimedb-webhooks/0.1")
            .header("webhook-id", claim.row.msg_id.as_str())
            .header("webhook-timestamp", ts_secs.to_string())
            .header(
                "webhook-signature",
                sign_standard(
                    &claim.endpoint.secret,
                    &claim.row.msg_id,
                    ts_secs,
                    claim.row.body.as_bytes(),
                ),
            )
            .extension(Timeout::from(TimeDuration::from_duration(HTTP_TIMEOUT)))
            .body(claim.row.body.clone());
        let outcome = match request {
            Err(e) => Err((0, format!("bad request: {e}"))),
            Ok(request) => match ctx.http.send(request) {
                Err(e) => Err((0, format!("transport error: {e}"))),
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if resp.status().is_success() {
                        Ok(status)
                    } else {
                        let text: String = resp
                            .into_body()
                            .into_string_lossy()
                            .chars()
                            .take(200)
                            .collect();
                        Err((status, format!("{status} {text}")))
                    }
                }
            },
        };
        let sent_at = now;
        ctx.with_tx(|tx| finish(tx, &claim, &outcome, sent_at));
    }
    ctx.with_tx(|tx| {
        if let Some(at) = next_due(tx) {
            schedule_flush(tx, at.max(tx.timestamp));
        }
    });
}

fn finish(
    ctx: &ReducerContext,
    claim: &Claim,
    outcome: &Result<u16, (u16, String)>,
    sent_at: Timestamp,
) {
    let Some(row) = ctx.db.webhook_outbox().id().find(claim.row.id) else {
        return;
    };
    let name = claim.endpoint.name.as_str();
    let attempt = row.attempts + 1;
    let latency = ctx.timestamp.to_micros_since_unix_epoch() - sent_at.to_micros_since_unix_epoch();
    match outcome {
        Ok(status) => {
            log(
                ctx,
                "out",
                name,
                &row.event_type,
                &row.msg_id,
                "delivered",
                *status,
                &format!("attempt {attempt}"),
                latency,
            );
            ctx.db.webhook_outbox().id().delete(row.id);
        }
        Err((410, err)) => {
            // 410 Gone: the receiver asked us to stop. Disable the endpoint and drop its queue.
            if let Some(ep) = ctx.db.webhook_endpoint().id().find(row.endpoint_id) {
                ctx.db.webhook_endpoint().id().update(WebhookEndpoint {
                    enabled: false,
                    disabled_reason: "receiver answered 410 Gone".into(),
                    ..ep
                });
            }
            log(
                ctx,
                "out",
                name,
                &row.event_type,
                &row.msg_id,
                "disabled",
                410,
                err,
                latency,
            );
            for other in ctx
                .db
                .webhook_outbox()
                .endpoint_id()
                .filter(row.endpoint_id)
                .filter(|r| !r.dead)
                .collect::<Vec<_>>()
            {
                kill(
                    ctx,
                    other,
                    name,
                    "endpoint disabled: receiver answered 410 Gone",
                );
            }
        }
        Err((status, err)) => {
            let schedule = retry_schedule(ctx.env.WEBHOOK_RETRY_SECS());
            if attempt as usize > schedule.len() {
                log(
                    ctx,
                    "out",
                    name,
                    &row.event_type,
                    &row.msg_id,
                    "dead",
                    *status,
                    &format!("gave up after {attempt} attempts: {err}"),
                    latency,
                );
                ctx.db.webhook_outbox().id().update(WebhookOutbox {
                    attempts: attempt,
                    dead: true,
                    in_flight_until: None,
                    last_error: err.clone(),
                    ..row
                });
            } else {
                let delay = schedule[attempt as usize - 1];
                log(
                    ctx,
                    "out",
                    name,
                    &row.event_type,
                    &row.msg_id,
                    "retry",
                    *status,
                    &format!("attempt {attempt} failed, retrying in {delay}s: {err}"),
                    latency,
                );
                ctx.db.webhook_outbox().id().update(WebhookOutbox {
                    attempts: attempt,
                    next_attempt: ctx.timestamp + Duration::from_secs_f64(delay),
                    in_flight_until: None,
                    last_error: err.clone(),
                    ..row
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Housekeeping and dashboards
// ---------------------------------------------------------------------------

#[spacetimedb::reducer]
pub fn webhook_prune(ctx: &ReducerContext, _job: WebhookPruneJob) {
    let cutoff = ctx.timestamp - SEEN_RETENTION;
    let old: Vec<String> = ctx
        .db
        .webhook_seen()
        .at()
        .filter(..cutoff)
        .map(|s| s.key)
        .collect();
    for key in old {
        ctx.db.webhook_seen().key().delete(key);
    }
}

#[allow(clippy::too_many_arguments)]
fn log(
    ctx: &ReducerContext,
    direction: &str,
    peer: &str,
    event_type: &str,
    msg_id: &str,
    outcome: &str,
    status: u16,
    detail: &str,
    latency_us: i64,
) {
    ctx.db.webhook_log().insert(WebhookLog {
        id: 0,
        at: ctx.timestamp,
        direction: direction.into(),
        peer: peer.into(),
        event_type: event_type.into(),
        msg_id: msg_id.into(),
        outcome: outcome.into(),
        status,
        detail: detail.chars().take(300).collect(),
        latency_us,
    });
    // Ids can skip (rolled-back inserts use them up), so prune by count, 100 rows at a time.
    if ctx.db.webhook_log().count() > LOG_KEEP + 100 {
        let mut ids: Vec<u64> = ctx.db.webhook_log().iter().map(|l| l.id).collect();
        ids.sort_unstable();
        for id in &ids[..ids.len() - LOG_KEEP as usize] {
            ctx.db.webhook_log().id().delete(id);
        }
    }
}

/// Endpoints (without secrets), queue counts and the recent log, as JSON for a dashboard.
/// Don't expose it publicly in production: event types and endpoint URLs can be sensitive.
pub fn state_json(ctx: &ReducerContext) -> Value {
    let endpoints: Vec<Value> = ctx
        .db
        .webhook_endpoint()
        .iter()
        .map(|e| {
            let rows: Vec<WebhookOutbox> =
                ctx.db.webhook_outbox().endpoint_id().filter(e.id).collect();
            json!({
                "name": e.name,
                "url": e.url,
                "event_types": e.event_types,
                "enabled": e.enabled,
                "disabled_reason": e.disabled_reason,
                "pending": rows.iter().filter(|r| !r.dead).count(),
                "dead": rows.iter().filter(|r| r.dead).count(),
            })
        })
        .collect();
    let mut log: Vec<WebhookLog> = ctx.db.webhook_log().iter().collect();
    log.sort_by_key(|l| std::cmp::Reverse(l.id));
    let log: Vec<Value> = log
        .into_iter()
        .take(150)
        .map(|l| {
            json!({
                "id": l.id,
                "at": l.at.to_micros_since_unix_epoch(),
                "direction": l.direction,
                "peer": l.peer,
                "event_type": l.event_type,
                "msg_id": l.msg_id,
                "outcome": l.outcome,
                "status": l.status,
                "detail": l.detail,
                "latency_us": l.latency_us,
            })
        })
        .collect();
    json!({ "endpoints": endpoints, "log": log })
}
