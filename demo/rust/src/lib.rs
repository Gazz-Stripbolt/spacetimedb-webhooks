//! Demo: a module that receives webhooks from six kinds of sender and sends its own,
//! with a live dashboard at `/route/`.

#[path = "../../../rust/webhooks.rs"]
pub mod webhooks;

use http::{StatusCode, header};
use serde_json::{Value, json};
use spacetimedb::http::{Body, HandlerContext, Request, Response, Router, handler, router};
use spacetimedb::{ReducerContext, Table, Timestamp};
use webhooks::{EnvAccess, WebhookEvent};

const PAGE: &str = include_str!("../../dashboard/index.html");
/// The inbound routes. `spare` has no configuration, to show what an unconfigured source returns.
const SOURCES: &[&str] = &[
    "github", "twitch", "stripe", "app", "discord", "custom", "spare",
];

/// Every webhook this module has accepted.
#[spacetimedb::table(accessor = demo_event, public)]
pub struct DemoEvent {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    pub at: Timestamp,
    pub source: String,
    pub kind: String,
    pub event_type: String,
    pub msg_id: String,
    pub summary: String,
}

#[spacetimedb::reducer(init)]
pub fn init(ctx: &ReducerContext) {
    webhooks::init(ctx);
}

/// Called by webhooks.rs for each verified, first-time delivery, in the same transaction as
/// the dedupe record.
pub fn on_webhook(ctx: &ReducerContext, event: &WebhookEvent) -> Result<Option<String>, String> {
    let body: Value = serde_json::from_str(&event.body).unwrap_or(Value::Null);
    if body["fail"] == true {
        return Err("demo handler failed on purpose".into());
    }
    ctx.db.demo_event().insert(DemoEvent {
        id: 0,
        at: ctx.timestamp,
        source: event.source.clone(),
        kind: event.kind.as_str().into(),
        event_type: event.event_type.clone(),
        msg_id: event.id.clone(),
        summary: event.body.chars().take(160).collect(),
    });
    if event.event_type == "application_command" {
        let name = body["data"]["name"].as_str().unwrap_or("command");
        let reply =
            json!({ "type": 4, "data": { "content": format!("Pong from SpacetimeDB (/{name})") } });
        return Ok(Some(reply.to_string()));
    }
    Ok(None)
}

fn json_response(status: StatusCode, value: Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_bytes(value.to_string()))
        .unwrap()
}

fn body_json(req: Request) -> Value {
    serde_json::from_slice(&req.into_body().into_bytes()).unwrap_or(Value::Null)
}

#[handler]
fn page(_ctx: &mut HandlerContext, _req: Request) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_bytes(PAGE))
        .unwrap()
}

/// Dashboard data. Demo only: a real module shouldn't expose its webhook log publicly.
#[handler]
fn state(ctx: &mut HandlerContext, _req: Request) -> Response {
    let sources: Vec<Value> =
        webhooks::parse_sources(&ctx.env.WEBHOOK_SOURCES().unwrap_or_default())
            .unwrap_or_default()
            .into_iter()
            .map(|s| json!({ "name": s.name, "kind": s.kind.as_str() }))
            .collect();
    let value = ctx.with_tx(|tx| {
        let mut events: Vec<DemoEvent> = tx.db.demo_event().iter().collect();
        events.sort_by_key(|e| std::cmp::Reverse(e.id));
        let events: Vec<Value> = events
            .into_iter()
            .take(60)
            .map(|e| {
                json!({ "id": e.id, "at": e.at.to_micros_since_unix_epoch(), "source": e.source, "kind": e.kind,
                        "event_type": e.event_type, "msg_id": e.msg_id, "summary": e.summary })
            })
            .collect();
        let mut v = webhooks::state_json(tx);
        v["events"] = json!(events);
        v
    });
    let mut value = value;
    value["sources"] = json!(sources);
    value["routes"] = json!(SOURCES);
    json_response(StatusCode::OK, value)
}

/// `{"event_type": "...", "data": {...}, "fail": false}`: queue an outbound event. With
/// `fail: true` the transaction rolls back after queueing, so nothing is sent.
#[handler]
fn demo_send(ctx: &mut HandlerContext, req: Request) -> Response {
    let b = body_json(req);
    let event_type = b["event_type"].as_str().unwrap_or("demo.ping").to_string();
    let data = b["data"].clone();
    let fail = b["fail"] == true;
    match ctx.try_with_tx(|tx| {
        let ids = webhooks::send(tx, &event_type, data.clone());
        if fail {
            Err("rolled back on purpose".to_string())
        } else {
            Ok(ids)
        }
    }) {
        Ok(ids) => json_response(StatusCode::OK, json!({ "queued": ids })),
        Err(e) => json_response(StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": e })),
    }
}

/// `{"name": "...", "url": "...", "secret": "whsec_...", "event_types": ["order.*"]}`.
/// Demo only: anyone who can reach this route can add endpoints.
#[handler]
fn demo_endpoint(ctx: &mut HandlerContext, req: Request) -> Response {
    let b = body_json(req);
    let s = |k: &str| b[k].as_str().unwrap_or_default().to_string();
    let types: Vec<String> = b["event_types"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let (name, url, secret) = (s("name"), s("url"), s("secret"));
    let result = ctx.try_with_tx(|tx| {
        if b["remove"] == true {
            webhooks::remove_endpoint(tx, &name);
            return Ok(0);
        }
        let refs: Vec<&str> = types.iter().map(String::as_str).collect();
        webhooks::add_endpoint(tx, &name, &url, &secret, &refs)
    });
    match result {
        Ok(id) => json_response(StatusCode::OK, json!({ "id": id })),
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({ "error": e })),
    }
}

#[router]
fn routes() -> Router {
    webhooks::router(SOURCES)
        .get("/", page)
        .get("/api/state", state)
        .post("/demo/send", demo_send)
        .post("/demo/endpoint", demo_endpoint)
}
