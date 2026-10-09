/**
 * Demo, in TypeScript, using `spacetimedb-webhooks` as a submodule. Same behaviour as demo/rust
 * and demo/csharp: receives webhooks from six kinds of sender, sends its own, and serves a live
 * dashboard at /route/.
 */
import { schema, table, t, Router, SyncResponse, type ReducerCtx } from 'spacetimedb/server';
import * as webhooks from 'spacetimedb-webhooks';
import PAGE from './page.gen';

/** The inbound routes. `spare` has no configuration, to show what that returns. */
const SOURCES = ['github', 'twitch', 'stripe', 'app', 'discord', 'custom', 'spare'];

/** Every webhook this module has accepted. */
const demoEvent = table(
  { name: 'demo_event', public: true },
  {
    id: t.u64().primaryKey().autoInc(),
    at: t.timestamp(),
    source: t.string(),
    kind: t.string(),
    eventType: t.string(),
    msgId: t.string(),
    summary: t.string(),
  }
);

const spacetimedb = schema(
  { demoEvent, webhooks },
  { env: { WEBHOOK_SOURCES: t.string().optional(), WEBHOOK_RETRY_SECS: t.string().optional() } }
);
export default spacetimedb;
type Ctx = ReducerCtx<typeof spacetimedb.schemaType>;

// ---------------------------------------------------------------------------
// webhooks wiring: config in, routes registered, events handled
// ---------------------------------------------------------------------------

const config = (ctx: { env: { WEBHOOK_RETRY_SECS?: string } }) => ({ retrySecs: ctx.env.WEBHOOK_RETRY_SECS });
export const init = spacetimedb.init((ctx) => webhooks.configure(ctx.as.webhooks, config(ctx)));
/** Re-read config after `spacetime publish --env-only`. */
export const webhooksKick = spacetimedb.reducer((ctx) => webhooks.configure(ctx.as.webhooks, config(ctx)));

export const webhooksInbox = spacetimedb.httpHandler((ctx, req) =>
  webhooks.inbox(ctx, req, { sources: ctx.env.WEBHOOK_SOURCES, scope: (tx: Ctx) => tx.as.webhooks, onEvent })
);

/** Called for each verified, first-time delivery, in the same transaction as the dedupe record. */
function onEvent(tx: Ctx, event: webhooks.WebhookEvent): string | undefined {
  let body: any = null;
  try {
    body = JSON.parse(event.body);
  } catch {}
  if (body?.fail === true) throw new Error('demo handler failed on purpose');
  tx.db.demoEvent.insert({
    id: 0n,
    at: tx.timestamp,
    source: event.source,
    kind: event.kind,
    eventType: event.eventType,
    msgId: event.id,
    summary: event.body.slice(0, 160),
  });
  if (event.eventType === 'application_command') {
    const name = typeof body?.data?.name === 'string' ? body.data.name : 'command';
    return JSON.stringify({ type: 4, data: { content: `Pong from SpacetimeDB (/${name})` } });
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Dashboard and demo controls
// ---------------------------------------------------------------------------

const json = (status: number, value: unknown) =>
  new SyncResponse(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const bodyJson = (req: { text(): string }) => {
  try {
    return JSON.parse(req.text());
  } catch {
    return {};
  }
};

export const page = spacetimedb.httpHandler(
  () => new SyncResponse(PAGE, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' } })
);

/** Dashboard data. Demo only: a real module shouldn't expose its webhook log publicly. */
export const state = spacetimedb.httpHandler((ctx) => {
  const sources = webhooks.parseSources(ctx.env.WEBHOOK_SOURCES).map((s) => ({ name: s.name, kind: s.kind }));
  const value = ctx.withTx((tx) => {
    const events = [...tx.db.demoEvent.iter()]
      .sort((a, b) => (a.id > b.id ? -1 : 1))
      .slice(0, 60)
      .map((e) => ({
        id: Number(e.id),
        at: Number(e.at.microsSinceUnixEpoch),
        source: e.source,
        kind: e.kind,
        event_type: e.eventType,
        msg_id: e.msgId,
        summary: e.summary,
      }));
    return { ...webhooks.stateJson(tx.as.webhooks), events };
  });
  return json(200, { ...value, sources, routes: SOURCES });
});

/** `{"event_type", "data", "fail"}`: queue an outbound event; `fail: true` rolls it back. */
export const demoSend = spacetimedb.httpHandler((ctx, req) => {
  const b = bodyJson(req);
  try {
    const queued = ctx.withTx((tx) => {
      const ids = webhooks.send(tx.as.webhooks, typeof b.event_type === 'string' ? b.event_type : 'demo.ping', b.data ?? null);
      if (b.fail === true) throw new Error('rolled back on purpose');
      return ids;
    });
    return json(200, { queued });
  } catch (e) {
    return json(500, { error: (e as Error).message });
  }
});

/** `{"name", "url", "secret", "event_types", "remove"}`. Demo only: anyone can add endpoints. */
export const demoEndpoint = spacetimedb.httpHandler((ctx, req) => {
  const b = bodyJson(req);
  try {
    const id = ctx.withTx((tx) => {
      if (b.remove === true) {
        webhooks.removeEndpoint(tx.as.webhooks, String(b.name ?? ''));
        return 0;
      }
      const types = Array.isArray(b.event_types) ? b.event_types.filter((x: unknown) => typeof x === 'string') : [];
      return Number(webhooks.addEndpoint(tx.as.webhooks, String(b.name ?? ''), String(b.url ?? ''), String(b.secret ?? ''), types));
    });
    return json(200, { id });
  } catch (e) {
    return json(400, { error: (e as Error).message });
  }
});

export const router = spacetimedb.httpRouter(
  webhooks
    .routes(new Router(), webhooksInbox, SOURCES)
    .get('/', page)
    .get('/api/state', state)
    .post('/demo/send', demoSend)
    .post('/demo/endpoint', demoEndpoint)
);
