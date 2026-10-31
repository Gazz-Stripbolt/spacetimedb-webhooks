/**
 * # spacetimedb-webhooks: verified inbound and signed outbound webhooks, as a submodule
 *
 * The TypeScript twin of `rust/webhooks.rs` and `csharp/Webhooks.cs`: same sources, headers,
 * signatures and behaviour.
 *
 * - **Inbound:** `inbox()` verifies GitHub, Twitch EventSub, Stripe, Standard Webhooks, Discord
 *   interactions or a generic HMAC, checks the replay window, dedupes by delivery id, and runs
 *   your handler in the same transaction as the dedupe record.
 * - **Outbound:** `addEndpoint()` + `send()` write to a transactional outbox; a one-shot
 *   scheduled procedure POSTs each event signed per the Standard Webhooks spec, with retries,
 *   backoff and dead letters.
 *
 * Submodules can't read env vars or own routes, so the consumer passes `WEBHOOK_SOURCES` to
 * `inbox()`, calls `configure()` from init, and registers the routes. See README.md.
 */
import { schema, table, t, Router, SyncResponse } from 'spacetimedb/server';
import type { ReducerCtx, Request } from 'spacetimedb/server';
import { ScheduleAt, TimeDuration, Timestamp } from 'spacetimedb';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { ed25519 } from '@noble/curves/ed25519';

// ---------------------------------------------------------------------------
// Tables (they live under the consumer's namespace, e.g. `webhooks.outbox`)
// ---------------------------------------------------------------------------

const config = table({ name: 'config' }, { key: t.u8().primaryKey(), retrySecs: t.string() });

/** Delivery ids already applied, per source. Pruned after 7 days. */
const seen = table({ name: 'seen' }, { key: t.string().primaryKey(), at: t.timestamp().index('btree') });

/** Outbound endpoints. Private: secrets never reach subscribers. */
const endpoint = table(
  { name: 'endpoint' },
  {
    id: t.u64().primaryKey().autoInc(),
    name: t.string().unique(),
    url: t.string(),
    /** `whsec_<base64>` (Standard Webhooks). Raw strings work too. */
    secret: t.string(),
    /** Exact (`order.paid`), prefix (`order.*`) or `*`. Empty = all. */
    eventTypes: t.array(t.string()),
    enabled: t.bool(),
    disabledReason: t.string(),
    created: t.timestamp(),
  }
);

/** Events waiting to be delivered, one row per endpoint. */
const outbox = table(
  { name: 'outbox' },
  {
    id: t.u64().primaryKey().autoInc(),
    endpointId: t.u64().index('btree'),
    /** The `webhook-id`: the same on every retry. */
    msgId: t.string(),
    eventType: t.string(),
    /** The exact JSON body, fixed at send time. */
    body: t.string(),
    created: t.timestamp(),
    attempts: t.u32(),
    nextAttempt: t.timestamp(),
    inFlightUntil: t.option(t.timestamp()),
    /** Dead letters stay until redelivered or removed; indexed so the queue scan skips them. */
    dead: t.bool().index('btree'),
    lastError: t.string(),
  }
);

/** Activity feed, both directions. Metadata only. */
const log = table(
  { name: 'log' },
  {
    id: t.u64().primaryKey().autoInc(),
    at: t.timestamp(),
    direction: t.string(),
    peer: t.string(),
    eventType: t.string(),
    msgId: t.string(),
    outcome: t.string(),
    status: t.u16(),
    detail: t.string(),
    latencyUs: t.i64(),
  }
);

const state = table({ name: 'state' }, { key: t.u8().primaryKey(), epoch: t.string() });
const flushJob = table({ name: 'flush_job' }, { scheduledId: t.u64().primaryKey().autoInc(), scheduledAt: t.scheduleAt() });
const pruneJob = table({ name: 'prune_job' }, { scheduledId: t.u64().primaryKey().autoInc(), scheduledAt: t.scheduleAt() });

const spacetimedb = schema({ config, seen, endpoint, outbox, log, state, flushJob, pruneJob });
export default spacetimedb;

type S = typeof spacetimedb.schemaType;
/** A context narrowed to this submodule: pass `ctx.as.webhooks` (or whatever you named it). */
export type WebhooksCtx = ReducerCtx<S>;
type EndpointRow = NonNullable<ReturnType<WebhooksCtx['db']['endpoint']['id']['find']>>;
type OutboxRow = NonNullable<ReturnType<WebhooksCtx['db']['outbox']['id']['find']>>;

const DEFAULT_RETRY_SECS = [5, 30, 120, 600, 1800, 3600, 7200, 14400];
const HTTP_TIMEOUT = TimeDuration.fromMillis(15_000);
const LEASE_US = 60n * 1_000_000n;
const LOG_KEEP = 500n;
const SEEN_RETENTION_US = 7n * 24n * 3600n * 1_000_000n;

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

export interface Config {
  /** Outbound retry delays in seconds, comma-separated (the WEBHOOK_RETRY_SECS env var). */
  retrySecs?: string;
}

/**
 * Store the config and do the one-time setup. Call it from your `init` and from a kick
 * reducer (run that after `spacetime publish --env-only`, or once after adding webhooks to a
 * database that's already live). Idempotent.
 */
export function configure(ctx: WebhooksCtx, cfg: Config = {}): void {
  const row = { key: 0, retrySecs: cfg.retrySecs ?? '' };
  if (ctx.db.config.key.find(0)) ctx.db.config.key.update(row);
  else ctx.db.config.insert(row);
  init(ctx);
  scheduleFlush(ctx, ctx.timestamp.microsSinceUnixEpoch);
}

function init(ctx: WebhooksCtx): void {
  if (!ctx.db.state.key.find(0)) ctx.db.state.insert({ key: 0, epoch: ctx.timestamp.microsSinceUnixEpoch.toString(16) });
  if (ctx.db.pruneJob.count() === 0n) {
    ctx.db.pruneJob.insert({ scheduledId: 0n, scheduledAt: ScheduleAt.interval(3600n * 1_000_000n) });
  }
}

function retrySchedule(ctx: WebhooksCtx): number[] {
  const raw = ctx.db.config.key.find(0)?.retrySecs ?? '';
  const list = raw
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
    .map(Number)
    .filter((x) => Number.isFinite(x) && x >= 0);
  return list.length ? list : DEFAULT_RETRY_SECS;
}

/** `POST /webhooks/<name>` for each source, all handled by `handler` (your httpHandler wrapping `inbox`). */
export function routes(router: Router, handler: Parameters<Router['post']>[1], sources: string[]): Router {
  return sources.reduce((r, name) => r.post(`/webhooks/${name}`, handler), router);
}

// ---------------------------------------------------------------------------
// Small helpers (no Buffer/atob in the module runtime)
// ---------------------------------------------------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
function unhex(s: string): Uint8Array | undefined {
  s = s.trim();
  if (s.length % 2 || !/^[0-9a-fA-F]*$/.test(s)) return undefined;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64encode(b: Uint8Array): string {
  let out = '';
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + (i + 1 < b.length ? B64[(n >> 6) & 63] : '=') + (i + 2 < b.length ? B64[n & 63] : '=');
  }
  return out;
}
function b64decode(s: string): Uint8Array | undefined {
  s = s.trim().replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]*$/.test(s) || s.length % 4 === 1) return undefined;
  const out: number[] = [];
  let bits = 0;
  let acc = 0;
  for (const c of s) {
    acc = (acc << 6) | B64.indexOf(c);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 255);
    }
  }
  return new Uint8Array(out);
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
const anyMatch = (keys: Uint8Array[], msg: Uint8Array, candidates: Uint8Array[]) =>
  keys.some((k) => {
    const m = hmac(sha256, k, msg);
    return candidates.some((c) => equal(m, c));
  });
const standardKey = (secret: string) => b64decode(secret.replace(/^whsec_/, '')) ?? enc.encode(secret);

/** RFC 3339 (Twitch sends nanoseconds) to unix seconds. */
function parseRfc3339(s: string): number | undefined {
  const m = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|z|[+-]\d{2}:\d{2})$/.exec(s.trim());
  if (!m) return undefined;
  let secs = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000;
  if (m[7].length === 6) {
    const off = (+m[7].slice(1, 3) * 60 + +m[7].slice(4, 6)) * 60;
    secs += m[7][0] === '+' ? -off : off;
  }
  return secs;
}
const rfc3339 = (t: Timestamp) => new Date(Number(t.microsSinceUnixEpoch / 1000n)).toISOString();

// ---------------------------------------------------------------------------
// Inbound
// ---------------------------------------------------------------------------

export type Kind = 'standard' | 'github' | 'twitch' | 'stripe' | 'discord' | 'hmac';

export interface Source {
  name: string;
  kind: Kind;
  secrets: string[];
  publicKey: string;
  header: string;
  prefix: string;
  encoding: string;
  idHeader: string;
  typeHeader: string;
  toleranceSecs: number;
}

/** Parse `WEBHOOK_SOURCES` (a JSON object keyed by source name). */
export function parseSources(raw: string | undefined | null): Source[] {
  if (!raw || !raw.trim()) return [];
  const obj = JSON.parse(raw);
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('WEBHOOK_SOURCES must be a JSON object');
  return Object.entries(obj).map(([name, cfg]: [string, any]) => {
    const s = (k: string) => (typeof cfg?.[k] === 'string' ? (cfg[k] as string) : '');
    const kind = s('kind') as Kind;
    if (!['standard', 'github', 'twitch', 'stripe', 'discord', 'hmac'].includes(kind)) {
      throw new Error(`source \`${name}\`: unknown kind \`${kind}\``);
    }
    const secrets = [s('secret'), ...(Array.isArray(cfg.secrets) ? cfg.secrets.filter((x: unknown) => typeof x === 'string') : [])].filter(Boolean);
    if (kind === 'discord' && !s('public_key')) throw new Error(`source \`${name}\`: discord needs public_key`);
    if (kind !== 'discord' && !secrets.length) throw new Error(`source \`${name}\`: needs secret`);
    return {
      name,
      kind,
      secrets,
      publicKey: s('public_key'),
      header: (s('header') || 'x-signature').toLowerCase(),
      prefix: s('prefix'),
      encoding: s('encoding') || 'hex',
      idHeader: s('id_header').toLowerCase(),
      typeHeader: s('type_header').toLowerCase(),
      toleranceSecs: typeof cfg.tolerance_secs === 'number' ? cfg.tolerance_secs : kind === 'twitch' ? 600 : 300,
    };
  });
}

/** A verified, not-yet-seen inbound webhook. */
export interface WebhookEvent {
  /** The source name (the route segment). */
  source: string;
  kind: Kind;
  /** The sender's delivery id (what dedupe uses). */
  id: string;
  /** GitHub: X-GitHub-Event. Twitch: subscription type or `revocation`. Stripe/Standard: body `type`. Discord: `application_command`, ... */
  eventType: string;
  /** The raw body (UTF-8). */
  body: string;
}

class Reject extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}
const unauthorized = (m: string) => new Reject(401, m);

type Verified = { id: string; eventType: string } | { outcome: string; response: SyncResponse };

const json = (status: number, value: unknown) =>
  new SyncResponse(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });

function bodyField(body: Uint8Array, key: string): string {
  try {
    const v = JSON.parse(dec.decode(body))?.[key];
    return typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '';
  } catch {
    return '';
  }
}

function verify(src: Source, req: Request, body: Uint8Array, nowSecs: number): Verified {
  const h = (n: string) => req.headers.get(n);
  const need = (n: string) => {
    const v = h(n);
    if (v === null) throw unauthorized(`missing ${n} header`);
    return v;
  };
  const window = (ts: number) => {
    if (!Number.isFinite(ts) || Math.abs(nowSecs - ts) > src.toleranceSecs) throw unauthorized('timestamp outside the allowed window');
  };
  const secrets = src.secrets.map((s) => enc.encode(s));
  switch (src.kind) {
    case 'standard': {
      const id = need('webhook-id');
      const ts = need('webhook-timestamp').trim();
      if (!/^\d+$/.test(ts)) throw unauthorized('bad webhook-timestamp');
      window(Number(ts));
      // Headers.get joins repeated headers with ", ": split on whitespace and keep v1 entries.
      const sigs = need('webhook-signature')
        .split(/[\s]+/)
        .map((e) => e.replace(/,$/, ''))
        .filter((e) => e.startsWith('v1,'))
        .map((e) => b64decode(e.slice(3)))
        .filter((b): b is Uint8Array => !!b);
      const msg = concat(enc.encode(`${id}.${ts}.`), body);
      if (!anyMatch(src.secrets.map(standardKey), msg, sigs)) throw unauthorized('bad signature');
      return { id, eventType: bodyField(body, 'type') };
    }
    case 'github': {
      const sig = need('x-hub-signature-256');
      const raw = sig.startsWith('sha256=') ? unhex(sig.slice(7)) : undefined;
      if (!raw) throw unauthorized('malformed x-hub-signature-256');
      if (!anyMatch(secrets, body, [raw])) throw unauthorized('bad signature');
      // GitHub signs no timestamp: dedupe by delivery id is the only replay protection.
      return { id: h('x-github-delivery') ?? hex(sha256(body)), eventType: h('x-github-event') ?? '' };
    }
    case 'twitch': {
      const id = need('twitch-eventsub-message-id');
      const ts = need('twitch-eventsub-message-timestamp');
      const sig = need('twitch-eventsub-message-signature');
      const raw = sig.startsWith('sha256=') ? unhex(sig.slice(7)) : undefined;
      if (!raw) throw unauthorized('malformed twitch-eventsub-message-signature');
      if (!anyMatch(secrets, concat(enc.encode(id), enc.encode(ts), body), [raw])) throw unauthorized('bad signature');
      const at = parseRfc3339(ts);
      if (at === undefined) throw unauthorized('bad message timestamp');
      window(at);
      const type = h('twitch-eventsub-message-type');
      if (type === 'webhook_callback_verification') {
        return {
          outcome: 'challenge',
          response: new SyncResponse(bodyField(body, 'challenge'), { status: 200, headers: { 'content-type': 'text/plain' } }),
        };
      }
      if (type === 'revocation') return { id, eventType: 'revocation' };
      return { id, eventType: h('twitch-eventsub-subscription-type') ?? '' };
    }
    case 'stripe': {
      let ts: number | undefined;
      const v1: Uint8Array[] = [];
      for (const part of need('stripe-signature').split(',')) {
        const i = part.indexOf('=');
        const k = part.slice(0, i).trim();
        const v = part.slice(i + 1).trim();
        if (k === 't' && /^\d+$/.test(v)) ts = Number(v);
        if (k === 'v1') {
          const b = unhex(v);
          if (b) v1.push(b);
        }
      }
      if (ts === undefined) throw unauthorized('malformed stripe-signature');
      window(ts);
      if (!anyMatch(secrets, concat(enc.encode(`${ts}.`), body), v1)) throw unauthorized('bad signature');
      return { id: bodyField(body, 'id'), eventType: bodyField(body, 'type') };
    }
    case 'hmac': {
      let sig = need(src.header).trim();
      if (src.prefix && sig.startsWith(src.prefix)) sig = sig.slice(src.prefix.length);
      const raw = src.encoding === 'base64' ? b64decode(sig) : unhex(sig);
      if (!raw) throw unauthorized('malformed signature');
      if (!anyMatch(secrets, body, [raw])) throw unauthorized('bad signature');
      return {
        id: (src.idHeader && h(src.idHeader)) || hex(sha256(body)),
        eventType: (src.typeHeader && h(src.typeHeader)) || '',
      };
    }
    case 'discord': {
      const sig = unhex(need('x-signature-ed25519'));
      const ts = need('x-signature-timestamp');
      const key = unhex(src.publicKey);
      if (key?.length !== 32) throw new Reject(500, 'bad discord public_key');
      if (sig?.length !== 64) throw unauthorized('malformed x-signature-ed25519');
      let ok = false;
      try {
        ok = ed25519.verify(sig, concat(enc.encode(ts), body), key);
      } catch {}
      if (!ok) throw unauthorized('bad signature');
      if (!/^\d+$/.test(ts.trim())) throw unauthorized('bad x-signature-timestamp');
      window(Number(ts.trim()));
      let type = 0;
      try {
        type = Number(JSON.parse(dec.decode(body))?.type) || 0;
      } catch {}
      if (type === 1) return { outcome: 'ping', response: json(200, { type: 1 }) };
      const names: Record<number, string> = {
        2: 'application_command',
        3: 'message_component',
        4: 'application_command_autocomplete',
        5: 'modal_submit',
      };
      return { id: bodyField(body, 'id'), eventType: names[type] ?? 'unknown' };
    }
  }
}

/** What Discord gets when your handler returns no reply. */
function discordDefault(eventType: string) {
  if (eventType === 'message_component') return { type: 6 };
  if (eventType === 'application_command_autocomplete') return { type: 8, data: { choices: [] } };
  return { type: 5 };
}

interface TxRunner<Tx> {
  withTx<T>(body: (tx: Tx) => T): T;
  timestamp: Timestamp;
}

export interface InboxOptions<Tx> {
  /** The WEBHOOK_SOURCES JSON (read it from your env: submodules can't). */
  sources: string | undefined | null;
  /** Narrow the consumer's transaction context to this submodule, e.g. `tx => tx.as.webhooks`. */
  scope: (tx: Tx) => WebhooksCtx;
  /**
   * Handle a verified, first-time delivery, in the dedupe transaction. Return a JSON string to
   * send back (Discord replies), or nothing. Throw to reject: the dedupe record rolls back with
   * your changes and the sender's retry gets a clean try.
   */
  onEvent: (tx: Tx, event: WebhookEvent) => string | void | undefined;
}

/**
 * The inbound handler. Register it for every source:
 * `export const webhooksInbox = spacetimedb.httpHandler((ctx, req) => webhooks.inbox(ctx, req, { sources: ctx.env.WEBHOOK_SOURCES, scope: tx => tx.as.webhooks, onEvent }))`
 */
export function inbox<Tx>(ctx: TxRunner<Tx>, req: Request, opts: InboxOptions<Tx>): SyncResponse {
  const path = req.uri.split('?')[0];
  const name = path.slice(path.lastIndexOf('/') + 1);
  let src: Source | undefined;
  try {
    src = parseSources(opts.sources).find((s) => s.name === name);
  } catch (e) {
    return json(500, { error: (e as Error).message });
  }
  if (!src) return json(404, { error: `no webhook source \`${name}\` configured` });
  const body = req.bytes();
  const writeLog = (e: LogEntry) => ctx.withTx((tx) => logRow(opts.scope(tx), e));
  let verified: Verified;
  try {
    verified = verify(src, req, body, Number(ctx.timestamp.microsSinceUnixEpoch / 1_000_000n));
  } catch (e) {
    const status = e instanceof Reject ? e.status : 401;
    writeLog({ direction: 'in', peer: src.name, outcome: 'rejected', status, detail: (e as Error).message });
    return json(status, { error: (e as Error).message });
  }
  if ('response' in verified) {
    writeLog({ direction: 'in', peer: src.name, outcome: verified.outcome, status: 200 });
    return verified.response;
  }
  const event: WebhookEvent = {
    source: src.name,
    kind: src.kind,
    id: verified.id || hex(sha256(body)),
    eventType: verified.eventType,
    body: dec.decode(body),
  };
  try {
    const result = ctx.withTx((tx) => {
      const w = opts.scope(tx);
      const key = `${event.source}|${event.id}`;
      const base = { direction: 'in', peer: event.source, eventType: event.eventType, msgId: event.id, status: 200 };
      if (w.db.seen.key.find(key)) {
        logRow(w, { ...base, outcome: 'duplicate', detail: 'already applied' });
        return { duplicate: true, reply: undefined };
      }
      w.db.seen.insert({ key, at: w.timestamp });
      const reply = opts.onEvent(tx, event);
      logRow(w, { ...base, outcome: 'applied' });
      return { duplicate: false, reply: reply ?? undefined };
    });
    if (result.duplicate) return json(200, { ok: true, duplicate: true });
    if (result.reply !== undefined) {
      return new SyncResponse(result.reply, { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return json(200, src.kind === 'discord' ? discordDefault(event.eventType) : { ok: true });
  } catch (e) {
    // The dedupe record rolled back with the handler, so the sender's retry is applied fresh.
    const msg = (e as Error)?.message ?? String(e);
    writeLog({ direction: 'in', peer: event.source, eventType: event.eventType, msgId: event.id, outcome: 'error', status: 500, detail: msg });
    return json(500, { error: msg });
  }
}

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

/**
 * Register (or replace) an endpoint. Generate the secret outside the module (`whsec_` + base64 of
 * 24-64 random bytes): the module's RNG is seeded from the timestamp, so it's guessable.
 */
export function addEndpoint(ctx: WebhooksCtx, name: string, url: string, secret: string, eventTypes: string[] = []): bigint {
  name = name.trim();
  if (!name || !/^https?:\/\//.test(url)) throw new Error('endpoint needs a name and an http(s) URL');
  if (secret.length < 16) throw new Error('endpoint secret is too short');
  const row = { id: 0n, name, url, secret, eventTypes, enabled: true, disabledReason: '', created: ctx.timestamp };
  const old = ctx.db.endpoint.name.find(name);
  if (old) {
    ctx.db.endpoint.id.update({ ...row, id: old.id, created: old.created });
    return old.id;
  }
  return ctx.db.endpoint.insert(row).id;
}

/** Remove an endpoint and drop its queued messages. */
export function removeEndpoint(ctx: WebhooksCtx, name: string): void {
  const ep = ctx.db.endpoint.name.find(name);
  if (!ep) return;
  for (const row of [...ctx.db.outbox.endpointId.filter(ep.id)]) ctx.db.outbox.id.delete(row.id);
  ctx.db.endpoint.id.delete(ep.id);
}

export function setEndpointEnabled(ctx: WebhooksCtx, name: string, enabled: boolean): void {
  const ep = ctx.db.endpoint.name.find(name);
  if (!ep) throw new Error('no such endpoint');
  ctx.db.endpoint.id.update({ ...ep, enabled, disabledReason: enabled ? '' : 'disabled by the module' });
}

const wants = (ep: EndpointRow, eventType: string) =>
  ep.eventTypes.length === 0 ||
  ep.eventTypes.some((p) => p === '*' || p === eventType || (p.endsWith('*') && eventType.startsWith(p.slice(0, -1))));

/** Queue `data` for every enabled endpoint that wants `eventType`. Returns the message ids. */
export function send(ctx: WebhooksCtx, eventType: string, data: unknown): string[] {
  return [...ctx.db.endpoint.iter()].filter((e) => e.enabled && wants(e, eventType)).map((ep) => enqueue(ctx, ep, eventType, data));
}

/** Queue `data` for one endpoint (ignores its event-type filter). */
export function sendTo(ctx: WebhooksCtx, endpointName: string, eventType: string, data: unknown): string {
  const ep = ctx.db.endpoint.name.find(endpointName);
  if (!ep) throw new Error('no such endpoint');
  if (!ep.enabled) throw new Error(`endpoint \`${endpointName}\` is disabled`);
  return enqueue(ctx, ep, eventType, data);
}

function enqueue(ctx: WebhooksCtx, ep: EndpointRow, eventType: string, data: unknown): string {
  init(ctx);
  const body = JSON.stringify({ type: eventType, timestamp: rfc3339(ctx.timestamp), data: data ?? null });
  const row = ctx.db.outbox.insert({
    id: 0n,
    endpointId: ep.id,
    msgId: '',
    eventType,
    body,
    created: ctx.timestamp,
    attempts: 0,
    nextAttempt: ctx.timestamp,
    inFlightUntil: undefined,
    dead: false,
    lastError: '',
  });
  const msgId = `msg_${ctx.db.state.key.find(0)?.epoch ?? ''}_${row.id}`;
  ctx.db.outbox.id.update({ ...row, msgId });
  logRow(ctx, { direction: 'out', peer: ep.name, eventType, msgId, outcome: 'queued' });
  scheduleFlush(ctx, ctx.timestamp.microsSinceUnixEpoch);
  scheduleBackstop(ctx);
  return msgId;
}

/** Put an endpoint's dead messages back in the queue. Returns how many. */
export function redeliverDead(ctx: WebhooksCtx, endpointName: string): number {
  const ep = ctx.db.endpoint.name.find(endpointName);
  if (!ep) throw new Error('no such endpoint');
  const dead = [...ctx.db.outbox.endpointId.filter(ep.id)].filter((r) => r.dead);
  for (const r of dead) ctx.db.outbox.id.update({ ...r, dead: false, attempts: 0, nextAttempt: ctx.timestamp, inFlightUntil: undefined });
  scheduleFlush(ctx, ctx.timestamp.microsSinceUnixEpoch);
  scheduleBackstop(ctx);
  return dead.length;
}

function scheduleFlush(ctx: WebhooksCtx, atUs: bigint): void {
  for (const j of ctx.db.flushJob.iter()) {
    if (j.scheduledAt.tag === 'Time' && j.scheduledAt.value.microsSinceUnixEpoch <= atUs) return;
  }
  ctx.db.flushJob.insert({ scheduledId: 0n, scheduledAt: ScheduleAt.time(atUs) });
}

/** When the outbox next needs a flush, if it has anything queued. */
function nextDue(ctx: WebhooksCtx): bigint | undefined {
  let next: bigint | undefined;
  for (const r of ctx.db.outbox.dead.filter(false)) {
    let at = r.nextAttempt.microsSinceUnixEpoch;
    if (r.inFlightUntil && r.inFlightUntil.microsSinceUnixEpoch > at) at = r.inFlightUntil.microsSinceUnixEpoch;
    if (next === undefined || at < next) next = at;
  }
  return next;
}

/**
 * Keep a later flush on the books while anything is queued. A flush job is deleted before the flush
 * runs, so a crash part-way through would leave leased messages with nothing to pick them up. This
 * runs in the same transaction as the lease, so one can't be lost without the other. It waits for the
 * next due message rather than the lease alone, so a message in a long backoff costs one job, not a
 * flush every minute.
 */
function scheduleBackstop(ctx: WebhooksCtx): void {
  const next = nextDue(ctx);
  if (next === undefined) return;
  const now = ctx.timestamp.microsSinceUnixEpoch;
  const at = next > now + LEASE_US ? next : now + LEASE_US;
  for (const j of ctx.db.flushJob.iter()) {
    if (j.scheduledAt.tag !== 'Time') continue;
    const t = j.scheduledAt.value.microsSinceUnixEpoch;
    if (t >= now + LEASE_US / 2n && t <= at) return;
  }
  ctx.db.flushJob.insert({ scheduledId: 0n, scheduledAt: ScheduleAt.time(at) });
}

/** Standard Webhooks: `v1,<base64 HMAC-SHA256(key, "<id>.<ts>.<body>")>`. */
export function signStandard(secret: string, msgId: string, tsSecs: number, body: Uint8Array): string {
  return `v1,${b64encode(hmac(sha256, standardKey(secret), concat(enc.encode(`${msgId}.${tsSecs}.`), body)))}`;
}

interface Claim {
  row: OutboxRow;
  endpoint: EndpointRow;
}

function claimNext(ctx: WebhooksCtx): Claim | undefined {
  scheduleBackstop(ctx);
  const now = ctx.timestamp.microsSinceUnixEpoch;
  const due = [...ctx.db.outbox.dead.filter(false)]
    .filter((r) => r.nextAttempt.microsSinceUnixEpoch <= now && !(r.inFlightUntil && r.inFlightUntil.microsSinceUnixEpoch > now))
    .sort((a, b) => (a.id < b.id ? -1 : 1));
  for (const row of due) {
    const ep = ctx.db.endpoint.id.find(row.endpointId);
    if (ep?.enabled) {
      ctx.db.outbox.id.update({ ...row, inFlightUntil: new Timestamp(now + LEASE_US) });
      return { row, endpoint: ep };
    }
    kill(ctx, row, '?', ep ? `endpoint disabled: ${ep.disabledReason}` : 'endpoint removed');
  }
  return undefined;
}

function kill(ctx: WebhooksCtx, row: OutboxRow, endpointName: string, why: string): void {
  logRow(ctx, { direction: 'out', peer: endpointName, eventType: row.eventType, msgId: row.msgId, outcome: 'dead', detail: why });
  ctx.db.outbox.id.update({ ...row, dead: true, inFlightUntil: undefined, lastError: why });
}

/** Scheduled procedure: deliver everything that's due, then reschedule for the next retry. */
export const flush = spacetimedb.procedure({ onSchedule: flushJob }, { arg: flushJob.rowType }, t.unit(), (ctx) => {
  for (let i = 0; i < 500; i++) {
    const claim = ctx.withTx((tx) => claimNext(tx));
    if (!claim) break;
    const now = ctx.withTx((tx) => tx.timestamp);
    const tsSecs = Number(now.microsSinceUnixEpoch / 1_000_000n);
    const body = enc.encode(claim.row.body);
    let status = 0;
    let error: string | undefined;
    try {
      const res = ctx.http.fetch(claim.endpoint.url, {
        method: 'POST',
        headers: [
          ['content-type', 'application/json'],
          ['user-agent', 'spacetimedb-webhooks/0.1'],
          ['webhook-id', claim.row.msgId],
          ['webhook-timestamp', String(tsSecs)],
          ['webhook-signature', signStandard(claim.endpoint.secret, claim.row.msgId, tsSecs, body)],
        ],
        body: claim.row.body,
        timeout: HTTP_TIMEOUT,
      });
      status = res.status;
      if (status < 200 || status >= 300) error = `${status} ${res.text().slice(0, 200)}`;
    } catch (e) {
      error = `transport error: ${String((e as Error)?.message ?? e)}`;
    }
    ctx.withTx((tx) => finish(tx, claim, status, error, now));
  }
  ctx.withTx((tx) => {
    const next = nextDue(tx);
    if (next !== undefined) {
      const now = tx.timestamp.microsSinceUnixEpoch;
      scheduleFlush(tx, next > now ? next : now);
    }
  });
  return {};
});

function finish(ctx: WebhooksCtx, claim: Claim, status: number, error: string | undefined, sentAt: Timestamp): void {
  const row = ctx.db.outbox.id.find(claim.row.id);
  if (!row) return;
  const name = claim.endpoint.name;
  const attempt = row.attempts + 1;
  const latencyUs = ctx.timestamp.microsSinceUnixEpoch - sentAt.microsSinceUnixEpoch;
  const base = { direction: 'out', peer: name, eventType: row.eventType, msgId: row.msgId, status, latencyUs };
  if (error === undefined) {
    logRow(ctx, { ...base, outcome: 'delivered', detail: `attempt ${attempt}` });
    ctx.db.outbox.id.delete(row.id);
  } else if (status === 410) {
    // 410 Gone: the receiver asked us to stop. Disable the endpoint and drop its queue.
    const ep = ctx.db.endpoint.id.find(row.endpointId);
    if (ep) ctx.db.endpoint.id.update({ ...ep, enabled: false, disabledReason: 'receiver answered 410 Gone' });
    logRow(ctx, { ...base, outcome: 'disabled', detail: error });
    for (const other of [...ctx.db.outbox.endpointId.filter(row.endpointId)].filter((r) => !r.dead)) {
      kill(ctx, other, name, 'endpoint disabled: receiver answered 410 Gone');
    }
  } else {
    const schedule = retrySchedule(ctx);
    if (attempt > schedule.length) {
      logRow(ctx, { ...base, outcome: 'dead', detail: `gave up after ${attempt} attempts: ${error}` });
      ctx.db.outbox.id.update({ ...row, attempts: attempt, dead: true, inFlightUntil: undefined, lastError: error });
    } else {
      const delay = schedule[attempt - 1];
      logRow(ctx, { ...base, outcome: 'retry', detail: `attempt ${attempt} failed, retrying in ${delay}s: ${error}` });
      ctx.db.outbox.id.update({
        ...row,
        attempts: attempt,
        nextAttempt: new Timestamp(ctx.timestamp.microsSinceUnixEpoch + BigInt(Math.round(delay * 1e6))),
        inFlightUntil: undefined,
        lastError: error,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Housekeeping and dashboards
// ---------------------------------------------------------------------------

export const prune = spacetimedb.reducer({ onSchedule: pruneJob }, { arg: pruneJob.rowType }, (ctx) => {
  const cutoff = ctx.timestamp.microsSinceUnixEpoch - SEEN_RETENTION_US;
  for (const s of [...ctx.db.seen.iter()]) {
    if (s.at.microsSinceUnixEpoch < cutoff) ctx.db.seen.key.delete(s.key);
  }
});

interface LogEntry {
  direction: string;
  peer: string;
  eventType?: string;
  msgId?: string;
  outcome: string;
  status?: number;
  detail?: string;
  latencyUs?: bigint;
}

function logRow(ctx: WebhooksCtx, e: LogEntry): void {
  ctx.db.log.insert({
    id: 0n,
    at: ctx.timestamp,
    direction: e.direction,
    peer: e.peer,
    eventType: e.eventType ?? '',
    msgId: e.msgId ?? '',
    outcome: e.outcome,
    status: e.status ?? 0,
    detail: (e.detail ?? '').slice(0, 300),
    latencyUs: e.latencyUs ?? 0n,
  });
  // Ids can skip (rolled-back inserts use them up), so prune by count, 100 rows at a time.
  if (ctx.db.log.count() > LOG_KEEP + 100n) {
    const ids = [...ctx.db.log.iter()].map((l) => l.id).sort((x, y) => (x < y ? -1 : 1));
    for (const id of ids.slice(0, ids.length - Number(LOG_KEEP))) ctx.db.log.id.delete(id);
  }
}

/** Endpoints (without secrets), queue counts and the recent log, for a dashboard. */
export function stateJson(ctx: WebhooksCtx) {
  const endpoints = [...ctx.db.endpoint.iter()].map((e) => {
    const rows = [...ctx.db.outbox.endpointId.filter(e.id)];
    return {
      name: e.name,
      url: e.url,
      event_types: e.eventTypes,
      enabled: e.enabled,
      disabled_reason: e.disabledReason,
      pending: rows.filter((r) => !r.dead).length,
      dead: rows.filter((r) => r.dead).length,
    };
  });
  const log = [...ctx.db.log.iter()]
    .sort((a, b) => (a.id > b.id ? -1 : 1))
    .slice(0, 150)
    .map((l) => ({
      id: Number(l.id),
      at: Number(l.at.microsSinceUnixEpoch),
      direction: l.direction,
      peer: l.peer,
      event_type: l.eventType,
      msg_id: l.msgId,
      outcome: l.outcome,
      status: l.status,
      detail: l.detail,
      latency_us: Number(l.latencyUs),
    }));
  return { endpoints, log };
}
