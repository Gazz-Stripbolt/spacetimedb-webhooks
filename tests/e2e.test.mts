// End-to-end tests against a published demo module, over plain HTTP.
//
//   BASE=http://127.0.0.1:3000/v1/database/wh-rust/route npx tsx tests/e2e.test.mts
//
// The demo must be published with WEBHOOK_SOURCES from `node tests/fixtures.mjs sources` and a
// short WEBHOOK_RETRY_SECS (scripts/e2e.sh does both).
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  SECRETS, DISCORD_PUBLIC_HEX, signStandard, signGithub, signTwitch, signStripe, signHex, signDiscord, verifyStandard,
} from './fixtures.mjs';

const BASE = process.env.BASE ?? 'http://127.0.0.1:3000/v1/database/wh-rust/route';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const now = () => Math.floor(Date.now() / 1000);
const uid = (p: string) => `${p}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;

async function post(path: string, headers: Record<string, string>, body: string) {
  const res = await fetch(BASE + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body });
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: res.status, text, json };
}

async function state(): Promise<any> {
  return (await fetch(BASE + '/api/state')).json();
}
async function events(): Promise<any[]> {
  return (await state()).events;
}
async function waitFor<T>(what: string, fn: () => Promise<T | undefined | false>, ms = 8000): Promise<T> {
  const t0 = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v as T;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(100);
  }
}

let passed = 0;
async function test(name: string, fn: () => Promise<void>) {
  await fn();
  passed++;
  console.log(`  ok  ${name}`);
}

// ---------------------------------------------------------------------------
console.log('signers match published test vectors');

await test('Standard Webhooks spec vector', async () => {
  assert.equal(
    signStandard(SECRETS.app, 'msg_p5jXN8AQM9LWM0D4loKWxJek', '1614265330', '{"test": 2432232314}'),
    'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE='
  );
});
await test('GitHub docs vector', async () => {
  assert.equal(signGithub(SECRETS.github, 'Hello, World!'), 'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17');
});
await test('RFC 8032 ed25519 test 1 (Discord signer)', async () => {
  assert.equal(DISCORD_PUBLIC_HEX, 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
  // Test 1 signs the empty message; our signer prepends the timestamp, so pass it as ts = ''.
  assert.equal(
    signDiscord('', ''),
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
  );
});

// ---------------------------------------------------------------------------
console.log('inbound');

await test('standard: valid → applied with its type; replay → duplicate; tampered/stale/unsigned → 401', async () => {
  const id = uid('msg');
  const ts = String(now());
  const body = JSON.stringify({ type: 'invoice.paid', data: { n: 1 } });
  const h = { 'webhook-id': id, 'webhook-timestamp': ts, 'webhook-signature': signStandard(SECRETS.app, id, ts, body) };
  const r = await post('/webhooks/app', h, body);
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json, { ok: true });
  const dup = await post('/webhooks/app', h, body);
  assert.equal(dup.status, 200);
  assert.equal(dup.json.duplicate, true);
  const ev = (await events()).filter((e) => e.msg_id === id);
  assert.equal(ev.length, 1, 'applied exactly once');
  assert.equal(ev[0].event_type, 'invoice.paid');
  assert.equal(ev[0].kind, 'standard');
  assert.equal((await post('/webhooks/app', h, body.replace('1', '2'))).status, 401, 'tampered body');
  const old = String(now() - 600);
  assert.equal(
    (await post('/webhooks/app', { ...h, 'webhook-timestamp': old, 'webhook-signature': signStandard(SECRETS.app, id, old, body) }, body)).status,
    401,
    'stale timestamp'
  );
  assert.equal((await post('/webhooks/app', { 'webhook-id': id, 'webhook-timestamp': ts }, body)).status, 401, 'unsigned');
});

await test('standard: key rotation (old secret, and several signatures in one header)', async () => {
  const id = uid('msg');
  const ts = String(now());
  const body = JSON.stringify({ type: 'rotated' });
  const wrong = signStandard('whsec_' + Buffer.from('nope-nope-nope-nope').toString('base64'), id, ts, body);
  const sig = `${wrong} ${signStandard(SECRETS.appOld, id, ts, body)}`;
  const r = await post('/webhooks/app', { 'webhook-id': id, 'webhook-timestamp': ts, 'webhook-signature': sig }, body);
  assert.equal(r.status, 200, r.text);
});

await test('github: valid → applied with X-GitHub-Event; bad signature → 401', async () => {
  const id = crypto.randomUUID();
  const body = JSON.stringify({ ref: 'refs/heads/main', commits: [] });
  const h = { 'x-github-event': 'push', 'x-github-delivery': id, 'x-hub-signature-256': signGithub(SECRETS.github, body) };
  assert.equal((await post('/webhooks/github', h, body)).status, 200);
  const ev = (await events()).find((e) => e.msg_id === id);
  assert.equal(ev?.event_type, 'push');
  assert.equal((await post('/webhooks/github', { ...h, 'x-hub-signature-256': signGithub('wrong', body) }, body)).status, 401);
});

await test('twitch: challenge answered, notification and revocation applied, stale rejected', async () => {
  const ts = new Date().toISOString().replace('Z', '123456Z'); // Twitch sends nanoseconds
  const send = (type: string, id: string, body: string, at = ts, subType = 'channel.follow') =>
    post('/webhooks/twitch', {
      'twitch-eventsub-message-id': id,
      'twitch-eventsub-message-timestamp': at,
      'twitch-eventsub-message-type': type,
      'twitch-eventsub-subscription-type': subType,
      'twitch-eventsub-message-signature': signTwitch(SECRETS.twitch, id, at, body),
    }, body);
  const challenge = 'pogchamp-kappa-360noscope-vohiyo';
  const c = await send('webhook_callback_verification', uid('tw'), JSON.stringify({ challenge, subscription: {} }));
  assert.equal(c.status, 200);
  assert.equal(c.text, challenge);
  const id = uid('tw');
  assert.equal((await send('notification', id, JSON.stringify({ event: { user_login: 'chippy' } }))).status, 200);
  assert.equal((await send('notification', id, JSON.stringify({ event: { user_login: 'chippy' } }))).json.duplicate, true);
  const rid = uid('tw');
  assert.equal((await send('revocation', rid, JSON.stringify({ subscription: { status: 'authorization_revoked' } }))).status, 200);
  const evs = await events();
  assert.equal(evs.find((e) => e.msg_id === id)?.event_type, 'channel.follow');
  assert.equal(evs.find((e) => e.msg_id === rid)?.event_type, 'revocation');
  const stale = new Date(Date.now() - 11 * 60_000).toISOString();
  assert.equal((await send('notification', uid('tw'), '{}', stale)).status, 401);
});

await test('stripe: valid (with an extra wrong v1) → applied with id and type from the body; stale → 401', async () => {
  const id = uid('evt');
  const body = JSON.stringify({ id, type: 'payment_intent.succeeded', data: { object: {} } });
  const t = now();
  const sig = signStripe(SECRETS.stripe, t, body).replace(',v1=', `,v1=${'0'.repeat(64)},v1=`);
  assert.equal((await post('/webhooks/stripe', { 'stripe-signature': sig }, body)).status, 200);
  assert.equal((await events()).find((e) => e.msg_id === id)?.event_type, 'payment_intent.succeeded');
  const old = now() - 400;
  assert.equal((await post('/webhooks/stripe', { 'stripe-signature': signStripe(SECRETS.stripe, old, body) }, body)).status, 401);
});

await test('generic HMAC: configurable header, prefix, id and type headers', async () => {
  const id = uid('req');
  const body = JSON.stringify({ hello: 'world' });
  const h = { 'x-signature': `sha256=${signHex(SECRETS.custom, body)}`, 'x-request-id': id, 'x-event-type': 'thing.happened' };
  assert.equal((await post('/webhooks/custom', h, body)).status, 200);
  assert.equal((await events()).find((e) => e.msg_id === id)?.event_type, 'thing.happened');
  assert.equal((await post('/webhooks/custom', h, body)).json.duplicate, true);
  assert.equal((await post('/webhooks/custom', { ...h, 'x-signature': 'sha256=00' }, body)).status, 401);
});

await test('discord: PING → PONG, command → the handler\'s reply, bad signature → 401', async () => {
  const ts = String(now());
  const ping = JSON.stringify({ id: uid('ping'), type: 1 });
  const r = await post('/webhooks/discord', { 'x-signature-ed25519': signDiscord(ts, ping), 'x-signature-timestamp': ts }, ping);
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json, { type: 1 });
  const cmd = JSON.stringify({ id: uid('ix'), type: 2, data: { name: 'ping' } });
  const c = await post('/webhooks/discord', { 'x-signature-ed25519': signDiscord(ts, cmd), 'x-signature-timestamp': ts }, cmd);
  assert.equal(c.status, 200, c.text);
  assert.deepEqual(c.json, { type: 4, data: { content: 'Pong from SpacetimeDB (/ping)' } });
  const comp = JSON.stringify({ id: uid('ix'), type: 3, data: {} });
  const d = await post('/webhooks/discord', { 'x-signature-ed25519': signDiscord(ts, comp), 'x-signature-timestamp': ts }, comp);
  assert.deepEqual(d.json, { type: 6 }, 'default ack for components');
  assert.equal((await post('/webhooks/discord', { 'x-signature-ed25519': signDiscord(ts, ping), 'x-signature-timestamp': ts }, cmd)).status, 401);
});

await test('unconfigured source → 404', async () => {
  assert.equal((await post('/webhooks/spare', {}, '{}')).status, 404);
});

await test('handler error → 500 and nothing recorded, so the sender\'s retry is applied fresh', async () => {
  const id = uid('msg');
  const ts = String(now());
  const bad = JSON.stringify({ type: 'flaky', fail: true });
  const r = await post('/webhooks/app', { 'webhook-id': id, 'webhook-timestamp': ts, 'webhook-signature': signStandard(SECRETS.app, id, ts, bad) }, bad);
  assert.equal(r.status, 500);
  assert.equal((await events()).some((e) => e.msg_id === id), false);
  const good = JSON.stringify({ type: 'flaky' });
  const r2 = await post('/webhooks/app', { 'webhook-id': id, 'webhook-timestamp': ts, 'webhook-signature': signStandard(SECRETS.app, id, ts, good) }, good);
  assert.equal(r2.status, 200);
  assert.notEqual(r2.json.duplicate, true, 'not a duplicate: the first attempt rolled back');
});

// ---------------------------------------------------------------------------
console.log('outbound');

type Hit = { path: string; headers: IncomingMessage['headers']; body: string; status: number; at: number };
const hits: Hit[] = [];
const plan = new Map<string, number[]>(); // path -> statuses to answer, in order (then 200)
const server = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const path = req.url ?? '/';
    const queue = plan.get(path) ?? [];
    const status = queue.length ? queue.shift()! : 200;
    hits.push({ path, headers: req.headers, body, status, at: Date.now() });
    res.writeHead(status, { 'content-type': 'text/plain' }).end(status === 200 ? 'ok' : 'nope');
  });
});
await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
const port = (server.address() as AddressInfo).port;
const receiver = (path: string) => `http://127.0.0.1:${port}${path}`;
const endpoint = (name: string, url: string, event_types: string[] = [], secret = SECRETS.endpoint) =>
  post('/demo/endpoint', {}, JSON.stringify({ name, url, secret, event_types }));
const sendEvent = (event_type: string, data: unknown, fail = false) =>
  post('/demo/send', {}, JSON.stringify({ event_type, data, fail }));
const hitsFor = (path: string) => hits.filter((h) => h.path === path);

try {
  await test('delivered right after commit, signed per Standard Webhooks, standard payload shape', async () => {
    assert.equal((await endpoint('main', receiver('/main'))).status, 200);
    const t0 = Date.now();
    const r = await sendEvent('order.created', { order: 42 });
    assert.equal(r.status, 200, r.text);
    const hit = await waitFor('delivery', async () => hitsFor('/main')[0]);
    console.log(`      delivered ${hit.at - t0} ms after the request that queued it`);
    assert.ok(verifyStandard(SECRETS.endpoint, hit.headers, hit.body), 'signature verifies');
    assert.equal(hit.headers['webhook-id'], r.json.queued[0]);
    const body = JSON.parse(hit.body);
    assert.equal(body.type, 'order.created');
    assert.deepEqual(body.data, { order: 42 });
    assert.ok(!Number.isNaN(Date.parse(body.timestamp)));
  });

  await test('transactional: a rolled-back send is never delivered', async () => {
    const before = hitsFor('/main').length;
    assert.equal((await sendEvent('order.created', { order: 'ghost' }, true)).status, 500);
    await sleep(1500);
    assert.equal(hitsFor('/main').length, before);
  });

  await test('retries with backoff, same webhook-id, fresh signature each time', async () => {
    plan.set('/flaky', [503, 500]);
    await endpoint('flaky', receiver('/flaky'), ['flaky.*']);
    const r = await sendEvent('flaky.event', { n: 1 });
    const hs = await waitFor('3 attempts', async () => hitsFor('/flaky').length >= 3 && hitsFor('/flaky'));
    assert.deepEqual(hs.map((h) => h.status), [503, 500, 200]);
    assert.ok(hs.every((h) => h.headers['webhook-id'] === r.json.queued.at(-1)));
    assert.ok(hs.every((h) => verifyStandard(SECRETS.endpoint, h.headers, h.body)));
    const log = (await state()).log.filter((l: any) => l.peer === 'flaky');
    assert.deepEqual(log.map((l: any) => l.outcome).reverse(), ['queued', 'retry', 'retry', 'delivered']);
  });

  await test('dead letter after the retry schedule runs out', async () => {
    await endpoint('down', 'http://127.0.0.1:9/nothing-listens-here', ['down.*']);
    await sendEvent('down.event', {});
    const ep = await waitFor('dead letter', async () => (await state()).endpoints.find((e: any) => e.name === 'down' && e.dead === 1), 15000);
    assert.equal(ep.pending, 0);
  });

  await test('410 Gone disables the endpoint', async () => {
    plan.set('/gone', [410]);
    await endpoint('gone', receiver('/gone'), ['gone.*']);
    await sendEvent('gone.event', {});
    const ep = await waitFor('disabled', async () => (await state()).endpoints.find((e: any) => e.name === 'gone' && !e.enabled));
    assert.match(ep.disabled_reason, /410/);
    await sendEvent('gone.event', {});
    await sleep(800);
    assert.equal(hitsFor('/gone').length, 1, 'nothing more sent to a disabled endpoint');
  });

  await test('event-type filters: exact, prefix.*, and catch-all', async () => {
    await endpoint('orders', receiver('/orders'), ['order.*']);
    await endpoint('users', receiver('/users'), ['user.created']);
    await sendEvent('user.created', { u: 1 });
    await sendEvent('order.paid', { o: 1 });
    await waitFor('orders + users', async () => hitsFor('/orders').length >= 1 && hitsFor('/users').length >= 1);
    await sleep(500);
    assert.deepEqual(hitsFor('/orders').map((h) => JSON.parse(h.body).type), ['order.paid']);
    assert.deepEqual(hitsFor('/users').map((h) => JSON.parse(h.body).type), ['user.created']);
    assert.ok(hitsFor('/main').some((h) => JSON.parse(h.body).type === 'order.paid'), 'no filter = everything');
  });

  await test('loopback: the module sends to its own inbound route and receives it', async () => {
    await endpoint('self', `${BASE}/webhooks/app`, ['loop.*'], SECRETS.app);
    const r = await sendEvent('loop.test', { hello: 'me' });
    const id = r.json.queued.at(-1);
    const ev = await waitFor('loopback event', async () => (await events()).find((e) => e.msg_id === id));
    assert.equal(ev.event_type, 'loop.test');
    assert.equal(ev.source, 'app');
  });
} finally {
  server.close();
}

console.log(`\n${passed} passed`);
