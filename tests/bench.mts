// Throughput: N signed inbound webhooks (C concurrent), then N outbound events to a local receiver.
//
//   BASE=http://127.0.0.1:3000/v1/database/wh-rust/route N=500 C=16 npx tsx tests/bench.mts
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { SECRETS, signStandard } from './fixtures.mjs';

const BASE = process.env.BASE ?? 'http://127.0.0.1:3000/v1/database/wh-rust/route';
const N = Number(process.env.N ?? 500);
const C = Number(process.env.C ?? 16);
const pct = (xs: number[], q: number) => xs.sort((a, b) => a - b)[Math.floor(q * (xs.length - 1))].toFixed(1);

// Inbound
const lat: number[] = [];
let next = 0;
const run = Date.now().toString(36);
const t0 = performance.now();
await Promise.all(
  Array.from({ length: C }, async () => {
    while (next < N) {
      const i = next++;
      const id = `bench_${run}_${i}`;
      const ts = String(Math.floor(Date.now() / 1000));
      const body = JSON.stringify({ type: 'bench.in', data: { i } });
      const s = performance.now();
      const r = await fetch(`${BASE}/webhooks/app`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'webhook-id': id, 'webhook-timestamp': ts, 'webhook-signature': signStandard(SECRETS.app, id, ts, body) },
        body,
      });
      if (r.status !== 200) throw new Error(`inbound ${r.status} ${await r.text()}`);
      lat.push(performance.now() - s);
    }
  })
);
const inSecs = (performance.now() - t0) / 1000;
console.log(`inbound:  ${N} verified + applied in ${inSecs.toFixed(2)} s = ${(N / inSecs).toFixed(0)}/s (concurrency ${C}), p50 ${pct(lat, 0.5)} ms, p99 ${pct(lat, 0.99)} ms`);

// Outbound
const arrived: number[] = [];
const server = createServer((req, res) => {
  req.resume();
  req.on('end', () => {
    arrived.push(performance.now());
    res.end('ok');
  });
});
await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/bench`;
await fetch(`${BASE}/demo/endpoint`, { method: 'POST', body: JSON.stringify({ name: `bench-${run}`, url, secret: SECRETS.endpoint, event_types: ['bench.out'] }) });
const t1 = performance.now();
next = 0;
await Promise.all(
  Array.from({ length: C }, async () => {
    while (next < N) {
      next++;
      await fetch(`${BASE}/demo/send`, { method: 'POST', body: JSON.stringify({ event_type: 'bench.out', data: {} }) });
    }
  })
);
const queued = (performance.now() - t1) / 1000;
while (arrived.length < N) await new Promise((r) => setTimeout(r, 20));
const outSecs = (arrived[arrived.length - 1] - t1) / 1000;
console.log(`outbound: ${N} queued in ${queued.toFixed(2)} s, all delivered after ${outSecs.toFixed(2)} s = ${(N / outSecs).toFixed(0)}/s (one POST at a time per flush)`);
await fetch(`${BASE}/demo/endpoint`, { method: 'POST', body: JSON.stringify({ name: `bench-${run}`, remove: true }) });
server.close();
