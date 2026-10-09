# spacetimedb-webhooks for TypeScript (submodule)

Verified inbound and signed outbound webhooks as a **SpacetimeDB submodule**.

Source: [`src/index.ts`](src/index.ts) · Complete example: [`demo/typescript`](../demo/typescript/src/index.ts) ·
Protocol: [`docs/PROTOCOL.md`](../docs/PROTOCOL.md)

## Install

It isn't on npm yet. Copy this folder into your repo and add it as an npm workspace package, so there's a single
copy of `spacetimedb` (with two copies, `spacetime publish` fails with *"Local module schema inspection failed"*).
It depends on `@noble/hashes` and `@noble/curves`.

## Wire it up

Submodules can't read env vars or own routes, so your module adds a few lines:

```typescript
import { schema, t, Router, type ReducerCtx } from 'spacetimedb/server';
import * as webhooks from 'spacetimedb-webhooks';          // `import * as`, not a default import

const spacetimedb = schema(
  { /* your tables */, webhooks },
  { env: { WEBHOOK_SOURCES: t.string().optional(), WEBHOOK_RETRY_SECS: t.string().optional() } }
);
export default spacetimedb;
type Ctx = ReducerCtx<typeof spacetimedb.schemaType>;

const cfg = (ctx: Ctx) => ({ retrySecs: ctx.env.WEBHOOK_RETRY_SECS });
export const init = spacetimedb.init((ctx) => webhooks.configure(ctx.as.webhooks, cfg(ctx)));
export const webhooksKick = spacetimedb.reducer((ctx) => webhooks.configure(ctx.as.webhooks, cfg(ctx)));

export const webhooksInbox = spacetimedb.httpHandler((ctx, req) =>
  webhooks.inbox(ctx, req, { sources: ctx.env.WEBHOOK_SOURCES, scope: (tx: Ctx) => tx.as.webhooks, onEvent })
);
export const router = spacetimedb.httpRouter(webhooks.routes(new Router(), webhooksInbox, ['github', 'twitch']));

// Verified, first-time deliveries, in the dedupe transaction. Throw to refuse; return JSON to reply.
function onEvent(tx: Ctx, ev: webhooks.WebhookEvent) {
  if (ev.source === 'twitch' && ev.eventType === 'channel.follow') { /* tx.db... */ }
}

// Outbound, from any reducer:
//   webhooks.addEndpoint(ctx.as.webhooks, 'billing', 'https://example.com/hooks', 'whsec_...', ['order.*']);
//   webhooks.send(ctx.as.webhooks, 'order.paid', { order: 42 });
```

## Names

Tables live under your namespace (`webhooks.outbox`, `webhooks.endpoint`, …), and they're all private.

Outbound POSTs don't use `ctx.http.fetch`, because the SDK splits header values on commas and that breaks
`webhook-signature: v1,…`. They call the host directly; details in [FINDINGS](../docs/FINDINGS.md).
