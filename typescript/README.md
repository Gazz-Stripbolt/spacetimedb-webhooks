# spacetimedb-webhooks for TypeScript (submodule)

Verified inbound and signed outbound webhooks as a **SpacetimeDB submodule**.

Source: [`src/index.ts`](src/index.ts) · Complete example: [`demo/typescript`](../demo/typescript/src/index.ts) ·
Protocol: [`docs/PROTOCOL.md`](../docs/PROTOCOL.md)

## Install

```bash
npm install @pogly/spacetimedb-webhooks spacetimedb
```

Use `spacetimedb` 2.11.x or 2.12.x, and keep only one copy of it in your module's dependency tree. With two copies,
`spacetime publish` fails with *"Local module schema inspection failed"*. The package ships compiled JavaScript plus
its TypeScript source, which is where the types come from. It depends on `@noble/hashes` and `@noble/curves`.

To work on it from a clone instead, add this folder to your npm workspaces next to your module:

```jsonc
// package.json at your repo root
{ "private": true, "workspaces": ["spacetimedb-webhooks/typescript", "my-module"] }
// my-module/package.json
{ "dependencies": { "spacetimedb": "2.12.*", "@pogly/spacetimedb-webhooks": "*" } }
```

## Wire it up

Submodules can't read env vars or own routes, so your module adds a few lines:

```typescript
import { schema, t, Router, type ReducerCtx } from 'spacetimedb/server';
import * as webhooks from '@pogly/spacetimedb-webhooks';          // `import * as`, not a default import

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
