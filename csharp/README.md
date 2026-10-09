# Webhooks.cs: webhooks for C# modules

One file. Add [`Webhooks.cs`](Webhooks.cs) to your module project (or link it like
[`demo/csharp/StdbModule.csproj`](../demo/csharp/StdbModule.csproj) does). It has no dependencies: SHA-256,
SHA-512 and Ed25519 are managed code, because `System.Security.Cryptography` isn't available on wasi.

```csharp
public static partial class Module
{
    [Reducer(ReducerKind.Init)]
    public static void Init(ReducerContext ctx) => WebhooksInit(ctx);

    // Verified, first-time deliveries, in the dedupe transaction. Throw to refuse; return JSON to reply.
    public static partial string? OnWebhook(WebhookTx tx, WebhookEvent ev)
    {
        if (ev.Source == "github" && ev.EventType == "push") { /* tx.Db... */ }
        return null;
    }

    [HttpRouter]
    public static Router Routes() => WebhookRoutes(Router.New(), "github", "twitch", "stripe", "discord");
}
```

Sources come from the `WEBHOOK_SOURCES` env var (see [PROTOCOL.md](../docs/PROTOCOL.md)). `Webhooks.cs` declares
the module's `[SpacetimeDB.Env]` struct. If you already have one, move the two fields into it.

Outbound: `WebhookAddEndpoint(tx, "billing", url, "whsec_...", "order.*")`, then
`WebhookSend(ctx, "order.paid", new JsonObject { ["order"] = 42 })` in any reducer. Also `WebhookSendTo`,
`WebhookRemoveEndpoint`, `WebhookSetEndpointEnabled`, `WebhookRedeliverDead` and `WebhookStateJson`. A complete
module is in [`demo/csharp`](../demo/csharp/Lib.cs). It builds with NativeAOT-LLVM (.NET 10).
