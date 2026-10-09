// Demo: a module that receives webhooks from six kinds of sender and sends its own, with a
// live dashboard at /route/. The C# twin of demo/rust.

#pragma warning disable STDB_UNSTABLE
#nullable enable

using System.Text;
using System.Text.Json.Nodes;
using SpacetimeDB;

public static partial class Module
{
    /// <summary>The inbound routes. "spare" has no configuration, to show what that returns.</summary>
    static readonly string[] DemoSources = { "github", "twitch", "stripe", "app", "discord", "custom", "spare" };

    /// <summary>Every webhook this module has accepted.</summary>
    [SpacetimeDB.Table(Accessor = "DemoEvent", Public = true)]
    public partial struct DemoEvent
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        public Timestamp At;
        public string Source;
        public string Kind;
        public string EventType;
        public string MsgId;
        public string Summary;
    }

    [SpacetimeDB.Reducer(ReducerKind.Init)]
    public static void Init(ReducerContext ctx) => WebhooksInit(ctx);

    /// <summary>Called by Webhooks.cs for each verified, first-time delivery.</summary>
    public static partial string? OnWebhook(WebhookTx tx, WebhookEvent ev)
    {
        JsonNode? body = null;
        try { body = JsonNode.Parse(ev.Body); } catch { }
        if (body?["fail"] is JsonValue f && f.TryGetValue<bool>(out var fail) && fail)
            throw new Exception("demo handler failed on purpose");
        tx.Db.DemoEvent.Insert(new DemoEvent
        {
            At = tx.Timestamp, Source = ev.Source, Kind = ev.Kind, EventType = ev.EventType, MsgId = ev.Id,
            Summary = ev.Body.Length > 160 ? ev.Body[..160] : ev.Body,
        });
        if (ev.EventType == "application_command")
        {
            var name = body?["data"]?["name"] is JsonValue n && n.TryGetValue<string>(out var s) ? s : "command";
            return new JsonObject { ["type"] = 4, ["data"] = new JsonObject { ["content"] = $"Pong from SpacetimeDB (/{name})" } }.ToJsonString();
        }
        return null;
    }

    static HttpResponse DemoJson(ushort status, JsonNode body) =>
        new(status, HttpVersion.Http11,
            new List<HttpHeader> { new("content-type", "application/json"), new("cache-control", "no-store") },
            HttpBody.FromString(body.ToJsonString()));

    static JsonNode? DemoBody(HttpRequest req)
    {
        try { return JsonNode.Parse(req.Body.ToBytes()); } catch { return null; }
    }

    static readonly Lazy<byte[]> DemoPage = new(() =>
    {
        using var s = typeof(Module).Assembly.GetManifestResourceStream("index.html")!;
        using var m = new MemoryStream();
        s.CopyTo(m);
        return m.ToArray();
    });

    [SpacetimeDB.HttpHandler]
    public static HttpResponse Page(HandlerContext ctx, HttpRequest req) =>
        new(200, HttpVersion.Http11,
            new List<HttpHeader> { new("content-type", "text/html; charset=utf-8"), new("cache-control", "no-cache") },
            new HttpBody(DemoPage.Value));

    /// <summary>Dashboard data. Demo only: a real module shouldn't expose its webhook log publicly.</summary>
    [SpacetimeDB.HttpHandler]
    public static HttpResponse State(HandlerContext ctx, HttpRequest req)
    {
        var json = ctx.WithTx(tx =>
        {
            var v = WebhookStateJson(new WebhookTx(tx.Db, tx.Timestamp));
            var events = new JsonArray();
            foreach (var e in tx.Db.DemoEvent.Iter().OrderByDescending(e => e.Id).Take(60))
            {
                events.Add((JsonNode)new JsonObject
                {
                    ["id"] = e.Id, ["at"] = e.At.MicrosecondsSinceUnixEpoch, ["source"] = e.Source, ["kind"] = e.Kind,
                    ["event_type"] = e.EventType, ["msg_id"] = e.MsgId, ["summary"] = e.Summary,
                });
            }
            v["events"] = events;
            var sources = new JsonArray();
            foreach (var s in WebhookParseSources(WebhookEnv.WEBHOOK_SOURCES))
                sources.Add((JsonNode)new JsonObject { ["name"] = s.Name, ["kind"] = s.Kind });
            v["sources"] = sources;
            v["routes"] = new JsonArray(DemoSources.Select(r => (JsonNode?)JsonValue.Create(r)).ToArray());
            return v.ToJsonString();
        });
        return new HttpResponse(200, HttpVersion.Http11,
            new List<HttpHeader> { new("content-type", "application/json"), new("cache-control", "no-store") },
            HttpBody.FromString(json));
    }

    /// <summary>{"event_type", "data", "fail"}: queue an outbound event; fail=true rolls it back.</summary>
    [SpacetimeDB.HttpHandler]
    public static HttpResponse DemoSend(HandlerContext ctx, HttpRequest req)
    {
        var b = DemoBody(req);
        var eventType = b?["event_type"] is JsonValue t && t.TryGetValue<string>(out var et) ? et : "demo.ping";
        var data = b?["data"]?.DeepClone();
        var fail = b?["fail"] is JsonValue f && f.TryGetValue<bool>(out var ff) && ff;
        try
        {
            var ids = ctx.WithTx(tx =>
            {
                var queued = WebhookSend(new WebhookTx(tx.Db, tx.Timestamp), eventType, data?.DeepClone());
                if (fail) throw new Exception("rolled back on purpose");
                return queued;
            });
            return DemoJson(200, new JsonObject { ["queued"] = new JsonArray(ids.Select(i => (JsonNode?)JsonValue.Create(i)).ToArray()) });
        }
        catch (Exception e)
        {
            return DemoJson(500, new JsonObject { ["error"] = e.Message });
        }
    }

    /// <summary>{"name", "url", "secret", "event_types", "remove"}. Demo only: anyone can add endpoints.</summary>
    [SpacetimeDB.HttpHandler]
    public static HttpResponse DemoEndpoint(HandlerContext ctx, HttpRequest req)
    {
        var b = DemoBody(req);
        string S(string k) => b?[k] is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
        var types = (b?["event_types"] as JsonArray)?.Select(x => x is JsonValue v && v.TryGetValue<string>(out var s) ? s : "")
            .Where(s => s.Length > 0).ToArray() ?? Array.Empty<string>();
        var remove = b?["remove"] is JsonValue r && r.TryGetValue<bool>(out var rr) && rr;
        try
        {
            var id = ctx.WithTx(tx =>
            {
                var wtx = new WebhookTx(tx.Db, tx.Timestamp);
                if (remove) { WebhookRemoveEndpoint(wtx, S("name")); return 0UL; }
                return WebhookAddEndpoint(wtx, S("name"), S("url"), S("secret"), types);
            });
            return DemoJson(200, new JsonObject { ["id"] = id });
        }
        catch (Exception e)
        {
            return DemoJson(400, new JsonObject { ["error"] = e.Message });
        }
    }

    [SpacetimeDB.HttpRouter]
    public static Router Routes() =>
        WebhookRoutes(Router.New(), DemoSources)
            .Get("/", Handlers.Page)
            .Get("/api/state", Handlers.State)
            .Post("/demo/send", Handlers.DemoSend)
            .Post("/demo/endpoint", Handlers.DemoEndpoint);
}
