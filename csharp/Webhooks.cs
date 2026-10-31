// Webhooks.cs: verified inbound and signed outbound webhooks for SpacetimeDB C# modules.
//
// The C# twin of rust/webhooks.rs and the spacetimedb-webhooks TypeScript submodule: same
// sources, same headers, same signatures, same behaviour.
//
// Drop this file into your module project and implement one method:
//
//     public static partial string? OnWebhook(WebhookTx tx, WebhookEvent ev) { ... }
//
// Return null, or a JSON string to send back (Discord interaction replies). Throw to reject:
// the dedupe record rolls back with your changes and the sender's retry gets a clean try.
//
// Then call WebhooksInit(ctx) from Init and add WebhookRoutes(router, "github", "twitch", ...)
// to your [HttpRouter]. Inbound sources come from the WEBHOOK_SOURCES env var (JSON).
// Outbound: WebhookAddEndpoint, then WebhookSend inside any reducer or transaction.

#pragma warning disable STDB_UNSTABLE
#nullable enable

using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;
using SpacetimeDB;
using HttpMethod = SpacetimeDB.HttpMethod;

/// <summary>A transaction: works from reducers, procedures and HTTP handlers.</summary>
public readonly record struct WebhookTx(Local Db, Timestamp Timestamp);

/// <summary>A verified, not-yet-seen inbound webhook.</summary>
/// <param name="Source">The source name (the route segment).</param>
/// <param name="Kind">standard, github, twitch, stripe, discord or hmac.</param>
/// <param name="Id">The sender's delivery id (what dedupe uses).</param>
/// <param name="EventType">GitHub: X-GitHub-Event. Twitch: subscription type or "revocation". Stripe/Standard: body "type". Discord: application_command, ...</param>
/// <param name="Body">The raw body (UTF-8).</param>
public readonly record struct WebhookEvent(string Source, string Kind, string Id, string EventType, string Body);

public static partial class Module
{
    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    /// <summary>
    /// Owner-set configuration. A module has one env declaration: if yours already has one,
    /// move these fields into it and delete this struct.
    /// </summary>
    [SpacetimeDB.Env]
    public partial struct WebhooksEnvironment
    {
        /// <summary>JSON object of inbound sources. See docs/PROTOCOL.md.</summary>
        public string? WEBHOOK_SOURCES;
        /// <summary>Outbound retry delays in seconds, comma-separated.</summary>
        public string? WEBHOOK_RETRY_SECS;
    }

    // ModuleEnvironment isn't generated on .NET 10, where only ctx.Env has these fields, and this
    // code often has no ctx. DatabaseEnvironment.Get works on every target.
    readonly struct WebhookEnvValues
    {
        public string? WEBHOOK_SOURCES => default(DatabaseEnvironment).Get("WEBHOOK_SOURCES");
        public string? WEBHOOK_RETRY_SECS => default(DatabaseEnvironment).Get("WEBHOOK_RETRY_SECS");
    }

    static WebhookEnvValues WebhookEnv => default;

    static readonly double[] WebhookDefaultRetrySecs = { 5, 30, 120, 600, 1800, 3600, 7200, 14400 };
    static readonly TimeSpan WebhookHttpTimeout = TimeSpan.FromSeconds(15);
    const long WebhookLeaseUs = 60L * 1_000_000;
    const ulong WebhookLogKeep = 500;
    const long WebhookSeenRetentionUs = 7L * 24 * 3600 * 1_000_000;

    /// <summary>Your handler for verified, first-time deliveries. Runs in the dedupe transaction.</summary>
    public static partial string? OnWebhook(WebhookTx tx, WebhookEvent ev);

    public sealed record WebhookSource(
        string Name, string Kind, List<string> Secrets, string PublicKey, string Header, string Prefix,
        string Encoding, string IdHeader, string TypeHeader, long ToleranceSecs);

    /// <summary>Parse WEBHOOK_SOURCES.</summary>
    public static List<WebhookSource> WebhookParseSources(string? raw)
    {
        var list = new List<WebhookSource>();
        if (string.IsNullOrWhiteSpace(raw)) return list;
        if (JsonNode.Parse(raw) is not JsonObject obj) throw new Exception("WEBHOOK_SOURCES must be a JSON object");
        foreach (var (name, node) in obj)
        {
            if (node is not JsonObject cfg) throw new Exception($"source `{name}`: not an object");
            string S(string k) => cfg[k] is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
            var kind = S("kind");
            if (kind is not ("standard" or "github" or "twitch" or "stripe" or "discord" or "hmac"))
                throw new Exception($"source `{name}`: unknown kind `{kind}`");
            var secrets = new List<string>();
            if (S("secret") is { Length: > 0 } one) secrets.Add(one);
            if (cfg["secrets"] is JsonArray arr)
                foreach (var x in arr)
                    if (x is JsonValue v && v.TryGetValue<string>(out var s)) secrets.Add(s);
            if (kind == "discord" && S("public_key").Length == 0) throw new Exception($"source `{name}`: discord needs public_key");
            if (kind != "discord" && secrets.Count == 0) throw new Exception($"source `{name}`: needs secret");
            long tolerance = cfg["tolerance_secs"] is JsonValue tv && tv.TryGetValue<long>(out var t) ? t : kind == "twitch" ? 600 : 300;
            list.Add(new WebhookSource(
                name, kind, secrets, S("public_key"),
                (S("header") is { Length: > 0 } h ? h : "x-signature").ToLowerInvariant(),
                S("prefix"), S("encoding") is { Length: > 0 } e ? e : "hex",
                S("id_header").ToLowerInvariant(), S("type_header").ToLowerInvariant(), tolerance));
        }
        return list;
    }

    static double[] WebhookRetrySchedule(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return WebhookDefaultRetrySecs;
        var list = raw.Split(',')
            .Select(x => double.TryParse(x.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : -1)
            .Where(d => d >= 0 && double.IsFinite(d))
            .ToArray();
        return list.Length == 0 ? WebhookDefaultRetrySecs : list;
    }

    // -----------------------------------------------------------------------
    // Tables
    // -----------------------------------------------------------------------

    /// <summary>Delivery ids already applied, per source. Pruned after 7 days.</summary>
    [SpacetimeDB.Table(Accessor = "WebhookSeen")]
    public partial struct WebhookSeen
    {
        [SpacetimeDB.PrimaryKey]
        public string Key;
        [SpacetimeDB.Index.BTree]
        public Timestamp At;
    }

    /// <summary>Outbound endpoints. Private: secrets never reach subscribers.</summary>
    [SpacetimeDB.Table(Accessor = "WebhookEndpoint")]
    public partial struct WebhookEndpoint
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        [SpacetimeDB.Unique]
        public string Name;
        public string Url;
        /// <summary>whsec_&lt;base64&gt; (Standard Webhooks). Raw strings work too.</summary>
        public string Secret;
        /// <summary>Exact (order.paid), prefix (order.*) or *. Empty = all.</summary>
        public List<string> EventTypes;
        public bool Enabled;
        public string DisabledReason;
        public Timestamp Created;
    }

    /// <summary>Events waiting to be delivered, one row per endpoint.</summary>
    [SpacetimeDB.Table(Accessor = "WebhookOutbox")]
    public partial struct WebhookOutbox
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        [SpacetimeDB.Index.BTree]
        public ulong EndpointId;
        /// <summary>The webhook-id: the same on every retry.</summary>
        public string MsgId;
        public string EventType;
        /// <summary>The exact JSON body, fixed at send time.</summary>
        public string Body;
        public Timestamp Created;
        public uint Attempts;
        public Timestamp NextAttempt;
        public Timestamp? InFlightUntil;
        /// <summary>Dead letters stay until redelivered or removed; indexed so the queue scan skips them.</summary>
        [SpacetimeDB.Index.BTree]
        public bool Dead;
        public string LastError;
    }

    /// <summary>Activity feed, both directions. Metadata only.</summary>
    [SpacetimeDB.Table(Accessor = "WebhookLog")]
    public partial struct WebhookLog
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        public Timestamp At;
        public string Direction;
        public string Peer;
        public string EventType;
        public string MsgId;
        public string Outcome;
        public ushort Status;
        public string Detail;
        public long LatencyUs;
    }

    [SpacetimeDB.Table(Accessor = "WebhookState")]
    public partial struct WebhookState
    {
        [SpacetimeDB.PrimaryKey]
        public byte Key;
        public string Epoch;
    }

    [SpacetimeDB.Table(Accessor = "WebhookFlushJob", Scheduled = nameof(WebhookFlush), ScheduledAt = nameof(WebhookFlushJob.ScheduledAt))]
    public partial struct WebhookFlushJob
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong ScheduledId;
        public ScheduleAt ScheduledAt;
    }

    [SpacetimeDB.Table(Accessor = "WebhookPruneJob", Scheduled = nameof(WebhookPrune), ScheduledAt = nameof(WebhookPruneJob.ScheduledAt))]
    public partial struct WebhookPruneJob
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong ScheduledId;
        public ScheduleAt ScheduledAt;
    }

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    /// <summary>Call from Init. Idempotent. Already published? Call the webhooks_kick reducer once.</summary>
    public static void WebhooksInit(WebhookTx tx)
    {
        if (tx.Db.WebhookState.Key.Find(0) is null)
            tx.Db.WebhookState.Insert(new WebhookState { Key = 0, Epoch = tx.Timestamp.MicrosecondsSinceUnixEpoch.ToString("x") });
        if (tx.Db.WebhookPruneJob.Count == 0)
            tx.Db.WebhookPruneJob.Insert(new WebhookPruneJob { ScheduledAt = new ScheduleAt.Interval(TimeSpan.FromHours(1)) });
    }

    public static void WebhooksInit(ReducerContext ctx) => WebhooksInit(new WebhookTx(ctx.Db, ctx.Timestamp));

    /// <summary>Re-run setup and flush the outbox. Safe for anyone to call.</summary>
    [SpacetimeDB.Reducer]
    public static void WebhooksKick(ReducerContext ctx)
    {
        var tx = new WebhookTx(ctx.Db, ctx.Timestamp);
        WebhooksInit(tx);
        WebhookScheduleFlush(tx, ctx.Timestamp);
    }

    /// <summary>Add POST /webhooks/&lt;name&gt; for each source to your router.</summary>
    public static Router WebhookRoutes(Router router, params string[] sources) =>
        sources.Aggregate(router, (r, name) => r.Post($"/webhooks/{name}", Handlers.WebhooksInbox));

    // -----------------------------------------------------------------------
    // Inbound
    // -----------------------------------------------------------------------

    sealed class WebhookReject(ushort status, string message) : Exception(message)
    {
        public ushort Status { get; } = status;
    }

    static WebhookReject Unauthorized(string m) => new(401, m);

    abstract record WebhookVerified;
    sealed record WebhookVerifiedEvent(string Id, string EventType) : WebhookVerified;
    sealed record WebhookVerifiedReply(string Outcome, HttpResponse Response) : WebhookVerified;

    static List<string> WebhookHeaderValues(HttpRequest req, string name) =>
        req.Headers.Where(h => string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase))
            .Select(h => Encoding.ASCII.GetString(h.Value)).ToList();

    static string? WebhookHeader(HttpRequest req, string name) =>
        WebhookHeaderValues(req, name) is { Count: > 0 } v ? string.Join(",", v) : null;

    static string WebhookNeed(HttpRequest req, string name) =>
        WebhookHeader(req, name) ?? throw Unauthorized($"missing {name} header");

    static string WebhookHex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    static byte[]? WebhookUnhex(string s)
    {
        s = s.Trim();
        if (s.Length % 2 != 0) return null;
        try { return Convert.FromHexString(s); } catch { return null; }
    }

    static byte[]? WebhookUnbase64(string s)
    {
        try { return Convert.FromBase64String(s.Trim()); } catch { return null; }
    }

    static byte[] WebhookConcat(params byte[][] parts)
    {
        var all = new byte[parts.Sum(p => p.Length)];
        var o = 0;
        foreach (var p in parts) { p.CopyTo(all, o); o += p.Length; }
        return all;
    }

    static bool WebhookFixedEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    static bool WebhookAnyMatch(IEnumerable<byte[]> keys, byte[] message, List<byte[]> candidates) =>
        keys.Any(k =>
        {
            var mac = WebhookSha256.Hmac(k, message);
            return candidates.Any(c => WebhookFixedEquals(mac, c));
        });

    static byte[] WebhookStandardKey(string secret)
    {
        var b = secret.StartsWith("whsec_", StringComparison.Ordinal) ? secret[6..] : secret;
        return WebhookUnbase64(b) ?? Encoding.UTF8.GetBytes(secret);
    }

    static void WebhookCheckWindow(Timestamp now, long tsSecs, long tolerance)
    {
        if (Math.Abs(now.MicrosecondsSinceUnixEpoch / 1_000_000 - tsSecs) > tolerance)
            throw Unauthorized("timestamp outside the allowed window");
    }

    static string WebhookBodyField(byte[] body, string key)
    {
        try
        {
            return JsonNode.Parse(body)?[key] switch
            {
                JsonValue v when v.TryGetValue<string>(out var s) => s,
                JsonValue v => v.ToJsonString(),
                _ => "",
            };
        }
        catch { return ""; }
    }

    static long WebhookBodyNumber(byte[] body, string key)
    {
        try { return JsonNode.Parse(body)?[key] is JsonValue v && v.TryGetValue<long>(out var n) ? n : 0; }
        catch { return 0; }
    }

    /// <summary>RFC 3339 (Twitch sends nanoseconds) to unix seconds.</summary>
    static long WebhookParseRfc3339(string s)
    {
        s = s.Trim();
        if (s.Length < 20 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != 't' && s[10] != ' ') || s[13] != ':' || s[16] != ':')
            throw Unauthorized("bad message timestamp");
        int P(int i, int n) => int.Parse(s.AsSpan(i, n), NumberStyles.None, CultureInfo.InvariantCulture);
        var dt = new DateTimeOffset(P(0, 4), P(5, 2), P(8, 2), P(11, 2), P(14, 2), P(17, 2), TimeSpan.Zero);
        var i = 19;
        if (i < s.Length && s[i] == '.') { i++; while (i < s.Length && char.IsAsciiDigit(s[i])) i++; }
        var zone = s[i..];
        if (zone is "Z" or "z") return dt.ToUnixTimeSeconds();
        if (zone.Length == 6 && (zone[0] == '+' || zone[0] == '-') && zone[3] == ':')
        {
            var offset = new TimeSpan(int.Parse(zone.AsSpan(1, 2), CultureInfo.InvariantCulture), int.Parse(zone.AsSpan(4, 2), CultureInfo.InvariantCulture), 0);
            return (zone[0] == '+' ? dt - offset : dt + offset).ToUnixTimeSeconds();
        }
        throw Unauthorized("bad message timestamp");
    }

    static WebhookVerified WebhookVerify(WebhookSource src, HttpRequest req, byte[] body, Timestamp now)
    {
        var secrets = src.Secrets.Select(s => Encoding.UTF8.GetBytes(s)).ToList();
        switch (src.Kind)
        {
            case "standard":
            {
                var id = WebhookNeed(req, "webhook-id");
                var ts = WebhookNeed(req, "webhook-timestamp");
                if (!long.TryParse(ts.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var tsSecs)) throw Unauthorized("bad webhook-timestamp");
                WebhookCheckWindow(now, tsSecs, src.ToleranceSecs);
                var sigs = WebhookHeaderValues(req, "webhook-signature")
                    .SelectMany(v => v.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    .Where(e => e.StartsWith("v1,", StringComparison.Ordinal))
                    .Select(e => WebhookUnbase64(e[3..]))
                    .OfType<byte[]>().ToList();
                var msg = WebhookConcat(Encoding.UTF8.GetBytes($"{id}.{tsSecs}."), body);
                if (!WebhookAnyMatch(src.Secrets.Select(WebhookStandardKey), msg, sigs)) throw Unauthorized("bad signature");
                return new WebhookVerifiedEvent(id, WebhookBodyField(body, "type"));
            }
            case "github":
            {
                var sig = WebhookNeed(req, "x-hub-signature-256");
                var raw = sig.StartsWith("sha256=", StringComparison.Ordinal) ? WebhookUnhex(sig[7..]) : null;
                if (raw is null) throw Unauthorized("malformed x-hub-signature-256");
                if (!WebhookAnyMatch(secrets, body, new() { raw })) throw Unauthorized("bad signature");
                // GitHub signs no timestamp: dedupe by delivery id is the only replay protection.
                var id = WebhookHeader(req, "x-github-delivery") ?? WebhookHex(WebhookSha256.Hash(body));
                return new WebhookVerifiedEvent(id, WebhookHeader(req, "x-github-event") ?? "");
            }
            case "twitch":
            {
                var id = WebhookNeed(req, "twitch-eventsub-message-id");
                var ts = WebhookNeed(req, "twitch-eventsub-message-timestamp");
                var sig = WebhookNeed(req, "twitch-eventsub-message-signature");
                var raw = sig.StartsWith("sha256=", StringComparison.Ordinal) ? WebhookUnhex(sig[7..]) : null;
                if (raw is null) throw Unauthorized("malformed twitch-eventsub-message-signature");
                var msg = WebhookConcat(Encoding.UTF8.GetBytes(id), Encoding.UTF8.GetBytes(ts), body);
                if (!WebhookAnyMatch(secrets, msg, new() { raw })) throw Unauthorized("bad signature");
                WebhookCheckWindow(now, WebhookParseRfc3339(ts), src.ToleranceSecs);
                switch (WebhookHeader(req, "twitch-eventsub-message-type"))
                {
                    case "webhook_callback_verification":
                        return new WebhookVerifiedReply("challenge", new HttpResponse(200, HttpVersion.Http11,
                            new List<HttpHeader> { new("content-type", "text/plain") },
                            HttpBody.FromString(WebhookBodyField(body, "challenge"))));
                    case "revocation":
                        return new WebhookVerifiedEvent(id, "revocation");
                    default:
                        return new WebhookVerifiedEvent(id, WebhookHeader(req, "twitch-eventsub-subscription-type") ?? "");
                }
            }
            case "stripe":
            {
                var header = WebhookNeed(req, "stripe-signature");
                long? t = null;
                var v1 = new List<byte[]>();
                foreach (var part in header.Split(','))
                {
                    var kv = part.Trim().Split('=', 2);
                    if (kv.Length != 2) continue;
                    if (kv[0] == "t" && long.TryParse(kv[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)) t = parsed;
                    if (kv[0] == "v1" && WebhookUnhex(kv[1]) is { } b) v1.Add(b);
                }
                if (t is null) throw Unauthorized("malformed stripe-signature");
                WebhookCheckWindow(now, t.Value, src.ToleranceSecs);
                var msg = WebhookConcat(Encoding.UTF8.GetBytes($"{t}."), body);
                if (!WebhookAnyMatch(secrets, msg, v1)) throw Unauthorized("bad signature");
                return new WebhookVerifiedEvent(WebhookBodyField(body, "id"), WebhookBodyField(body, "type"));
            }
            case "hmac":
            {
                var sig = WebhookNeed(req, src.Header).Trim();
                if (src.Prefix.Length > 0 && sig.StartsWith(src.Prefix, StringComparison.Ordinal)) sig = sig[src.Prefix.Length..];
                var raw = src.Encoding == "base64" ? WebhookUnbase64(sig) : WebhookUnhex(sig);
                if (raw is null) throw Unauthorized("malformed signature");
                if (!WebhookAnyMatch(secrets, body, new() { raw })) throw Unauthorized("bad signature");
                var id = (src.IdHeader.Length > 0 ? WebhookHeader(req, src.IdHeader) : null) ?? WebhookHex(WebhookSha256.Hash(body));
                var type = (src.TypeHeader.Length > 0 ? WebhookHeader(req, src.TypeHeader) : null) ?? "";
                return new WebhookVerifiedEvent(id, type);
            }
            case "discord":
            {
                var sig = WebhookUnhex(WebhookNeed(req, "x-signature-ed25519"));
                var ts = WebhookNeed(req, "x-signature-timestamp");
                var key = WebhookUnhex(src.PublicKey);
                if (key is not { Length: 32 }) throw new WebhookReject(500, "bad discord public_key");
                if (sig is not { Length: 64 }) throw Unauthorized("malformed x-signature-ed25519");
                if (!WebhookEd25519.Verify(key, WebhookConcat(Encoding.UTF8.GetBytes(ts), body), sig)) throw Unauthorized("bad signature");
                if (!long.TryParse(ts.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var tsSecs)) throw Unauthorized("bad x-signature-timestamp");
                WebhookCheckWindow(now, tsSecs, src.ToleranceSecs);
                var type = WebhookBodyNumber(body, "type");
                if (type == 1) return new WebhookVerifiedReply("ping", WebhookJson(200, new JsonObject { ["type"] = 1 }));
                var name = type switch
                {
                    2 => "application_command",
                    3 => "message_component",
                    4 => "application_command_autocomplete",
                    5 => "modal_submit",
                    _ => "unknown",
                };
                return new WebhookVerifiedEvent(WebhookBodyField(body, "id"), name);
            }
        }
        throw new WebhookReject(500, $"unknown kind {src.Kind}");
    }

    /// <summary>What Discord gets when your handler returns no reply.</summary>
    static JsonObject WebhookDiscordDefault(string eventType) => eventType switch
    {
        "message_component" => new JsonObject { ["type"] = 6 },
        "application_command_autocomplete" => new JsonObject { ["type"] = 8, ["data"] = new JsonObject { ["choices"] = new JsonArray() } },
        _ => new JsonObject { ["type"] = 5 },
    };

    static HttpResponse WebhookJson(ushort status, JsonNode body) =>
        new(status, HttpVersion.Http11, new List<HttpHeader> { new("content-type", "application/json") },
            HttpBody.FromString(body.ToJsonString()));

    static HttpResponse WebhookError(ushort status, string message) => WebhookJson(status, new JsonObject { ["error"] = message });

    /// <summary>Dedupe, then the host's handler, in one transaction. Null = duplicate.</summary>
    static (bool Duplicate, string? Reply) WebhookApply(WebhookTx tx, WebhookEvent ev)
    {
        var key = $"{ev.Source}|{ev.Id}";
        if (tx.Db.WebhookSeen.Key.Find(key) is not null)
        {
            WebhookWriteLog(tx, "in", ev.Source, ev.EventType, ev.Id, "duplicate", 200, "already applied");
            return (true, null);
        }
        tx.Db.WebhookSeen.Insert(new WebhookSeen { Key = key, At = tx.Timestamp });
        var reply = OnWebhook(tx, ev);
        WebhookWriteLog(tx, "in", ev.Source, ev.EventType, ev.Id, "applied", 200, "");
        return (false, reply);
    }

    /// <summary>Every inbound route lands here; the last path segment names the source.</summary>
    [SpacetimeDB.HttpHandler]
    public static HttpResponse WebhooksInbox(HandlerContext ctx, HttpRequest req)
    {
        var path = req.Uri.Split('?')[0];
        var name = path[(path.LastIndexOf('/') + 1)..];
        WebhookSource? src;
        try { src = WebhookParseSources(ctx.WithTx(_ => WebhookEnv.WEBHOOK_SOURCES)).FirstOrDefault(s => s.Name == name); }
        catch (Exception e) { return WebhookError(500, e.Message); }
        if (src is null) return WebhookError(404, $"no webhook source `{name}` configured");

        var body = req.Body.ToBytes();
        WebhookVerified verified;
        try { verified = WebhookVerify(src, req, body, ctx.Timestamp); }
        catch (Exception e)
        {
            var status = e is WebhookReject r ? r.Status : (ushort)401;
            ctx.WithTx(tx => { WebhookWriteLog(new WebhookTx(tx.Db, tx.Timestamp), "in", src.Name, "", "", "rejected", status, e.Message); return 0; });
            return WebhookError(status, e.Message);
        }
        if (verified is WebhookVerifiedReply reply)
        {
            ctx.WithTx(tx => { WebhookWriteLog(new WebhookTx(tx.Db, tx.Timestamp), "in", src.Name, "", "", reply.Outcome, 200, ""); return 0; });
            return reply.Response;
        }
        var v = (WebhookVerifiedEvent)verified;
        var ev = new WebhookEvent(src.Name, src.Kind, v.Id.Length > 0 ? v.Id : WebhookHex(WebhookSha256.Hash(body)), v.EventType, Encoding.UTF8.GetString(body));
        try
        {
            var (duplicate, answer) = ctx.WithTx(tx => WebhookApply(new WebhookTx(tx.Db, tx.Timestamp), ev));
            if (duplicate) return WebhookJson(200, new JsonObject { ["ok"] = true, ["duplicate"] = true });
            if (answer is not null)
                return new HttpResponse(200, HttpVersion.Http11, new List<HttpHeader> { new("content-type", "application/json") }, HttpBody.FromString(answer));
            return src.Kind == "discord" ? WebhookJson(200, WebhookDiscordDefault(ev.EventType)) : WebhookJson(200, new JsonObject { ["ok"] = true });
        }
        catch (Exception e)
        {
            // The dedupe record rolled back with the handler, so the sender's retry is applied fresh.
            ctx.WithTx(tx => { WebhookWriteLog(new WebhookTx(tx.Db, tx.Timestamp), "in", ev.Source, ev.EventType, ev.Id, "error", 500, e.Message); return 0; });
            return WebhookError(500, e.Message);
        }
    }

    // -----------------------------------------------------------------------
    // Outbound
    // -----------------------------------------------------------------------

    /// <summary>
    /// Register (or replace) an endpoint. Generate the secret outside the module (whsec_ + base64 of
    /// 24-64 random bytes): ctx.Rng is seeded from the timestamp, so it's guessable.
    /// </summary>
    public static ulong WebhookAddEndpoint(WebhookTx tx, string name, string url, string secret, params string[] eventTypes)
    {
        name = name.Trim();
        if (name.Length == 0 || !(url.StartsWith("http://", StringComparison.Ordinal) || url.StartsWith("https://", StringComparison.Ordinal)))
            throw new Exception("endpoint needs a name and an http(s) URL");
        if (secret.Length < 16) throw new Exception("endpoint secret is too short");
        var row = new WebhookEndpoint
        {
            Name = name, Url = url, Secret = secret, EventTypes = eventTypes.ToList(), Enabled = true,
            DisabledReason = "", Created = tx.Timestamp,
        };
        if (tx.Db.WebhookEndpoint.Name.Find(name) is { } old)
        {
            tx.Db.WebhookEndpoint.Id.Update(row with { Id = old.Id, Created = old.Created });
            return old.Id;
        }
        return tx.Db.WebhookEndpoint.Insert(row).Id;
    }

    /// <summary>Remove an endpoint and drop its queued messages.</summary>
    public static void WebhookRemoveEndpoint(WebhookTx tx, string name)
    {
        if (tx.Db.WebhookEndpoint.Name.Find(name) is not { } ep) return;
        foreach (var row in tx.Db.WebhookOutbox.EndpointId.Filter(ep.Id).ToList()) tx.Db.WebhookOutbox.Id.Delete(row.Id);
        tx.Db.WebhookEndpoint.Id.Delete(ep.Id);
    }

    public static void WebhookSetEndpointEnabled(WebhookTx tx, string name, bool enabled)
    {
        var ep = tx.Db.WebhookEndpoint.Name.Find(name) ?? throw new Exception("no such endpoint");
        tx.Db.WebhookEndpoint.Id.Update(ep with { Enabled = enabled, DisabledReason = enabled ? "" : "disabled by the module" });
    }

    static bool WebhookWants(WebhookEndpoint ep, string eventType) =>
        ep.EventTypes.Count == 0 || ep.EventTypes.Any(p =>
            p == "*" || p == eventType || (p.EndsWith('*') && eventType.StartsWith(p[..^1], StringComparison.Ordinal)));

    /// <summary>Queue data for every enabled endpoint that wants eventType. Returns the message ids.</summary>
    public static List<string> WebhookSend(WebhookTx tx, string eventType, JsonNode? data) =>
        tx.Db.WebhookEndpoint.Iter().Where(e => e.Enabled && WebhookWants(e, eventType)).ToList()
            .Select(ep => WebhookEnqueue(tx, ep, eventType, data)).ToList();

    public static List<string> WebhookSend(ReducerContext ctx, string eventType, JsonNode? data) =>
        WebhookSend(new WebhookTx(ctx.Db, ctx.Timestamp), eventType, data);

    /// <summary>Queue data for one endpoint (ignores its event-type filter).</summary>
    public static string WebhookSendTo(WebhookTx tx, string endpoint, string eventType, JsonNode? data)
    {
        var ep = tx.Db.WebhookEndpoint.Name.Find(endpoint) ?? throw new Exception("no such endpoint");
        if (!ep.Enabled) throw new Exception($"endpoint `{endpoint}` is disabled");
        return WebhookEnqueue(tx, ep, eventType, data);
    }

    static string WebhookRfc3339(Timestamp t) =>
        DateTime.UnixEpoch.AddTicks(t.MicrosecondsSinceUnixEpoch * 10).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);

    static string WebhookEnqueue(WebhookTx tx, WebhookEndpoint ep, string eventType, JsonNode? data)
    {
        WebhooksInit(tx);
        var body = new JsonObject
        {
            ["type"] = eventType,
            ["timestamp"] = WebhookRfc3339(tx.Timestamp),
            ["data"] = data?.DeepClone(),
        }.ToJsonString();
        var row = tx.Db.WebhookOutbox.Insert(new WebhookOutbox
        {
            EndpointId = ep.Id, MsgId = "", EventType = eventType, Body = body, Created = tx.Timestamp,
            Attempts = 0, NextAttempt = tx.Timestamp, InFlightUntil = null, Dead = false, LastError = "",
        });
        var msgId = $"msg_{tx.Db.WebhookState.Key.Find(0)?.Epoch ?? ""}_{row.Id}";
        tx.Db.WebhookOutbox.Id.Update(row with { MsgId = msgId });
        WebhookWriteLog(tx, "out", ep.Name, eventType, msgId, "queued", 0, "");
        WebhookScheduleFlush(tx, tx.Timestamp);
        WebhookScheduleBackstop(tx);
        return msgId;
    }

    /// <summary>Put an endpoint's dead messages back in the queue. Returns how many.</summary>
    public static int WebhookRedeliverDead(WebhookTx tx, string endpoint)
    {
        var ep = tx.Db.WebhookEndpoint.Name.Find(endpoint) ?? throw new Exception("no such endpoint");
        var dead = tx.Db.WebhookOutbox.EndpointId.Filter(ep.Id).Where(r => r.Dead).ToList();
        foreach (var row in dead)
            tx.Db.WebhookOutbox.Id.Update(row with { Dead = false, Attempts = 0, NextAttempt = tx.Timestamp, InFlightUntil = null });
        WebhookScheduleFlush(tx, tx.Timestamp);
        WebhookScheduleBackstop(tx);
        return dead.Count;
    }

    static void WebhookScheduleFlush(WebhookTx tx, Timestamp at)
    {
        foreach (var j in tx.Db.WebhookFlushJob.Iter())
            if (j.ScheduledAt is ScheduleAt.Time(var t) && t.MicrosecondsSinceUnixEpoch <= at.MicrosecondsSinceUnixEpoch) return;
        tx.Db.WebhookFlushJob.Insert(new WebhookFlushJob { ScheduledAt = new ScheduleAt.Time(at) });
    }

    /// <summary>When the outbox next needs a flush, if it has anything queued.</summary>
    static long? WebhookNextDue(WebhookTx tx)
    {
        long? next = null;
        foreach (var r in tx.Db.WebhookOutbox.Dead.Filter(false))
        {
            var at = r.NextAttempt.MicrosecondsSinceUnixEpoch;
            if (r.InFlightUntil is { } t && t.MicrosecondsSinceUnixEpoch > at) at = t.MicrosecondsSinceUnixEpoch;
            if (next is null || at < next) next = at;
        }
        return next;
    }

    /// <summary>
    /// Keep a later flush on the books while anything is queued. A flush job is deleted before the
    /// flush runs, so a crash part-way through would leave leased messages with nothing to pick them
    /// up. This runs in the same transaction as the lease, so one can't be lost without the other.
    /// It waits for the next due message rather than the lease alone, so a message in a long backoff
    /// costs one job, not a flush every minute.
    /// </summary>
    static void WebhookScheduleBackstop(WebhookTx tx)
    {
        if (WebhookNextDue(tx) is not { } next) return;
        var now = tx.Timestamp.MicrosecondsSinceUnixEpoch;
        var at = Math.Max(next, now + WebhookLeaseUs);
        foreach (var j in tx.Db.WebhookFlushJob.Iter())
            if (j.ScheduledAt is ScheduleAt.Time(var t) && t.MicrosecondsSinceUnixEpoch >= now + WebhookLeaseUs / 2 && t.MicrosecondsSinceUnixEpoch <= at) return;
        tx.Db.WebhookFlushJob.Insert(new WebhookFlushJob { ScheduledAt = new ScheduleAt.Time(new Timestamp(at)) });
    }

    readonly record struct WebhookClaim(WebhookOutbox Row, WebhookEndpoint Endpoint);

    static WebhookClaim? WebhookClaimNext(WebhookTx tx)
    {
        WebhookScheduleBackstop(tx);
        var now = tx.Timestamp.MicrosecondsSinceUnixEpoch;
        var due = tx.Db.WebhookOutbox.Dead.Filter(false)
            .Where(r => r.NextAttempt.MicrosecondsSinceUnixEpoch <= now
                && !(r.InFlightUntil is { } f && f.MicrosecondsSinceUnixEpoch > now))
            .OrderBy(r => r.Id).ToList();
        foreach (var row in due)
        {
            var ep = tx.Db.WebhookEndpoint.Id.Find(row.EndpointId);
            if (ep is { Enabled: true } e)
            {
                tx.Db.WebhookOutbox.Id.Update(row with { InFlightUntil = new Timestamp(now + WebhookLeaseUs) });
                return new WebhookClaim(row, e);
            }
            WebhookKill(tx, row, "?", ep is null ? "endpoint removed" : $"endpoint disabled: {ep.Value.DisabledReason}");
        }
        return null;
    }

    static void WebhookKill(WebhookTx tx, WebhookOutbox row, string endpoint, string why)
    {
        WebhookWriteLog(tx, "out", endpoint, row.EventType, row.MsgId, "dead", 0, why);
        tx.Db.WebhookOutbox.Id.Update(row with { Dead = true, InFlightUntil = null, LastError = why });
    }

    /// <summary>Standard Webhooks: v1,&lt;base64 HMAC-SHA256(key, "&lt;id&gt;.&lt;ts&gt;.&lt;body&gt;")&gt;.</summary>
    public static string WebhookSignStandard(string secret, string msgId, long tsSecs, byte[] body) =>
        "v1," + Convert.ToBase64String(WebhookSha256.Hmac(WebhookStandardKey(secret), WebhookConcat(Encoding.UTF8.GetBytes($"{msgId}.{tsSecs}."), body)));

    /// <summary>Scheduled procedure: deliver everything that's due, then reschedule for the next retry.</summary>
    [SpacetimeDB.Procedure]
    public static void WebhookFlush(ProcedureContext ctx, WebhookFlushJob job)
    {
        for (var i = 0; i < 500; i++)
        {
            var claim = ctx.WithTx(tx => WebhookClaimNext(new WebhookTx(tx.Db, tx.Timestamp)));
            if (claim is not { } c) break;
            var now = ctx.WithTx(tx => tx.Timestamp);
            var tsSecs = now.MicrosecondsSinceUnixEpoch / 1_000_000;
            var body = Encoding.UTF8.GetBytes(c.Row.Body);
            var request = new HttpRequest
            {
                Uri = c.Endpoint.Url,
                Method = HttpMethod.Post,
                Timeout = WebhookHttpTimeout,
                Headers = new()
                {
                    new("content-type", "application/json"),
                    new("user-agent", "spacetimedb-webhooks/0.1"),
                    new("webhook-id", c.Row.MsgId),
                    new("webhook-timestamp", tsSecs.ToString(CultureInfo.InvariantCulture)),
                    new("webhook-signature", WebhookSignStandard(c.Endpoint.Secret, c.Row.MsgId, tsSecs, body)),
                },
                Body = new HttpBody(body),
            };
            ushort status = 0;
            string? error = null;
            ctx.Http.Send(request).Match(
                response =>
                {
                    status = response.StatusCode;
                    if (status is < 200 or >= 300)
                    {
                        var text = response.Body.ToStringUtf8Lossy();
                        error = $"{status} {(text.Length > 200 ? text[..200] : text)}";
                    }
                    return 0;
                },
                err =>
                {
                    error = $"transport error: {err.Message}";
                    return 0;
                });
            ctx.WithTx(tx => { WebhookFinish(new WebhookTx(tx.Db, tx.Timestamp), c, status, error, now); return 0; });
        }
        ctx.WithTx(tx =>
        {
            var wtx = new WebhookTx(tx.Db, tx.Timestamp);
            if (WebhookNextDue(wtx) is { } n)
                WebhookScheduleFlush(wtx, new Timestamp(Math.Max(n, tx.Timestamp.MicrosecondsSinceUnixEpoch)));
            return 0;
        });
    }

    static void WebhookFinish(WebhookTx tx, WebhookClaim c, ushort status, string? error, Timestamp sentAt)
    {
        if (tx.Db.WebhookOutbox.Id.Find(c.Row.Id) is not { } row) return;
        var name = c.Endpoint.Name;
        var attempt = row.Attempts + 1;
        var latency = tx.Timestamp.MicrosecondsSinceUnixEpoch - sentAt.MicrosecondsSinceUnixEpoch;
        if (error is null)
        {
            WebhookWriteLog(tx, "out", name, row.EventType, row.MsgId, "delivered", status, $"attempt {attempt}", latency);
            tx.Db.WebhookOutbox.Id.Delete(row.Id);
        }
        else if (status == 410)
        {
            // 410 Gone: the receiver asked us to stop. Disable the endpoint and drop its queue.
            if (tx.Db.WebhookEndpoint.Id.Find(row.EndpointId) is { } ep)
                tx.Db.WebhookEndpoint.Id.Update(ep with { Enabled = false, DisabledReason = "receiver answered 410 Gone" });
            WebhookWriteLog(tx, "out", name, row.EventType, row.MsgId, "disabled", 410, error, latency);
            foreach (var other in tx.Db.WebhookOutbox.EndpointId.Filter(row.EndpointId).Where(r => !r.Dead).ToList())
                WebhookKill(tx, other, name, "endpoint disabled: receiver answered 410 Gone");
        }
        else
        {
            var schedule = WebhookRetrySchedule(WebhookEnv.WEBHOOK_RETRY_SECS);
            if (attempt > schedule.Length)
            {
                WebhookWriteLog(tx, "out", name, row.EventType, row.MsgId, "dead", status, $"gave up after {attempt} attempts: {error}", latency);
                tx.Db.WebhookOutbox.Id.Update(row with { Attempts = attempt, Dead = true, InFlightUntil = null, LastError = error });
            }
            else
            {
                var delay = schedule[attempt - 1];
                WebhookWriteLog(tx, "out", name, row.EventType, row.MsgId, "retry", status,
                    $"attempt {attempt} failed, retrying in {delay.ToString(CultureInfo.InvariantCulture)}s: {error}", latency);
                tx.Db.WebhookOutbox.Id.Update(row with
                {
                    Attempts = attempt,
                    NextAttempt = new Timestamp(tx.Timestamp.MicrosecondsSinceUnixEpoch + (long)(delay * 1e6)),
                    InFlightUntil = null,
                    LastError = error,
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Housekeeping and dashboards
    // -----------------------------------------------------------------------

    [SpacetimeDB.Reducer]
    public static void WebhookPrune(ReducerContext ctx, WebhookPruneJob job)
    {
        var cutoff = new Timestamp(ctx.Timestamp.MicrosecondsSinceUnixEpoch - WebhookSeenRetentionUs);
        foreach (var s in ctx.Db.WebhookSeen.Iter().Where(s => s.At.MicrosecondsSinceUnixEpoch < cutoff.MicrosecondsSinceUnixEpoch).ToList())
            ctx.Db.WebhookSeen.Key.Delete(s.Key);
    }

    static void WebhookWriteLog(WebhookTx tx, string direction, string peer, string eventType, string msgId, string outcome, ushort status, string detail, long latencyUs = 0)
    {
        tx.Db.WebhookLog.Insert(new WebhookLog
        {
            At = tx.Timestamp, Direction = direction, Peer = peer, EventType = eventType, MsgId = msgId,
            Outcome = outcome, Status = status, Detail = detail.Length > 300 ? detail[..300] : detail, LatencyUs = latencyUs,
        });
        // Ids can skip (rolled-back inserts use them up), so prune by count, 100 rows at a time.
        if (tx.Db.WebhookLog.Count > WebhookLogKeep + 100)
        {
            var ids = tx.Db.WebhookLog.Iter().Select(l => l.Id).OrderBy(id => id).ToList();
            foreach (var id in ids.Take(ids.Count - (int)WebhookLogKeep)) tx.Db.WebhookLog.Id.Delete(id);
        }
    }

    /// <summary>Endpoints (without secrets), queue counts and the recent log, for a dashboard.</summary>
    public static JsonObject WebhookStateJson(WebhookTx tx)
    {
        var endpoints = new JsonArray();
        foreach (var e in tx.Db.WebhookEndpoint.Iter())
        {
            var rows = tx.Db.WebhookOutbox.EndpointId.Filter(e.Id).ToList();
            endpoints.Add((JsonNode)new JsonObject
            {
                ["name"] = e.Name, ["url"] = e.Url,
                ["event_types"] = new JsonArray(e.EventTypes.Select(t => (JsonNode?)JsonValue.Create(t)).ToArray()),
                ["enabled"] = e.Enabled, ["disabled_reason"] = e.DisabledReason,
                ["pending"] = rows.Count(r => !r.Dead), ["dead"] = rows.Count(r => r.Dead),
            });
        }
        var log = new JsonArray();
        foreach (var l in tx.Db.WebhookLog.Iter().OrderByDescending(l => l.Id).Take(150))
        {
            log.Add((JsonNode)new JsonObject
            {
                ["id"] = l.Id, ["at"] = l.At.MicrosecondsSinceUnixEpoch, ["direction"] = l.Direction, ["peer"] = l.Peer,
                ["event_type"] = l.EventType, ["msg_id"] = l.MsgId, ["outcome"] = l.Outcome, ["status"] = l.Status,
                ["detail"] = l.Detail, ["latency_us"] = l.LatencyUs,
            });
        }
        return new JsonObject { ["endpoints"] = endpoints, ["log"] = log };
    }
}

/// <summary>Small managed SHA-256 / HMAC-SHA256 (System.Security.Cryptography isn't available on wasi).</summary>
static class WebhookSha256
{
    static readonly uint[] K =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    static uint Rotr(uint x, int n) => (x >> n) | (x << (32 - n));

    public static byte[] Hash(byte[] data)
    {
        uint[] h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
        var bitLen = (ulong)data.LongLength * 8;
        var padded = new byte[((data.Length + 9 + 63) / 64) * 64];
        data.CopyTo(padded, 0);
        padded[data.Length] = 0x80;
        for (var i = 0; i < 8; i++) padded[padded.Length - 1 - i] = (byte)(bitLen >> (8 * i));
        var w = new uint[64];
        for (var chunk = 0; chunk < padded.Length; chunk += 64)
        {
            for (var i = 0; i < 16; i++)
                w[i] = (uint)(padded[chunk + 4 * i] << 24 | padded[chunk + 4 * i + 1] << 16 | padded[chunk + 4 * i + 2] << 8 | padded[chunk + 4 * i + 3]);
            for (var i = 16; i < 64; i++)
            {
                var s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                var s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (var i = 0; i < 64; i++)
            {
                var t1 = hh + (Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
                var t2 = (Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
                hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        }
        var result = new byte[32];
        for (var i = 0; i < 8; i++)
        {
            result[4 * i] = (byte)(h[i] >> 24); result[4 * i + 1] = (byte)(h[i] >> 16);
            result[4 * i + 2] = (byte)(h[i] >> 8); result[4 * i + 3] = (byte)h[i];
        }
        return result;
    }

    public static byte[] Hmac(byte[] key, byte[] message)
    {
        if (key.Length > 64) key = Hash(key);
        var k = new byte[64];
        key.CopyTo(k, 0);
        var inner = new byte[64 + message.Length];
        var outer = new byte[64 + 32];
        for (var i = 0; i < 64; i++) { inner[i] = (byte)(k[i] ^ 0x36); outer[i] = (byte)(k[i] ^ 0x5c); }
        message.CopyTo(inner, 64);
        Hash(inner).CopyTo(outer, 64);
        return Hash(outer);
    }
}

/// <summary>Small managed SHA-512 (for Ed25519).</summary>
static class WebhookSha512
{
    static readonly ulong[] K =
    {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
        0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
        0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    };

    static ulong Rotr(ulong x, int n) => (x >> n) | (x << (64 - n));

    public static byte[] Hash(byte[] data)
    {
        ulong[] h =
        {
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
        };
        var bitLen = (ulong)data.LongLength * 8;
        var padded = new byte[((data.Length + 17 + 127) / 128) * 128];
        data.CopyTo(padded, 0);
        padded[data.Length] = 0x80;
        for (var i = 0; i < 8; i++) padded[padded.Length - 1 - i] = (byte)(bitLen >> (8 * i));
        var w = new ulong[80];
        for (var chunk = 0; chunk < padded.Length; chunk += 128)
        {
            for (var i = 0; i < 16; i++)
            {
                ulong v = 0;
                for (var j = 0; j < 8; j++) v = (v << 8) | padded[chunk + 8 * i + j];
                w[i] = v;
            }
            for (var i = 16; i < 80; i++)
            {
                var s0 = Rotr(w[i - 15], 1) ^ Rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
                var s1 = Rotr(w[i - 2], 19) ^ Rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            ulong a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (var i = 0; i < 80; i++)
            {
                var t1 = hh + (Rotr(e, 14) ^ Rotr(e, 18) ^ Rotr(e, 41)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
                var t2 = (Rotr(a, 28) ^ Rotr(a, 34) ^ Rotr(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
                hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        }
        var result = new byte[64];
        for (var i = 0; i < 8; i++)
            for (var j = 0; j < 8; j++) result[8 * i + j] = (byte)(h[i] >> (56 - 8 * j));
        return result;
    }
}

/// <summary>
/// Ed25519 signature verification (RFC 8032), for Discord interactions. Straightforward
/// BigInteger arithmetic: not constant time, which is fine for verifying public signatures.
/// </summary>
static class WebhookEd25519
{
    static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);
    static readonly BigInteger D = Mod(-121665 * Inv(121666));
    static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);
    static readonly Pt G = MakeBase();

    readonly record struct Pt(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T);

    static BigInteger Mod(BigInteger a)
    {
        var r = a % P;
        return r.Sign < 0 ? r + P : r;
    }

    static BigInteger Inv(BigInteger x) => BigInteger.ModPow(Mod(x), P - 2, P);

    static Pt MakeBase()
    {
        var y = Mod(4 * Inv(5));
        var x = RecoverX(y, false)!.Value;
        return new Pt(x, y, 1, Mod(x * y));
    }

    static Pt Add(Pt p, Pt q)
    {
        var a = Mod((p.Y - p.X) * (q.Y - q.X));
        var b = Mod((p.Y + p.X) * (q.Y + q.X));
        var c = Mod(2 * p.T * q.T * D);
        var d = Mod(2 * p.Z * q.Z);
        var e = b - a;
        var f = d - c;
        var g = d + c;
        var h = b + a;
        return new Pt(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    static Pt Mul(BigInteger s, Pt p)
    {
        var q = new Pt(0, 1, 1, 0);
        while (s.Sign > 0)
        {
            if (!s.IsEven) q = Add(q, p);
            p = Add(p, p);
            s >>= 1;
        }
        return q;
    }

    static bool Equal(Pt p, Pt q) => Mod(p.X * q.Z - q.X * p.Z).IsZero && Mod(p.Y * q.Z - q.Y * p.Z).IsZero;

    static BigInteger? RecoverX(BigInteger y, bool sign)
    {
        if (y >= P) return null;
        var x2 = Mod((y * y - 1) * Inv(D * y * y + 1));
        if (x2.IsZero) return sign ? null : BigInteger.Zero;
        var x = BigInteger.ModPow(x2, (P + 3) / 8, P);
        if (!Mod(x * x - x2).IsZero) x = Mod(x * SqrtM1);
        if (!Mod(x * x - x2).IsZero) return null;
        if (!x.IsEven != sign) x = P - x;
        return x;
    }

    static Pt? Decompress(ReadOnlySpan<byte> s)
    {
        var bytes = s.ToArray();
        var sign = (bytes[31] >> 7) == 1;
        bytes[31] &= 0x7f;
        var y = new BigInteger(bytes, isUnsigned: true, isBigEndian: false);
        var x = RecoverX(y, sign);
        return x is { } xv ? new Pt(xv, y, 1, Mod(xv * y)) : null;
    }

    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;
        if (Decompress(publicKey) is not { } a) return false;
        if (Decompress(signature.AsSpan(0, 32)) is not { } r) return false;
        var s = new BigInteger(signature.AsSpan(32, 32), isUnsigned: true, isBigEndian: false);
        if (s >= L) return false;
        var input = new byte[64 + message.Length];
        Array.Copy(signature, 0, input, 0, 32);
        publicKey.CopyTo(input, 32);
        message.CopyTo(input, 64);
        var digest = WebhookSha512.Hash(input);
        var h = new BigInteger(digest, isUnsigned: true, isBigEndian: false) % L;
        return Equal(Mul(s, G), Add(r, Mul(h, a)));
    }
}
