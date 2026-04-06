using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallApp
{
    public class WebServer
    {
        // ─── Web session (independent of desktop AppSession) ─────────────────
        private sealed class WebSession
        {
            public string Username { get; set; } = "";
            public string Role     { get; set; } = "Viewer";
            public bool   IsAdmin  => Role.Equals("Admin", StringComparison.OrdinalIgnoreCase);
            public DateTime ExpiresAt { get; set; }
        }

        // token → session  (thread-safe, in-memory)
        private readonly ConcurrentDictionary<string, WebSession> _sessions = new();

        // ─── Services ────────────────────────────────────────────────────────
        private readonly FirewallManager  _fw;
        private readonly TimedRuleService _timed;
        private readonly AppConfig        _cfg;
        private readonly Func<string>     _getLocalIp;
        private readonly int              _port;

        private HttpListener?             _listener;
        private CancellationTokenSource?  _cts;
        private Task?                     _loop;

        private static readonly JsonSerializerOptions JsonOut = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true
        };
        private static readonly JsonSerializerOptions JsonIn = new()
        {
            PropertyNameCaseInsensitive = true
        };

        // ════════════════════════════════════════════════════════════════════
        public WebServer(
            FirewallManager fw,
            TimedRuleService timed,
            AppConfig cfg,
            int port = 2309,
            Func<string>? getLocalIp = null)
        {
            _fw         = fw;
            _timed      = timed;
            _cfg        = cfg;
            _port       = port;
            _getLocalIp = getLocalIp ?? (() => "127.0.0.1");
        }

        // ─── Start / Stop ────────────────────────────────────────────────────
        public void Start()
        {
            if (_listener != null && _listener.IsListening) return;

            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://+:{_port}/");
            _listener.Start();

            _cts  = new CancellationTokenSource();
            _loop = Task.Run(() => AcceptLoop(_cts.Token));

            // Expire old tokens every 15 minutes
            Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromMinutes(15));
                    foreach (var kv in _sessions)
                        if (kv.Value.ExpiresAt < DateTime.UtcNow)
                            _sessions.TryRemove(kv.Key, out _);
                }
            });

            try
            {
                string lanIp = _getLocalIp();
                Logger.Log($"[WEB] started: http://localhost:{_port}/  |  LAN: http://{lanIp}:{_port}/");
            }
            catch { }
        }

        public void Stop()
        {
            try
            {
                _cts?.Cancel();
                if (_listener != null)
                {
                    if (_listener.IsListening) _listener.Stop();
                    _listener.Close();
                }
            }
            catch { }
        }

        // ─── Accept loop ─────────────────────────────────────────────────────
        private async Task AcceptLoop(CancellationToken token)
        {
            if (_listener == null) return;
            while (!token.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync(); }
                catch { break; }
                _ = Task.Run(() => Handle(ctx));
            }
        }

        // ─── Token helpers ───────────────────────────────────────────────────
        private string CreateToken(AppUser user)
        {
            var token = Guid.NewGuid().ToString("N"); // 32-char hex, no dashes
            _sessions[token] = new WebSession
            {
                Username  = user.Username,
                Role      = user.Role,
                ExpiresAt = DateTime.UtcNow.AddHours(8)
            };
            return token;
        }

        /// <summary>Extract Bearer token from Authorization header.</summary>
        private static string? ExtractToken(HttpListenerContext ctx)
        {
            var auth = ctx.Request.Headers["Authorization"];
            if (!string.IsNullOrWhiteSpace(auth) && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return auth.Substring(7).Trim();
            return null;
        }

        /// <summary>Validate token → WebSession. Returns null and sends 401 if invalid.</summary>
        private async Task<WebSession?> RequireAuth(HttpListenerContext ctx)
        {
            var token = ExtractToken(ctx);
            if (token != null && _sessions.TryGetValue(token, out var session))
            {
                if (session.ExpiresAt > DateTime.UtcNow)
                {
                    session.ExpiresAt = DateTime.UtcNow.AddHours(8); // sliding expiry
                    return session;
                }
                _sessions.TryRemove(token, out _); // expired
            }

            await Json(ctx, new { ok = false, error = "Unauthorized. Please log in." }, 401);
            return null;
        }

        /// <summary>Require Admin role. Returns null and sends 403 if not admin.</summary>
        private async Task<WebSession?> RequireAdmin(HttpListenerContext ctx)
        {
            var session = await RequireAuth(ctx);
            if (session == null) return null;

            if (!session.IsAdmin)
            {
                await Json(ctx, new { ok = false, error = "Forbidden. Admin role required." }, 403);
                return null;
            }
            return session;
        }

        // ════════════════════════════════════════════════════════════════════
        //  MAIN HANDLER
        // ════════════════════════════════════════════════════════════════════
        private async Task Handle(HttpListenerContext ctx)
        {
            AddCors(ctx);

            if (ctx.Request.HttpMethod == "OPTIONS")
            {
                ctx.Response.StatusCode = 204;
                ctx.Response.Close();
                return;
            }

            var rawPath = ctx.Request.Url?.AbsolutePath ?? "/";
            var path    = rawPath.TrimEnd('/');
            if (path == "") path = "/";

            try
            {
                // ── Static files (no auth) ───────────────────────────────────
                if (!path.StartsWith("/api", StringComparison.OrdinalIgnoreCase))
                {
                    if (await TryServeStatic(ctx, path)) return;
                }

                // ════════════════════════════════════════════════════════════
                //  PUBLIC ENDPOINTS  (no token needed)
                // ════════════════════════════════════════════════════════════

                // POST /api/login  — validate credentials, return token
                if (ctx.Request.HttpMethod == "POST" && path == "/api/login")
                {
                    var body    = await ReadBody(ctx);
                    var req     = JsonSerializer.Deserialize<LoginRequest>(body, JsonIn) ?? new LoginRequest();
                    var entered = (req.Username ?? "").Trim();
                    var pass    = req.Password ?? "";

                    AppUser? matched = null;
                    if (_cfg.Users != null)
                    {
                        foreach (var u in _cfg.Users)
                        {
                            if (string.Equals(entered, u.Username ?? "", StringComparison.OrdinalIgnoreCase) &&
                                string.Equals(pass, u.Password ?? "", StringComparison.Ordinal))
                            {
                                matched = u;
                                break;
                            }
                        }
                    }

                    if (matched == null)
                    {
                        Logger.Log($"[WEB] Failed login attempt for '{entered}'");
                        await Json(ctx, new { ok = false, error = "Invalid username or password." }, 401);
                        return;
                    }

                    var token = CreateToken(matched);
                    Logger.Log($"[WEB] Login: {matched.Username} ({matched.Role})");

                    await Json(ctx, new
                    {
                        ok       = true,
                        token,
                        username = matched.Username,
                        role     = matched.Role,
                        isAdmin  = matched.Role.Equals("Admin", StringComparison.OrdinalIgnoreCase)
                    });
                    return;
                }

                // POST /api/logout  — invalidate token
                if (ctx.Request.HttpMethod == "POST" && path == "/api/logout")
                {
                    var token = ExtractToken(ctx);
                    if (token != null) _sessions.TryRemove(token, out _);
                    await Json(ctx, new { ok = true });
                    return;
                }

                // ════════════════════════════════════════════════════════════
                //  PROTECTED ENDPOINTS  (token required)
                // ════════════════════════════════════════════════════════════

                // GET /api/me
                if (ctx.Request.HttpMethod == "GET" && path == "/api/me")
                {
                    var s = await RequireAuth(ctx);
                    if (s == null) return;
                    await Json(ctx, new { ok = true, username = s.Username, role = s.Role, isAdmin = s.IsAdmin });
                    return;
                }

                // GET /api/rules
                if (ctx.Request.HttpMethod == "GET" && path == "/api/rules")
                {
                    if (await RequireAuth(ctx) == null) return;

                    var rules = _fw.GetAppRules();
                    string timedFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "timed_rules.json");
                    var expMap = LoadExpirationsMap(timedFile);

                    var list = new List<object>();
                    foreach (var r in rules)
                    {
                        DateTime? exp = null;
                        if (!string.IsNullOrWhiteSpace(r.Name) && expMap.TryGetValue(r.Name, out var dt))
                            exp = dt;

                        list.Add(new
                        {
                            name          = r.Name,
                            remoteIp      = r.RemoteIp,
                            port          = r.Port,
                            protocol      = r.Protocol,
                            action        = r.Action,
                            createdAt     = r.CreatedAt,
                            expiresAt     = exp,
                            expiresText   = ToExpiresText(exp),
                            sourceIp      = _getLocalIp(),
                            destinationIp = string.IsNullOrWhiteSpace(r.RemoteIp) ? "Any" : r.RemoteIp
                        });
                    }

                    await Json(ctx, list);
                    return;
                }

                // POST /api/rules  — add rule (Admin only)
                if (ctx.Request.HttpMethod == "POST" && (path == "/api/rules" || path == "/api/rules/add"))
                {
                    var s = await RequireAdmin(ctx);
                    if (s == null) return;

                    var body = await ReadBody(ctx);
                    var req  = JsonSerializer.Deserialize<AddRuleRequest>(body, JsonIn) ?? new AddRuleRequest();

                    if (string.IsNullOrWhiteSpace(req.RemoteIp))
                    {
                        await Json(ctx, new { ok = false, error = "remoteIp is required" }, 400);
                        return;
                    }

                    var ruleName = $"FW-Web-{Guid.NewGuid()}";
                    var now      = DateTime.Now;
                    var proto    = string.IsNullOrWhiteSpace(req.Protocol) ? "Any" : req.Protocol!;
                    var act      = string.IsNullOrWhiteSpace(req.Action)   ? "Block" : req.Action!;

                    if (string.Equals(act, "Allow", StringComparison.OrdinalIgnoreCase))
                        _fw.AddAllowRule(ruleName, req.RemoteIp.Trim(), req.Port, proto);
                    else
                        _fw.AddBlockRule(ruleName, req.RemoteIp.Trim(), req.Port, proto);

                    DateTime? exp = null;
                    if (!req.Permanent && req.Minutes > 0)
                    {
                        exp = now.AddMinutes(req.Minutes);
                        var model = new FirewallRuleModel
                        {
                            Name = ruleName, RemoteIp = req.RemoteIp.Trim(), Port = req.Port,
                            Protocol = proto, Action = act, CreatedAt = now,
                            SourceIp = _getLocalIp(), DestinationIp = req.RemoteIp.Trim(), ExpiresAt = exp
                        };
                        _timed.AddTimedRule(model, req.Minutes);
                    }

                    Logger.Log($"[WEB] Rule added: {ruleName} by {s.Username} ({s.Role})");

                    await Json(ctx, new
                    {
                        ok = true,
                        rule = new
                        {
                            name = ruleName, remoteIp = req.RemoteIp.Trim(), port = req.Port,
                            protocol = proto, action = act, createdAt = now,
                            expiresAt = exp, expiresText = ToExpiresText(exp),
                            sourceIp = _getLocalIp(), destinationIp = req.RemoteIp.Trim()
                        }
                    });
                    return;
                }

                // DELETE /api/rules?name=... or /api/rules/{name}  (Admin only)
                if (ctx.Request.HttpMethod == "DELETE" &&
                    (path == "/api/rules" || path.StartsWith("/api/rules/", StringComparison.OrdinalIgnoreCase)))
                {
                    var s = await RequireAdmin(ctx);
                    if (s == null) return;

                    string? name = path == "/api/rules"
                        ? ctx.Request.QueryString["name"]
                        : Uri.UnescapeDataString(path.Substring("/api/rules/".Length));

                    if (string.IsNullOrWhiteSpace(name))
                    {
                        await Json(ctx, new { ok = false, error = "name is required" }, 400);
                        return;
                    }

                    _fw.RemoveRule(name);
                    Logger.Log($"[WEB] Rule removed: {name} by {s.Username} ({s.Role})");
                    await Json(ctx, new { ok = true });
                    return;
                }

                // POST /api/rules/blockall  (Admin only)
                if (ctx.Request.HttpMethod == "POST" && path == "/api/rules/blockall")
                {
                    var s = await RequireAdmin(ctx);
                    if (s == null) return;

                    var ruleName = $"FW-BlockAll-{Guid.NewGuid()}";
                    _fw.AddBlockAllRule(ruleName);
                    Logger.Log($"[WEB] Block ALL added: {ruleName} by {s.Username} ({s.Role})");
                    await Json(ctx, new { ok = true, name = ruleName });
                    return;
                }

                // POST /api/firewall/windows/on  (Admin only)
                if (ctx.Request.HttpMethod == "POST" && path == "/api/firewall/windows/on")
                {
                    var s = await RequireAdmin(ctx); if (s == null) return;
                    _fw.SetFirewallEnabled(true);
                    Logger.Log($"[WEB] Windows Firewall ON by {s.Username}");
                    await Json(ctx, new { ok = true }); return;
                }

                // POST /api/firewall/windows/off  (Admin only)
                if (ctx.Request.HttpMethod == "POST" && path == "/api/firewall/windows/off")
                {
                    var s = await RequireAdmin(ctx); if (s == null) return;
                    _fw.SetFirewallEnabled(false);
                    Logger.Log($"[WEB] Windows Firewall OFF by {s.Username}");
                    await Json(ctx, new { ok = true }); return;
                }

                // POST /api/firewall/app/on  (Admin only)
                if (ctx.Request.HttpMethod == "POST" && path == "/api/firewall/app/on")
                {
                    var s = await RequireAdmin(ctx); if (s == null) return;
                    _fw.SetAppRulesEnabled(true);
                    Logger.Log($"[WEB] App Rules ON by {s.Username}");
                    await Json(ctx, new { ok = true }); return;
                }

                // POST /api/firewall/app/off  (Admin only)
                if (ctx.Request.HttpMethod == "POST" && path == "/api/firewall/app/off")
                {
                    var s = await RequireAdmin(ctx); if (s == null) return;
                    _fw.SetAppRulesEnabled(false);
                    Logger.Log($"[WEB] App Rules OFF by {s.Username}");
                    await Json(ctx, new { ok = true }); return;
                }

                // POST /api/firewall/builtin/disable  (Admin only)
                if (ctx.Request.HttpMethod == "POST" && path == "/api/firewall/builtin/disable")
                {
                    var s = await RequireAdmin(ctx); if (s == null) return;
                    Logger.Log($"[WEB] Disable Built-in Rules requested by {s.Username}");
                    _fw.DisableBuiltinRules();
                    Logger.Log($"[WEB] Built-in Rules DISABLED by {s.Username}");
                    await Json(ctx, new { ok = true }); return;
                }

                // POST /api/firewall/builtin/restore  (Admin only)
                if (ctx.Request.HttpMethod == "POST" && path == "/api/firewall/builtin/restore")
                {
                    var s = await RequireAdmin(ctx); if (s == null) return;
                    Logger.Log($"[WEB] Restore Built-in Rules requested by {s.Username}");
                    _fw.EnableBuiltinRules();
                    Logger.Log($"[WEB] Built-in Rules RESTORED by {s.Username}");
                    await Json(ctx, new { ok = true }); return;
                }

                // POST /api/ping  (any authenticated user)
                if (ctx.Request.HttpMethod == "POST" && path == "/api/ping")
                {
                    if (await RequireAuth(ctx) == null) return;

                    var body = await ReadBody(ctx);
                    var req  = JsonSerializer.Deserialize<PingRequest>(body, JsonIn) ?? new PingRequest();
                    var host = (req.Host ?? "").Trim();

                    if (string.IsNullOrWhiteSpace(host))
                    {
                        await Json(ctx, new { ok = false, error = "host is required" }, 400);
                        return;
                    }

                    int count   = req.Count   <= 0 ? 4    : Math.Min(req.Count, 20);
                    int timeout = req.TimeoutMs <= 0 ? 1000 : Math.Min(req.TimeoutMs, 10000);

                    var results  = new List<object>();
                    int sent = count, received = 0;
                    long min = long.MaxValue, max = 0, sum = 0;

                    using var ping = new Ping();
                    for (int i = 1; i <= count; i++)
                    {
                        try
                        {
                            var reply = await ping.SendPingAsync(host, timeout);
                            if (reply.Status == IPStatus.Success)
                            {
                                received++;
                                var rtt = reply.RoundtripTime;
                                min = Math.Min(min, rtt); max = Math.Max(max, rtt); sum += rtt;
                                results.Add(new { seq = i, status = reply.Status.ToString(), address = reply.Address?.ToString(), rttMs = (long?)rtt });
                            }
                            else
                            {
                                results.Add(new { seq = i, status = reply.Status.ToString(), address = reply.Address?.ToString(), rttMs = (long?)null });
                            }
                        }
                        catch (Exception ex)
                        {
                            results.Add(new { seq = i, status = "Error", error = ex.Message });
                        }
                    }

                    int    lost = sent - received;
                    double avg  = received > 0 ? (double)sum / received : 0;
                    await Json(ctx, new
                    {
                        ok = true, host,
                        summary = new { sent, received, lost, minMs = received > 0 ? min : 0, maxMs = received > 0 ? max : 0, avgMs = Math.Round(avg, 2) },
                        results
                    });
                    return;
                }

                // GET /api/logs  (any authenticated user)
                if (ctx.Request.HttpMethod == "GET" && path == "/api/logs")
                {
                    if (await RequireAuth(ctx) == null) return;

                    var logPath = _cfg.LogFilePath ?? "firewall_log.csv";
                    var list    = new List<object>();

                    if (File.Exists(logPath))
                    {
                        var lines = File.ReadAllLines(logPath);
                        for (int i = 1; i < lines.Length; i++)
                        {
                            var parts = lines[i].Split(';');
                            if (parts.Length >= 3)
                                list.Add(new { time = parts[0], type = parts[1], message = parts[2] });
                        }
                    }

                    await Json(ctx, list);
                    return;
                }

                await Json(ctx, new { ok = false, error = "Not found" }, 404);
            }
            catch (Exception ex)
            {
                await Json(ctx, new { ok = false, error = ex.Message }, 500);
            }
        }

        // ─── Static file serving ─────────────────────────────────────────────
        private async Task<bool> TryServeStatic(HttpListenerContext ctx, string path)
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string webDir  = Path.Combine(baseDir, "web");
            if (!Directory.Exists(webDir)) return false;

            string rel = path == "/" ? "index.html" : path.TrimStart('/');
            if (string.IsNullOrWhiteSpace(rel)) rel = "index.html";
            if (rel.Contains("..")) return false;

            string fullWeb  = Path.GetFullPath(webDir);
            string fullPath = Path.GetFullPath(Path.Combine(fullWeb, rel));

            if (!fullPath.StartsWith(fullWeb, StringComparison.OrdinalIgnoreCase)) return false;

            if (!File.Exists(fullPath))
            {
                if (!rel.Contains('.'))
                {
                    fullPath = Path.Combine(fullWeb, "index.html");
                    if (!File.Exists(fullPath)) return false;
                }
                else return false;
            }

            byte[] bytes = await File.ReadAllBytesAsync(fullPath);
            ctx.Response.StatusCode    = 200;
            ctx.Response.ContentType   = GetContentType(Path.GetExtension(fullPath));
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length);
            ctx.Response.Close();
            return true;
        }

        // ─── Utility ─────────────────────────────────────────────────────────
        private static string GetContentType(string ext) => ext.ToLowerInvariant() switch
        {
            ".html" => "text/html; charset=utf-8",
            ".css"  => "text/css; charset=utf-8",
            ".js"   => "application/javascript; charset=utf-8",
            ".json" => "application/json; charset=utf-8",
            ".png"  => "image/png",
            ".jpg"  => "image/jpeg",
            ".jpeg" => "image/jpeg",
            ".svg"  => "image/svg+xml",
            ".ico"  => "image/x-icon",
            _       => "application/octet-stream"
        };

        private void AddCors(HttpListenerContext ctx)
        {
            ctx.Response.Headers["Access-Control-Allow-Origin"]  = "*";
            ctx.Response.Headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS";
            ctx.Response.Headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization";
        }

        private static async Task<string> ReadBody(HttpListenerContext ctx)
        {
            using var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding);
            return await reader.ReadToEndAsync();
        }

        private static async Task Json(HttpListenerContext ctx, object data, int status = 200)
        {
            var json  = JsonSerializer.Serialize(data, JsonOut);
            var bytes = Encoding.UTF8.GetBytes(json);
            ctx.Response.StatusCode      = status;
            ctx.Response.ContentType     = "application/json; charset=utf-8";
            ctx.Response.ContentEncoding = Encoding.UTF8;
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length);
            ctx.Response.Close();
        }

        private static string ToExpiresText(DateTime? exp)
        {
            if (exp == null) return "Permanent";
            var diff = exp.Value - DateTime.Now;
            if (diff.TotalSeconds <= 0) return "Expired";
            if (diff.TotalHours >= 1)   return $"{(int)diff.TotalHours}h {(int)diff.Minutes}m";
            return $"{(int)diff.TotalMinutes}m {diff.Seconds}s";
        }

        private static Dictionary<string, DateTime> LoadExpirationsMap(string path)
        {
            var map = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!File.Exists(path)) return map;
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                if (doc.RootElement.ValueKind != JsonValueKind.Array) return map;

                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    string? name = null;
                    DateTime? exp = null;
                    if (item.TryGetProperty("Name",    out var n1)) name = n1.GetString();
                    else if (item.TryGetProperty("RuleName", out var n2)) name = n2.GetString();

                    if (item.TryGetProperty("ExpiresAt", out var e1) && e1.ValueKind == JsonValueKind.String
                        && DateTime.TryParse(e1.GetString(), out var dt1)) exp = dt1;
                    else if (item.TryGetProperty("Expiry", out var e2) && e2.ValueKind == JsonValueKind.String
                        && DateTime.TryParse(e2.GetString(), out var dt2)) exp = dt2;

                    if (!string.IsNullOrWhiteSpace(name) && exp != null)
                        map[name] = exp.Value;
                }
            }
            catch { }
            return map;
        }

        // ─── Request DTOs ─────────────────────────────────────────────────────
        private class LoginRequest
        {
            public string? Username { get; set; }
            public string? Password { get; set; }
        }

        private class AddRuleRequest
        {
            public string? RemoteIp  { get; set; }
            public int     Port      { get; set; } = 0;
            public string? Protocol  { get; set; } = "Any";
            public string? Action    { get; set; } = "Block";
            public bool    Permanent { get; set; } = true;
            public int     Minutes   { get; set; } = 0;
        }

        private class PingRequest
        {
            public string? Host      { get; set; }
            public int     Count     { get; set; } = 4;
            public int     TimeoutMs { get; set; } = 1000;
        }
    }
}
