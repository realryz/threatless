using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ThreatlessResource
{
    public sealed class GameEvent
    {
        public string Type;
        public int SourceId;
        public long ConnectionSeq;
        public string Name;
        public string OccurredAt;
        public string Reason;
        public Dictionary<string, string> Identifiers;
        public List<KeyValuePair<int, long>> Players;
    }

    public sealed class Bridge
    {
        public const string ApiKeyConvar = "threatless_api_key";
        private static readonly Regex KeyFormat = new Regex("^tl_game_[0-9a-f]{32}\\..+$", RegexOptions.Compiled);
        private static readonly JsonSerializerSettings AsciiJson = new JsonSerializerSettings { StringEscapeHandling = StringEscapeHandling.EscapeNonAscii };

        private sealed class Connection
        {
            public long Seq;
            public string Name;
            public string License;
            public string DropKind;
            public string DropAt;
        }

        private sealed class Batch
        {
            public long Seq;
            public string Reason;
            public int Dropped;
            public List<GameEvent> Events;
        }

        private readonly IHost _host;
        private readonly BridgeConfig _config;
        private readonly LinkedList<GameEvent> _queue = new LinkedList<GameEvent>();
        private readonly Dictionary<int, Connection> _connections = new Dictionary<int, Connection>();
        private readonly Random _random = new Random();
        private const string KvpPrivateKey = "threatless:private_key";
        private const string KvpApiKey = "threatless:api_key";
        private static readonly Regex KeyInText = new Regex("tl_game_[0-9a-f]{32}\\.[A-Za-z0-9._~+/=-]+", RegexOptions.Compiled);
        private static readonly Regex ConsoleUnsafe = new Regex("\\^[0-9]|[\\u0000-\\u001f\\u007f-\\u009f]", RegexOptions.Compiled);
        private string _apiKey;
        private bool _keyFromConvar;
        private bool _triedRegistration;
        private string _privateKey;
        private IDictionary<string, string> _policy;
        private long _connectionSeq;
        private long _batchSeq;
        private int _dropped;
        private int _flushMs;
        private bool _lastSnapshotEmpty;
        private Batch _pending;
        private bool _booting;
        private bool _scheduled;
        private long _scheduledAt;
        private long _scheduleGeneration;
        private long _pausedUntil;
        private bool _started;

        public Bridge(IHost host, BridgeConfig config)
        {
            _host = host;
            _config = config;
            _flushMs = Math.Max(1000, config.FlushIntervalMs);
        }

        public string BootId { get; private set; }
        public string PublicKey { get; private set; }
        public bool InFlight { get; private set; }
        public int Failures { get; private set; }
        public int QueueDepth => _queue.Count + (_pending?.Events.Count ?? 0);
        public int Online => _connections.Count;

        public void Safe(string name, Action action)
        {
            try { action(); }
            catch (Exception e) when (!(e is OutOfMemoryException))
            {
                _host.Log("error", $"Fehler in {name}: {e.GetType().Name}");
            }
        }

        public void Start()
        {
            if (!_config.ApiBaseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                _host.Log("error", "ApiBaseUrl muss https verwenden, Threatless bleibt inaktiv");
                return;
            }
            var convarKey = _host.ConvarGet(ApiKeyConvar);
            if (!string.IsNullOrEmpty(convarKey))
            {
                if (KeyFormat.IsMatch(convarKey))
                {
                    _apiKey = convarKey;
                    _keyFromConvar = true;
                }
                else _host.Log("error", $"{ApiKeyConvar} hat ein ungültiges Format und wird ignoriert");
            }
            if (_apiKey == null)
            {
                var stored = _host.KvpGet(KvpApiKey);
                if (!string.IsNullOrEmpty(stored) && KeyFormat.IsMatch(stored)) _apiKey = stored;
            }
            LoadSigningKey();
            _started = true;
            Boot();
            Every(_config.SnapshotIntervalMs, Snapshot);
        }

        private void LoadSigningKey()
        {
            _privateKey = _host.KvpGet(KvpPrivateKey);
            var created = string.IsNullOrEmpty(_privateKey);
            if (created)
            {
                Signing.Generate(out var publicKey, out var privateKey);
                _privateKey = privateKey;
                _host.KvpSet(KvpPrivateKey, privateKey);
            }
            PublicKey = Signing.PublicKeyOf(_privateKey);
            _host.Log("info", created
                ? $"Neuer Signaturschlüssel erstellt, Public Key: {PublicKey}"
                : $"Signaturschlüssel geladen, Public Key: {PublicKey}");
        }

        public void LogPublicKey() => _host.Log("info", $"Public Key: {PublicKey ?? "keiner"}");

        private void Every(int intervalMs, Action action)
        {
            void Run()
            {
                Safe("timer", action);
                _host.After(intervalMs, Run);
            }
            _host.After(intervalMs, Run);
        }

        private string Now() => _host.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

        private static string Truncate(string value, int max)
        {
            if (value == null || value.Length <= max) return value ?? "";
            return value.Substring(0, char.IsHighSurrogate(value[max - 1]) ? max - 1 : max);
        }

        private void Enqueue(GameEvent ev)
        {
            if (_queue.Count >= _config.MaxQueue)
            {
                _queue.RemoveFirst();
                _dropped++;
            }
            _queue.AddLast(ev);
            if (_queue.Count >= _config.MaxBatchSize) Schedule(0, "size");
            else Schedule(IsPlayerChange(ev) ? PlayerChangeDelayMs : _flushMs, "interval");
        }

        private const int PlayerChangeDelayMs = 1000;

        private static bool IsPlayerChange(GameEvent ev) => ev.Type == "player.connected" || ev.Type == "player.disconnected";

        private static string Plain(string text) => ConsoleUnsafe.Replace(text ?? "", "");

        private void AnnounceConnected(int source, Dictionary<string, string> identifiers)
        {
            var connection = new Connection
            {
                Seq = ++_connectionSeq,
                Name = Truncate(_host.PlayerName(source), 128),
                License = LicenseOf(identifiers),
            };
            _connections[source] = connection;
            Enqueue(new GameEvent
            {
                Type = "player.connected",
                SourceId = source,
                ConnectionSeq = connection.Seq,
                Name = connection.Name,
                OccurredAt = Now(),
                Identifiers = identifiers,
            });
        }

        private static string LicenseOf(Dictionary<string, string> identifiers) =>
            identifiers.TryGetValue("license", out var license) ? license : null;

        public void PlayerJoined(int source)
        {
            if (!_started) return;
            var identifiers = Identifiers.Parse(_host.PlayerIdentifiers(source));
            if (_connections.TryGetValue(source, out var known))
            {
                var license = LicenseOf(identifiers);
                var same = license != null || known.License != null
                    ? license == known.License
                    : Truncate(_host.PlayerName(source), 128) == known.Name;
                if (same) return;
                Close(source, known, known.DropKind ?? "quit", known.DropAt ?? Now());
            }
            _host.Log("info", $"Spieler verbunden: {Plain(_host.PlayerName(source))} (ID {source})");
            AnnounceConnected(source, identifiers);
        }

        private static readonly int[] DropChecksMs = { 1000, 4000, 10000 };

        public void PlayerDropped(int source, string reason)
        {
            if (!_started || !_connections.TryGetValue(source, out var connection)) return;
            connection.DropKind = ClassifyDrop(reason);
            connection.DropAt = Now();
            ConfirmDrop(source, connection, 0);
        }

        private void ConfirmDrop(int source, Connection connection, int attempt)
        {
            _host.After(DropChecksMs[attempt], () => Safe("playerDropped", () =>
            {
                if (!_connections.TryGetValue(source, out var current) || current != connection) return;
                if (_host.Players.Contains(source))
                {
                    if (attempt + 1 < DropChecksMs.Length) ConfirmDrop(source, connection, attempt + 1);
                    else connection.DropKind = connection.DropAt = null;
                    return;
                }
                Close(source, connection, connection.DropKind, connection.DropAt);
            }));
        }

        private void Close(int source, Connection connection, string kind, string occurredAt)
        {
            _connections.Remove(source);
            _host.Log("info", $"Spieler getrennt: {Plain(connection.Name)} (ID {source}, {kind})");
            Enqueue(new GameEvent { Type = "player.disconnected", SourceId = source, ConnectionSeq = connection.Seq, OccurredAt = occurredAt, Reason = kind });
        }

        public static string ClassifyDrop(string reason)
        {
            var text = (reason ?? "").ToLowerInvariant();
            if (text.Contains("timed out") || text.Contains("timeout") || text.Contains("connection") || text.Contains("crash")) return "timeout";
            if (text.Contains("kick") || text.Contains("ban")) return "kicked";
            return "quit";
        }

        public void Snapshot()
        {
            if (!_started || BootId == null) return;
            var empty = _connections.Count == 0;
            if (empty && _lastSnapshotEmpty) return;
            _lastSnapshotEmpty = empty;
            for (var node = _queue.First; node != null;)
            {
                var next = node.Next;
                if (node.Value.Type == "presence.snapshot") _queue.Remove(node);
                node = next;
            }
            Enqueue(new GameEvent
            {
                Type = "presence.snapshot",
                OccurredAt = Now(),
                Players = _connections.Select(c => new KeyValuePair<int, long>(c.Key, c.Value.Seq)).ToList(),
            });
        }

        public void Shutdown()
        {
            if (_started) Flush("shutdown");
        }

        private static string StatusText(int status)
        {
            switch (status)
            {
                case -1: return "Senden fehlgeschlagen";
                case 0: return "keine Antwort";
                case 200: return "200 OK";
                case 400: return "400 Ungültige Daten";
                case 401: return "401 Nicht autorisiert";
                case 403: return "403 Zugriff verweigert";
                case 404: return "404 Nicht gefunden";
                case 409: return "409 Konflikt";
                case 410: return "410 Boot unbekannt";
                case 413: return "413 Zu groß";
                case 429: return "429 Rate-Limit";
                default: return status >= 500 ? $"{status} Serverfehler" : status.ToString(CultureInfo.InvariantCulture);
            }
        }

        private void Request(string method, string path, string what, string body, Action<int, string, IDictionary<string, string>> callback)
        {
            var finished = false;
            void Finish(int status, string responseBody, IDictionary<string, string> headers)
            {
                if (finished) return;
                finished = true;
                if (status < 200 || status >= 300)
                {
                    var trace = TraceId(responseBody);
                    _host.Log(status == 429 || status == 0 ? "warn" : "error", $"Fehler {path}: {StatusText(status)}{(trace != null ? $" (Trace-ID {trace})" : "")}");
                }
                Safe("response " + path, () => callback(status, responseBody, headers));
            }
            var url = _config.ApiBaseUrl + path;
            var requestHeaders = new Dictionary<string, string> { ["Content-Type"] = "application/json" };
            if (_apiKey != null) requestHeaders["Authorization"] = "Bearer " + _apiKey;
            Signing.Apply(requestHeaders, PublicKey, _privateKey, method, new Uri(url).PathAndQuery, body, _host.UtcNow);
            _host.Log("info", $"Sende {method} {path}: {what}");
            _host.After(_config.HttpTimeoutMs, () => Finish(0, null, null));
            try { _host.Http(method, url, body, requestHeaders, Finish); }
            catch (Exception e) when (!(e is OutOfMemoryException))
            {
                _host.After(0, () => Finish(-1, null, null));
            }
        }

        private static JObject ParseObject(string body)
        {
            if (string.IsNullOrEmpty(body)) return null;
            try { return JToken.Parse(body) as JObject; }
            catch (JsonException) { return null; }
        }

        private static string Text(JToken token) => token?.Type == JTokenType.String ? (string)token : null;

        private static int? Number(JToken token) =>
            token?.Type == JTokenType.Integer && (long)token >= int.MinValue && (long)token <= int.MaxValue ? (int)(long)token : (int?)null;

        private static readonly Regex TraceIdInText = new Regex("\"traceId\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.Compiled);

        private static string TraceId(string body)
        {
            var match = TraceIdInText.Match(body ?? "");
            return match.Success ? Plain(match.Groups[1].Value) : null;
        }

        public string ServerLabel()
        {
            foreach (var name in new[] { "sv_projectName", "sv_hostname" })
            {
                var value = Plain(_host.ConvarGet(name)).Trim();
                if (value.Length > 0) return value.Length > 100 ? value.Substring(0, 100) : value;
            }
            return "FiveM Server";
        }

        private void Register()
        {
            _triedRegistration = true;
            var request = new Dictionary<string, object> { ["label"] = ServerLabel() };
            Request("POST", "/game-servers", "Registrierung", JsonConvert.SerializeObject(request), (status, response, headers) =>
            {
                var key = status >= 200 && status < 300 && response != null ? KeyInText.Match(response).Value : "";
                if (key.Length == 0)
                {
                    _host.Log("error", $"Die API verlangt einen Key und hat keinen ausgestellt. Setze {ApiKeyConvar} in der server.cfg");
                    Pause(300000, () =>
                    {
                        _triedRegistration = false;
                        Boot();
                    });
                    return;
                }
                _apiKey = key;
                _host.KvpSet(KvpApiKey, key);
                _host.Log("info", "Bei Threatless registriert, der Key liegt nur auf diesem Server");
                Boot();
            });
        }

        private int Backoff()
        {
            var ceiling = Math.Min(_config.RetryMaxMs, _config.RetryBaseMs * Math.Pow(2, Math.Min(Failures, 16)));
            return (int)(_config.RetryBaseMs / 2 + _random.NextDouble() * ceiling);
        }

        private int RetryDelay(int status, IDictionary<string, string> headers)
        {
            if (status == 401 || status == 403) return 300000;
            if (status == 404) return 60000;
            if (status != 429) return Backoff();
            var value = headers?.FirstOrDefault(h => string.Equals(h.Key, "retry-after", StringComparison.OrdinalIgnoreCase)).Value;
            var seconds = int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ? Math.Max(1, Math.Min(3600, parsed)) : 60;
            return seconds * 1000 + _random.Next(1000);
        }

        private void Pause(int delayMs, Action retry)
        {
            Failures++;
            _pausedUntil = _host.NowMs + delayMs;
            _host.After(delayMs, retry);
        }

        private void SetFlushInterval(int? value)
        {
            if (value.HasValue) _flushMs = Math.Max(Math.Max(1000, _config.FlushIntervalMs), Math.Min(300000, value.Value));
        }

        private void Boot()
        {
            if (_booting) return;
            _booting = true;
            var body = JsonConvert.SerializeObject(new { resourceVersion = _config.Version, capabilities = new[] { "events", "identifiers", "snapshot" } });
            Request("POST", "/game/boot", "Anmeldung", body, (status, response, headers) =>
            {
                _booting = false;
                if (status == 401 && !_keyFromConvar && !_triedRegistration)
                {
                    _host.Log("info", "Die API verlangt einen Key, registriere diesen Server");
                    Register();
                    return;
                }
                var decoded = status == 200 ? ParseObject(response) : null;
                var bootId = Text(decoded?["bootId"]);
                if (bootId == null)
                {
                    Pause(RetryDelay(status, headers), () => Safe("boot", Boot));
                    return;
                }
                var previous = BootId;
                BootId = bootId;
                _policy = (decoded["identifierPolicy"] as JObject)?.Properties()
                    .Where(p => Text(p.Value) != null)
                    .ToDictionary(p => p.Name, p => Text(p.Value)) ?? new Dictionary<string, string>();
                SetFlushInterval(Number(decoded["flushHintMs"]));
                Failures = 0;
                _triedRegistration = false;
                if (previous != null) _dropped += _queue.Count(e => e.Type != "presence.snapshot") + (_pending?.Events.Count ?? 0);
                _pending = null;
                _queue.Clear();
                _connections.Clear();
                _batchSeq = 0;
                _connectionSeq = 0;
                _lastSnapshotEmpty = false;
                foreach (var source in _host.Players) AnnounceConnected(source, Identifiers.Parse(_host.PlayerIdentifiers(source)));
                Snapshot();
                _host.Log("info", $"Verbunden mit Threatless: {_connections.Count} Spieler online, Boot {BootId}");
            });
        }

        private void Schedule(int delayMs, string reason)
        {
            var due = _host.NowMs + delayMs;
            if (_scheduled && due >= _scheduledAt) return;
            _scheduled = true;
            _scheduledAt = due;
            var generation = ++_scheduleGeneration;
            _host.After(delayMs, () =>
            {
                if (generation != _scheduleGeneration) return;
                _scheduled = false;
                Safe("flush", () => Flush(reason));
            });
        }

        private JObject Serialize(GameEvent ev)
        {
            var json = new JObject { ["type"] = ev.Type };
            if (ev.Type == "presence.snapshot")
            {
                json["occurredAt"] = ev.OccurredAt;
                json["players"] = new JArray(ev.Players.Select(p => new JObject { ["sourceId"] = p.Key, ["connectionSeq"] = p.Value }));
                return json;
            }
            json["sourceId"] = ev.SourceId;
            json["connectionSeq"] = ev.ConnectionSeq;
            if (ev.Type == "player.connected")
            {
                json["name"] = ev.Name;
                json["occurredAt"] = ev.OccurredAt;
                json["identifiers"] = JObject.FromObject(Identifiers.Apply(ev.Identifiers, _policy));
            }
            else
            {
                json["occurredAt"] = ev.OccurredAt;
                json["leftAt"] = ev.OccurredAt;
                json["reason"] = ev.Reason;
            }
            return json;
        }

        private string Body(Batch batch) => JsonConvert.SerializeObject(new JObject
        {
            ["bootId"] = BootId,
            ["batchSeq"] = batch.Seq,
            ["flushReason"] = batch.Reason,
            ["droppedEvents"] = batch.Dropped,
            ["events"] = new JArray(batch.Events.Select(Serialize)),
        }, AsciiJson);

        public void Flush(string reason)
        {
            if (InFlight || _booting || BootId == null) return;
            var now = _host.NowMs;
            if (now < _pausedUntil)
            {
                Schedule((int)(_pausedUntil - now), reason);
                return;
            }
            if (_pending == null)
            {
                if (_queue.Count == 0) return;
                var events = new List<GameEvent>();
                while (events.Count < _config.MaxBatchSize && _queue.Count > 0)
                {
                    events.Add(_queue.First.Value);
                    _queue.RemoveFirst();
                }
                _pending = new Batch { Seq = ++_batchSeq, Reason = reason, Dropped = _dropped, Events = events };
                _dropped = 0;
            }
            var batch = _pending;
            var boot = BootId;
            var what = string.Join(", ", batch.Events.GroupBy(e => e.Type).Select(g => g.Count() > 1 ? $"{g.Count()}x {g.Key}" : g.Key));
            var body = Body(batch);
            InFlight = true;
            Request("POST", "/game/events", what, body, (status, response, headers) =>
            {
                InFlight = false;
                if (boot == BootId) OnBatchResponse(batch, status, response, headers);
            });
        }

        private void OnBatchResponse(Batch batch, int status, string response, IDictionary<string, string> headers)
        {
            if (status == 200)
            {
                var decoded = ParseObject(response);
                foreach (var warning in (decoded?["warnings"] as JArray ?? new JArray()).Select(Text).Where(w => w != null))
                    _host.Log("warn", $"Hinweis der API: {Plain(warning)}");
                SetFlushInterval(Number(decoded?["nextFlushIntervalMs"]));
                Failures = 0;
                _pending = null;
                if (_queue.Count > 0)
                {
                    var full = _queue.Count >= _config.MaxBatchSize;
                    Schedule(full ? 0 : _queue.Any(IsPlayerChange) ? PlayerChangeDelayMs : _flushMs, full ? "size" : "interval");
                }
                return;
            }

            if (status == 400 || status == 413)
            {
                if (batch.Events.Count > 1)
                {
                    var half = batch.Events.Count / 2;
                    for (var i = batch.Events.Count - 1; i >= half; i--) _queue.AddFirst(batch.Events[i]);
                    batch.Events = batch.Events.Take(half).ToList();
                }
                else
                {
                    _dropped += batch.Dropped + batch.Events.Count;
                    _batchSeq = batch.Seq - 1;
                    _pending = null;
                    if (_queue.Count == 0) return;
                }
                Schedule(_flushMs, batch.Reason);
                return;
            }

            if (status == 409)
            {
                batch.Seq = ++_batchSeq;
                Schedule(_flushMs, batch.Reason);
                return;
            }

            if (status == 410)
            {
                _host.Log("warn", "Boot der API unbekannt, starte neuen Boot");
                Boot();
                return;
            }

            Pause(RetryDelay(status, headers), () => Safe("flush", () => Flush(batch.Reason)));
        }

        public void LogStatus() =>
            _host.Log("info", $"Status: Boot {BootId ?? "keiner"}, {Online} Spieler online, {QueueDepth} Events wartend, {Failures} Fehlversuche");
    }
}
