using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CitizenFX.Core;
using CitizenFX.Core.Native;
using Newtonsoft.Json;

namespace ThreatlessResource
{
    internal sealed class FiveMHost : IHost
    {
        private readonly Dictionary<int, Action<int, string, IDictionary<string, string>>> _pending = new Dictionary<int, Action<int, string, IDictionary<string, string>>>();

        public long NowMs => API.GetGameTimer();
        public DateTime UtcNow => DateTime.UtcNow;

        public async void After(int delayMs, Action action)
        {
            await BaseScript.Delay(delayMs);
            action();
        }

        public void Http(string method, string url, string body, IDictionary<string, string> headers, Action<int, string, IDictionary<string, string>> callback)
        {
            var request = new Dictionary<string, object> { ["url"] = url, ["method"] = method, ["data"] = body ?? "", ["headers"] = headers, ["followLocation"] = false };
            var json = JsonConvert.SerializeObject(request);
            var token = API.PerformHttpRequestInternal(json, Encoding.UTF8.GetByteCount(json));
            if (token == -1) token = API.PerformHttpRequestInternalEx(request);
            if (token == -1) callback(0, null, null);
            else _pending[token] = callback;
        }

        private readonly Dictionary<int, string> _errorBodies = new Dictionary<int, string>();

        public void OnHttpError(int token, int status, string body, object headers, object errorData)
        {
            if (_pending.ContainsKey(token) && errorData is string text && text.Length > 0) _errorBodies[token] = text;
        }

        public void OnHttpResponse(int token, int status, string body, object headers)
        {
            if (_errorBodies.TryGetValue(token, out var error))
            {
                _errorBodies.Remove(token);
                if (string.IsNullOrEmpty(body)) body = error;
            }
            if (!_pending.TryGetValue(token, out var callback)) return;
            _pending.Remove(token);
            var map = (headers as IDictionary<string, object>)?.ToDictionary(h => h.Key, h => h.Value?.ToString(), StringComparer.OrdinalIgnoreCase);
            callback(status, body, map);
        }

        public string ConvarGet(string name) => API.GetConvar(name, "");
        public string KvpGet(string key) => API.GetResourceKvpString(key);

        public void KvpSet(string key, string value)
        {
            API.SetResourceKvp(key, value);
            API.FlushResourceKvp();
        }
        private const string Reset = "\u001b[0m";
        private const string Pink = "\u001b[38;5;205m";
        private const string Cyan = "\u001b[96m";
        private const string Green = "\u001b[92m";
        private const string Yellow = "\u001b[93m";
        private const string Red = "\u001b[91m";
        private const string Prefix = "[" + Pink + "Threatless" + Reset + "]";

        private static readonly string[] BannerLines =
        {
            @" _____  _                         _    _",
            @"|_   _|| |__   _ __   ___   __ _ | |_ | |  ___  ___  ___",
            @"  | |  | '_ \ | '__| / _ \ / _` || __|| | / _ \/ __|/ __|",
            @"  | |  | | | || |   |  __/| (_| || |_ | ||  __/\__ \\__ \",
            @"  |_|  |_| |_||_|    \___| \__,_| \__||_| \___||___/|___/",
        };

        public void Log(string level, string message)
        {
            string label, color, value;
            switch (level)
            {
                case "warn": label = "WARN"; color = Yellow; value = Yellow; break;
                case "error": label = "ERROR"; color = Red; value = Red; break;
                default: label = "INFO"; color = Cyan; value = Green; break;
            }
            var split = message.IndexOf(": ", StringComparison.Ordinal);
            var text = split < 0 ? message : message.Substring(0, split + 2) + value + message.Substring(split + 2) + Reset;
            Write(label, color, text);
        }

        private static void Write(string label, string color, string text) => Debug.WriteLine($"{Prefix} - {color}{label}{Reset}: {text}");

        private static void Info(string name, string value, string color) => Write("INFO", Cyan, $"{name} {color}{value}{Reset}");

        public void Banner(string version, string api, string server)
        {
            Debug.WriteLine("");
            foreach (var line in BannerLines) Debug.WriteLine($"  {Pink}{line}{Reset}");
            Debug.WriteLine("");
            Info("Version:", "v" + version.TrimStart('v', 'V', '.'), Red);
            Info("API:    ", api, Green);
            Info("Script: ", "justaskidlol", Red);
            Info("Server: ", server, Green);
        }

        public IReadOnlyList<int> Players =>
            Enumerable.Range(0, API.GetNumPlayerIndices()).Select(i => int.Parse(API.GetPlayerFromIndex(i))).ToList();

        public IReadOnlyList<string> PlayerIdentifiers(int source)
        {
            var handle = source.ToString();
            return Enumerable.Range(0, API.GetNumPlayerIdentifiers(handle)).Select(i => API.GetPlayerIdentifier(handle, i)).ToList();
        }

        public string PlayerName(int source) => API.GetPlayerName(source.ToString());

    }

    public sealed class Entry : BaseScript
    {
        private readonly FiveMHost _host = new FiveMHost();
        private readonly BridgeConfig _config;
        private readonly Bridge _bridge;

        public Entry()
        {
            _config = new BridgeConfig();
            _bridge = new Bridge(_host, _config);

            EventHandlers["__cfx_internal:httpResponse"] += new Action<int, int, string, object, object>(_host.OnHttpError);
            EventHandlers["__cfx_internal:httpResponse"] += new Action<int, int, string, object>(_host.OnHttpResponse);
            EventHandlers["playerJoining"] += new Action<Player>(([FromSource] Player player) =>
                _bridge.Safe("playerJoining", () => _bridge.PlayerJoined(int.Parse(player.Handle))));
            EventHandlers["playerDropped"] += new Action<Player, string>(([FromSource] Player player, string reason) =>
                _bridge.Safe("playerDropped", () => _bridge.PlayerDropped(int.Parse(player.Handle), reason)));
            EventHandlers["onResourceStop"] += new Action<string>(name =>
                _bridge.Safe("onResourceStop", () => { if (name == API.GetCurrentResourceName()) _bridge.Shutdown(); }));
            EventHandlers["txAdmin:events:serverShuttingDown"] += new Action<object>(_ => _bridge.Safe("serverShuttingDown", _bridge.Shutdown));

            API.RegisterCommand("threatless_status", new Action<int, List<object>, string>((source, _, __) =>
                _bridge.Safe("threatless_status", () => { if (source == 0) _bridge.LogStatus(); })), true);
            API.RegisterCommand("threatless_pubkey", new Action<int, List<object>, string>((source, _, __) =>
                _bridge.Safe("threatless_pubkey", () => { if (source == 0) _bridge.LogPublicKey(); })), true);

            Tick += FirstTick;
        }

        private const int StartDelayMs = 15000;

        private async Task FirstTick()
        {
            Tick -= FirstTick;
            await Delay(StartDelayMs);
            _bridge.Safe("banner", () => _host.Banner(_config.Version, _config.ApiBaseUrl, _bridge.ServerLabel()));
            _bridge.Safe("start", _bridge.Start);
        }
    }
}
