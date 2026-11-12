using System;
using System.Collections.Generic;

namespace ThreatlessResource
{
    public interface IHost
    {
        long NowMs { get; }
        DateTime UtcNow { get; }
        void After(int delayMs, Action action);
        void Http(string method, string url, string body, IDictionary<string, string> headers, Action<int, string, IDictionary<string, string>> callback);
        string ConvarGet(string name);
        string KvpGet(string key);
        void KvpSet(string key, string value);
        void Log(string level, string message);
        IReadOnlyList<int> Players { get; }
        IReadOnlyList<string> PlayerIdentifiers(int source);
        string PlayerName(int source);
    }

    public sealed class BridgeConfig
    {
        public string Version = "1.0.0";
        public string ApiBaseUrl = "https://api-preprod.threatless.cc/v1";
        public int HttpTimeoutMs = 10000;
        public int FlushIntervalMs = 30000;
        public int MaxBatchSize = 100;
        public int MaxQueue = 5000;
        public int SnapshotIntervalMs = 300000;
        public int RetryBaseMs = 1000;
        public int RetryMaxMs = 60000;
    }
}
