using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace ThreatlessResource
{
    public static class Identifiers
    {
        private static readonly HashSet<string> Known = new HashSet<string> { "license", "fivem", "discord", "ip" };

        public static Dictionary<string, string> Parse(IEnumerable<string> raw)
        {
            var result = new Dictionary<string, string>();
            foreach (var item in raw ?? new string[0])
            {
                var split = item?.IndexOf(':') ?? -1;
                if (split <= 0) continue;
                var provider = item.Substring(0, split);
                var value = item.Substring(split + 1);
                if (!Known.Contains(provider) || value.Length == 0 || result.ContainsKey(provider)) continue;
                if (provider == "ip")
                {
                    value = Address(value);
                    if (value == null) continue;
                }
                result[provider] = value;
            }
            return result;
        }

        public static string Address(string value)
        {
            value = value.Trim();
            if (value.StartsWith("["))
            {
                var end = value.IndexOf(']');
                if (end < 0) return null;
                value = value.Substring(1, end - 1);
            }
            else if (value.IndexOf(':') == value.LastIndexOf(':') && value.IndexOf(':') > 0)
                value = value.Substring(0, value.IndexOf(':'));
            var zone = value.IndexOf('%');
            if (zone >= 0) value = value.Substring(0, zone);
            if (!IPAddress.TryParse(value, out var address)) return null;
            if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            return address.ToString();
        }

        public static Dictionary<string, string> Apply(Dictionary<string, string> raw, IDictionary<string, string> policy)
        {
            var result = new Dictionary<string, string>();
            foreach (var pair in raw)
            {
                if (policy == null || !policy.TryGetValue(pair.Key, out var rule)) continue;
                if (rule == "accept" || rule == "hash_only") result[pair.Key] = pair.Value;
            }
            return result;
        }
    }
}
