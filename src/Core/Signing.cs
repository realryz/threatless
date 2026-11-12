using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace ThreatlessResource
{
    public static class Signing
    {
        public const string KeyHeader = "X-Threatless-Key";
        public const string TimestampHeader = "X-Threatless-Timestamp";
        public const string NonceHeader = "X-Threatless-Nonce";
        public const string SignatureHeader = "X-Threatless-Signature";

        public static string Encode(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        public static byte[] Decode(string text)
        {
            var padded = text.Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '='));
        }

        public static void Generate(out string publicKey, out string privateKey)
        {
            var key = new Ed25519PrivateKeyParameters(new SecureRandom());
            privateKey = Encode(key.GetEncoded());
            publicKey = Encode(key.GeneratePublicKey().GetEncoded());
        }

        public static string PublicKeyOf(string privateKey) =>
            Encode(new Ed25519PrivateKeyParameters(Decode(privateKey), 0).GeneratePublicKey().GetEncoded());

        public static string Message(string method, string pathAndQuery, string timestamp, string nonce, string body)
        {
            byte[] hash;
            using (var sha = SHA256.Create()) hash = sha.ComputeHash(Encoding.UTF8.GetBytes(body ?? ""));
            return $"TL1\n{method}\n{pathAndQuery}\n{timestamp}\n{nonce}\n{BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant()}";
        }

        public static void Apply(IDictionary<string, string> headers, string publicKey, string privateKey, string method, string pathAndQuery, string body, DateTime utcNow)
        {
            var timestamp = new DateTimeOffset(utcNow, TimeSpan.Zero).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            var nonceBytes = new byte[18];
            using (var random = RandomNumberGenerator.Create()) random.GetBytes(nonceBytes);
            var nonce = Encode(nonceBytes);
            var message = Encoding.UTF8.GetBytes(Message(method, pathAndQuery, timestamp, nonce, body));

            var signer = new Ed25519Signer();
            signer.Init(true, new Ed25519PrivateKeyParameters(Decode(privateKey), 0));
            signer.BlockUpdate(message, 0, message.Length);

            headers[KeyHeader] = publicKey;
            headers[TimestampHeader] = timestamp;
            headers[NonceHeader] = nonce;
            headers[SignatureHeader] = Encode(signer.GenerateSignature());
        }
    }
}
