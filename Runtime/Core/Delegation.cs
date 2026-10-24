using System;
using System.Collections.Generic;
using System.Text;

namespace Dotrino
{
    /// <summary>Key ids and the device's certificate («papel»), as the pilar defines them.</summary>
    public static class Delegation
    {
        /// <summary><c>pubkeyId</c> (<c>vault/keyid.js</c>): sha-256 hex of <c>{"crv","kty","x","y"}</c> in that order.</summary>
        public static string PubkeyId(string jwk)
        {
            var o = JsonValue.Parse(jwk);
            var canon = new StringBuilder("{");
            string[] fields = { "crv", "kty", "x", "y" };
            for (int i = 0; i < fields.Length; i++)
            {
                if (i > 0) canon.Append(',');
                Canonical.Quote(fields[i], canon);
                canon.Append(':');
                Canonical.Quote(o[fields[i]]?.Str ?? throw new ArgumentException("jwk: no " + fields[i]), canon);
            }
            canon.Append('}');
            byte[] h = Crypto.Sha256(Crypto.Utf8(canon.ToString()));
            var hex = new StringBuilder(64);
            foreach (byte b in h) hex.Append(b.ToString("x2"));
            return hex.ToString();
        }

        /// <summary>The label a person reads and compares: <c>AB12-CD34</c>.</summary>
        public static string KeyLabel(string jwk)
        {
            string id = PubkeyId(jwk).Substring(0, 8).ToUpperInvariant();
            return id.Substring(0, 4) + "-" + id.Substring(4);
        }

        /// <summary>Two JWK strings name the same key when x and y match (field order and extras do not matter).</summary>
        public static bool SamePubkey(string a, string b)
        {
            if (a == null || b == null) return false;
            try
            {
                var x = JsonValue.Parse(a);
                var y = JsonValue.Parse(b);
                return x["x"]?.Str != null && x["x"].Str == y["x"]?.Str && x["y"]?.Str == y["y"]?.Str;
            }
            catch (FormatException) { return false; }
        }

        /// <summary><c>delegationBody</c>: what the issuer signed. Old papers (<c>exp</c>) and new ones (<c>seq</c>) have different bodies.</summary>
        public static JsonObject Body(JsonValue cert)
        {
            var o = new JsonObject();
            bool legacy = cert["seq"]?.Long == null && cert["exp"]?.Long != null;
            foreach (var k in new[] { "v", "iss", "sub", "scope", "iat" }) if (cert[k] != null) o.Set(k, cert[k]);
            string tail = legacy ? "exp" : "seq";
            if (cert[tail] != null) o.Set(tail, cert[tail]);
            if (cert["nonce"] != null) o.Set("nonce", cert["nonce"]);
            return o;
        }

        public static List<string> Scope(JsonValue cert)
        {
            var list = new List<string>();
            switch (cert["scope"])
            {
                case JsonArray a: foreach (var s in a) if (s.Str != null) list.Add(s.Str); break;
                case JsonString s: list.Add(s.Value); break;
            }
            return list;
        }

        /// <summary>
        /// Is <paramref name="cert"/> a paper for MY key, issued by the vault I enrolled with, and
        /// does it allow <paramref name="expectedScope"/>? Returns the reason it is not, or null
        /// when it is. A paper from another sealer is refused and said — never taken as good.
        /// </summary>
        public static string Check(JsonValue cert, string vault, string sub, string expectedScope)
        {
            string iss = cert["iss"]?.Str, sig = cert["sig"]?.Str;
            if (iss == null || sig == null) return "shape";
            if (!SamePubkey(iss, vault)) return "paper-from-another-vault";
            if (!SamePubkey(cert["sub"]?.Str, sub)) return "sub";
            if (!Crypto.Verify(iss, Body(cert), sig)) return "bad-signature";
            if (expectedScope != null && !Scope(cert).Contains(expectedScope)) return "scope";
            return null;
        }
    }
}
