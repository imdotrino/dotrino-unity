using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Dotrino
{
    /// <summary>An error that crosses processes: callers compare <see cref="Code"/>, never the message.</summary>
    public sealed class DotrinoException : Exception
    {
        public readonly string Code;
        public DotrinoException(string message, string code) : base(message) { Code = code; }
    }

    /// <summary>
    /// The identity's envelope (<c>encrypt</c>/<c>decrypt</c> of <c>@dotrino/identity</c>, v2): a
    /// fresh AES key for the text, wrapped to each recipient with ECDH between MY encryption key
    /// and theirs. The wraps are keyed by the first 16 hex of each recipient's key id.
    /// </summary>
    public static class Envelope
    {
        public static string EncKeyId(string encPub) => Delegation.PubkeyId(encPub).Substring(0, 16);

        public static async Task<JsonObject> Encrypt(IDeviceKeys mine, IReadOnlyList<string> recipientEncPubs, string plaintext)
        {
            if (recipientEncPubs == null || recipientEncPubs.Count == 0) throw new ArgumentException("recipients required");
            byte[] k = Crypto.RandomBytes(32);
            try
            {
                var (iv, ct) = Crypto.AesGcmSeal(k, Crypto.Utf8(plaintext));
                var wrap = new JsonObject();
                var seen = new HashSet<string>();
                foreach (var encPub in recipientEncPubs)
                {
                    if (!seen.Add(encPub)) continue;
                    byte[] shared = await mine.Agree(encPub).ConfigureAwait(false);
                    var (wiv, wct) = Crypto.AesGcmSeal(shared, k);
                    wrap.Set(EncKeyId(encPub), new JsonObject { { "iv", Crypto.B64(wiv) }, { "ct", Crypto.B64(wct) } });
                }
                return new JsonObject { { "v", 2 }, { "iv", Crypto.B64(iv) }, { "ct", Crypto.B64(ct) }, { "wrap", wrap } };
            }
            finally { Array.Clear(k, 0, k.Length); }
        }

        /// <summary>My wrap (by the id of my key), then the text. Throws if it is not for me.</summary>
        public static async Task<string> Decrypt(IDeviceKeys mine, string senderEncPub, JsonValue envelope)
        {
            long? v = envelope["v"]?.Long;
            if (v != 1 && v != 2) throw new DotrinoException("unsupported envelope", "bad-envelope");
            var w = envelope["wrap"]?[EncKeyId(mine.EncPub)]
                ?? throw new DotrinoException("this device is not among the message recipients", "not-for-me");
            byte[] shared = await mine.Agree(senderEncPub).ConfigureAwait(false);
            byte[] k = Crypto.AesGcmOpen(shared, Crypto.FromB64(w["iv"].Str), Crypto.FromB64(w["ct"].Str));
            try
            {
                return Encoding.UTF8.GetString(Crypto.AesGcmOpen(k, Crypto.FromB64(envelope["iv"].Str), Crypto.FromB64(envelope["ct"].Str)));
            }
            finally { Array.Clear(k, 0, k.Length); }
        }
    }

    /// <summary>
    /// <c>identitySealing</c> of <c>@dotrino/proxy-client</c>: a directed message as
    /// <c>{ app, sealed, from }</c>. <c>from</c> is the sender's encryption key — only its holder
    /// could build the wrap, so it is what says WHO sealed it.
    /// </summary>
    public sealed class IdentitySealing
    {
        readonly IDeviceKeys _keys;
        public readonly string App;

        public IdentitySealing(IDeviceKeys keys, string app) { _keys = keys; App = app; }

        public bool IsSealed(JsonValue m) => m?["app"]?.Str == App && m["sealed"] is JsonObject;

        /// <summary>Nothing to seal to = it does not go (<c>unsealed</c>): an envelope for nobody is a lost message that looks sent.</summary>
        public async Task<JsonObject> Seal(JsonObject msg, IReadOnlyList<string> recipientEncPubs)
        {
            var keys = new List<string>();
            foreach (var k in recipientEncPubs) if (!string.IsNullOrWhiteSpace(k) && !keys.Contains(k)) keys.Add(k);
            if (keys.Count == 0) throw new DotrinoException("no encryption key for the other side", "unsealed");
            var sealedEnv = await Envelope.Encrypt(_keys, keys, msg.ToString()).ConfigureAwait(false);
            return new JsonObject { { "app", App }, { "sealed", sealedEnv }, { "from", _keys.EncPub } };
        }

        /// <summary>
        /// A BINARY sealed envelope (proxy-client ≥ 0.35, the way everything leaves): a fresh
        /// AES-256 message key sealed with <see cref="Seal"/> as <c>k</c>, and the package of
        /// <paramref name="msg"/> encrypted with it as iv/ct.
        /// </summary>
        public async Task<byte[]> SealBinary(JsonObject msg, IReadOnlyList<string> recipientEncPubs)
        {
            byte[] cek = Crypto.RandomBytes(32);
            try
            {
                var k = await Seal(new JsonObject { { "cek", Crypto.B64(cek) } }, recipientEncPubs).ConfigureAwait(false);
                var (iv, ct) = Crypto.AesGcmSeal(cek, BinPack.Pack(msg));
                return BinPack.PackSealed(k, iv, ct);
            }
            finally { Array.Clear(cek, 0, cek.Length); }
        }

        /// <summary>Opens a binary sealed envelope. Its bytes reach the app as base64 (<see cref="BinPack.Packed.Resolved"/>).</summary>
        public async Task<(JsonObject payload, string senderEncPub)> OpenBinary(BinPack.Packed p)
        {
            if (!BinPack.IsBinSealed(p)) throw new DotrinoException("not a binary sealed envelope", "not-sealed");
            var (key, from) = await Open(p.Json["k"]).ConfigureAwait(false);
            string cek = key["cek"]?.Str ?? throw new DotrinoException("the sealed key of a message has no key inside", "bad-pack");
            byte[] plain;
            try { plain = Crypto.AesGcmOpen(Crypto.FromB64(cek), p.BytesOf(p.Json["iv"]), p.BytesOf(p.Json["ct"])); }
            catch (System.Security.Cryptography.CryptographicException e) { throw new DotrinoException("the message does not open with its key: " + e.Message, "undecipherable"); }
            var payload = BinPack.Unpack(plain).Resolved().Obj ?? throw new DotrinoException("sealed payload is not an object", "bad-payload");
            return (payload, from);
        }

        public async Task<(JsonObject payload, string senderEncPub)> Open(JsonValue env)
        {
            if (!IsSealed(env)) throw new DotrinoException("not a sealed envelope of " + App, "not-sealed");
            string from = env["from"]?.Str ?? throw new DotrinoException("sealed envelope without sender key", "not-sealed");
            string text = await Envelope.Decrypt(_keys, from, env["sealed"]).ConfigureAwait(false);
            var payload = JsonValue.Parse(text).Obj ?? throw new DotrinoException("sealed payload is not an object", "bad-payload");
            return (payload, from);
        }
    }
}
