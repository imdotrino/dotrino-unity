using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Dotrino
{
    /// <summary>A P-256 public key as raw coordinates.</summary>
    public readonly struct EcPublicKey
    {
        public readonly byte[] X, Y;
        public EcPublicKey(byte[] x, byte[] y) { X = x; Y = y; }
    }

    /// <summary>
    /// Formats and envelopes of <c>@dotrino/identity</c>, the same as dotrino-native's
    /// <c>Crypto</c>: JWK strings, P1363 signatures over canonical text, and the wraps of
    /// <c>vault/content.js</c>. The primitives come from <see cref="CryptoBackend.Current"/>.
    /// </summary>
    public static class Crypto
    {
        /// <summary>Standard base64 with padding: what <c>btoa</c> produces in the JS pilar.</summary>
        public static string B64(byte[] bytes) => Convert.ToBase64String(bytes);
        public static byte[] FromB64(string s) => Convert.FromBase64String(s);

        public static string B64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        public static byte[] FromB64Url(string s)
        {
            string t = s.Replace('-', '+').Replace('_', '/');
            switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
            return Convert.FromBase64String(t);
        }

        public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

        public static byte[] Sha256(byte[] data)
        {
            using (var h = SHA256.Create()) return h.ComputeHash(data);
        }

        public static byte[] HmacSha256(byte[] key, byte[] data)
        {
            using (var h = new HMACSHA256(key)) return h.ComputeHash(data);
        }

        /// <summary>HKDF-SHA256 (RFC 5869), for up to 32 bytes: one block of extract-and-expand.</summary>
        public static byte[] Hkdf32(byte[] ikm, byte[] salt, byte[] info, int length = 32)
        {
            if (length < 1 || length > 32) throw new ArgumentOutOfRangeException(nameof(length), "hkdf: one block only");
            byte[] prk = HmacSha256(salt ?? new byte[32], ikm);
            var t = new byte[(info?.Length ?? 0) + 1];
            if (info != null) Buffer.BlockCopy(info, 0, t, 0, info.Length);
            t[t.Length - 1] = 1;
            byte[] okm = HmacSha256(prk, t);
            if (length == 32) return okm;
            var cut = new byte[length];
            Buffer.BlockCopy(okm, 0, cut, 0, length);
            return cut;
        }

        public static byte[] RandomBytes(int n)
        {
            var b = new byte[n];
            using (var r = RandomNumberGenerator.Create()) r.GetBytes(b);
            return b;
        }

        /// <summary><c>{"kty":"EC","crv":"P-256","x":…,"y":…}</c> — the field order the ecosystem writes.</summary>
        public static string Jwk(EcPublicKey k) =>
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + B64Url(k.X) + "\",\"y\":\"" + B64Url(k.Y) + "\"}";

        public static EcPublicKey PublicKeyOf(string jwk)
        {
            var o = JsonValue.Parse(jwk).Obj ?? throw new ArgumentException("jwk: not an object");
            if (o["crv"]?.Str != "P-256") throw new ArgumentException("jwk: only P-256 keys");
            byte[] x = FromB64Url(o["x"]?.Str ?? throw new ArgumentException("jwk: no x"));
            byte[] y = FromB64Url(o["y"]?.Str ?? throw new ArgumentException("jwk: no y"));
            if (x.Length != 32 || y.Length != 32) throw new ArgumentException("jwk: coordinates must be 32 bytes");
            return new EcPublicKey(x, y);
        }

        /// <summary><c>verifyDeviceSig</c> of the pilar: P1363 base64 signature over the canonical text of <paramref name="data"/>.</summary>
        public static bool Verify(string publickey, JsonValue data, string signature)
        {
            try
            {
                var k = PublicKeyOf(publickey);
                return CryptoBackend.Current.VerifyP256(k.X, k.Y, Utf8(Canonical.Stringify(data)), FromB64(signature));
            }
            catch (ArgumentException) { return false; }
            catch (FormatException) { return false; }
        }

        /// <summary>AES-GCM with a fresh 12-byte iv: (iv, ct‖tag), as WebCrypto gives them.</summary>
        public static (byte[] iv, byte[] ct) AesGcmSeal(byte[] key, byte[] plain)
        {
            byte[] iv = RandomBytes(12);
            return (iv, CryptoBackend.Current.AesGcmSeal(key, iv, plain));
        }

        public static byte[] AesGcmOpen(byte[] key, byte[] iv, byte[] ct) => CryptoBackend.Current.AesGcmOpen(key, iv, ct);

        /// <summary><c>makeContentKey</c> of the pilar: a fresh AES-256 key, as base64.</summary>
        public static string MakeContentKey() => B64(RandomBytes(32));

        static string Field(JsonValue o, string k, string what) => o?[k]?.Str ?? throw new ArgumentException("invalid " + what);

        /// <summary><c>decryptWithCek</c>: the envelope <c>{ iv, ct }</c> with a content key given as base64.</summary>
        public static string DecryptWithCek(string cek, JsonValue envelope) =>
            Encoding.UTF8.GetString(AesGcmOpen(FromB64(cek), FromB64(Field(envelope, "iv", "envelope")), FromB64(Field(envelope, "ct", "envelope"))));

        /// <summary><c>encryptWithCek</c>: <c>{ gen, iv, ct }</c> with a content key given as base64.</summary>
        public static JsonObject EncryptWithCek(string cek, int gen, string plaintext)
        {
            var (iv, ct) = AesGcmSeal(FromB64(cek), Utf8(plaintext));
            return new JsonObject { { "gen", gen }, { "iv", B64(iv) }, { "ct", B64(ct) } };
        }

        /// <summary>
        /// <c>wrapForMember</c> of the pilar (<c>vault/content.js</c>): the content key wrapped to ONE
        /// member with an ephemeral ECDH key. The ephemeral private half is dropped here.
        /// </summary>
        public static JsonObject WrapForMember(string cek, string memberEncPub)
        {
            if (string.IsNullOrEmpty(cek)) throw new ArgumentException("wrapForMember: missing content key");
            if (string.IsNullOrEmpty(memberEncPub)) throw new ArgumentException("wrapForMember: member has no encryption key");
            var peer = PublicKeyOf(memberEncPub);
            CryptoBackend.Current.GenerateP256(out byte[] d, out byte[] x, out byte[] y);
            try
            {
                byte[] secret = CryptoBackend.Current.EcdhP256(d, x, y, peer.X, peer.Y);
                var (iv, ct) = AesGcmSeal(secret, Utf8(cek));
                return new JsonObject { { "epk", Jwk(new EcPublicKey(x, y)) }, { "iv", B64(iv) }, { "ct", B64(ct) } };
            }
            finally { Array.Clear(d, 0, d.Length); }
        }

        /// <summary>
        /// <c>openWrap</c> of the pilar: ECDH between my encryption key and the ephemeral <c>epk</c>,
        /// the 32 raw bytes as the AES-GCM key, and out comes the content key (a base64 string).
        /// </summary>
        public static async Task<string> OpenWrap(JsonValue wrap, IDeviceKeys keys)
        {
            string epk = Field(wrap, "epk", "wrap"), iv = Field(wrap, "iv", "wrap"), ct = Field(wrap, "ct", "wrap");
            byte[] secret = await keys.Agree(epk).ConfigureAwait(false);
            return Encoding.UTF8.GetString(AesGcmOpen(secret, FromB64(iv), FromB64(ct)));
        }

        /// <summary>What the vault seals to a device (the command of a request): a wrap plus an envelope.</summary>
        public static async Task<string> OpenSealed(JsonValue wrap, JsonValue envelope, IDeviceKeys keys) =>
            DecryptWithCek(await OpenWrap(wrap, keys).ConfigureAwait(false), envelope);
    }

    /// <summary>DER ECDSA signatures (what OpenSSL gives) ↔ P1363 r‖s (what WebCrypto gives).</summary>
    public static class Der
    {
        public static byte[] ToP1363(byte[] der, int length)
        {
            int i = 0;
            if (length < 8 || der[i++] != 0x30) throw new CryptographicException("der: not a sequence");
            int len = der[i++];
            if ((len & 0x80) != 0) i += len & 0x7f;
            var out64 = new byte[64];
            for (int part = 0; part < 2; part++)
            {
                if (der[i++] != 0x02) throw new CryptographicException("der: not an integer");
                int l = der[i++];
                int start = i;
                i += l;
                while (l > 32 && der[start] == 0) { start++; l--; }   // sign padding
                if (l > 32) throw new CryptographicException("der: integer longer than 32 bytes");
                Buffer.BlockCopy(der, start, out64, part * 32 + (32 - l), l);
            }
            return out64;
        }

        public static byte[] FromP1363(byte[] sig)
        {
            if (sig.Length != 64) throw new CryptographicException("p1363: expected 64 bytes");
            byte[] r = Int(sig, 0), s = Int(sig, 32);
            var der = new byte[2 + r.Length + s.Length];
            der[0] = 0x30;
            der[1] = (byte)(r.Length + s.Length);
            Buffer.BlockCopy(r, 0, der, 2, r.Length);
            Buffer.BlockCopy(s, 0, der, 2 + r.Length, s.Length);
            return der;
        }

        static byte[] Int(byte[] sig, int offset)
        {
            int start = offset, end = offset + 32;
            while (start < end - 1 && sig[start] == 0) start++;
            bool pad = (sig[start] & 0x80) != 0;
            int n = end - start + (pad ? 1 : 0);
            var b = new byte[2 + n];
            b[0] = 0x02;
            b[1] = (byte)n;
            Buffer.BlockCopy(sig, start, b, 2 + (pad ? 1 : 0), end - start);
            return b;
        }
    }
}
