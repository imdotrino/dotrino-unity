using System;
using System.Threading.Tasks;

namespace Dotrino
{
    /// <summary>
    /// The two keys of ONE account on this device, as dotrino-native defines them. The private
    /// halves stay wherever they live — on a phone, the Identidad Dotrino app or the Secure
    /// Enclave (§16); on a desktop, sealed on disk — and this interface only asks them to work.
    /// Asking may take a round trip (IPC to another app), hence Task.
    ///
    /// - <see cref="Publickey"/>: signing key (ECDSA P-256), <c>{"kty","crv","x","y"}</c>.
    /// - <see cref="EncPub"/>: encryption key (ECDH P-256), same shape.
    /// </summary>
    public interface IDeviceKeys
    {
        string Publickey { get; }
        string EncPub { get; }
        /// <summary>Signs the UTF-8 bytes of <paramref name="text"/>: P1363 (r‖s) signature in base64.</summary>
        Task<string> Sign(string text);
        /// <summary>Raw ECDH shared secret (x coordinate, 32 bytes) with the key in <paramref name="peerJwk"/>.</summary>
        Task<byte[]> Agree(string peerJwk);
    }

    /// <summary>
    /// Keys held in this process's memory, for a desktop device (and the tests). Whoever owns the
    /// instance owns the private scalars: <see cref="Dispose"/> wipes them.
    /// </summary>
    public sealed class SoftwareKeys : IDeviceKeys, IDisposable
    {
        readonly byte[] _sd, _sx, _sy, _ed, _ex, _ey;

        public string Publickey { get; }
        public string EncPub { get; }

        SoftwareKeys(byte[] sd, byte[] sx, byte[] sy, byte[] ed, byte[] ex, byte[] ey)
        {
            _sd = sd; _sx = sx; _sy = sy; _ed = ed; _ex = ex; _ey = ey;
            Publickey = sd != null ? Crypto.Jwk(new EcPublicKey(sx, sy)) : "";
            EncPub = ed != null ? Crypto.Jwk(new EcPublicKey(ex, ey)) : "";
        }

        /// <summary>A fresh pair of keys: signing and encryption.</summary>
        public static SoftwareKeys Generate()
        {
            var b = CryptoBackend.Current;
            b.GenerateP256(out byte[] sd, out byte[] sx, out byte[] sy);
            b.GenerateP256(out byte[] ed, out byte[] ex, out byte[] ey);
            return new SoftwareKeys(sd, sx, sy, ed, ex, ey);
        }

        /// <summary>From private JWKs (<c>{ d, x, y }</c>). Either may be null: that key is then absent.</summary>
        public static SoftwareKeys FromJwk(JsonValue signPrivate, JsonValue encPrivate)
        {
            byte[] sd = null, sx = null, sy = null, ed = null, ex = null, ey = null;
            if (signPrivate != null) Read(signPrivate, out sd, out sx, out sy);
            if (encPrivate != null) Read(encPrivate, out ed, out ex, out ey);
            return new SoftwareKeys(sd, sx, sy, ed, ex, ey);
        }

        static void Read(JsonValue jwk, out byte[] d, out byte[] x, out byte[] y)
        {
            if (jwk["crv"]?.Str != "P-256") throw new ArgumentException("jwk: only P-256 keys");
            d = Crypto.FromB64Url(jwk["d"]?.Str ?? throw new ArgumentException("jwk: no d"));
            x = Crypto.FromB64Url(jwk["x"]?.Str ?? throw new ArgumentException("jwk: no x"));
            y = Crypto.FromB64Url(jwk["y"]?.Str ?? throw new ArgumentException("jwk: no y"));
        }

        /// <summary>The private JWK of the signing key, to be sealed by whoever stores it.</summary>
        public JsonObject SignPrivateJwk() => PrivateJwk(_sd, _sx, _sy);
        public JsonObject EncPrivateJwk() => PrivateJwk(_ed, _ex, _ey);

        static JsonObject PrivateJwk(byte[] d, byte[] x, byte[] y) => d == null ? null : new JsonObject
        {
            { "kty", "EC" }, { "crv", "P-256" }, { "x", Crypto.B64Url(x) }, { "y", Crypto.B64Url(y) }, { "d", Crypto.B64Url(d) },
        };

        public Task<string> Sign(string text)
        {
            if (_sd == null) throw new InvalidOperationException("this device has no signing key");
            return Task.FromResult(Crypto.B64(CryptoBackend.Current.SignP256(_sd, _sx, _sy, Crypto.Utf8(text))));
        }

        public Task<byte[]> Agree(string peerJwk)
        {
            if (_ed == null) throw new InvalidOperationException("this device has no encryption key");
            var p = Crypto.PublicKeyOf(peerJwk);
            return Task.FromResult(CryptoBackend.Current.EcdhP256(_ed, _ex, _ey, p.X, p.Y));
        }

        public void Dispose()
        {
            if (_sd != null) Array.Clear(_sd, 0, _sd.Length);
            if (_ed != null) Array.Clear(_ed, 0, _ed.Length);
        }
    }
}
