using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Dotrino
{
    /// <summary>
    /// macOS and iOS: CryptoKit, through the small Swift file in <c>Plugins/iOS/DotrinoCrypto.swift</c>
    /// (the only public AES-GCM on Apple platforms is Swift). On iOS Unity links it into the app
    /// (<c>__Internal</c>); on macOS it is <c>Plugins/macOS/libDotrinoCrypto.dylib</c>.
    /// </summary>
    public sealed class AppleCrypto : ICryptoBackend
    {
#if UNITY_IOS && !UNITY_EDITOR
        const string Lib = "__Internal";
#else
        const string Lib = "DotrinoCrypto";
#endif

        public string Name => "apple";

        static void Check(int r, string what)
        {
            if (r != 0) throw new CryptographicException("cryptokit: " + what + " failed (" + r + ")");
        }

        static void Coords(byte[] x, byte[] y)
        {
            if (x == null || y == null || x.Length != 32 || y.Length != 32) throw new CryptographicException("p-256: coordinates must be 32 bytes");
        }

        public void GenerateP256(out byte[] d, out byte[] x, out byte[] y)
        {
            d = new byte[32]; x = new byte[32]; y = new byte[32];
            Check(dotrino_p256_generate(d, x, y), "generate");
        }

        public byte[] SignP256(byte[] d, byte[] x, byte[] y, byte[] message)
        {
            if (d == null || d.Length != 32) throw new CryptographicException("p-256: private key must be 32 bytes");
            var sig = new byte[64];
            Check(dotrino_p256_sign(d, message, message.Length, sig), "sign");
            return sig;
        }

        public bool VerifyP256(byte[] x, byte[] y, byte[] message, byte[] signature)
        {
            if (signature == null || signature.Length != 64 || x == null || y == null || x.Length != 32 || y.Length != 32) return false;
            return dotrino_p256_verify(x, y, message, message.Length, signature) == 0;
        }

        public byte[] EcdhP256(byte[] d, byte[] x, byte[] y, byte[] peerX, byte[] peerY)
        {
            Coords(peerX, peerY);
            var secret = new byte[32];
            Check(dotrino_p256_ecdh(d, peerX, peerY, secret), "derive");
            return secret;
        }

        public byte[] AesGcmSeal(byte[] key, byte[] iv, byte[] plain)
        {
            var output = new byte[plain.Length + 16];
            Check(dotrino_aesgcm_seal(key, key.Length, iv, iv.Length, plain, plain.Length, output), "aes-gcm seal");
            return output;
        }

        public byte[] AesGcmOpen(byte[] key, byte[] iv, byte[] sealedBytes)
        {
            if (sealedBytes == null || sealedBytes.Length < 16) throw new CryptographicException("aes-gcm: shorter than its tag");
            var plain = new byte[sealedBytes.Length - 16];
            int r = dotrino_aesgcm_open(key, key.Length, iv, iv.Length, sealedBytes, sealedBytes.Length, plain);
            if (r == -2) throw new CryptographicException("aes-gcm: the tag does not match");
            Check(r, "aes-gcm open");
            return plain;
        }

        [DllImport(Lib)] static extern int dotrino_p256_generate(byte[] d, byte[] x, byte[] y);
        [DllImport(Lib)] static extern int dotrino_p256_sign(byte[] d, byte[] msg, int len, byte[] sig);
        [DllImport(Lib)] static extern int dotrino_p256_verify(byte[] x, byte[] y, byte[] msg, int len, byte[] sig);
        [DllImport(Lib)] static extern int dotrino_p256_ecdh(byte[] d, byte[] px, byte[] py, byte[] output);
        [DllImport(Lib)] static extern int dotrino_aesgcm_seal(byte[] key, int keyLen, byte[] iv, int ivLen, byte[] plain, int len, byte[] output);
        [DllImport(Lib)] static extern int dotrino_aesgcm_open(byte[] key, int keyLen, byte[] iv, int ivLen, byte[] sealedBytes, int len, byte[] output);
    }
}
