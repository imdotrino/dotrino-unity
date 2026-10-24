#if NET5_0_OR_GREATER
using System;
using System.Security.Cryptography;

namespace Dotrino
{
    /// <summary>
    /// .NET 8+ (a game server, the tests): the runtime's own crypto, which on Linux is OpenSSL
    /// and on Windows CNG underneath. Not compiled into Unity, whose Mono lacks it.
    /// </summary>
    public sealed class BclCrypto : ICryptoBackend
    {
        public string Name => "bcl";

        static ECParameters Params(byte[] d, byte[] x, byte[] y) => new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = d,
            Q = new ECPoint { X = x, Y = y },
        };

        public void GenerateP256(out byte[] d, out byte[] x, out byte[] y)
        {
            using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var p = k.ExportParameters(true);
            d = p.D; x = p.Q.X; y = p.Q.Y;
        }

        public byte[] SignP256(byte[] d, byte[] x, byte[] y, byte[] message)
        {
            using var k = ECDsa.Create(Params(d, x, y));
            return k.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        public bool VerifyP256(byte[] x, byte[] y, byte[] message, byte[] signature)
        {
            try
            {
                using var k = ECDsa.Create(Params(null, x, y));
                return k.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch (CryptographicException) { return false; }
        }

        public byte[] EcdhP256(byte[] d, byte[] x, byte[] y, byte[] peerX, byte[] peerY)
        {
            using var mine = ECDiffieHellman.Create(Params(d, x, y));
            using var peer = ECDiffieHellman.Create(Params(null, peerX, peerY));
            return mine.DeriveRawSecretAgreement(peer.PublicKey);
        }

        public byte[] AesGcmSeal(byte[] key, byte[] iv, byte[] plain)
        {
            var output = new byte[plain.Length + 16];
            using var g = new AesGcm(key, 16);
            g.Encrypt(iv, plain, output.AsSpan(0, plain.Length), output.AsSpan(plain.Length));
            return output;
        }

        public byte[] AesGcmOpen(byte[] key, byte[] iv, byte[] sealedBytes)
        {
            if (sealedBytes.Length < 16) throw new CryptographicException("aes-gcm: shorter than its tag");
            int n = sealedBytes.Length - 16;
            var plain = new byte[n];
            using var g = new AesGcm(key, 16);
            g.Decrypt(iv, sealedBytes.AsSpan(0, n), sealedBytes.AsSpan(n), plain);
            return plain;
        }
    }
}
#endif
