using System;
using System.Security.Cryptography;
using UnityEngine;

namespace Dotrino
{
    /// <summary>
    /// Android: javax.crypto of the platform, through <c>Plugins/Android/DotrinoCrypto.java</c>
    /// (JNI). It lives in its own assembly because it needs UnityEngine (AndroidJavaClass), and
    /// the core has no engine references; it registers itself before the first scene loads.
    /// </summary>
    public sealed class AndroidCrypto : ICryptoBackend
    {
        readonly AndroidJavaClass _j = new AndroidJavaClass("com.dotrino.unity.DotrinoCrypto");

        public string Name => "android";

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.SubsystemRegistration)]
        static void Register() => CryptoBackend.Current = new AndroidCrypto();

        // Unity passes Java byte[] as sbyte[].
        static sbyte[] J(byte[] b)
        {
            var s = new sbyte[b.Length];
            Buffer.BlockCopy(b, 0, s, 0, b.Length);
            return s;
        }

        static byte[] C(sbyte[] s)
        {
            if (s == null) return null;
            var b = new byte[s.Length];
            Buffer.BlockCopy(s, 0, b, 0, s.Length);
            return b;
        }

        byte[] Call(string method, string what, params object[] args)
        {
            try { return C(_j.CallStatic<sbyte[]>(method, args)); }
            catch (AndroidJavaException e) { throw new CryptographicException("javax.crypto: " + what + " failed: " + e.Message); }
        }

        public void GenerateP256(out byte[] d, out byte[] x, out byte[] y)
        {
            byte[] all = Call("generate", "generate");
            d = new byte[32]; x = new byte[32]; y = new byte[32];
            Buffer.BlockCopy(all, 0, d, 0, 32);
            Buffer.BlockCopy(all, 32, x, 0, 32);
            Buffer.BlockCopy(all, 64, y, 0, 32);
            Array.Clear(all, 0, all.Length);
        }

        public byte[] SignP256(byte[] d, byte[] x, byte[] y, byte[] message) => Call("sign", "sign", J(d), J(message));

        public bool VerifyP256(byte[] x, byte[] y, byte[] message, byte[] signature)
        {
            if (signature == null || signature.Length != 64 || x == null || y == null || x.Length != 32 || y.Length != 32) return false;
            return _j.CallStatic<bool>("verify", J(x), J(y), J(message), J(signature));
        }

        public byte[] EcdhP256(byte[] d, byte[] x, byte[] y, byte[] peerX, byte[] peerY)
        {
            byte[] s = Call("ecdh", "derive", J(d), J(peerX), J(peerY));
            if (s == null || s.Length != 32) throw new CryptographicException("javax.crypto: shared secret is not 32 bytes");
            return s;
        }

        public byte[] AesGcmSeal(byte[] key, byte[] iv, byte[] plain) => Call("gcmSeal", "aes-gcm seal", J(key), J(iv), J(plain));

        public byte[] AesGcmOpen(byte[] key, byte[] iv, byte[] sealedBytes)
        {
            if (sealedBytes == null || sealedBytes.Length < 16) throw new CryptographicException("aes-gcm: shorter than its tag");
            return Call("gcmOpen", "aes-gcm open", J(key), J(iv), J(sealedBytes))
                ?? throw new CryptographicException("aes-gcm: the tag does not match");
        }
    }
}
