using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Dotrino
{
    /// <summary>
    /// Windows: CNG (<c>bcrypt.dll</c>), the system's own, present since Windows Vista; the raw
    /// ECDH secret needs Windows 10. Keys go in as ECCPUBLICBLOB / ECCPRIVATEBLOB.
    ///
    /// Two traps CNG sets, both handled here: <c>BCRYPT_KDF_RAW_SECRET</c> gives the shared
    /// secret LITTLE-endian (reversed to what WebCrypto gives), and ECDSA and ECDH keys are
    /// different algorithms with different blob magics, even for the same P-256 point.
    /// </summary>
    public sealed class CngCrypto : ICryptoBackend
    {
        const string Lib = "bcrypt.dll";
        const uint EcdsaPublicMagic = 0x31534345, EcdsaPrivateMagic = 0x32534345;   // ECS1, ECS2
        const uint EcdhPublicMagic = 0x314B4345, EcdhPrivateMagic = 0x324B4345;     // ECK1, ECK2
        const uint StatusInvalidSignature = 0xC000A000;

        static readonly IntPtr Ecdsa = Open("ECDSA_P256");
        static readonly IntPtr Ecdh = Open("ECDH_P256");
        static readonly IntPtr Aes = OpenGcm();

        public string Name => "cng";

        static void Check(uint status, string what)
        {
            if (status != 0) throw new CryptographicException("cng: " + what + " failed (0x" + status.ToString("X8") + ")");
        }

        static IntPtr Open(string alg)
        {
            Check(BCryptOpenAlgorithmProvider(out IntPtr h, alg, null, 0), "open " + alg);
            return h;
        }

        static IntPtr OpenGcm()
        {
            IntPtr h = Open("AES");
            byte[] mode = System.Text.Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            Check(BCryptSetProperty(h, "ChainingMode", mode, mode.Length, 0), "set gcm");
            return h;
        }

        static IntPtr Import(IntPtr alg, uint magic, byte[] x, byte[] y, byte[] d)
        {
            if (x == null || y == null || x.Length != 32 || y.Length != 32) throw new CryptographicException("p-256: coordinates must be 32 bytes");
            var blob = new byte[8 + 64 + (d != null ? 32 : 0)];
            BitConverter.GetBytes(magic).CopyTo(blob, 0);
            BitConverter.GetBytes(32u).CopyTo(blob, 4);
            Buffer.BlockCopy(x, 0, blob, 8, 32);
            Buffer.BlockCopy(y, 0, blob, 40, 32);
            if (d != null) Buffer.BlockCopy(d, 0, blob, 72, 32);
            try
            {
                Check(BCryptImportKeyPair(alg, IntPtr.Zero, d != null ? "ECCPRIVATEBLOB" : "ECCPUBLICBLOB", out IntPtr key, blob, blob.Length, 0), "import key");
                return key;
            }
            finally { Array.Clear(blob, 0, blob.Length); }
        }

        public void GenerateP256(out byte[] d, out byte[] x, out byte[] y)
        {
            Check(BCryptGenerateKeyPair(Ecdsa, out IntPtr key, 256, 0), "generate");
            var blob = new byte[8 + 96];
            try
            {
                Check(BCryptFinalizeKeyPair(key, 0), "finalize");
                Check(BCryptExportKey(key, IntPtr.Zero, "ECCPRIVATEBLOB", blob, blob.Length, out int n, 0), "export");
                if (n != blob.Length) throw new CryptographicException("cng: unexpected private blob size");
                x = new byte[32]; y = new byte[32]; d = new byte[32];
                Buffer.BlockCopy(blob, 8, x, 0, 32);
                Buffer.BlockCopy(blob, 40, y, 0, 32);
                Buffer.BlockCopy(blob, 72, d, 0, 32);
            }
            finally
            {
                Array.Clear(blob, 0, blob.Length);
                BCryptDestroyKey(key);
            }
        }

        public byte[] SignP256(byte[] d, byte[] x, byte[] y, byte[] message)
        {
            IntPtr key = Import(Ecdsa, EcdsaPrivateMagic, x, y, d);
            try
            {
                byte[] hash = Crypto.Sha256(message);
                var sig = new byte[64];
                Check(BCryptSignHash(key, IntPtr.Zero, hash, hash.Length, sig, sig.Length, out int n, 0), "sign");
                if (n != 64) throw new CryptographicException("cng: signature is not 64 bytes");
                return sig;   // already P1363 (r‖s)
            }
            finally { BCryptDestroyKey(key); }
        }

        public bool VerifyP256(byte[] x, byte[] y, byte[] message, byte[] signature)
        {
            if (signature == null || signature.Length != 64) return false;
            IntPtr key;
            try { key = Import(Ecdsa, EcdsaPublicMagic, x, y, null); } catch (CryptographicException) { return false; }
            try
            {
                byte[] hash = Crypto.Sha256(message);
                uint s = BCryptVerifySignature(key, IntPtr.Zero, hash, hash.Length, signature, signature.Length, 0);
                if (s == 0) return true;
                if (s == StatusInvalidSignature) return false;
                throw new CryptographicException("cng: verify failed (0x" + s.ToString("X8") + ")");
            }
            finally { BCryptDestroyKey(key); }
        }

        public byte[] EcdhP256(byte[] d, byte[] x, byte[] y, byte[] peerX, byte[] peerY)
        {
            IntPtr mine = Import(Ecdh, EcdhPrivateMagic, x, y, d), peer = IntPtr.Zero, secret = IntPtr.Zero;
            try
            {
                peer = Import(Ecdh, EcdhPublicMagic, peerX, peerY, null);
                Check(BCryptSecretAgreement(mine, peer, out secret, 0), "agree");
                var raw = new byte[32];
                Check(BCryptDeriveKey(secret, "TRUNCATE", IntPtr.Zero, raw, raw.Length, out int n, 0), "raw secret");
                if (n != 32) throw new CryptographicException("cng: shared secret is not 32 bytes");
                Array.Reverse(raw);   // CNG gives it little-endian
                return raw;
            }
            finally
            {
                if (secret != IntPtr.Zero) BCryptDestroySecret(secret);
                if (peer != IntPtr.Zero) BCryptDestroyKey(peer);
                BCryptDestroyKey(mine);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct AuthInfo
        {
            public int cbSize, dwInfoVersion;
            public IntPtr pbNonce; public int cbNonce;
            public IntPtr pbAuthData; public int cbAuthData;
            public IntPtr pbTag; public int cbTag;
            public IntPtr pbMacContext; public int cbMacContext;
            public int cbAAD; public long cbData; public int dwFlags;
        }

        delegate uint GcmCall(IntPtr key, ref AuthInfo info);

        static void Gcm(byte[] key, byte[] iv, byte[] tag, GcmCall call)
        {
            if (key == null || (key.Length != 16 && key.Length != 32)) throw new CryptographicException("aes-gcm: key must be 16 or 32 bytes");
            Check(BCryptGenerateSymmetricKey(Aes, out IntPtr h, IntPtr.Zero, 0, key, key.Length, 0), "aes key");
            var pinIv = GCHandle.Alloc(iv, GCHandleType.Pinned);
            var pinTag = GCHandle.Alloc(tag, GCHandleType.Pinned);
            try
            {
                var info = new AuthInfo
                {
                    cbSize = Marshal.SizeOf(typeof(AuthInfo)), dwInfoVersion = 1,
                    pbNonce = pinIv.AddrOfPinnedObject(), cbNonce = iv.Length,
                    pbTag = pinTag.AddrOfPinnedObject(), cbTag = tag.Length,
                };
                uint s = call(h, ref info);
                if (s == 0xC000A002) throw new CryptographicException("aes-gcm: the tag does not match");
                Check(s, "aes-gcm");
            }
            finally
            {
                pinIv.Free();
                pinTag.Free();
                BCryptDestroyKey(h);
            }
        }

        public byte[] AesGcmSeal(byte[] key, byte[] iv, byte[] plain)
        {
            var ct = new byte[plain.Length];
            var tag = new byte[16];
            Gcm(key, iv, tag, (IntPtr h, ref AuthInfo info) => BCryptEncrypt(h, plain, plain.Length, ref info, null, 0, ct, ct.Length, out _, 0));
            var output = new byte[ct.Length + 16];
            Buffer.BlockCopy(ct, 0, output, 0, ct.Length);
            Buffer.BlockCopy(tag, 0, output, ct.Length, 16);
            return output;
        }

        public byte[] AesGcmOpen(byte[] key, byte[] iv, byte[] sealedBytes)
        {
            if (sealedBytes == null || sealedBytes.Length < 16) throw new CryptographicException("aes-gcm: shorter than its tag");
            int n = sealedBytes.Length - 16;
            var ct = new byte[n];
            var tag = new byte[16];
            Buffer.BlockCopy(sealedBytes, 0, ct, 0, n);
            Buffer.BlockCopy(sealedBytes, n, tag, 0, 16);
            var plain = new byte[n];
            Gcm(key, iv, tag, (IntPtr h, ref AuthInfo info) => BCryptDecrypt(h, ct, ct.Length, ref info, null, 0, plain, plain.Length, out _, 0));
            return plain;
        }

        [DllImport(Lib, CharSet = CharSet.Unicode)] static extern uint BCryptOpenAlgorithmProvider(out IntPtr alg, string id, string impl, int flags);
        [DllImport(Lib, CharSet = CharSet.Unicode)] static extern uint BCryptSetProperty(IntPtr obj, string prop, byte[] input, int len, int flags);
        [DllImport(Lib, CharSet = CharSet.Unicode)] static extern uint BCryptImportKeyPair(IntPtr alg, IntPtr importKey, string blobType, out IntPtr key, byte[] input, int len, int flags);
        [DllImport(Lib, CharSet = CharSet.Unicode)] static extern uint BCryptExportKey(IntPtr key, IntPtr exportKey, string blobType, byte[] output, int len, out int result, int flags);
        [DllImport(Lib)] static extern uint BCryptGenerateKeyPair(IntPtr alg, out IntPtr key, int length, int flags);
        [DllImport(Lib)] static extern uint BCryptFinalizeKeyPair(IntPtr key, int flags);
        [DllImport(Lib)] static extern uint BCryptDestroyKey(IntPtr key);
        [DllImport(Lib)] static extern uint BCryptSignHash(IntPtr key, IntPtr padding, byte[] hash, int hashLen, byte[] sig, int sigLen, out int result, int flags);
        [DllImport(Lib)] static extern uint BCryptVerifySignature(IntPtr key, IntPtr padding, byte[] hash, int hashLen, byte[] sig, int sigLen, int flags);
        [DllImport(Lib)] static extern uint BCryptSecretAgreement(IntPtr priv, IntPtr pub, out IntPtr secret, int flags);
        [DllImport(Lib)] static extern uint BCryptDestroySecret(IntPtr secret);
        [DllImport(Lib, CharSet = CharSet.Unicode)] static extern uint BCryptDeriveKey(IntPtr secret, string kdf, IntPtr parameters, byte[] output, int len, out int result, int flags);
        [DllImport(Lib)] static extern uint BCryptGenerateSymmetricKey(IntPtr alg, out IntPtr key, IntPtr obj, int objLen, byte[] secret, int secretLen, int flags);
        [DllImport(Lib)] static extern uint BCryptEncrypt(IntPtr key, byte[] input, int inLen, ref AuthInfo info, byte[] iv, int ivLen, byte[] output, int outLen, out int result, int flags);
        [DllImport(Lib)] static extern uint BCryptDecrypt(IntPtr key, byte[] input, int inLen, ref AuthInfo info, byte[] iv, int ivLen, byte[] output, int outLen, out int result, int flags);
    }
}
