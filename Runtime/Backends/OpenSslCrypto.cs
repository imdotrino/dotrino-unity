using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Dotrino
{
    /// <summary>
    /// Linux desktop: libcrypto 3 (OpenSSL 3.x), the system's own, through the EVP and
    /// OSSL_PARAM API — not the EC_KEY functions, which 3.0 deprecated.
    ///
    /// Every native object is freed in a finally: a key that leaks here is a private key left
    /// in memory nobody owns.
    /// </summary>
    public sealed class OpenSslCrypto : ICryptoBackend
    {
        const string Lib = "libcrypto.so.3";

        public string Name => "openssl";

        // OSSL_PARAM_BLD keeps the POINTERS to the names until the params are built (and the
        // built params point at them), so the names live in unmanaged memory for good.
        static readonly IntPtr KGroup = Marshal.StringToHGlobalAnsi("group");
        static readonly IntPtr KPub = Marshal.StringToHGlobalAnsi("pub");
        static readonly IntPtr KPriv = Marshal.StringToHGlobalAnsi("priv");
        static readonly IntPtr VP256 = Marshal.StringToHGlobalAnsi("P-256");
        static readonly IntPtr VEc = Marshal.StringToHGlobalAnsi("EC");

        const int SelectPublic = 0x86;   // EVP_PKEY_PUBLIC_KEY
        const int SelectKeypair = 0x87;  // EVP_PKEY_KEYPAIR
        const int GcmSetIvLen = 0x9, GcmGetTag = 0x10, GcmSetTag = 0x11;

        static void Check(int r, string what)
        {
            if (r <= 0) throw new CryptographicException("openssl: " + what + " failed");
        }

        static IntPtr NotNull(IntPtr p, string what)
        {
            if (p == IntPtr.Zero) throw new CryptographicException("openssl: " + what + " failed");
            return p;
        }

        /// <summary>An EVP_PKEY from raw coordinates (and the scalar, when signing or deriving).</summary>
        static IntPtr Key(byte[] d, byte[] x, byte[] y)
        {
            if (x == null || y == null || x.Length != 32 || y.Length != 32) throw new CryptographicException("p-256: coordinates must be 32 bytes");
            var point = new byte[65];
            point[0] = 0x04;
            Buffer.BlockCopy(x, 0, point, 1, 32);
            Buffer.BlockCopy(y, 0, point, 33, 32);

            IntPtr bld = IntPtr.Zero, prms = IntPtr.Zero, bn = IntPtr.Zero, ctx = IntPtr.Zero;
            var pin = GCHandle.Alloc(point, GCHandleType.Pinned);
            try
            {
                bld = NotNull(OSSL_PARAM_BLD_new(), "param builder");
                Check(OSSL_PARAM_BLD_push_utf8_string(bld, KGroup, VP256, 0), "push group");
                Check(OSSL_PARAM_BLD_push_octet_string(bld, KPub, pin.AddrOfPinnedObject(), (nuint)point.Length), "push pub");
                if (d != null)
                {
                    bn = NotNull(BN_bin2bn(d, d.Length, IntPtr.Zero), "bn");
                    Check(OSSL_PARAM_BLD_push_BN(bld, KPriv, bn), "push priv");
                }
                prms = NotNull(OSSL_PARAM_BLD_to_param(bld), "build params");
                ctx = NotNull(EVP_PKEY_CTX_new_from_name(IntPtr.Zero, VEc, IntPtr.Zero), "key context");
                Check(EVP_PKEY_fromdata_init(ctx), "fromdata init");
                Check(EVP_PKEY_fromdata(ctx, out IntPtr pkey, d != null ? SelectKeypair : SelectPublic, prms), "import key");
                return pkey;
            }
            finally
            {
                if (ctx != IntPtr.Zero) EVP_PKEY_CTX_free(ctx);
                if (prms != IntPtr.Zero) OSSL_PARAM_free(prms);
                if (bn != IntPtr.Zero) BN_clear_free(bn);
                if (bld != IntPtr.Zero) OSSL_PARAM_BLD_free(bld);
                pin.Free();
            }
        }

        public void GenerateP256(out byte[] d, out byte[] x, out byte[] y)
        {
            IntPtr ctx = IntPtr.Zero, pkey = IntPtr.Zero, bn = IntPtr.Zero;
            try
            {
                ctx = NotNull(EVP_PKEY_CTX_new_from_name(IntPtr.Zero, VEc, IntPtr.Zero), "key context");
                Check(EVP_PKEY_keygen_init(ctx), "keygen init");
                Check(EVP_PKEY_CTX_set_group_name(ctx, VP256), "set group");
                Check(EVP_PKEY_generate(ctx, out pkey), "generate");
                Check(EVP_PKEY_get_bn_param(pkey, KPriv, ref bn), "read priv");
                d = new byte[32];
                Check(BN_bn2binpad(bn, d, 32) == 32 ? 1 : 0, "write priv");
                var point = new byte[65];
                Check(EVP_PKEY_get_octet_string_param(pkey, KPub, point, (nuint)point.Length, out nuint n), "read pub");
                if (n != 65 || point[0] != 0x04) throw new CryptographicException("openssl: public key is not an uncompressed point");
                x = new byte[32]; y = new byte[32];
                Buffer.BlockCopy(point, 1, x, 0, 32);
                Buffer.BlockCopy(point, 33, y, 0, 32);
            }
            finally
            {
                if (bn != IntPtr.Zero) BN_clear_free(bn);
                if (pkey != IntPtr.Zero) EVP_PKEY_free(pkey);
                if (ctx != IntPtr.Zero) EVP_PKEY_CTX_free(ctx);
            }
        }

        public byte[] SignP256(byte[] d, byte[] x, byte[] y, byte[] message)
        {
            IntPtr pkey = Key(d, x, y), md = IntPtr.Zero;
            try
            {
                md = NotNull(EVP_MD_CTX_new(), "digest context");
                Check(EVP_DigestSignInit(md, IntPtr.Zero, EVP_sha256(), IntPtr.Zero, pkey), "sign init");
                var der = new byte[80];
                nuint len = (nuint)der.Length;
                Check(EVP_DigestSign(md, der, ref len, message, (nuint)message.Length), "sign");
                return Der.ToP1363(der, (int)len);
            }
            finally
            {
                if (md != IntPtr.Zero) EVP_MD_CTX_free(md);
                EVP_PKEY_free(pkey);
            }
        }

        public bool VerifyP256(byte[] x, byte[] y, byte[] message, byte[] signature)
        {
            if (signature == null || signature.Length != 64) return false;
            IntPtr pkey;
            try { pkey = Key(null, x, y); } catch (CryptographicException) { return false; }
            IntPtr md = IntPtr.Zero;
            try
            {
                md = NotNull(EVP_MD_CTX_new(), "digest context");
                if (EVP_DigestVerifyInit(md, IntPtr.Zero, EVP_sha256(), IntPtr.Zero, pkey) <= 0) return false;
                byte[] der = Der.FromP1363(signature);
                return EVP_DigestVerify(md, der, (nuint)der.Length, message, (nuint)message.Length) == 1;
            }
            finally
            {
                if (md != IntPtr.Zero) EVP_MD_CTX_free(md);
                EVP_PKEY_free(pkey);
            }
        }

        public byte[] EcdhP256(byte[] d, byte[] x, byte[] y, byte[] peerX, byte[] peerY)
        {
            IntPtr mine = Key(d, x, y), peer = IntPtr.Zero, ctx = IntPtr.Zero;
            try
            {
                peer = Key(null, peerX, peerY);
                ctx = NotNull(EVP_PKEY_CTX_new_from_pkey(IntPtr.Zero, mine, IntPtr.Zero), "derive context");
                Check(EVP_PKEY_derive_init(ctx), "derive init");
                Check(EVP_PKEY_derive_set_peer(ctx, peer), "derive peer");
                var secret = new byte[32];
                nuint len = (nuint)secret.Length;
                Check(EVP_PKEY_derive(ctx, secret, ref len), "derive");
                if (len != 32) throw new CryptographicException("openssl: shared secret is not 32 bytes");
                return secret;
            }
            finally
            {
                if (ctx != IntPtr.Zero) EVP_PKEY_CTX_free(ctx);
                if (peer != IntPtr.Zero) EVP_PKEY_free(peer);
                EVP_PKEY_free(mine);
            }
        }

        static IntPtr Gcm(byte[] key)
        {
            switch (key?.Length)
            {
                case 16: return EVP_aes_128_gcm();
                case 32: return EVP_aes_256_gcm();
                default: throw new CryptographicException("aes-gcm: key must be 16 or 32 bytes");
            }
        }

        public byte[] AesGcmSeal(byte[] key, byte[] iv, byte[] plain)
        {
            IntPtr ctx = NotNull(EVP_CIPHER_CTX_new(), "cipher context");
            try
            {
                Check(EVP_EncryptInit_ex(ctx, Gcm(key), IntPtr.Zero, null, null), "encrypt init");
                Check(EVP_CIPHER_CTX_ctrl(ctx, GcmSetIvLen, iv.Length, null), "set iv length");
                Check(EVP_EncryptInit_ex(ctx, IntPtr.Zero, IntPtr.Zero, key, iv), "encrypt key");
                var output = new byte[plain.Length + 16];
                var ct = new byte[plain.Length + 16];
                Check(EVP_EncryptUpdate(ctx, ct, out int n, plain, plain.Length), "encrypt");
                Check(EVP_EncryptFinal_ex(ctx, new byte[16], out _), "encrypt final");
                var tag = new byte[16];
                Check(EVP_CIPHER_CTX_ctrl(ctx, GcmGetTag, 16, tag), "get tag");
                if (n != plain.Length) throw new CryptographicException("openssl: gcm wrote an unexpected length");
                Buffer.BlockCopy(ct, 0, output, 0, n);
                Buffer.BlockCopy(tag, 0, output, n, 16);
                return output;
            }
            finally { EVP_CIPHER_CTX_free(ctx); }
        }

        public byte[] AesGcmOpen(byte[] key, byte[] iv, byte[] sealedBytes)
        {
            if (sealedBytes == null || sealedBytes.Length < 16) throw new CryptographicException("aes-gcm: shorter than its tag");
            int len = sealedBytes.Length - 16;
            var ct = new byte[len];
            var tag = new byte[16];
            Buffer.BlockCopy(sealedBytes, 0, ct, 0, len);
            Buffer.BlockCopy(sealedBytes, len, tag, 0, 16);
            IntPtr ctx = NotNull(EVP_CIPHER_CTX_new(), "cipher context");
            try
            {
                Check(EVP_DecryptInit_ex(ctx, Gcm(key), IntPtr.Zero, null, null), "decrypt init");
                Check(EVP_CIPHER_CTX_ctrl(ctx, GcmSetIvLen, iv.Length, null), "set iv length");
                Check(EVP_DecryptInit_ex(ctx, IntPtr.Zero, IntPtr.Zero, key, iv), "decrypt key");
                var plain = new byte[len + 16];
                Check(EVP_DecryptUpdate(ctx, plain, out int n, ct, len), "decrypt");
                Check(EVP_CIPHER_CTX_ctrl(ctx, GcmSetTag, 16, tag), "set tag");
                if (EVP_DecryptFinal_ex(ctx, new byte[16], out _) <= 0) throw new CryptographicException("aes-gcm: the tag does not match");
                Array.Resize(ref plain, n);
                return plain;
            }
            finally { EVP_CIPHER_CTX_free(ctx); }
        }

        [DllImport(Lib)] static extern IntPtr OSSL_PARAM_BLD_new();
        [DllImport(Lib)] static extern void OSSL_PARAM_BLD_free(IntPtr bld);
        [DllImport(Lib)] static extern int OSSL_PARAM_BLD_push_utf8_string(IntPtr bld, IntPtr key, IntPtr buf, nuint bsize);
        [DllImport(Lib)] static extern int OSSL_PARAM_BLD_push_octet_string(IntPtr bld, IntPtr key, IntPtr buf, nuint bsize);
        [DllImport(Lib)] static extern int OSSL_PARAM_BLD_push_BN(IntPtr bld, IntPtr key, IntPtr bn);
        [DllImport(Lib)] static extern IntPtr OSSL_PARAM_BLD_to_param(IntPtr bld);
        [DllImport(Lib)] static extern void OSSL_PARAM_free(IntPtr p);
        [DllImport(Lib)] static extern IntPtr BN_bin2bn(byte[] s, int len, IntPtr ret);
        [DllImport(Lib)] static extern int BN_bn2binpad(IntPtr a, byte[] to, int tolen);
        [DllImport(Lib)] static extern void BN_clear_free(IntPtr a);
        [DllImport(Lib)] static extern IntPtr EVP_PKEY_CTX_new_from_name(IntPtr libctx, IntPtr name, IntPtr propq);
        [DllImport(Lib)] static extern IntPtr EVP_PKEY_CTX_new_from_pkey(IntPtr libctx, IntPtr pkey, IntPtr propq);
        [DllImport(Lib)] static extern void EVP_PKEY_CTX_free(IntPtr ctx);
        [DllImport(Lib)] static extern int EVP_PKEY_fromdata_init(IntPtr ctx);
        [DllImport(Lib)] static extern int EVP_PKEY_fromdata(IntPtr ctx, out IntPtr pkey, int selection, IntPtr param);
        [DllImport(Lib)] static extern int EVP_PKEY_keygen_init(IntPtr ctx);
        [DllImport(Lib)] static extern int EVP_PKEY_CTX_set_group_name(IntPtr ctx, IntPtr name);
        [DllImport(Lib)] static extern int EVP_PKEY_generate(IntPtr ctx, out IntPtr pkey);
        [DllImport(Lib)] static extern int EVP_PKEY_get_bn_param(IntPtr pkey, IntPtr key, ref IntPtr bn);
        [DllImport(Lib)] static extern int EVP_PKEY_get_octet_string_param(IntPtr pkey, IntPtr key, byte[] buf, nuint max, out nuint outLen);
        [DllImport(Lib)] static extern void EVP_PKEY_free(IntPtr pkey);
        [DllImport(Lib)] static extern IntPtr EVP_MD_CTX_new();
        [DllImport(Lib)] static extern void EVP_MD_CTX_free(IntPtr ctx);
        [DllImport(Lib)] static extern IntPtr EVP_sha256();
        [DllImport(Lib)] static extern int EVP_DigestSignInit(IntPtr ctx, IntPtr pctx, IntPtr type, IntPtr engine, IntPtr pkey);
        [DllImport(Lib)] static extern int EVP_DigestSign(IntPtr ctx, byte[] sig, ref nuint sigLen, byte[] tbs, nuint tbsLen);
        [DllImport(Lib)] static extern int EVP_DigestVerifyInit(IntPtr ctx, IntPtr pctx, IntPtr type, IntPtr engine, IntPtr pkey);
        [DllImport(Lib)] static extern int EVP_DigestVerify(IntPtr ctx, byte[] sig, nuint sigLen, byte[] tbs, nuint tbsLen);
        [DllImport(Lib)] static extern int EVP_PKEY_derive_init(IntPtr ctx);
        [DllImport(Lib)] static extern int EVP_PKEY_derive_set_peer(IntPtr ctx, IntPtr peer);
        [DllImport(Lib)] static extern int EVP_PKEY_derive(IntPtr ctx, byte[] key, ref nuint keyLen);
        [DllImport(Lib)] static extern IntPtr EVP_CIPHER_CTX_new();
        [DllImport(Lib)] static extern void EVP_CIPHER_CTX_free(IntPtr ctx);
        [DllImport(Lib)] static extern IntPtr EVP_aes_128_gcm();
        [DllImport(Lib)] static extern IntPtr EVP_aes_256_gcm();
        [DllImport(Lib)] static extern int EVP_CIPHER_CTX_ctrl(IntPtr ctx, int type, int arg, byte[] ptr);
        [DllImport(Lib)] static extern int EVP_EncryptInit_ex(IntPtr ctx, IntPtr cipher, IntPtr impl, byte[] key, byte[] iv);
        [DllImport(Lib)] static extern int EVP_EncryptUpdate(IntPtr ctx, byte[] output, out int outLen, byte[] input, int inLen);
        [DllImport(Lib)] static extern int EVP_EncryptFinal_ex(IntPtr ctx, byte[] output, out int outLen);
        [DllImport(Lib)] static extern int EVP_DecryptInit_ex(IntPtr ctx, IntPtr cipher, IntPtr impl, byte[] key, byte[] iv);
        [DllImport(Lib)] static extern int EVP_DecryptUpdate(IntPtr ctx, byte[] output, out int outLen, byte[] input, int inLen);
        [DllImport(Lib)] static extern int EVP_DecryptFinal_ex(IntPtr ctx, byte[] output, out int outLen);
    }
}
