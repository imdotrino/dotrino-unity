using System;
using System.Runtime.InteropServices;

namespace Dotrino
{
    /// <summary>
    /// The four primitives the platform has to give: ECDSA P-256 with SHA-256, ECDH P-256 and
    /// AES-GCM, plus key generation. Unity's Mono declares ECDsa/ECDiffieHellman but throws
    /// NotImplementedException, and netstandard2.1 has no AesGcm, so each platform brings its
    /// own (decided with the owner on 2026-10-23: native crypto, no third-party library).
    ///
    /// SHA-256, HMAC and random bytes do work in Mono and stay in managed code (<see cref="Crypto"/>).
    ///
    /// Keys go in and out as raw big-endian bytes: d (32), x (32), y (32). Signatures are P1363
    /// (r‖s, 64 bytes), what WebCrypto gives. AES-GCM output is ct‖tag (16-byte tag), also as
    /// WebCrypto gives it.
    /// </summary>
    public interface ICryptoBackend
    {
        string Name { get; }
        void GenerateP256(out byte[] d, out byte[] x, out byte[] y);
        byte[] SignP256(byte[] d, byte[] x, byte[] y, byte[] message);
        bool VerifyP256(byte[] x, byte[] y, byte[] message, byte[] signature);
        /// <summary>The raw shared secret: the x coordinate, 32 bytes.</summary>
        byte[] EcdhP256(byte[] d, byte[] x, byte[] y, byte[] peerX, byte[] peerY);
        byte[] AesGcmSeal(byte[] key, byte[] iv, byte[] plain);
        /// <summary>Throws <see cref="System.Security.Cryptography.CryptographicException"/> when the tag does not match.</summary>
        byte[] AesGcmOpen(byte[] key, byte[] iv, byte[] sealedBytes);
    }

    public static class CryptoBackend
    {
        static ICryptoBackend _current;

        /// <summary>
        /// The backend in use. Picked once from the platform; a platform without one throws
        /// here, by name, instead of signing with something that only looks right.
        /// </summary>
        public static ICryptoBackend Current
        {
            get => _current ?? (_current = Detect());
            set => _current = value ?? throw new ArgumentNullException(nameof(value));
        }

        static ICryptoBackend Detect()
        {
#if NET5_0_OR_GREATER
            return new BclCrypto();
#elif UNITY_IOS
            return new AppleCrypto();
#elif UNITY_ANDROID
            // Android reports itself as Linux, and has no libcrypto for apps. Its backend
            // (AndroidCrypto, javax.crypto by JNI) needs UnityEngine, so it lives in the
            // Dotrino.Unity.Android assembly and sets Current itself before the first scene.
            throw new PlatformNotSupportedException("dotrino: AndroidCrypto did not register (is Dotrino.Unity.Android in the build?)");
#else
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return new CngCrypto();
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) return new AppleCrypto();
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return new OpenSslCrypto();
            throw new PlatformNotSupportedException(
                "dotrino: no crypto backend for " + RuntimeInformation.OSDescription + " yet");
#endif
        }
    }
}
