package com.dotrino.unity;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Android: the crypto primitives of dotrino-unity from the platform's own javax.crypto, called
 * from C# (AndroidCrypto.cs) through JNI. Raw big-endian bytes in and out — d, x, y (32 each),
 * P1363 signatures (64), AES-GCM ct‖tag — the same contract as the other backends.
 *
 * Keys of the PERSON do not come through here: on Android they live in Identidad Dotrino
 * (dotrino-native, CONVENCIONES §16). This is for checking, sealing and ephemeral keys.
 */
public final class DotrinoCrypto {
    private DotrinoCrypto() {}

    private static ECParameterSpec p256() throws Exception {
        AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
        p.init(new ECGenParameterSpec("secp256r1"));
        return p.getParameterSpec(ECParameterSpec.class);
    }

    private static byte[] u32(BigInteger n) {
        byte[] b = n.toByteArray(), out = new byte[32];
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, 32 - len, len);
        return out;
    }

    private static byte[] part(byte[] b, int from) {
        byte[] out = new byte[32];
        System.arraycopy(b, from, out, 0, 32);
        return out;
    }

    private static PublicKey pub(byte[] x, byte[] y) throws Exception {
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), p256()));
    }

    private static PrivateKey priv(byte[] d) throws Exception {
        return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, d), p256()));
    }

    /** d‖x‖y, 96 bytes. */
    public static byte[] generate() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair k = g.generateKeyPair();
        ECPublicKey p = (ECPublicKey) k.getPublic();
        byte[] out = new byte[96];
        System.arraycopy(u32(((ECPrivateKey) k.getPrivate()).getS()), 0, out, 0, 32);
        System.arraycopy(u32(p.getW().getAffineX()), 0, out, 32, 32);
        System.arraycopy(u32(p.getW().getAffineY()), 0, out, 64, 32);
        return out;
    }

    public static byte[] sign(byte[] d, byte[] msg) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(priv(d));
        s.update(msg);
        return derToP1363(s.sign());
    }

    public static boolean verify(byte[] x, byte[] y, byte[] msg, byte[] sig) {
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(pub(x, y));
            s.update(msg);
            return s.verify(p1363ToDer(sig));
        } catch (Exception e) {
            return false;
        }
    }

    public static byte[] ecdh(byte[] d, byte[] px, byte[] py) throws Exception {
        KeyAgreement a = KeyAgreement.getInstance("ECDH");
        a.init(priv(d));
        a.doPhase(pub(px, py), true);
        return a.generateSecret();
    }

    public static byte[] gcmSeal(byte[] key, byte[] iv, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return c.doFinal(plain);
    }

    /** Null when the tag does not match: the C# side turns that into its CryptographicException. */
    public static byte[] gcmOpen(byte[] key, byte[] iv, byte[] sealed) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        try {
            return c.doFinal(sealed);
        } catch (AEADBadTagException e) {
            return null;
        }
    }

    private static byte[] derToP1363(byte[] der) {
        int i = 2;
        if ((der[1] & 0x80) != 0) i += der[1] & 0x7f;
        byte[] out = new byte[64];
        for (int part = 0; part < 2; part++) {
            int l = der[i + 1];
            int start = i + 2;
            i = start + l;
            while (l > 32 && der[start] == 0) { start++; l--; }
            System.arraycopy(der, start, out, part * 32 + (32 - l), l);
        }
        return out;
    }

    private static byte[] p1363ToDer(byte[] sig) {
        byte[] r = new BigInteger(1, part(sig, 0)).toByteArray(), s = new BigInteger(1, part(sig, 32)).toByteArray();
        byte[] der = new byte[6 + r.length + s.length];
        der[0] = 0x30; der[1] = (byte) (4 + r.length + s.length);
        der[2] = 0x02; der[3] = (byte) r.length;
        System.arraycopy(r, 0, der, 4, r.length);
        der[4 + r.length] = 0x02; der[5 + r.length] = (byte) s.length;
        System.arraycopy(s, 0, der, 6 + r.length, s.length);
        return der;
    }
}
