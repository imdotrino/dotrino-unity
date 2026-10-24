import com.dotrino.unity.DotrinoCrypto;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

// Corre el backend de Android (Plugins/Android/DotrinoCrypto.java) en un JVM de escritorio con
// las entradas que genera la BCL de .NET (`dotrino-unity-tests --jvm-input`), y escribe lo que
// sale para que .NET lo compruebe (`--jvm-check`). Mismo javax.crypto que en Android.
public class JvmCheck {
    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }

    static String hex(byte[] b) {
        if (b == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Map<String, byte[]> in = new HashMap<>();
        BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
        for (String line; (line = r.readLine()) != null; ) {
            int eq = line.indexOf('=');
            if (eq > 0) in.put(line.substring(0, eq), hex(line.substring(eq + 1)));
        }
        byte[] d = in.get("d"), x = in.get("x"), y = in.get("y"), msg = in.get("msg");
        System.out.println("verify=" + DotrinoCrypto.verify(x, y, msg, in.get("sig")));
        System.out.println("verifyTampered=" + DotrinoCrypto.verify(x, y, in.get("msg2"), in.get("sig")));
        System.out.println("verifyShort=" + DotrinoCrypto.verify(x, y, msg, new byte[10]));
        System.out.println("sig=" + hex(DotrinoCrypto.sign(d, msg)));
        System.out.println("ecdh=" + hex(DotrinoCrypto.ecdh(d, in.get("px"), in.get("py"))));
        System.out.println("seal=" + hex(DotrinoCrypto.gcmSeal(in.get("key"), in.get("iv"), in.get("plain"))));
        System.out.println("open=" + hex(DotrinoCrypto.gcmOpen(in.get("key"), in.get("iv"), in.get("sealed"))));
        System.out.println("tampered=" + hex(DotrinoCrypto.gcmOpen(in.get("key"), in.get("iv"), in.get("sealedBad"))));
        System.out.println("gen=" + hex(DotrinoCrypto.generate()));
    }
}
