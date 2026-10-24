using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Dotrino;

// Golden vectors: the SAME file dotrino-native tests with (test-vectors/gen.mjs, made from
// @dotrino/identity itself). A mismatch here is a signature the vault would reject or an
// envelope this device could not open.
//
// Runs every check once per crypto backend available on this machine. It compiles with the
// .NET SDK (net9: BCL + OpenSSL) and with Unity's own compiler on Unity's Mono (OpenSSL only),
// which is the runtime that matters: see README.
//
//   dotrino-unity-tests [vectors.json]

static class Program
{
    static int _failed, _passed;
    static JsonValue V;

    static int Main(string[] args)
    {
        string path = args.Length > 0 ? args[0] : Path.Combine(AppContext.BaseDirectory, "vectors.json");
        V = JsonValue.Parse(File.ReadAllText(path));

        var backends = new List<ICryptoBackend>();
#if NET5_0_OR_GREATER
        backends.Add(new BclCrypto());
#endif
        backends.Add(new OpenSslCrypto());

        Console.WriteLine("runtime: " + System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
        Run("canonical matches the pilar", Canonical_);
        Run("canonical decimals only as JS writes them", Decimals);
        Run("json roundtrip keeps order and text", JsonRoundtrip);
        Run("hkdf matches RFC 5869 A.1", Hkdf);
        Run("key id and label match the pilar", KeyId);

        foreach (var b in backends)
        {
            CryptoBackend.Current = b;
            string n = " [" + b.Name + "]";
            Run("a signature made by the pilar verifies here" + n, PilarSignatureVerifies);
            Run("what this device signs verifies as the pilar would" + n, OwnSignatureVerifies);
            Run("opens what the vault sealed to this device" + n, OpensVaultSealed);
            Run("an envelope for another key does not open" + n, OtherKeyDoesNotOpen);
            Run("the paper checks against the pinned vault" + n, PaperChecks);
            Run("opens what a JS identity encrypted" + n, OpensJsEnvelope);
            Run("opens what the JS pilar sealed for an app" + n, OpensAppSealed);
            Run("envelope, wrap and cek roundtrips" + n, Roundtrips);
            Run("aes-gcm refuses a tampered byte" + n, Tamper);
            Run("opens the binary frame the JS pilar sealed" + n, OpensBinaryFrame);
            Run("what this device seals in binary opens only for its recipient" + n, BinaryRoundtrip);
        }
        Run("an unsealed package reaches the app with its bytes as base64", PlainPackage);
        Run("pack and frame round trip", PackFrameRoundtrip);
        Run("what is not a package or a frame is said with its code", BadPackCodes);

        if (backends.Count > 1) Run("signatures and secrets agree across backends", () => CrossBackend(backends[0], backends[1]));

        // Against the real proxy: two sessions, sealed both ways. Opt-in, it needs the network.
        string live = Environment.GetEnvironmentVariable("DOTRINO_LIVE_PROXY");
        if (!string.IsNullOrEmpty(live)) Run("two sessions talk sealed through " + live, () => Live(live));

        Console.WriteLine($"{_passed} passed, {_failed} failed");
        return _failed == 0 ? 0 : 1;
    }

    static void Run(string name, Action test)
    {
        try { test(); _passed++; Console.WriteLine("ok   " + name); }
        catch (Exception e) { _failed++; Console.WriteLine("FAIL " + name + ": " + e.GetType().Name + ": " + e.Message); }
    }

    static void Eq<T>(T expected, T actual, string what = "")
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new Exception($"{what} expected «{expected}», got «{actual}»");
    }

    static void True(bool cond, string what) { if (!cond) throw new Exception(what); }

    static void Throws<TEx>(Action a, string what) where TEx : Exception
    {
        try { a(); }
        catch (TEx) { return; }
        catch (AggregateException e) when (e.InnerException is TEx) { return; }
        throw new Exception(what + ": did not throw " + typeof(TEx).Name);
    }

    static void Canonical_()
    {
        foreach (var c in V["canon"].Arr) Eq(c["canonical"].Str, Canonical.Stringify(c["input"]), "canon");
    }

    static void Decimals()
    {
        Eq("{\"a\":1.5}", Canonical.Stringify(JsonValue.Parse("{\"a\":1.5}")));
        Throws<ArgumentException>(() => Canonical.Stringify(JsonValue.Parse("{\"a\":1e-7}")), "exponent");
        Throws<ArgumentException>(() => Canonical.Stringify(JsonValue.Parse("{\"a\":4.50}")), "trailing zero");
    }

    static void JsonRoundtrip()
    {
        const string s = "{\"z\":1,\"a\":[true,null,\"ñ\\n\\u0001\"],\"n\":-4.5}";
        Eq(s, JsonValue.Parse(s).ToString());
        Eq("{\"a\":[true,null,\"ñ\\n\\u0001\"],\"n\":-4.5,\"z\":1}", Canonical.Stringify(JsonValue.Parse(s)));
        Throws<FormatException>(() => JsonValue.Parse("{\"a\":1,}"), "trailing comma");
    }

    static byte[] Hex(string h) => Enumerable.Range(0, h.Length / 2).Select(i => Convert.ToByte(h.Substring(i * 2, 2), 16)).ToArray();

    static void Hkdf()
    {
        byte[] okm = Crypto.Hkdf32(Enumerable.Repeat((byte)0x0b, 22).ToArray(), Hex("000102030405060708090a0b0c"), Hex("f0f1f2f3f4f5f6f7f8f9"));
        Eq("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf", BitConverter.ToString(okm).Replace("-", "").ToLowerInvariant());
    }

    static void KeyId()
    {
        var k = V["keyid"];
        Eq(k["id"].Str, Delegation.PubkeyId(k["publickey"].Str), "id");
        Eq(k["label"].Str, Delegation.KeyLabel(k["publickey"].Str), "label");
    }

    static void PilarSignatureVerifies()
    {
        var s = V["sign"];
        True(Crypto.Verify(s["publickey"].Str, s["data"], s["signature"].Str), "pilar signature does not verify");
        var tampered = s["data"].Obj.Clone();
        tampered.Set("ts", 1);
        True(!Crypto.Verify(s["publickey"].Str, tampered, s["signature"].Str), "a tampered body verified");
    }

    static void OwnSignatureVerifies()
    {
        var s = V["sign"];
        using var keys = SoftwareKeys.FromJwk(s["privateJwk"], null);
        True(Delegation.SamePubkey(keys.Publickey, s["publickey"].Str), "different public key from the same private one");
        string sig = keys.Sign(Canonical.Stringify(s["data"])).Result;
        Eq(64, Crypto.FromB64(sig).Length, "signature length");
        True(Crypto.Verify(keys.Publickey, s["data"], sig), "own signature does not verify");
    }

    static void OpensVaultSealed()
    {
        var s = V["sealed"];
        using var keys = SoftwareKeys.FromJwk(null, s["encPrivateJwk"]);
        Eq(s["ctxPlain"].Str, Crypto.OpenSealed(s["ctxWrap"], s["ctxEnvelope"], keys).Result);
    }

    static void OtherKeyDoesNotOpen()
    {
        var s = V["sealed"];
        using var other = SoftwareKeys.FromJwk(null, V["sign"]["privateJwk"]);
        Throws<CryptographicException>(() => Crypto.OpenSealed(s["ctxWrap"], s["ctxEnvelope"], other).Wait(), "other key");
    }

    static void PaperChecks()
    {
        var c = V["cert"];
        var cert = c["cert"];
        string master = c["master"].Str, sub = c["sub"].Str;
        Eq(null, Delegation.Check(cert, master, sub, "vault:approve"), "good paper");
        Eq("scope", Delegation.Check(cert, master, sub, "vault:admin"));
        Eq("sub", Delegation.Check(cert, master, V["sealed"]["encPub"].Str, null));
        Eq("paper-from-another-vault", Delegation.Check(cert, sub, sub, null));
        var widened = cert.Obj.Clone();
        widened.Set("scope", new JsonArray { "vault:admin" });
        Eq("bad-signature", Delegation.Check(widened, master, sub, null));
    }

    static void OpensJsEnvelope()
    {
        var p = V["profile"];
        using var keys = SoftwareKeys.FromJwk(null, p["encPrivateJwk"]);
        Eq(p["encKeyId"].Str, Envelope.EncKeyId(keys.EncPub), "enc key id");
        Eq(p["plain"].Str, Envelope.Decrypt(keys, p["senderEncPub"].Str, p["envelope"]).Result);
    }

    static void OpensAppSealed()
    {
        var s = V["appSealed"];
        using var keys = SoftwareKeys.FromJwk(null, V["profile"]["encPrivateJwk"]);
        var (payload, sender) = new IdentitySealing(keys, "messenger").Open(s["envelope"]).Result;
        True(payload.DeepEquals(s["msg"]), "payload differs: " + payload);
        Eq(s["senderEncPub"].Str, sender, "sender");
        True(!new IdentitySealing(keys, "dotrino-lobby").IsSealed(s["envelope"]), "another app took it as its own");
    }

    static void Roundtrips()
    {
        using var a = SoftwareKeys.Generate();
        using var b = SoftwareKeys.Generate();
        var env = Envelope.Encrypt(a, new[] { b.EncPub, a.EncPub }, "hola ñandú").Result;
        Eq("hola ñandú", Envelope.Decrypt(b, a.EncPub, env).Result, "b opens");
        Eq("hola ñandú", Envelope.Decrypt(a, a.EncPub, env).Result, "a opens its own copy");

        using var c = SoftwareKeys.Generate();
        try { Envelope.Decrypt(c, a.EncPub, env).Wait(); throw new Exception("c opened a message not for it"); }
        catch (AggregateException e) when (e.InnerException is DotrinoException d) { Eq("not-for-me", d.Code); }

        string cek = Crypto.MakeContentKey();
        Eq(cek, Crypto.OpenWrap(Crypto.WrapForMember(cek, b.EncPub), b).Result, "wrap");
        Eq("{\"x\":1}", Crypto.DecryptWithCek(cek, Crypto.EncryptWithCek(cek, 3, "{\"x\":1}")), "cek");

        var sealing = new IdentitySealing(a, "autoball");
        var sealedMsg = sealing.Seal(new JsonObject { { "op", "hello" } }, new[] { b.EncPub }).Result;
        var (payload, from) = new IdentitySealing(b, "autoball").Open(sealedMsg).Result;
        Eq("hello", payload["op"].Str);
        Eq(a.EncPub, from);
        try { sealing.Seal(new JsonObject(), new string[0]).Wait(); throw new Exception("sealed to nobody"); }
        catch (AggregateException e) when (e.InnerException is DotrinoException d) { Eq("unsealed", d.Code); }
    }

    static void Tamper()
    {
        byte[] key = Crypto.RandomBytes(32);
        var (iv, ct) = Crypto.AesGcmSeal(key, Crypto.Utf8("datos"));
        Eq("datos", System.Text.Encoding.UTF8.GetString(Crypto.AesGcmOpen(key, iv, ct)));
        ct[0] ^= 1;
        Throws<CryptographicException>(() => Crypto.AesGcmOpen(key, iv, ct), "tampered ciphertext");
        Throws<CryptographicException>(() => Crypto.AesGcmOpen(key, iv, new byte[5]), "shorter than the tag");
    }

    static void CrossBackend(ICryptoBackend x, ICryptoBackend y)
    {
        byte[] msg = Crypto.Utf8("{\"op\":\"identify\"}");
        x.GenerateP256(out var d1, out var x1, out var y1);
        y.GenerateP256(out var d2, out var x2, out var y2);
        True(y.VerifyP256(x1, y1, msg, x.SignP256(d1, x1, y1, msg)), x.Name + " → " + y.Name);
        True(x.VerifyP256(x2, y2, msg, y.SignP256(d2, x2, y2, msg)), y.Name + " → " + x.Name);
        Eq(Convert.ToBase64String(x.EcdhP256(d1, x1, y1, x2, y2)), Convert.ToBase64String(y.EcdhP256(d2, x2, y2, x1, y1)), "ecdh");
        byte[] k = Crypto.RandomBytes(32), iv = Crypto.RandomBytes(12);
        Eq("cross", System.Text.Encoding.UTF8.GetString(y.AesGcmOpen(k, iv, x.AesGcmSeal(k, iv, Crypto.Utf8("cross")))), "gcm");
    }

    static void OpensBinaryFrame()
    {
        var b = V["binSealed"];
        byte[] frame = Crypto.FromB64(b["frame"].Str);
        var (header, body) = BinPack.DecodeFrame(frame);
        Eq("message", header["type"].Str);
        var inc = ProxyConnection.IncomingPackage("TOK-A", "PK-A", body);
        True(inc.Packed != null && BinPack.IsBinSealed(inc.Packed), "not a binary sealed envelope");
        True(System.Text.Encoding.UTF8.GetString(frame).IndexOf("archivo", StringComparison.Ordinal) < 0, "the proxy could read the message");
        using var keys = SoftwareKeys.FromJwk(null, V["profile"]["encPrivateJwk"]);
        var (payload, sender) = new IdentitySealing(keys, "messenger").OpenBinary(inc.Packed).Result;
        True(payload.DeepEquals(b["resolved"]), "payload differs: " + payload);
        Eq(b["senderEncPub"].Str, sender, "sender");
        using var other = SoftwareKeys.Generate();
        try { new IdentitySealing(other, "messenger").OpenBinary(inc.Packed).Wait(); throw new Exception("another key opened it"); }
        catch (AggregateException) { }
    }

    static void BinaryRoundtrip()
    {
        using var me = SoftwareKeys.Generate();
        var mine = new IdentitySealing(me, "messenger");
        var msg = new JsonObject { { "type", "DM" }, { "text", "hola ñ ✓" } };
        var packed = BinPack.Unpack(mine.SealBinary(msg, new[] { me.EncPub }).Result);
        True(BinPack.IsBinSealed(packed), "not sealed");
        var (payload, sender) = mine.OpenBinary(packed).Result;
        True(payload.DeepEquals(msg), "payload differs");
        Eq(me.EncPub, sender);
    }

    static void PlainPackage()
    {
        var b = V["binSealed"];
        var inc = ProxyConnection.IncomingPackage("T", null, Crypto.FromB64(b["plainPacked"].Str));
        True(inc.Payload.DeepEquals(b["plainResolved"]), "payload differs: " + inc.Payload);
        True(!BinPack.IsBinSealed(inc.Packed), "plain package taken as sealed");
    }

    static void PackFrameRoundtrip()
    {
        var o = new JsonObject { { "t", "x" }, { "ñ", "✓" } };
        var (h, body) = BinPack.DecodeFrame(BinPack.EncodeFrame(new JsonObject { { "to", "A" } }, BinPack.Pack(o)));
        Eq("A", h["to"].Str);
        True(BinPack.Unpack(body).Json.DeepEquals(o), "package differs");
    }

    static void BadPackCodes()
    {
        string Code(Action a) { try { a(); return null; } catch (DotrinoException e) { return e.Code; } }
        Eq("bad-frame", Code(() => BinPack.DecodeFrame(new byte[] { 9, 0, 0, 0, 0 })));
        Eq("bad-pack", Code(() => BinPack.Unpack(new byte[] { 1, 2 })));
        byte[] head = Crypto.Utf8("{\"x\":{\"__dotrino_bin\":[0,99]}}");
        var bad = new byte[5 + head.Length + 3];
        bad[0] = 0xB1; bad[4] = (byte)head.Length;
        Buffer.BlockCopy(head, 0, bad, 5, head.Length);
        Eq("bad-pack", Code(() => BinPack.Unpack(bad)));
    }

    static void Live(string url)
    {
        using var ka = SoftwareKeys.Generate();
        using var kb = SoftwareKeys.Generate();
        using var a = new SealedSession(new[] { url }, ka, "autoball");
        using var b = new SealedSession(new[] { url }, kb, "autoball");
        var got = new System.Collections.Concurrent.BlockingCollection<SealedSession.Received>();
        b.Message += m => got.Add(m);
        a.Start(); b.Start();
        True(a.AwaitOnline().Result && b.AwaitOnline().Result, "not online: " + a.Current + " / " + b.Current);

        // By pubkey: the proxy routes to the identity, and the key to seal to is looked up and verified.
        Eq(kb.EncPub, a.EncPubOf(kb.Publickey).Result, "announced key");
        a.SendSealed(kb.Publickey, new JsonObject { { "op", "kickoff" }, { "n", 1 } }).Wait();
        True(got.TryTake(out var m1, 10_000), "nothing arrived by pubkey");
        Eq("kickoff", m1.Payload["op"].Str);
        Eq(ka.EncPub, m1.SenderEncPub, "sender key");

        // By token: greet, learn whose it is, and send live.
        Eq(kb.Publickey, a.WhoIs(b.Token).Result, "greeting");
        a.SendSealedTo(b.Token, new JsonObject { { "op", "goal" } }).Wait();
        True(got.TryTake(out var m2, 10_000), "nothing arrived by token");
        Eq("goal", m2.Payload["op"].Str);
        Eq(ka.Publickey, m2.FromPubkey, "who the proxy says sent it");
    }
}
