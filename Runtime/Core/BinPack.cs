using System;
using System.Collections.Generic;
using System.Text;

namespace Dotrino
{
    /// <summary>
    /// BYTES THAT TRAVEL AS BYTES: <c>binpack.js</c> of <c>@dotrino/proxy-client</c> (≥ 0.35), the
    /// two binary formats of the transport, as dotrino-native ports them.
    ///
    ///  · THE PACKAGE: an object with bytes inside.
    ///      [0xB1][u32 BE length of the JSON][JSON][the bytes, one after another]
    ///    Each byte array is a <c>{"__dotrino_bin":[from,length]}</c> reference in the JSON.
    ///
    ///  · THE FRAME: what goes through the proxy's WebSocket.
    ///      [0x01][u32 BE length of the header][header JSON][body]
    ///    The header is the usual text frame without <c>message</c>; the body is the message.
    ///
    /// And the binary sealed envelope: a package <c>{ bv: 1, k, iv, ct }</c> where <c>k</c> is the
    /// usual sealed envelope with <c>{ cek }</c> inside and iv/ct the AES-GCM package of the message.
    /// </summary>
    public static class BinPack
    {
        public const string BinTag = "__dotrino_bin";
        public const int BinSealed = 1;
        const byte PackMagic = 0xB1;
        const byte FrameVersion = 0x01;

        /// <summary>A package, opened: its JSON (with the references) and the area they point into.</summary>
        public sealed class Packed
        {
            public readonly JsonValue Json;
            public readonly byte[] Area;
            public Packed(JsonValue json, byte[] area) { Json = json; Area = area; }

            /// <summary>The bytes a reference points to, or null if <paramref name="v"/> is not one.</summary>
            public byte[] BytesOf(JsonValue v)
            {
                if (!RefOf(v, out int off, out int len)) return null;
                var b = new byte[len];
                Buffer.BlockCopy(Area, off, b, 0, len);
                return b;
            }

            /// <summary>The JSON with each reference replaced by its bytes in base64 (what the apps read).</summary>
            public JsonValue Resolved() => Resolve(Json);

            JsonValue Resolve(JsonValue v)
            {
                switch (v)
                {
                    case JsonArray a: return new JsonArray(Map(a));
                    case JsonObject o:
                        var bytes = BytesOf(o);
                        if (bytes != null) return Crypto.B64(bytes);
                        var r = new JsonObject();
                        foreach (var kv in o) r.Set(kv.Key, Resolve(kv.Value));
                        return r;
                    default: return v;
                }
            }

            IEnumerable<JsonValue> Map(JsonArray a) { foreach (var i in a) yield return Resolve(i); }
        }

        static bool RefOf(JsonValue v, out int off, out int len)
        {
            off = len = 0;
            if (!(v is JsonObject o) || !(o[BinTag] is JsonArray r) || r.Count != 2) return false;
            long? a = r[0].Long, b = r[1].Long;
            if (a == null || b == null) return false;
            off = (int)a; len = (int)b;
            return true;
        }

        static uint ReadU32(byte[] b, int at) => (uint)(b[at] << 24 | b[at + 1] << 16 | b[at + 2] << 8 | b[at + 3]);

        static void WriteU32(byte[] b, int at, int v)
        {
            b[at] = (byte)(v >> 24); b[at + 1] = (byte)(v >> 16); b[at + 2] = (byte)(v >> 8); b[at + 3] = (byte)v;
        }

        public static bool IsPacked(byte[] b) => b != null && b.Length >= 5 && b[0] == PackMagic;

        /// <summary>A package → its JSON and its bytes. Throws <c>bad-pack</c> if it is not one or a reference leaves it.</summary>
        public static Packed Unpack(byte[] b)
        {
            if (!IsPacked(b)) throw new DotrinoException("not a packed message", "bad-pack");
            long len = ReadU32(b, 1);
            if (5 + len > b.Length) throw new DotrinoException("packed message is shorter than its header says", "bad-pack");
            var area = new byte[b.Length - 5 - (int)len];
            Buffer.BlockCopy(b, 5 + (int)len, area, 0, area.Length);
            JsonValue obj;
            try { obj = JsonValue.Parse(Encoding.UTF8.GetString(b, 5, (int)len)); }
            catch (FormatException) { throw new DotrinoException("packed message header is not JSON", "bad-pack"); }
            CheckRefs(obj, area.Length);
            return new Packed(obj, area);
        }

        static void CheckRefs(JsonValue v, int size)
        {
            switch (v)
            {
                case JsonArray a:
                    foreach (var i in a) CheckRefs(i, size);
                    break;
                case JsonObject o:
                    if (!o.ContainsKey(BinTag)) { foreach (var kv in o) CheckRefs(kv.Value, size); return; }
                    if (!(o[BinTag] is JsonArray r) || r.Count != 2 || !(r[0] is JsonNumber) || !(r[1] is JsonNumber) ||
                        !(r[0].Long is long off) || !(r[1].Long is long len) || off < 0 || len < 0 || off + len > size)
                        throw new DotrinoException("packed message points outside itself", "bad-pack");
                    break;
            }
        }

        /// <summary>An object → a package. <paramref name="blobs"/> are the bytes its <see cref="Ref"/>s point to, in order.</summary>
        public static byte[] Pack(JsonValue obj, IReadOnlyList<byte[]> blobs = null)
        {
            byte[] head = Encoding.UTF8.GetBytes(obj.ToString());
            int total = 5 + head.Length;
            if (blobs != null) foreach (var x in blobs) total += x.Length;
            var buf = new byte[total];
            buf[0] = PackMagic;
            WriteU32(buf, 1, head.Length);
            Buffer.BlockCopy(head, 0, buf, 5, head.Length);
            int at = 5 + head.Length;
            if (blobs != null) foreach (var x in blobs) { Buffer.BlockCopy(x, 0, buf, at, x.Length); at += x.Length; }
            return buf;
        }

        public static JsonObject Ref(int from, int length) => new JsonObject { { BinTag, new JsonArray { from, length } } };

        public static byte[] PackSealed(JsonObject k, byte[] iv, byte[] ct) => Pack(
            new JsonObject { { "bv", BinSealed }, { "k", k }, { "iv", Ref(0, iv.Length) }, { "ct", Ref(iv.Length, ct.Length) } },
            new[] { iv, ct });

        /// <summary>The proxy's binary frame → its header and its body. Throws <c>bad-frame</c> if it is not one.</summary>
        public static (JsonObject header, byte[] body) DecodeFrame(byte[] b)
        {
            if (b == null || b.Length < 5 || b[0] != FrameVersion) throw new DotrinoException("not a binary frame of a known version", "bad-frame");
            long len = ReadU32(b, 1);
            if (5 + len > b.Length) throw new DotrinoException("binary frame is shorter than its header says", "bad-frame");
            JsonObject header;
            try { header = JsonValue.Parse(Encoding.UTF8.GetString(b, 5, (int)len)).Obj; }
            catch (FormatException) { header = null; }
            if (header == null) throw new DotrinoException("binary frame header is not a JSON object", "bad-frame");
            var body = new byte[b.Length - 5 - (int)len];
            Buffer.BlockCopy(b, 5 + (int)len, body, 0, body.Length);
            return (header, body);
        }

        public static byte[] EncodeFrame(JsonObject header, byte[] body)
        {
            byte[] head = Encoding.UTF8.GetBytes(header.ToString());
            var buf = new byte[5 + head.Length + body.Length];
            buf[0] = FrameVersion;
            WriteU32(buf, 1, head.Length);
            Buffer.BlockCopy(head, 0, buf, 5, head.Length);
            Buffer.BlockCopy(body, 0, buf, 5 + head.Length, body.Length);
            return buf;
        }

        /// <summary>Is this package a binary sealed envelope (<c>{ bv: 1, k, iv, ct }</c>)?</summary>
        public static bool IsBinSealed(Packed p) =>
            p.Json is JsonObject o && o["bv"]?.Long == BinSealed && o["k"] is JsonObject &&
            RefOf(o["iv"], out _, out _) && RefOf(o["ct"], out _, out _);
    }
}
