using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Dotrino
{
    /// <summary>
    /// A small JSON tree: Unity has no general JSON parser outside the engine (JsonUtility maps to
    /// classes and loses unknown fields), and the library cannot take a dependency for this.
    ///
    /// Objects keep insertion order (what goes on the wire looks like what JS would write) and
    /// numbers keep their source text, so nothing is reformatted on the way through. Signing
    /// never uses <see cref="ToString"/>: it goes through <see cref="Canonical"/>.
    /// </summary>
    public abstract class JsonValue
    {
        public virtual JsonValue this[string key] => null;
        public virtual JsonValue this[int index] => null;

        /// <summary>The text of a JSON string; null for anything else.</summary>
        public string Str => (this as JsonString)?.Value;

        /// <summary>An integer that fits a long; null for anything else (a fraction, a string).</summary>
        public long? Long => this is JsonNumber n && long.TryParse(n.Raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long v) ? v : (long?)null;

        public JsonObject Obj => this as JsonObject;
        public JsonArray Arr => this as JsonArray;

        public static implicit operator JsonValue(string s) => s == null ? (JsonValue)JsonNull.Instance : new JsonString(s);
        public static implicit operator JsonValue(long n) => new JsonNumber(n.ToString(CultureInfo.InvariantCulture));
        public static implicit operator JsonValue(int n) => new JsonNumber(n.ToString(CultureInfo.InvariantCulture));
        public static implicit operator JsonValue(bool b) => b ? JsonBool.True : JsonBool.False;

        /// <summary>Compact JSON, in insertion order, escaped as JSON.stringify does.</summary>
        public override string ToString()
        {
            var sb = new StringBuilder();
            Write(sb);
            return sb.ToString();
        }

        internal abstract void Write(StringBuilder sb);

        public static JsonValue Parse(string text) => new JsonParser(text).ParseDocument();

        public abstract bool DeepEquals(JsonValue other);
    }

    public sealed class JsonNull : JsonValue
    {
        public static readonly JsonNull Instance = new JsonNull();
        JsonNull() { }
        internal override void Write(StringBuilder sb) => sb.Append("null");
        public override bool DeepEquals(JsonValue other) => other is JsonNull;
    }

    public sealed class JsonBool : JsonValue
    {
        public static readonly JsonBool True = new JsonBool(true);
        public static readonly JsonBool False = new JsonBool(false);
        public readonly bool Value;
        JsonBool(bool v) { Value = v; }
        internal override void Write(StringBuilder sb) => sb.Append(Value ? "true" : "false");
        public override bool DeepEquals(JsonValue other) => other is JsonBool b && b.Value == Value;
    }

    public sealed class JsonString : JsonValue
    {
        public readonly string Value;
        public JsonString(string v) { Value = v ?? throw new ArgumentNullException(nameof(v)); }
        internal override void Write(StringBuilder sb) => Canonical.Quote(Value, sb);
        public override bool DeepEquals(JsonValue other) => other is JsonString s && s.Value == Value;
    }

    /// <summary>A number as its source text: 1, -3, 4.5. Never reformatted.</summary>
    public sealed class JsonNumber : JsonValue
    {
        public readonly string Raw;
        public JsonNumber(string raw) { Raw = raw ?? throw new ArgumentNullException(nameof(raw)); }
        internal override void Write(StringBuilder sb) => sb.Append(Raw);
        public override bool DeepEquals(JsonValue other) =>
            other is JsonNumber n && (n.Raw == Raw || double.Parse(n.Raw, CultureInfo.InvariantCulture) == double.Parse(Raw, CultureInfo.InvariantCulture));
    }

    public sealed class JsonArray : JsonValue, IEnumerable<JsonValue>
    {
        readonly List<JsonValue> _items = new List<JsonValue>();
        public JsonArray() { }
        public JsonArray(IEnumerable<JsonValue> items) { foreach (var i in items) Add(i); }
        public int Count => _items.Count;
        public override JsonValue this[int index] => index >= 0 && index < _items.Count ? _items[index] : null;
        public void Add(JsonValue v) => _items.Add(v ?? JsonNull.Instance);
        public IEnumerator<JsonValue> GetEnumerator() => _items.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        internal override void Write(StringBuilder sb)
        {
            sb.Append('[');
            for (int i = 0; i < _items.Count; i++) { if (i > 0) sb.Append(','); _items[i].Write(sb); }
            sb.Append(']');
        }

        public override bool DeepEquals(JsonValue other)
        {
            if (!(other is JsonArray a) || a.Count != Count) return false;
            for (int i = 0; i < Count; i++) if (!_items[i].DeepEquals(a._items[i])) return false;
            return true;
        }
    }

    public sealed class JsonObject : JsonValue, IEnumerable<KeyValuePair<string, JsonValue>>
    {
        readonly List<string> _order = new List<string>();
        readonly Dictionary<string, JsonValue> _map = new Dictionary<string, JsonValue>(StringComparer.Ordinal);

        public int Count => _order.Count;
        public IReadOnlyList<string> Keys => _order;
        public bool ContainsKey(string key) => _map.ContainsKey(key);

        public override JsonValue this[string key] => key != null && _map.TryGetValue(key, out var v) ? v : null;

        /// <summary>Sets a field, keeping its place if it already existed (as JS assignment does).</summary>
        public void Set(string key, JsonValue value)
        {
            if (!_map.ContainsKey(key)) _order.Add(key);
            _map[key] = value ?? JsonNull.Instance;
        }

        /// <summary>For collection initializers: <c>new JsonObject { { "op", "identify" } }</c>.</summary>
        public void Add(string key, JsonValue value) => Set(key, value);

        public bool Remove(string key)
        {
            if (!_map.Remove(key)) return false;
            _order.Remove(key);
            return true;
        }

        public JsonObject Clone()
        {
            var o = new JsonObject();
            foreach (var k in _order) o.Set(k, _map[k]);
            return o;
        }

        public IEnumerator<KeyValuePair<string, JsonValue>> GetEnumerator()
        {
            foreach (var k in _order) yield return new KeyValuePair<string, JsonValue>(k, _map[k]);
        }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        internal override void Write(StringBuilder sb)
        {
            sb.Append('{');
            for (int i = 0; i < _order.Count; i++)
            {
                if (i > 0) sb.Append(',');
                Canonical.Quote(_order[i], sb);
                sb.Append(':');
                _map[_order[i]].Write(sb);
            }
            sb.Append('}');
        }

        public override bool DeepEquals(JsonValue other)
        {
            if (!(other is JsonObject o) || o.Count != Count) return false;
            foreach (var k in _order) if (!(o[k] is JsonValue v) || !_map[k].DeepEquals(v)) return false;
            return true;
        }
    }

    sealed class JsonParser
    {
        readonly string _s;
        int _i;

        public JsonParser(string s) { _s = s ?? throw new ArgumentNullException(nameof(s)); }

        public JsonValue ParseDocument()
        {
            var v = Value();
            Ws();
            if (_i != _s.Length) throw Fail("trailing characters");
            return v;
        }

        FormatException Fail(string what) => new FormatException($"json: {what} at {_i}");

        void Ws() { while (_i < _s.Length && (_s[_i] == ' ' || _s[_i] == '\t' || _s[_i] == '\n' || _s[_i] == '\r')) _i++; }

        JsonValue Value()
        {
            Ws();
            if (_i >= _s.Length) throw Fail("unexpected end");
            char c = _s[_i];
            switch (c)
            {
                case '{': return Object();
                case '[': return Array();
                case '"': return new JsonString(String());
                case 't': Word("true"); return JsonBool.True;
                case 'f': Word("false"); return JsonBool.False;
                case 'n': Word("null"); return JsonNull.Instance;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) return Number();
                    throw Fail($"unexpected '{c}'");
            }
        }

        void Word(string w)
        {
            if (string.CompareOrdinal(_s, _i, w, 0, w.Length) != 0) throw Fail($"expected {w}");
            _i += w.Length;
        }

        JsonObject Object()
        {
            var o = new JsonObject();
            _i++;
            Ws();
            if (_i < _s.Length && _s[_i] == '}') { _i++; return o; }
            while (true)
            {
                Ws();
                if (_i >= _s.Length || _s[_i] != '"') throw Fail("expected a key");
                string k = String();
                Ws();
                if (_i >= _s.Length || _s[_i] != ':') throw Fail("expected ':'");
                _i++;
                o.Set(k, Value());
                Ws();
                if (_i >= _s.Length) throw Fail("unexpected end");
                if (_s[_i] == ',') { _i++; continue; }
                if (_s[_i] == '}') { _i++; return o; }
                throw Fail("expected ',' or '}'");
            }
        }

        JsonArray Array()
        {
            var a = new JsonArray();
            _i++;
            Ws();
            if (_i < _s.Length && _s[_i] == ']') { _i++; return a; }
            while (true)
            {
                a.Add(Value());
                Ws();
                if (_i >= _s.Length) throw Fail("unexpected end");
                if (_s[_i] == ',') { _i++; continue; }
                if (_s[_i] == ']') { _i++; return a; }
                throw Fail("expected ',' or ']'");
            }
        }

        string String()
        {
            _i++;
            var sb = new StringBuilder();
            while (true)
            {
                if (_i >= _s.Length) throw Fail("unterminated string");
                char c = _s[_i++];
                if (c == '"') return sb.ToString();
                if (c < ' ') throw Fail("control character in string");
                if (c != '\\') { sb.Append(c); continue; }
                if (_i >= _s.Length) throw Fail("unterminated escape");
                char e = _s[_i++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (_i + 4 > _s.Length) throw Fail("short \\u escape");
                        sb.Append((char)int.Parse(_s.Substring(_i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        _i += 4;
                        break;
                    default: throw Fail($"bad escape \\{e}");
                }
            }
        }

        JsonNumber Number()
        {
            int start = _i;
            if (_s[_i] == '-') _i++;
            while (_i < _s.Length && "0123456789.eE+-".IndexOf(_s[_i]) >= 0) _i++;
            string raw = _s.Substring(start, _i - start);
            if (!double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out _)) throw Fail($"bad number {raw}");
            return new JsonNumber(raw);
        }
    }
}
