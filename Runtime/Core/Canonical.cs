using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Dotrino
{
    /// <summary>
    /// Canonical JSON, byte-identical to <c>canonicalStringify</c> in <c>@dotrino/identity</c>
    /// (<c>vault/core.js</c>): keys sorted, no whitespace, strings escaped as JSON.stringify does.
    ///
    /// Everything a vault signs or checks goes through this, so a single differing byte means a
    /// signature that never verifies — seen from outside as «the vault does not answer».
    ///
    /// Numbers: integers, and decimals only in the plain shortest form JS writes (4.5). An
    /// exponent or «4.50» cannot be guaranteed equal and throws instead (same rule as
    /// dotrino-native).
    /// </summary>
    public static class Canonical
    {
        static readonly Regex PlainDecimal = new Regex("^-?(0|[1-9][0-9]*)\\.[0-9]*[1-9]$", RegexOptions.CultureInvariant);

        public static string Stringify(JsonValue v)
        {
            var sb = new StringBuilder();
            Write(v, sb);
            return sb.ToString();
        }

        static void Write(JsonValue v, StringBuilder sb)
        {
            switch (v)
            {
                case null:
                case JsonNull _:
                    sb.Append("null");
                    break;
                case JsonBool b:
                    sb.Append(b.Value ? "true" : "false");
                    break;
                case JsonString s:
                    Quote(s.Value, sb);
                    break;
                case JsonNumber n:
                    if (long.TryParse(n.Raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long l))
                        sb.Append(l.ToString(CultureInfo.InvariantCulture));
                    else if (PlainDecimal.IsMatch(n.Raw))
                        sb.Append(n.Raw);
                    else
                        throw new ArgumentException($"canonical: number {n.Raw} cannot be written as JS writes it");
                    break;
                case JsonArray a:
                    sb.Append('[');
                    int i = 0;
                    foreach (var item in a) { if (i++ > 0) sb.Append(','); Write(item, sb); }
                    sb.Append(']');
                    break;
                case JsonObject o:
                    // JS `Object.keys(v).sort()` compares UTF-16 code units: ordinal comparison.
                    var keys = new List<string>(o.Keys);
                    keys.Sort(string.CompareOrdinal);
                    sb.Append('{');
                    for (int k = 0; k < keys.Count; k++)
                    {
                        if (k > 0) sb.Append(',');
                        Quote(keys[k], sb);
                        sb.Append(':');
                        Write(o[keys[k]], sb);
                    }
                    sb.Append('}');
                    break;
                default:
                    throw new ArgumentException("canonical: unknown json node " + v.GetType().Name);
            }
        }

        /// <summary>JSON.stringify for a string: <c>\" \\ \b \f \n \r \t</c>, other controls as <c>\u00xx</c>, the rest raw.</summary>
        public static void Quote(string s, StringBuilder sb)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < ' ') sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
    }
}
