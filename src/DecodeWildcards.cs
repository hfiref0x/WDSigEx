/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       DECODEWILDCARDS.CS
*
*  VERSION:     1.00
*
*  DATE:        12 Apr 2026
*
*  Windows Defender definitions wildcards decode logic.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

using System.Text;

public static partial class WDSigEx
{
    /// <summary>
    /// Base class for all tokens produced by <see cref="WildcardPattern.Tokenize"/>.
    /// </summary>
    private abstract class WildcardToken
    {
    }


    /// <summary>
    /// Represents a contiguous run of verbatim bytes that must match exactly.
    /// </summary>
    private sealed class TokLiteral : WildcardToken
    {
        public byte[] Bytes { get; }

        public TokLiteral(byte[] bytes)
        {
            Bytes = bytes ?? Array.Empty<byte>();
        }
    }

    /// <summary>
    /// Represents a wildcard gap: a variable- or fixed-length run of arbitrary
    /// bytes that the scan engine is allowed to skip over.
    /// </summary>
    private sealed class TokGap : WildcardToken
    {
        public int Max { get; }
        public bool Exact { get; }

        private TokGap(int max, bool exact)
        {
            Max = max < 0 ? 0 : max;
            Exact = exact;
        }

        public static TokGap Make(int param, bool exact)
        {
            return new TokGap(param, exact);
        }

        internal static TokGap InternalMake(int max, bool exact)
        {
            return new TokGap(max, exact);
        }
    }

    /// <summary>
    /// Stateless utility class that tokenises a Defender wildcard-pattern byte
    /// sequence and renders the resulting token list into human-readable or
    /// YARA-compatible strings.
    /// </summary>
    private static class WildcardPattern
    {
        /// <summary>
        /// Tokenises a slice of a Defender signature payload into a flat list of
        /// <see cref="WildcardToken"/> instances.
        /// </summary>
        public static List<WildcardToken> Tokenize(byte[] buf, int start, int length, out int consumed, out bool foundTerminator)
        {
            consumed = 0;
            foundTerminator = false;

            List<WildcardToken> tokens = new();
            if (buf == null)
                return tokens;
            if (length < 0)
                length = buf.Length - start;

            int end = start + length;
            if (start < 0 || end > buf.Length)
                return tokens;

            int i = start;
            int litStart = i;
            bool strictNextGapExact = false;

            void FlushLiteralUpTo(int pos)
            {
                int n = pos - litStart;
                if (n > 0)
                {
                    byte[] bytes = new byte[n];
                    Buffer.BlockCopy(buf, litStart, bytes, 0, n);
                    tokens.Add(new TokLiteral(bytes));
                }
                litStart = pos;
            }

            while (i < end)
            {
                if (i + 1 < end && buf[i] == 0x90 && buf[i + 1] == 0x00)
                {
                    FlushLiteralUpTo(i);
                    foundTerminator = true;
                    consumed = i - start;
                    return CoalesceGaps(tokens);
                }

                if (buf[i] != 0x90)
                {
                    i++;
                    continue;
                }

                FlushLiteralUpTo(i);

                if (i + 1 < end && buf[i + 1] == 0x90)
                {
                    tokens.Add(new TokLiteral(new byte[] { 0x90 }));
                    i += 2;
                    litStart = i;
                    continue;
                }

                if (i + 1 >= end)
                {
                    tokens.Add(new TokLiteral(new byte[] { 0x90 }));
                    i += 1;
                    litStart = i;
                    continue;
                }

                byte op = buf[i + 1];

                if (op >= 0x32)
                {
                    tokens.Add(new TokLiteral(new byte[] { 0x90, op }));
                    i += 2;
                    litStart = i;
                    continue;
                }

                if (op == 23)
                {
                    if (i + 2 >= end)
                    {
                        tokens.Add(new TokLiteral(Slice(buf, i, Math.Min(2, end - i))));
                        i += Math.Min(2, end - i);
                        litStart = i;
                        continue;
                    }

                    int p8 = buf[i + 2];
                    tokens.Add(TokGap.Make(p8, strictNextGapExact));
                    strictNextGapExact = false;
                    i += 3;
                    litStart = i;
                    continue;
                }

                if (op >= 0x01 && op <= 0x03)
                {
                    if (i + 2 >= end)
                    {
                        tokens.Add(new TokLiteral(Slice(buf, i, Math.Min(2, end - i))));
                        i += Math.Min(2, end - i);
                        litStart = i;
                        continue;
                    }

                    int p8 = buf[i + 2];
                    tokens.Add(TokGap.Make(p8, strictNextGapExact));
                    strictNextGapExact = false;
                    i += 3;
                    litStart = i;
                    continue;
                }

                if (op == 0x04 || op == 0x05 || op == 0x19 || op == 0x1A)
                {
                    if (i + 3 >= end)
                    {
                        tokens.Add(new TokLiteral(Slice(buf, i, Math.Min(2, end - i))));
                        i += Math.Min(2, end - i);
                        litStart = i;
                        continue;
                    }

                    int p8 = buf[i + 3];
                    tokens.Add(TokGap.Make(p8, strictNextGapExact));
                    strictNextGapExact = false;
                    i += 4;
                    litStart = i;
                    continue;
                }

                if (op == 0x09)
                {
                    if (i + 3 >= end)
                    {
                        tokens.Add(new TokLiteral(Slice(buf, i, Math.Min(2, end - i))));
                        i += Math.Min(2, end - i);
                        litStart = i;
                        continue;
                    }

                    int p16 = buf[i + 2] | (buf[i + 3] << 8);
                    tokens.Add(TokGap.Make(p16, strictNextGapExact));
                    strictNextGapExact = false;
                    i += 4;
                    litStart = i;
                    continue;
                }

                if (op == 0x1B)
                {
                    strictNextGapExact = true;
                    i += 2;
                    litStart = i;
                    continue;
                }

                if (i + 2 < end)
                {
                    bool have16 = i + 3 < end;
                    if (have16)
                    {
                        int lo = buf[i + 2];
                        int hi = buf[i + 3];
                        bool looksWord = hi == 0x00 || (lo <= 0x20 && hi <= 0x04);
                        if (looksWord)
                        {
                            int p16 = lo | (hi << 8);
                            tokens.Add(TokGap.Make(p16, strictNextGapExact));
                            strictNextGapExact = false;
                            i += 4;
                            litStart = i;
                            continue;
                        }
                    }

                    int p8 = buf[i + 2];
                    tokens.Add(TokGap.Make(p8, strictNextGapExact));
                    strictNextGapExact = false;
                    i += 3;
                    litStart = i;
                    continue;
                }

                tokens.Add(new TokLiteral(new byte[] { 0x90, op }));
                i += 2;
                litStart = i;
            }

            FlushLiteralUpTo(end);
            consumed = end - start;
            return CoalesceGaps(tokens);
        }

        /// <summary>
        /// Renders a token list as a compact, human-readable pattern string.
        /// </summary>
        public static string RenderHuman(List<WildcardToken> tokens)
        {
            StringBuilder sb = new();

            for (int i = 0; i < tokens.Count; i++)
            {
                if (tokens[i] is TokLiteral lit)
                {
                    sb.Append(ToSafeAscii(lit.Bytes));
                }
                else if (tokens[i] is TokGap gap)
                {
                    if (gap.Exact)
                        sb.AppendFormat("[=WILD:{0}]", Math.Max(0, gap.Max));
                    else
                        sb.AppendFormat("[=WILD:0x{0:X}]", Math.Max(0, gap.Max));
                }
            }

            return sb.ToString();
        }

        /// <summary>
        /// Renders a token list as a YARA-compatible hex string.
        /// </summary>
        public static string RenderYaraHex(List<WildcardToken> tokens)
        {
            StringBuilder sb = new();

            for (int i = 0; i < tokens.Count; i++)
            {
                if (i > 0)
                    sb.Append(' ');

                if (tokens[i] is TokLiteral lit)
                {
                    for (int j = 0; j < lit.Bytes.Length; j++)
                    {
                        sb.Append(lit.Bytes[j].ToString("X2"));
                        if (j + 1 < lit.Bytes.Length)
                            sb.Append(' ');
                    }
                }
                else if (tokens[i] is TokGap gap)
                {
                    int n = Math.Max(0, gap.Max);
                    if (n == 0)
                    {
                        if (sb.Length > 0 && sb[sb.Length - 1] == ' ')
                            sb.Length -= 1;
                        continue;
                    }

                    if (gap.Exact)
                        sb.AppendFormat("[{0}]", n);
                    else
                        sb.AppendFormat("[0-{0}]", n);
                }
            }

            return sb.ToString();
        }

        /// <summary>
        /// Merges adjacent <see cref="TokGap"/> tokens in <paramref name="src"/>
        /// into single, combined gap tokens.
        /// </summary>
        private static List<WildcardToken> CoalesceGaps(List<WildcardToken> src)
        {
            List<WildcardToken> result = new(src.Count);
            TokGap? acc = null;

            for (int i = 0; i < src.Count; i++)
            {
                if (src[i] is not TokGap g)
                {
                    if (acc != null)
                    {
                        result.Add(acc);
                        acc = null;
                    }

                    result.Add(src[i]);
                    continue;
                }

                if (acc == null)
                {
                    acc = g;
                    continue;
                }

                bool exact = acc.Exact && g.Exact;
                int max = acc.Max + g.Max;
                acc = TokGap.InternalMake(max, exact);
            }

            if (acc != null)
                result.Add(acc);

            return result;
        }

        /// <summary>
        /// Returns a sub-array of <paramref name="src"/> starting at
        /// <paramref name="start"/> with at most <paramref name="len"/> bytes,
        /// clamped to the actual remaining length of the buffer.
        /// </summary>
        /// <param name="src">Source buffer.</param>
        /// <param name="start">Start index within src.</param>
        /// <param name="len">Requested number of bytes.</param>
        private static byte[] Slice(byte[] src, int start, int len)
        {
            if (src == null || start >= src.Length || len <= 0)
                return Array.Empty<byte>();

            int n = Math.Min(len, src.Length - start);
            byte[] dst = new byte[n];
            Buffer.BlockCopy(src, start, dst, 0, n);
            return dst;
        }

        /// <summary>
        /// Converts a byte array to a printable ASCII string, replacing any byte
        /// outside the printable range (0x20–0x7E) with a dot ('.').
        /// </summary>
        private static string ToSafeAscii(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
                return string.Empty;

            StringBuilder sb = new(bytes.Length);
            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];
                if (b >= 0x20 && b <= 0x7E)
                    sb.Append((char)b);
                else
                    sb.Append('.');
            }

            return sb.ToString();
        }
    }
}
