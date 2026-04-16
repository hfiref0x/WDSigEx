/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       DECODEHELPERS.CS
*
*  VERSION:     1.00
*
*  DATE:        15 Apr 2026
*
*  Helpers routines used when decoding Windows Defender signatures.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

using System.Text;
using System.Text.Json;

public static partial class WDSigEx
{
    /// <summary>
    /// Provides utility methods for extracting and cleaning textual data from raw signature payloads.
    /// </summary>
    private static class DecodeTextHelper
    {
        /// <summary>
        /// Scans the byte array to collect all potential strings, checking both ASCII and UTF-16 encodings.
        /// </summary>
        /// <param name="data">The raw signature payload bytes.</param>
        /// <param name="minLen">The minimum required length for a string candidate to be considered.</param>
        /// <returns>A list of all collected string candidates from both encodings.</returns>
        public static List<string> CollectCandidateStrings(byte[] data, int minLen)
        {
            List<string> result = new();

            if (data == null || data.Length == 0)
                return result;

            string ascii = ExtractAsciiStrings(data, minLen);
            string utf16 = ExtractUtf16AsciiStrings(data, minLen);

            AddSplitLines(result, ascii);
            AddSplitLines(result, utf16);

            return result;
        }

        /// <summary>
        /// Splits a multi-line string into individual lines and adds them to the results list.
        /// </summary>
        /// <param name="result">The master list where extracted strings are added.</param>
        /// <param name="value">The raw string content potentially containing multiple lines.</param>
        public static void AddSplitLines(List<string> result, string value)
        {
            if (result == null || string.IsNullOrWhiteSpace(value))
                return;

            // Split by common line endings (\r\n or \n).
            string[] lines = value.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < lines.Length; i++)
            {
                string s = lines[i].Trim();
                if (!string.IsNullOrWhiteSpace(s))
                    result.Add(s);
            }
        }

        /// <summary>
        /// Filters, normalizes, and deduplicates a list of candidate strings based on specified criteria.
        /// </summary>
        /// <param name="input">The collection of raw string candidates.</param>
        /// <param name="ignoreCase">If true, comparisons are case-insensitive.</param>
        /// <param name="trimTrailingBackslash">If true, removes trailing backslashes from paths.</param>
        /// <param name="normalizeSlashes">If true, replaces forward slashes ('/') with backslashes ('\').</param>
        /// <returns>A list of unique, cleaned strings.</returns>
        public static List<string> NormalizeAndDistinct(IEnumerable<string> input, bool ignoreCase = true, bool trimTrailingBackslash = false, bool normalizeSlashes = false)
        {
            StringComparer comparer = ignoreCase ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
            HashSet<string> seen = new(comparer);
            List<string> result = new();

            foreach (string? raw in input)
            {
                if (raw == null)
                    continue;

                string s = raw.Trim().TrimEnd('\0');
                if (string.IsNullOrWhiteSpace(s))
                    continue;

                if (normalizeSlashes)
                    s = s.Replace('/', '\\');

                if (trimTrailingBackslash)
                    s = s.TrimEnd('\\');

                if (seen.Add(s))
                    result.Add(s);
            }

            return result;
        }

        /// <summary>
        /// Extracts contiguous sequences of printable ASCII characters from the buffer, treating non-printable bytes as delimiters.
        /// </summary>
        /// <param name="buffer">The raw byte array to scan.</param>
        /// <param name="minLen">Minimum length required for an extracted string.</param>
        /// <returns>A single string containing all collected ASCII sequences, separated by newlines.</returns>
        private static string ExtractAsciiStrings(byte[] buffer, int minLen)
        {
            StringBuilder result = new();
            StringBuilder current = new();

            for (int i = 0; i < buffer.Length; i++)
            {
                byte b = buffer[i];

                // Check for printable ASCII range (Space to Tilde).
                if (b >= 0x20 && b <= 0x7E)
                {
                    current.Append((char)b);
                }
                else
                {
                    // Append the completed string, separated by a newline if other strings were already added.
                    if (current.Length >= minLen)
                    {
                        if (result.Length > 0)
                            result.AppendLine();
                        result.Append(current.ToString());
                    }

                    current.Clear();
                }
            }

            // Handle any remaining sequence at the end of the buffer.
            if (current.Length >= minLen)
            {
                if (result.Length > 0)
                    result.AppendLine();
                result.Append(current.ToString());
            }

            return result.ToString();
        }

        /// <summary>
        /// Extracts contiguous sequences of characters encoded in UTF-16 (little-endian), treating null bytes as delimiters.
        /// </summary>
        /// <param name="buffer">The raw byte array to scan.</param>
        /// <param name="minLen">Minimum length required for an extracted string.</param>
        /// <returns>A single string containing all collected UTF-16 sequences, separated by newlines.</returns>
        private static string ExtractUtf16AsciiStrings(byte[] buffer, int minLen)
        {
            if (buffer.Length < 2)
                return string.Empty;

            StringBuilder result = new();
            StringBuilder current = new();

            int i = 0;
            while (i + 1 < buffer.Length)
            {
                byte lo = buffer[i];
                byte hi = buffer[i + 1];

                // Check for valid UTF-16 character structure (High byte is zero, Low byte is printable ASCII).
                if (hi == 0x00 && lo >= 0x20 && lo <= 0x7E)
                {
                    current.Append((char)lo);
                }
                else // Delimiter found (null byte or invalid sequence start)
                {
                    if (current.Length >= minLen)
                    {
                        if (result.Length > 0)
                            result.AppendLine();
                        result.Append(current.ToString());
                    }

                    current.Clear();
                }

                i += 2; // Advance by two bytes for UTF-16.
            }

            // Handle any remaining sequence at the end of the buffer.
            if (current.Length >= minLen)
            {
                if (result.Length > 0)
                    result.AppendLine();
                result.Append(current.ToString());
            }

            return result.ToString();
        }
    }

    private static class DecodeHexHelper
    {
        /// <summary>
        /// Converts a segment of raw bytes into a continuous hexadecimal string representation.
        /// </summary>
        /// <param name="data">The byte array.</param>
        /// <param name="offset">The starting offset in the byte array.</param>
        /// <param name="length">The number of bytes to convert.</param>
        /// <returns>A string containing all hex characters concatenated (e.g., "A1B2C3").</returns>
        public static string ToHex(byte[] data, int offset, int length)
        {
            if (data == null || length <= 0 || offset < 0 || offset + length > data.Length)
                return string.Empty;

            char[] chars = new char[length * 2];
            int k = 0;

            for (int i = 0; i < length; i++)
            {
                byte v = data[offset + i];
                chars[k++] = (char)((v >> 4) < 10 ? '0' + (v >> 4) : 'A' + ((v >> 4) - 10));
                chars[k++] = (char)((v & 0x0F) < 10 ? '0' + (v & 0x0F) : 'A' + ((v & 0x0F) - 10));
            }

            return new string(chars);
        }

        /// <summary>
        /// Converts a segment of raw bytes into a space-separated hexadecimal string representation.
        /// </summary>
        /// <param name="data">The byte array.</param>
        /// <param name="offset">The starting offset in the byte array.</param>
        /// <param name="length">The number of bytes to convert.</param>
        /// <returns>A string containing hex pairs separated by spaces (e.g., "A1 B2 C3").</returns>
        public static string ToHexSpaced(byte[] data, int offset, int length)
        {
            if (data == null || length <= 0 || offset < 0 || offset + length > data.Length)
                return string.Empty;

            StringBuilder sb = new(length * 3);
            for (int i = 0; i < length; i++)
            {
                sb.Append(data[offset + i].ToString("X2"));
                if (i + 1 < length)
                    sb.Append(' ');
            }

            return sb.ToString();
        }
    }

    private static class DecodeResultFactory
    {
        /// <summary>
        /// Creates a DecodedSignature object representing raw, unparsed binary data (Blob Fallback).
        /// </summary>
        /// <param name="context">Metadata about the record.</param>
        /// <param name="data">The raw payload bytes.</param>
        /// <param name="notes">Descriptive notes for the blob.</param>
        /// <param name="confidence">The confidence level assigned to this result.</param>
        /// <returns>A DecodedSignature object marked as BLOB.</returns>
        public static DecodedSignature CreateBlobFallback(SignatureParserContext context, byte[]? data, string notes, string confidence = "Low")
        {
            DecodedSignature decoded = new()
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "BLOB",
                ConditionValue = data == null ? 0 : data.Length,
                DecodeConfidence = confidence,
                Notes = notes ?? string.Empty
            };

            if (data != null && data.Length > 0)
                decoded.Pattern.Add(DecodeHexHelper.ToHexSpaced(data, 0, data.Length));

            return decoded;
        }

        /// <summary>
        /// Creates a DecodedSignature object representing successfully extracted textual or structured data.
        /// </summary>
        /// <param name="context">Metadata about the record.</param>
        /// <param name="conditionType">The specific type of data found (e.g., "DEFAULTS_DATA").</param>
        /// <param name="values">The list of extracted, normalized strings/data points.</param>
        /// <param name="confidence">The confidence level assigned to this result.</param>
        /// <param name="notes">Descriptive notes for the extraction.</param>
        /// <returns>A DecodedSignature object marked with the specified condition type.</returns>
        public static DecodedSignature CreateTextResult(SignatureParserContext context, string conditionType, IEnumerable<string> values, string confidence, string notes)
        {
            DecodedSignature decoded = new()
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = conditionType,
                ConditionValue = 0,
                DecodeConfidence = confidence,
                Notes = notes ?? string.Empty
            };

            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    decoded.Pattern.Add(value);
            }
            // ConditionValue is set to the count of successfully added pattern entries.
            decoded.ConditionValue = decoded.Pattern.Count;
            return decoded;
        }
    }

    private static class DecodeGridHelper
    {
        /// <summary>
        /// Attempts to parse a byte array as a structured hex grid, iterating through various header and entry size combinations.
        /// </summary>
        /// <param name="data">The raw payload bytes.</param>
        /// <param name="candidateHeaderSizes">Possible sizes for the initial header (e.g., 0, 2, 4).</param>
        /// <param name="candidateEntrySizes">Possible fixed sizes for each data entry in the grid.</param>
        /// <param name="acceptedTailPads">List of possible padding lengths at the end of the payload.</param>
        /// <param name="chosenHeaderSize">Output: The size of the header that successfully parsed.</param>
        /// <param name="chosenEntrySize">Output: The fixed size of each data entry.</param>
        /// <param name="usedLength">Output: The total length consumed by the successful grid structure.</param>
        /// <param name="entries">Output: A list containing the hex representation of every parsed entry.</param>
        /// <returns>True if a plausible grid structure was found; otherwise, false.</returns>
        public static bool TryParseHexGrid(
            byte[] data,
            int[] candidateHeaderSizes,
            int[] candidateEntrySizes,
            int[] acceptedTailPads,
            out int chosenHeaderSize,
            out int chosenEntrySize,
            out int usedLength,
            out List<string> entries)
        {
            chosenHeaderSize = 0;
            chosenEntrySize = 0;
            usedLength = 0;
            entries = new();

            for (int i = 0; i < candidateHeaderSizes.Length; i++)
            {
                int headerSize = candidateHeaderSizes[i];

                for (int j = 0; j < candidateEntrySizes.Length; j++)
                {
                    int entrySize = candidateEntrySizes[j];
                    List<string> currentEntries;
                    int currentUsed;

                    // Attempt to parse the grid structure with current sizes and padding options.
                    if (!TryParseHexGridWithSizes(data, headerSize, entrySize, acceptedTailPads, out currentEntries, out currentUsed))
                        continue;

                    // Validate that the extracted entries look like meaningful data (not all zeros or all FFs).
                    if (!LooksPlausibleHexEntryList(currentEntries))
                        continue;

                    chosenHeaderSize = headerSize;
                    chosenEntrySize = entrySize;
                    usedLength = currentUsed;
                    entries = currentEntries;
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Attempts to parse the grid structure given fixed sizes, checking against possible padding lengths.
        /// </summary>
        private static bool TryParseHexGridWithSizes(
            byte[] data,
            int headerSize,
            int entrySize,
            int[] acceptedTailPads,
            out List<string> entries,
            out int usedLength)
        {
            entries = new();
            usedLength = 0;

            if (data == null || data.Length == 0)
                return false;
            // Header size must be one of the expected values (0, 2, or 4 bytes).
            if (!(headerSize == 0 || headerSize == 2 || headerSize == 4))
                return false;
            if (entrySize <= 0)
                return false;
            if (data.Length < headerSize + entrySize)
                return false;

            int count;
            int start = headerSize;

            // Logic for fixed-size headers (2 or 4 bytes) to determine the node count dynamically.
            if (headerSize == 2)
            {
                count = data[0] | (data[1] << 8);
                if (count <= 0)
                    return false;

                for (int i = 0; i < acceptedTailPads.Length; i++)
                {
                    int pad = acceptedTailPads[i];
                    if (start + count * entrySize + pad == data.Length)
                    {
                        usedLength = start + count * entrySize;
                        return ExtractEntries(data, start, entrySize, count, out entries);
                    }
                }

                return false;
            }

            if (headerSize == 4)
            {
                count = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
                if (count <= 0)
                    return false;

                for (int i = 0; i < acceptedTailPads.Length; i++)
                {
                    int pad = acceptedTailPads[i];
                    if (start + count * entrySize + pad == data.Length)
                    {
                        usedLength = start + count * entrySize;
                        return ExtractEntries(data, start, entrySize, count, out entries);
                    }
                }

                return false;
            }

            // Logic for variable/implicit header size (headerSize == 0).
            int len = data.Length - start;
            if (len < entrySize)
                return false;

            // Check if the remaining length is perfectly divisible by the entry size.
            if (len % entrySize == 0)
            {
                count = len / entrySize;
                usedLength = start + count * entrySize;
                return ExtractEntries(data, start, entrySize, count, out entries);
            }

            // Check against padding options if not perfectly divisible.
            for (int i = 0; i < acceptedTailPads.Length; i++)
            {
                int pad = acceptedTailPads[i];
                int dataLen = len - pad;
                if (dataLen > 0 && dataLen % entrySize == 0)
                {
                    count = dataLen / entrySize;
                    usedLength = start + count * entrySize;
                    return ExtractEntries(data, start, entrySize, count, out entries);
                }
            }

            return false;
        }

        /// <summary>
        /// Extracts the specified number of hex-encoded entries from the data buffer.
        /// </summary>
        private static bool ExtractEntries(byte[] data, int start, int entrySize, int count, out List<string> entries)
        {
            entries = new(count);
            int pos = start;

            for (int i = 0; i < count; i++, pos += entrySize)
            {
                if (pos + entrySize > data.Length)
                    return false;

                entries.Add(DecodeHexHelper.ToHex(data, pos, entrySize));
            }

            return entries.Count > 0;
        }

        /// <summary>
        /// Validates if the extracted list of hex strings is plausible (i.e., not entirely zero or entirely FFs, and has at least two unique values).
        /// </summary>
        private static bool LooksPlausibleHexEntryList(List<string> entries)
        {
            if (entries.Count == 0)
                return false;

            HashSet<string> unique = new(StringComparer.Ordinal);
            bool allZero = true;
            bool allFF = true;

            for (int i = 0; i < entries.Count; i++)
            {
                string value = entries[i];
                unique.Add(value);

                if (!IsAllChar(value, '0'))
                    allZero = false;
                if (!IsAllChar(value, 'F'))
                    allFF = false;
            }

            // Reject lists that are uniform (all zero or all FF) or too small/non-diverse.
            if (allZero || allFF)
                return false;
            if (unique.Count < Math.Min(2, entries.Count))
                return false;

            return true;
        }

        /// <summary>
        /// Helper to check if every character in a string matches a specific character.
        /// </summary>
        private static bool IsAllChar(string value, char c)
        {
            if (string.IsNullOrEmpty(value))
                return false;

            for (int i = 0; i < value.Length; i++)
            {
                if (value[i] != c)
                    return false;
            }

            return true;
        }
    }

    /// <summary>
    /// Determines the correct directory path for saving decoded threat information based on its name and category.
    /// </summary>
    /// <param name="decodeDirectory">The root directory where all decoded data should be saved.</param>
    /// <param name="threat">The Threat object containing the resolved name.</param>
    /// <returns>The fully qualified path to the threat's specific decoding folder.</returns>
    private static string GetThreatDecodeDirectory(string decodeDirectory, Threat threat)
    {
        string category;
        string platform;
        string path;

        // Determine the logical category and platform from the threat name.
        GetThreatCategoryAndPlatform(threat.ResolvedThreatName, out category, out platform);

        path = Path.Combine(decodeDirectory, category, platform);
        Directory.CreateDirectory(path); // Ensure the directory structure exists.
        return path;
    }

    /// <summary>
    /// Parses a threat's resolved name to extract its logical category and operating system/platform identifier.
    /// </summary>
    /// <param name="threatName">The full, resolved name of the threat.</param>
    /// <param name="category">Output: The extracted threat category.</param>
    /// <param name="platform">Output: The extracted platform identifier.</param>
    private static void GetThreatCategoryAndPlatform(string threatName, out string category, out string platform)
    {
        string rawCategory;
        string rawPlatform;
        int colonIndex;
        int slashIndex;

        category = "Unknown";
        platform = "Unknown";

        if (string.IsNullOrWhiteSpace(threatName))
            return;

        threatName = threatName.Trim();

        // Attempt to split by ':' or '/' to find category/platform delimiters.
        colonIndex = threatName.IndexOf(':');
        slashIndex = threatName.IndexOf('/');

        if (colonIndex > 0)
        {
            rawCategory = threatName.Substring(0, colonIndex).Trim();
        }
        else if (slashIndex > 0)
        {
            rawCategory = threatName.Substring(0, slashIndex).Trim();
        }
        else
        {
            rawCategory = threatName.Trim(); // Use the whole name as category if no separator found.
        }

        // Extract platform based on position of separators.
        rawPlatform = ExtractThreatPlatform(threatName, colonIndex, slashIndex);

        // Normalize extracted parts to filesystem-safe names.
        rawCategory = NormalizeThreatPathPart(rawCategory, "Unknown");
        rawPlatform = NormalizeThreatPathPart(rawPlatform, "Unknown");

        category = rawCategory;
        platform = rawPlatform;
    }

    /// <summary>
    /// Extracts the platform identifier from a threat name based on separator positions.
    /// </summary>
    private static string ExtractThreatPlatform(string threatName, int colonIndex, int slashIndex)
    {
        string rawPlatform;

        // Case 1: Platform follows a colon (e.g., "Malware:Win32").
        if (colonIndex < 0)
            return "Unknown";

        // Case 2: Platform is between ':' and '/'.
        if (slashIndex > colonIndex + 1)
        {
            rawPlatform = threatName.Substring(colonIndex + 1, slashIndex - colonIndex - 1).Trim();
            if (!string.IsNullOrWhiteSpace(rawPlatform))
                return rawPlatform;
        }

        // Case 3: Platform follows a colon and is the remainder of the string (e.g., "Malware:Win32_Variant").
        if (colonIndex + 1 < threatName.Length)
        {
            rawPlatform = threatName.Substring(colonIndex + 1).Trim();
            // Stop at the next separator or space to isolate the platform name.
            int nextSeparator = rawPlatform.IndexOfAny(new[] { '/', '.', '!', ' ' });
            if (nextSeparator > 0)
                rawPlatform = rawPlatform.Substring(0, nextSeparator).Trim();

            if (!string.IsNullOrWhiteSpace(rawPlatform))
                return rawPlatform;
        }

        return "Unknown";
    }

    /// <summary>
    /// Sanitizes a string segment to be safe for use as a directory or file name by removing illegal characters.
    /// </summary>
    private static string NormalizeThreatPathPart(string value, string fallback)
    {
        if (string.IsNullOrWhiteSpace(value))
            return fallback;

        value = value.Trim();

        // Truncate the string at the first occurrence of a path separator or illegal character.
        int separator = value.IndexOfAny(new[] { '/', '\\', ':', '*', '?', '"', '<', '>', '|' });
        if (separator >= 0)
            value = value.Substring(0, separator).Trim();

        value = SanitizeFileName(value);

        if (string.IsNullOrWhiteSpace(value))
            return fallback;

        return value;
    }

    /// <summary>
    /// Saves the detailed decoded signature information for a single threat into a human-readable text file.
    /// </summary>
    /// <param name="threat">The Threat object containing all parsed signatures.</param>
    /// <param name="decodeDirectory">The root directory where the output files should be placed.</param>
    private static void SaveThreatDecodedText(Threat threat, string decodeDirectory)
    {
        string safeName;
        string threatDirectory;
        string outputPath;

        if (threat.DecodedSignatures.Count == 0)
            return;

        safeName = SanitizeFileName(threat.ResolvedThreatName);
        threatDirectory = GetThreatDecodeDirectory(decodeDirectory, threat);
        outputPath = Path.Combine(threatDirectory, safeName + "_" + threat.ThreatId + ".txt");

        using StreamWriter writer = new(outputPath, false, new UTF8Encoding(false));

        writer.WriteLine("Threat: " + threat.ResolvedThreatName);
        writer.WriteLine("ThreatId: " + threat.ThreatId);
        writer.WriteLine("BeginPosition: " + threat.BeginPosition);
        writer.WriteLine("EndPosition: " + threat.EndPosition);
        writer.WriteLine();

        for (int i = 0; i < threat.DecodedSignatures.Count; i++)
        {
            DecodedSignature sig = threat.DecodedSignatures[i];

            writer.WriteLine($"[{i + 1}] {sig.Type}");
            writer.WriteLine($"  Offset: {sig.Offset}");
            writer.WriteLine($"  ConditionType: {sig.ConditionType}");
            writer.WriteLine($"  ConditionValue: {sig.ConditionValue}");
            writer.WriteLine($"  DecodeConfidence: {sig.DecodeConfidence}");

            if (!string.IsNullOrWhiteSpace(sig.Notes))
                writer.WriteLine($"  Notes: {sig.Notes}");

            if (sig.Pattern.Count > 0)
            {
                writer.WriteLine("  Pattern:");
                for (int j = 0; j < sig.Pattern.Count; j++)
                    writer.WriteLine("    " + sig.Pattern[j]);
            }

            writer.WriteLine();
        }
    }

    /// <summary>
    /// Saves the detailed decoded signature information for a single threat into a structured JSON file.
    /// </summary>
    /// <param name="threat">The Threat object containing all parsed signatures.</param>
    /// <param name="decodeDirectory">The root directory where the output files should be placed.</param>
    private static void SaveThreatDecodedJson(Threat threat, string decodeDirectory)
    {
        string safeName;
        string threatDirectory;
        string outputPath;

        if (threat.DecodedSignatures.Count == 0)
            return;

        safeName = SanitizeFileName(threat.ResolvedThreatName);
        threatDirectory = GetThreatDecodeDirectory(decodeDirectory, threat);
        outputPath = Path.Combine(threatDirectory, safeName + "_" + threat.ThreatId + ".json");

        JsonSerializerOptions jsonOptions = new()
        {
            WriteIndented = true
        };

        // Structure the data for JSON serialization.
        string json = JsonSerializer.Serialize(new
        {
            threat.ThreatId,
            ThreatName = threat.ResolvedThreatName,
            ThreatNameFromFile = threat.ThreatNameFromFile,
            ThreatNameFromCatalog = threat.ThreatNameFromCatalog,
            threat.BeginPosition,
            threat.EndPosition,
            DecodedSignatures = threat.DecodedSignatures
        }, jsonOptions);

        File.WriteAllText(outputPath, json, new UTF8Encoding(false));
    }

    /// <summary>
    /// Generates and saves a summary report of all decoded signatures across all threats in text format.
    /// </summary>
    /// <param name="options">The decoding options object.</param>
    /// <param name="decodeDirectory">The directory to save the summary file.</param>
    private static void SaveDecodeSummaryText(Options options, string decodeDirectory)
    {
        string outputPath = Path.Combine(decodeDirectory, "decode_summary.txt");
        // Key: SignatureType; Value: (Total Count, High Confidence, Medium Confidence, Low Confidence)
        Dictionary<string, (int Count, int High, int Medium, int Low)> rows = new(StringComparer.Ordinal);

        foreach (Threat threat in GetFilteredThreats(options))
        {
            for (int i = 0; i < threat.DecodedSignatures.Count; i++)
            {
                DecodedSignature sig = threat.DecodedSignatures[i];
                if (!rows.TryGetValue(sig.Type, out var row))
                    row = (0, 0, 0, 0);

                row.Count++;

                if (string.Equals(sig.DecodeConfidence, "High", StringComparison.OrdinalIgnoreCase))
                    row.High++;
                else if (string.Equals(sig.DecodeConfidence, "Medium", StringComparison.OrdinalIgnoreCase))
                    row.Medium++;
                else
                    row.Low++;

                rows[sig.Type] = row;
            }
        }

        using StreamWriter writer = new(outputPath, false, Encoding.UTF8);

        writer.WriteLine("Decode summary");
        writer.WriteLine();

        // Output results sorted by Signature Type name.
        foreach (var kv in rows.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            writer.WriteLine($"{kv.Key}: Count={kv.Value.Count}, High={kv.Value.High}, Medium={kv.Value.Medium}, Low={kv.Value.Low}");
        }

        int decodedThreatFiles = GetFilteredThreats(options).Count(t => t.DecodedSignatures.Count > 0);

        writer.WriteLine();
        writer.WriteLine($"Decoded threat files: {decodedThreatFiles}");
    }

    /// <summary>
    /// Generates and saves a summary report of all decoded signatures across all threats in JSON format.
    /// </summary>
    /// <param name="options">The decoding options object.</param>
    /// <param name="decodeDirectory">The directory to save the summary file.</param>
    private static void SaveDecodeSummaryJson(Options options, string decodeDirectory)
    {
        string outputPath = Path.Combine(decodeDirectory, "decode_summary.json");

        Dictionary<string, object> rows = new(StringComparer.Ordinal);

        foreach (Threat threat in GetFilteredThreats(options))
        {
            for (int i = 0; i < threat.DecodedSignatures.Count; i++)
            {
                DecodedSignature sig = threat.DecodedSignatures[i];
                if (!rows.TryGetValue(sig.Type, out object? obj))
                {
                    obj = new DecodeSummaryRow();
                    rows[sig.Type] = obj;
                }

                DecodeSummaryRow row = (DecodeSummaryRow)obj;
                row.Count++;

                if (string.Equals(sig.DecodeConfidence, "High", StringComparison.OrdinalIgnoreCase))
                    row.High++;
                else if (string.Equals(sig.DecodeConfidence, "Medium", StringComparison.OrdinalIgnoreCase))
                    row.Medium++;
                else
                    row.Low++;
            }
        }

        // Map the internal row structure to a cleaner public model for JSON output.
        var model = rows
            .OrderBy(k => k.Key, StringComparer.Ordinal)
            .Select(k => new
            {
                SignatureType = k.Key,
                Count = ((DecodeSummaryRow)k.Value).Count,
                HighConfidence = ((DecodeSummaryRow)k.Value).High,
                MediumConfidence = ((DecodeSummaryRow)k.Value).Medium,
                LowConfidence = ((DecodeSummaryRow)k.Value).Low
            });

        string json = JsonSerializer.Serialize(model, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        File.WriteAllText(outputPath, json, Encoding.UTF8);
    }

    /// <summary>
    /// Internal class used to structure the summary data before JSON serialization.
    /// </summary>
    private sealed class DecodeSummaryRow
    {
        public int Count;
        public int High;
        public int Medium;
        public int Low;
    }

    /// <summary>
    /// Executes the main decoding loop: iterates through threats, applies all registered parsers to signature records, 
    /// and saves results in text/JSON format.
    /// </summary>
    /// <param name="options">Configuration settings for the decoding process.</param>
    private static void RunDecodePhase(Options options)
    {
        // Determine output directory, defaulting to a 'Decode' subdirectory within the main output path.
        string decodeDirectory = string.IsNullOrWhiteSpace(options.DecodeDirectory)
            ? Path.Combine(options.OutputDirectory, "Decode")
            : options.DecodeDirectory;
        Directory.CreateDirectory(decodeDirectory);

        // Initialize the dispatcher with all available parsers.
        SignatureParserDispatcher dispatcher = new(new ISignatureParser[]
        {
            new KcrcexParser(),
            new KcrceParser(),
            new FriendlyFileSha256Parser(),
            new RegKeyParser(),
            new FilePathParser(),
            new FolderNameParser(),
            new AsepFilepathParser(),
            new AsepFoldernameParser(),
            new PuaAppMapParser(),
            new LuaStandaloneParser(),
            new AaAggregatorParser(),
            new DefaultsParser(),
            new StaticParser(),
            new PepCodeParser(),
            new NscriptSpParser(),
            new NscriptCureParser(),
            new NdatParser(),
            new NidLikeParser(),
            new SnidExParser(),
            new BmInfoParser(),
            new Polyvir32Parser(),
            new PestaticParser(),
            new PestaticExParser(),
            new SigTreeParser(),
            new SigTreeExtParser(),
            new SigTreeBmParser(),
            new VersionCheckParser(),
            // Generic parsers for various string types (PEHSTR, DOSHSTR, etc.)
            new GenericWeightedPatternParser("SIGNATURE_TYPE_PEHSTR"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_PEHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_PEHSTR_EXT2"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_DOSHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_ELFHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_MACHOHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_MACROHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_SWFHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_CMDHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_INNOHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_AUTOITHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_ARHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_MDBHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_DMGHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_JAVAHSTR_EXT"),
            new GenericWeightedPatternParser("SIGNATURE_TYPE_DEXHSTR_EXT"),
            new GenericTextDumpParser(),
            new GenericBinarySignatureParser()
        });

        byte[] fileData = File.ReadAllBytes(options.FilePath);
        if (fileData.Length == 0) // Exit if the input file is empty.
            return;

        // Get threats that need processing, sorted by their starting position in the file.
        List<Threat> filteredThreats = GetFilteredThreats(options)
            .OrderBy(t => t.BeginPosition)
            .ToList();

        int totalThreats = filteredThreats.Count;
        int processedThreats = 0;
        int nextProgressPercent = 5;

        if (!options.Quiet)
        {
            Console.WriteLine("Decoding threats...");
        }

        foreach (Threat threat in filteredThreats)
        {
            threat.DecodedSignatures.Clear();

            // Iterate over every signature record associated with the current threat.
            for (int i = 0; i < threat.SignatureRecords.Count; i++)
            {
                SignatureRecord record = threat.SignatureRecords[i];

                // Boundary check: Ensure the record is within the bounds of the file data.
                if (record.DataOffset < 0 || record.DataSize <= 0 || record.DataOffset + record.DataSize > fileData.Length)
                    continue;

                // Extract the raw payload bytes for this specific signature record.
                byte[] payload = new byte[record.DataSize];
                Buffer.BlockCopy(fileData, record.DataOffset, payload, 0, record.DataSize);

                // Create context object containing all necessary metadata for the parser.
                SignatureParserContext context = new()
                {
                    ThreatId = threat.ThreatId,
                    ThreatName = threat.ResolvedThreatName,
                    SignatureType = record.SignatureType,
                    SignatureTypeName = record.SignatureTypeName,
                    RecordOffset = record.RecordOffset,
                    DataOffset = record.DataOffset,
                    OutputDirectory = options.OutputDirectory,
                    ExtractLua = options.ExtractLua
                };

                // Resolve the correct parser based on signature type IDs.
                ISignatureParser? parser = dispatcher.Resolve(record.SignatureType, record.SignatureTypeName);
                if (parser == null)
                    continue;

                try
                {
                    // Execute parsing logic.
                    DecodedSignature? decoded = parser.Parse(context, payload);
                    if (decoded != null)
                        threat.DecodedSignatures.Add(decoded);
                }
                catch (Exception ex)
                {
                    if (!options.Quiet)
                    {
                        Console.WriteLine($"Decode error for threat {threat.ThreatId} ({threat.ResolvedThreatName}), type {record.SignatureTypeName}: {ex.Message}");
                    }
                }
            } // End of signature record loop

            // Save results if any signatures were successfully decoded for this threat.
            if (threat.DecodedSignatures.Count > 0)
            {
                SaveThreatDecodedText(threat, decodeDirectory);

                if (options.DecodeJson)
                    SaveThreatDecodedJson(threat, decodeDirectory);
            }

            processedThreats++;

            // Display progress bar if not in quiet mode and there are threats to process.
            if (!options.Quiet && totalThreats > 0)
            {
                int percent = processedThreats * 100 / totalThreats;
                if (percent >= nextProgressPercent || processedThreats == totalThreats)
                {
                    Console.WriteLine($"  Decode progress: {processedThreats} / {totalThreats} ({percent}%)");
                    while (nextProgressPercent <= percent)
                        nextProgressPercent += 5;
                }
            }
        } // End of threat loop

        // Generate and save the final summary reports.
        SaveDecodeSummaryText(options, decodeDirectory);
        if (options.DecodeJson)
            SaveDecodeSummaryJson(options, decodeDirectory);
    }
}
