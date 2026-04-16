/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       PROGRAM.CS
*
*  VERSION:     1.00
*
*  DATE:        15 Apr 2026
*  
*  Codename:    Gilberta
*
*  WDSigEx commands parsing and entrypoint.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

using System.Text;

/// <summary>
// WDSigEx is a command - line tool for parsing and extracting threat signature
// records from Windows Defender database files after extraction via WDExtract.
/// </summary>
public static partial class WDSigEx
{
    // 
    // Version constants – used only for the banner printed at startup.
    // 
    private const int PROGRAM_MAJOR_VERSION = 1;
    private const int PROGRAM_MINOR_VERSION = 0;
    private const int PROGRAM_REVISION = 0;
    private const int PROGRAM_BUILD = 2604;

    private const byte SIG_TYPE_THREAT_BEGIN = 0x5C;
    private const byte SIG_TYPE_THREAT_END = 0x5D;
    private const int PROGRESS_STEP_BYTES = 16 * 1024 * 1024;

    private static readonly string[] SignatureTypeNames = BuildSignatureTypeNames();

    /// <summary>
    /// All settings parsed from the command line. Passed around by reference
    /// so every subsystem operates on the same configuration.
    /// </summary>
    public sealed class Options
    {
        /// <summary>Path to the raw binary database file to parse.</summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>Directory where all output files will be written.</summary>
        public string OutputDirectory { get; set; } = string.Empty;

        /// <summary>
        /// Optional path to a CSV file mapping numeric threat IDs to names.
        /// When provided, catalog names take precedence over names embedded in
        /// the binary file.
        /// </summary>
        public string CatalogPath { get; set; } = string.Empty;

        /// <summary>
        /// Case-insensitive substring filter: only threats whose resolved name
        /// contains this string will be included in output and exports.
        /// </summary>
        public string ThreatFilter { get; set; } = string.Empty;

        /// <summary>
        /// Filter threats by the presence of at least one record of this
        /// signature type.  Accepts a hex byte (0xNN), a decimal byte, or a
        /// full SIGNATURE_TYPE_* name.
        /// </summary>
        public string SignatureTypeFilter { get; set; } = string.Empty;

        /// <summary>
        /// Directory where decoded signature files are written.  Defaults to
        /// OutputDirectory when empty.
        /// </summary>
        public string DecodeDirectory { get; set; } = string.Empty;

        /// <summary>Suppress informational console output.</summary>
        public bool Quiet { get; set; }

        /// <summary>Skip raw .bin chunk export even when StatsOnly is false.</summary>
        public bool NoExport { get; set; }

        /// <summary>
        /// Produce only statistics files; implies NoExport.  No .bin files or
        /// decoded output will be written.
        /// </summary>
        public bool StatsOnly { get; set; }

        /// <summary>Generate HTML Chart.js bar charts alongside CSV stats.</summary>
        public bool Html { get; set; }

        /// <summary>Run the decode phase after extraction.</summary>
        public bool Decode { get; set; }

        /// <summary>
        /// When true the decode phase writes JSON instead of plain text.
        /// Implies Decode = true.
        /// </summary>
        public bool DecodeJson { get; set; }

        /// <summary>
        /// Skip raw .bin export entirely and only run the decode phase.
        /// Implies Decode = true and NoExport = true.
        /// </summary>
        public bool DecodeOnly { get; set; }

        /// <summary>
        /// Extract data which looks like Lua chunks.
        /// Implies Decode = true.
        /// </summary>
        public bool ExtractLua { get; set; }
    }

    /// <summary>
    /// Metadata describing a single variable-length record found in the binary
    /// stream. The record's raw bytes live in the source file and are not
    /// buffered here; only offsets and sizes are stored so the file can be
    /// seeked later for export.
    /// </summary>
    public sealed class SignatureRecord
    {
        /// <summary>The raw type byte read from the stream (e.g. 0x40).</summary>
        public byte SignatureType { get; set; }

        /// <summary>
        /// Human-readable name resolved from the SignatureTypeNames table
        /// (e.g. "SIGNATURE_TYPE_SIGTREE").
        /// </summary>
        public string SignatureTypeName { get; set; } = string.Empty;

        /// <summary>Byte offset of the type byte itself (start of the record header).</summary>
        public int RecordOffset { get; set; }

        /// <summary>Byte offset of the first data byte (after the 3-byte header).</summary>
        public int DataOffset { get; set; }

        /// <summary>Number of data bytes (does not include the 3-byte header).</summary>
        public int DataSize { get; set; }
    }

    /// <summary>
    /// The result of attempting to interpret a raw signature payload into a
    /// structured, human-readable form. Produced by the optional decode phase.
    /// </summary>
    public sealed class DecodedSignature
    {
        /// <summary>Signature type name (mirrors SignatureRecord.SignatureTypeName).</summary>
        public string Type { get; set; } = string.Empty;

        /// <summary>Hex string representation of the record's file offset.</summary>
        public string Offset { get; set; } = string.Empty;

        /// <summary>
        /// Describes the matching condition encoded in the payload
        /// </summary>
        public string ConditionType { get; set; } = string.Empty;

        /// <summary>Raw numeric condition value extracted from the payload.</summary>
        public int ConditionValue { get; set; }

        /// <summary>
        /// Decoded byte pattern(s) or string tokens from the payload, one entry
        /// per logical sub-pattern.
        /// </summary>
        public List<string> Pattern { get; } = new();

        /// <summary>
        /// Confidence level of the decode: "High", "Medium", or "Low".
        /// High = all fields were understood; Low = partial / heuristic decoding.
        /// </summary>
        public string DecodeConfidence { get; set; } = "Low";

        /// <summary>Optional free-text annotation added by the decoder.</summary>
        public string Notes { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents one threat: a named, uniquely identified group of signature
    /// records bounded by THREAT_BEGIN / THREAT_END sentinels in the binary file.
    /// </summary>
    public sealed class Threat
    {
        /// <summary>Numeric ID embedded in the THREAT_BEGIN record.</summary>
        public uint ThreatId { get; set; }

        /// <summary>Name string read directly from the binary file's THREAT_BEGIN record.</summary>
        public string ThreatNameFromFile { get; set; } = string.Empty;

        /// <summary>Name sourced from the external CSV catalog (empty if not loaded or not found).</summary>
        public string ThreatNameFromCatalog { get; set; } = string.Empty;

        /// <summary>File offset of the THREAT_BEGIN record header byte.</summary>
        public int BeginPosition { get; set; }

        /// <summary>File offset one byte past the last byte of the THREAT_END record payload.</summary>
        public int EndPosition { get; set; }

        public Dictionary<string, long> SignatureStats { get; } = new(StringComparer.Ordinal);

        /// <summary>Ordered list of every non-sentinel record belonging to this threat.</summary>
        public List<SignatureRecord> SignatureRecords { get; } = new();

        /// <summary>Populated by the optional decode phase; empty otherwise.</summary>
        public List<DecodedSignature> DecodedSignatures { get; } = new();

        /// <summary>
        /// The canonical display name used in all output.
        /// </summary>
        public string ResolvedThreatName
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(ThreatNameFromCatalog))
                    return ThreatNameFromCatalog;
                if (!string.IsNullOrWhiteSpace(ThreatNameFromFile))
                    return ThreatNameFromFile;
                return $"Threat_{ThreatId}";
            }
        }
    }

    /// <summary>
    /// Accumulated counters for one complete parse run. All fields are public
    /// so the summary printer can read them directly without property overhead.
    /// </summary>
    public sealed class ParserStats
    {
        /// <summary>Total number of records (headers) encountered, including sentinels.</summary>
        public long TotalRecords;

        /// <summary>Number of THREAT_BEGIN (0x5C) records seen.</summary>
        public long ThreatBegins;

        /// <summary>Number of THREAT_END (0x5D) records seen.</summary>
        public long ThreatEnds;

        /// <summary>Number of .bin files successfully written during export.</summary>
        public long ExportedThreats;

        /// <summary>Threats skipped during export because EndPosition <= BeginPosition.</summary>
        public long SkippedThreats;

        /// <summary>Number of threats that matched the active filters.</summary>
        public long FilterMatchedThreats;

        /// <summary>Number of times an unrecognised type byte caused a record to be skipped</summary>
        public long UnknownSignatureBytesSkipped;

        /// <summary>Histogram of unrecognised type bytes.</summary>
        public Dictionary<byte, long> UnknownSignatureTypes { get; } = new();
    }

    /// <summary>
    /// All threats discovered during the current run, keyed by their 32-bit ID.
    /// </summary>
    private static readonly Dictionary<uint, Threat> Threats = new();

    /// <summary>
    /// Threat ID → name mapping loaded from the optional CSV catalog.
    /// </summary>
    private static readonly Dictionary<uint, string> ThreatDictionary = new();

    /// <summary>
    /// Entry point of the application.
    /// </summary>
    /// <param name="args">Raw command-line arguments.</param>
    /// <returns>0 on success, 1 on argument/file error.</returns>
    public static int Main(string[] args)
    {
        bool catalogLoaded = false;
        Options options;

        Threats.Clear();
        ThreatDictionary.Clear();

        Console.WriteLine($"WDSigEx v{PROGRAM_MAJOR_VERSION}.{PROGRAM_MINOR_VERSION}.{PROGRAM_REVISION}.{PROGRAM_BUILD} (c) 2019 - 2026 hfiref0x");
        Console.WriteLine();

        if (!TryParseArguments(args, out options))
        {
            PrintUsage();
            return 1;
        }

        if (!File.Exists(options.FilePath))
        {
            Console.WriteLine($"{options.FilePath} does not exist.");
            return 1;
        }

        Directory.CreateDirectory(options.OutputDirectory);

        if (!string.IsNullOrWhiteSpace(options.CatalogPath))
        {
            if (File.Exists(options.CatalogPath))
            {
                ReadCatalogCsv(options.CatalogPath);
                if (!options.Quiet)
                    Console.WriteLine($"Loaded catalog entries: {ThreatDictionary.Count}");
                catalogLoaded = true;
            }
            else
            {
                Console.WriteLine($"Catalog CSV not found: {options.CatalogPath}");
                Console.WriteLine("Continuing without external catalog.");
            }
        }
        else if (!options.Quiet)
        {
            Console.WriteLine("No catalog CSV provided. Using threat names embedded in the file.");
        }

        if (!string.IsNullOrWhiteSpace(options.ThreatFilter) && !options.Quiet)
        {
            Console.WriteLine($"Threat filter: \"{options.ThreatFilter}\"");
        }

        if (!string.IsNullOrWhiteSpace(options.SignatureTypeFilter) && !options.Quiet)
        {
            Console.WriteLine($"Signature type filter: \"{options.SignatureTypeFilter}\"");
        }

        if (options.DecodeOnly && !options.Quiet)
        {
            Console.WriteLine("Decode-only mode enabled. Raw threat chunks will not be exported.");
        }

        ParserStats stats = ExtractThreatSignatures(options);

        SaveThreatsToFile(Threats, Path.Combine(options.OutputDirectory, "output.txt"), options);
        if (catalogLoaded)
        {
            SaveMissingThreatsToFile(Threats, ThreatDictionary, Path.Combine(options.OutputDirectory, "missing.txt"));
        }
        SaveStats(options.OutputDirectory, options);

        if (options.Html)
        {
            SaveHtmlCharts(options.OutputDirectory, options);
        }

        // Raw .bin export of each matched threat's byte range from the source file.
        if (!options.NoExport && !options.StatsOnly)
        {
            ExportThreats(options, stats);
        }

        // Optional decode phase: parse signature payloads into structured data.
        if (options.Decode)
        {
            RunDecodePhase(options);
        }

        PrintSummary(stats, options);
        return 0;
    }

    /// <summary>
    /// Parses the raw command-line argument array into an <see cref="Options"/> instance.
    /// </summary>
    /// <param name="args">Raw argv array passed to Main.</param>
    /// <param name="options">Populated on success; partially filled on failure.</param>
    /// <returns>True when all arguments were valid; false otherwise.</returns>
    private static bool TryParseArguments(string[] args, out Options options)
    {
        List<string> positional = new();
        options = new Options();

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (arg.Equals("--quiet", StringComparison.OrdinalIgnoreCase))
            {
                options.Quiet = true;
            }
            else if (arg.Equals("--no-export", StringComparison.OrdinalIgnoreCase))
            {
                options.NoExport = true;
            }
            else if (arg.Equals("--stats-only", StringComparison.OrdinalIgnoreCase))
            {
                options.StatsOnly = true;
                options.NoExport = true;
            }
            else if (arg.Equals("--html", StringComparison.OrdinalIgnoreCase))
            {
                options.Html = true;
            }
            else if (arg.Equals("--decode", StringComparison.OrdinalIgnoreCase))
            {
                options.Decode = true;
            }
            else if (arg.Equals("--decode-json", StringComparison.OrdinalIgnoreCase))
            {
                options.Decode = true;
                options.DecodeJson = true;
            }
            else if (arg.Equals("--decode-dir", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length)
                    return false;

                options.DecodeDirectory = args[++i];
                options.Decode = true;
            }
            else if (arg.Equals("--decode-only", StringComparison.OrdinalIgnoreCase))
            {
                options.DecodeOnly = true;
                options.Decode = true;
                options.NoExport = true;
            }
            else if (arg.Equals("--catalog", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length)
                    return false;

                options.CatalogPath = args[++i];
            }
            else if (arg.Equals("--extract-lua", StringComparison.OrdinalIgnoreCase))
            {
                options.ExtractLua = true;
                options.Decode = true;
            }
            else if (arg.Equals("--threat", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length)
                    return false;

                options.ThreatFilter = args[++i];
            }
            else if (arg.Equals("--sig-type", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length)
                    return false;

                options.SignatureTypeFilter = args[++i];
            }
            else if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                // Unknown "--" flag — treat as an error.
                return false;
            }
            else
            {
                positional.Add(arg);
            }
        }

        if (positional.Count != 2)
            return false;

        options.FilePath = positional[0];
        options.OutputDirectory = positional[1];
        return true;
    }

    /// <summary>
    /// Prints the command-line usage and examples to standard output.
    /// </summary>
    private static void PrintUsage()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  wdsigex <FilePath> <OutputDirectory> [--catalog <CatalogCsv>] [--threat <substring>] [--sig-type <type>]");
        Console.WriteLine("          [--quiet] [--no-export] [--stats-only] [--html] [--decode] [--decode-json]");
        Console.WriteLine("          [--decode-only] [--decode-dir <Directory>] [--extract-lua]");
        Console.WriteLine("Examples:");
        Console.WriteLine("  wdsigex mpavbase.extracted out");
        Console.WriteLine("  wdsigex mpavbase.extracted out --catalog defender.csv");
        Console.WriteLine("  wdsigex mpavbase.extracted out --threat Sirefef");
        Console.WriteLine("  wdsigex mpavbase.extracted out --sig-type SIGNATURE_TYPE_SIGTREE_BM");
        Console.WriteLine("  wdsigex mpavbase.extracted out --sig-type 0xB3");
        Console.WriteLine("  wdsigex mpavbase.extracted out --decode --extract-lua");
        Console.WriteLine("  wdsigex mpavbase.extracted out --quiet --stats-only");
        Console.WriteLine("  wdsigex mpavbase.extracted out --html");
        Console.WriteLine("  wdsigex mpavbase.extracted out --decode");
        Console.WriteLine("  wdsigex mpavbase.extracted out --decode-only --decode-json");
    }

    /// <summary>
    /// Core binary parsing loop.
    /// </summary>
    /// <param name="options">Active configuration.</param>
    /// <returns>Aggregate parse statistics.</returns>
    public static ParserStats ExtractThreatSignatures(Options options)
    {
        ParserStats stats = new();
        uint currentThreatId = 0;
        int nextProgressPosition = PROGRESS_STEP_BYTES;

        if (!options.Quiet)
        {
            Console.WriteLine("Threat names are resolved from file data, optionally backed by catalog.");
        }

        byte[] data = File.ReadAllBytes(options.FilePath);
        int position = 0;
        int length = data.Length;

        while (position < length)
        {
            if (!options.Quiet && position >= nextProgressPosition)
            {
                Console.WriteLine($"  Progress: 0x{position:X8} ({position}) / 0x{length:X8} ({length})");
                nextProgressPosition += PROGRESS_STEP_BYTES;
            }

            int recordStart = position;
            byte signatureTypeValue = data[position++];

            if (signatureTypeValue == SIG_TYPE_THREAT_BEGIN)
            {
                if (position + 3 > length)
                    break;

                stats.TotalRecords++;
                stats.ThreatBegins++;

                // Read the 3-byte little-endian size (1 low byte + 1 high word).
                byte sizeLow = data[position++];
                ushort sizeHigh = ReadUInt16LE(data, position);
                position += 2;

                int size = sizeLow | (sizeHigh << 8); // Actual payload byte count.
                int endPosition = position + size;
                if (endPosition > length)
                    break;

                if (position + 4 > length)
                    break;

                // First 4 bytes of the payload are the 32-bit threat ID.
                uint threatId = ReadUInt32LE(data, position);
                position += 4;
                currentThreatId = threatId;

                if (position + 8 > length)
                    break;

                // Skip 6 unknown header bytes.
                position += 6;
                byte threatNameSize = data[position++];

                // Skip 1 additional unknown byte.
                position += 1;

                if (position + threatNameSize + 9 > length)
                    break;

                string threatNameFromFile = Encoding.ASCII.GetString(data, position, threatNameSize);
                position += threatNameSize;

                // Skip 9 trailing unknown header bytes.
                position += 9;

                // Look up the catalog name for this ID (may be empty string).
                string catalogName = string.Empty;
                if (ThreatDictionary.TryGetValue(threatId, out string? foundCatalogName))
                {
                    catalogName = foundCatalogName;
                }

                if (!Threats.TryGetValue(threatId, out Threat? threat))
                {
                    threat = new Threat
                    {
                        ThreatId = threatId,
                        ThreatNameFromFile = threatNameFromFile,
                        ThreatNameFromCatalog = catalogName,
                        BeginPosition = recordStart
                    };
                    Threats[threatId] = threat;
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(threat.ThreatNameFromFile) && !string.IsNullOrWhiteSpace(threatNameFromFile))
                        threat.ThreatNameFromFile = threatNameFromFile;

                    if (string.IsNullOrWhiteSpace(threat.ThreatNameFromCatalog) && !string.IsNullOrWhiteSpace(catalogName))
                        threat.ThreatNameFromCatalog = catalogName;

                    if (threat.BeginPosition == 0)
                        threat.BeginPosition = recordStart;
                }

                position = endPosition; //-V3008
            }
            else if (signatureTypeValue == SIG_TYPE_THREAT_END)
            {
                if (position + 3 > length)
                    break;

                stats.TotalRecords++;
                stats.ThreatEnds++;

                byte sizeLow = data[position++];
                ushort sizeHigh = ReadUInt16LE(data, position);
                position += 2;

                int size = sizeLow | (sizeHigh << 8);
                int endPosition = position + size;
                if (endPosition > length)
                    break;

                if (position + 4 > length)
                    break;

                uint threatId = ReadUInt32LE(data, position);

                if (Threats.TryGetValue(threatId, out Threat? threat))
                {
                    if (threat.EndPosition == 0)
                        threat.EndPosition = endPosition;
                }

                position = endPosition;
                currentThreatId = 0;
            }
            else
            {
                if (position + 3 > length)
                {
                    TrackUnknown(stats, signatureTypeValue);
                    break;
                }

                byte sizeLow = data[position];
                ushort sizeHigh = ReadUInt16LE(data, position + 1);
                int size = sizeLow | (sizeHigh << 8);
                int recordDataStart = position + 3;
                int endPosition = recordDataStart + size;

                if (endPosition > length)
                {
                    // Truncated record at eof: skip one byte and retry.
                    TrackUnknown(stats, signatureTypeValue);
                    position += 1;
                    continue;
                }

                stats.TotalRecords++;

                string signatureTypeName = GetSignatureTypeName(signatureTypeValue);

                if (signatureTypeName == "SIGNATURE_TYPE_UNKNOWN")
                {
                    TrackUnknown(stats, signatureTypeValue);
                }
                else if (currentThreatId != 0 && Threats.TryGetValue(currentThreatId, out Threat? threat))
                {
                    if (!threat.SignatureStats.TryAdd(signatureTypeName, 1))
                        threat.SignatureStats[signatureTypeName]++;

                    threat.SignatureRecords.Add(new SignatureRecord
                    {
                        SignatureType = signatureTypeValue,
                        SignatureTypeName = signatureTypeName,
                        RecordOffset = recordStart,
                        DataOffset = recordDataStart,
                        DataSize = size
                    });
                }

                position = endPosition;
            }
        }

        return stats;
    }

    /// <summary>
    /// Exports the raw binary content of each matched threat as an individual .bin file.
    /// </summary>
    /// <param name="options">Active options.</param>
    /// <param name="stats">Counters updated in place.</param>
    private static void ExportThreats(Options options, ParserStats stats)
    {
        if (!options.Quiet)
            Console.WriteLine("Exporting threat chunks...");

        using FileStream fs = new(options.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);

        foreach (Threat threat in GetFilteredThreats(options).OrderBy(t => t.BeginPosition))
        {
            if (threat.EndPosition <= threat.BeginPosition)
            {
                stats.SkippedThreats++;
                continue;
            }

            string safeName = SanitizeFileName(threat.ResolvedThreatName);
            string outputPath = Path.Combine(options.OutputDirectory, safeName + "_" + threat.ThreatId + ".bin");

            SaveSignatureContent(fs, threat.BeginPosition, threat.EndPosition, outputPath);
            stats.ExportedThreats++;
        }
    }

    /// <summary>
    /// Returns a filtered enumeration of all parsed <see cref="Threat"/> values.
    /// </summary>
    /// <param name="options">Provides ThreatFilter and SignatureTypeFilter.</param>
    /// <returns>Sequence of matching threats in dictionary-insertion order.</returns>
    private static IEnumerable<Threat> GetFilteredThreats(Options options)
    {
        return Threats.Values.Where(t => IsThreatMatch(t, options));
    }

    /// <summary>
    /// Prints the post-run summary to standard output.
    /// </summary>
    /// <param name="stats">Final aggregate counters.</param>
    /// <param name="options">Used to determine which optional sections to print.</param>
    private static void PrintSummary(ParserStats stats, Options options)
    {
        stats.FilterMatchedThreats = GetFilteredThreats(options).LongCount();

        Console.WriteLine();
        Console.WriteLine("Summary:");
        Console.WriteLine($"  Threats parsed              : {Threats.Count}");
        Console.WriteLine($"  Total parsed records        : {stats.TotalRecords}");
        Console.WriteLine($"  Threat begins               : {stats.ThreatBegins}");
        Console.WriteLine($"  Threat ends                 : {stats.ThreatEnds}");
        Console.WriteLine($"  Unknown bytes skipped       : {stats.UnknownSignatureBytesSkipped}");

        if (!string.IsNullOrWhiteSpace(options.ThreatFilter))
        {
            Console.WriteLine($"  Threat filter               : {options.ThreatFilter}");
            Console.WriteLine($"  Filter matched threats      : {stats.FilterMatchedThreats}");
        }

        if (!string.IsNullOrWhiteSpace(options.SignatureTypeFilter))
        {
            Console.WriteLine($"  Signature type filter       : {options.SignatureTypeFilter}");
        }

        if (options.DecodeOnly)
        {
            Console.WriteLine("  Mode                        : Decode-only");
        }

        if (!options.NoExport && !options.StatsOnly)
        {
            Console.WriteLine($"  Exported threats            : {stats.ExportedThreats}");
            Console.WriteLine($"  Skipped threats             : {stats.SkippedThreats}");
        }

        if (options.Decode)
        {
            long decodedThreats = GetFilteredThreats(options).LongCount(t => t.DecodedSignatures.Count > 0);
            long decodedSignatures = GetFilteredThreats(options).Sum(t => (long)t.DecodedSignatures.Count);

            long highConfidence = GetFilteredThreats(options)
                .Sum(t => (long)t.DecodedSignatures.Count(s => string.Equals(s.DecodeConfidence, "High", StringComparison.OrdinalIgnoreCase)));

            long mediumConfidence = GetFilteredThreats(options)
                .Sum(t => (long)t.DecodedSignatures.Count(s => string.Equals(s.DecodeConfidence, "Medium", StringComparison.OrdinalIgnoreCase)));

            long lowConfidence = GetFilteredThreats(options)
                .Sum(t => (long)t.DecodedSignatures.Count(s => string.Equals(s.DecodeConfidence, "Low", StringComparison.OrdinalIgnoreCase)));

            Console.WriteLine($"  Decoded threats             : {decodedThreats}");
            Console.WriteLine($"  Decoded signatures          : {decodedSignatures}");
            Console.WriteLine($"  High-confidence decodes     : {highConfidence}");
            Console.WriteLine($"  Medium-confidence decodes   : {mediumConfidence}");
            Console.WriteLine($"  Low-confidence decodes      : {lowConfidence}");
        }

        if (stats.UnknownSignatureTypes.Count > 0)
        {
            Console.WriteLine("  Unknown signature types:");
            foreach (var kv in stats.UnknownSignatureTypes.OrderBy(k => k.Key))
            {
                Console.WriteLine($"    0x{kv.Key:X2} ({kv.Key}) -> {kv.Value}");
            }
        }
    }

    /// <summary>
    /// Increments the occurrence counter for an unrecognised signature type byte in the
    /// provided <see cref="ParserStats"/> instance and increments the total unknown-bytes-
    /// skipped counter by one.
    /// </summary>
    /// <param name="stats">Stats object to update.</param>
    /// <param name="signatureTypeValue">The unrecognised byte value.</param>
    private static void TrackUnknown(ParserStats stats, byte signatureTypeValue)
    {
        if (!stats.UnknownSignatureTypes.TryAdd(signatureTypeValue, 1))
            stats.UnknownSignatureTypes[signatureTypeValue]++;

        stats.UnknownSignatureBytesSkipped++;
    }

    /// <summary>
    /// Reads a 16-bit unsigned integer from <paramref name="data"/> at the given
    /// <paramref name="offset"/> using little-endian byte order.
    /// </summary>
    /// <param name="data"></param>
    /// <param name="offset"></param>
    /// <returns></returns>
    private static ushort ReadUInt16LE(byte[] data, int offset)
    {
        return (ushort)(data[offset] | (data[offset + 1] << 8));
    }

    /// <summary>
    /// Reads a 32-bit unsigned integer from <paramref name="data"/> at the given
    /// <paramref name="offset"/> using little-endian byte order.
    /// </summary>
    /// <param name="data"></param>
    /// <param name="offset"></param>
    /// <returns></returns>
    private static uint ReadUInt32LE(byte[] data, int offset)
    {
        return (uint)(
            data[offset] |
            (data[offset + 1] << 8) |
            (data[offset + 2] << 16) |
            (data[offset + 3] << 24));
    }

    /// <summary>
    /// Maps a raw signature type byte to its symbolic name string by indexing into the
    /// pre-built <see cref="SignatureTypeNames"/> lookup table.
    /// </summary>
    /// <param name="signatureType"></param>
    /// <returns></returns>
    private static string GetSignatureTypeName(byte signatureType)
    {
        return SignatureTypeNames[signatureType];
    }

    /// <summary>
    /// Produces a file-system-safe version of a threat name by replacing any character
    /// that is invalid in a file name (as reported by <see cref="Path.GetInvalidFileNameChars"/>),
    /// as well as the forward-slash and colon characters, with an underscore.
    /// </summary>
    /// <param name="input"></param>
    /// <returns></returns>
    private static string SanitizeFileName(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return "unnamed_threat";

        char[] invalid = Path.GetInvalidFileNameChars();
        StringBuilder sb = new(input.Length);

        foreach (char c in input)
        {
            if (invalid.Contains(c) || c == '/' || c == ':')
                sb.Append('_');
            else
                sb.Append(c);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Extracts the byte range [<paramref name="beginPosition"/>, <paramref name="endPosition"/>)
    /// from the already-open <paramref name="fs"/> file stream and writes it verbatim to
    /// <paramref name="outputFilePath"/>.
    /// </summary>
    /// <param name="fs"></param>
    /// <param name="beginPosition"></param>
    /// <param name="endPosition"></param>
    /// <param name="outputFilePath"></param>
    public static void SaveSignatureContent(FileStream fs, int beginPosition, int endPosition, string outputFilePath)
    {
        if (endPosition <= beginPosition)
            return;

        int length = endPosition - beginPosition;
        byte[] content = new byte[length];

        fs.Seek(beginPosition, SeekOrigin.Begin);

        int totalRead = 0;
        while (totalRead < content.Length)
        {
            int read = fs.Read(content, totalRead, content.Length - totalRead);
            if (read == 0)
                break;
            totalRead += read;
        }

        if (totalRead == content.Length)
        {
            File.WriteAllBytes(outputFilePath, content);
        }
    }

    /// <summary>
    /// Populates the global <see cref="ThreatDictionary"/> from a CSV file at <paramref name="filePath"/>.
    /// </summary>
    /// <param name="filePath"></param>
    public static void ReadCatalogCsv(string filePath)
    {
        string[] lines = File.ReadAllLines(filePath);

        for (int i = 1; i < lines.Length; i++)
        {
            string[] fields = SplitCsvLine(lines[i]);
            if (fields.Length >= 4 && uint.TryParse(fields[2], out uint threatId))
            {
                string threatName = fields[3];
                if (!ThreatDictionary.ContainsKey(threatId))
                    ThreatDictionary.Add(threatId, threatName);
            }
        }
    }

    /// <summary>
    /// Splits a single CSV line into fields.
    /// </summary>
    /// <param name="line"></param>
    /// <returns></returns>
    private static string[] SplitCsvLine(string line)
    {
        List<string> result = new();
        bool inQuotes = false;
        StringBuilder currentField = new();

        if (line == null)
            return result.ToArray();

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];

            if (c == '\"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '\"')
                {
                    currentField.Append('\"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (c == ',' && !inQuotes)
            {
                result.Add(currentField.ToString());
                currentField.Clear();
            }
            else
            {
                currentField.Append(c);
            }
        }

        result.Add(currentField.ToString());
        return result.ToArray();
    }

    /// <summary>
    /// Writes a human-readable listing of all threats that pass the active filter to
    /// <paramref name="filePath"/>.
    /// </summary>
    /// <param name="dictionary"></param>
    /// <param name="filePath"></param>
    /// <param name="options"></param>
    private static void SaveThreatsToFile(Dictionary<uint, Threat> dictionary, string filePath, Options options)
    {
        using StreamWriter writer = new(filePath);

        foreach (var kvp in dictionary.OrderBy(k => k.Key))
        {
            Threat threat = kvp.Value;
            if (!IsThreatMatch(threat, options))
                continue;

            writer.WriteLine(
                $"Key: {kvp.Key}, ThreatName: {threat.ResolvedThreatName}, " +
                $"ThreatNameFromFile: {threat.ThreatNameFromFile}, " +
                $"ThreatNameFromCatalog: {threat.ThreatNameFromCatalog}, " +
                $"BeginPosition: {threat.BeginPosition}, EndPosition: {threat.EndPosition}");
        }
    }

    /// <summary>
    /// Writes a listing of all threat IDs that appear in <paramref name="threatDictionary"/>
    /// but have no corresponding entry in the parsed <paramref name="threats"/> dictionary
    /// to <paramref name="filePath"/>.
    /// </summary>
    /// <param name="threats"></param>
    /// <param name="threatDictionary"></param>
    /// <param name="filePath"></param>
    private static void SaveMissingThreatsToFile(Dictionary<uint, Threat> threats, Dictionary<uint, string> threatDictionary, string filePath)
    {
        using StreamWriter writer = new(filePath);

        foreach (var kvp in threatDictionary)
        {
            if (!threats.ContainsKey(kvp.Key))
            {
                writer.WriteLine($"Key: {kvp.Key}, Description: {kvp.Value}");
            }
        }
    }

    /// <summary>
    /// Produces two CSV statistics files in <paramref name="outputDirectory"/>.
    /// </summary>
    /// <param name="outputDirectory"></param>
    /// <param name="options"></param>
    public static void SaveStats(string outputDirectory, Options options)
    {
        List<Threat> filteredThreats = GetFilteredThreats(options).OrderBy(t => t.ResolvedThreatName).ToList();

        HashSet<string> allKeysSet = new(StringComparer.Ordinal);
        foreach (Threat threat in filteredThreats)
        {
            foreach (string key in threat.SignatureStats.Keys)
                allKeysSet.Add(key);
        }

        List<string> allKeys = allKeysSet.OrderBy(k => k, StringComparer.Ordinal).ToList();

        using (StreamWriter writer = new(Path.Combine(outputDirectory, "ThreatsStats.csv")))
        {
            writer.Write("ThreatName");
            foreach (string key in allKeys)
                writer.Write($",{key}");
            writer.WriteLine();

            foreach (Threat threat in filteredThreats)
            {
                writer.Write(threat.ResolvedThreatName);
                foreach (string key in allKeys)
                {
                    writer.Write(",");
                    writer.Write(threat.SignatureStats.TryGetValue(key, out long count) ? count : 0);
                }
                writer.WriteLine();
            }
        }

        Dictionary<string, long> globalSums = new(StringComparer.Ordinal);
        foreach (string key in allKeys)
            globalSums[key] = 0;

        foreach (Threat threat in filteredThreats)
        {
            foreach (var stat in threat.SignatureStats)
                globalSums[stat.Key] += stat.Value;
        }

        using (StreamWriter writer = new(Path.Combine(outputDirectory, "ThreatsGlobalStats.csv")))
        {
            writer.WriteLine(string.Join(",", allKeys));
            writer.WriteLine(string.Join(",", allKeys.Select(key => globalSums[key])));
        }
    }

    /// <summary>
    /// Generates two standalone HTML files containing Chart.js bar charts and writes them
    /// to <paramref name="outputDirectory"/>.
    /// </summary>
    /// <param name="outputDirectory"></param>
    /// <param name="options"></param>
    public static void SaveHtmlCharts(string outputDirectory, Options options)
    {
        List<Threat> filteredThreats = GetFilteredThreats(options).ToList();

        HashSet<string> allKeysSet = new(StringComparer.Ordinal);
        foreach (Threat threat in filteredThreats)
        {
            foreach (string key in threat.SignatureStats.Keys)
                allKeysSet.Add(key);
        }

        List<string> allKeys = allKeysSet.OrderBy(k => k, StringComparer.Ordinal).ToList();

        Dictionary<string, long> globalSums = new(StringComparer.Ordinal);
        foreach (string key in allKeys)
            globalSums[key] = 0;

        foreach (Threat threat in filteredThreats)
        {
            foreach (var stat in threat.SignatureStats)
                globalSums[stat.Key] += stat.Value;
        }

        var top30GlobalSums = globalSums.OrderByDescending(kvp => kvp.Value).Take(30).ToList();

        List<string> headers = top30GlobalSums.Select(kvp => kvp.Key).ToList();
        List<long> values = top30GlobalSums.Select(kvp => kvp.Value).ToList();

        string strHeaders = "[" + string.Join(",", headers.Select(h => $"'{EscapeJsString(h)}'")) + "]";
        string strValues = "[" + string.Join(",", values) + "]";

        StringBuilder htmlContent = new();

        htmlContent.AppendLine("<!DOCTYPE html>");
        htmlContent.AppendLine("<html lang='en'>");
        htmlContent.AppendLine("<head>");
        htmlContent.AppendLine("    <meta charset='UTF-8'>");
        htmlContent.AppendLine("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>");
        htmlContent.AppendLine("    <title>WDSigEx Charts</title>");
        htmlContent.AppendLine("    <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>");
        htmlContent.AppendLine("    <style>");
        htmlContent.AppendLine("        body {");
        htmlContent.AppendLine("            font-family: Arial, sans-serif;");
        htmlContent.AppendLine("            margin: 20px;");
        htmlContent.AppendLine("        }");
        htmlContent.AppendLine("        canvas {");
        htmlContent.AppendLine("            margin-top: 20px;");
        htmlContent.AppendLine("        }");
        htmlContent.AppendLine("    </style>");
        htmlContent.AppendLine("</head>");
        htmlContent.AppendLine("<body>");
        htmlContent.AppendLine("    <h1>WDSigEx - Top 30 Global Threats Signatures Stats Chart</h1>");
        htmlContent.AppendLine("    <canvas id='globalSumsChart'></canvas>");
        htmlContent.AppendLine();
        htmlContent.AppendLine("    <script>");
        htmlContent.AppendLine("        document.addEventListener('DOMContentLoaded', function() {");
        htmlContent.AppendLine($"            const headers = {strHeaders};");
        htmlContent.AppendLine($"            const values = {strValues};");
        htmlContent.AppendLine();
        htmlContent.AppendLine("            function createGlobalSumsChart(headers, values) {");
        htmlContent.AppendLine("                const ctx = document.getElementById('globalSumsChart').getContext('2d');");
        htmlContent.AppendLine();
        htmlContent.AppendLine("                new Chart(ctx, {");
        htmlContent.AppendLine("                    type: 'bar',");
        htmlContent.AppendLine("                    data: {");
        htmlContent.AppendLine("                        labels: headers,");
        htmlContent.AppendLine("                        datasets: [{");
        htmlContent.AppendLine("                            label: 'Global Sums',");
        htmlContent.AppendLine("                            data: values,");
        htmlContent.AppendLine("                            backgroundColor: getRandomColor()");
        htmlContent.AppendLine("                        }]");
        htmlContent.AppendLine("                    },");
        htmlContent.AppendLine("                    options: {");
        htmlContent.AppendLine("                        responsive: true,");
        htmlContent.AppendLine("                        scales: {");
        htmlContent.AppendLine("                            y: {");
        htmlContent.AppendLine("                                beginAtZero: true");
        htmlContent.AppendLine("                            }");
        htmlContent.AppendLine("                        }");
        htmlContent.AppendLine("                    }");
        htmlContent.AppendLine("                });");
        htmlContent.AppendLine("            }");
        htmlContent.AppendLine();
        htmlContent.AppendLine("            function getRandomColor() {");
        htmlContent.AppendLine("                const r = Math.floor(Math.random() * 255);");
        htmlContent.AppendLine("                const g = Math.floor(Math.random() * 255);");
        htmlContent.AppendLine("                const b = Math.floor(Math.random() * 255);");
        htmlContent.AppendLine("                return `rgba(${r}, ${g}, ${b}, 0.6)`;");
        htmlContent.AppendLine("            }");
        htmlContent.AppendLine();
        htmlContent.AppendLine("            createGlobalSumsChart(headers, values);");
        htmlContent.AppendLine("        });");
        htmlContent.AppendLine("    </script>");
        htmlContent.AppendLine("</body>");
        htmlContent.AppendLine("</html>");

        File.WriteAllText(Path.Combine(outputDirectory, "Top30GlobalStatsChart.html"), htmlContent.ToString());

        var groupedThreats = filteredThreats
            .GroupBy(t => GetThreatGroupName(t.ResolvedThreatName))
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);

        Dictionary<string, Dictionary<string, long>> groupedSums = new(StringComparer.Ordinal);
        foreach (var group in groupedThreats)
        {
            Dictionary<string, long> signatureStatsSums = new(StringComparer.Ordinal);

            foreach (Threat threat in group.Value)
            {
                foreach (var stat in threat.SignatureStats)
                {
                    if (!signatureStatsSums.TryAdd(stat.Key, stat.Value))
                        signatureStatsSums[stat.Key] += stat.Value;
                }
            }

            groupedSums[group.Key] = signatureStatsSums
                .OrderByDescending(kvp => kvp.Value)
                .Take(10)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.Ordinal);
        }

        StringBuilder htmlContent2 = new();

        htmlContent2.AppendLine("<!DOCTYPE html>");
        htmlContent2.AppendLine("<html lang='en'>");
        htmlContent2.AppendLine("<head>");
        htmlContent2.AppendLine("    <meta charset='UTF-8'>");
        htmlContent2.AppendLine("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>");
        htmlContent2.AppendLine("    <title>WDSigEx Charts</title>");
        htmlContent2.AppendLine("    <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>");
        htmlContent2.AppendLine("    <style>");
        htmlContent2.AppendLine("        body {");
        htmlContent2.AppendLine("            font-family: Arial, sans-serif;");
        htmlContent2.AppendLine("            margin: 20px;");
        htmlContent2.AppendLine("        }");
        htmlContent2.AppendLine("        canvas {");
        htmlContent2.AppendLine("            margin-top: 20px;");
        htmlContent2.AppendLine("        }");
        htmlContent2.AppendLine("    </style>");
        htmlContent2.AppendLine("</head>");
        htmlContent2.AppendLine("<body>");
        htmlContent2.AppendLine("    <h1>WDSigEx - Threat Groups Top 10 Signatures Stats Chart</h1>");

        foreach (var group in groupedSums)
        {
            List<string> headers2 = group.Value.Keys.ToList();
            List<long> values2 = group.Value.Values.ToList();
            string groupName = group.Key;
            string safeGroupId = SanitizeHtmlId(groupName);

            string strHeaders2 = "[" + string.Join(",", headers2.Select(h => $"'{EscapeJsString(h)}'")) + "]";
            string strValues2 = "[" + string.Join(",", values2) + "]";

            htmlContent2.AppendLine($"    <h2>{System.Net.WebUtility.HtmlEncode(groupName)}</h2>");
            htmlContent2.AppendLine($"    <canvas id='{safeGroupId}Chart'></canvas>");
            htmlContent2.AppendLine("    <script>");
            htmlContent2.AppendLine("        document.addEventListener('DOMContentLoaded', function() {");
            htmlContent2.AppendLine($"            const headers = {strHeaders2};");
            htmlContent2.AppendLine($"            const values = {strValues2};");
            htmlContent2.AppendLine();
            htmlContent2.AppendLine("            function createChart(ctx, headers, values) {");
            htmlContent2.AppendLine("                new Chart(ctx, {");
            htmlContent2.AppendLine("                    type: 'bar',");
            htmlContent2.AppendLine("                    data: {");
            htmlContent2.AppendLine("                        labels: headers,");
            htmlContent2.AppendLine("                        datasets: [{");
            htmlContent2.AppendLine($"                            label: '{EscapeJsString(groupName)} Sums',");
            htmlContent2.AppendLine("                            data: values,");
            htmlContent2.AppendLine("                            backgroundColor: getRandomColor()");
            htmlContent2.AppendLine("                        }]");
            htmlContent2.AppendLine("                    },");
            htmlContent2.AppendLine("                    options: {");
            htmlContent2.AppendLine("                        responsive: true,");
            htmlContent2.AppendLine("                        scales: {");
            htmlContent2.AppendLine("                            y: {");
            htmlContent2.AppendLine("                                beginAtZero: true");
            htmlContent2.AppendLine("                            }");
            htmlContent2.AppendLine("                        }");
            htmlContent2.AppendLine("                    }");
            htmlContent2.AppendLine("                });");
            htmlContent2.AppendLine("            }");
            htmlContent2.AppendLine();
            htmlContent2.AppendLine("            function getRandomColor() {");
            htmlContent2.AppendLine("                const r = Math.floor(Math.random() * 255);");
            htmlContent2.AppendLine("                const g = Math.floor(Math.random() * 255);");
            htmlContent2.AppendLine("                const b = Math.floor(Math.random() * 255);");
            htmlContent2.AppendLine("                return `rgba(${r}, ${g}, ${b}, 0.6)`;");
            htmlContent2.AppendLine("            }");
            htmlContent2.AppendLine();
            htmlContent2.AppendLine($"            const ctx = document.getElementById('{safeGroupId}Chart').getContext('2d');");
            htmlContent2.AppendLine("            createChart(ctx, headers, values);");
            htmlContent2.AppendLine("        });");
            htmlContent2.AppendLine("    </script>");
        }

        htmlContent2.AppendLine("</body>");
        htmlContent2.AppendLine("</html>");

        File.WriteAllText(Path.Combine(outputDirectory, "ThreatGroupStatsCharts.html"), htmlContent2.ToString());
    }

    /// <summary>
    /// Returns true if <paramref name="threat"/> should be included in output, based on
    /// the current filter in <paramref name="options"/>.
    /// </summary>
    /// <param name="threat"></param>
    /// <param name="options"></param>
    /// <returns></returns>
    private static bool IsThreatMatch(Threat threat, Options options)
    {
        if (threat == null)
            return false;

        if (!string.IsNullOrWhiteSpace(options.ThreatFilter))
        {
            if (threat.ResolvedThreatName.IndexOf(options.ThreatFilter, StringComparison.OrdinalIgnoreCase) < 0)
                return false;
        }

        if (!IsThreatMatchBySignatureType(threat, options))
            return false;

        return true;
    }

    /// <summary>
    /// Returns true when the threat contains at least one <see cref="SignatureRecord"/>
    /// whose type matches the parsed signature type filter in <paramref name="options"/>.
    /// </summary>
    private static bool IsThreatMatchBySignatureType(Threat threat, Options options)
    {
        byte signatureTypeValue;
        string signatureTypeName;

        if (string.IsNullOrWhiteSpace(options.SignatureTypeFilter))
            return true;

        if (threat == null || threat.SignatureRecords.Count == 0)
            return false;

        if (TryParseSignatureTypeFilter(options.SignatureTypeFilter, out signatureTypeValue, out signatureTypeName))
        {
            for (int i = 0; i < threat.SignatureRecords.Count; i++)
            {
                SignatureRecord record = threat.SignatureRecords[i];

                if (!string.IsNullOrWhiteSpace(signatureTypeName) &&
                    string.Equals(record.SignatureTypeName, signatureTypeName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (record.SignatureType == signatureTypeValue)
                    return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Attempts to interpret a filter string as a signature type, populating
    /// both the numeric byte value and the symbolic name.
    /// </summary>
    private static bool TryParseSignatureTypeFilter(string filter, out byte signatureTypeValue, out string signatureTypeName)
    {
        string normalized;

        signatureTypeValue = 0;
        signatureTypeName = string.Empty;

        if (string.IsNullOrWhiteSpace(filter))
            return false;

        normalized = filter.Trim();

        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (byte.TryParse(normalized.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out signatureTypeValue))
            {
                signatureTypeName = GetSignatureTypeName(signatureTypeValue);
                return true;
            }
        }

        if (byte.TryParse(normalized, out signatureTypeValue))
        {
            signatureTypeName = GetSignatureTypeName(signatureTypeValue);
            return true;
        }

        if (!normalized.StartsWith("SIGNATURE_TYPE_", StringComparison.OrdinalIgnoreCase))
            normalized = "SIGNATURE_TYPE_" + normalized;

        for (int i = 0; i < SignatureTypeNames.Length; i++)
        {
            if (string.Equals(SignatureTypeNames[i], normalized, StringComparison.OrdinalIgnoreCase))
            {
                signatureTypeValue = (byte)i;
                signatureTypeName = SignatureTypeNames[i];
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Escapes a string for safe embedding as a JavaScript single-quoted string literal.
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    private static string EscapeJsString(string value)
    {
        return (value ?? string.Empty)
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("'", "\\'", StringComparison.Ordinal)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// Derives a threat group name from a fully qualified threat name by returning the
    /// substring before the first colon character.
    /// </summary>
    /// <param name="threatName"></param>
    /// <returns></returns>
    private static string GetThreatGroupName(string threatName)
    {
        if (string.IsNullOrWhiteSpace(threatName))
            return "Unknown";

        int idx = threatName.IndexOf(':');
        if (idx > 0)
            return threatName[..idx];

        return threatName;
    }

    /// <summary>
    /// Produces an HTML-element-safe ID string from an arbitrary group name by replacing
    /// every character that is not a letter or digit with an underscore.
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    private static string SanitizeHtmlId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "unknown";

        StringBuilder sb = new(value.Length);
        foreach (char c in value)
        {
            if (char.IsLetterOrDigit(c))
                sb.Append(c);
            else
                sb.Append('_');
        }

        return sb.ToString();
    }

    private static string ExportLuaChunk(SignatureParserContext context, byte[] data, int chunkOffset)
    {
        string baseDirectory;
        string luaDirectory;
        string threatDirectory;
        string fileName;
        string fullPath;
        int chunkLength;
        byte[] chunk;

        if (context == null)
            return string.Empty;

        if (data == null || chunkOffset < 0 || chunkOffset >= data.Length)
            return string.Empty;

        baseDirectory = !string.IsNullOrWhiteSpace(context.OutputDirectory)
            ? context.OutputDirectory
            : Directory.GetCurrentDirectory();

        luaDirectory = Path.Combine(baseDirectory, "lua_chunks");
        threatDirectory = Path.Combine(luaDirectory, SanitizeFileName(context.ThreatName));

        Directory.CreateDirectory(threatDirectory);

        fileName = $"{SanitizeFileName(context.ThreatName)}_{context.ThreatId}_0x{context.RecordOffset:X}.luac.bin";
        fullPath = Path.Combine(threatDirectory, fileName);

        chunkLength = data.Length - chunkOffset;
        chunk = new byte[chunkLength];
        Buffer.BlockCopy(data, chunkOffset, chunk, 0, chunkLength);

        File.WriteAllBytes(fullPath, chunk);
        return fullPath;
    }

    /// <summary>
    /// Builds and returns the 256-element signature type name lookup table,
    /// indexed by raw byte value.
    ///
    /// The names below are a best-effort reconstruction of the internal Windows
    /// Defender signature type enumeration. Some entries may be incorrect or
    /// may correspond to types that were reassigned between VDM versions.
    /// </summary>
    /// <returns>A 256-element array of signature type name strings.</returns>
    private static string[] BuildSignatureTypeNames()
    {
        string[] names = new string[256];

        // Default all slots to UNKNOWN so unregistered bytes are safe to look up.
        Array.Fill(names, "SIGNATURE_TYPE_UNKNOWN");

        //
        // Note: not everything in this table is confirmed accurate.
        //       Treat entries without any additional documentation as best-guess.
        //
        names[0x01] = "SIGNATURE_TYPE_RESERVED";
        names[0x02] = "SIGNATURE_TYPE_VOLATILE_THREAT_INFO";
        names[0x03] = "SIGNATURE_TYPE_VOLATILE_THREAT_ID";
        names[0x11] = "SIGNATURE_TYPE_CKOLDREC";
        names[0x20] = "SIGNATURE_TYPE_KVIR32";
        names[0x21] = "SIGNATURE_TYPE_POLYVIR32";
        names[0x27] = "SIGNATURE_TYPE_NSCRIPT_NORMAL";
        names[0x28] = "SIGNATURE_TYPE_NSCRIPT_SP";
        names[0x29] = "SIGNATURE_TYPE_NSCRIPT_BRUTE";
        names[0x2C] = "SIGNATURE_TYPE_NSCRIPT_CURE";
        names[0x30] = "SIGNATURE_TYPE_TITANFLT";
        names[0x3D] = "SIGNATURE_TYPE_PEFILE_CURE";
        names[0x3E] = "SIGNATURE_TYPE_MAC_CURE";
        names[0x40] = "SIGNATURE_TYPE_SIGTREE";
        names[0x41] = "SIGNATURE_TYPE_SIGTREE_EXT";
        names[0x42] = "SIGNATURE_TYPE_MACRO_PCODE";
        names[0x43] = "SIGNATURE_TYPE_MACRO_SOURCE";
        names[0x44] = "SIGNATURE_TYPE_BOOT";
        names[0x49] = "SIGNATURE_TYPE_CLEANSCRIPT";
        names[0x4A] = "SIGNATURE_TYPE_TARGET_SCRIPT";
        names[0x50] = "SIGNATURE_TYPE_CKSIMPLEREC";
        names[0x51] = "SIGNATURE_TYPE_PATTMATCH";
        names[0x53] = "SIGNATURE_TYPE_RPFROUTINE";
        names[0x55] = "SIGNATURE_TYPE_NID";
        names[0x56] = "SIGNATURE_TYPE_GENSFX";
        names[0x57] = "SIGNATURE_TYPE_UNPLIB";
        names[0x58] = "SIGNATURE_TYPE_DEFAULTS";
        names[0x5B] = "SIGNATURE_TYPE_DBVAR";
        names[0x5C] = "SIGNATURE_TYPE_THREAT_BEGIN";
        names[0x5D] = "SIGNATURE_TYPE_THREAT_END";
        names[0x5E] = "SIGNATURE_TYPE_FILENAME";
        names[0x5F] = "SIGNATURE_TYPE_FILEPATH";
        names[0x60] = "SIGNATURE_TYPE_FOLDERNAME";
        names[0x61] = "SIGNATURE_TYPE_PEHSTR";
        names[0x62] = "SIGNATURE_TYPE_LOCALHASH";
        names[0x63] = "SIGNATURE_TYPE_REGKEY";
        names[0x64] = "SIGNATURE_TYPE_HOSTSENTRY";
        names[0x67] = "SIGNATURE_TYPE_STATIC";
        names[0x69] = "SIGNATURE_TYPE_LATENT_THREAT";
        names[0x6A] = "SIGNATURE_TYPE_REMOVAL_POLICY";
        names[0x6B] = "SIGNATURE_TYPE_WVT_EXCEPTION";
        names[0x6C] = "SIGNATURE_TYPE_REVOKED_CERTIFICATE";
        names[0x70] = "SIGNATURE_TYPE_TRUSTED_PUBLISHER";
        names[0x71] = "SIGNATURE_TYPE_ASEP_FILEPATH";
        names[0x73] = "SIGNATURE_TYPE_DELTA_BLOB";
        names[0x74] = "SIGNATURE_TYPE_DELTA_BLOB_RECINFO";
        names[0x75] = "SIGNATURE_TYPE_ASEP_FOLDERNAME";
        names[0x77] = "SIGNATURE_TYPE_PATTMATCH_V2";
        names[0x78] = "SIGNATURE_TYPE_PEHSTR_EXT";
        names[0x79] = "SIGNATURE_TYPE_VDLL_X86";
        names[0x7A] = "SIGNATURE_TYPE_VERSIONCHECK";
        names[0x7B] = "SIGNATURE_TYPE_SAMPLE_REQUEST";
        names[0x7C] = "SIGNATURE_TYPE_VDLL_X64";
        names[0x7E] = "SIGNATURE_TYPE_SNID";
        names[0x7F] = "SIGNATURE_TYPE_FOP";
        names[0x80] = "SIGNATURE_TYPE_KCRCE";
        names[0x83] = "SIGNATURE_TYPE_VFILE";
        names[0x84] = "SIGNATURE_TYPE_SIGFLAGS";
        names[0x85] = "SIGNATURE_TYPE_PEHSTR_EXT2";
        names[0x86] = "SIGNATURE_TYPE_PEMAIN_LOCATOR";
        names[0x87] = "SIGNATURE_TYPE_PESTATIC";
        names[0x88] = "SIGNATURE_TYPE_UFSP_DISABLE";
        names[0x89] = "SIGNATURE_TYPE_FOPEX";
        names[0x8A] = "SIGNATURE_TYPE_PEPCODE";
        names[0x8B] = "SIGNATURE_TYPE_IL_PATTERN";
        names[0x8C] = "SIGNATURE_TYPE_ELFHSTR_EXT";
        names[0x8D] = "SIGNATURE_TYPE_MACHOHSTR_EXT";
        names[0x8E] = "SIGNATURE_TYPE_DOSHSTR_EXT";
        names[0x8F] = "SIGNATURE_TYPE_MACROHSTR_EXT";
        names[0x90] = "SIGNATURE_TYPE_TARGET_SCRIPT_PCODE";
        names[0x91] = "SIGNATURE_TYPE_VDLL_IA64";
        names[0x92] = "SIGNATURE_TYPE_UNS";
        names[0x93] = "SIGNATURE_TYPE_AEL_RECORD";
        names[0x94] = "SIGNATURE_TYPE_SIG_RECORD";
        names[0x95] = "SIGNATURE_TYPE_PEBMPAT";
        names[0x96] = "SIGNATURE_TYPE_AAGGREGATOR";
        names[0x97] = "SIGNATURE_TYPE_SAMPLE_REQUEST_BY_NAME";
        names[0x98] = "SIGNATURE_TYPE_REMOVAL_POLICY_BY_NAME";
        names[0x99] = "SIGNATURE_TYPE_TUNNEL_X86";
        names[0x9A] = "SIGNATURE_TYPE_TUNNEL_X64";
        names[0x9B] = "SIGNATURE_TYPE_TUNNEL_IA64";
        names[0x9C] = "SIGNATURE_TYPE_VDLL_ARM";
        names[0x9D] = "SIGNATURE_TYPE_THREAD_X86";
        names[0x9E] = "SIGNATURE_TYPE_THREAD_X64";
        names[0x9F] = "SIGNATURE_TYPE_THREAD_IA64";
        names[0xA0] = "SIGNATURE_TYPE_FRIENDLYFILE_SHA256";
        names[0xA1] = "SIGNATURE_TYPE_FRIENDLYFILE_SHA512";
        names[0xA2] = "SIGNATURE_TYPE_SHARED_THREAT";
        names[0xA3] = "SIGNATURE_TYPE_VDM_METADATA";
        names[0xA4] = "SIGNATURE_TYPE_VSTORE";
        names[0xA5] = "SIGNATURE_TYPE_VDLL_SYMINFO";
        names[0xA6] = "SIGNATURE_TYPE_IL2_PATTERN";
        names[0xA7] = "SIGNATURE_TYPE_BM_STATIC";
        names[0xA8] = "SIGNATURE_TYPE_BM_INFO";
        names[0xA9] = "SIGNATURE_TYPE_NDAT";
        names[0xAA] = "SIGNATURE_TYPE_FASTPATH_DATA";
        names[0xAB] = "SIGNATURE_TYPE_FASTPATH_SDN";
        names[0xAC] = "SIGNATURE_TYPE_DATABASE_CERT";
        names[0xAD] = "SIGNATURE_TYPE_SOURCE_INFO";
        names[0xAE] = "SIGNATURE_TYPE_HIDDEN_FILE";
        names[0xAF] = "SIGNATURE_TYPE_COMMON_CODE";
        names[0xB0] = "SIGNATURE_TYPE_VREG";
        names[0xB1] = "SIGNATURE_TYPE_NISBLOB";
        names[0xB2] = "SIGNATURE_TYPE_VFILEEX";
        names[0xB3] = "SIGNATURE_TYPE_SIGTREE_BM";
        names[0xB4] = "SIGNATURE_TYPE_VBFOP";
        names[0xB5] = "SIGNATURE_TYPE_VDLL_META";
        names[0xB6] = "SIGNATURE_TYPE_TUNNEL_ARM";
        names[0xB7] = "SIGNATURE_TYPE_THREAD_ARM";
        names[0xB8] = "SIGNATURE_TYPE_PCODEVALIDATOR";
        names[0xBA] = "SIGNATURE_TYPE_MSILFOP";
        names[0xBB] = "SIGNATURE_TYPE_KPAT";
        names[0xBC] = "SIGNATURE_TYPE_KPATEX";
        names[0xBD] = "SIGNATURE_TYPE_LUASTANDALONE";
        names[0xBE] = "SIGNATURE_TYPE_DEXHSTR_EXT";
        names[0xBF] = "SIGNATURE_TYPE_JAVAHSTR_EXT";
        names[0xC0] = "SIGNATURE_TYPE_MAGICCODE";
        names[0xC1] = "SIGNATURE_TYPE_CLEANSTORE_RULE";
        names[0xC2] = "SIGNATURE_TYPE_VDLL_CHECKSUM";
        names[0xC3] = "SIGNATURE_TYPE_THREAT_UPDATE_STATUS";
        names[0xC4] = "SIGNATURE_TYPE_VDLL_MSIL";
        names[0xC5] = "SIGNATURE_TYPE_ARHSTR_EXT";
        names[0xC6] = "SIGNATURE_TYPE_MSILFOPEX";
        names[0xC7] = "SIGNATURE_TYPE_VBFOPEX";
        names[0xC8] = "SIGNATURE_TYPE_FOP64";
        names[0xC9] = "SIGNATURE_TYPE_FOPEX64";
        names[0xCA] = "SIGNATURE_TYPE_JSINIT";
        names[0xCB] = "SIGNATURE_TYPE_PESTATICEX";
        names[0xCC] = "SIGNATURE_TYPE_KCRCEX";
        names[0xCD] = "SIGNATURE_TYPE_FTRIE_POS";
        names[0xCE] = "SIGNATURE_TYPE_NID64";
        names[0xCF] = "SIGNATURE_TYPE_MACRO_PCODE64";
        names[0xD0] = "SIGNATURE_TYPE_BRUTE";
        names[0xD1] = "SIGNATURE_TYPE_SWFHSTR_EXT";
        names[0xD2] = "SIGNATURE_TYPE_REWSIGS";
        names[0xD3] = "SIGNATURE_TYPE_AUTOITHSTR_EXT";
        names[0xD4] = "SIGNATURE_TYPE_INNOHSTR_EXT";
        names[0xD5] = "SIGNATURE_TYPE_CERT_STORE_ENTRY";
        names[0xD6] = "SIGNATURE_TYPE_EXPLICITRESOURCE";
        names[0xD7] = "SIGNATURE_TYPE_CMDHSTR_EXT";
        names[0xD8] = "SIGNATURE_TYPE_FASTPATH_TDN";
        names[0xD9] = "SIGNATURE_TYPE_EXPLICITRESOURCEHASH";
        names[0xDA] = "SIGNATURE_TYPE_FASTPATH_SDN_EX";
        names[0xDB] = "SIGNATURE_TYPE_BLOOM_FILTER";
        names[0xDC] = "SIGNATURE_TYPE_RESEARCH_TAG";
        names[0xDE] = "SIGNATURE_TYPE_ENVELOPE";
        names[0xDF] = "SIGNATURE_TYPE_REMOVAL_POLICY64";
        names[0xE0] = "SIGNATURE_TYPE_REMOVAL_POLICY64_BY_NAME";
        names[0xE1] = "SIGNATURE_TYPE_VDLL_META_X64";
        names[0xE2] = "SIGNATURE_TYPE_VDLL_META_ARM";
        names[0xE3] = "SIGNATURE_TYPE_VDLL_META_MSIL";
        names[0xE4] = "SIGNATURE_TYPE_MDBHSTR_EXT";
        names[0xE5] = "SIGNATURE_TYPE_SNIDEX";
        names[0xE6] = "SIGNATURE_TYPE_SNIDEX2";
        names[0xE7] = "SIGNATURE_TYPE_AAGGREGATOREX";
        names[0xE8] = "SIGNATURE_TYPE_PUA_APPMAP";
        names[0xE9] = "SIGNATURE_TYPE_PROPERTY_BAG";
        names[0xEA] = "SIGNATURE_TYPE_DMGHSTR_EXT";
        names[0xEB] = "SIGNATURE_TYPE_DATABASE_CATALOG";
        names[0xEC] = "SIGNATURE_TYPE_DATABASE_CERT2";
        names[0xED] = "SIGNATURE_TYPE_BM_ENV_VAR_MAP";

        return names;
    }
}
