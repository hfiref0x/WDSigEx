/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       DECODEMODEL.CS
*
*  VERSION:     1.00
*
*  DATE:        09 Apr 2026
*
*  Models used during decoding Windows Defender definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

public static partial class WDSigEx
{
    /// <summary>
    /// Structured representation of a decoded signature record, capturing the
    /// weighted threshold logic used by the Windows Defender scan engine.
    /// </summary>
    public sealed class SignatureLogic
    {
        /// <summary>
        /// Minimum accumulated sub-rule weight required for the signature to fire.
        /// Maps to the threshold field in the raw payload header.
        /// </summary>
        public int Threshold { get; set; }

        /// <summary>
        /// Ordered list of sub-rules that make up this signature.
        /// Each sub-rule contributes its <see cref="SubRuleLogic.Weight"/> when
        /// its <see cref="SubRuleLogic.Pattern"/> is found in the scan target.
        /// </summary>
        public List<SubRuleLogic> SubRules { get; } = new();
    }

    /// <summary>
    /// A single weighted pattern within a <see cref="SignatureLogic"/> rule.
    /// </summary>
    public sealed class SubRuleLogic
    {
        /// <summary>
        /// The byte pattern or token to search for.
        /// </summary>
        public string Pattern { get; set; } = string.Empty;

        /// <summary>
        /// Score added to the running weight total when this sub-rule matches.
        /// </summary>
        public int Weight { get; set; }

        /// <summary>
        /// Raw control/flags byte extracted from the payload.
        /// </summary>
        public byte Control { get; set; }
    }

    /// <summary>
    /// Aggregates the metadata a parser needs without having to receive the full
    /// <see cref="Threat"/> and <see cref="SignatureRecord"/> objects, keeping
    /// the ISignatureParser contract narrow and easy to implement.
    /// </summary>
    private sealed class SignatureParserContext
    {
        /// <summary>Numeric ID of the owning threat (for annotation / logging).</summary>
        public uint ThreatId { get; set; }

        /// <summary>Resolved display name of the owning threat.</summary>
        public string ThreatName { get; set; } = string.Empty;

        /// <summary>Raw signature type byte (e.g. 0x40 for SIGTREE).</summary>
        public byte SignatureType { get; set; }

        /// <summary>Symbolic name resolved from the type byte (e.g. "SIGNATURE_TYPE_SIGTREE").</summary>
        public string SignatureTypeName { get; set; } = string.Empty;

        /// <summary>
        /// Byte offset of the record's type byte within the source file.
        /// </summary>
        public int RecordOffset { get; set; }

        /// <summary>
        /// Byte offset of the first payload byte within the source file.
        /// </summary>
        public int DataOffset { get; set; }

        public string OutputDirectory { get; set; } = string.Empty;
        public bool ExtractLua { get; set; }
    }

    /// <summary>
    /// Strategy interface for signature payload decoders.
    /// </summary>
    private interface ISignatureParser
    {
        /// <summary>
        /// Returns true when this parser is able to decode the given signature type.
        /// </param>
        /// <returns>True if this parser handles the type; false otherwise.</returns>
        bool CanParse(byte signatureType, string signatureTypeName);

        /// <summary>
        /// Decodes the payload of a single signature record and returns a
        /// structured <see cref="DecodedSignature"/>.
        /// </summary>
        /// <param name="context">Metadata about the record being decoded.</param>
        /// <param name="data">
        /// The entire source file loaded into memory.  Parsers read from
        /// <see cref="SignatureParserContext.DataOffset"/> up to
        /// <c>DataOffset + record.DataSize</c>.
        /// </param>
        /// <returns>A populated <see cref="DecodedSignature"/> instance.</returns>
        DecodedSignature Parse(SignatureParserContext context, byte[] data);
    }

    /// <summary>
    /// Resolves the correct <see cref="ISignatureParser"/> for a given signature
    /// type by performing a linear search through a prioritised parser list.
    /// </summary>
    private sealed class SignatureParserDispatcher
    {
        /// <summary>
        /// Immutable, ordered list of registered parsers.
        /// </summary>
        private readonly List<ISignatureParser> _parsers;

        /// <summary>
        /// Initialises the dispatcher with a fixed set of parsers.
        /// </summary>
        /// <param name="parsers">
        /// Ordered enumeration of parsers.  The first parser in the sequence
        /// that returns true from <see cref="ISignatureParser.CanParse"/> wins,
        /// so more-specific parsers should appear earlier in the list.
        /// </param>
        public SignatureParserDispatcher(IEnumerable<ISignatureParser> parsers)
        {
            _parsers = new List<ISignatureParser>(parsers);
        }

        /// <summary>
        /// Returns the first registered parser that claims it can handle the
        /// supplied signature type, or <c>null</c> if none can.
        /// </summary>
        /// <param name="signatureType">Raw type byte from the binary stream.</param>
        /// <param name="signatureTypeName">Resolved symbolic type name.</param>
        /// <returns>
        /// The matching <see cref="ISignatureParser"/>, or null when no
        /// registered parser handles the type.
        /// </returns>
        public ISignatureParser? Resolve(byte signatureType, string signatureTypeName)
        {
            for (int i = 0; i < _parsers.Count; i++)
            {
                if (_parsers[i].CanParse(signatureType, signatureTypeName))
                    return _parsers[i];
            }

            // No registered parser matched — caller decides how to handle this.
            return null;
        }
    }
}
