/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       DECODEPARSERS.CS
*
*  VERSION:     1.00
*
*  DATE:        15 Apr 2026
*
*  Windows Defender definition parsers logic.
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
    /// Parser class for:
    ///     SIGNATURE_TYPE_AAGGREGATOR
    ///     SIGNATURE_TYPE_AAGGREGATOREX
    /// </summary>
    private sealed class AaAggregatorParser : ISignatureParser
    {
        // Defines the signature types this parser is capable of handling.
        private static readonly HashSet<string> SupportedTypes = new(StringComparer.Ordinal)
        {
            "SIGNATURE_TYPE_AAGGREGATOR",
            "SIGNATURE_TYPE_AAGGREGATOREX"
        };

        // List of known prefixes that indicate a specific type of operand within the aggregator data.
        private static readonly string[] OperandPrefixes =
        {
            "HSTR:",
            "PEHSTR:",
            "PESTATIC:",
            "SIGATTR:",
            "FOP:",
            "TUNNEL:",
            "THREAD:",
            "NSCRIPT:",
            "BRUTE:",
            "Lua",
            "!"
        };

        /// <summary>
        /// Checks if this parser is applicable to the given signature type name.
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return SupportedTypes.Contains(signatureTypeName);
        }

        /// <summary>
        /// Parses aggregator payloads by attempting to extract a boolean expression or rendering structured binary data.
        /// </summary>
        /// <param name="context">Metadata about the record being decoded.</param>
        /// <param name="data">The raw byte array containing the signature payload.</param>
        /// <returns>A populated DecodedSignature object detailing the extracted expression or structure.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> normalized;
            string expression;
            List<string> operands;
            string operators;
            bool isExtended;

            DecodedSignature decoded = new DecodedSignature
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "AGGREGATED_DATA",
                ConditionValue = data?.Length ?? 0,
                DecodeConfidence = "Low",
                Notes = "Aggregator payload interpreted heuristically"
            };

            if (data == null || data.Length == 0)
            {
                decoded.ConditionType = "EMPTY";
                decoded.ConditionValue = 0;
                decoded.Notes = "Empty aggregator payload";
                return decoded;
            }

            // Determine if this is the extended version of the aggregator parser.
            isExtended = string.Equals(context.SignatureTypeName, "SIGNATURE_TYPE_AAGGREGATOREX", StringComparison.Ordinal);

            // Collect and normalize all potential text candidates from the payload.
            normalized = DecodeTextHelper.NormalizeAndDistinct(DecodeTextHelper.CollectCandidateStrings(data, 4));
            normalized = normalized
                .Select(NormalizeAaggCandidate)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            // Attempt to find the best boolean expression from the candidates.
            expression = FindBestAaggExpression(normalized);
            operands = ExtractAaggOperands(expression, normalized);
            operators = ExtractAaggOperators(expression);

            if (!string.IsNullOrWhiteSpace(expression))
            {
                // Case 1: A clear boolean expression was found.
                decoded.ConditionType = isExtended ? "BOOLEAN_EXPRESSION_EX" : "BOOLEAN_EXPRESSION";
                decoded.ConditionValue = operands.Count > 0 ? operands.Count : 1;
                decoded.DecodeConfidence = operands.Count >= 2 ? "Medium" : "Low";
                decoded.Notes = isExtended
                    ? "Extended aggregator expression with possible scoring/threshold context"
                    : "Boolean aggregator expression extracted";

                decoded.Pattern.Add($"Expression={expression}");

                if (operands.Count > 0)
                    decoded.Pattern.Add($"Operands={string.Join(" | ", operands)}");

                if (!string.IsNullOrWhiteSpace(operators))
                    decoded.Pattern.Add($"Operators={operators}");

                // Add specific numeric hints if it's the extended version.
                if (isExtended)
                    AddCompactAggregatorNumericHints(decoded.Pattern, data);

                return decoded;
            }

            // Case 2: No clear expression found, check for structured binary payload in extended mode.
            if (isExtended && LooksLikeStructuredExPayload(data))
            {
                RenderStructuredAaggEx(decoded, data);
                return decoded;
            }

            // Case 3: Fallback to general data rendering (either standard or extended).
            decoded.ConditionType = isExtended ? "AGGREGATED_DATA_EX" : "AGGREGATED_DATA";
            decoded.ConditionValue = data.Length;
            decoded.Pattern.Add($"Length={data.Length}");

            if (isExtended)
                AddCompactAggregatorNumericHints(decoded.Pattern, data);
            else
                AddAggregatorNumericHints(decoded.Pattern, data);

            for (int i = 0; i < normalized.Count && i < 6; i++)
                decoded.Pattern.Add($"String[{i}]={normalized[i]}");

            if (LooksLikeExpressionFragmentSet(normalized))
            {
                // If fragments look like expressions, boost confidence slightly.
                decoded.DecodeConfidence = "Medium";
                decoded.Notes = isExtended
                    ? "Extended aggregator payload contains expression fragments and numeric context"
                    : "Aggregator payload contains boolean-expression-like fragments";
            }
            else
            {
                // Otherwise, render a hex preview of the raw data.
                decoded.Pattern.Add($"Preview={DecodeHexHelper.ToHexSpaced(data, 0, Math.Min(data.Length, 48))}");
                decoded.Notes = isExtended
                    ? "Extended aggregator payload rendered as structured fallback"
                    : "Aggregator payload rendered as structured fallback";
            }

            return decoded;
        }

        /// <summary>
        /// Infers the number of initial header-like dwords based on control value patterns in the first few 32-bit integers.
        /// </summary>
        private static int InferAaggExHeaderLikeCount(uint[] values)
        {
            if (values == null || values.Length == 0)
                return 0;

            if (values.Length == 1)
                return 1;

            // Check for patterns suggesting a small control value followed by another small control value.
            if (values.Length >= 3)
            {
                if (LooksLikeSmallControlValue(values[0]) && LooksLikeSmallControlValue(values[1]))
                    return 2;

                if (LooksLikeSmallControlValue(values[0]))
                    return 1;
            }

            return LooksLikeSmallControlValue(values[0]) ? 1 : 0;
        }

        /// <summary>
        /// Checks if a 32-bit unsigned integer resembles a small control, mode, or count field (<= 0x10000).
        /// </summary>
        private static bool LooksLikeSmallControlValue(uint value)
        {
            if (value == 0)
                return true;

            if (value <= 0x10000)
                return true;

            ushort lo = (ushort)(value & 0xFFFF);
            ushort hi = (ushort)((value >> 16) & 0xFFFF);
            if (hi == 0 && lo <= 0x1000)
                return true;

            return false;
        }

        /// <summary>
        /// Adds heuristic hints to the pattern list based on control values found in the initial DWORDS.
        /// </summary>
        /// <param name="pattern">The DecodedSignature's Pattern list to append hints to.</param>
        /// <param name="values">Array of 32-bit unsigned integers extracted from the payload.</param>
        private static void AddAaggExHeuristicHints(List<string> pattern, uint[] values)
        {
            if (pattern == null || values == null || values.Length == 0)
                return;

            uint first = values[0];
            ushort firstLo = (ushort)(first & 0xFFFF);
            ushort firstHi = (ushort)((first >> 16) & 0xFFFF);

            pattern.Add($"Header0.Lo=0x{firstLo:X4} ({firstLo})");
            pattern.Add($"Header0.Hi=0x{firstHi:X4} ({firstHi})");

            if (LooksLikeSmallControlValue(first))
                pattern.Add("Hint=HeaderDword[0] looks like control/mode/count-like data");

            if (values.Length >= 2)
            {
                uint second = values[1];
                ushort secondLo = (ushort)(second & 0xFFFF);
                ushort secondHi = (ushort)((second >> 16) & 0xFFFF);

                pattern.Add($"Header1.Lo=0x{secondLo:X4} ({secondLo})");
                pattern.Add($"Header1.Hi=0x{secondHi:X4} ({secondHi})");

                if (LooksLikeSmallControlValue(second))
                    pattern.Add("Hint=HeaderDword[1] looks like control/threshold-like data");
            }

            // Check for multiple small prefixes indicating dense, controlled data start.
            if (values.Length >= 3)
            {
                int smallPrefixCount = 0;

                for (int i = 0; i < values.Length && i < 3; i++)
                {
                    if (LooksLikeSmallControlValue(values[i]))
                        smallPrefixCount++;
                }

                if (smallPrefixCount >= 2)
                    pattern.Add("Hint=Payload begins with multiple small control-like fields followed by denser data");
            }
        }

        /// <summary>
        /// Renders the extended aggregator payload structure into pattern entries, analyzing DWORDS for context.
        /// </summary>
        /// <param name="decoded">The DecodedSignature object to populate with findings.</param>
        /// <param name="data">The raw byte array of the payload.</param>
        private static void RenderStructuredAaggEx(DecodedSignature decoded, byte[] data)
        {
            decoded.ConditionType = "EXTENDED_STRUCTURED_DATA";
            decoded.ConditionValue = data.Length;
            decoded.DecodeConfidence = data.Length >= 16 ? "Medium" : "Low";
            decoded.Notes = "Extended aggregator payload appears to contain fixed binary scoring/context fields";

            decoded.Pattern.Add($"Length={data.Length}");

            int dwordCount = data.Length / 4;
            decoded.Pattern.Add($"DwordCount={dwordCount}");

            uint[] values = new uint[dwordCount];
            int nonZeroCount = 0;

            for (int i = 0; i < dwordCount; i++)
            {
                values[i] = BitConverter.ToUInt32(data, i * 4);
                if (values[i] != 0)
                    nonZeroCount++;
            }

            decoded.Pattern.Add($"NonZeroDwordCount={nonZeroCount}");

            int headerLikeCount = InferAaggExHeaderLikeCount(values);

            // Render the first 8 DWORDS, labeling them as 'Header' if they fall within the inferred header count.
            for (int i = 0; i < dwordCount && i < 8; i++)
            {
                string label;

                if (i < headerLikeCount)
                    label = $"HeaderDword[{i}]";
                else
                    label = $"Dword[{i}]";

                decoded.Pattern.Add($"{label}=0x{values[i]:X8} ({values[i]})");
            }

            if (dwordCount > 8)
                decoded.Pattern.Add($"... +{dwordCount - 8} more dwords");

            // Add heuristic hints based on the values themselves.
            AddAaggExHeuristicHints(decoded.Pattern, values);

            // Append any remaining bytes as a raw hex tail if length is not divisible by 4.
            if ((data.Length % 4) != 0)
                decoded.Pattern.Add($"Tail={DecodeHexHelper.ToHexSpaced(data, dwordCount * 4, data.Length - (dwordCount * 4))}");
        }

        /// <summary>
        /// Checks if the payload structure matches criteria for extended structured data analysis.
        /// </summary>
        /// <param name="data">The raw byte array of the payload.</param>
        /// <returns>True if the payload appears to be a valid, non-trivial structured block; otherwise, false.</returns>
        private static bool LooksLikeStructuredExPayload(byte[] data)
        {
            int nonZeroCount;
            int dwordCount;

            if (data == null || data.Length < 12)
                return false;

            if ((data.Length % 4) != 0)
                return false;

            dwordCount = data.Length / 4;
            nonZeroCount = 0;

            for (int i = 0; i < dwordCount; i++)
            {
                if (BitConverter.ToUInt32(data, i * 4) != 0)
                    nonZeroCount++;
            }

            if (dwordCount < 3)
                return false;

            return nonZeroCount >= 2;
        }

        /// <summary>
        /// Normalizes and cleans a candidate string by removing extraneous characters, while preserving key symbols.
        /// </summary>
        /// <param name="value">The raw string candidate extracted from the payload.</param>
        /// <returns>A cleaned, trimmed version of the input string.</returns>
        private static string NormalizeAaggCandidate(string value)
        {
            StringBuilder sb;
            bool previousWasSpace;

            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            sb = new StringBuilder(value.Length);
            previousWasSpace = false;

            for (int i = 0; i < value.Length; i++)
            {
                char ch = value[i];

                // Keep alphanumeric characters and specific symbols relevant to expressions/paths.
                if (char.IsLetterOrDigit(ch) ||
                    ch == ':' || ch == '!' || ch == '&' || ch == '|' || ch == '(' ||
                    ch == ')' || ch == '_' || ch == '-' || ch == '.' || ch == '/' ||
                    ch == '\\' || ch == '%')
                {
                    sb.Append(ch);
                    previousWasSpace = false;
                }
                // Collapse multiple whitespace characters into a single space.
                else if (char.IsWhiteSpace(ch))
                {
                    if (!previousWasSpace)
                    {
                        sb.Append(' ');
                        previousWasSpace = true;
                    }
                }
            }

            return sb.ToString().Trim();
        }

        /// <summary>
        /// Analyzes a list of normalized strings to determine the most likely boolean expression structure.
        /// </summary>
        /// <param name="strings">The list of cleaned, distinct string candidates.</param>
        /// <returns>The best candidate expression string found, or an empty string if none is strong enough.</returns>
        private static string FindBestAaggExpression(List<string> strings)
        {
            string best;
            int bestScore;

            best = string.Empty;
            bestScore = -1;

            if (strings == null || strings.Count == 0)
                return string.Empty;

            for (int i = 0; i < strings.Count; i++)
            {
                string s = strings[i];
                int score = ScoreAaggExpressionCandidate(s);

                if (score > bestScore)
                {
                    best = s;
                    bestScore = score;
                }
            }

            if (bestScore < 3)
                return string.Empty;

            return best;
        }

        /// <summary>
        /// Scores a candidate string based on the presence and type of operators/prefixes, indicating its likelihood as an expression.
        /// </summary>
        /// <param name="value">The normalized token to score.</param>
        /// <returns>A numerical score representing the complexity and relevance of the token.</returns>
        private static int ScoreAaggExpressionCandidate(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0;

            int score = 0;
            int operandHits = 0;

            // Scoring based on logical operators.
            if (value.Contains("&", StringComparison.Ordinal)) score += 2;
            if (value.Contains("|", StringComparison.Ordinal)) score += 2;
            if (value.Contains("!", StringComparison.Ordinal)) score += 1;
            if (value.Contains("(", StringComparison.Ordinal) || value.Contains(")", StringComparison.Ordinal)) score += 1;

            // Scoring based on known operand prefixes.
            for (int i = 0; i < OperandPrefixes.Length; i++)
            {
                if (value.Contains(OperandPrefixes[i], StringComparison.OrdinalIgnoreCase))
                {
                    score += 2;
                    operandHits++;
                }
            }

            // Bonus for having multiple recognized operands within the string.
            if (operandHits >= 2) score += 2;
            if (value.Length >= 12) score += 1; // Bonus for length/density.
            return score;
        }

        /// <summary>
        /// Extracts all distinct, ranked operands from a determined expression string.
        /// </summary>
        /// <param name="expression">The best candidate expression string.</param>
        /// <param name="strings">All normalized strings available for reference.</param>
        /// <returns>A list of the top 12 most relevant and ranked operands.</returns>
        private static List<string> ExtractAaggOperands(string expression, List<string> strings)
        {
            List<string> operands;
            IEnumerable<string> candidates;

            operands = new List<string>();

            if (!string.IsNullOrWhiteSpace(expression))
                candidates = TokenizeExpression(expression);
            else
                candidates = strings ?? Enumerable.Empty<string>();

            foreach (string candidate in candidates)
            {
                string token = NormalizeOperand(candidate);
                if (!LooksLikeAaggOperand(token))
                    continue;

                AddRankedOperand(operands, token);
            }

            operands = operands
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(GetOperandRank)
                .ThenBy(s => s, StringComparer.OrdinalIgnoreCase)
                .Take(12)
                .ToList();

            return operands;
        }

        /// <summary>
        /// Splits an expression string into its constituent tokens based on defined separators.
        /// </summary>
        /// <param name="expression">The raw expression string.</param>
        /// <returns>An enumerable collection of individual token strings.</returns>
        private static IEnumerable<string> TokenizeExpression(string expression)
        {
            char[] separators = { '&', '|', '(', ')', ' ' };
            return expression.Split(separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        /// <summary>
        /// Cleans a token by stripping non-essential characters while preserving structural symbols.
        /// </summary>
        /// <param name="token">The raw token string.</param>
        /// <returns>A sanitized, trimmed operand string.</returns>
        private static string NormalizeOperand(string token)
        {
            StringBuilder sb;

            if (string.IsNullOrWhiteSpace(token))
                return string.Empty;

            sb = new StringBuilder(token.Length);

            for (int i = 0; i < token.Length; i++)
            {
                char ch = token[i];

                // Allowed characters: alphanumeric, path/symbol delimiters.
                if (char.IsLetterOrDigit(ch) ||
                    ch == ':' || ch == '!' || ch == '_' || ch == '-' ||
                    ch == '.' || ch == '/' || ch == '\\' || ch == '%')
                {
                    sb.Append(ch);
                }
            }

            return sb.ToString().Trim();
        }

        /// <summary>
        /// Checks if a token matches the structural pattern of an aggregator operand (e.g., starts with a known prefix or is prefixed by '!').
        /// </summary>
        /// <param name="token">The normalized token string.</param>
        /// <returns>True if the token appears to be a valid aggregator operand; otherwise, false.</returns>
        private static bool LooksLikeAaggOperand(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return false;

            if (token.Length < 2)
                return false;

            // Check against known prefixes defined in OperandPrefixes array.
            for (int i = 0; i < OperandPrefixes.Length; i++)
            {
                if (token.StartsWith(OperandPrefixes[i], StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Check for negation prefix '!' followed by content.
            if (token.StartsWith("!", StringComparison.Ordinal) && token.Length >= 3) return true;
            // Check for colon usage, suggesting a key:value structure.
            if (token.Contains(":", StringComparison.Ordinal) && token.Length >= 6) return true;

            return false;
        }

        /// <summary>
        /// Extracts the logical operators (&, |, !, etc.) present in the expression string.
        /// </summary>
        /// <param name="expression">The full expression string.</param>
        /// <returns>A comma-separated string of detected operators.</returns>
        private static string ExtractAaggOperators(string expression)
        {
            List<string> operators;
            if (string.IsNullOrWhiteSpace(expression)) return string.Empty;

            operators = new List<string>();
            if (expression.Contains("&", StringComparison.Ordinal)) operators.Add("&");
            if (expression.Contains("|", StringComparison.Ordinal)) operators.Add("|");
            if (expression.Contains("!", StringComparison.Ordinal)) operators.Add("!");
            if (expression.Contains("(", StringComparison.Ordinal) || expression.Contains(")", StringComparison.Ordinal)) operators.Add("()");
            return string.Join(", ", operators);
        }

        /// <summary>
        /// Checks if the set of normalized strings contains enough candidates that resemble expression fragments.
        /// </summary>
        /// <param name="strings">The list of all normalized candidate strings.</param>
        /// <returns>True if at least one string scores highly as an expression fragment; otherwise, false.</returns>
        private static bool LooksLikeExpressionFragmentSet(List<string> strings)
        {
            if (strings == null || strings.Count == 0)
                return false;

            int count = 0;

            for (int i = 0; i < strings.Count; i++)
            {
                // Score >= 3 indicates a high likelihood of being an expression fragment.
                if (ScoreAaggExpressionCandidate(strings[i]) >= 3)
                    count++;
            }

            return count > 0;
        }

        /// <summary>
        /// Adds the token to the operands list, ensuring uniqueness and preventing redundant entries.
        /// </summary>
        /// <param name="operands">The master list of unique operands.</param>
        /// <param name="token">The operand token to potentially add.</param>
        private static void AddRankedOperand(List<string> operands, string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return;

            // Prevent exact duplicates.
            if (operands.Any(existing => string.Equals(existing, token, StringComparison.OrdinalIgnoreCase)))
                return;

            if (operands.Any(existing => existing.Contains(token, StringComparison.OrdinalIgnoreCase) && existing.Length > token.Length))
                return;

            // Prevent adding a less specific operand if a more specific one already exists that contains it.
            operands.RemoveAll(existing => token.Contains(existing, StringComparison.OrdinalIgnoreCase) && token.Length > existing.Length);
            operands.Add(token);
        }

        /// <summary>
        /// Determines the precedence rank of an operand based on its prefix or structure. Higher number means higher priority.
        /// </summary>
        /// <param name="token">The normalized token string.</param>
        /// <returns>An integer representing the token's processing precedence (1 being lowest).</returns>
        private static int GetOperandRank(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return 0;
            // Highest priority: Negation or explicit attribute flags.
            if (token.StartsWith("!", StringComparison.Ordinal)) return 4;
            if (token.StartsWith("SIGATTR:", StringComparison.OrdinalIgnoreCase)) return 4;

            // High priority: Specific data source prefixes.
            if (token.StartsWith("HSTR:", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("PEHSTR:", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("PESTATIC:", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("NSCRIPT:", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("BRUTE:", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("FOP:", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("TUNNEL:", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("THREAD:", StringComparison.OrdinalIgnoreCase))
            {
                return 3;
            }

            // Medium priority: Tokens containing a key-value separator.
            if (token.Contains(":", StringComparison.Ordinal)) return 2;

            // Lowest priority: Generic tokens.
            return 1;
        }

        /// <summary>
        /// Adds basic numeric hints derived from the raw payload bytes for standard aggregator types.
        /// </summary>
        /// <param name="pattern">The list of strings to which numeric hints will be added.</param>
        /// <param name="data">The raw byte array containing the signature payload.</param>
        private static void AddAggregatorNumericHints(List<string> pattern, byte[] data)
        {
            if (pattern == null || data == null || data.Length == 0)
                return;

            if (data.Length >= 2)
                pattern.Add($"Word0=0x{BitConverter.ToUInt16(data, 0):X4}");

            if (data.Length >= 4)
                pattern.Add($"Dword0=0x{BitConverter.ToUInt32(data, 0):X8}");

            if (data.Length >= 8)
                pattern.Add($"Dword1=0x{BitConverter.ToUInt32(data, 4):X8}");

            if (data.Length >= 12)
                pattern.Add($"Dword2=0x{BitConverter.ToUInt32(data, 8):X8}");
        }

        /// <summary>
        /// Adds compact numeric hints derived from the raw payload bytes for extended aggregator types.
        /// </summary>
        /// <param name="pattern">The list of strings to which numeric hints will be added.</param>
        /// <param name="data">The raw byte array containing the signature payload.</param>
        private static void AddCompactAggregatorNumericHints(List<string> pattern, byte[] data)
        {
            if (pattern == null || data == null || data.Length == 0)
                return;

            if (data.Length >= 4)
                pattern.Add($"Dword0=0x{BitConverter.ToUInt32(data, 0):X8}");

            if (data.Length >= 8)
                pattern.Add($"Dword1=0x{BitConverter.ToUInt32(data, 4):X8}");
        }
    }

    /// <summary>
    /// Parser class for bitmap/info-like structures (BM_INFO).
    /// </summary>
    private sealed class BmInfoParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_BM_INFO".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_BM_INFO", StringComparison.Ordinal);
        }

        /// <summary>
        /// Parses the raw byte data of a bitmap/info-like record to extract structural hints and readable strings.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes for the BM_INFO structure.</param>
        /// <returns>A DecodedSignature object detailing hex previews, numeric values, and extracted strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            DecodedSignature decoded = new DecodedSignature
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "BITMAP_INFO",
                ConditionValue = data?.Length ?? 0,
                DecodeConfidence = "Low",
                Notes = "Bitmap/info-like payload interpreted heuristically"
            };

            if (data == null || data.Length == 0)
            {
                decoded.ConditionType = "EMPTY";
                decoded.ConditionValue = 0;
                decoded.Notes = "Empty bitmap/info-like payload";
                return decoded;
            }

            decoded.Pattern.Add($"Length={data.Length}");

            if (data.Length <= 32)
                decoded.Pattern.Add($"Hex={DecodeHexHelper.ToHexSpaced(data, 0, data.Length)}");
            else
                decoded.Pattern.Add($"Preview={DecodeHexHelper.ToHexSpaced(data, 0, 32)}");

            if (data.Length >= 2)
                decoded.Pattern.Add($"Word0=0x{BitConverter.ToUInt16(data, 0):X4}");

            if (data.Length >= 4)
                decoded.Pattern.Add($"Dword0=0x{BitConverter.ToUInt32(data, 0):X8}");

            if (data.Length >= 8)
                decoded.Pattern.Add($"Dword1=0x{BitConverter.ToUInt32(data, 4):X8}");

            if (data.Length >= 12)
                decoded.Pattern.Add($"Dword2=0x{BitConverter.ToUInt32(data, 8):X8}");

            // Collect and normalize readable strings from the payload.
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 4);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings);

            for (int i = 0; i < normalized.Count && i < 6; i++)
                decoded.Pattern.Add($"String[{i}]={normalized[i]}");

            if (LooksLikeUniformWordGrid(data))
            {
                decoded.DecodeConfidence = "Medium";
                decoded.Notes = "Bitmap/info-like payload shows regular word-aligned structure";
            }
            else if (normalized.Count > 0)
            {
                decoded.DecodeConfidence = "Medium";
                decoded.Notes = "Bitmap/info-like payload contains embedded readable strings";
            }

            return decoded;
        }

        /// <summary>
        /// Checks if the byte array exhibits characteristics of a uniform word grid structure (many zeroed pairs).
        /// </summary>
        /// <param name="data">The raw data buffer to check.</param>
        /// <returns>True if the data appears structured like a uniform word grid; otherwise, false.</returns>
        private static bool LooksLikeUniformWordGrid(byte[] data)
        {
            // Must be at least 8 bytes and have an even length.
            if (data == null || data.Length < 8 || (data.Length % 2) != 0)
                return false;

            int evenZeroCount = 0;
            int wordCount = data.Length / 2;

            for (int i = 0; i < data.Length; i += 2)
            {
                if (data[i] == 0 && data[i + 1] == 0)
                    evenZeroCount++;
            }

            return evenZeroCount > 0 && evenZeroCount * 3 >= wordCount;
        }
    }

    /// <summary>
    /// Generic parser that treats any input as raw binary data if no specific parser matches.
    /// </summary>
    private sealed class GenericBinarySignatureParser : ISignatureParser
    {
        public bool CanParse(byte signatureType, string signatureTypeName) => true;

        /// <summary>
        /// Parses the raw data by converting the entire payload into a space-separated hexadecimal string.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes for the generic binary fallback.</param>
        /// <returns>A DecodedSignature object containing the full hex representation of the data.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            DecodedSignature decoded = new()
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "PRESENT",
                ConditionValue = 1,
                DecodeConfidence = "Low",
                Notes = "Generic binary fallback"
            };

            decoded.Pattern.Add(DecodeHexHelper.ToHexSpaced(data, 0, data.Length));
            return decoded;
        }
    }

    /// <summary>
    /// Generic parser designed to extract readable strings from various signature types that might contain text dumps.
    /// </summary>
    private sealed class GenericTextDumpParser : ISignatureParser
    {
        private static readonly HashSet<string> SupportedTypes = new(StringComparer.Ordinal)
        {
            "SIGNATURE_TYPE_FILENAME",
            "SIGNATURE_TYPE_FILEPATH",
            "SIGNATURE_TYPE_FOLDERNAME",
            "SIGNATURE_TYPE_ASEP_FILEPATH",
            "SIGNATURE_TYPE_ASEP_FOLDERNAME",
            "SIGNATURE_TYPE_REGKEY"
        };

        /// <summary>
        /// Checks if this parser is applicable to the given signature type name.
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return SupportedTypes.Contains(signatureTypeName);
        }

        /// <summary>
        /// Extracts all candidate strings from the payload and returns them as a text dump result if any are found.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes for the text extraction.</param>
        /// <returns>A DecodedSignature object containing extracted strings, or a blob fallback if none are found.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 4);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: false);

            if (normalized.Count > 0)
            {
                DecodedSignature decoded = new()
                {
                    Type = context.SignatureTypeName,
                    Offset = $"0x{context.RecordOffset:X}",
                    ConditionType = "TEXT_DUMP",
                    ConditionValue = normalized.Count,
                    DecodeConfidence = "Low",
                    Notes = "Generic readable text extracted"
                };

                for (int i = 0; i < normalized.Count; i++)
                    decoded.Pattern.Add(normalized[i]);

                return decoded;
            }

            // If no text is found, fall back to showing the raw data as a blob.
            return DecodeResultFactory.CreateBlobFallback(context, data, "No readable text recognized; included hex view", "Low");
        }
    }

    /// <summary>
    /// Parser for signatures based on SHA256 hash values.
    /// </summary>
    private sealed class FriendlyFileSha256Parser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_FRIENDLYFILE_SHA256".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_FRIENDLYFILE_SHA256", StringComparison.Ordinal);
        }

        /// <summary>
        /// Parses the SHA256 hash payload, extracting the hash and any subsequent readable strings from the tail data.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing the hash and potential extra data.</param>
        /// <returns>A DecodedSignature object detailing the SHA256 match and any extracted strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            if (data == null || data.Length < 32)
                return DecodeResultFactory.CreateBlobFallback(context, data, "Payload too small for SHA256", "Low");

            DecodedSignature decoded = new()
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "HASH_MATCH",
                ConditionValue = 1,
                DecodeConfidence = "High",
                Notes = "Structured SHA256 payload recognized"
            };

            decoded.Pattern.Add("SHA256=" + DecodeHexHelper.ToHex(data, 0, 32));

            if (data.Length > 32)
            {
                byte[] tail = new byte[data.Length - 32];
                Buffer.BlockCopy(data, 32, tail, 0, tail.Length);

                List<string> strings = DecodeTextHelper.CollectCandidateStrings(tail, 2);
                List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings);

                for (int i = 0; i < normalized.Count; i++)
                    decoded.Pattern.Add(normalized[i]);
            }

            return decoded;
        }
    }

    /// <summary>
    /// Parser for registry key paths found within the signature data.
    /// </summary>
    private sealed class RegKeyParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_REGKEY".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_REGKEY", StringComparison.Ordinal);
        }

        /// <summary>
        /// Parses registry-like strings by normalizing path separators and mapping common short prefixes to full registry root names.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential registry paths.</param>
        /// <returns>A DecodedSignature object listing normalized, canonicalized registry paths.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 3);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: true, normalizeSlashes: true);

            for (int i = 0; i < normalized.Count; i++)
                normalized[i] = NormalizeRegistryPath(normalized[i]);

            normalized = DecodeTextHelper.NormalizeAndDistinct(normalized, ignoreCase: true);

            if (normalized.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable registry path recognized");

            return DecodeResultFactory.CreateTextResult(context, "REGISTRY_MATCH", normalized, "Low", "Readable registry-like strings extracted");
        }

        /// <summary>
        /// Converts common short or slash-based registry path prefixes (e.g., HKCR\, HKU\) into canonical Windows Registry root names.
        /// </summary>
        /// <param name="value">The raw string candidate from the payload.</param>
        /// <returns>The fully qualified, normalized registry path string.</returns>
        private static string NormalizeRegistryPath(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return value;

            string s = value.Replace('/', '\\').Trim();

            if (s.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
                return "HKEY_LOCAL_MACHINE" + s[4..];
            if (s.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
                return "HKEY_CURRENT_USER" + s[4..];
            if (s.StartsWith("HKCR\\", StringComparison.OrdinalIgnoreCase))
                return "HKEY_CLASSES_ROOT" + s[4..];
            if (s.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase))
                return "HKEY_USERS" + s[3..];

            return s;
        }
    }

    /// <summary>
    /// Parser for signatures based on file paths or filenames found in the data.
    /// </summary>
    private sealed class FilePathParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles either "SIGNATURE_TYPE_FILEPATH" or "SIGNATURE_TYPE_FILENAME".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_FILEPATH", StringComparison.Ordinal) ||
                   string.Equals(signatureTypeName, "SIGNATURE_TYPE_FILENAME", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts and normalizes file path or filename strings from the payload. If parsing a FILENAME, it extracts only the base name if a full path is detected.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential file paths/names.</param>
        /// <returns>A DecodedSignature object listing normalized file names or full paths.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 2);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: true, normalizeSlashes: true);

            if (string.Equals(context.SignatureTypeName, "SIGNATURE_TYPE_FILENAME", StringComparison.Ordinal))
            {
                for (int i = 0; i < normalized.Count; i++)
                {
                    if (LooksLikePath(normalized[i]))
                        normalized[i] = Path.GetFileName(normalized[i]);
                }

                normalized = DecodeTextHelper.NormalizeAndDistinct(normalized, ignoreCase: true);
            }

            if (normalized.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable file path recognized");

            string conditionType = string.Equals(context.SignatureTypeName, "SIGNATURE_TYPE_FILENAME", StringComparison.Ordinal)
                ? "FILENAME_MATCH"
                : "FILEPATH_MATCH";

            return DecodeResultFactory.CreateTextResult(context, conditionType, normalized, "Low", "Readable file path strings extracted");
        }

        /// <summary>
        /// Determines if a given string contains characters indicative of a file system path (slashes or colons).
        /// </summary>
        /// <param name="value">The string to check.</param>
        /// <returns>True if the string resembles a path; otherwise, false.</returns>
        private static bool LooksLikePath(string value)
        {
            return !string.IsNullOrWhiteSpace(value) &&
                   (value.Contains("\\", StringComparison.Ordinal) ||
                    value.Contains("/", StringComparison.Ordinal) ||
                    value.Contains(":", StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// Parser for signatures based on folder names (directory structures).
    /// </summary>
    private sealed class FolderNameParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_FOLDERNAME".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_FOLDERNAME", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts and normalizes folder/path-like strings from the payload.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential folder names.</param>
        /// <returns>A DecodedSignature object listing normalized, path-like strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 2);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: true, trimTrailingBackslash: true, normalizeSlashes: true);

            if (normalized.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable folder name recognized");

            return DecodeResultFactory.CreateTextResult(context, "FOLDER_MATCH", normalized, "Low", "Readable folder/path-like strings extracted");
        }
    }

    /// <summary>
    /// Parser for signatures based on ASEP file paths.
    /// </summary>
    private sealed class AsepFilepathParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_ASEP_FILEPATH".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_ASEP_FILEPATH", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts and normalizes ASEP file path strings from the payload.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential ASEP file paths.</param>
        /// <returns>A DecodedSignature object listing normalized ASEP file path strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 2);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: true, normalizeSlashes: true);

            if (normalized.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable ASEP file path recognized");

            return DecodeResultFactory.CreateTextResult(context, "ASEP_FILEPATH_MATCH", normalized, "Low", "Readable ASEP file path strings extracted");
        }
    }

    /// <summary>
    /// Parser for signatures based on ASEP folder names (directory structures).
    /// </summary>
    private sealed class AsepFoldernameParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_ASEP_FOLDERNAME".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_ASEP_FOLDERNAME", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts and normalizes ASEP folder/path-like strings from the payload, ensuring trailing backslashes are removed.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential ASEP folder names.</param>
        /// <returns>A DecodedSignature object listing normalized ASEP folder/path strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 2);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: true, trimTrailingBackslash: true, normalizeSlashes: true);

            if (normalized.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable ASEP folder name recognized");

            return DecodeResultFactory.CreateTextResult(context, "ASEP_FOLDER_MATCH", normalized, "Low", "Readable ASEP folder/path-like strings extracted");
        }
    }

    /// <summary>
    /// Parser for signatures containing PUA application map data.
    /// </summary>
    private sealed class PuaAppMapParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_PUA_APPMAP".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_PUA_APPMAP", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts and normalizes readable strings from the PUA application map payload.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential app map content.</param>
        /// <returns>A DecodedSignature object listing extracted PUA app map strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 2);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: true);

            if (normalized.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable PUA app map content recognized");

            return DecodeResultFactory.CreateTextResult(context, "PUA_APP_MAP", normalized, "Low", "Readable PUA app map strings extracted");
        }
    }

    /// <summary>
    /// Parser for signatures containing standalone Lua script content.
    /// </summary>
    private sealed class LuaStandaloneParser : ISignatureParser
    {
        // Keywords indicating malware verdict status found within the Lua strings.
        private static readonly HashSet<string> VerdictWords = new(StringComparer.OrdinalIgnoreCase)
        {
            "CLEAN",
            "INFECTED"
        };

        // Keywords related to Portable Executable (PE) file structure elements.
        private static readonly HashSet<string> ModuleWords = new(StringComparer.OrdinalIgnoreCase)
        {
            "mp",
            "pehdr",
            "pesecs",
            "peattributes"
        };

        // Keywords corresponding to standard PE header fields.
        private static readonly HashSet<string> PeFieldWords = new(StringComparer.OrdinalIgnoreCase)
        {
            "NumberOfSections",
            "VirtualAddress",
            "VirtualSize",
            "SizeOfCode",
            "SizeOfImage",
            "DataDirectory",
            "Size",
            "Subsystem",
            "Characteristics",
            "MajorLinkerVersion",
            "MinorLinkerVersion",
            "SizeOfHeaders",
            "MajorSubsystemVersion",
            "DllCharacteristics"
        };

        // Keywords related to PE file attributes.
        private static readonly HashSet<string> AttributeWords = new(StringComparer.OrdinalIgnoreCase)
        {
            "epinfirstsect",
            "hasstandardentry",
            "packed",
            "peattributes"
        };

        private static readonly HashSet<string> HelperWords = new(StringComparer.OrdinalIgnoreCase)
        {
            "readu_u32",
            "epcode",
            "readprotection",
            "readfile",
            "foffset_rva",
            "crc32"
        };

        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_LUASTANDALONE".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_LUASTANDALONE", StringComparison.Ordinal);
        }

        /// <summary>
        /// Parses the Lua payload by extracting all candidate strings, filtering them based on usefulness (Lua-specific keywords or structure), and categorizing findings into modules, PE fields, attributes, and verdicts.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing Lua script content.</param>
        /// <returns>A DecodedSignature object detailing extracted strings and metadata, or a fallback if empty.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            DecodedSignature decoded;
            List<string> allStrings;
            List<string> filteredStrings;
            List<string> modules;
            List<string> peFields;
            List<string> attributes;
            List<string> verdicts;
            List<string> helpers;
            bool isCompiledChunk;
            int chunkOffset;
            string exportedPath;

            decoded = new DecodedSignature
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "LUA_SCRIPT",
                ConditionValue = data?.Length ?? 0,
                DecodeConfidence = "Low",
                Notes = "Lua payload interpreted heuristically"
            };

            if (data == null || data.Length == 0)
            {
                decoded.ConditionType = "EMPTY";
                decoded.ConditionValue = 0;
                decoded.Notes = "Empty Lua payload";
                return decoded;
            }

            isCompiledChunk = TryFindLuaChunk(data, out chunkOffset);
            allStrings = DecodeTextHelper.NormalizeAndDistinct(DecodeTextHelper.CollectCandidateStrings(data, 2));
            filteredStrings = allStrings
                .Where(IsUsefulLuaString)
                .ToList();

            modules = filteredStrings
                .Where(s => ModuleWords.Contains(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList();

            peFields = filteredStrings
                .Where(s => PeFieldWords.Contains(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList();

            attributes = filteredStrings
                .Where(s => AttributeWords.Contains(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList();

            verdicts = filteredStrings
                .Where(s => VerdictWords.Contains(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList();

            helpers = filteredStrings
                .Where(s => HelperWords.Contains(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList();

            decoded.ConditionType = isCompiledChunk ? "COMPILED_LUA_CHUNK" : "LUA_SCRIPT";
            decoded.ConditionValue = data.Length;

            if (isCompiledChunk)
            {
                decoded.Pattern.Add("ChunkSignature=Lua");
                decoded.Pattern.Add($"ChunkOffset=0x{chunkOffset:X}");

                if (context.ExtractLua)
                {
                    decoded.Pattern.Add($"ChunkStartBytes={DecodeHexHelper.ToHexSpaced(data, chunkOffset, Math.Min(8, data.Length - chunkOffset))}");
                    exportedPath = ExportLuaChunk(context, data, chunkOffset);
                    if (!string.IsNullOrWhiteSpace(exportedPath))
                        decoded.Pattern.Add($"ExportedChunk={exportedPath}");
                }
            }

            decoded.Pattern.Add($"StringCount={allStrings.Count}");
            decoded.Pattern.Add($"InterestingStringCount={filteredStrings.Count}");

            for (int i = 0; i < modules.Count && i < 8; i++)
                decoded.Pattern.Add($"Module[{i}]={modules[i]}");

            for (int i = 0; i < peFields.Count && i < 16; i++)
                decoded.Pattern.Add($"PeField[{i}]={peFields[i]}");

            for (int i = 0; i < attributes.Count && i < 12; i++)
                decoded.Pattern.Add($"Attribute[{i}]={attributes[i]}");

            for (int i = 0; i < helpers.Count && i < 12; i++)
                decoded.Pattern.Add($"Helper[{i}]={helpers[i]}");

            for (int i = 0; i < verdicts.Count && i < 8; i++)
                decoded.Pattern.Add($"Verdict[{i}]={verdicts[i]}");

            if (modules.Count == 0 && peFields.Count == 0 && attributes.Count == 0 && helpers.Count == 0 && verdicts.Count == 0)
            {
                for (int i = 0; i < filteredStrings.Count && i < 12; i++)
                    decoded.Pattern.Add($"String[{i}]={filteredStrings[i]}");
            }
            else
            {
                List<string> extras = filteredStrings
                    .Where(s =>
                        !modules.Contains(s, StringComparer.OrdinalIgnoreCase) &&
                        !peFields.Contains(s, StringComparer.OrdinalIgnoreCase) &&
                        !attributes.Contains(s, StringComparer.OrdinalIgnoreCase) &&
                        !helpers.Contains(s, StringComparer.OrdinalIgnoreCase) &&
                        !verdicts.Contains(s, StringComparer.OrdinalIgnoreCase))
                    .Take(8)
                    .ToList();

                for (int i = 0; i < extras.Count; i++)
                    decoded.Pattern.Add($"Extra[{i}]={extras[i]}");
            }

            if (isCompiledChunk && (peFields.Count > 0 || attributes.Count > 0))
            {
                decoded.DecodeConfidence = "Medium";
                decoded.Notes = "Embedded compiled Lua chunk with PE-header and PE-attribute inspection constants";
            }
            else if (isCompiledChunk)
            {
                decoded.DecodeConfidence = "Medium";
                decoded.Notes = "Embedded compiled Lua chunk with readable constant table";
            }
            else if (filteredStrings.Count > 0)
            {
                decoded.DecodeConfidence = "Low";
                decoded.Notes = "Readable Lua-related strings extracted";
            }
            else
            {
                decoded.Pattern.Add($"Preview={DecodeHexHelper.ToHexSpaced(data, 0, Math.Min(data.Length, 48))}");
                decoded.Notes = "Lua payload rendered as bounded binary fallback";
            }

            return decoded;
        }

        /// <summary>
        /// Searches the data for a specific byte sequence indicating the start of a compiled Lua chunk (e.g., 0x1B 'L' 'u' 'a').
        /// </summary>
        /// <param name="data">The raw payload bytes.</param>
        /// <param name="chunkOffset">Output: The starting offset if found, otherwise -1.</param>
        /// <returns>True if the Lua chunk signature was found, false otherwise.</returns>
        private static bool TryFindLuaChunk(byte[] data, out int chunkOffset)
        {
            chunkOffset = -1;

            if (data == null || data.Length < 4)
                return false;

            for (int i = 0; i <= data.Length - 4; i++)
            {
                if (data[i] == 0x1B &&
                    data[i + 1] == (byte)'L' &&
                    data[i + 2] == (byte)'u' &&
                    data[i + 3] == (byte)'a')
                {
                    chunkOffset = i;
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines if a string is likely relevant to Lua analysis by checking for keywords or structural properties.
        /// </summary>
        /// <param name="value">The candidate string.</param>
        /// <returns>True if the string appears useful in a Lua context, false otherwise.</returns>
        private static bool IsUsefulLuaString(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            value = value.Trim();

            if (value.Length < 2)
                return false;

            if (IsLikelyLuaNoise(value))
                return false;

            if (ModuleWords.Contains(value) ||
                PeFieldWords.Contains(value) ||
                AttributeWords.Contains(value) ||
                VerdictWords.Contains(value) ||
                HelperWords.Contains(value))
            {
                return true;
            }

            if (string.Equals(value, "LuaQ", StringComparison.OrdinalIgnoreCase))
                return true;

            if (value.Length >= 4 && value.All(ch => char.IsLetterOrDigit(ch) || ch == '_' || ch == ':'))
                return true;

            return false;
        }

        /// <summary>
        /// Heuristically filters out strings that appear to be Lua noise (e.g., short, heavily punctuated, or starting/ending with '@').
        /// </summary>
        private static bool IsLikelyLuaNoise(string value)
        {
            int letterCount;
            int punctuationCount;

            if (string.IsNullOrWhiteSpace(value))
                return true;

            if (value.Length <= 3)
            {
                if (value.StartsWith("@", StringComparison.Ordinal) ||
                    value.EndsWith("@", StringComparison.Ordinal) ||
                    value.Contains("@", StringComparison.Ordinal))
                {
                    return true;
                }
            }

            letterCount = 0;
            punctuationCount = 0;

            for (int i = 0; i < value.Length; i++)
            {
                char ch = value[i];

                if (char.IsLetter(ch))
                    letterCount++;
                else if (!char.IsDigit(ch))
                    punctuationCount++;
            }

            if (letterCount == 0)
                return true;

            if (value.Length <= 4 && punctuationCount > 0)
                return true;

            return false;
        }
    }

    /// <summary>
    /// Parser for signatures containing default configuration or settings data.
    /// </summary>
    private sealed class DefaultsParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_DEFAULTS".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_DEFAULTS", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts and filters readable strings from the defaults payload, keeping only those deemed useful configuration data.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential default settings.</param>
        /// <returns>A DecodedSignature object listing filtered, useful defaults strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 2);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings);
            List<string> filtered = new List<string>();

            for (int i = 0; i < normalized.Count; i++)
            {
                string s = normalized[i];

                if (IsUsefulDefaultsString(s))
                    filtered.Add(s);
            }

            if (filtered.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable defaults/config data recognized");

            return DecodeResultFactory.CreateTextResult(context, "DEFAULTS_DATA", filtered, "Low", "Readable defaults/config-like strings extracted");
        }
    }

    /// <summary>
    /// Parser for static data blobs, attempting to classify them as textual, structured binary, or hash-like content.
    /// </summary>
    private sealed class StaticParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_STATIC".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_STATIC", StringComparison.Ordinal);
        }

        /// <summary>
        /// Analyzes the static payload to determine its nature (textual, structured binary, etc.) and extracts relevant information.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes for the static data.</param>
        /// <returns>A DecodedSignature object detailing the classification, confidence, and extracted content.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings;
            List<string> normalized;
            string hexPreview;

            DecodedSignature decoded = new DecodedSignature
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "STATIC_DATA",
                ConditionValue = data?.Length ?? 0,
                DecodeConfidence = "Low",
                Notes = "Static payload classified heuristically"
            };

            if (data == null || data.Length == 0)
            {
                decoded.ConditionType = "EMPTY";
                decoded.ConditionValue = 0;
                decoded.Notes = "Empty static payload";
                return decoded;
            }

            strings = DecodeTextHelper.CollectCandidateStrings(data, 4);
            normalized = DecodeTextHelper.NormalizeAndDistinct(strings);

            if (normalized.Count > 0 && LooksMostlyTextual(normalized))
            {
                decoded.DecodeConfidence = "Medium";
                decoded.Notes = "Static payload contains readable string content";

                for (int i = 0; i < normalized.Count && i < 12; i++)
                    decoded.Pattern.Add(normalized[i]);

                if (normalized.Count > 12)
                    decoded.Pattern.Add($"... +{normalized.Count - 12} more strings");

                return decoded;
            }

            if (LooksLikeUtf16TextBlock(data))
            {
                string utf16Text = ExtractUtf16TextPreview(data);
                if (!string.IsNullOrWhiteSpace(utf16Text))
                {
                    decoded.DecodeConfidence = "Medium";
                    decoded.Notes = "Static payload appears to contain UTF-16 text";
                    decoded.Pattern.Add(utf16Text);
                    return decoded;
                }
            }

            if (LooksLikeGuidOrPathSet(normalized))
            {
                decoded.DecodeConfidence = "Medium";
                decoded.Notes = "Static payload contains config/path/GUID-like strings";

                for (int i = 0; i < normalized.Count && i < 12; i++)
                    decoded.Pattern.Add(normalized[i]);

                if (normalized.Count > 12)
                    decoded.Pattern.Add($"... +{normalized.Count - 12} more strings");

                return decoded;
            }

            if (LooksLikeHashLikeBlob(data))
            {
                decoded.DecodeConfidence = "Low";
                decoded.Notes = "Static payload resembles compact hash/identifier-like binary";
                decoded.Pattern.Add($"Length={data.Length}");
                decoded.Pattern.Add($"Hex={DecodeHexHelper.ToHexSpaced(data, 0, data.Length)}");
                return decoded;
            }

            if (LooksLikeStructuredStaticBlob(data))
            {
                decoded.DecodeConfidence = "Medium";
                decoded.Notes = "Static payload shows regular structured binary layout";
                decoded.Pattern.Add($"Length={data.Length}");

                if (data.Length >= 4)
                    decoded.Pattern.Add($"Dword0=0x{BitConverter.ToUInt32(data, 0):X8}");
                if (data.Length >= 8)
                    decoded.Pattern.Add($"Dword1=0x{BitConverter.ToUInt32(data, 4):X8}");
                if (data.Length >= 12)
                    decoded.Pattern.Add($"Dword2=0x{BitConverter.ToUInt32(data, 8):X8}");

                hexPreview = DecodeHexHelper.ToHexSpaced(data, 0, Math.Min(data.Length, 32));
                decoded.Pattern.Add($"Preview={hexPreview}");
                return decoded;
            }

            decoded.DecodeConfidence = "Low";
            decoded.Notes = "Generic static binary fallback";
            decoded.Pattern.Add(DecodeHexHelper.ToHexSpaced(data, 0, Math.Min(data.Length, 32)));

            if (data.Length > 32)
                decoded.Pattern.Add($"Length={data.Length}");

            return decoded;
        }

        /// <summary>
        /// Heuristically determines if the collected strings are predominantly textual in nature.
        /// </summary>
        /// <param name="strings">The list of normalized candidate strings.</param>
        /// <returns>True if a significant portion of strings meet basic text criteria; otherwise, false.</returns>
        private static bool LooksMostlyTextual(List<string> strings)
        {
            int usefulCount;

            if (strings == null || strings.Count == 0)
                return false;

            usefulCount = 0;

            for (int i = 0; i < strings.Count; i++)
            {
                string s = strings[i];

                if (string.IsNullOrWhiteSpace(s))
                    continue;

                if (s.Length >= 6)
                    usefulCount++;

                if (s.Contains("\\", StringComparison.Ordinal) ||
                    s.Contains("/", StringComparison.Ordinal) ||
                    s.Contains(".", StringComparison.Ordinal) ||
                    s.Contains("%", StringComparison.Ordinal))
                {
                    usefulCount++;
                }
            }

            return usefulCount >= 2;
        }

        /// <summary>
        /// Checks if the data stream exhibits characteristics of a UTF-16 encoded text block (high density of null bytes).
        /// </summary>
        /// <param name="data">The raw byte array to check.</param>
        /// <returns>True if the data appears to be structured as UTF-16; otherwise, false.</returns>
        private static bool LooksLikeUtf16TextBlock(byte[] data)
        {
            int zeroOddCount;
            int pairs;

            if (data == null || data.Length < 8 || (data.Length % 2) != 0)
                return false;

            zeroOddCount = 0;
            pairs = data.Length / 2;

            for (int i = 1; i < data.Length; i += 2)
            {
                if (data[i] == 0)
                    zeroOddCount++;
            }

            return zeroOddCount * 2 >= pairs;
        }

        /// <summary>
        /// Extracts a preview of text content assuming the data is encoded in UTF-16.
        /// </summary>
        /// <param name="data">The raw byte array to decode.</param>
        /// <returns>A string containing the decoded text preview, or an empty string if decoding fails.</returns>
        private static string ExtractUtf16TextPreview(byte[] data)
        {
            string text;
            List<string> strings;

            try
            {
                text = Encoding.Unicode.GetString(data).Trim('\0', ' ', '\r', '\n', '\t');
            }
            catch
            {
                return string.Empty;
            }

            if (string.IsNullOrWhiteSpace(text))
                return string.Empty;

            strings = DecodeTextHelper.NormalizeAndDistinct(
                DecodeTextHelper.CollectCandidateStrings(Encoding.Unicode.GetBytes(text), 4));

            if (strings.Count > 0)
                return string.Join(" | ", strings.Take(8));

            return text.Length > 120 ? text.Substring(0, 120) : text;
        }

        /// <summary>
        /// Checks if the collected strings resemble GUIDs or file paths/identifiers.
        /// </summary>
        /// <param name="strings">The list of normalized candidate strings.</param>
        /// <returns>True if a sufficient number of strings match identifier/path patterns; otherwise, false.</returns>
        private static bool LooksLikeGuidOrPathSet(List<string> strings)
        {
            int score;

            if (strings == null || strings.Count == 0)
                return false;

            score = 0;

            for (int i = 0; i < strings.Count; i++)
            {
                string s = strings[i];

                if (s.Contains("\\", StringComparison.Ordinal) || s.Contains("/", StringComparison.Ordinal))
                    score++;

                if (s.Contains("{", StringComparison.Ordinal) &&
                    s.Contains("}", StringComparison.Ordinal) &&
                    s.Contains("-", StringComparison.Ordinal))
                    score++;

                if (s.Contains(".dll", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains(".exe", StringComparison.OrdinalIgnoreCase))
                    score++;
            }

            return score >= 2;
        }

        /// <summary>
        /// Checks if the data length matches common sizes for cryptographic hashes (16, 20, 32, or 64 bytes).
        /// </summary>
        /// <param name="data">The raw byte array.</param>
        /// <returns>True if the length suggests a hash blob; otherwise, false.</returns>
        private static bool LooksLikeHashLikeBlob(byte[] data)
        {
            if (data == null)
                return false;

            return data.Length == 16 || data.Length == 20 || data.Length == 32 || data.Length == 64;
        }

        /// <summary>
        /// Checks if the data exhibits characteristics of a structured binary layout (e.g., fixed-size records with many zeroed entries).
        /// </summary>
        /// <param name="data">The raw byte array to check.</param>
        /// <returns>True if the structure suggests regular, potentially sparse, binary data; otherwise, false.</returns>
        private static bool LooksLikeStructuredStaticBlob(byte[] data)
        {
            int zeroDwordCount;
            int dwordCount;

            if (data == null || data.Length < 16 || (data.Length % 4) != 0)
                return false;

            zeroDwordCount = 0;
            dwordCount = data.Length / 4;

            for (int i = 0; i + 4 <= data.Length; i += 4)
            {
                if (BitConverter.ToUInt32(data, i) == 0)
                    zeroDwordCount++;
            }

            return zeroDwordCount > 0 && zeroDwordCount * 3 >= dwordCount;
        }
    }

    /// <summary>
    /// Parser for signatures containing PEP code snippets.
    /// </summary>
    private sealed class PepCodeParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_PEPCODE".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_PEPCODE", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts and normalizes readable strings from the PEP code payload.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential PEP code snippets.</param>
        /// <returns>A DecodedSignature object listing extracted PEP code-like strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 3);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: false);

            if (normalized.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable PEP code content recognized");

            return DecodeResultFactory.CreateTextResult(context, "PEP_CODE", normalized, "Low", "Readable PEP code-like strings extracted");
        }
    }

    /// <summary>
    /// Parser for signatures containing NSCRIPT_SP (Script Pattern) data.
    /// </summary>
    private sealed class NscriptSpParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_NSCRIPT_SP".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_NSCRIPT_SP", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts and normalizes readable strings from the NSCRIPT_SP payload.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential script pattern data.</param>
        /// <returns>A DecodedSignature object listing extracted script-pattern strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 2);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: false);

            if (normalized.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable NSCRIPT_SP content recognized");

            return DecodeResultFactory.CreateTextResult(context, "SCRIPT_PATTERN", normalized, "Low", "Readable script-pattern strings extracted");
        }
    }

    /// <summary>
    /// Parser for signatures containing NSCRIPT_CURE data.
    /// </summary>
    private sealed class NscriptCureParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_NSCRIPT_CURE".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_NSCRIPT_CURE", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts and normalizes readable strings from the NSCRIPT_CURE payload.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential script cure data.</param>
        /// <returns>A DecodedSignature object listing extracted script-cure strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 2);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: false);

            if (normalized.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable NSCRIPT_CURE content recognized");

            return DecodeResultFactory.CreateTextResult(context, "SCRIPT_CURE", normalized, "Low", "Readable script-cure strings extracted");
        }
    }

    /// <summary>
    /// Parser for signatures containing NDAT related information.
    /// </summary>
    private sealed class NdatParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_NDAT".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_NDAT", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts and normalizes readable strings from the NDAT payload.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing potential NDAT content.</param>
        /// <returns>A DecodedSignature object listing extracted NDAT-related strings.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 2);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: true);

            if (normalized.Count == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "No readable NDAT content recognized");

            return DecodeResultFactory.CreateTextResult(context, "NDAT_DATA", normalized, "Low", "Readable NDAT-related strings extracted");
        }
    }

    /// <summary>
    /// Parser for signatures matching specific identifier types (NID, SNID, NID64).
    /// </summary>
    private sealed class NidLikeParser : ISignatureParser
    {
        // Defines the set of signature types this parser supports.
        private static readonly HashSet<string> SupportedTypes = new(StringComparer.Ordinal)
        {
            "SIGNATURE_TYPE_NID",
            "SIGNATURE_TYPE_SNID",
            "SIGNATURE_TYPE_NID64"
        };

        /// <summary>
        /// Checks if this parser handles any of the supported identifier signature types.
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return SupportedTypes.Contains(signatureTypeName);
        }

        /// <summary>
        /// Parses the compact identifier payload by rendering the raw bytes as a hexadecimal string.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing the identifier data.</param>
        /// <returns>A DecodedSignature object showing the hex representation of the ID.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            DecodedSignature decoded = new()
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "ID_MATCH",
                ConditionValue = 1,
                DecodeConfidence = "Low",
                Notes = "Compact identifier-like payload rendered as hex"
            };

            if (data == null || data.Length == 0)
            {
                decoded.ConditionType = "EMPTY";
                decoded.ConditionValue = 0;
                decoded.Notes = "Empty identifier-like payload";
                return decoded;
            }

            decoded.Pattern.Add(DecodeHexHelper.ToHexSpaced(data, 0, data.Length));
            return decoded;
        }
    }

    /// <summary>
    /// Parser for signatures matching extended identifier types (SNIDEX, SNIDEX2).
    /// </summary>
    private sealed class SnidExParser : ISignatureParser
    {
        // Defines the set of signature types this parser supports.
        private static readonly HashSet<string> SupportedTypes = new(StringComparer.Ordinal)
        {
            "SIGNATURE_TYPE_SNIDEX",
            "SIGNATURE_TYPE_SNIDEX2"
        };

        /// <summary>
        /// Checks if this parser handles any of the supported extended identifier signature types.
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return SupportedTypes.Contains(signatureTypeName);
        }

        /// <summary>
        /// Parses the extended identifier payload by logging its length and rendering it as hex, providing structural notes based on size.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing the extended identifier data.</param>
        /// <returns>A DecodedSignature object detailing the length, hex representation, and structural notes.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            DecodedSignature decoded = new DecodedSignature
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "EXTENDED_ID_MATCH",
                ConditionValue = 1,
                DecodeConfidence = "Low",
                Notes = "Extended identifier-like payload rendered as compact structured data"
            };

            if (data == null || data.Length == 0)
            {
                decoded.ConditionType = "EMPTY";
                decoded.ConditionValue = 0;
                decoded.Notes = "Empty extended identifier-like payload";
                return decoded;
            }

            int length = data.Length;

            decoded.Pattern.Add($"Length={length}");
            decoded.Pattern.Add($"Hex={DecodeHexHelper.ToHexSpaced(data, 0, data.Length)}");

            if (data.Length >= 4)
                decoded.Pattern.Add($"Dword0=0x{BitConverter.ToUInt32(data, 0):X8}");

            if (data.Length >= 8)
                decoded.Pattern.Add($"Dword1=0x{BitConverter.ToUInt32(data, 4):X8}");

            if (data.Length == 16)
                decoded.Notes = "Extended identifier-like payload rendered as 128-bit structured data";
            else if (data.Length == 8)
                decoded.Notes = "Extended identifier-like payload rendered as 64-bit structured data";

            return decoded;
        }
    }

    /// <summary>
    /// Parser for signatures based on Polyvir32 data structures (grid/text).
    /// </summary>
    private sealed class Polyvir32Parser : ISignatureParser
    {
        private static readonly int[] CandidateEntrySizes = { 4, 8, 12, 16, 20, 24, 28, 32 };
        private static readonly int[] CandidateHeaderSizes = { 0, 2, 4 };
        private static readonly int[] AcceptedTailPads = { 0, 2, 4, 6, 8 };

        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_POLYVIR32".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_POLYVIR32", StringComparison.Ordinal);
        }

        /// <summary>
        /// Attempts to parse the Polyvir32 data either as a structured grid or by extracting readable strings if the grid fails.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes for the Polyvir32 structure.</param>
        /// <returns>A DecodedSignature object detailing the parsed grid or extracted text.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            int chosenHeader;
            int chosenEntry;
            int usedLength;
            List<string> entries;

            if (DecodeGridHelper.TryParseHexGrid(data, CandidateHeaderSizes, CandidateEntrySizes, AcceptedTailPads, out chosenHeader, out chosenEntry, out usedLength, out entries))
            {
                DecodedSignature decoded = new()
                {
                    Type = context.SignatureTypeName,
                    Offset = $"0x{context.RecordOffset:X}",
                    ConditionType = "POLYVIR32_GRID",
                    ConditionValue = entries.Count,
                    DecodeConfidence = "Medium",
                    Notes = "Polyvir32 record layout inferred heuristically"
                };

                decoded.Pattern.Add($"entrySize={chosenEntry}, header={chosenHeader}, count={entries.Count}, used={usedLength}");
                for (int i = 0; i < entries.Count; i++)
                    decoded.Pattern.Add(entries[i]);

                return decoded;
            }

            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 3);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings);

            if (normalized.Count > 0)
                return DecodeResultFactory.CreateTextResult(context, "POLYVIR32_TEXT", normalized, "Low", "Readable Polyvir32-related strings extracted");

            return DecodeResultFactory.CreateBlobFallback(context, data, "No plausible Polyvir32 layout recognized");
        }
    }

    /// <summary>
    /// Parser for signatures based on PESTATIC data structures (grid/text).
    /// </summary>
    private sealed class PestaticParser : ISignatureParser
    {
        private static readonly int[] CandidateHeaderSizes = { 0, 2, 4 };
        private static readonly int[] CandidateRecordSizes = { 8, 12, 16, 20, 24, 28, 32, 40, 48, 64 };
        private static readonly int[] AcceptedTailPads = { 0, 2, 4, 6, 8 };

        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_PESTATIC".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_PESTATIC", StringComparison.Ordinal);
        }

        /// <summary>
        /// Attempts to parse the PESTATIC data either as a structured grid or by extracting readable strings if the grid fails.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes for the PESTATIC structure.</param>
        /// <returns>A DecodedSignature object detailing the parsed grid or extracted text.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            int chosenHeader;
            int chosenEntry;
            int usedLength;
            List<string> records;

            // Attempt to parse the data as a structured hex grid.
            if (DecodeGridHelper.TryParseHexGrid(data, CandidateHeaderSizes, CandidateRecordSizes, AcceptedTailPads, out chosenHeader, out chosenEntry, out usedLength, out records))
            {
                DecodedSignature decoded = new()
                {
                    Type = context.SignatureTypeName,
                    Offset = $"0x{context.RecordOffset:X}",
                    ConditionType = "PESTATIC_GRID",
                    ConditionValue = records.Count,
                    DecodeConfidence = InferGridConfidence(records.Count, chosenEntry, chosenHeader),
                    Notes = "Record layout inferred heuristically"
                };

                decoded.Pattern.Add($"recordSize={chosenEntry}, header={chosenHeader}, count={records.Count}, used={usedLength}");
                for (int i = 0; i < records.Count; i++)
                    decoded.Pattern.Add(records[i]);

                return decoded;
            }

            // If grid parsing fails, attempt to extract readable strings.
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 3);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings);

            if (normalized.Count > 0)
                return DecodeResultFactory.CreateTextResult(context, "PESTATIC_TEXT", normalized, "Low", "Structured layout not recognized; extracted readable strings");

            // Fallback if neither grid nor text extraction yields results.
            return DecodeResultFactory.CreateBlobFallback(context, data, "No plausible PESTATIC layout recognized");
        }
    }

    /// <summary>
    /// Parser for signatures based on PESTATICEX data structures (extended grid/text).
    /// </summary>
    private sealed class PestaticExParser : ISignatureParser
    {
        private static readonly int[] CandidateHeaderSizes = { 0, 2, 4 };
        private static readonly int[] CandidateRecordSizes = { 12, 16, 20, 24, 28, 32, 40, 48, 64, 80 };
        private static readonly int[] AcceptedTailPads = { 0, 2, 4, 6, 8 };

        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_PESTATICEX".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_PESTATICEX", StringComparison.Ordinal);
        }

        /// <summary>
        /// Attempts to parse the PESTATICEX data either as a structured grid or by extracting readable strings if the grid fails.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes for the PESTATICEX structure.</param>
        /// <returns>A DecodedSignature object detailing the parsed grid or extracted text.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            int chosenHeader;
            int chosenEntry;
            int usedLength;
            List<string> records;

            // Attempt to parse the data as a structured hex grid.
            if (DecodeGridHelper.TryParseHexGrid(data, CandidateHeaderSizes, CandidateRecordSizes, AcceptedTailPads, out chosenHeader, out chosenEntry, out usedLength, out records))
            {
                DecodedSignature decoded = new()
                {
                    Type = context.SignatureTypeName,
                    Offset = $"0x{context.RecordOffset:X}",
                    ConditionType = "PESTATICEX_GRID",
                    ConditionValue = records.Count,
                    DecodeConfidence = InferGridConfidence(records.Count, chosenEntry, chosenHeader),
                    Notes = "Extended record layout inferred heuristically"
                };

                decoded.Pattern.Add($"recordSize={chosenEntry}, header={chosenHeader}, count={records.Count}, used={usedLength}");
                for (int i = 0; i < records.Count; i++)
                    decoded.Pattern.Add(records[i]);

                return decoded;
            }

            // If grid parsing fails, attempt to extract readable strings.
            List<string> strings = DecodeTextHelper.CollectCandidateStrings(data, 3);
            List<string> normalized = DecodeTextHelper.NormalizeAndDistinct(strings);

            if (normalized.Count > 0)
                return DecodeResultFactory.CreateTextResult(context, "PESTATICEX_TEXT", normalized, "Low", "Structured extended layout not recognized; extracted readable strings");

            // Fallback if neither grid nor text extraction yields results.
            return DecodeResultFactory.CreateBlobFallback(context, data, "No plausible PESTATICEX layout recognized");
        }
    }

    /// <summary>
    /// Parser for signatures based on standard signature tree structures (SIGTREE).
    /// </summary>
    private sealed class SigTreeParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_SIGTREE".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_SIGTREE", StringComparison.Ordinal);
        }

        /// <summary>
        /// Attempts to parse the SIGTREE data by first checking for a fixed layout structure; otherwise, it treats it as generic binary data.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing the signature tree data.</param>
        /// <returns>A DecodedSignature object detailing the parsed structure or generic binary information.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            int nodeCount;
            int version;
            int treeType;
            int flags;
            int parsedNodes;

            DecodedSignature decoded = new DecodedSignature
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "SIGTREE_DATA",
                ConditionValue = data?.Length ?? 0,
                DecodeConfidence = "Low",
                Notes = "Signature tree interpreted heuristically"
            };

            if (data == null || data.Length == 0)
            {
                decoded.ConditionType = "EMPTY";
                decoded.ConditionValue = 0;
                decoded.Notes = "Empty signature tree payload";
                return decoded;
            }

            // Attempt to parse the header information from the payload.
            if (!TryParseSigTreeHeader(data, out nodeCount, out version, out treeType, out flags))
                return DecodeResultFactory.CreateBlobFallback(context, data, "Unable to parse signature tree header");

            decoded.Pattern.Add($"Header.NodeCount={nodeCount}");
            decoded.Pattern.Add($"Header.Version={version}");
            decoded.Pattern.Add($"Header.TreeType={treeType}");
            decoded.Pattern.Add($"Header.Flags=0x{flags:X2}");

            AddHexPreview(decoded.Pattern, data, 32);

            // Check if the structure matches a known fixed-node layout (e.g., 5-byte header + N*16-byte nodes).
            if (LooksLikeFixedSigTreeLayout(data, nodeCount))
            {
                parsedNodes = 0;

                for (int i = 0; i < nodeCount && i < 8; i++)
                {
                    int nodeOffset = 5 + (i * 16);
                    decoded.Pattern.Add($"Node[{i}]={RenderSigTreeNode(data, nodeOffset)}");
                    parsedNodes++;
                }

                if (nodeCount > 8)
                    decoded.Pattern.Add($"... +{nodeCount - 8} more nodes");

                decoded.ConditionValue = nodeCount;
                decoded.DecodeConfidence = InferStructuredConfidence(nodeCount, 16, 5, true, false);
                decoded.Notes = "Signature tree parsed as 5-byte header plus fixed 16-byte nodes";
                return decoded;
            }

            // If the structure doesn't match the fixed layout, treat it as generic binary data.
            decoded.ConditionType = "STRUCTURED_BINARY";
            decoded.ConditionValue = data.Length;
            decoded.DecodeConfidence = "Low";
            decoded.Notes = "Binary payload shows partial signature-tree-like structure";
            return decoded;
        }
    }

    /// <summary>
    /// Parser for signatures based on extended signature tree structures (SIGTREE_EXT).
    /// </summary>
    private sealed class SigTreeExtParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_SIGTREE_EXT".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_SIGTREE_EXT", StringComparison.Ordinal);
        }

        /// <summary>
        /// Attempts to parse the extended SIGTREE data by analyzing its header structure and extracting inline strings/patterns if present.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing the extended signature tree data.</param>
        /// <returns>A DecodedSignature object detailing the parsed structure, header information, and extracted strings/patterns.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            int nodeCount;
            int version;
            int treeType;
            int flags;
            List<string> normalized;
            bool hasWildcards;

            DecodedSignature decoded = new DecodedSignature
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "SIGTREE_EXT_DATA",
                ConditionValue = data?.Length ?? 0,
                DecodeConfidence = "Low",
                Notes = "Extended signature tree interpreted heuristically"
            };

            if (data == null || data.Length == 0)
            {
                decoded.ConditionType = "EMPTY";
                decoded.ConditionValue = 0;
                decoded.Notes = "Empty extended signature tree payload";
                return decoded;
            }

            // Attempt to parse the header information from the payload.
            if (!TryParseSigTreeHeader(data, out nodeCount, out version, out treeType, out flags))
                return DecodeResultFactory.CreateBlobFallback(context, data, "Unable to parse extended signature tree header");

            normalized = MergeSigTreeStrings(data);
            hasWildcards = ContainsSigTreeWildcardEscape(data);

            decoded.Pattern.Add($"Header.NodeCount={nodeCount}");
            decoded.Pattern.Add($"Header.Version={version}");
            decoded.Pattern.Add($"Header.TreeType={treeType}");
            decoded.Pattern.Add($"Header.Flags=0x{flags:X2}");
            decoded.Pattern.Add($"ContainsWildcardEscapes={(hasWildcards ? "True" : "False")}");

            AddHexPreview(decoded.Pattern, data, 32);

            // Check if the structure matches a known fixed-node layout (e.g., N nodes at fixed offsets).
            if (LooksLikeFixedSigTreeLayout(data, nodeCount))
            {
                for (int i = 0; i < nodeCount && i < 6; i++)
                {
                    int nodeOffset = 5 + (i * 16);
                    decoded.Pattern.Add($"Node[{i}]={RenderSigTreeNode(data, nodeOffset)}");
                }

                if (nodeCount > 6)
                    decoded.Pattern.Add($"... +{nodeCount - 6} more nodes");
            }

            // Log the first few extracted strings/patterns for quick review.
            for (int i = 0; i < normalized.Count && i < 6; i++)
            {
                string label = LooksLikePathOrPatternString(normalized[i]) ? "PatternString" : "String";
                decoded.Pattern.Add($"{label}[{i}]={normalized[i]}");
            }

            // Set final values based on parsing success and content found.
            decoded.ConditionValue = nodeCount > 0 ? nodeCount : data.Length;
            decoded.DecodeConfidence = InferStructuredConfidence(nodeCount, 16, 5, true, normalized.Count > 0);
            decoded.Notes = normalized.Count > 0
                        ? "Extended signature tree contains inline strings, paths, or wildcard-like patterns"
                        : "Extended signature tree parsed with structural header heuristics";

            return decoded;
        }
    }

    /// <summary>
    /// Parser for signatures based on behavioral monitoring tree structures (SIGTREE_BM).
    /// </summary>
    private sealed class SigTreeBmParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_SIGTREE_BM".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_SIGTREE_BM", StringComparison.Ordinal);
        }

        /// <summary>
        /// Attempts to parse the SIGTREE_BM data by determining if it follows a short or standard fixed layout, and extracts associated strings/patterns.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing the behavioral-monitoring tree data.</param>
        /// <returns>A DecodedSignature object detailing the parsed mode, node count, and extracted strings/patterns.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            int nodeCount;
            int version;
            int treeType;
            int flags;
            int bmNodeCount;
            int bmVariant;
            int bmFlags;

            DecodedSignature decoded = new DecodedSignature
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "SIGTREE_BM_DATA",
                ConditionValue = data?.Length ?? 0,
                DecodeConfidence = "Low",
                Notes = "Behavioral-monitoring signature tree interpreted heuristically"
            };

            if (data == null || data.Length == 0)
            {
                decoded.ConditionType = "EMPTY";
                decoded.ConditionValue = 0;
                decoded.Notes = "Empty behavioral-monitoring signature tree payload";
                return decoded;
            }

            // Extract and filter strings that look like paths or useful UTF-16 content.
            List<string> normalized = MergeSigTreeStrings(data);
            normalized = normalized
                .Where(s => LooksLikePathOrPatternString(s) || LooksLikeUsefulUtf16String(s))
                .ToList();

            bool parsedFixed = false;
            bool standardValid = false;
            bool shortValid = false;
            int chosenHeaderSize = 0;
            int chosenNodeCount = 0;
            string chosenMode = string.Empty;

            if (TryParseSigTreeHeader(data, out nodeCount, out version, out treeType, out flags) &&
                LooksLikeFixedSigTreeLayout(data, nodeCount))
            {
                standardValid = true;
            }

            if (TryParseBmShortHeader(data, out bmNodeCount, out bmVariant, out bmFlags) &&
                data.Length >= 3 + (bmNodeCount * 16))
            {
                shortValid = true;
            }

            if (shortValid)
            {
                chosenMode = "BM_SHORT";
                chosenHeaderSize = 3;
                chosenNodeCount = bmNodeCount;

                decoded.Pattern.Add("HeaderMode=BM_SHORT");
                decoded.Pattern.Add($"Header.NodeCount={bmNodeCount}");
                decoded.Pattern.Add($"Header.Variant={bmVariant}");
                decoded.Pattern.Add($"Header.Flags=0x{bmFlags:X2}");
            }
            else if (standardValid)
            {
                chosenMode = "STANDARD";
                chosenHeaderSize = 5;
                chosenNodeCount = nodeCount;

                decoded.Pattern.Add("HeaderMode=STANDARD");
                decoded.Pattern.Add($"Header.NodeCount={nodeCount}");
                decoded.Pattern.Add($"Header.Version={version}");
                decoded.Pattern.Add($"Header.TreeType={treeType}");
                decoded.Pattern.Add($"Header.Flags=0x{flags:X2}");
            }

            if (!string.IsNullOrWhiteSpace(chosenMode))
            {
                for (int i = 0; i < chosenNodeCount && i < 6; i++)
                {
                    int nodeOffset = chosenHeaderSize + (i * 16);
                    if (nodeOffset + 16 <= data.Length)
                        decoded.Pattern.Add($"Node[{i}]={RenderSigTreeNode(data, nodeOffset)}");
                }

                if (chosenNodeCount > 6)
                    decoded.Pattern.Add($"... +{chosenNodeCount - 6} more nodes");

                decoded.ConditionValue = chosenNodeCount;
                parsedFixed = true;
            }

            AddHexPreview(decoded.Pattern, data, 32);

            for (int i = 0; i < normalized.Count && i < 6; i++)
            {
                string label = LooksLikePathOrPatternString(normalized[i]) ? "PatternString" : "String";
                decoded.Pattern.Add($"{label}[{i}]={normalized[i]}");
            }

            if (parsedFixed)
            {
                decoded.DecodeConfidence = InferStructuredConfidence(decoded.ConditionValue, 16, chosenHeaderSize, true, normalized.Count > 0);
                decoded.Notes = normalized.Count > 0
                    ? "Behavioral-monitoring signature tree parsed with embedded ASCII/UTF-16 strings"
                    : "Behavioral-monitoring signature tree parsed with structural heuristics";
                return decoded;
            }

            // Fallback if no fixed structure was identified.
            decoded.ConditionType = "STRUCTURED_BINARY";
            decoded.ConditionValue = data.Length;
            decoded.DecodeConfidence = normalized.Count > 0 ? "Medium" : "Low";
            decoded.Notes = normalized.Count > 0
                ? "Behavioral-monitoring tree contains ASCII/UTF-16 strings but full node layout remains ambiguous"
                : "Behavioral-monitoring tree rendered as bounded structural fallback";

            return decoded;
        }
    }

    /// <summary>
    /// Parser for signatures based on KCRCE data structures (CRC list).
    /// </summary>
    private sealed class KcrceParser : ISignatureParser
    {
        // Defines possible strides (the distance between consecutive items) in the payload.
        private static readonly int[] CandidateStrides = { 6, 8, 12, 16, 20 };
        // Defines possible header sizes to check during layout parsing.
        private static readonly int[] TryHeaderSizes = { 4, 2, 0 };
        // Defines acceptable padding lengths at the end of a record.
        private static readonly int[] AcceptedTailPads = { 0, 2, 4, 6, 8 };

        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_KCRCE".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_KCRCE", StringComparison.Ordinal);
        }

        /// <summary>
        /// Attempts to parse the KCRCE data by iterating through all possible header sizes and strides until a plausible layout is found.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing the CRC list structure.</param>
        /// <returns>A DecodedSignature object detailing the parsed CRC entries, or a fallback if no layout matches.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            if (data == null || data.Length == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "Empty KCRCE payload");

            for (int i = 0; i < TryHeaderSizes.Length; i++)
            {
                int headerSize = TryHeaderSizes[i];

                for (int j = 0; j < CandidateStrides.Length; j++)
                {
                    int stride = CandidateStrides[j];

                    List<KcrceItem> entries;
                    int usedLength;
                    if (TryParseLayout(data, headerSize, stride, out entries, out usedLength))
                    {
                        if (!LooksLikeKcrce(entries))
                            continue;

                        return EmitDecodedSignature(context, entries, stride, headerSize, usedLength);
                    }
                }
            }

            return DecodeResultFactory.CreateBlobFallback(context, data, "No plausible KCRCE layout recognized");
        }

        /// <summary>
        /// Attempts to parse the raw byte array into a list of KcrceItem entries based on specified header size and stride.
        /// </summary>
        /// <param name="b">The raw payload bytes.</param>
        /// <param name="headerSize">The expected size of the initial header.</param>
        /// <param name="stride">The byte distance between consecutive items.</param>
        /// <param name="items">Output list containing the parsed KcrceItem entries if successful.</param>
        /// <param name="usedLength">Output variable indicating the total length consumed by the structure.</param>
        /// <returns>True if a valid layout was successfully extracted, false otherwise.</returns>
        private static bool TryParseLayout(byte[] b, int headerSize, int stride, out List<KcrceItem> items, out int usedLength)
        {
            items = new();
            usedLength = 0;
            if (!(headerSize == 0 || headerSize == 2 || headerSize == 4)) return false;
            if (stride <= 0) return false;
            if (b == null || b.Length < headerSize + stride) return false;
            if (b.Length < headerSize) return false;

            int count;
            int gridStart = headerSize;

            if (headerSize == 2)
            {
                count = ReadU16LE(b, 0);
                if (count <= 0) return false;

                foreach (int pad in AcceptedTailPads)
                {
                    if (gridStart + count * stride + pad == b.Length)
                    {
                        usedLength = gridStart + count * stride;
                        return ExtractItems(b, gridStart, stride, count, out items);
                    }
                }
                return false;
            }
            else if (headerSize == 4)
            {
                count = (int)ReadU32LE(b, 0);
                if (count <= 0) return false;

                foreach (int pad in AcceptedTailPads)
                {
                    if (gridStart + count * stride + pad == b.Length)
                    {
                        usedLength = gridStart + count * stride;
                        return ExtractItems(b, gridStart, stride, count, out items);
                    }
                }
                return false;
            }
            else
            {
                int len = b.Length - gridStart;
                if (len < stride) return false;

                if (len % stride == 0)
                {
                    count = len / stride;
                    usedLength = gridStart + count * stride;
                    return ExtractItems(b, gridStart, stride, count, out items);
                }

                foreach (int pad in AcceptedTailPads)
                {
                    int dataLen = len - pad;
                    if (dataLen > 0 && dataLen % stride == 0)
                    {
                        count = dataLen / stride;
                        usedLength = gridStart + count * stride;
                        return ExtractItems(b, gridStart, stride, count, out items);
                    }
                }
                return false;
            }
        }

        /// <summary>
        /// Extracts individual KcrceItem structures from the byte array based on layout parameters.
        /// </summary>
        /// <param name="b">The raw payload bytes.</param>
        /// <param name="start">The starting offset of the first item.</param>
        /// <param name="stride">The distance between items.</param>
        /// <param name="count">The total number of items to extract.</param>
        /// <param name="list">Output list populated with extracted KcrceItem objects.</param>
        /// <returns>True if at least one item was successfully extracted, false otherwise.</returns>
        private static bool ExtractItems(byte[] b, int start, int stride, int count, out List<KcrceItem> list)
        {
            list = new(count);
            int pos = start;

            for (int i = 0; i < count; i++, pos += stride)
            {
                if (pos + stride > b.Length) return false;

                uint crc = ReadU32LE(b, pos);
                uint? index = null;
                ushort? weight = null;
                ushort? flags = null;
                string? extra = null;

                if (stride >= 8) index = ReadU32LE(b, pos + 4);
                if (stride >= 10) weight = ReadU16LE(b, pos + 8);
                if (stride >= 12) flags = ReadU16LE(b, pos + 10);
                if (stride > 12) extra = DecodeHexHelper.ToHex(b, pos + 12, stride - 12);

                list.Add(new KcrceItem
                {
                    Crc32 = crc,
                    Index = index,
                    Weight = weight,
                    Flags = flags,
                    ExtraHex = extra
                });
            }

            return list.Count > 0;
        }

        /// <summary>
        /// Heuristically checks if the extracted items conform to expected KCRCE characteristics (e.g., CRC distribution).
        /// </summary>
        /// <param name="items">The list of parsed KcrceItem entries.</param>
        /// <returns>True if the item set appears consistent with a valid KCRCE structure, false otherwise.</returns>
        private static bool LooksLikeKcrce(List<KcrceItem> items)
        {
            if (items.Count == 0) return false;

            HashSet<uint> seen = new();
            bool allZero = true, allFFFF = true;

            for (int i = 0; i < items.Count; i++)
            {
                uint c = items[i].Crc32;
                if (c != 0) allZero = false;
                if (c != 0xFFFFFFFFu) allFFFF = false;
                seen.Add(c);
            }

            if (allZero || allFFFF) return false;

            int n = items.Count;
            int unique = seen.Count;

            if (n <= 4)
            {
                if (n == 1) return items[0].Crc32 != 0 && items[0].Crc32 != 0xFFFFFFFFu;
                return unique >= 2;
            }

            if (unique < Math.Max(3, n / 4)) return false;
            return true;
        }

        /// <summary>
        /// Generates the final DecodedSignature object from successfully parsed KcrceItem entries.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="entries">The list of validated KcrceItem entries.</param>
        /// <param name="stride">The stride used during parsing.</param>
        /// <param name="headerSize">The header size used during parsing.</param>
        /// <param name="usedLength">The total length consumed by the structure.</param>
        /// <returns>The fully constructed DecodedSignature object.</returns>
        private static DecodedSignature EmitDecodedSignature(SignatureParserContext context, List<KcrceItem> entries, int stride, int headerSize, int usedLength)
        {
            DecodedSignature decoded = new()
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "CRC_MATCH_LIST",
                ConditionValue = entries.Count,
                DecodeConfidence = "Medium",
                Notes = "KCRCE layout inferred heuristically"
            };

            decoded.Pattern.Add($"stride={stride}, header={headerSize}, count={entries.Count}, used={usedLength}");

            for (int i = 0; i < entries.Count; i++)
            {
                KcrceItem e = entries[i];
                StringBuilder sb = new();
                sb.AppendFormat("[{0}] CRC=0x{1:X8}", i + 1, e.Crc32);
                if (e.Index.HasValue) sb.AppendFormat(" Index=0x{0:X8}", e.Index.Value);
                if (e.Weight.HasValue) sb.AppendFormat(" Weight={0}", e.Weight.Value);
                if (e.Flags.HasValue) sb.AppendFormat(" Flags=0x{0:X4}", e.Flags.Value);
                if (!string.IsNullOrEmpty(e.ExtraHex)) sb.Append(" Extra=" + e.ExtraHex);
                decoded.Pattern.Add(sb.ToString());
            }

            return decoded;
        }

        /// <summary>
        /// Represents a single entry within the KCRCE structure, holding CRC and optional metadata.
        /// </summary>
        private sealed class KcrceItem
        {
            public uint Crc32;
            public uint? Index;
            public ushort? Weight;
            public ushort? Flags;
            public string? ExtraHex;
        }
    }

    /// <summary>
    /// Parser for signatures based on KCRCEX data structures (extended CRC list).
    /// </summary>
    private sealed class KcrcexParser : ISignatureParser
    {
        // Defines possible strides (the distance between consecutive items) in the payload.
        private static readonly int[] CandidateStrides = { 12, 16, 20, 24, 28, 32 };
        // Defines possible header sizes to check during layout parsing.
        private static readonly int[] TryHeaderSizes = { 4, 2, 0 };
        // Defines acceptable padding lengths at the end of a record.
        private static readonly int[] AcceptedTailPads = { 0, 2, 4, 6, 8 };

        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_KCRCEX".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_KCRCEX", StringComparison.Ordinal);
        }

        /// <summary>
        /// Attempts to parse the KCRCEX data by iterating through all possible header sizes and strides until a plausible layout is found.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing the extended CRC list structure.</param>
        /// <returns>A DecodedSignature object detailing the parsed CRC entries, or a fallback if no layout matches.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            if (data == null || data.Length == 0)
                return DecodeResultFactory.CreateBlobFallback(context, data, "Empty KCRCEX payload");

            for (int i = 0; i < TryHeaderSizes.Length; i++)
            {
                int headerSize = TryHeaderSizes[i];

                for (int j = 0; j < CandidateStrides.Length; j++)
                {
                    int stride = CandidateStrides[j];

                    List<KcrcexItem> items;
                    int usedLength;
                    if (TryParseLayout(data, headerSize, stride, out items, out usedLength))
                    {
                        if (!LooksLike(items))
                            continue;

                        return EmitDecodedSignature(context, items, stride, headerSize, usedLength);
                    }
                }
            }

            return DecodeResultFactory.CreateBlobFallback(context, data, "No plausible KCRCEX layout recognized");
        }

        /// <summary>
        /// Attempts to parse the raw byte array into a list of KcrcexItem entries based on specified header size and stride.
        /// </summary>
        /// <param name="b">The raw payload bytes.</param>
        /// <param name="headerSize">The expected size of the initial header.</param>
        /// <param name="stride">The byte distance between consecutive items.</param>
        /// <param name="items">Output list containing the parsed KcrcexItem entries if successful.</param>
        /// <param name="usedLength">Output variable indicating the total length consumed by the structure.</param>
        /// <returns>True if a valid layout was successfully extracted, false otherwise.</returns>
        private static bool TryParseLayout(byte[] b, int headerSize, int stride, out List<KcrcexItem> items, out int usedLength)
        {
            items = new();
            usedLength = 0;
            if (!(headerSize == 0 || headerSize == 2 || headerSize == 4)) return false;
            if (stride <= 0) return false;
            if (b == null || b.Length < headerSize + stride) return false;

            int count;
            int gridStart = headerSize;

            if (headerSize == 2)
            {
                count = ReadU16LE(b, 0);
                if (count <= 0) return false;

                foreach (int pad in AcceptedTailPads)
                {
                    if (gridStart + count * stride + pad == b.Length)
                    {
                        usedLength = gridStart + count * stride;
                        return ExtractItems(b, gridStart, stride, count, out items);
                    }
                }

                return false;
            }
            else if (headerSize == 4)
            {
                count = (int)ReadU32LE(b, 0);
                if (count <= 0) return false;

                foreach (int pad in AcceptedTailPads)
                {
                    if (gridStart + count * stride + pad == b.Length)
                    {
                        usedLength = gridStart + count * stride;
                        return ExtractItems(b, gridStart, stride, count, out items);
                    }
                }

                return false;
            }
            else
            {
                int len = b.Length - gridStart;
                if (len < stride) return false;

                if (len % stride == 0)
                {
                    count = len / stride;
                    usedLength = gridStart + count * stride;
                    return ExtractItems(b, gridStart, stride, count, out items);
                }

                foreach (int pad in AcceptedTailPads)
                {
                    int dataLen = len - pad;
                    if (dataLen > 0 && dataLen % stride == 0)
                    {
                        count = dataLen / stride;
                        usedLength = gridStart + count * stride;
                        return ExtractItems(b, gridStart, stride, count, out items);
                    }
                }

                return false;
            }
        }

        /// <summary>
        /// Extracts individual KcrcexItem structures from the byte array based on layout parameters.
        /// </summary>
        /// <param name="b">The raw payload bytes.</param>
        /// <param name="start">The starting offset of the first item.</param>
        /// <param name="stride">The distance between items.</param>
        /// <param name="count">The total number of items to extract.</param>
        /// <param name="items">Output list populated with extracted KcrcexItem objects.</param>
        /// <returns>True if at least one item was successfully extracted, false otherwise.</returns>
        private static bool ExtractItems(byte[] b, int start, int stride, int count, out List<KcrcexItem> items)
        {
            items = new(count);
            int pos = start;

            for (int i = 0; i < count; i++, pos += stride)
            {
                if (pos + stride > b.Length) return false;

                items.Add(new KcrcexItem
                {
                    Crc32 = ReadU32LE(b, pos),
                    Index = stride >= 8 ? ReadU32LE(b, pos + 4) : 0,
                    Weight = stride >= 10 ? ReadU16LE(b, pos + 8) : null,
                    Flags = stride >= 12 ? ReadU16LE(b, pos + 10) : null,
                    ExtraHex = stride > 12 ? DecodeHexHelper.ToHex(b, pos + 12, stride - 12) : null
                });
            }

            return items.Count > 0;
        }

        /// <summary>
        /// Heuristically checks if the extracted items conform to expected KCRCEX characteristics (e.g., CRC distribution).
        /// </summary>
        /// <param name="items">The list of parsed KcrcexItem entries.</param>
        /// <returns>True if the item set appears consistent with a valid KCRCEX structure, false otherwise.</returns>
        private static bool LooksLike(List<KcrcexItem> items)
        {
            if (items.Count == 0) return false;

            HashSet<uint> seen = new();
            bool allZero = true;
            bool allFFFF = true;

            for (int i = 0; i < items.Count; i++)
            {
                uint c = items[i].Crc32;
                if (c != 0) allZero = false;
                if (c != 0xFFFFFFFFu) allFFFF = false;
                seen.Add(c);
            }

            // Reject trivial cases where all CRCs are identical or zero/max value.
            if (allZero || allFFFF) return false;

            int n = items.Count;
            int unique = seen.Count;

            // Apply heuristics based on item count.
            if (n <= 4)
            {
                if (n == 1) return items[0].Crc32 != 0 && items[0].Crc32 != 0xFFFFFFFFu;
                return unique >= 2;
            }

            return unique >= Math.Max(3, n / 4);
        }

        /// <summary>
        /// Generates the final DecodedSignature object from successfully parsed KcrcexItem entries.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="entries">The list of validated KcrcexItem entries.</param>
        /// <param name="stride">The stride used during parsing.</param>
        /// <param name="headerSize">The header size used during parsing.</param>
        /// <param name="usedLength">The total length consumed by the structure.</param>
        /// <returns>The fully constructed DecodedSignature object.</returns>
        private static DecodedSignature EmitDecodedSignature(SignatureParserContext context, List<KcrcexItem> entries, int stride, int headerSize, int usedLength)
        {
            DecodedSignature decoded = new()
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "CRC_MATCH_LIST",
                ConditionValue = entries.Count,
                DecodeConfidence = "Medium",
                Notes = "KCRCEX layout inferred heuristically"
            };

            decoded.Pattern.Add($"stride={stride}, header={headerSize}, count={entries.Count}, used={usedLength}");

            for (int i = 0; i < entries.Count; i++)
            {
                KcrcexItem e = entries[i];
                StringBuilder sb = new();
                sb.AppendFormat("[{0}] CRC=0x{1:X8} Index=0x{2:X8}", i + 1, e.Crc32, e.Index);
                if (e.Weight.HasValue) sb.AppendFormat(" Weight={0}", e.Weight.Value);
                if (e.Flags.HasValue) sb.AppendFormat(" Flags=0x{0:X4}", e.Flags.Value);
                if (!string.IsNullOrEmpty(e.ExtraHex)) sb.Append(" Extra=" + e.ExtraHex);
                decoded.Pattern.Add(sb.ToString());
            }

            return decoded;
        }

        /// <summary>
        /// Represents a single entry within the KCRCEX structure, holding CRC and optional metadata.
        /// </summary>
        private sealed class KcrcexItem
        {
            public uint Crc32;
            public uint Index;
            public ushort? Weight;
            public ushort? Flags;
            public string? ExtraHex;
        }
    }

    /// <summary>
    /// Parser for signatures based on version checking or constraint validation.
    /// </summary>
    private sealed class VersionCheckParser : ISignatureParser
    {
        /// <summary>
        /// Checks if this parser handles the specific signature type "SIGNATURE_TYPE_VERSIONCHECK".
        /// </summary>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, "SIGNATURE_TYPE_VERSIONCHECK", StringComparison.Ordinal);
        }

        /// <summary>
        /// Attempts to parse the version/check payload by interpreting it as a fixed 8-byte tuple or as sequential DWORDs if shorter.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw payload bytes containing the version check data.</param>
        /// <returns>A DecodedSignature object detailing the interpreted numeric fields or a fallback if empty.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            DecodedSignature decoded = new DecodedSignature
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                ConditionType = "VERSION_CONSTRAINT",
                ConditionValue = data?.Length ?? 0,
                DecodeConfidence = "Low",
                Notes = "Version/check payload rendered as fixed numeric tuple"
            };

            if (data == null || data.Length == 0)
            {
                decoded.ConditionType = "EMPTY";
                decoded.ConditionValue = 0;
                decoded.Notes = "Empty version/check payload";
                return decoded;
            }

            decoded.Pattern.Add($"Length={data.Length}");

            if (data.Length == 8)
            {
                uint field0 = BitConverter.ToUInt32(data, 0);
                uint field1 = BitConverter.ToUInt32(data, 4);
                ushort field1Lo = BitConverter.ToUInt16(data, 4);
                ushort field1Hi = BitConverter.ToUInt16(data, 6);

                decoded.Pattern.Add($"Field0=0x{field0:X8} ({field0})");
                decoded.Pattern.Add($"Field1Dword=0x{field1:X8} ({field1})");
                decoded.Pattern.Add($"Field1Lo=0x{field1Lo:X4} ({field1Lo})");
                decoded.Pattern.Add($"Field1Hi=0x{field1Hi:X4} ({field1Hi})");
                decoded.Pattern.Add($"Tuple={field0},{field1Lo},{field1Hi}");

                if (field0 == 0 && field1 == 0)
                {
                    decoded.Notes = "Version/check payload is an all-zero fixed tuple";
                }
                else if (field1Hi != 0)
                {
                    decoded.DecodeConfidence = "Medium";
                    decoded.Notes = "Version/check payload resembles id + two-word structured tuple";
                }

                return decoded;
            }

            if (data.Length >= 4)
            {
                int dwordCount = Math.Min(data.Length / 4, 4);
                for (int i = 0; i < dwordCount; i++)
                {
                    uint value = BitConverter.ToUInt32(data, i * 4);
                    decoded.Pattern.Add($"Dword{i}=0x{value:X8} ({value})");
                }
            }

            decoded.Pattern.Add($"Preview={DecodeHexHelper.ToHexSpaced(data, 0, Math.Min(data.Length, 24))}");
            decoded.Notes = "Version/check payload rendered as numeric/binary fallback";
            return decoded;
        }
    }

    /// <summary>
    /// Parser for signatures based on generic weighted pattern structures.
    /// </summary>
    private sealed class GenericWeightedPatternParser : ISignatureParser
    {
        private readonly string _signatureType;

        /// <summary>
        /// Initializes a new instance of the <see cref="GenericWeightedPatternParser"/> class.
        /// </summary>
        /// <param name="signatureType">The specific signature type this parser is designed to handle.</param>
        public GenericWeightedPatternParser(string signatureType)
        {
            _signatureType = signatureType;
        }

        /// <summary>
        /// Checks if this parser handles the specified signature type.
        /// </summary>
        /// <param name="signatureType">The raw byte signature type.</param>
        /// <param name="signatureTypeName">The string representation of the signature type.</param>
        /// <returns>True if the names match, false otherwise.</returns>
        public bool CanParse(byte signatureType, string signatureTypeName)
        {
            return string.Equals(signatureTypeName, _signatureType, StringComparison.Ordinal);
        }

        /// <summary>
        /// Parses the weighted pattern payload by reading header fields, then iterating through each sub-rule to decode its weight and pattern content.
        /// </summary>
        /// <param name="context">Metadata about the current signature record.</param>
        /// <param name="data">The raw byte array containing the weighted pattern data.</param>
        /// <returns>A DecodedSignature object detailing the parsed sub-rules, or a fallback if the payload is too small.</returns>
        public DecodedSignature Parse(SignatureParserContext context, byte[] data)
        {
            if (data == null || data.Length < 7)
                return DecodeResultFactory.CreateBlobFallback(context, data, "Weighted pattern payload too small");

            DecodedSignature decoded = new()
            {
                Type = context.SignatureTypeName,
                Offset = $"0x{context.RecordOffset:X}",
                DecodeConfidence = "Medium",
                Notes = "Weighted pattern structure interpreted heuristically"
            };

            int pos = 0;
            ushort unknown = ReadU16LE(data, pos);
            pos += 2;
            ushort threshold = ReadU16LE(data, pos);
            pos += 2;
            ushort subRuleCount = ReadU16LE(data, pos);
            pos += 2;
            byte ctrl = data[pos++];
            _ = unknown; // Unknown field is read but not used in logic.
            _ = ctrl; // Control field is read but not used in logic.

            SignatureLogic logic = new()
            {
                Threshold = threshold
            };

            for (int i = 0; i < subRuleCount && pos < data.Length; i++)
            {
                if (pos + 3 > data.Length)
                    break;

                ushort weight = ReadU16LE(data, pos);
                pos += 2;

                if (pos >= data.Length)
                    break;

                byte b1 = data[pos++];
                byte typeByte = 0xFF;
                byte ruleLen;

                if (b1 <= 0x02)
                {
                    typeByte = b1;
                    if (pos >= data.Length)
                        break;

                    ruleLen = data[pos++];
                }
                else
                {
                    ruleLen = b1;
                }

                bool hadAsciiTag = false;
                if (pos + 2 <= data.Length)
                {
                    byte t0 = data[pos];
                    byte t1 = data[pos + 1];
                    if (t0 == 0x80 && t1 == 0x01)
                    {
                        hadAsciiTag = true;
                        pos += 2;
                    }
                }

                if (pos + ruleLen > data.Length)
                    break;

                byte[] patternBytes = new byte[ruleLen];
                Buffer.BlockCopy(data, pos, patternBytes, 0, ruleLen);
                pos += ruleLen;

                if (patternBytes.Length == 0)
                {
                    decoded.Pattern.Add($"SubRule[{i}] Empty");
                    logic.SubRules.Add(new SubRuleLogic
                    {
                        Pattern = string.Empty,
                        Weight = weight,
                        Control = typeByte <= 0x02 ? typeByte : (byte)0
                    });
                    continue;
                }

                string renderedHuman;
                if (!hadAsciiTag && LooksLikeWildcardPattern(patternBytes))
                {
                    int consumed;
                    bool hadTerminator;
                    List<WildcardToken> tokens = WildcardPattern.Tokenize(patternBytes, 0, patternBytes.Length, out consumed, out hadTerminator);
                    renderedHuman = WildcardPattern.RenderHuman(tokens);

                    string yara = WildcardPattern.RenderYaraHex(tokens);
                    decoded.Pattern.Add($"SubRule[{i}] Human={renderedHuman}");
                    if (!string.IsNullOrWhiteSpace(yara))
                        decoded.Pattern.Add($"SubRule[{i}] Yara={yara}");
                }
                else
                {
                    List<string> fragments;

                    renderedHuman = IsLikelyUtf16(patternBytes)
                        ? Encoding.Unicode.GetString(patternBytes).TrimEnd('\0')
                        : Encoding.UTF8.GetString(patternBytes).TrimEnd('\0');

                    renderedHuman = SanitizeDecodedText(renderedHuman);
                    fragments = ExtractMeaningfulFragments(patternBytes, 4);

                    if (fragments.Count > 1)
                    {
                        decoded.Pattern.Add($"SubRule[{i}] Fragments={string.Join(" | ", fragments)}");
                        renderedHuman = string.Join(" | ", fragments);
                    }
                    else if (fragments.Count == 1)
                    {
                        decoded.Pattern.Add($"SubRule[{i}] Pattern={fragments[0]}");
                        renderedHuman = fragments[0];
                    }
                    else if (LooksReadableText(renderedHuman))
                    {
                        decoded.Pattern.Add($"SubRule[{i}] Pattern={renderedHuman}");
                    }
                    else
                    {
                        renderedHuman = DecodeHexHelper.ToHex(patternBytes, 0, patternBytes.Length);
                        decoded.Pattern.Add($"SubRule[{i}] Hex={renderedHuman}");
                    }
                }

                logic.SubRules.Add(new SubRuleLogic
                {
                    Pattern = renderedHuman,
                    Weight = weight,
                    Control = typeByte <= 0x02 ? typeByte : (byte)0
                });
            }

            decoded.ConditionType = "WEIGHTED_PATTERN";
            decoded.ConditionValue = logic.SubRules.Count;
            return decoded;
        }

        /// <summary>
        /// Heuristically checks if the byte array contains patterns resembling wildcard expressions (e.g., 0x90 followed by specific bytes).
        /// </summary>
        /// <param name="data">The pattern bytes to check.</param>
        /// <returns>True if a wildcard pattern is suspected, false otherwise.</returns>
        private static bool LooksLikeWildcardPattern(byte[] data)
        {
            if (data == null || data.Length == 0)
                return false;

            for (int i = 0; i < data.Length; i++)
            {
                if (data[i] != 0x90)
                    continue;

                if (i + 1 < data.Length)
                {
                    byte next = data[i + 1];
                    if (next == 0x00 || next == 0x90)
                        return true;
                    if (next < 0x32)
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines if the byte array is likely encoded using UTF-16 encoding.
        /// </summary>
        /// <param name="data">The pattern bytes to check.</param>
        /// <returns>True if a high density of null bytes suggests UTF-16, false otherwise.</returns>
        private static bool IsLikelyUtf16(byte[] data)
        {
            if (data == null || data.Length < 2)
                return false;

            int nulls = 0;
            for (int i = 1; i < data.Length; i += 2)
            {
                if (data[i] == 0x00)
                    nulls++;
            }

            return nulls >= data.Length / 4;
        }
    }

    /// <summary>
    /// Reads a 16-bit unsigned integer from the byte array using Little Endian format.
    /// </summary>
    private static ushort ReadU16LE(byte[] data, int offset)
    {
        if (offset + 1 >= data.Length)
            return 0;

        return (ushort)(data[offset] | (data[offset + 1] << 8));
    }

    /// <summary>
    /// Reads a 32-bit unsigned integer from the byte array using Little Endian format.
    /// </summary>
    private static uint ReadU32LE(byte[] data, int offset)
    {
        if (offset + 3 >= data.Length)
            return 0;

        return (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
    }

    /// <summary>
    /// Sanitizes decoded text by replacing control characters and excessive whitespace with single spaces.
    /// </summary>
    /// <param name="value">The raw string to sanitize.</param>
    /// <returns>A cleaned, trimmed string.</returns>
    private static string SanitizeDecodedText(string value)
    {
        StringBuilder sb;
        bool lastWasSeparator;

        if (string.IsNullOrEmpty(value))
            return string.Empty;

        sb = new StringBuilder(value.Length);
        lastWasSeparator = false;

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            // Replace non-printable control characters with a space, unless it's already a separator.
            if (char.IsControl(c) && !char.IsWhiteSpace(c))
            {
                if (!lastWasSeparator && sb.Length > 0)
                {
                    sb.Append(' ');
                    lastWasSeparator = true;
                }
                continue;
            }

            // Replace Unicode replacement characters with a space if not already separated.
            if (c == '\uFFFD')
            {
                if (!lastWasSeparator && sb.Length > 0)
                {
                    sb.Append(' ');
                    lastWasSeparator = true;
                }
                continue;
            }

            sb.Append(c);
            lastWasSeparator = char.IsWhiteSpace(c);
        }

        return sb.ToString().Trim();
    }

    /// <summary>
    /// Checks if the decoded string contains a sufficient ratio of printable characters to be considered readable text.
    /// </summary>
    /// <param name="value">The string to check.</param>
    /// <returns>True if the text appears human-readable, false otherwise.</returns>
    private static bool LooksReadableText(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        int printable = 0;
        int weird = 0;

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            // Count control characters that are not whitespace as 'weird'.
            if (char.IsControl(c) && !char.IsWhiteSpace(c))
            {
                weird++;
                continue;
            }

            // Count standard printable ASCII or whitespace as 'printable'.
            if (c >= 0x20 && c <= 0x7E)
            {
                printable++;
            }
            else if (char.IsWhiteSpace(c))
            {
                printable++;
            }
            else
            {
                weird++;
            }
        }

        if (printable == 0)
            return false;

        // If the ratio of weird characters to printable characters is low (less than 1:4), consider it readable.
        return weird == 0 || weird * 4 < printable;
    }

    /// <summary>
    /// Extracts meaningful, readable fragments from raw binary data by collecting candidate strings, normalizing them, sanitizing them, and filtering based on readability and minimum length.
    /// </summary>
    /// <param name="data">The raw byte array to scan for text.</param>
    /// <param name="minLen">The minimum required length for a string fragment to be considered meaningful.</param>
    /// <returns>A list of unique, sanitized strings that pass readability and length checks.</returns>
    private static List<string> ExtractMeaningfulFragments(byte[] data, int minLen)
    {
        List<string> result;
        List<string> strings;
        List<string> normalized;

        result = new List<string>();

        if (data == null || data.Length == 0)
            return result;

        strings = DecodeTextHelper.CollectCandidateStrings(data, minLen);
        normalized = DecodeTextHelper.NormalizeAndDistinct(strings, ignoreCase: false);

        for (int i = 0; i < normalized.Count; i++)
        {
            string s = SanitizeDecodedText(normalized[i]);

            if (!LooksReadableText(s))
                continue;

            // Skip if the string is shorter than the minimum required length.
            if (s.Length < minLen)
                continue;

            result.Add(s);
        }

        // Return a final list of unique, meaningful fragments.
        return DecodeTextHelper.NormalizeAndDistinct(result, ignoreCase: false);
    }

    /// <summary>
    /// Checks if a given string value matches common patterns associated with useful configuration or file paths (e.g., registry keys, DLLs, GUIDs).
    /// </summary>
    /// <param name="value">The string to evaluate.</param>
    /// <returns>True if the string exhibits characteristics of a useful path, service name, or identifier; false otherwise.</returns>
    private static bool IsUsefulDefaultsString(string value)
    {
        int alphaNumCount;
        bool hasSlashLike;
        bool hasPercent;
        bool hasGuidLike;
        bool hasRegistryLike;
        bool hasServiceLike;
        bool hasWhitespace;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        value = value.Trim();

        if (value.Length < 4)
            return false;

        alphaNumCount = 0;
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsLetterOrDigit(value[i]))
                alphaNumCount++;
        }

        if (alphaNumCount < 3)
            return false;

        // Check for path/directory separators or wildcards.
        hasSlashLike = value.Contains("\\", StringComparison.Ordinal) || value.Contains("/", StringComparison.Ordinal);
        // Check for URL encoding indicators.
        hasPercent = value.Contains("%", StringComparison.Ordinal);
        // Check for GUID format {xxxxxxxx-xxxx-...}.
        hasGuidLike = value.Contains("{", StringComparison.Ordinal) && value.Contains("}", StringComparison.Ordinal) && value.Contains("-", StringComparison.Ordinal);
        // Check for common registry key patterns.
        hasRegistryLike =
            value.Contains("HKCU", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("HKLM", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("HKEY_", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("CurrentControlSet", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("Parameters", StringComparison.OrdinalIgnoreCase);
        // Check for common executable or service indicators.
        hasServiceLike =
            value.Contains(".dll", StringComparison.OrdinalIgnoreCase) ||
            value.Contains(".exe", StringComparison.OrdinalIgnoreCase) ||
            value.Contains(".sys", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("Service", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("Privilege", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("AUTHORITY\\", StringComparison.OrdinalIgnoreCase);
        hasWhitespace = value.Contains(' ');

        if (hasRegistryLike || hasServiceLike || hasGuidLike)
            return true;

        if (hasSlashLike && alphaNumCount >= 6)
            return true;

        if (hasPercent && (hasSlashLike || hasWhitespace) && alphaNumCount >= 6)
            return true;

        if (value.Length >= 12 && alphaNumCount >= 8)
            return true;

        return false;
    }

    /// <summary>
    /// Infers the confidence level of a structured signature based on the count of entries, size per entry, and header information provided.
    /// </summary>
    /// <param name="entryCount">The number of parsed items/entries.</param>
    /// <param name="entrySize">The expected byte size of each item structure.</param>
    /// <param name="headerSize">The size of the initial header block.</param>
    /// <returns>A confidence string ("Low", "Medium").</returns>
    private static string InferGridConfidence(int entryCount, int entrySize, int headerSize)
    {
        if (entryCount >= 4 && entrySize >= 8)
            return "Medium";

        if (entryCount >= 2 && (headerSize == 2 || headerSize == 4))
            return "Medium";

        return "Low";
    }

    /// <summary>
    /// Attempts to parse the signature tree header to extract node count, version, tree type, and flags.
    /// </summary>
    /// <param name="data">The raw payload bytes.</param>
    /// <param name="nodeCount">Output: The number of nodes found in the structure.</param>
    /// <param name="version">Output: The signature version number.</param>
    /// <param name="treeType">Output: The type identifier for the tree.</param>
    /// <param name="flags">Output: Miscellaneous flags associated with the header.</param>
    /// <returns>True if the basic header structure could be parsed, false otherwise.</returns>
    private static bool TryParseSigTreeHeader(byte[] data, out int nodeCount, out int version, out int treeType, out int flags)
    {
        nodeCount = 0;
        version = 0;
        treeType = 0;
        flags = 0;

        if (data == null || data.Length < 5)
            return false;

        nodeCount = BitConverter.ToUInt16(data, 0);
        version = data[2];
        treeType = data[3];
        flags = data[4];

        return true;
    }

    /// <summary>
    /// Checks if the total length of the data payload matches the expected size based on a fixed header and node count.
    /// </summary>
    /// <param name="data">The raw payload bytes.</param>
    /// <param name="nodeCount">The number of nodes to check against.</param>
    /// <returns>True if the length perfectly matches the fixed layout expectation, false otherwise.</returns>
    private static bool LooksLikeFixedSigTreeLayout(byte[] data, int nodeCount)
    {
        if (data == null || data.Length < 5 || nodeCount <= 0)
            return false;

        return data.Length == 5 + (nodeCount * 16);
    }

    /// <summary>
    /// Attempts to parse a short behavioral monitoring header structure, extracting node count, variant ID, and flags.
    /// </summary>
    /// <param name="data">The raw payload bytes.</param>
    /// <param name="nodeCount">Output: The number of nodes in the short format.</param>
    /// <param name="variant">Output: The behavioral monitoring variant identifier.</param>
    /// <param name="flags">Output: Flags associated with the short header.</param>
    /// <returns>True if the short header structure was successfully parsed, false otherwise.</returns>
    private static bool TryParseBmShortHeader(byte[] data, out int nodeCount, out int variant, out int flags)
    {
        nodeCount = 0;
        variant = 0;
        flags = 0;

        if (data == null || data.Length < 3)
            return false;

        nodeCount = data[0];
        variant = data[1];
        flags = data[2];

        if (nodeCount <= 0)
            return false;

        return true;
    }

    /// <summary>
    /// Renders a single signature tree node structure into a human-readable string, detailing its internal fields.
    /// </summary>
    /// <param name="data">The raw payload bytes.</param>
    /// <param name="offset">The starting byte offset of the specific node within the data.</param>
    /// <returns>A formatted string describing the node's contents (Flags, AttrId, Hash, etc.).</returns>
    private static string RenderSigTreeNode(byte[] data, int offset)
    {
        ushort flagsField = BitConverter.ToUInt16(data, offset);
        ushort attrId = BitConverter.ToUInt16(data, offset + 2);
        byte attrIndex = data[offset + 4];
        byte marker = data[offset + 5];
        byte mode = data[offset + 6];
        uint hash = BitConverter.ToUInt32(data, offset + 7);
        string tail = DecodeHexHelper.ToHexSpaced(data, offset + 11, 5);

        return $"Flags=0x{flagsField:X4} AttrId=0x{attrId:X4} AttrIndex=0x{attrIndex:X2} Marker=0x{marker:X2} Mode=0x{mode:X2} Hash=0x{hash:X8} Tail={tail}";
    }

    /// <summary>
    /// Checks if the raw data contains any byte sequence indicating a wildcard escape character (0x90).
    /// </summary>
    /// <param name="data">The raw payload bytes.</param>
    /// <returns>True if a wildcard escape is found, false otherwise.</returns>
    private static bool ContainsSigTreeWildcardEscape(byte[] data)
    {
        if (data == null || data.Length < 2)
            return false;

        for (int i = 0; i < data.Length - 1; i++)
        {
            if (data[i] == 0x90)
                return true;
        }

        return false;
    }

    /// <summary>
    /// Infers the confidence level of a structured signature based on parsing metrics like node count, entry size, and presence of strings/preview data.
    /// </summary>
    /// <param name="count">The number of parsed items.</param>
    /// <param name="entrySize">The expected byte size per item.</param>
    /// <param name="headerSize">The header size used for parsing.</param>
    /// <param name="hasPreview">Whether a hex preview was generated.</param>
    /// <param name="hasStrings">Whether any meaningful strings were extracted.</param>
    /// <returns>A confidence string ("Low", "Medium").</returns>
    private static string InferStructuredConfidence(int count, int entrySize, int headerSize, bool hasPreview, bool hasStrings)
    {
        if (hasStrings)
            return "Medium";

        // Medium confidence for a decent number of entries with reasonable size.
        if (count >= 4 && entrySize >= 16)
            return "Medium";

        // Medium confidence if structure is somewhat defined by header/preview, even without strings.
        if (count >= 2 && headerSize == 5 && hasPreview)
            return "Medium";

        return "Low";
    }

    /// <summary>
    /// Appends a hexadecimal preview of the beginning of the raw data to the pattern string for quick inspection.
    /// </summary>
    /// <param name="pattern">The list where the hex preview will be added.</param>
    /// <param name="data">The raw byte array.</param>
    /// <param name="maxBytes">The maximum number of bytes to display in the preview.</param>
    private static void AddHexPreview(List<string> pattern, byte[] data, int maxBytes)
    {
        if (pattern == null || data == null || data.Length == 0)
            return;

        pattern.Add($"Preview={DecodeHexHelper.ToHexSpaced(data, 0, Math.Min(data.Length, maxBytes))}");
    }

    /// <summary>
    /// Collects all potential string candidates from the raw data by scanning for sequences that resemble text (ASCII or UTF-16).
    /// </summary>
    /// <param name="data">The raw byte array.</param>
    /// <param name="minimumLength">The minimum length to consider a candidate string.</param>
    /// <returns>A list of collected, unnormalized string candidates.</returns>
    private static List<string> CollectUtf16CandidateStrings(byte[] data, int minimumLength)
    {
        List<string> results;
        StringBuilder current;
        int i;

        results = new List<string>();

        if (data == null || data.Length < 2)
            return results;

        current = new StringBuilder();

        for (i = 0; i + 1 < data.Length; i += 2)
        {
            char ch = (char)(data[i] | (data[i + 1] << 8));

            if (IsReasonableTextChar(ch))
            {
                current.Append(ch);
            }
            else
            {
                FlushUtf16String(results, current, minimumLength);
            }
        }

        FlushUtf16String(results, current, minimumLength);

        results = DecodeTextHelper.NormalizeAndDistinct(results)
            .Where(LooksLikeUsefulUtf16String)
            .ToList();

        return results;
    }

    /// <summary>
    /// Writes the content of the current string buffer to the results list if it meets the minimum length requirement, then clears the buffer.
    /// </summary>
    private static void FlushUtf16String(List<string> results, StringBuilder current, int minimumLength)
    {
        string value;

        if (current == null || current.Length == 0)
            return;

        value = current.ToString().Trim();

        if (value.Length >= minimumLength && !string.IsNullOrWhiteSpace(value))
            results.Add(value);

        current.Clear();
    }

    /// <summary>
    /// Determines if a character is considered part of reasonable text content for string extraction purposes.
    /// </summary>
    private static bool IsReasonableTextChar(char ch)
    {
        if (ch >= 'A' && ch <= 'Z')
            return true;

        if (ch >= 'a' && ch <= 'z')
            return true;

        if (ch >= '0' && ch <= '9')
            return true;

        // Allow common path/identifier characters, whitespace, and punctuation.
        return ch switch
        {
            ' ' or '\t' or '\\' or '/' or ':' or '.' or '_' or '-' or '%' or '*' or '?' or '{' or '}' or '(' or ')' or '[' or ']' or '!' or '=' or '+' or ',' or ';' => true,
            _ => false
        };
    }

    /// <summary>
    /// Replaces wildcard escape sequences (0x90) within a string with a standardized placeholder token.
    /// </summary>
    /// <param name="value">The raw string containing potential wildcards.</param>
    /// <returns>The string with all wildcards replaced by "{WILDCARD}".</returns>
    private static string NormalizeSigTreeWildcardString(string value)
    {
        StringBuilder sb;
        int i;

        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        sb = new StringBuilder(value.Length);

        for (i = 0; i < value.Length; i++)
        {
            char ch = value[i];

            if (ch == '\u0090')
            {
                sb.Append("{WILDCARD}");
                continue;
            }

            sb.Append(ch);
        }

        return sb.ToString().Trim();
    }

    /// <summary>
    /// Merges strings extracted from ASCII and UTF-16 sources, normalizing them to handle wildcards and ensuring uniqueness across both sets.
    /// </summary>
    /// <param name="data">The raw payload bytes.</param>
    /// <returns>A list of unique, normalized string fragments.</returns>
    private static List<string> MergeSigTreeStrings(byte[] data)
    {
        List<string> asciiStrings;
        List<string> utf16Strings;
        List<string> merged;

        asciiStrings = DecodeTextHelper.NormalizeAndDistinct(DecodeTextHelper.CollectCandidateStrings(data, 4));
        utf16Strings = CollectUtf16CandidateStrings(data, 4);

        merged = new List<string>();

        for (int i = 0; i < asciiStrings.Count; i++)
        {
            string normalized = NormalizeSigTreeWildcardString(asciiStrings[i]);
            if (!string.IsNullOrWhiteSpace(normalized) && !merged.Contains(normalized, StringComparer.OrdinalIgnoreCase))
                merged.Add(normalized);
        }

        for (int i = 0; i < utf16Strings.Count; i++)
        {
            string normalized = NormalizeSigTreeWildcardString(utf16Strings[i]);
            if (!string.IsNullOrWhiteSpace(normalized) && !merged.Contains(normalized, StringComparer.OrdinalIgnoreCase))
                merged.Add(normalized);
        }

        return merged;
    }

    /// <summary>
    /// Checks if a string contains characteristics typical of file paths or pattern matching syntax (e.g., slashes, wildcards, registry keys).
    /// </summary>
    private static bool LooksLikePathOrPatternString(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        return
            value.Contains("\\", StringComparison.Ordinal) ||
            value.Contains("/", StringComparison.Ordinal) ||
            value.Contains(":", StringComparison.Ordinal) ||
            value.Contains("*", StringComparison.Ordinal) ||
            value.Contains("%", StringComparison.Ordinal) ||
            value.Contains("http", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("hklm", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("system32", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Checks if a string, after decoding, appears to be derived from UTF-16 encoding and meets minimum content criteria for usefulness.
    /// </summary>
    private static bool LooksLikeUsefulUtf16String(string value)
    {
        int alphaNumCount;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        value = value.Trim();

        if (value.Length < 4)
            return false;

        alphaNumCount = 0;
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsLetterOrDigit(value[i]))
                alphaNumCount++;
        }

        if (alphaNumCount < 3)
            return false;

        if (LooksLikePathOrPatternString(value))
            return true;

        return false;
    }
}
