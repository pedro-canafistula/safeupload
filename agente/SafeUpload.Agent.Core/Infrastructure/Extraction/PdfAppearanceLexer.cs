using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

// A content-stream lexer, not a renderer. Only a closed set of non-painting-text
// operators is admitted; resources are inspected separately by PdfAuxiliaryText.
internal sealed class PdfAppearanceLexer(ReadOnlyMemory<byte> content, Action countToken, Action<string, string> resource, Func<CancellationToken> token)
{
    private const int MaximumDepth = 64;
    private enum Kind { Number, Name, String, Hex, Comment, Boolean, Null, Array, NumberArray, Dictionary, OpenArray, CloseArray, OpenDictionary, CloseDictionary, Operator }
    private readonly record struct Lexeme(Kind Kind, int Start, int End);
    private sealed class Container(bool dictionary)
    {
        public bool Dictionary { get; } = dictionary;
        public bool Key = true, Numbers = true;
    }
    private int _position;
    private byte At(int index) => content.Span[index];

    internal void Validate()
    {
        var containers = new Stack<Container>();
        var operands = new List<Kind>();
        var operandTokens = new List<Lexeme>();
        int graphics = 0, marked = 0;
        bool text = false;
        _position = 0;
        while (Next() is { } item)
        {
            token().ThrowIfCancellationRequested(); countToken();
            if (item.Kind == Kind.Comment) continue;
            if (item.Kind == Kind.Name && NameEquals(item, "ActualText")) throw new UnsupportedContentException();
            if (item.Kind is Kind.OpenArray or Kind.OpenDictionary)
            {
                if (containers.Count >= MaximumDepth) throw new InspectionLimitException();
                if (containers.TryPeek(out var parent) && parent.Dictionary && parent.Key) throw new UnsupportedContentException();
                containers.Push(new(item.Kind == Kind.OpenDictionary)); continue;
            }
            Kind kind = item.Kind;
            if (kind is Kind.CloseArray or Kind.CloseDictionary)
            {
                if (!containers.TryPop(out var closed) || closed.Dictionary != (kind == Kind.CloseDictionary) || closed.Dictionary && !closed.Key)
                    throw new UnsupportedContentException();
                kind = closed.Dictionary ? Kind.Dictionary : closed.Numbers ? Kind.NumberArray : Kind.Array;
            }
            if (kind == Kind.Operator)
            {
                if (containers.Count != 0 || item.End - item.Start > 8) throw new UnsupportedContentException();
                string op = System.Text.Encoding.ASCII.GetString(content.Span.Slice(item.Start, item.End - item.Start));
                switch (op)
                {
                    case "Tj": case "TJ": case "'": case "\"": case "Do": case "BI": case "ID": case "EI":
                        throw new UnsupportedContentException();
                    case "q": Require(); if (++graphics > MaximumDepth) throw new InspectionLimitException(); break;
                    case "Q": Require(); if (graphics-- == 0) throw new UnsupportedContentException(); break;
                    case "BT": Require(); if (text) throw new UnsupportedContentException(); text = true; break;
                    case "ET": Require(); if (!text) throw new UnsupportedContentException(); text = false; break;
                    case "BMC": Require(Kind.Name); if (++marked > MaximumDepth) throw new InspectionLimitException(); break;
                    case "BDC":
                        if (operands.Count != 2 || operands[0] != Kind.Name || operands[1] is not (Kind.Name or Kind.Dictionary)) throw new UnsupportedContentException();
                        if (operands[1] == Kind.Name) Resource("Properties", 1);
                        if (++marked > MaximumDepth) throw new InspectionLimitException(); break;
                    case "EMC": Require(); if (marked-- == 0) throw new UnsupportedContentException(); break;
                    case "MP": Require(Kind.Name); break;
                    case "DP":
                        if (operands.Count != 2 || operands[0] != Kind.Name || operands[1] is not (Kind.Name or Kind.Dictionary)) throw new UnsupportedContentException();
                        if (operands[1] == Kind.Name) Resource("Properties", 1);
                        break;
                    case "cm": case "c": Numbers(6); break;
                    case "re": case "v": case "y": case "K": case "k": Numbers(4); break;
                    case "RG": case "rg": Numbers(3); break;
                    case "m": case "l": Numbers(2); break;
                    case "w": case "J": case "j": case "M": case "i": case "G": case "g": Numbers(1); break;
                    case "d": Require(Kind.NumberArray, Kind.Number); break;
                    case "ri": Require(Kind.Name); break;
                    case "gs": Require(Kind.Name); Resource("ExtGState", 0); break;
                    case "CS": case "cs": Require(Kind.Name); Resource("ColorSpace", 0); break;
                    case "sh": Require(Kind.Name); Resource("Shading", 0); break;
                    case "SC": case "sc":
                        if (operands.Count is < 1 or > 32 || operands.Any(value => value != Kind.Number)) throw new UnsupportedContentException();
                        break;
                    case "SCN": case "scn":
                        if (operands.Count is < 1 or > 32 || operands.Take(operands.Count - 1).Any(value => value != Kind.Number) ||
                            operands[^1] is not (Kind.Number or Kind.Name)) throw new UnsupportedContentException();
                        if (operands[^1] == Kind.Name) Resource("Pattern", operands.Count - 1);
                        break;
                    case "h": case "S": case "s": case "f": case "F": case "f*": case "B": case "B*": case "b": case "b*": case "n": case "W": case "W*": Require(); break;
                    case "Tf": if (!text) throw new UnsupportedContentException(); Require(Kind.Name, Kind.Number); Resource("Font", 0); break;
                    case "Tm": if (!text) throw new UnsupportedContentException(); Numbers(6); break;
                    case "Td": case "TD": if (!text) throw new UnsupportedContentException(); Numbers(2); break;
                    case "Tc": case "Tw": case "Tz": case "TL": case "Tr": case "Ts": if (!text) throw new UnsupportedContentException(); Numbers(1); break;
                    case "T*": if (!text) throw new UnsupportedContentException(); Require(); break;
                    default: throw new UnsupportedContentException();
                }
                operands.Clear(); operandTokens.Clear(); continue;
            }
            if (containers.TryPeek(out var container))
            {
                if (container.Dictionary)
                {
                    if (container.Key && kind != Kind.Name) throw new UnsupportedContentException();
                    container.Key = !container.Key;
                }
                container.Numbers &= kind == Kind.Number;
            }
            else
            {
                if (operands.Count == 32) throw new InspectionLimitException();
                operands.Add(kind); operandTokens.Add(item);
            }
        }
        if (containers.Count != 0 || operands.Count != 0 || graphics != 0 || marked != 0 || text) throw new UnsupportedContentException();

        void Resource(string category, int index)
        {
            var name = new System.Text.StringBuilder();
            foreach (byte value in ValueBytes(operandTokens[index]))
            {
                if (name.Length == 1024) throw new InspectionLimitException();
                name.Append((char)value);
            }
            string key = name.ToString();
            if (category == "ColorSpace" && key is "DeviceGray" or "DeviceRGB" or "DeviceCMYK" or "Pattern") return;
            resource(category, key);
        }
        void Require(params Kind[] expected)
        { if (!operands.SequenceEqual(expected)) throw new UnsupportedContentException(); }
        void Numbers(int count)
        { if (operands.Count != count || operands.Any(value => value != Kind.Number)) throw new UnsupportedContentException(); }
    }

    // Stored literal/hex/name operands can carry text even when they are not
    // painted. Decode each as its own item after syntax validation, using one
    // fixed buffer. This does not concatenate unrelated property values.
    internal IEnumerable<ReadOnlyMemory<char>> ReadText()
    {
        var buffer = new char[8192];
        _position = 0;
        while (Next() is { } item)
        {
            if (item.Kind is not (Kind.String or Kind.Hex or Kind.Name or Kind.Comment)) continue;
            int count = 0;
            using var bytes = ValueBytes(item).GetEnumerator();
            int first = bytes.MoveNext() ? bytes.Current : -1;
            int second = bytes.MoveNext() ? bytes.Current : -1;
            bool bigEndian = first == 254 && second == 255, littleEndian = first == 255 && second == 254;
            if (bigEndian || littleEndian)
            {
                while (bytes.MoveNext())
                {
                    int high = bytes.Current;
                    if (!bytes.MoveNext()) throw new UnsupportedContentException();
                    buffer[count++] = (char)(bigEndian ? high * 256 + bytes.Current : bytes.Current * 256 + high);
                    if (count == buffer.Length) { yield return buffer.AsMemory(0, count); count = 0; }
                }
            }
            else
            {
                if (first >= 0) buffer[count++] = Character(first, item.Kind);
                if (second >= 0) buffer[count++] = Character(second, item.Kind);
                while (bytes.MoveNext())
                {
                    buffer[count++] = Character(bytes.Current, item.Kind);
                    if (count == buffer.Length) { yield return buffer.AsMemory(0, count); count = 0; }
                }
            }
            if (count != 0) yield return buffer.AsMemory(0, count);
            yield return "\n".AsMemory();
        }
    }

    private static readonly char[] PdfCharacters = Enumerable.Range(0, 256).Select(value =>
        UglyToad.PdfPig.Core.PdfDocEncoding.TryConvertBytesToString(new[] { (byte)value }, out string? text) && text is { Length: 1 }
            ? text[0] : '\uffff').ToArray();
    private static char Character(int value, Kind kind)
    {
        // Property text strings use PDFDocEncoding; names/comments retain raw
        // byte values because they do not declare a text-string encoding.
        char result = kind is Kind.String or Kind.Hex ? PdfCharacters[value] : (char)value;
        if (result == '\uffff') throw new UnsupportedContentException();
        return result;
    }

    private Lexeme? Next()
    {
        while (_position < content.Length)
        {
            token().ThrowIfCancellationRequested();
            byte value = At(_position);
            if (White(value)) { _position++; continue; }
            if (value == '%')
            {
                int comment = _position++;
                while (_position < content.Length && At(_position) is not (10 or 13)) { token().ThrowIfCancellationRequested(); _position++; }
                return new(Kind.Comment, comment, _position);
            }
            break;
        }
        if (_position == content.Length) return null;
        int start = _position; byte current = At(_position++);
        switch (current)
        {
            case (byte)'[': return new(Kind.OpenArray, start, _position);
            case (byte)']': return new(Kind.CloseArray, start, _position);
            case (byte)'<':
                if (_position < content.Length && At(_position) == '<') { _position++; return new(Kind.OpenDictionary, start, _position); }
                while (_position < content.Length && At(_position) != '>')
                { token().ThrowIfCancellationRequested(); if (!White(At(_position)) && Hex(At(_position)) < 0) throw new UnsupportedContentException(); _position++; }
                if (_position == content.Length) throw new UnsupportedContentException();
                _position++; return new(Kind.Hex, start, _position);
            case (byte)'>':
                if (_position == content.Length || At(_position++) != '>') throw new UnsupportedContentException();
                return new(Kind.CloseDictionary, start, _position);
            case (byte)'(':
                int depth = 1;
                while (_position < content.Length && depth != 0)
                {
                    token().ThrowIfCancellationRequested(); byte value = At(_position++);
                    if (value == '\\')
                    {
                        if (_position == content.Length) throw new UnsupportedContentException();
                        _position++; // Escaped parentheses never change nesting.
                    }
                    else if (value == '(') { if (++depth > MaximumDepth) throw new InspectionLimitException(); }
                    else if (value == ')') depth--;
                }
                if (depth != 0) throw new UnsupportedContentException();
                return new(Kind.String, start, _position);
            case (byte)'/':
                while (_position < content.Length && !Delimiter(At(_position)))
                {
                    token().ThrowIfCancellationRequested();
                    if (At(_position++) == '#')
                    {
                        if (_position + 1 >= content.Length || Hex(At(_position)) < 0 || Hex(At(_position + 1)) < 0 ||
                            Hex(At(_position)) * 16 + Hex(At(_position + 1)) == 0) throw new UnsupportedContentException();
                        _position += 2;
                    }
                }
                return new(Kind.Name, start, _position);
            case (byte)')': case (byte)'{': case (byte)'}': throw new UnsupportedContentException();
        }
        while (_position < content.Length && !Delimiter(At(_position))) { token().ThrowIfCancellationRequested(); _position++; }
        var span = content.Span.Slice(start, _position - start);
        Kind kind = Number(span) ? Kind.Number : span.SequenceEqual("true"u8) || span.SequenceEqual("false"u8) ? Kind.Boolean :
            span.SequenceEqual("null"u8) ? Kind.Null : Kind.Operator;
        return new(kind, start, _position);
    }

    private bool NameEquals(Lexeme name, string expected)
    {
        int offset = 0;
        foreach (byte value in ValueBytes(name))
        { if (offset == expected.Length || value != expected[offset++]) return false; }
        return offset == expected.Length;
    }
    private IEnumerable<byte> ValueBytes(Lexeme item)
    {
        int end = item.Kind is Kind.Name or Kind.Comment ? item.End : item.End - 1;
        for (int i = item.Start + 1; i < end; i++)
        {
            token().ThrowIfCancellationRequested(); byte value = At(i);
            if (item.Kind == Kind.Comment) { yield return value; continue; }
            if (item.Kind == Kind.Name)
            {
                if (value == '#') { value = (byte)(Hex(At(i + 1)) * 16 + Hex(At(i + 2))); i += 2; }
            }
            else if (item.Kind == Kind.Hex)
            {
                if (White(value)) continue;
                int high = Hex(value), low = 0;
                while (++i < end && White(At(i))) token().ThrowIfCancellationRequested();
                if (i < end) low = Hex(At(i));
                value = (byte)(high * 16 + low);
            }
            else if (value == '\\')
            {
                value = At(++i);
                if (value is 10 or 13)
                { if (value == 13 && i + 1 < end && At(i + 1) == 10) i++; continue; }
                if (value is >= (byte)'0' and <= (byte)'7')
                {
                    int octal = value - '0';
                    for (int digits = 1; digits < 3 && i + 1 < end && At(i + 1) is >= (byte)'0' and <= (byte)'7'; digits++) octal = octal * 8 + At(++i) - '0';
                    value = (byte)octal;
                }
                else value = value switch { (byte)'n' => 10, (byte)'r' => 13, (byte)'t' => 9, (byte)'b' => 8, (byte)'f' => 12, _ => value };
            }
            else if (value == 13) { if (i + 1 < end && At(i + 1) == 10) i++; value = 10; }
            yield return value;
        }
    }
    private static bool Number(ReadOnlySpan<byte> value)
    {
        int index = value[0] is (byte)'+' or (byte)'-' ? 1 : 0;
        bool digit = false, dot = false;
        for (; index < value.Length; index++)
        {
            if (value[index] is >= (byte)'0' and <= (byte)'9') digit = true;
            else if (value[index] == '.' && !dot) dot = true;
            else return false;
        }
        return digit;
    }
    private static bool White(byte value) => value is 0 or 9 or 10 or 12 or 13 or 32;
    private static bool Delimiter(byte value) => White(value) || value is (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';
    private static int Hex(byte value) => value is >= (byte)'0' and <= (byte)'9' ? value - '0' :
        value is >= (byte)'A' and <= (byte)'F' ? value - 'A' + 10 : value is >= (byte)'a' and <= (byte)'f' ? value - 'a' + 10 : -1;
}
