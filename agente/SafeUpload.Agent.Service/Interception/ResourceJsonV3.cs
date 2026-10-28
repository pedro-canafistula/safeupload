#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace SafeUpload.Agent.Service.Interception;

// Shared passive JSON grammar. No repair of untrusted evidence, I/O or adoption.
internal static class ResourceJsonV3
{
    internal const int MaximumDepth = 16;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly UnicodeEncoding Utf16 = new(false, false, true);
    internal static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var resolver = new DefaultJsonTypeInfoResolver();
        resolver.Modifiers.Add(info =>
        {
            if (info.Kind != JsonTypeInfoKind.Object) return;
            foreach (var property in info.Properties)
            {
                property.IsRequired = true;
                // Modern snapshots retain required-null source properties. This
                // option is local; the shipped journal options/bytes are untouched.
                property.ShouldSerialize = null;
            }
        });
        return new()
        {
            MaxDepth = MaximumDepth, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            RespectRequiredConstructorParameters = true, TypeInfoResolver = resolver,
            Converters = { new CanonicalGuidConverter() }
        };
    }

    internal static byte[] Serialize<T>(T value, int maximumBytes)
    {
        using var stream = new BoundedStream(maximumBytes);
        try
        {
            using (var writer = new Utf8JsonWriter(stream)) JsonSerializer.Serialize(writer, value, Options);
            byte[] bytes = stream.ToArray();
            CheckTokens(bytes);
            return bytes;
        }
        catch (Exception error) when (error is JsonException or ArgumentException or OverflowException)
        { throw new InvalidDataException("Invalid schema-3 JSON.", error); }
    }

    internal static T Deserialize<T>(ReadOnlySpan<byte> bytes, int maximumBytes)
    {
        Require(bytes.Length is > 0 && bytes.Length <= maximumBytes, "Record exceeds its byte bound.");
        try
        {
            CheckTokens(bytes);
            return JsonSerializer.Deserialize<T>(bytes, Options) ?? throw new InvalidDataException("Missing record.");
        }
        catch (Exception error) when (error is JsonException or ArgumentException or FormatException or OverflowException or InvalidOperationException)
        { throw new InvalidDataException("Invalid schema-3 JSON.", error); }
    }

    internal static void CheckTokens(ReadOnlySpan<byte> bytes)
    {
        Utf8.GetCharCount(bytes);
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = MaximumDepth });
        var objects = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject) objects.Push(new(StringComparer.Ordinal));
            else if (reader.TokenType == JsonTokenType.EndObject) objects.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                string name = reader.GetString()!; Text(name, 0, int.MaxValue);
                Require(objects.Peek().Add(name), "Duplicate JSON property.");
            }
            else if (reader.TokenType == JsonTokenType.String)
            {
                // GetString rejects unpaired escaped surrogates; check raw
                // UTF-16 too so callers never silently write replacement chars.
                Text(reader.GetString()!, 0, int.MaxValue);
            }
            else if (reader.TokenType == JsonTokenType.Number)
            {
                var number = reader.ValueSpan;
                Require(number.IndexOfAny((byte)'.', (byte)'e', (byte)'E') < 0 &&
                    !number.SequenceEqual("-0"u8), "Integer encoding is noncanonical.");
            }
        }
    }

    internal static void Text(string value, int minimum, int maximum)
    {
        Require(value is not null && value.Length >= minimum && value.Length <= maximum && !value.Contains('\0'),
            "String length/NUL is invalid.");
        try { Utf16.GetByteCount(value!); }
        catch (EncoderFallbackException error) { throw new InvalidDataException("Invalid UTF-16.", error); }
    }
    internal static void Hex(string value) => Require(value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F'), "SHA256 is not canonical.");
    internal static byte[] Base64(string value, int size)
    {
        try
        {
            byte[] bytes = Convert.FromBase64String(value);
            Require(bytes.Length == size && Convert.ToBase64String(bytes) == value, "Base64 is not canonical/exact.");
            return bytes;
        }
        catch (Exception error) when (error is FormatException or ArgumentNullException)
        { throw new InvalidDataException("Invalid Base64.", error); }
    }
    internal static void Identity(StagedStageIdentity? value) => Require(value is not null &&
        (value.FileIdLow | value.FileIdHigh) != 0, "Missing file identity.");
    internal static void Id(Guid value) => Require(value != Guid.Empty, "Empty GUID.");
    internal static void Require([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool value, string message) { if (!value) throw new InvalidDataException(message); }

    // The writer fails before returning bytes at limit+1; it cannot create a
    // candidate or invoke a native adapter. It stores at most the selected bound.
    private sealed class BoundedStream(int maximumBytes) : Stream
    {
        private readonly MemoryStream content = new();
        internal byte[] ToArray() => content.ToArray();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => content.Length;
        public override long Position { get => content.Position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Flush() { }
        protected override void Dispose(bool disposing) { if (disposing) content.Dispose(); base.Dispose(disposing); }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Require(buffer.Length <= maximumBytes - Length, "Record exceeds its byte bound.");
            content.Write(buffer);
        }
    }

    private sealed class CanonicalGuidConverter : JsonConverter<Guid>
    {
        public override Guid Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options)
        {
            string? text = reader.GetString();
            Require(Guid.TryParseExact(text, "D", out var value) && value.ToString("D", CultureInfo.InvariantCulture) == text,
                "GUID is not lowercase D.");
            return value;
        }
        public override void Write(Utf8JsonWriter writer, Guid value, JsonSerializerOptions options) => writer.WriteStringValue(value);
    }
}
#endif
