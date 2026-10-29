#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Text.Json;

namespace SafeUpload.Agent.Service.Interception;

// V4 additionally enforces CLR nullable annotations, including required-null
// versus required-nonnull DTO members. The historical v3 options stay unchanged.
internal static class ResourceJsonV4
{
    private static readonly JsonSerializerOptions Options = new(ResourceJsonV3.Options) { RespectNullableAnnotations = true };
    internal static T Deserialize<T>(ReadOnlySpan<byte> bytes, int maximum)
    {
        EvidenceBinaryV1.Need(bytes.Length is > 0 && bytes.Length <= maximum, "Record byte bound exceeded.");
        try
        {
            ResourceJsonV3.CheckTokens(bytes);
            return JsonSerializer.Deserialize<T>(bytes, Options) ?? throw new InvalidDataException("Missing record.");
        }
        catch (Exception error) when (error is JsonException or ArgumentException or FormatException or OverflowException or InvalidOperationException)
        { throw new InvalidDataException("Invalid v4 JSON.", error); }
    }
}
#endif
