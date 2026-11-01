using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Gate;

/// <summary>Encodes the existing v1 gate layout, refusing scopes it cannot represent in full.</summary>
internal sealed record GatePolicyMessage(byte[] Bytes, string Key, int PathCount)
{
    internal const uint ProtocolVersion = 1;
    internal const int MaxPaths = 16, MaxPathChars = 512;
    private static readonly Encoding Utf16 = new UnicodeEncoding(false, false, true);

    internal static GatePolicyMessage Create(IReadOnlyList<string> folders, bool removable, bool network,
        Func<string, string?> resolve)
    {
        ArgumentNullException.ThrowIfNull(folders);
        ArgumentNullException.ThrowIfNull(resolve);
        if (folders.Count > MaxPaths)
            throw new InvalidPolicyException("Gate policy exceeds the supported folder count; no partial policy was sent.");
        var message = new byte[16 + MaxPaths * MaxPathChars * 2];
        BitConverter.TryWriteBytes(message.AsSpan(0), 1u); // Existing SetPolicy command.
        BitConverter.TryWriteBytes(message.AsSpan(4), ProtocolVersion);
        BitConverter.TryWriteBytes(message.AsSpan(8), (removable ? 1u : 0u) | (network ? 2u : 0u));
        BitConverter.TryWriteBytes(message.AsSpan(12), (uint)folders.Count);
        for (int i = 0; i < folders.Count; i++)
        {
            string? path = resolve(folders[i]);
            if (string.IsNullOrWhiteSpace(path) || path.Length >= MaxPathChars || path.IndexOf('\0') >= 0)
                throw new InvalidPolicyException("Gate policy contains an unresolved or oversized path; no partial policy was sent.");
            try { Utf16.GetBytes(path).CopyTo(message, 16 + i * MaxPathChars * 2); }
            catch (EncoderFallbackException)
            { throw new InvalidPolicyException("Gate policy contains invalid path encoding; no partial policy was sent."); }
        }
        return new(message, Convert.ToHexString(SHA256.HashData(message)), folders.Count);
    }
}
