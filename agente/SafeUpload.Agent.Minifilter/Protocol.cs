// Managed mirror of driver/SafeUpload.Minifilter/Protocol.h.
//
// Protocol.h is the source of truth. Every structure here exists to match
// it byte for byte, and Contract.Verify() checks that claim at startup
// rather than letting a mismatch surface as a corrupted path string.
//
// The layout rules that make this safe to mirror at all, restated from
// Protocol.h: fixed-size structures, explicit field widths, field order
// chosen so there is no implicit padding. Nothing here may use a type
// whose size depends on the runtime or on the process bitness.

using System;
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Minifilter;

public static class Contract
{
    public const string PortName = @"\SafeUploadPort";

    /// <summary>
    /// Must equal SAFEUPLOAD_PROTOCOL_VERSION in Protocol.h. The driver
    /// rejects any message carrying a different value, which is the
    /// mechanism that turns an incompatible pair into a clean refusal
    /// instead of a misread structure.
    /// </summary>
    public const uint Version = 8;

    public const int MaxPathChars = 512;
    public const int MaxImageNameChars = 64;

    public const int MaxExtensions = 32;
    public const int MaxExtensionChars = 16;
    public const int MaxPrefixes = 16;
    public const int MaxPrefixChars = 260;
    public const int MaxSourcePrefixes = 16;
    public const int MaxImages = 16;
    public const int MaxImageChars = 64;

    // Sizes asserted by C_ASSERT on the kernel side. Duplicated here on
    // purpose: if the two ever disagree, Verify() says so by name.
    public const int RequestSize = 1192;
    public const int ResponseSize = 24;
    public const int ControlSize = 16;
    public const int PolicyMessageSize = 19752;
    public const int CountersSize = 160;

    /// <summary>
    /// Throws if any managed structure fails to match the size the driver
    /// asserts for its C counterpart.
    ///
    /// Call this before connecting. A layout mismatch found here is a
    /// one-line error message; the same mismatch found at run time is a
    /// verdict answered for the wrong request, and nothing in the system
    /// would report it as an error.
    /// </summary>
    public static unsafe void Verify()
    {
        Check(nameof(SafeUploadRequest), sizeof(SafeUploadRequest), RequestSize);
        Check(nameof(SafeUploadResponse), sizeof(SafeUploadResponse), ResponseSize);
        Check(nameof(SafeUploadControl), sizeof(SafeUploadControl), ControlSize);
        Check(nameof(SafeUploadPolicyMessage), sizeof(SafeUploadPolicyMessage), PolicyMessageSize);
        Check(nameof(SafeUploadCounters), sizeof(SafeUploadCounters), CountersSize);

        // Offsets that carry real risk: everything after them shifts if
        // they are wrong, and a shifted path is still a readable string.
        CheckOffset(nameof(SafeUploadRequest) + ".Path",
                    (int) Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.Path)), 40);
        CheckOffset(nameof(SafeUploadRequest) + ".ImageName",
                    (int) Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.ImageName)), 1064);
        CheckOffset(nameof(SafeUploadPolicyMessage) + ".Prefixes",
                    (int) Marshal.OffsetOf<SafeUploadPolicyMessage>(nameof(SafeUploadPolicyMessage.Prefixes)), 1064);
        CheckOffset(nameof(SafeUploadPolicyMessage) + ".SourcePrefixes",
                    (int) Marshal.OffsetOf<SafeUploadPolicyMessage>(nameof(SafeUploadPolicyMessage.SourcePrefixes)), 9384);
        CheckOffset(nameof(SafeUploadPolicyMessage) + ".Images",
                    (int) Marshal.OffsetOf<SafeUploadPolicyMessage>(nameof(SafeUploadPolicyMessage.Images)), 17704);
        CheckOffset(nameof(SafeUploadCounters) + ".TaintHits",
                    (int) Marshal.OffsetOf<SafeUploadCounters>(nameof(SafeUploadCounters.TaintHits)), 96);
    }

    private static void Check(string name, int actual, int expected)
    {
        if (actual != expected)
        {
            throw new InvalidOperationException(
                $"{name} tem {actual} bytes, o driver espera {expected}. " +
                "Protocol.cs saiu de sincronia com Protocol.h.");
        }
    }

    private static void CheckOffset(string name, int actual, int expected)
    {
        if (actual != expected)
        {
            throw new InvalidOperationException(
                $"{name} esta no offset {actual}, o driver espera {expected}. " +
                "Protocol.cs saiu de sincronia com Protocol.h.");
        }
    }
}

public static class Operation
{
    public const uint Create = 1;

    /// <summary>
    /// Kept for contract completeness. The driver no longer registers
    /// IRP_MJ_READ, so this value does not appear in practice - see the
    /// comment on the registration table in Filter.c for why.
    /// </summary>
    public const uint Read = 2;
}

public static class Verdict
{
    public const uint Allow = 0;
    public const uint Deny = 1;
}

[Flags]
public enum RequestFlags : uint
{
    None = 0,
    PathTruncated = 0x00000001,
    ImageNameTruncated = 0x00000002,
    PathNotNormalized = 0x00000004,

    /// <summary>The create is heading into a monitored destination.</summary>
    ScopeDestination = 0x00000008,

    /// <summary>The create is reading from a monitored source.</summary>
    ScopeSource = 0x00000010,
}

[Flags]
public enum PolicyFlags : uint
{
    None = 0,
    Removable = 0x00000001,
    Network = 0x00000002,
}

public static class ControlCommand
{
    public const uint SetPolicy = 1;
    public const uint GetCounters = 2;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadRequest
{
    public uint Version;
    public uint StructSize;
    public ulong RequestId;
    public uint Operation;
    public uint RequestorProcessId;
    public uint Flags;
    public uint PathLength;      // bytes, excluding the terminator
    public uint ImageNameLength; // bytes, excluding the terminator
    public uint Reserved;
    public fixed char Path[Contract.MaxPathChars];
    public fixed char ImageName[Contract.MaxImageNameChars];

    public RequestFlags TypedFlags => (RequestFlags) Flags;

    public string GetPath()
    {
        fixed (char* p = Path) { return Read(p, PathLength, Contract.MaxPathChars); }
    }

    public string GetImageName()
    {
        fixed (char* p = ImageName) { return Read(p, ImageNameLength, Contract.MaxImageNameChars); }
    }

    // The length field is in bytes and comes from the kernel. It is
    // trusted only after being clamped: a client that indexes straight
    // into a fixed buffer with a value it did not verify is one bad
    // message away from reading past the structure.
    private static string Read(char* buffer, uint lengthInBytes, int capacityInChars)
    {
        int chars = (int) (lengthInBytes / sizeof(char));

        if (chars < 0 || chars > capacityInChars)
        {
            chars = capacityInChars;
        }

        return new string(buffer, 0, chars);
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadResponse
{
    public uint Version;
    public uint StructSize;
    public ulong RequestId;
    public uint Verdict;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadControl
{
    public uint Version;
    public uint StructSize;
    public uint Command;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadPolicyMessage
{
    public SafeUploadControl Control;

    public uint ExtensionCount;
    public uint PrefixCount;
    public uint ImageCount;
    public uint SourcePrefixCount;
    public uint Flags;

    /// <summary>
    /// Quanto o kernel espera por um veredito, em milissegundos.
    ///
    /// Vem da politica e nao de uma constante no driver porque o prazo e da
    /// inspecao, nao do transporte: a RN-012 da um orcamento ao motor, e ter
    /// o mesmo numero escrito em dois lugares e como os dois divergem. Zero
    /// significa "use o padrao do driver". O driver limita o valor.
    /// </summary>
    public uint VerdictTimeoutMs;

    public fixed char Extensions[Contract.MaxExtensions * Contract.MaxExtensionChars];
    public fixed char Prefixes[Contract.MaxPrefixes * Contract.MaxPrefixChars];
    public fixed char SourcePrefixes[Contract.MaxSourcePrefixes * Contract.MaxPrefixChars];
    public fixed char Images[Contract.MaxImages * Contract.MaxImageChars];
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadCounters
{
    public uint Version;
    public uint StructSize;

    public ulong CreatesSeen;
    public ulong CreatesPastCheapGates;
    public ulong ScopeEvaluations;
    public ulong UserModeRoundTrips;
    public ulong CacheHits;
    public ulong DeniedPreCreate;
    public ulong DeniedPostCreate;
    public ulong DeniedRename;
    public ulong AllowedWithoutInspection;
    public ulong TaintsRecorded;
    public ulong TaintLookups;
    public ulong TaintHits;
    public ulong SetInformationSeen;
    public ulong RenamesSeen;
    public ulong RenamesFromTainted;
    public ulong LinksSeen;
    public ulong LinksFromTainted;
    public ulong ClassesSeenLow;
    public ulong ClassesSeenHigh;
}
