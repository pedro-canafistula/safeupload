#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Diagnostics;

namespace SafeUpload.Agent.Minifilter;

/// <summary>Feature-only, bounded prototype observation and trace controls.
/// Never policy, publication, overrides, capacity, fault or trust controls.</summary>
public static class StagedProofProxyWire
{
    public const uint Magic = 0x46505553; // SUPF, distinct from capture requests.
    public const int HeaderBytes = 64;
    public const int MaxRequestBytes = 4096;
    public const int MaxReplyBytes = Contract.AdmissionCoverageStatusSize;

    public static int Validate(ReadOnlySpan<byte> input, int outputBytes)
    {
        if (input.Length < 16 || input.Length > MaxRequestBytes - HeaderBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(input) != Contract.Version ||
            BinaryPrimitives.ReadUInt32LittleEndian(input[4..]) != input.Length)
            throw new InvalidDataException("Invalid prototype proof control header.");
        uint command = BinaryPrimitives.ReadUInt32LittleEndian(input[8..]);
        uint reserved = BinaryPrimitives.ReadUInt32LittleEndian(input[12..]);
        int expected = command switch
        {
            2 => 184, 5 or 6 or 7 => 0, 8 => 1960, 12 => 288, 17 => 104,
            19 => 36136, 20 => 32, 22 => 672, 23 => 6672,
            24 => Contract.AdmissionCoverageStatusSize, 25 => 36392,
            _ => throw new InvalidDataException("Prototype proof control is not allowed."),
        };
        if (outputBytes != expected)
            throw new InvalidDataException("Prototype proof reply buffer size mismatch.");
        if (command is 8 or 22)
        {
            if (input.Length != 32 || reserved != 0)
                throw new InvalidDataException("Invalid trace paging request.");
        }
        else if (command == 17)
        {
            if (input.Length < 28 || reserved != 0)
                throw new InvalidDataException("Invalid registry probe request.");
            int volume = BinaryPrimitives.ReadUInt16LittleEndian(input[16..]);
            int path = BinaryPrimitives.ReadUInt16LittleEndian(input[18..]);
            if (volume is < 1 or > 260 || path is < 1 or > 260 || input.Length != 24 + 2 * (volume + path) ||
                BinaryPrimitives.ReadUInt32LittleEndian(input[20..]) != 0)
                throw new InvalidDataException("Invalid registry probe strings.");
        }
        else if (input.Length != 16 || (command == 5 ? reserved > 3 :
                 command is 19 or 25 ? reserved > 20480 || reserved % 32 != 0 : reserved != 0))
            throw new InvalidDataException("Invalid prototype proof options.");
        return expected;
    }

    public static (byte[] Input, int OutputBytes) Parse(ReadOnlySpan<byte> body)
    {
        if (body.Length < HeaderBytes + 16 || body.Length > MaxRequestBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(body) != Magic)
            throw new InvalidDataException("Invalid prototype proof request.");
        uint requestedOutput = BinaryPrimitives.ReadUInt32LittleEndian(body[4..]);
        if (requestedOutput > MaxReplyBytes) throw new InvalidDataException("Prototype proof reply cap.");
        int output = (int)requestedOutput;
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(body[8..]);
        if (length != body.Length - HeaderBytes || body.Slice(12, HeaderBytes - 12).ContainsAnyExcept((byte)0))
            throw new InvalidDataException("Invalid prototype proof frame bounds/reserved bytes.");
        byte[] input = body[HeaderBytes..].ToArray();
        Validate(input, output);
        return (input, output);
    }
}

public interface IStagedProofSender
{
    AdmissionEvidenceReply SendStagedProof(byte[] request, int outputBytes);
}

public sealed partial class FilterPort : IStagedProofSender
{
    public AdmissionEvidenceReply SendStagedProof(byte[] request, int outputBytes)
    {
        // Copy before validation: a caller cannot change the validated opcode
        // while waiting for the port send lease.
        ArgumentNullException.ThrowIfNull(request);
        byte[] input = (byte[])request.Clone();
        StagedProofProxyWire.Validate(input, outputBytes);
        byte[] output = new byte[outputBytes];
        uint returned;
        int hr;
        using var send = EnterSend();
        DateTimeOffset startUtc = DateTimeOffset.UtcNow;
        long start = Stopwatch.GetTimestamp();
        if (_admissionEvidenceNativeSender is { } native)
            hr = native.Send(send.Handle, input, output, out returned);
        else
        {
            unsafe
            {
                fixed (byte* source = input)
                fixed (byte* destination = output)
                    hr = FilterSendMessage(send.Handle, (IntPtr)source, (uint)input.Length,
                        (IntPtr)destination, (uint)output.Length, out returned);
            }
        }
        long end = Stopwatch.GetTimestamp();
        string? error = hr == 0 && returned != outputBytes ? "Incomplete or overreported prototype proof reply." : null;
        byte[] raw = hr == 0 ? output.AsSpan(0, (int)Math.Min(returned, (uint)output.Length)).ToArray() : [];
        return new AdmissionEvidenceReply(input, raw, hr, returned, startUtc, DateTimeOffset.UtcNow, start, end, error);
    }
}
#endif
