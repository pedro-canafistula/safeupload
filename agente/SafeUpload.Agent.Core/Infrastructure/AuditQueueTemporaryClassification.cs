using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

public sealed record AuditQueueTemporaryClassification(bool DirectoryExists, long EntriesExamined,
    long CandidateEntries, long InUseCandidates, long UnterminatedCandidates,
    long StructurallyCompleteCandidates, long SuspiciousCandidates, long UnavailableCandidates,
    long IndeterminateCandidates, long UnsafeCandidates, long BytesRead,
    bool ScanLimitReached, bool DirectoryTraversalBlocked)
{
    public bool Complete => !ScanLimitReached && !DirectoryTraversalBlocked &&
        UnavailableCandidates == 0 && IndeterminateCandidates == 0 && UnsafeCandidates == 0;
    public bool RequiresAttention => CandidateEntries > 0 || !Complete;
    public bool OwnershipVerified => false;
    public bool RecoveryEligible => false;
    public bool PromotionSupported => false;
    public bool DeletionSupported => false;
    public int CandidateLimit => 16;
    public int FileByteLimit => 4 * 1024 * 1024;
    public int TotalByteLimit => 16 * 1024 * 1024;
    public int LineByteLimit => 64 * 1024;
}

public sealed partial class LocalQueueAuditSink
{
    /// <summary>
    /// Explicit bounded Windows-only content classification, never recovery.
    /// Does not open the published queue or expose candidate names/IDs/content.
    /// Exclusive candidate handles stabilize each observation, not the directory.
    /// A structurally complete file may still be stale, incomplete or fabricated.
    /// </summary>
    public async Task<AuditQueueTemporaryClassification> ClassifyTemporaryFilesAsync(CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows candidate handle validation required.");
        await _writeLock.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var directory = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(_queueFile))!);
            long entries = 0, candidates = 0, busy = 0, unterminated = 0, complete = 0,
                suspicious = 0, unavailable = 0, indeterminate = 0, unsafeFiles = 0, bytesRead = 0;
            AuditQueueTemporaryClassification Result(bool exists = true, bool limited = false, bool blocked = false) =>
                new(exists, entries, candidates, busy, unterminated, complete, suspicious,
                    unavailable, indeterminate, unsafeFiles, bytesRead, limited, blocked);
            try
            {
                for (var ancestor = directory; ancestor is not null; ancestor = ancestor.Parent)
                {
                    token.ThrowIfCancellationRequested();
                    if ((File.GetAttributes(ancestor.FullName) & FileAttributes.ReparsePoint) != 0)
                        return Result(blocked: true);
                }
            }
            catch (DirectoryNotFoundException) { return Result(exists: false); }
            catch (FileNotFoundException) { return Result(exists: false); }
            var prefix = Path.GetFileName(_queueFile) + ".";
            var enumeration = new EnumerationOptions { RecurseSubdirectories = false, IgnoreInaccessible = false,
                AttributesToSkip = 0, ReturnSpecialDirectories = false };
            foreach (var path in Directory.EnumerateFileSystemEntries(directory.FullName, "*", enumeration))
            {
                token.ThrowIfCancellationRequested();
                if (entries == 10_000) return Result(limited: true);
                entries++;
                var name = Path.GetFileName(path);
                if (name.Length != prefix.Length + 36 || !name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                    !name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
                    !Guid.TryParseExact(name.AsSpan(prefix.Length, 32), "N", out _)) continue;
                if (candidates == 16) return Result(limited: true);
                candidates++;
                try
                {
                    if ((File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                    { unsafeFiles++; continue; }
                    using var handle = TemporaryNative.Open(path);
                    if (handle.IsInvalid)
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error is 32 or 33) busy++; else unavailable++;
                        continue;
                    }
                    if (!TemporaryNative.IsRegularSingleLinkAtPath(handle, path)) { unsafeFiles++; continue; }
                    // ShareMode=None excludes external writers and renames until this handle closes.
                    await using var stream = new FileStream(handle, FileAccess.Read, 8192, isAsync: false);
                    if (stream.Length > 4 * 1024 * 1024 || stream.Length > 16 * 1024 * 1024 - bytesRead)
                    { indeterminate++; continue; }
                    var (state, _) = await ClassifyTemporaryContentAsync(stream, count => bytesRead += count, token).ConfigureAwait(false);
                    switch (state)
                    {
                        case TemporaryState.StructurallyComplete: complete++; break;
                        case TemporaryState.Unterminated: unterminated++; break;
                        case TemporaryState.Suspicious: suspicious++; break;
                        default: indeterminate++; break;
                    }
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (IOException) { unavailable++; }
                catch (UnauthorizedAccessException) { unavailable++; }
                catch (Win32Exception) { unavailable++; }
            }
            token.ThrowIfCancellationRequested();
            return Result();
        }
        finally { _writeLock.Release(); }
    }

    private enum TemporaryState { StructurallyComplete, Unterminated, Suspicious, Indeterminate }

    private static async Task<(TemporaryState State, long Bytes)> ClassifyTemporaryContentAsync(FileStream stream, Action<int> observeRead, CancellationToken token)
    {
        var buffer = new byte[8192];
        var line = new byte[64 * 1024];
        var used = 0; long read = 0, records = 0;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var count = await stream.ReadAsync(buffer, token).ConfigureAwait(false);
            if (count == 0) break;
            read += count;
            observeRead(count);
            for (var i = 0; i < count; i++)
            {
                if ((i & 1023) == 0) token.ThrowIfCancellationRequested();
                if (buffer[i] == 10)
                {
                    var length = used > 0 && line[used - 1] == 13 ? used - 1 : used;
                    if (!IsSupportedTemporaryLine(line.AsMemory(0, length))) return (TemporaryState.Suspicious, read);
                    used = 0; records++;
                }
                else
                {
                    if (used == line.Length) return (TemporaryState.Indeterminate, read);
                    line[used++] = buffer[i];
                }
            }
        }
        if (used != 0) return (TemporaryState.Unterminated, read);
        return (records > 0 ? TemporaryState.StructurallyComplete : TemporaryState.Suspicious, read);
    }

    private static bool IsSupportedTemporaryLine(ReadOnlyMemory<byte> bytes)
    {
        try
        {
            // Strict UTF-8, unlike the queue reader's compatibility replacement fallback.
            _ = new UTF8Encoding(false, true).GetCharCount(bytes.Span);
            using var json = JsonDocument.Parse(bytes);
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject()) if (!names.Add(property.Name)) return false;
            if (!root.TryGetProperty("eventId", out var id) || id.ValueKind != JsonValueKind.String ||
                !id.TryGetGuid(out var guid) || guid == Guid.Empty) return false;
            if (root.TryGetProperty("dispatched", out var dispatched) &&
                dispatched.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
            if (root.TryGetProperty("type", out var type))
            {
                if (type.ValueKind != JsonValueKind.String || type.GetString() != "override") return false;
                var value = JsonSerializer.Deserialize<AuditOverride>(bytes.Span, Options);
                return value is not null && value.OccurredAtUtc != default &&
                    !string.IsNullOrWhiteSpace(value.Justification) && !string.IsNullOrWhiteSpace(value.UserName) &&
                    !string.IsNullOrWhiteSpace(value.EndpointId);
            }
            var item = JsonSerializer.Deserialize<AuditEvent>(bytes.Span, Options);
            return root.TryGetProperty("dispatched", out _) && item is not null && item.OccurredAtUtc != default &&
                !string.IsNullOrWhiteSpace(item.EndpointId) && !string.IsNullOrWhiteSpace(item.UserName) &&
                item.Categories is not null && item.MaskedSnippets is not null && item.SizeBytes >= 0 &&
                Enum.IsDefined(item.Verdict) && Enum.IsDefined(item.Channel);
        }
        catch (JsonException) { return false; }
        catch (DecoderFallbackException) { return false; }
    }

    private static class TemporaryNative
    {
        // Open the leaf itself, not a reparse target; no write/delete access or sharing.
        internal static SafeFileHandle Open(string path) => CreateFileW(path, 0x80000000, 0, IntPtr.Zero, 3,
            0x00200000 | 0x08000000, IntPtr.Zero);
        internal static bool IsRegularSingleLinkAtPath(SafeFileHandle handle, string expected)
        {
            if (GetFileType(handle) != 1) return false;
            if (!GetFileInformationByHandle(handle, out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((info.Attributes & (0x10u | 0x400u)) != 0 || info.Links != 1) return false;
            var path = new StringBuilder(32768);
            var count = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, 0);
            if (count == 0 || count >= path.Capacity) throw new IOException("Candidate handle identity unavailable.");
            var final = path.ToString();
            if (final.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) final = @"\\" + final[8..];
            else if (final.StartsWith(@"\\?\", StringComparison.Ordinal)) final = final[4..];
            return Path.GetFullPath(final).Equals(Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase);
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInformation
        {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetFileType(SafeFileHandle handle);
    }
}
