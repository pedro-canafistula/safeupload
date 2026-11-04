using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Drive;

internal sealed record RetainedFile(string StageName, string RelativePath, DriveWriter? Writer, uint Attributes,
    string? PreviousRelativePath);
internal sealed record StageMap(int Format, string Backing, string DestinationIdentity, RetainedFile[] Entries);

/// <summary>Private namespace intents only. No approval, justification or inspection result is persisted here.</summary>
internal sealed class DriveRecoveryStore : IDisposable
{
    internal const string MapName = "stage-map.json";
    private const int MaximumMapBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions Options = new()
    {
        AllowDuplicateProperties = false, MaxDepth = 16
    };
    private readonly string _backing, _stage, _map, _identity;
    private readonly FileStream _owner;
    private Dictionary<string, RetainedFile> _entries = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    internal DriveRecoveryStore(string backing, string privateRoot)
    {
        _backing = backing;
        _stage = Path.GetFullPath(Path.Combine(privateRoot, "stage"));
        _map = Path.Combine(privateRoot, MapName);
        RejectReparsePoint(_stage);
        _identity = IdentifyDestination(backing);
        // Prevent two live filesystems from independently replacing the same catalog.
        _owner = new FileStream(Path.Combine(privateRoot, "stage-owner.lock"), FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        try
        {
            if (!File.Exists(_map)) return; // Pre-catalog orphan bytes are preserved, never guessed or published.
            RejectReparsePoint(_map);
            using var input = new FileStream(_map, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (input.Length > MaximumMapBytes) throw new IOException("Stage catalog exceeds its limit.");
            var map = JsonSerializer.Deserialize<StageMap>(input, Options);
            if (map is not { Format: 1, Entries: not null } || map.Entries.Length > 4096)
                throw new IOException("Invalid stage catalog.");
            if (map.Entries.Length != 0 &&
                (!string.Equals(map.Backing, _backing, StringComparison.OrdinalIgnoreCase) || map.DestinationIdentity != _identity))
                throw new IOException("Retained stage belongs to another destination or volume.");
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in map.Entries)
            {
                ValidateEntry(entry);
                if (!_entries.TryAdd(entry.StageName, entry) || !paths.Add(entry.RelativePath))
                    throw new IOException("Conflicting retained stage names.");
                ValidateStageFile(StagePath(entry));
            }
        }
        catch { _owner.Dispose(); throw; }
    }

    internal IEnumerable<RetainedFile> Entries => _entries.Values;
    internal string DestinationIdentity => _identity;
    internal string StagePath(RetainedFile entry) => Path.Combine(_stage, entry.StageName);

    internal void Track(string stagePath, string relative, DriveWriter? writer, uint attributes, string? previousRelative)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var entry = new RetainedFile(Path.GetFileName(stagePath), relative, writer, attributes, previousRelative);
        ValidateEntry(entry);
        if (!string.Equals(Path.GetFullPath(stagePath), StagePath(entry), StringComparison.OrdinalIgnoreCase))
            throw new IOException("Retained bytes are outside the private stage.");
        ValidateStageFile(stagePath);
        if (_entries.TryGetValue(entry.StageName, out var old) && old == entry) return;
        var next = new Dictionary<string, RetainedFile>(_entries, StringComparer.OrdinalIgnoreCase) { [entry.StageName] = entry };
        Commit(next);
    }

    internal void Remove(string stagePath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string id = Path.GetFileName(stagePath);
        if (!_entries.ContainsKey(id)) return;
        var next = new Dictionary<string, RetainedFile>(_entries, StringComparer.OrdinalIgnoreCase);
        next.Remove(id);
        Commit(next);
    }

    // Commit the whole rename intent before moving a backing directory or deleting a replaced target.
    // After an interruption the intended new name can be recovered even if the backing move did not finish.
    internal void Rename(string oldPath, string newPath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var moving = _entries.Values.Where(e => e.RelativePath.Equals(oldPath, StringComparison.OrdinalIgnoreCase) ||
            e.RelativePath.StartsWith(oldPath + "\\", StringComparison.OrdinalIgnoreCase)).ToArray();
        var next = new Dictionary<string, RetainedFile>(_entries, StringComparer.OrdinalIgnoreCase);
        foreach (var entry in _entries.Values)
            if (entry.RelativePath.Equals(newPath, StringComparison.OrdinalIgnoreCase) && !moving.Contains(entry))
                next.Remove(entry.StageName);
        foreach (var entry in moving)
            next[entry.StageName] = entry with { RelativePath = newPath + entry.RelativePath[oldPath.Length..] };
        if (!moving.Any() && next.Count == _entries.Count) return;
        Commit(next);
    }

    internal void ValidateDestination()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (IdentifyDestination(_backing) != _identity)
            throw new IOException("Protected destination identity changed.");
    }

    private void Commit(Dictionary<string, RetainedFile> next)
    {
        ValidateDestination();
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in next.Values)
        {
            ValidateEntry(entry);
            if (!paths.Add(entry.RelativePath)) throw new IOException("Conflicting retained paths.");
        }
        if (next.Count > 4096) throw new IOException("Too many retained stage entries.");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new StageMap(1, _backing, _identity, next.Values.ToArray()), Options);
        if (bytes.Length > MaximumMapBytes) throw new IOException("Stage catalog exceeds its limit.");
        var temp = _map + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                output.Write(bytes);
                output.Flush(true);
            }
            File.Move(temp, _map, overwrite: true);
            _entries = next;
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private static void ValidateEntry(RetainedFile? entry)
    {
        if (entry is null || !Guid.TryParseExact(entry.StageName, "N", out _))
            throw new IOException("Invalid retained stage entry.");
        ValidateRelativePath(entry.RelativePath);
        if (entry.PreviousRelativePath is { } previous) ValidateRelativePath(previous);
    }

    internal static void ValidateRelativePath(string relative)
    {
        if (string.IsNullOrEmpty(relative)) throw new IOException("Invalid retained relative path.");
        var parts = relative.Split('\\');
        foreach (string part in parts)
        {
            string stem = part.Split('.')[0].ToUpperInvariant();
            if (part.Length is 0 or > 255 || part is "." or ".." || part.EndsWith('.') || part.EndsWith(' ') ||
                part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                stem is "CON" or "PRN" or "AUX" or "NUL" ||
                stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && stem[3] is >= '1' and <= '9')
                throw new IOException("Invalid retained relative path.");
        }
        if (parts[0].Equals("System Volume Information", StringComparison.OrdinalIgnoreCase) ||
            parts[0].Equals("$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase) || parts.Any(p => p.StartsWith(".~su-", StringComparison.Ordinal)))
            throw new IOException("Reserved retained relative path.");
    }

    internal static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Recovery does not follow reparse points.");
    }

    private static string IdentifyDestination(string path)
    {
        var info = ReadHandleInfo(path);
        return $"{info.VolumeSerial:X8}:{info.IndexHigh:X8}{info.IndexLow:X8}";
    }

    private static void ValidateStageFile(string path)
    {
        RejectReparsePoint(path);
        var info = ReadHandleInfo(path);
        if ((info.Attributes & (uint)FileAttributes.Directory) != 0 || info.Links != 1)
            throw new IOException("Retained stage must be a private regular file without hard links.");
    }

    private static HandleInfo ReadHandleInfo(string path)
    {
        using var handle = CreateFile(path, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info))
            throw new IOException("Cannot identify protected destination.", new Win32Exception(Marshal.GetLastWin32Error()));
        return info;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HandleInfo
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out HandleInfo info);

    public void Dispose() { _disposed = true; _owner.Dispose(); }
}
