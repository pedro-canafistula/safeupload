using System.Runtime.Versioning;
using System.Security.AccessControl;

namespace SafeUpload.Agent.Core.Infrastructure;

public sealed partial class LocalQueueAuditSink
{
    private readonly QueueStorageProtection? _protection;
    internal bool EnforcesProtectedStorage => _protection is not null;

    private bool VerifyQueueParentReadonly()
    {
        if (_protection is null) return true;
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Protected queue storage requires Windows.");
        return _protection.PrepareParent(create: false);
    }

    [SupportedOSPlatform("windows")]
    internal LocalQueueAuditSink(string file, QueueStorageProtection protection,
        Func<string, FileStream>? confirmationFactory = null) : this(file)
    {
        if (!Path.GetFullPath(file).Equals(protection.FilePath, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Queue protection is bound to a different file.", nameof(protection));
        _protection = protection;
        _confirmationStreamFactory = confirmationFactory;
    }

    private bool QueueExistsChecked()
    {
        if (_protection is null) return File.Exists(_queueFile);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Protected queue storage requires Windows.");
        return _protection.QueueExists();
    }

    private void EnsureQueueDirectory()
    {
        if (_protection is not null)
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Protected queue storage requires Windows.");
            _protection.PrepareParent(create: true);
        }
        else if (Path.GetDirectoryName(_queueFile) is { Length: > 0 } directory) Directory.CreateDirectory(directory);
    }

    private FileStream OpenQueueRead()
    {
        if (_protection is not null && !QueueExistsChecked()) throw new FileNotFoundException("Audit queue is absent.");
        var stream = new FileStream(_queueFile, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.Asynchronous);
        try { VerifyQueueHandle(stream, _queueFile); return stream; }
        catch { stream.Dispose(); throw; }
    }

    private FileStream OpenQueueAppend()
    {
        EnsureQueueDirectory();
        if (_protection is null) return new FileStream(_queueFile, FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.Asynchronous);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Protected queue storage requires Windows.");
        FileStream stream;
        if (QueueExistsChecked()) stream = new FileStream(_queueFile, FileMode.Open, FileAccess.ReadWrite,
            FileShare.Read, 4096, FileOptions.Asynchronous);
        else
        {
            try { stream = new FileInfo(_queueFile).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                FileShare.Read, 4096, FileOptions.Asynchronous, _protection.FileSecurity()); }
            catch (IOException) when (QueueExistsChecked())
            {
                stream = new FileStream(_queueFile, FileMode.Open, FileAccess.ReadWrite,
                    FileShare.Read, 4096, FileOptions.Asynchronous);
            }
        }
        try { VerifyQueueHandle(stream, _queueFile); return stream; }
        catch { stream.Dispose(); throw; }
    }

    private FileStream CreateConfirmationStream(string temporary)
    {
        if (_protection is null) return _confirmationStreamFactory?.Invoke(temporary) ?? new FileStream(temporary,
            FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Protected queue storage requires Windows.");
        _protection.PrepareParent(create: false);
        return _confirmationStreamFactory?.Invoke(temporary) ?? new FileInfo(temporary).Create(FileMode.CreateNew,
            FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.Asynchronous, _protection.FileSecurity());
    }

    private void VerifyQueueHandle(FileStream stream, string expected)
    {
        if (_protection is null) return;
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Protected queue storage requires Windows.");
        _protection.Verify(stream.GetAccessControl(), directory: false);
        if (!TemporaryNative.IsRegularSingleLinkAtPath(stream.SafeFileHandle, expected)) throw QueueStorageProtection.Rejected();
    }

    private void VerifyConfirmationBoundary(string temporary)
    {
        if (_protection is null) return;
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Protected queue storage requires Windows.");
        using var live = OpenQueueRead(); // Recheck a drifted descriptor before replacing data.
        QueueStorageProtection.RejectLeaf(File.GetAttributes(temporary), directory: false);
        using var staged = new FileStream(temporary, FileMode.Open, FileAccess.Read, FileShare.Read);
        VerifyQueueHandle(staged, temporary);
    }
}
