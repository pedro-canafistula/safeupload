namespace SafeUpload.Agent.Drive;

/// <summary>Plain text log, one line per event, safe to call from any thread.</summary>
internal static class DriveLog
{
    private static readonly object Gate = new();
    private static string? _path;

    public static void Open(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        _path = path;
    }

    public static void Write(string message)
    {
        var line = $"{DateTime.Now:HH:mm:ss.fff} {message}";
        lock (Gate)
        {
            Console.WriteLine(line);
            if (_path is not null)
                File.AppendAllText(_path, line + Environment.NewLine);
        }
    }
}
