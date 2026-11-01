namespace SafeUpload.Agent.Drive;

/// <summary>One line per drive event; the host decides where lines go (the agent sends them to its logger).</summary>
public static class DriveLog
{
    public static Action<string>? Sink { get; set; }

    public static void Write(string message) => Sink?.Invoke(message);
}
