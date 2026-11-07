namespace SafeUpload.Agent.Service.Diagnostics;

/// <summary>A falha de um destino de log não pode encerrar a proteção. Cada chamada volta a tentar.</summary>
internal sealed class BestEffortLogger<T>(ILoggerFactory factory) : ILogger<T>
{
    private readonly ILogger _inner = factory.CreateLogger<T>();

    public bool IsEnabled(LogLevel logLevel)
    {
        try { return _inner.IsEnabled(logLevel); }
        catch (Exception) { return false; }
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        try { return _inner.BeginScope(state) is { } scope ? new BestEffortScope(scope) : null; }
        catch (Exception) { return null; }
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        try { _inner.Log(logLevel, eventId, state, exception, formatter); }
        catch (Exception) { /* Other configured providers still receive the record through LoggerFactory. */ }
    }

    private sealed class BestEffortScope(IDisposable inner) : IDisposable
    {
        public void Dispose()
        {
            try { inner.Dispose(); }
            catch (Exception) { }
        }
    }
}
