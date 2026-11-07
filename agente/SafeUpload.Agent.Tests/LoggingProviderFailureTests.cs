using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SafeUpload.Agent.Service;

namespace SafeUpload.Agent.Tests;

public sealed class LoggingProviderFailureTests
{
    [Theory]
    [InlineData("write")]
    [InlineData("enabled")]
    [InlineData("scope")]
    [InlineData("scope-dispose")]
    public void Falha_do_destino_de_log_nao_interrompe_operacao_e_proxima_tentativa_recupera(string failure)
    {
        var broken = new Sink { Failure = failure };
        var healthy = new Sink();
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddProvider(broken).AddProvider(healthy));
        Program.ConfigureOperationalLogging(services);
        using var provider = services.BuildServiceProvider();
        var logger = provider.GetRequiredService<ILogger<LoggingProviderFailureTests>>();

        var completed = false;
        var error = Record.Exception(() =>
        {
            _ = logger.IsEnabled(LogLevel.Information);
            using (logger.BeginScope("synthetic scope"))
                logger.LogInformation(new EventId(123), "Synthetic {Value}", "record");
            completed = true;
        });
        Assert.Null(error);
        Assert.True(completed);

        broken.Failure = null;
        Assert.True(logger.IsEnabled(LogLevel.Information));
        using (logger.BeginScope("recovered scope"))
            logger.LogInformation(new EventId(456), "Recovered {Value}", "record");
        Assert.Contains(broken.Records, record => record == (456, "Recovered record"));
        Assert.Contains(healthy.Records, record => record == (456, "Recovered record"));
        if (failure == "write") Assert.Contains(healthy.Records, record => record == (123, "Synthetic record"));
    }

    [Fact]
    public void Excecao_da_operacao_continua_visivel_com_logger_configurado()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddProvider(new Sink { Failure = "write" }));
        Program.ConfigureOperationalLogging(services);
        using var provider = services.BuildServiceProvider();
        var logger = provider.GetRequiredService<ILogger<LoggingProviderFailureTests>>();
        var error = new InvalidOperationException("synthetic operation failure");
        var observed = Record.Exception((Action)(() =>
        {
            logger.LogWarning("Synthetic warning");
            throw error;
        }));
        Assert.Same(error, observed);
    }

    private sealed class Sink : ILoggerProvider, ILogger
    {
        public string? Failure;
        public List<(int, string)> Records { get; } = [];
        public ILogger CreateLogger(string categoryName) => this;
        public void Dispose() { }
        public bool IsEnabled(LogLevel logLevel)
        {
            Fail("enabled");
            return true;
        }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            Fail("scope");
            return new Scope(this);
        }
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Fail("write");
            Records.Add((eventId.Id, formatter(state, exception)));
        }
        private void Fail(string stage)
        {
            if (Failure == stage) throw new InvalidOperationException("synthetic unavailable log sink");
        }
        private sealed class Scope(Sink sink) : IDisposable
        {
            public void Dispose() => sink.Fail("scope-dispose");
        }
    }
}
