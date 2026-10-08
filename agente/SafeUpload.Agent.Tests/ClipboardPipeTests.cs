using System.IO.Pipes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Clipboard;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O canal de clipboard por um named pipe de verdade: o que o aplicativo e o
/// serviço trocam, e o que acontece quando um dos lados não se comporta.
/// </summary>
public class ClipboardPipeTests
{
    private const string CpfValido = "529.982.247-25";

    private sealed class FixedPolicyStore(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken cancellationToken) => Task.FromResult(policy);
    }

    private static Policy Politica() =>
        new(
            Version: 1,
            ActiveCategories: Enum.GetValues<Category>().ToHashSet(),
            MonitoredScopes: new MonitoredScopes(
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".txt" },
                [],
                RemovableDrives: true,
                NetworkPaths: true),
            MaxFileSizeMb: 20,
            InspectionTimeoutSeconds: 5,
            FailOpen: true,
            ExcludedProcesses: new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            Clipboard: new ClipboardPolicy(
                ClipboardMode.Audit,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "chrome" },
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                ClipboardPolicy.DefaultMaxTextLength,
                OversizedTextIsDirty: true));

    /// <summary>Guarda o que o servidor do pipe registrou como erro.</summary>
    private sealed class ErrorLog<T> : ILogger<T>
    {
        public List<string> Errors { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= LogLevel.Error)
            {
                lock (Errors)
                {
                    Errors.Add(formatter(state, exception));
                }
            }
        }
    }

    /// <summary>Sobe um servidor num pipe de nome único e o derruba no fim.</summary>
    private sealed class Server : IAsyncDisposable
    {
        private readonly ClipboardPipeServer _server;

        public Server(string? pipeName = null, TimeSpan? retryDelay = null)
        {
            PipeName = pipeName ?? "SafeUpload.Test.Clipboard." + Guid.NewGuid().ToString("N");
            Service = new ClipboardService(
                new FixedPolicyStore(Politica()),
                new ClipboardCopyStore(),
                new ClipboardMetrics(),
                NullLogger<ClipboardService>.Instance);
            _server = new ClipboardPipeServer(Service, Log, PipeName, retryDelay);
        }

        public string PipeName { get; }

        public ClipboardService Service { get; }

        public ErrorLog<ClipboardPipeServer> Log { get; } = new();

        /// <summary>A tarefa do servidor: se ela terminar enquanto o serviço roda, o host cairia.</summary>
        public Task? ExecuteTask => _server.ExecuteTask;

        public Task StartAsync() => _server.StartAsync(CancellationToken.None);

        public async ValueTask DisposeAsync()
        {
            await _server.StopAsync(CancellationToken.None);
            _server.Dispose();
        }

        /// <summary>Uma conexão: escreve a linha e lê a resposta, se vier.</summary>
        public async Task<ClipboardResponse?> PerguntarAsync(string linha)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(cts.Token);

            await using (var writer = new StreamWriter(pipe, ClipboardProtocol.Encoding, 1024, leaveOpen: true))
            {
                await writer.WriteAsync(linha.AsMemory(), cts.Token);
                await writer.FlushAsync(cts.Token);
            }

            using var reader = new StreamReader(pipe, ClipboardProtocol.Encoding, false, 4096, leaveOpen: true);
            var resposta = await ClipboardProtocol.ReadLineAsync(reader, cts.Token);
            return ClipboardProtocol.DeserializeResponse(resposta);
        }
    }

    [Fact]
    public async Task Classifica_e_depois_responde_a_sonda_de_foco_pelo_pipe()
    {
        await using var server = new Server();
        await server.StartAsync();

        var copia = await server.PerguntarAsync(
            ClipboardProtocol.Serialize(ClipboardRequest.Classify("CPF " + CpfValido, "notepad")) + "\n");

        Assert.NotNull(copia);
        Assert.True(copia.Dirty);
        Assert.NotNull(copia.CopyId);

        var foco = await server.PerguntarAsync(
            ClipboardProtocol.Serialize(ClipboardRequest.Paste(copia.CopyId, "chrome")) + "\n");

        Assert.NotNull(foco);
        Assert.Equal(ClipboardPasteVerdict.AuditOnly, foco.Verdict);
        Assert.Equal(1, server.Service.Metrics.FocusOnEgressWhileDirty);
    }

    [Fact]
    public async Task Falha_ao_criar_o_pipe_nao_derruba_o_servidor_e_ele_se_recupera()
    {
        var pipeName = "SafeUpload.Test.Clipboard." + Guid.NewGuid().ToString("N");

        // Ocupa o nome com uma instância só: criar outra com o mesmo nome falha.
        var ocupante = new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

        await using var server = new Server(pipeName, retryDelay: TimeSpan.FromMilliseconds(50));
        await server.StartAsync();

        // Várias tentativas falham. Se a exceção saísse do servidor, a tarefa
        // terminaria com falha, e num serviço de verdade o host cairia junto.
        await Task.Delay(400);

        Assert.False(
            server.ExecuteTask!.IsCompleted,
            "O servidor terminou (a exceção da criação do pipe saiu dele).");
        lock (server.Log.Errors)
        {
            Assert.NotEmpty(server.Log.Errors);
        }

        // Liberado o nome, o servidor se recupera sozinho e passa a atender.
        ocupante.Dispose();

        var resposta = await server.PerguntarAsync(
            ClipboardProtocol.Serialize(ClipboardRequest.Classify("CPF " + CpfValido, "notepad")) + "\n");

        Assert.NotNull(resposta);
        Assert.True(resposta.Dirty);
    }

    [Fact]
    public async Task Atende_varias_conexoes_seguidas()
    {
        await using var server = new Server();
        await server.StartAsync();

        for (var i = 0; i < 20; i++)
        {
            var resposta = await server.PerguntarAsync(
                ClipboardProtocol.Serialize(ClipboardRequest.Classify("texto " + i, "notepad")) + "\n");

            Assert.NotNull(resposta);
            Assert.False(resposta.Dirty);
        }

        Assert.Equal(20, server.Service.Metrics.Copies);
    }

    [Fact]
    public async Task Linha_malformada_fecha_sem_responder_e_o_servidor_segue_de_pe()
    {
        await using var server = new Server();
        await server.StartAsync();

        var resposta = await server.PerguntarAsync("isto nao e json\n");
        Assert.Null(resposta);

        var depois = await server.PerguntarAsync(
            ClipboardProtocol.Serialize(ClipboardRequest.Classify("CPF " + CpfValido, "notepad")) + "\n");
        Assert.NotNull(depois);
        Assert.True(depois.Dirty);
    }

    [Fact]
    public async Task Linha_acima_do_teto_e_descartada_sem_resposta()
    {
        await using var server = new Server();
        await server.StartAsync();

        var enorme = new string('a', ClipboardProtocol.MaxLineLength + 10_000);

        var resposta = await server.PerguntarAsync(enorme + "\n");

        Assert.Null(resposta);
        Assert.Equal(0, server.Service.Metrics.Copies);
    }

    [Fact]
    public async Task Pedido_de_tipo_desconhecido_fecha_sem_responder()
    {
        await using var server = new Server();
        await server.StartAsync();

        var resposta = await server.PerguntarAsync("{\"type\":\"formatar-disco\"}\n");

        Assert.Null(resposta);
    }

    // ---------------------------------------------------------- leitura de linha

    [Fact]
    public async Task Leitura_de_linha_para_na_quebra_e_tira_o_retorno_de_carro()
    {
        using var reader = new StringReader("primeira\r\nsegunda\n");

        var linha = await ClipboardProtocol.ReadLineAsync(reader, CancellationToken.None);

        Assert.Equal("primeira", linha);
    }

    [Fact]
    public async Task Leitura_de_linha_sem_quebra_vale_o_que_chegou()
    {
        using var reader = new StringReader("sem quebra");

        Assert.Equal("sem quebra", await ClipboardProtocol.ReadLineAsync(reader, CancellationToken.None));
    }

    [Fact]
    public async Task Leitura_de_linha_vazia_devolve_nulo()
    {
        using var reader = new StringReader(string.Empty);

        Assert.Null(await ClipboardProtocol.ReadLineAsync(reader, CancellationToken.None));
    }

    [Fact]
    public async Task Leitura_de_linha_acima_do_teto_devolve_nulo_mesmo_com_a_quebra_no_fim()
    {
        using var reader = new StringReader(new string('a', ClipboardProtocol.MaxLineLength + 1) + "\n");

        Assert.Null(await ClipboardProtocol.ReadLineAsync(reader, CancellationToken.None));
    }

    [Fact]
    public async Task Leitura_de_linha_no_teto_exato_passa()
    {
        using var reader = new StringReader(new string('a', ClipboardProtocol.MaxLineLength) + "\n");

        var linha = await ClipboardProtocol.ReadLineAsync(reader, CancellationToken.None);

        Assert.Equal(ClipboardProtocol.MaxLineLength, linha!.Length);
    }
}
