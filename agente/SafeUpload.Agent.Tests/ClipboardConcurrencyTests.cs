using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class ClipboardConcurrencyTests
{
    private static Policy Policy() => LocalPolicyStore.CreateDefault() with
    {
        ActiveCategories = new HashSet<Category> { Category.Cpf },
        Clipboard = new ClipboardPolicy(ClipboardMode.Block,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "chrome" },
            new HashSet<string>(), 1000, true)
    };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Classificacao_antiga_terminando_depois_nao_substitui_copia_mais_recente(bool latestDirty)
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<Policy>(TaskCreationOptions.RunContinuationsAsynchronously);
        var reads = 0;
        var copies = new ClipboardCopyStore();
        var service = new ClipboardInspectionService(new DelegatePolicy(_ =>
        {
            if (Interlocked.Increment(ref reads) != 1) return Task.FromResult(Policy());
            started.SetResult();
            return release.Task;
        }), copies, new ClipboardMetrics());

        var old = service.HandleAsync(ClipboardRequest.Classify(Text(!latestDirty), "notepad"), 7, CancellationToken.None);
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var latest = (await service.HandleAsync(ClipboardRequest.Classify(Text(latestDirty), "notepad"),
                7, CancellationToken.None)).Response;
            Assert.Equal(latestDirty, latest.Dirty);
            release.SetResult(Policy());
            var late = (await old.WaitAsync(TimeSpan.FromSeconds(5))).Response;

            var paste = await service.HandleAsync(ClipboardRequest.PasteAttempt(latest.CopyId!, "chrome"),
                7, CancellationToken.None);
            Assert.Equal(latestDirty ? ClipboardPasteVerdict.Block : ClipboardPasteVerdict.Allow, paste.Response.Verdict);
            Assert.NotNull(copies.TryGet(7, latest.CopyId!));
            Assert.Null(copies.TryGet(7, late.CopyId!));
        }
        finally
        {
            release.TrySetResult(Policy());
            await old.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Theory]
    [InlineData("classify", "before")]
    [InlineData("paste", "before")]
    [InlineData("state", "before")]
    [InlineData("classify", "during")]
    [InlineData("paste", "during")]
    [InlineData("state", "during")]
    [InlineData("classify", "failure")]
    [InlineData("paste", "failure")]
    [InlineData("state", "failure")]
    public async Task Pedido_cancelado_nao_substitui_copia_nem_conta_observacao(string type, string timing)
    {
        using var stop = new CancellationTokenSource();
        var interrupt = false;
        var copies = new ClipboardCopyStore();
        var service = new ClipboardInspectionService(new DelegatePolicy(_ =>
        {
            if (interrupt)
            {
                stop.Cancel();
                if (timing == "failure") throw new IOException("synthetic policy failure");
            }
            return Task.FromResult(Policy());
        }), copies, new ClipboardMetrics());
        var current = (await service.HandleAsync(ClipboardRequest.Classify(Text(true), "notepad"),
            7, CancellationToken.None)).Response;
        var before = service.Metrics;
        if (timing == "before") stop.Cancel();
        else interrupt = true;
        var request = type switch
        {
            "classify" => ClipboardRequest.Classify(Text(false), "notepad"),
            "paste" => ClipboardRequest.PasteAttempt(current.CopyId!, "chrome"),
            _ => ClipboardRequest.State()
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.HandleAsync(request, 7, stop.Token));
        Assert.NotNull(copies.TryGet(7, current.CopyId!));
        Assert.Equal(before, service.Metrics);
    }

    [Fact]
    public async Task Classificacao_em_outra_sessao_nao_invalida_resultado_em_voo()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<Policy>(TaskCreationOptions.RunContinuationsAsynchronously);
        var reads = 0;
        var copies = new ClipboardCopyStore();
        var service = new ClipboardInspectionService(new DelegatePolicy(_ =>
        {
            if (Interlocked.Increment(ref reads) != 1) return Task.FromResult(Policy());
            started.SetResult();
            return release.Task;
        }), copies, new ClipboardMetrics());
        var first = service.HandleAsync(ClipboardRequest.Classify(Text(true), "notepad"), 7, CancellationToken.None);
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var second = (await service.HandleAsync(ClipboardRequest.Classify(Text(true), "notepad"),
                8, CancellationToken.None)).Response;
            release.SetResult(Policy());
            var completed = (await first.WaitAsync(TimeSpan.FromSeconds(5))).Response;
            Assert.NotNull(copies.TryGet(7, completed.CopyId!));
            Assert.NotNull(copies.TryGet(8, second.CopyId!));
            Assert.Null(copies.TryGet(7, second.CopyId!));
        }
        finally { release.TrySetResult(Policy()); await first.WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    private static string Text(bool dirty) => dirty ? "Synthetic CPF: 529.982.247-25" : "Synthetic clean text";

    private sealed class DelegatePolicy(Func<CancellationToken, Task<Policy>> load) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken cancellationToken) => load(cancellationToken);
    }
}
