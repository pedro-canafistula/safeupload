using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Guarda a última política carregada por um intervalo, na frente de qualquer
/// <see cref="IPolicyStore"/>.
///
/// <para><b>Por que existe.</b> O <see cref="HttpPolicyStore"/> faz uma chamada
/// HTTP a cada carga e não tem cache. Com o painel fora do ar, cada chamada
/// espera o prazo do cliente HTTP antes de cair no padrão embutido; o canal web
/// mediu 2 s por chamada nessa situação. Um canal que decide no caminho do
/// usuário, como a colagem (prazo de 500 ms), não pode pagar isso a cada
/// pedido. O canal web resolveu o mesmo problema com um cache próprio de 30 s;
/// este é o mesmo cache, separado, para quem precisar.</para>
///
/// <para><b>O que fica guardado.</b> Só uma política carregada com sucesso.
/// Exceção não é guardada: a próxima carga tenta de novo. O
/// <see cref="HttpPolicyStore"/> não lança quando o painel cai, devolve o
/// padrão embutido, e esse padrão é guardado como qualquer política: é o que
/// evita esperar o prazo do HTTP em todo pedido.</para>
///
/// <para><b>O custo.</b> Uma mudança na política leva até
/// <see cref="Lifetime"/> para valer.</para>
///
/// <para>Uma carga por vez: pedidos simultâneos com o cache vencido esperam a
/// mesma carga, em vez de cada um ir ao painel.</para>
/// </summary>
public sealed class CachedPolicyStore : IPolicyStore
{
    private readonly IPolicyStore _inner;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _gate = new(1, 1);

    // Política e vencimento num registro só, trocado de uma vez: um leitor
    // nunca vê a política nova com o vencimento antigo, nem o contrário.
    private Entry? _entry;

    /// <summary>Compõe o cache.</summary>
    /// <param name="inner">De onde a política vem de verdade.</param>
    /// <param name="lifetime">Quanto tempo uma política carregada vale.</param>
    /// <param name="clock">Relógio; só os testes usam outro.</param>
    public CachedPolicyStore(IPolicyStore inner, TimeSpan lifetime, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);

        _inner = inner;
        Lifetime = lifetime;
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>Quanto tempo uma política carregada vale.</summary>
    public TimeSpan Lifetime { get; }

    /// <inheritdoc />
    public async Task<Policy> LoadAsync(CancellationToken cancellationToken)
    {
        if (Fresh() is { } cached)
        {
            return cached;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            // Outro pedido pode ter carregado enquanto este esperava.
            if (Fresh() is { } loaded)
            {
                return loaded;
            }

            var policy = await _inner.LoadAsync(cancellationToken).ConfigureAwait(false);

            Volatile.Write(ref _entry, new Entry(policy, _clock.GetUtcNow() + Lifetime));

            return policy;
        }
        finally
        {
            _gate.Release();
        }
    }

    private Policy? Fresh()
    {
        var entry = Volatile.Read(ref _entry);
        return entry is not null && _clock.GetUtcNow() < entry.ExpiresAt ? entry.Policy : null;
    }

    private sealed record Entry(Policy Policy, DateTimeOffset ExpiresAt);
}
