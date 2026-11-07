using System.Globalization;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Service.Dispatch;

/// <summary>
/// Com qual servidor o serviço fala. A resposta vem só da identidade gravada pelo comando "cadastrar"
/// (docs/console-agente.md): sem identidade, o agente protege sozinho com o policy.json local.
/// Do appsettings só vêm os prazos (CentroAdministracao:TimeoutSeconds e DispatchIntervalSeconds).
/// </summary>
internal sealed record AdministrationConfiguration(SignedAgentIdentity? Identity, TimeSpan Timeout,
    TimeSpan DispatchInterval, string? Problem = null)
{
    public Uri? BaseUri => Identity?.Server;

    internal static AdministrationConfiguration Parse(IConfiguration configuration, Func<SignedAgentIdentity?> loadIdentity)
    {
        var timeout = ReadPositiveSeconds(configuration, "TimeoutSeconds", 5);
        var interval = ReadPositiveSeconds(configuration, "DispatchIntervalSeconds", 30);
        if (timeout.TotalMilliseconds > int.MaxValue)
            throw new InvalidOperationException("CentroAdministracao:TimeoutSeconds excede o limite do cliente HTTP.");
        if (interval.TotalMilliseconds > uint.MaxValue - 1)
            throw new InvalidOperationException("CentroAdministracao:DispatchIntervalSeconds excede o limite do temporizador.");
        try
        {
            var identity = loadIdentity();
            if (identity is null)
                return new(null, timeout, interval,
                    string.IsNullOrWhiteSpace(configuration["CentroAdministracao:BaseUrl"]) ? null
                        : "CentroAdministracao:BaseUrl é ignorada: cadastre a máquina com \"SafeUpload.Agent.Service.exe cadastrar\".");
            AgentHttp.ServerUri(identity.Server.AbsoluteUri);
            return new(identity, timeout, interval);
        }
        catch (Exception error) when (error is AgentIdentityException or ArgumentException)
        {
            // A proteção local continua; o problema aparece no log do serviço.
            return new(null, timeout, interval, "Cadastro no servidor inutilizável; protegendo só com o policy.json local. " +
                error.Message);
        }
    }

    private static TimeSpan ReadPositiveSeconds(IConfiguration configuration, string name, int fallback)
    {
        string? value = configuration["CentroAdministracao:" + name];
        if (string.IsNullOrWhiteSpace(value)) return TimeSpan.FromSeconds(fallback);
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int seconds) || seconds <= 0)
            throw new InvalidOperationException("CentroAdministracao:" + name + " precisa ser um número inteiro positivo.");
        return TimeSpan.FromSeconds(seconds);
    }
}
