using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Network.Diversion;

/// <summary>
/// Impede os navegadores de sair direto para a internet pelas portas web,
/// por filtros da Windows Filtering Platform (Fase 3 do plano).
///
/// As políticas (<see cref="BrowserProxyPolicies"/>) mandam o navegador usar o
/// proxy. Este filtro garante que ele não tenha alternativa: conexões dos
/// executáveis de navegador para as portas 80 e 443, em TCP ou UDP, são
/// bloqueadas no Windows. A conexão do navegador com o proxy (127.0.0.1:8877)
/// não usa essas portas e passa; a saída do proxy para o site é do processo
/// do serviço, não do navegador, e também passa. O efeito:
///
/// - navegador seguindo a política: funciona, pelo proxy;
/// - navegador com o proxy desligado (extensão, linha de comando): fica sem
///   conexão, em vez de escapar da inspeção;
/// - QUIC (HTTP/3 em UDP 443) bloqueado: o navegador volta para TCP. Cobre o
///   Firefox, que não tem política para desligar o QUIC.
///
/// Os filtros são criados numa sessão dinâmica: o Windows os apaga sozinho
/// quando a sessão fecha, inclusive se o serviço travar ou for morto. Um
/// serviço fora do ar nunca deixa os navegadores bloqueados.
///
/// Só a API de filtros, em modo usuário, sem driver (ver o plano).
/// </summary>
public sealed class BrowserEgressFilter : IDisposable
{
    /// <summary>Executáveis de navegador conhecidos, nos caminhos de instalação padrão.</summary>
    public static IReadOnlyList<string> DefaultBrowserPaths { get; } =
    [
        @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        @"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        @"C:\Program Files\Google\Chrome\Application\chrome.exe",
        @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        @"C:\Program Files\Mozilla Firefox\firefox.exe",
        @"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
    ];

    private static readonly Guid SubLayerKey = new("2f3b7a5e-6d1c-4f8e-9a0b-5c4d3e2f1a10");

    private IntPtr _engine;

    private BrowserEgressFilter(IntPtr engine, IReadOnlyList<string> blockedApplications)
    {
        _engine = engine;
        BlockedApplications = blockedApplications;
    }

    /// <summary>Executáveis efetivamente cobertos pelos filtros.</summary>
    public IReadOnlyList<string> BlockedApplications { get; }

    /// <summary>
    /// Cria os filtros para os navegadores instalados. Exige administrador ou
    /// SYSTEM. Os filtros valem enquanto o objeto não for descartado.
    /// </summary>
    public static BrowserEgressFilter Install() => Install(DefaultBrowserPaths);

    /// <summary>Cria os filtros para executáveis específicos. Os que não existem são ignorados.</summary>
    public static BrowserEgressFilter Install(IEnumerable<string> applicationPaths)
    {
        string[] present = applicationPaths.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        var session = new WfpNative.Session { Flags = WfpNative.SessionFlagDynamic };
        Check(WfpNative.FwpmEngineOpen0(null, WfpNative.RpcAuthnDefault, IntPtr.Zero, ref session, out IntPtr engine), "abrir a WFP");

        var filter = new BrowserEgressFilter(engine, present);

        if (present.Length == 0)
        {
            return filter;
        }

        try
        {
            filter.AddFilters(present);
            return filter;
        }
        catch
        {
            filter.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_engine != IntPtr.Zero)
        {
            // Fechar a sessão dinâmica apaga a subcamada e os filtros.
            WfpNative.FwpmEngineClose0(_engine);
            _engine = IntPtr.Zero;
        }
    }

    private void AddFilters(string[] applications)
    {
        // Tudo numa transação: ou entram todos os filtros, ou nenhum.
        Check(WfpNative.FwpmTransactionBegin0(_engine, 0), "iniciar a transação");

        var allocations = new List<IntPtr>();
        var appIds = new List<IntPtr>();

        try
        {
            IntPtr name = Track(allocations, Marshal.StringToHGlobalUni("SafeUpload - inspeção web"));

            var subLayer = new WfpNative.SubLayer
            {
                SubLayerKey = SubLayerKey,
                DisplayData = new WfpNative.DisplayData { Name = name },
                Weight = 0x8000,
            };
            Check(WfpNative.FwpmSubLayerAdd0(_engine, ref subLayer, IntPtr.Zero), "criar a subcamada");

            // Condições do mesmo campo valem como OU; de campos diferentes, como E:
            // (navegador A OU B...) E (porta 80 OU 443) E (TCP OU UDP).
            var conditions = new List<WfpNative.FilterCondition>();

            foreach (string application in applications)
            {
                Check(WfpNative.FwpmGetAppIdFromFileName0(application, out IntPtr appId), $"identificar {application}");
                appIds.Add(appId);
                conditions.Add(Condition(WfpNative.ConditionAleAppId, WfpNative.DataByteBlob, (ulong)appId));
            }

            conditions.Add(Condition(WfpNative.ConditionIpRemotePort, WfpNative.DataUInt16, 80));
            conditions.Add(Condition(WfpNative.ConditionIpRemotePort, WfpNative.DataUInt16, 443));
            conditions.Add(Condition(WfpNative.ConditionIpProtocol, WfpNative.DataUInt8, WfpNative.ProtocolTcp));
            conditions.Add(Condition(WfpNative.ConditionIpProtocol, WfpNative.DataUInt8, WfpNative.ProtocolUdp));

            int conditionSize = Marshal.SizeOf<WfpNative.FilterCondition>();
            IntPtr conditionArray = Track(allocations, Marshal.AllocHGlobal(conditionSize * conditions.Count));

            for (int i = 0; i < conditions.Count; i++)
            {
                Marshal.StructureToPtr(conditions[i], conditionArray + (i * conditionSize), fDeleteOld: false);
            }

            foreach (Guid layer in new[] { WfpNative.LayerAleAuthConnectV4, WfpNative.LayerAleAuthConnectV6 })
            {
                var filter = new WfpNative.Filter
                {
                    FilterKey = Guid.NewGuid(),
                    DisplayData = new WfpNative.DisplayData { Name = name },
                    LayerKey = layer,
                    SubLayerKey = SubLayerKey,
                    Weight = new WfpNative.Value { Type = WfpNative.DataEmpty },
                    NumFilterConditions = (uint)conditions.Count,
                    FilterCondition = conditionArray,
                    Action = new WfpNative.Action { Type = WfpNative.ActionBlock },
                };

                Check(WfpNative.FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out _), "criar o filtro");
            }

            Check(WfpNative.FwpmTransactionCommit0(_engine), "confirmar a transação");
        }
        catch
        {
            WfpNative.FwpmTransactionAbort0(_engine);
            throw;
        }
        finally
        {
            for (int i = 0; i < appIds.Count; i++)
            {
                IntPtr appId = appIds[i];
                WfpNative.FwpmFreeMemory0(ref appId);
            }

            foreach (IntPtr allocation in allocations)
            {
                Marshal.FreeHGlobal(allocation);
            }
        }
    }

    private static WfpNative.FilterCondition Condition(Guid field, uint type, ulong value) => new()
    {
        FieldKey = field,
        MatchType = WfpNative.MatchEqual,
        ConditionValue = new WfpNative.Value { Type = type, Data = value },
    };

    private static IntPtr Track(List<IntPtr> allocations, IntPtr pointer)
    {
        allocations.Add(pointer);
        return pointer;
    }

    private static void Check(uint result, string step)
    {
        if (result != 0)
        {
            throw new Win32Exception(unchecked((int)result), $"WFP: falha ao {step} (0x{result:X8}).");
        }
    }
}
