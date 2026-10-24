using System.Buffers.Binary;
using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class M2DiagnosticClientTests
{
    [Fact]
    public void Perfil_M2_preserva_layouts_legados_e_offsets_nativos()
    {
        M2DiagnosticContract.Verify(); DiagnosticsContract.Verify();
        Assert.Equal(120, Marshal.SizeOf<SafeUploadDiagCounters>());
        Assert.Equal(288, Marshal.SizeOf<SafeUploadWriterStateStatus>());
        Assert.Equal(296, Marshal.SizeOf<M2DiagnosticCounters>());
        Assert.Equal(176, Marshal.SizeOf<M2StageLifetimeCounters>());
        Assert.Equal(304, Marshal.SizeOf<M2WriterStateStatus>());
        Assert.Equal(120, Marshal.OffsetOf<M2DiagnosticCounters>(nameof(M2DiagnosticCounters.Stage)).ToInt32());
        Assert.Equal(288, Marshal.OffsetOf<M2WriterStateStatus>(nameof(M2WriterStateStatus.WriterGlobalFirstUnknown)).ToInt32());
        Assert.Equal(292, Marshal.OffsetOf<M2WriterStateStatus>(nameof(M2WriterStateStatus.WriterEntryFirstUnknown)).ToInt32());
        Assert.Equal(296, Marshal.OffsetOf<M2WriterStateStatus>(nameof(M2WriterStateStatus.WriterSopFirstUnknown)).ToInt32());
        Assert.Equal(300, Marshal.OffsetOf<M2WriterStateStatus>(nameof(M2WriterStateStatus.WriterSopUnknownCount)).ToInt32());
    }

    [Fact]
    public void Contadores_M2_usam_capacidades_exatas_e_preservam_prefixos_e_caudas()
    {
        var transport = new Fake();
        var snapshot = new M2DiagnosticClient(transport).ReadCounters();
        Assert.Equal(new[] { M2DiagnosticQuery.Counters, M2DiagnosticQuery.WriterState }, transport.Calls.Select(c => c.Query));
        Assert.Equal(new[] { 296, 304 }, transport.Calls.Select(c => c.Bytes));
        Assert.Equal(296u, snapshot.Counters.Prefix.StructSize);
        Assert.Equal(0x1122334455667788ul, snapshot.Counters.Prefix.DenyRecorded);
        Assert.Equal(1u, snapshot.Counters.Stage.LiveVersions);
        Assert.Equal(4u, snapshot.Counters.Stage.WaitingVersions);
        Assert.Equal(100ul, snapshot.Counters.Stage.VersionsCreated);
        Assert.Equal(119ul, snapshot.Counters.Stage.StageDeleteFailures);
        Assert.Equal(304u, snapshot.WriterState.Prefix.StructSize);
        Assert.Equal(7u, snapshot.WriterState.Prefix.SectionInFlightNow); // Not protocol version.
        Assert.Equal(111u, snapshot.WriterState.WriterGlobalFirstUnknown);
        Assert.Equal(222u, snapshot.WriterState.WriterEntryFirstUnknown);
        Assert.Equal(333u, snapshot.WriterState.WriterSopFirstUnknown);
        Assert.Equal(444u, snapshot.WriterState.WriterSopUnknownCount);
    }

    [Fact]
    public void Stage_streams_usa_transporte_e_decodificador_validado()
    {
        var transport = new Fake();
        var snapshot = new M2DiagnosticClient(transport).ReadStageStreams();
        Assert.Equal(M2DiagnosticQuery.StageStreams, Assert.Single(transport.Calls).Query);
        Assert.Equal(2576, transport.Calls[0].Bytes);
        Assert.Equal("abc", Assert.Single(snapshot.Records).Name);
        Assert.True(snapshot.Truncated); Assert.Equal(2u, snapshot.Total);
    }

    [Theory]
    [InlineData(-1)] [InlineData(0)] [InlineData(295)] [InlineData(297)]
    public void Bytes_retornados_divergentes_nao_viram_contadores(int returned)
    {
        var transport = new Fake { ReturnedOverride = returned };
        Assert.Throws<InvalidDataException>(() => new M2DiagnosticClient(transport).ReadCounters());
        Assert.Single(transport.Calls);
    }

    [Theory]
    [InlineData(303)] [InlineData(305)]
    public void Falha_na_segunda_resposta_nao_publica_snapshot_parcial_nem_tenta_perfil_legado(int returned)
    {
        var transport = new Fake { BadQuery = M2DiagnosticQuery.WriterState, ReturnedOverride = returned };
        Assert.Throws<InvalidDataException>(() => new M2DiagnosticClient(transport).ReadCounters());
        Assert.Equal(new[] { 296, 304 }, transport.Calls.Select(c => c.Bytes));
    }

    [Theory]
    [InlineData(0u)] [InlineData(120u)] [InlineData(295u)] [InlineData(297u)]
    public void Tamanho_declarado_do_perfil_errado_e_recusado(uint size)
    {
        var transport = new Fake { DeclaredSizeOverride = size };
        Assert.Throws<InvalidDataException>(() => new M2DiagnosticClient(transport).ReadCounters());
        Assert.Single(transport.Calls);
    }

    [Theory]
    [InlineData(0u)] [InlineData(17u)] [InlineData(19u)]
    public void Versao_desconhecida_e_recusada_sem_fallback(uint version)
    {
        var transport = new Fake { VersionOverride = version };
        Assert.Throws<InvalidDataException>(() => new M2DiagnosticClient(transport).ReadCounters());
        Assert.Single(transport.Calls);
    }

    [Fact]
    public void Writer_state_legado_nao_e_aceito_como_M2()
    {
        var transport = new Fake { BadQuery = M2DiagnosticQuery.WriterState, DeclaredSizeOverride = 288 };
        Assert.Throws<InvalidDataException>(() => new M2DiagnosticClient(transport).ReadCounters());
        Assert.Equal(2, transport.Calls.Count);
    }

    [Theory]
    [InlineData(2575)] [InlineData(2577)]
    public void Stage_streams_recusa_comprimento_retornado_divergente(int returned)
    {
        var transport = new Fake { BadQuery = M2DiagnosticQuery.StageStreams, ReturnedOverride = returned };
        Assert.Throws<InvalidDataException>(() => new M2DiagnosticClient(transport).ReadStageStreams());
        Assert.Single(transport.Calls);
    }

    [Fact]
    public void Driver_que_recusa_comando_nao_e_tratado_como_snapshot_vazio()
    {
        var error = new Win32Exception(unchecked((int)0x80070032), "unsupported synthetic query");
        var transport = new Fake { Error = error };
        Assert.Same(error, Assert.Throws<Win32Exception>(() => new M2DiagnosticClient(transport).ReadCounters()));
        Assert.Single(transport.Calls);
        Assert.Throws<ArgumentNullException>(() => new M2DiagnosticClient(null!));
    }

    [Theory]
    [InlineData(0u)] [InlineData(1u)] [InlineData(3u)] [InlineData(999u)]
    public void Adaptador_nativo_recusa_comandos_fora_da_lista_de_leitura_antes_de_PInvoke(uint command)
    {
        using var port = UnconnectedPort();
        Assert.Throws<ArgumentOutOfRangeException>(() => ((IM2DiagnosticTransport)port).Query((M2DiagnosticQuery)command, new byte[296]));
    }

    [Theory]
    [InlineData(12u, 288)] [InlineData(28u, 120)] [InlineData(29u, 2575)]
    public void Adaptador_nativo_recusa_capacidade_errada_antes_de_PInvoke(uint command, int bytes)
    {
        using var port = UnconnectedPort();
        Assert.Throws<ArgumentException>(() => ((IM2DiagnosticTransport)port).Query((M2DiagnosticQuery)command, new byte[bytes]));
    }

    [Fact]
    public void Fabrica_nao_conecta_e_porta_descartada_recusa_novo_envio()
    {
        var port = UnconnectedPort();
        Assert.NotNull(port.CreateM2DiagnosticClient()); // No transport is invoked.
        port.Dispose();
        Assert.Throws<ObjectDisposedException>(() => ((IM2DiagnosticTransport)port).Query(M2DiagnosticQuery.Counters, new byte[296]));
    }

    // Test-only construction: invalid, non-owning handle. Every adapter case is
    // rejected before native I/O; no driver is connected and no test hook is shipped.
    private static FilterPort UnconnectedPort() => (FilterPort)typeof(FilterPort)
        .GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null,
            [typeof(SafeFileHandle), typeof(string)], null)!
        .Invoke([new SafeFileHandle(IntPtr.Zero, ownsHandle: false), "synthetic-not-connected"]);

    private sealed class Fake : IM2DiagnosticTransport
    {
        public List<(M2DiagnosticQuery Query, int Bytes)> Calls { get; } = [];
        public M2DiagnosticQuery BadQuery { get; init; } = M2DiagnosticQuery.Counters;
        public int? ReturnedOverride { get; init; }
        public uint? DeclaredSizeOverride { get; init; }
        public uint? VersionOverride { get; init; }
        public Exception? Error { get; init; }
        public int Query(M2DiagnosticQuery query, Span<byte> response)
        {
            Calls.Add((query, response.Length));
            if (Error is not null) throw Error;
            response.Clear(); U32(response, 0, (uint)response.Length);
            if (query == M2DiagnosticQuery.WriterState)
            {
                U32(response, 4, 7); U32(response, 288, 111); U32(response, 292, 222);
                U32(response, 296, 333); U32(response, 300, 444);
            }
            else
            {
                U32(response, 4, 18);
                if (query == M2DiagnosticQuery.Counters)
                {
                    BinaryPrimitives.WriteUInt64LittleEndian(response[8..], 0x1122334455667788);
                    for (int i = 0; i < 4; i++) U32(response, 120 + i * 4, (uint)i + 1);
                    for (int i = 0; i < 20; i++) BinaryPrimitives.WriteUInt64LittleEndian(response[(136 + i * 8)..], (ulong)i + 100);
                }
                else
                {
                    U32(response, 8, 1); U32(response, 12, 2); U32(response, 16 + 56, 3);
                    for (int i = 0; i < 3; i++) BinaryPrimitives.WriteUInt16LittleEndian(response[(16 + 64 + i * 2)..], (ushort)('a' + i));
                }
            }
            if (query == BadQuery)
            {
                if (DeclaredSizeOverride is { } size) U32(response, 0, size);
                if (VersionOverride is { } version) U32(response, 4, version);
                if (ReturnedOverride is { } returned) return returned;
            }
            return response.Length;
        }
        private static void U32(Span<byte> bytes, int offset, uint value) =>
            BinaryPrimitives.WriteUInt32LittleEndian(bytes[offset..], value);
    }
}
