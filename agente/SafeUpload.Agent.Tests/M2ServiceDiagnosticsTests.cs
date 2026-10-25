using System.Buffers.Binary;
using System.ComponentModel;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

public sealed class M2ServiceDiagnosticsTests
{
    [Fact]
    public void Contadores_projetam_prefixos_caudas_e_inteiros_sem_perda_no_JSON()
    {
        var transport = new Fake();
        var data = RoundTrip(DriverDiagnosticsSource.QueryM2Counters(transport));
        Assert.Equal(new[] { M2DiagnosticQuery.Counters, M2DiagnosticQuery.WriterState }, transport.Calls);
        Assert.Equal("m2-e0df8d1c", data["profile"]!.GetValue<string>());
        Assert.False(data["atomic"]!.GetValue<bool>());
        Assert.False(data["compatibilityVerified"]!.GetValue<bool>());
        Assert.False(data["protectionVerified"]!.GetValue<bool>());
        Assert.Equal(ulong.MaxValue, data["snapshot"]!["counters"]!["prefix"]!["denyRecorded"]!.GetValue<ulong>());
        Assert.Equal(123ul, data["snapshot"]!["counters"]!["stage"]!["versionsCreated"]!.GetValue<ulong>());
        Assert.Equal(456ul, data["snapshot"]!["counters"]!["stage"]!["stageDeleteFailures"]!.GetValue<ulong>());
        Assert.Equal(7u, data["snapshot"]!["writerState"]!["prefix"]!["sectionInFlightNow"]!.GetValue<uint>());
        Assert.Equal(uint.MaxValue, data["snapshot"]!["writerState"]!["writerSopUnknownCount"]!.GetValue<uint>());
    }

    [Fact]
    public void Stage_streams_preserva_bits_GUID_geracao_e_WCHAR_inclusive_surrogate_truncado()
    {
        var transport = new Fake();
        var data = RoundTrip(DriverDiagnosticsSource.QueryM2StageStreams(transport));
        Assert.Equal(M2DiagnosticQuery.StageStreams, Assert.Single(transport.Calls));
        Assert.True(data["truncated"]!.GetValue<bool>());
        Assert.Equal(1, data["count"]!.GetValue<int>());
        Assert.Equal(2u, data["total"]!.GetValue<uint>());
        var record = Assert.Single(data["records"]!.AsArray())!;
        Assert.Equal(Fake.TransferId, record["transferId"]!.GetValue<Guid>());
        Assert.Equal(0x80000001u, record["flags"]!.GetValue<uint>());
        Assert.Equal(ulong.MaxValue, record["destinationGeneration"]!.GetValue<ulong>());
        Assert.Equal(new[] { 65, 0, 0xD800 }, record["nameCodeUnits"]!.AsArray().Select(x => x!.GetValue<int>()));
        Assert.False(data["protectionVerified"]!.GetValue<bool>());
    }

    [Fact]
    public void Snapshot_vazio_valido_nao_e_falha_ou_prova_de_protecao()
    {
        var data = DriverDiagnosticsSource.QueryM2StageStreams(new Fake { Empty = true });
        Assert.Empty(data["records"]!.AsArray());
        Assert.False(data["truncated"]!.GetValue<bool>());
        Assert.False(data["compatibilityVerified"]!.GetValue<bool>());
    }

    [Fact]
    public void Falha_na_segunda_consulta_nao_produz_JSON_parcial()
    {
        var transport = new Fake { FailWriter = true };
        Assert.Throws<InvalidDataException>(() => DriverDiagnosticsSource.QueryM2Counters(transport));
        Assert.Equal(2, transport.Calls.Count);
    }

    [Fact]
    public void Stage_invalido_nao_e_transformado_em_lista_vazia()
    {
        var transport = new Fake { InvalidStage = true };
        Assert.Throws<InvalidDataException>(() => DriverDiagnosticsSource.QueryM2StageStreams(transport));
        Assert.Single(transport.Calls);
    }

    [Fact]
    public void Erro_nativo_e_propagado_sem_fallback()
    {
        var error = new Win32Exception(50);
        var transport = new Fake { Error = error };
        Assert.Same(error, Assert.Throws<Win32Exception>(() => DriverDiagnosticsSource.QueryM2Counters(transport)));
        Assert.Single(transport.Calls);
    }

    [Fact]
    public void Servico_sem_driver_recusa_ambas_as_consultas()
    {
        var source = new DriverDiagnosticsSource();
        Assert.Throws<InvalidOperationException>(() => source.ReadM2Counters());
        Assert.Throws<InvalidOperationException>(() => source.ReadM2StageStreams());
        Assert.False(source.IsConnected);
    }

    private static JsonObject RoundTrip(JsonObject value) => JsonNode.Parse(value.ToJsonString())!.AsObject();

    private sealed class Fake : IM2DiagnosticTransport
    {
        public static readonly Guid TransferId = Guid.Parse("0dd117aa-8924-4433-bbaa-112233445566");
        public List<M2DiagnosticQuery> Calls { get; } = [];
        public bool FailWriter { get; init; }
        public bool InvalidStage { get; init; }
        public bool Empty { get; init; }
        public Exception? Error { get; init; }
        public int Query(M2DiagnosticQuery query, Span<byte> bytes)
        {
            Calls.Add(query);
            if (Error is not null) throw Error;
            Assert.Equal(M2DiagnosticContract.ResponseBytes(query), bytes.Length);
            bytes.Clear(); U32(bytes, 0, (uint)bytes.Length); U32(bytes, 4, 18);
            switch (query)
            {
                case M2DiagnosticQuery.Counters:
                    U64(bytes, 8, ulong.MaxValue); U64(bytes, 136, 123); U64(bytes, 288, 456);
                    break;
                case M2DiagnosticQuery.WriterState:
                    U32(bytes, 4, 7); U32(bytes, 300, uint.MaxValue);
                    if (FailWriter) return 303;
                    break;
                case M2DiagnosticQuery.StageStreams:
                    if (Empty) break;
                    U32(bytes, 8, InvalidStage ? 17u : 1u); U32(bytes, 12, 2);
                    TransferId.TryWriteBytes(bytes[16..]); U32(bytes, 32, 0x80000001);
                    U64(bytes, 64, ulong.MaxValue); U32(bytes, 72, 3);
                    BinaryPrimitives.WriteUInt16LittleEndian(bytes[80..], 65);
                    BinaryPrimitives.WriteUInt16LittleEndian(bytes[84..], 0xD800);
                    break;
            }
            return bytes.Length;
        }
        private static void U32(Span<byte> bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes[offset..], value);
        private static void U64(Span<byte> bytes, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes[offset..], value);
    }
}
