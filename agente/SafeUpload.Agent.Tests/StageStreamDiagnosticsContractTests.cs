using System.Buffers.Binary;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class StageStreamDiagnosticsContractTests
{
    [Fact]
    public void Header_vazio_aceito_sem_ler_slots_nao_declarados()
    {
        var bytes = Header(0, 0);
        Array.Fill(bytes, (byte)0xff, 16, bytes.Length - 16);
        var snapshot = StageStreamDiagnosticsContract.Decode(bytes);
        Assert.Empty(snapshot.Records);
        Assert.Equal(0u, snapshot.Total);
        Assert.False(snapshot.Truncated);
    }

    [Fact]
    public void Registro_nativo_tem_offsets_GUID_UTF16_e_bits_futuros_preservados()
    {
        var bytes = Header(1, uint.MaxValue);
        // Windows GUID layout: 00112233-4455-6677-8899-aabbccddeeff.
        Convert.FromHexString("33221100554477668899AABBCCDDEEFF").CopyTo(bytes, 16);
        U32(bytes, 16 + 16, 0x80000001);
        U32(bytes, 16 + 20, 2); U32(bytes, 16 + 24, 3); U32(bytes, 16 + 28, 4);
        U32(bytes, 16 + 32, 5); U32(bytes, 16 + 36, 6); U32(bytes, 16 + 40, 0x80000004);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16 + 48), ulong.MaxValue);
        Name(bytes, 0, "A\0ç\ud83d\ude00\ud800");
        var snapshot = StageStreamDiagnosticsContract.Decode(bytes);
        var record = Assert.Single(snapshot.Records);
        Assert.Equal(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"), record.TransferId);
        Assert.Equal(0x80000001u, record.Flags); Assert.Equal(0x80000004u, record.SectionBits);
        Assert.Equal(2u, record.FileObjects); Assert.Equal(3u, record.ShareOpenCount);
        Assert.Equal(4u, record.RpcReferences); Assert.Equal(5u, record.OwnerProcessId);
        Assert.Equal(6u, record.Wait); Assert.Equal(ulong.MaxValue, record.DestinationGeneration);
        Assert.Equal("A\0ç\ud83d\ude00\ud800", record.Name);
        Assert.Equal(uint.MaxValue, snapshot.Total); Assert.True(snapshot.Truncated);
    }

    [Fact]
    public void Capacidade_maxima_e_nomes_de_48_unidades_sem_terminador()
    {
        var bytes = Header(16, 16);
        for (int i = 0; i < 16; i++) Name(bytes, i, new string((char)('a' + i), 48));
        var snapshot = StageStreamDiagnosticsContract.Decode(bytes);
        Assert.Equal(16, snapshot.Records.Count); Assert.False(snapshot.Truncated);
        for (int i = 0; i < 16; i++) Assert.Equal(new string((char)('a' + i), 48), snapshot.Records[i].Name);
    }

    [Theory]
    [InlineData(0)] [InlineData(15)] [InlineData(2575)] [InlineData(2577)]
    public void Comprimento_recebido_incorreto_recusado(int length) =>
        Assert.Throws<InvalidDataException>(() => StageStreamDiagnosticsContract.Decode(new byte[length]));

    [Theory]
    [InlineData(0u)] [InlineData(16u)] [InlineData(2575u)] [InlineData(uint.MaxValue)]
    public void Tamanho_declarado_incorreto_recusado(uint size)
    {
        var bytes = Header(0, 0); U32(bytes, 0, size);
        Assert.Throws<InvalidDataException>(() => StageStreamDiagnosticsContract.Decode(bytes));
    }

    [Theory]
    [InlineData(0u)] [InlineData(17u)] [InlineData(19u)]
    public void Versao_diferente_do_layout_18_recusada(uint version)
    {
        var bytes = Header(0, 0); U32(bytes, 4, version);
        Assert.Throws<InvalidDataException>(() => StageStreamDiagnosticsContract.Decode(bytes));
    }

    [Theory]
    [InlineData(17u, 17u)] [InlineData(1u, 0u)] [InlineData(uint.MaxValue, uint.MaxValue)]
    public void Contagem_fora_do_buffer_ou_maior_que_total_recusada(uint count, uint total) =>
        Assert.Throws<InvalidDataException>(() => StageStreamDiagnosticsContract.Decode(Header(count, total)));

    [Theory]
    [InlineData(49u)] [InlineData(uint.MaxValue)]
    public void Nome_fora_do_registro_recusado_sem_expor_conteudo(uint chars)
    {
        var bytes = Header(1, 1); Name(bytes, 0, "SENSIVEL"); U32(bytes, 16 + 56, chars);
        var error = Assert.Throws<InvalidDataException>(() => StageStreamDiagnosticsContract.Decode(bytes));
        Assert.DoesNotContain("SENSIVEL", error.Message);
    }

    [Fact]
    public void Resposta_original_nao_alterada_e_nome_vazio_aceito()
    {
        var bytes = Header(1, 1); var original = bytes.ToArray();
        Assert.Empty(Assert.Single(StageStreamDiagnosticsContract.Decode(bytes).Records).Name);
        Assert.Equal(original, bytes);
        Assert.Equal(29u, StageStreamDiagnosticsContract.Command);
        Assert.Equal(2576, StageStreamDiagnosticsContract.SnapshotBytes);
        Assert.Equal(160, StageStreamDiagnosticsContract.RecordBytes);
    }

    private static byte[] Header(uint count, uint total)
    {
        var bytes = new byte[2576]; U32(bytes, 0, 2576); U32(bytes, 4, 18);
        U32(bytes, 8, count); U32(bytes, 12, total); return bytes;
    }
    private static void U32(byte[] bytes, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
    private static void Name(byte[] bytes, int index, string name)
    {
        int start = 16 + index * 160; U32(bytes, start + 56, (uint)name.Length);
        for (int i = 0; i < name.Length; i++)
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(start + 64 + i * 2), name[i]);
    }
}
