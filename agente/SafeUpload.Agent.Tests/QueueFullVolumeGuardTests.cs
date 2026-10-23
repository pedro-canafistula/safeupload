using SafeUpload.Agent.QueueFullVolumeProbe;

namespace SafeUpload.Agent.Tests;

public sealed class QueueFullVolumeGuardTests
{
    private const string Nonce = "12345678123412341234123456789abc";
    private const string Volume = @"\\?\Volume{12345678-1234-1234-1234-123456789abc}\";
    private static string NonSystemRoot => Path.GetPathRoot(Environment.SystemDirectory) == @"P:\" ? @"Q:\" : @"P:\";

    [Theory]
    [InlineData("relative")]
    [InlineData(@"\\server\share\")]
    [InlineData(@"P:\child\")]
    public void Recusa_caminho_que_nao_seja_raiz_de_volume_descartavel(string root)
    {
        using var workspace = new TestWorkspace();
        Assert.Throws<ArgumentException>(() => VolumeGuard.ValidateRequest(root, Nonce, Volume, Path.Combine(workspace.Root, "new-results")));
    }

    [Fact]
    public void Recusa_disco_do_Windows_destino_da_fila_existente_e_resultado_no_volume_a_encher()
    {
        using var workspace = new TestWorkspace();
        var output = Path.Combine(workspace.Root, "new-results");
        Assert.Throws<ArgumentException>(() => VolumeGuard.ValidateRequest(Path.GetPathRoot(Environment.SystemDirectory)!, Nonce, Volume, output));
        Assert.Throws<ArgumentException>(() => VolumeGuard.ValidateRequest(NonSystemRoot, Nonce, Volume, workspace.Root));
        Assert.Throws<ArgumentException>(() => VolumeGuard.ValidateRequest(NonSystemRoot, Nonce, Volume, NonSystemRoot + "results"));
        Assert.Throws<ArgumentException>(() => VolumeGuard.ValidateRequest(NonSystemRoot, Nonce, Volume,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SafeUpload", "results")));
        Assert.False(Directory.Exists(output));
    }

    [Fact]
    public void Exige_nonce_e_identidade_de_volume_validos_sem_criar_diretorios()
    {
        using var workspace = new TestWorkspace();
        var output = Path.Combine(workspace.Root, "new-results");
        Assert.Throws<ArgumentException>(() => VolumeGuard.ValidateRequest(NonSystemRoot, "invalid", Volume, output));
        Assert.Throws<ArgumentException>(() => VolumeGuard.ValidateRequest(NonSystemRoot, Nonce, @"P:\", output));
        VolumeGuard.ValidateRequest(NonSystemRoot, Nonce, Volume, output);
        Assert.False(Directory.Exists(output));
    }

    [Theory]
    [InlineData("FAT32", DriveType.Fixed, 64L * 1024 * 1024, "SUQ123456781234")]
    [InlineData("NTFS", DriveType.Removable, 64L * 1024 * 1024, "SUQ123456781234")]
    [InlineData("NTFS", DriveType.Fixed, 1024L * 1024, "SUQ123456781234")]
    [InlineData("NTFS", DriveType.Fixed, 64L * 1024 * 1024 * 1024, "SUQ123456781234")]
    [InlineData("NTFS", DriveType.Fixed, 64L * 1024 * 1024, "OUTRO")]
    public void Recusa_geometria_tipo_sistema_de_arquivos_ou_rotulo_divergente(string format, DriveType type, long bytes, string label)
        => Assert.Throws<InvalidOperationException>(() => VolumeGuard.ValidateGeometry(format, type, bytes, label, Nonce));

    [Fact]
    public void Aceita_somente_geometria_pequena_com_identidade_esperada()
        => VolumeGuard.ValidateGeometry("NTFS", DriveType.Fixed, 64L * 1024 * 1024, "SUQ123456781234", Nonce);
}
