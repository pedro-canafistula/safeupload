using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedStageFileAttachedMetadataTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "SafeUpload.AttachedMetadata." + Guid.NewGuid().ToString("N"));

    public StagedStageFileAttachedMetadataTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    // m2t5boot7: the driver keeps a writable stage backing open with no sharing while a writer is attached,
    // so the v20 attach PREPARE's data open failed with a sharing violation and every save was denied.
    [Fact]
    public void Attached_metadata_reads_identity_and_length_beside_an_exclusive_writer()
    {
        string path = Path.Combine(_root, "stage.txt");
        File.WriteAllBytes(path, new byte[37]);
        StagedStageIdentity expected;
        using (var reader = StagedStageFile.Open(path)) expected = reader.Identity;

        using (var writer = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            Assert.Throws<IOException>(() => StagedStageFile.Open(path, allowWriters: true).Dispose());

            var (identity, length) = StagedStageFile.ReadAttachedMetadata(path);
            Assert.Equal(expected, identity);
            Assert.Equal(37, length);

            writer.SetLength(5);
            writer.Flush();
            Assert.Equal(5, StagedStageFile.ReadAttachedMetadata(path).Length);
        }
    }

    [Fact]
    public void Attached_metadata_refuses_a_missing_stage_and_a_hard_linked_stage()
    {
        string missing = Path.Combine(_root, "missing.txt");
        Assert.Throws<FileNotFoundException>(() => StagedStageFile.ReadAttachedMetadata(missing));

        string path = Path.Combine(_root, "linked.txt");
        File.WriteAllBytes(path, new byte[3]);
        Assert.True(CreateHardLink(Path.Combine(_root, "second-name.txt"), path, IntPtr.Zero));
        Assert.Throws<IOException>(() => StagedStageFile.ReadAttachedMetadata(path));
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLink(string fileName, string existingFileName, IntPtr securityAttributes);
}
