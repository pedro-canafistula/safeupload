using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class InspectionSharingTests
{
    [Fact]
    public async Task Source_inspection_can_coexist_with_an_approved_replacement_handle()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var workspace = new TestWorkspace();
        string path = workspace.WriteText("replace.txt", "ordinary approved content");
        // A rename/delete-capable handle exposes the sharing conflict without
        // timing a race between the source classifier and the publisher.
        using var rename = CreateFile(path, 0x10000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        Assert.False(rename.IsInvalid);
        var service = new InspectionService(new LocalPolicyStore(workspace.PolicyFile),
            new LocalQueueAuditSink(workspace.QueueFile), ExtractorRegistry.CreateDefault(),
            new VerdictCache(), "PC-TESTE", "usuario.teste");
        var result = await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Approved, result.Verdict);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
}
