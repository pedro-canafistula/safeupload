using System.Security.AccessControl;
using System.Security.Principal;
using System.Diagnostics;
using SafeUpload.Agent.Core.Infrastructure;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

/// <summary>Explicit SYSTEM phases, each executed in a separate process by CI or the matrix.</summary>
public sealed class RegisteredHostIdentitySystemTests(ITestOutputHelper output)
{
    [IdentitySystemFact("provision")]
    public void Provisiona_arquivo_protegido_SYSTEM() => VerifyPhase("provision");

    [IdentitySystemFact("restore")]
    public void Recupera_arquivo_protegido_em_outro_processo_SYSTEM() => VerifyPhase("restore");

    private void VerifyPhase(string expectedPhase)
    {
        Assert.True(WindowsIdentity.GetCurrent().IsSystem);
        string phase = Environment.GetEnvironmentVariable("SAFEUPLOAD_IDENTITY_PHASE")!;
        Assert.Equal(expectedPhase, phase);
        using var process = Process.GetCurrentProcess();
        output.WriteLine($"HOST_IDENTITY_PROCESS={phase}|{process.Id}|{process.StartTime.ToUniversalTime().Ticks}");
        string root = Path.GetFullPath(Environment.GetEnvironmentVariable("SAFEUPLOAD_IDENTITY_TEST_ROOT")!);
        string runnerTemp = Path.GetFullPath(Environment.GetEnvironmentVariable("RUNNER_TEMP")!);
        Assert.StartsWith(Path.TrimEndingDirectorySeparator(runnerTemp) + Path.DirectorySeparatorChar, root,
            StringComparison.OrdinalIgnoreCase);
        Assert.False(root.StartsWith(AgentPaths.RootDirectory, StringComparison.OrdinalIgnoreCase));
        string file = Path.Combine(root, "protected", "host-registration.json");
        var server = new Uri("https://identity-test.example/agent/");
        var store = new RegisteredHostIdentityStore(file);
        if (phase == "provision")
        {
            Assert.False(Directory.Exists(root));
            Assert.Equal(23, store.Resolve(server, 23));
        }
        else
        {
            Assert.Equal("restore", phase);
            var before = File.ReadAllBytes(file);
            Assert.Equal(23, store.Resolve(server, null));
            Assert.Equal("server_mismatch", Assert.Throws<HostIdentityException>(() =>
                store.Resolve(new Uri("https://another-test.example/agent/"), null)).Code);
            Assert.Equal(before, File.ReadAllBytes(file));
        }
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var fileAcl = new FileInfo(file).GetAccessControl();
        var directoryAcl = new DirectoryInfo(Path.GetDirectoryName(file)!).GetAccessControl();
        Assert.Equal(system, fileAcl.GetOwner(typeof(SecurityIdentifier)));
        Assert.Equal(system, directoryAcl.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(fileAcl.AreAccessRulesProtected);
        Assert.True(directoryAcl.AreAccessRulesProtected);
        Assert.Equal(2, fileAcl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Count);
        Assert.Equal(2, directoryAcl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Count);
    }
}

public sealed class IdentitySystemFactAttribute : FactAttribute
{
    public IdentitySystemFactAttribute(string expectedPhase)
    {
        if (!OperatingSystem.IsWindows() || !WindowsIdentity.GetCurrent().IsSystem ||
            Environment.GetEnvironmentVariable("SAFEUPLOAD_IDENTITY_PHASE") != expectedPhase)
            Skip = "Exige a fase explícita correspondente e execução SYSTEM em fixture isolada.";
    }
}
