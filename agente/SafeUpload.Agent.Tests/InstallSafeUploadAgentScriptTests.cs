namespace SafeUpload.Agent.Tests;

public sealed class InstallSafeUploadAgentScriptTests
{
    [Fact]
    public void Installer_requires_successful_system_seed_before_staging_boot_start()
    {
        string script = ReadInstallerScript();
        int demandCall = script.IndexOf("\nSet-SafeUploadDriverDemandBeforeSeed\n", StringComparison.Ordinal);
        int seedCall = script.IndexOf("\nInvoke-BootPolicySeedAsSystem\n", StringComparison.Ordinal);
        int driverBootStartCall = script.IndexOf("\nSet-SafeUploadDriverBootStart\n", StringComparison.Ordinal);

        Assert.True(demandCall >= 0 && demandCall < seedCall,
            "Installer must hold the INF-installed driver at demand-start before seeding.");
        Assert.True(seedCall >= 0, "Installer must invoke the SYSTEM seed task.");
        Assert.True(driverBootStartCall > seedCall, "Driver boot-start may only be configured after seed success.");
        Assert.Contains("Invoke-ScChecked @('config', 'SafeUpload', 'start=', 'demand')", script, StringComparison.Ordinal);
        Assert.Contains("Invoke-ScChecked @('config', 'SafeUpload', 'start=', 'boot')", script, StringComparison.Ordinal);
        Assert.Contains("New-ScheduledTaskPrincipal -UserId 'SYSTEM'", script, StringComparison.Ordinal);
        Assert.Contains("if ([int]$info.LastTaskResult -ne 0)", script, StringComparison.Ordinal);
        Assert.Contains("DriverStartedByInstaller=False", script, StringComparison.Ordinal);
        Assert.Contains("Protection activates after reboot.", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Invoke-ScChecked @('start', 'SafeUpload'", script, StringComparison.Ordinal);
    }

    private static string ReadInstallerScript()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "scripts", "Install-SafeUploadAgent.ps1");
            if (File.Exists(candidate))
                return File.ReadAllText(candidate);
        }

        throw new FileNotFoundException("Could not find agente/scripts/Install-SafeUploadAgent.ps1 from test output.");
    }
}
