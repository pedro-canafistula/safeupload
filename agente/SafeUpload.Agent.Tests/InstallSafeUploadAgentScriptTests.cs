using System.Text.RegularExpressions;

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

    [Fact]
    public void Installer_registers_the_agent_in_staged_minifilter_mode()
    {
        string script = ReadInstallerScript();
        int imagePathCall = script.IndexOf("\nSet-SafeUploadAgentImagePath\n", StringComparison.Ordinal);
        int createCall = script.IndexOf("'Creating SafeUploadAgent'", StringComparison.Ordinal);
        int configureCall = script.IndexOf("'Configuring SafeUploadAgent'", StringComparison.Ordinal);

        // Without these two arguments the agent runs outside staged mode (admissionCoverage NotAvailable) and the
        // driver refuses every standard-user save into a protected folder.
        Assert.Contains("'--Interception:Mode=Minifilter'", script, StringComparison.Ordinal);
        Assert.Contains("'--Interception:StagingPrototype=true'", script, StringComparison.Ordinal);
        // appsettings.json ships a panel address; the installer must say explicitly where the policy comes from.
        Assert.Contains("'--CentroAdministracao:BaseUrl=' + $AdminBaseUrl", script, StringComparison.Ordinal);
        Assert.Contains("[string] $AdminBaseUrl = ''", script, StringComparison.Ordinal);
        Assert.Contains("(@($quotedExecutable) + $ServiceArguments) -join ' '", script, StringComparison.Ordinal);
        Assert.Contains("Set-ItemProperty -LiteralPath $agentServiceKey -Name ImagePath", script, StringComparison.Ordinal);
        Assert.Contains("if ($written -ne $binaryPath)", script, StringComparison.Ordinal);
        Assert.True(createCall >= 0 && configureCall >= 0, "Installer must create or configure the service.");
        Assert.True(imagePathCall > createCall && imagePathCall > configureCall,
            "ImagePath must be written after the service exists, in both the create and the configure branch.");
        // PowerShell 5.1 mangles embedded quotes passed to sc.exe: sc.exe only ever sees the bare quoted executable.
        Assert.Contains("'binPath=', $quotedExecutable", script, StringComparison.Ordinal);
        Assert.DoesNotContain("'binPath=', $binaryPath", script, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SERVICE_NAME: SafeUploadAgent\r\n        SERVICE_SID_TYPE:  UNRESTRICTED\r\n", true)]
    [InlineData("SERVICE_SID_TYPE_UNRESTRICTED", true)]
    [InlineData("SERVICE_SID_TYPE:  RESTRICTED", false)]
    [InlineData("SERVICE_SID_TYPE:  NONE", false)]
    public void Installer_sid_type_check_accepts_the_windows_10_output(string scOutput, bool expected)
    {
        Match match = Regex.Match(ReadInstallerScript(),
            @"function Test-ServiceSidTypeUnrestricted.*?-match '(?<pattern>[^']+)'", RegexOptions.Singleline);

        Assert.True(match.Success, "Installer must define Test-ServiceSidTypeUnrestricted with a -match pattern.");
        Assert.Equal(expected, Regex.IsMatch(scOutput, match.Groups["pattern"].Value, RegexOptions.IgnoreCase));
        Assert.Contains("-not (Test-ServiceSidTypeUnrestricted $sidType)", ReadInstallerScript(), StringComparison.Ordinal);
    }

    private static string ReadInstallerScript()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "scripts", "Install-SafeUploadAgent.ps1");
            // The assertions look for whole lines ("\nName\n"); a Windows checkout has CR LF line endings.
            if (File.Exists(candidate))
                return File.ReadAllText(candidate).Replace("\r\n", "\n", StringComparison.Ordinal);
        }

        throw new FileNotFoundException("Could not find agente/scripts/Install-SafeUploadAgent.ps1 from test output.");
    }
}
