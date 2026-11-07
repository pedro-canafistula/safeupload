namespace SafeUpload.Agent.Tests;

/// <summary>Text checks of the PowerShell install scripts (they only run on a real Windows machine).</summary>
public sealed class InstallSafeUploadAgentScriptTests
{
    [Fact]
    public void Installer_installs_winfsp_only_when_missing_and_registers_the_gate_driver_directly()
    {
        string script = ReadScript("scripts", "Install-SafeUploadAgent.ps1");
        Assert.Contains(@"WinFsp\bin\winfsp-x64.dll", script, StringComparison.Ordinal);
        Assert.Contains("'/qn', '/norestart'", script, StringComparison.Ordinal);
        // An INF install needs a signed catalog and silently does nothing without one: the script registers the
        // demand-start filter service and its instance itself.
        Assert.DoesNotContain("InstallHinfSection", script, StringComparison.Ordinal);
        Assert.Contains("type= filesys start= demand", script, StringComparison.Ordinal);
        Assert.Contains("group= 'FSFilter Anti-Virus' depend= FltMgr", script, StringComparison.Ordinal);
        Assert.Contains("-Name Altitude -Value '321410'", script, StringComparison.Ordinal);
        Assert.Contains(@"'System32\drivers\SafeUpload.sys'", script, StringComparison.Ordinal);
        Assert.Contains("Gate driver file was not replaced.", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Prerequisites_only_mode_stops_before_the_service_and_tray_app()
    {
        string script = ReadScript("scripts", "Install-SafeUploadAgent.ps1");
        int stop = script.IndexOf("if ($PrerequisitesOnly) { return }", StringComparison.Ordinal);
        Assert.True(stop > 0, "The script must stop after WinFsp and the driver in prerequisites-only mode.");
        Assert.True(stop < script.IndexOf("New-Service -Name SafeUploadAgent", StringComparison.Ordinal));
        Assert.True(stop < script.IndexOf("SafeUploadApp", StringComparison.Ordinal));
    }

    [Fact]
    public void Installer_registers_a_drive_mode_service_and_the_tray_for_every_user()
    {
        string script = ReadScript("scripts", "Install-SafeUploadAgent.ps1");
        Assert.Contains("New-Service -Name SafeUploadAgent -BinaryPathName $binaryPath -StartupType Automatic", script, StringComparison.Ordinal);
        Assert.DoesNotContain("--CentroAdministracao:BaseUrl=", script, StringComparison.Ordinal);
        Assert.Contains("if ($AdminBaseUrl) { throw", script, StringComparison.Ordinal);
        Assert.DoesNotContain("StagingPrototype", script, StringComparison.Ordinal);
        Assert.DoesNotContain("seed-boot-policy", script, StringComparison.Ordinal);
        Assert.Contains(@"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadApp", script, StringComparison.Ordinal);
        Assert.Contains("Start-Service -Name SafeUploadAgent", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Uninstall_stops_the_service_first_and_removes_the_gate_driver_but_keeps_data()
    {
        string script = ReadScript("scripts", "Uninstall-SafeUploadAgent.ps1");
        int stop = script.IndexOf("Stop-Service -Name SafeUploadAgent", StringComparison.Ordinal);
        Assert.True(stop >= 0 && stop < script.IndexOf("sc.exe delete SafeUploadAgent", StringComparison.Ordinal));
        Assert.Contains("Remove-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name SafeUploadApp", script, StringComparison.Ordinal);
        Assert.Contains("fltmc.exe unload SafeUpload", script, StringComparison.Ordinal);
        Assert.Contains("sc.exe delete SafeUpload", script, StringComparison.Ordinal);
        // Policy, audit queue and files waiting for inspection (ProgramData) are kept.
        Assert.DoesNotContain(script.Split('\n'), line => line.Contains("Remove-Item", StringComparison.Ordinal) &&
            line.Contains("ProgramData", StringComparison.Ordinal));
    }

    [Fact]
    public void Exe_installer_drive_mode_uses_the_script_for_prerequisites_only()
    {
        string setup = ReadScript(Path.Combine("installer", "support"), "Invoke-AgentSetup.ps1");
        Assert.Contains("$prerequisites = @{ PrerequisitesOnly = $true }", setup, StringComparison.Ordinal);
        Assert.Contains("& (Join-Path $PSScriptRoot 'Install-SafeUploadAgent.ps1') @prerequisites", setup, StringComparison.Ordinal);
        Assert.DoesNotContain("StagingPrototype", setup, StringComparison.Ordinal);
    }

    private static string ReadScript(string folder, string name)
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, folder, name);
            if (File.Exists(candidate))
                return File.ReadAllText(candidate).Replace("\r\n", "\n", StringComparison.Ordinal);
        }
        throw new FileNotFoundException($"Could not find agente/{folder}/{name} from the test output.");
    }
}
