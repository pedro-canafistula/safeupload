#Requires -Version 7.0
[CmdletBinding()]
param([string]$ResultsPath)
$ErrorActionPreference = 'Stop'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('safeupload-environment-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    # Exercise the actual bootstrap statement without executing the privileged
    # setup body. No service/registry or machine-wide environment is modified.
    $tokens=$null; $errors=$null
    $scriptPath = Join-Path $PSScriptRoot '../support/Invoke-AgentSetup.ps1'
    $ast=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors)
    if ($errors) { throw 'Setup parsing failed.' }
    $bootstrap=$ast.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$env:PSModulePath'},$true)
    $import=$ast.Find({param($node) $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Import-Module'},$true)
    if (-not $bootstrap -or $bootstrap.Extent.StartOffset -ge $import.Extent.StartOffset) {
        throw 'Trusted module path must be set before importing setup modules.'
    }
    $shadow = Join-Path $fixture 'Microsoft.PowerShell.Security'
    New-Item -ItemType Directory -Path $shadow | Out-Null
    [IO.File]::WriteAllText((Join-Path $shadow 'Microsoft.PowerShell.Security.psm1'),
        "function Get-Acl { throw 'Untrusted module selected' }; Export-ModuleMember -Function Get-Acl")
    [IO.File]::WriteAllText((Join-Path $shadow 'Microsoft.PowerShell.Security.psd1'),
        "@{RootModule='Microsoft.PowerShell.Security.psm1';ModuleVersion='99.0.0';GUID='50f42eb0-28f7-48dc-8c7b-c97376f0ef71';FunctionsToExport=@('Get-Acl')}")
    $testScript = Join-Path $fixture 'probe.ps1'
    $probe = @'
param([string]$UntrustedModules, [switch]$Secure)
$ErrorActionPreference='Stop'
$env:PSModulePath=$UntrustedModules
if ($Secure) {
__BOOTSTRAP__
}
$acl=Get-Acl -LiteralPath $env:ProgramFiles
if (-not $acl) { throw 'ACL was not read.' }
$module=Get-Module Microsoft.PowerShell.Security
if (-not $module.Path.StartsWith(($PSHOME + '\Modules\'),[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Get-Acl was not loaded from Windows PowerShell.'
}
'OK'
'@
    [IO.File]::WriteAllText($testScript,$probe.Replace('__BOOTSTRAP__',$bootstrap.Extent.Text))
    function Invoke-Probe([bool]$Secure) {
        $start=[Diagnostics.ProcessStartInfo]::new()
        $start.FileName="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true
        $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
        foreach ($argument in @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$testScript,'-UntrustedModules',$fixture)) {
            $start.ArgumentList.Add($argument)
        }
        if ($Secure) { $start.ArgumentList.Add('-Secure') }
        $process=[Diagnostics.Process]::Start($start)
        $stdout=$process.StandardOutput.ReadToEnd(); $stderr=$process.StandardError.ReadToEnd()
        $process.WaitForExit()
        try { [pscustomobject]@{exitCode=$process.ExitCode;stdout=$stdout;stderr=$stderr} }
        finally { $process.Dispose() }
    }
    $baseline=Invoke-Probe $false
    if ($baseline.exitCode -eq 0 -or $baseline.stderr -notlike '*Untrusted module selected*') {
        throw 'The control did not reproduce inherited-module shadowing.'
    }
    $secured=Invoke-Probe $true
    if ($secured.exitCode -ne 0 -or $secured.stdout.Trim() -ne 'OK') {
        throw "The real setup bootstrap did not isolate built-in cmdlets: $($secured.stderr)"
    }
    $summary=[ordered]@{passed=2;failed=0;tests=@('untrusted inherited module selected in control',
        'actual setup bootstrap loads native Windows PowerShell Get-Acl')}
    if ($ResultsPath) { $summary | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $ResultsPath -Encoding utf8NoBOM }
    'InstallerEnvironment: 2/2 passed'
} finally {
    $full=[IO.Path]::GetFullPath($fixture)
    $temporary=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $full.StartsWith($temporary,[StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $full) -notmatch '^safeupload-environment-[a-f0-9]{32}$') { throw 'Unsafe cleanup target.' }
    Remove-Item -LiteralPath $full -Recurse -Force
}
