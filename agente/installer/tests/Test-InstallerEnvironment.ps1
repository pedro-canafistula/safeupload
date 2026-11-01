#Requires -Version 7.5
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
    $smokePath=Join-Path $PSScriptRoot 'Test-InstallerSmoke.ps1'
    $smokeAst=[Management.Automation.Language.Parser]::ParseFile($smokePath,[ref]$tokens,[ref]$errors)
    $readFunction=$smokeAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Read-AuditEvents'},$true)
    if (-not $readFunction) { throw 'The smoke audit reader is absent.' }
    . ([scriptblock]::Create($readFunction.Extent.Text))
    $queueFile=Join-Path $fixture 'queue.jsonl'
    $timestamp='2026-10-20T23:43:24.750+00:00'
    [IO.File]::WriteAllText($queueFile,
        ('{"eventId":"50f42eb0-28f7-48dc-8c7b-c97376f0ef71","occurredAtUtc":"' + $timestamp + '"}' + "`n" + '{"eventId":'))
    $events=@(Read-AuditEvents $queueFile)
    if ($events.Count -ne 1) { throw 'The audit reader lost a complete event before a truncated append.' }
    if ($events[0].occurredAtUtc -isnot [string] -or $events[0].occurredAtUtc -cne $timestamp) {
        throw 'Audit timestamps must remain original strings, independent of PowerShell date conversion.'
    }
    $summary=[ordered]@{passed=4;failed=0;tests=@('untrusted inherited module selected in control',
        'actual setup bootstrap loads native Windows PowerShell Get-Acl',
        'actual smoke reader preserves complete records before truncated tail',
        'actual smoke reader preserves the original timestamp without culture conversion')}
    if ($ResultsPath) { $summary | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $ResultsPath -Encoding utf8NoBOM }
    'InstallerEnvironment: 4/4 passed'
} finally {
    $full=[IO.Path]::GetFullPath($fixture)
    $temporary=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $full.StartsWith($temporary,[StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $full) -notmatch '^safeupload-environment-[a-f0-9]{32}$') { throw 'Unsafe cleanup target.' }
    Remove-Item -LiteralPath $full -Recurse -Force
}
