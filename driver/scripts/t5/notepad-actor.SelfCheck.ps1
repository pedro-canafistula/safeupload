[CmdletBinding()]
param([string]$ActorPath = (Join-Path $PSScriptRoot 'notepad-actor.ps1'))
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'This actor gate requires Windows PowerShell 5.1.'
}
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ActorPath, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count) { throw ('Actor parse failed: ' + ($parseErrors | Out-String)) }
'PowerShell51ActorParse=PASS'
$commands = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq 'Add-Type' -and
    @($node.CommandElements | Where-Object {
        $_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'TypeDefinition'
    }).Count -eq 1
}, $true))
if ($commands.Count -ne 1) { throw 'Expected exactly one native actor definition.' }
$sources = @($commands[0].CommandElements | Where-Object {
    $_ -is [Management.Automation.Language.StringConstantExpressionAst] -and $_.Value.Contains('class T5Native')
})
if ($sources.Count -ne 1) { throw 'Native actor source was ambiguous.' }
Add-Type -TypeDefinition $sources[0].Value
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class T5ActorSelfCheckIdentity {
    [StructLayout(LayoutKind.Sequential)] struct FileIdInfo { public ulong Volume, Low, High; }
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file, int informationClass, out FileIdInfo info, uint size);
    public static string Read(string path) {
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
            FileIdInfo info;
            if (!GetFileInformationByHandleEx(stream.SafeFileHandle, 18, out info, 24))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return info.Volume.ToString("X16") + ":" + info.High.ToString("X16") + ":" + info.Low.ToString("X16");
        }
    }
}
'@
function Assert-Actor([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw ('Actor native control failed: ' + $Message) }
}
$root = Join-Path $env:TEMP ('safeupload-t5-actor-control-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try {
    $splitNativeControl = $null -ne [T5Native].GetMethod('ProbeCreate')
    $path = Join-Path $root 'existing.txt'
    [IO.File]::WriteAllBytes($path, [Text.Encoding]::ASCII.GetBytes('prior bytes'))
    $before = [T5ActorSelfCheckIdentity]::Read($path)
    $saved = [Text.Encoding]::ASCII.GetBytes('clean saved bytes')
    if ($splitNativeControl) {
        $probe = [T5Native]::ProbeCreate($path, $false)
        Assert-Actor (-not $probe.Created -and $probe.Steps -match '^test-create=(80|183)$') 'existing CREATE_NEW must fail'
        Assert-Actor ([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($path)) -eq 'prior bytes') 'probe changed prior bytes'
        $finish = [T5Native]::ProbeFinish($path, $saved, $true, $probe.Created)
        $steps = $probe.Steps + ' ' + $finish
    } else {
        $steps = [T5Native]::Probe($path, $saved, $false)
    }
    Assert-Actor ($steps -match '^test-create=(80|183) test-delete=skipped-create-failed save-create=0 save-write=0 save-close=0$') 'failed probe attempted deletion or save failed'
    Assert-Actor ([T5ActorSelfCheckIdentity]::Read($path) -eq $before) 'failed probe deleted/recreated the public object'
    Assert-Actor ([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($path)) -eq 'clean saved bytes') 'final clean bytes differ'
    'ExistingNameFailedProbe=PASS; identity=' + $before + '; ' + $steps

    $newPath = Join-Path $root 'new.txt'
    if ($splitNativeControl) {
        $probe = [T5Native]::ProbeCreate($newPath, $false)
        Assert-Actor ($probe.Created -and $probe.Steps -eq 'test-create=0 test-close=0') 'new probe creation failed'
        Assert-Actor ((Get-Item -LiteralPath $newPath).Length -eq 0) 'probe must be empty'
        $finish = [T5Native]::ProbeFinish($newPath, $saved, $true, $probe.Created)
        $steps = $probe.Steps + ' ' + $finish
    } else {
        $steps = [T5Native]::Probe($newPath, $saved, $false)
    }
    Assert-Actor ($steps -eq 'test-create=0 test-close=0 test-delete=0 save-create=0 save-write=0 save-close=0') 'new probe delete/save failed'
    Assert-Actor ([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($newPath)) -eq 'clean saved bytes') 'new-name final bytes differ'
    'NewNameProbe=PASS; SplitNativeControl=' + $splitNativeControl + '; ' + $steps
    'NativeActorControl=PASS; ProductQualified=False; ProtectedDestination=False'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
