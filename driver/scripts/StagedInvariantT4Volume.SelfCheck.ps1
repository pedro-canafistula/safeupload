#requires -Version 5.1
# Actual classification/native helpers only: synthetic samples and temporary files/processes.
# No VHD, diskpart, fltmc, memory purge, product driver or privileged operation is invoked.
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 't4\cycles-coordinator.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Coordinator does not parse' }
foreach ($name in 'Initialize-T4VolumeIdentity','Get-T4VolumeObservation','Invoke-T4VolumeNative') {
    $functions = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $false))
    if ($functions.Count -ne 1) { throw ('Actual volume helper unavailable: ' + $name) }
    Invoke-Expression $functions[0].Extent.Text
}
$count = 0
function Assert-VolumeControl([bool]$Good, [string]$Label) {
    if (-not $Good) { throw ('T4 volume control failed: ' + $Label) }
    $script:count++
}
function New-VolumeControl([int]$Growth=512, [int]$Residual=64) {
    $samples = @(foreach ($value in @(@('vol-s0',900), @('vol-s1',1000), @('vol-s2',(1000+$Growth)),
                                    @('vol-s3',1256), @('vol-s4',(1000+$Residual)))) {
        [pscustomobject]@{ Label=$value[0]; TagSUfl=@{ NonPagedAllocs=(5000+$value[1]); NonPagedFrees=5000 } }
    })
    [ordered]@{ N=512; Samples=$samples; Errors=@(); FilterAttached=@{ First=$true; Second=$true }; NativeReceipts=@() }
}
$row = New-VolumeControl
$observation = Get-T4VolumeObservation $row
Assert-VolumeControl ($observation.Classification -ceq 'StreamRetention' -and $observation.Growth -eq 512 -and
    $observation.DeleteRelease -eq 256 -and $observation.TeardownRelease -eq 192 -and $observation.Residual -eq 64) 'release arithmetic and residual boundary'
Assert-VolumeControl ((Get-T4VolumeObservation (New-VolumeControl 512 65)).Classification -ceq 'DriverReference') 'above residual boundary'
Assert-VolumeControl ((Get-T4VolumeObservation (New-VolumeControl 256 64)).Classification -ceq 'StreamRetention') 'growth boundary inclusive'
Assert-VolumeControl ((Get-T4VolumeObservation (New-VolumeControl 255 0)).Classification -ceq 'Inconclusive') 'insufficient growth'
foreach ($label in 'vol-s0','vol-s1','vol-s2','vol-s3','vol-s4') {
    $row = New-VolumeControl
    $row.Samples = @($row.Samples | Where-Object { $_.Label -ne $label })
    Assert-VolumeControl ((Get-T4VolumeObservation $row).Classification -ceq 'Inconclusive') ($label + ' missing')
}
$row = New-VolumeControl
$row.Samples[0].TagSUfl = $null
Assert-VolumeControl ((Get-T4VolumeObservation $row).Classification -ceq 'Inconclusive') 'SUfl unavailable'
$row = New-VolumeControl
$row.Errors = @('cleanup error')
Assert-VolumeControl ((Get-T4VolumeObservation $row).Classification -ceq 'Inconclusive') 'cleanup failure'
foreach ($attach in 'First','Second') {
    $row = New-VolumeControl
    $row.FilterAttached[$attach] = $false
    Assert-VolumeControl ((Get-T4VolumeObservation $row).Classification -ceq 'Inconclusive') ($attach + ' filter absent')
}
$row = New-VolumeControl
$row.Samples[0].TagSUfl = @{ NonPagedAllocs=-2147483600L; NonPagedFrees=2147483000L }
Assert-VolumeControl ((Get-T4VolumeObservation $row).LiveSUfl['vol-s0'] -eq 696) 'unsigned 32-bit counter arithmetic'
$root = Join-Path $env:TEMP ('T4VolumeSelfCheck-' + [guid]::NewGuid().ToString('N'))
$stream = $null
try {
    New-Item -ItemType Directory -Path $root | Out-Null
    Initialize-T4VolumeIdentity # compiles the actual P/Invoke declarations under Windows PowerShell 5.1
    $path = Join-Path $root 'identity.txt'
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $id = [T4VolumeIdentity]::Read($path)
    Assert-VolumeControl ($id -cmatch '^[0-9A-F]{48}$') 'FILE_READ_ATTRIBUTES FileIdInfo despite exclusive data writer'
    Assert-VolumeControl ([T4VolumeIdentity]::Read($path) -ceq $id) 'stable full identity and sharing'
    $stream.Dispose(); $stream = $null
    [IO.File]::Delete($path)
    Assert-VolumeControl (-not [IO.File]::Exists($path)) 'native identity handles closed'
    $row = New-VolumeControl
    $receipt = Invoke-T4VolumeNative $row $root 'native-ok' 'cmd.exe' @('/d','/c','echo T4VolumeNativeControl')
    Assert-VolumeControl ($receipt.ExitCode -eq 0 -and $null -eq $receipt.Error -and
        [IO.File]::ReadAllText($receipt.Stdout).Contains('T4VolumeNativeControl')) 'native output and zero exit receipt'
    $refused = $false
    try { $null = Invoke-T4VolumeNative $row $root 'native-error' 'cmd.exe' @('/d','/c','exit 7') }
    catch { $refused = $true }
    $saved = [IO.File]::ReadAllText((Join-Path $root 'native-error.receipt.json')) | ConvertFrom-Json
    Assert-VolumeControl ($refused -and $saved.ExitCode -eq 7 -and $saved.Error -and $row.NativeReceipts.Count -eq 2) 'native error retained before propagation'
} finally {
    if ($null -ne $stream) { $stream.Dispose() }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
'T4VolumeSelfCheck=PASS;Controls=' + $count + ';Qualification=False'
