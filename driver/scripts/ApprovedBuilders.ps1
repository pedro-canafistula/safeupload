# Shared by exact build tools and their offline self-checks. Windows PowerShell 5.1.
function Get-ApprovedBuilder {
    param([string] $Role, [string] $Label, [string] $BuilderName = $env:SAFEUPLOAD_BUILDER,
        [string] $ConfigPath = (Join-Path $PSScriptRoot 'approved-builders.json'))
    if ([string]::IsNullOrEmpty($BuilderName)) { $BuilderName = 'builder1' }
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $matches = @($config.builders | Where-Object { $_.name -ceq $BuilderName })
    if ($matches.Count -ne 1) { throw ('Unknown approved builder: ' + $BuilderName) }
    $builder = $matches[0]
    if ($Role -cnotin @($builder.roles)) { throw ('Builder lacks role: ' + $Role) }
    if ($builder.gate_approved -isnot [bool]) { throw 'Invalid gate approval flag.' }
    if (-not $builder.gate_approved -and -not $Label.StartsWith('parity-', [StringComparison]::Ordinal)) {
        throw 'Builder is not gate approved; only parity- labels are allowed.'
    }
    $builder | Add-Member -NotePropertyName ParityCheck -NotePropertyValue ($Label.StartsWith('parity-', [StringComparison]::Ordinal))
    return $builder
}
function Assert-ApprovedBuilderIdentity {
    param($Builder, [string] $ComputerName = $env:COMPUTERNAME)
    if ($ComputerName -ine $Builder.computer_name) { throw 'Wrong builder.' }
    if ($Builder.uuid -and (Get-CimInstance Win32_ComputerSystemProduct).UUID -ine $Builder.uuid) { throw 'Wrong builder UUID.' }
    if ($Builder.mac -and -not @(Get-NetAdapter | Where-Object { $_.MacAddress -ieq $Builder.mac }).Count) { throw 'Wrong builder MAC.' }
}
function Get-BuilderReceipt {
    param($Builder)
    @('Builder=' + $Builder.name; 'BuilderHost=' + $Builder.host
      'BuilderComputerName=' + $Builder.computer_name; 'ParityCheck=' + $Builder.ParityCheck)
    if ($Builder.ParityCheck) { 'ParityCheck: not a gate' }
}
