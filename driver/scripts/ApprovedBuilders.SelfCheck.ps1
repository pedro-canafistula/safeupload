param([string] $SupportPath = (Join-Path $PSScriptRoot 'ApprovedBuilders.ps1'))
$ErrorActionPreference = 'Stop'
$source = [IO.File]::ReadAllText($SupportPath)
. $SupportPath
# The refusal controls keep their own unapproved fixture after a future manual
# promotion. No self-check writes the actual approved-builder list.
$fixtureDirectory = Join-Path ([IO.Path]::GetTempPath()) ('builders-selfcheck-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixtureDirectory)
$script:builderConfig = Join-Path $fixtureDirectory 'approved-builders.json'
$config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'approved-builders.json') -Raw | ConvertFrom-Json
foreach ($row in $config.builders) { if ($row.name -ceq 'builder2') { $row.gate_approved = $false } }
$config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:builderConfig -Encoding UTF8
function Assert-Control([bool] $Condition, [string] $Message) { if (-not $Condition) { throw $Message } }
function Assert-Refuses([scriptblock] $Action, [string] $Expected) {
    $refused = $false
    try { & $Action | Out-Null } catch { $refused = $_.Exception.Message -like $Expected }
    Assert-Control $refused 'A builder guard accepted the negative control.'
}
function Get-CimInstance { param($ClassName) [pscustomobject]@{ UUID = $script:fixtureUuid } }
function Get-NetAdapter { [pscustomobject]@{ MacAddress = $script:fixtureMac } }
function Test-BuilderControls {
    $env:SAFEUPLOAD_BUILDER = $null
    $one = Get-ApprovedBuilder -ConfigPath $script:builderConfig -Role matrix -Label control-default
    Assert-Control ($one.name -ceq 'builder1' -and $one.host -ceq '192.168.122.210' -and
        $one.computer_name -ceq 'DESKTOP-O1LP5DG' -and $one.ssh_user -ceq 'vika' -and $one.gate_approved) 'Default builder changed.'
    $script:fixtureUuid = $one.uuid; $script:fixtureMac = $one.mac
    Assert-ApprovedBuilderIdentity $one -ComputerName DESKTOP-O1LP5DG
    $script:fixtureUuid = 'different-uuid'
    Assert-Refuses { Assert-ApprovedBuilderIdentity $one -ComputerName DESKTOP-O1LP5DG } '*Wrong builder UUID*'
    $script:fixtureUuid = $one.uuid; $script:fixtureMac = 'different-mac'
    Assert-Refuses { Assert-ApprovedBuilderIdentity $one -ComputerName DESKTOP-O1LP5DG } '*Wrong builder MAC*'
    $script:fixtureMac = $one.mac
    $parityOne = Get-ApprovedBuilder -ConfigPath $script:builderConfig -Role matrix -Label parity-control -BuilderName builder1
    Assert-Control $parityOne.ParityCheck 'Builder1 parity label lost its marker.'
    Assert-Refuses { Get-ApprovedBuilder -ConfigPath $script:builderConfig -Role matrix -Label control-unknown -BuilderName unknown } '*Unknown approved builder*'
    Assert-Refuses { Get-ApprovedBuilder -ConfigPath $script:builderConfig -Role kernel-sign -Label parity-kernel -BuilderName builder2 } '*lacks role*'
    Assert-Refuses { Get-ApprovedBuilder -ConfigPath $script:builderConfig -Role matrix -Label control-gate -BuilderName builder2 } '*only parity-*'
    $two = Get-ApprovedBuilder -ConfigPath $script:builderConfig -Role matrix -Label parity-control -BuilderName builder2
    $script:fixtureUuid = $two.uuid; $script:fixtureMac = $two.mac   # builder2's own pinned identity (27c8807f)
    Assert-Refuses { Assert-ApprovedBuilderIdentity $two -ComputerName DESKTOP-O1LP5DG } 'Wrong builder.'   # name alone differs
    Assert-ApprovedBuilderIdentity $two -ComputerName SU-BUILDER2
    $script:fixtureUuid = $one.uuid; $script:fixtureMac = $one.mac
    $rows = @(Get-BuilderReceipt $two)
    foreach ($row in @('Builder=builder2', 'BuilderHost=192.168.122.211', 'BuilderComputerName=SU-BUILDER2', 'ParityCheck=True', 'ParityCheck: not a gate')) {
        Assert-Control ($rows -ccontains $row) ('Missing receipt: ' + $row)
    }
}
$oldBuilder = $env:SAFEUPLOAD_BUILDER
try {
    Test-BuilderControls
    $mutations = @(
        @("'builder1'", "'builder2'"),
        @('if ($matches.Count -ne 1)', 'if ($false)'),
        @('if ($Role -cnotin @($builder.roles))', 'if ($false)'),
        @('if (-not $builder.gate_approved -and -not $Label.StartsWith', 'if ($false -and -not $Label.StartsWith'),
        @('if ($Builder.uuid -and (Get-CimInstance Win32_ComputerSystemProduct).UUID -ine $Builder.uuid)', 'if ($false)'),
        @('if ($Builder.mac -and -not @(Get-NetAdapter | Where-Object { $_.MacAddress -ieq $Builder.mac }).Count)', 'if ($false)'),
        @('if ($ComputerName -ine $Builder.computer_name)', 'if ($false)'),
        @('''Builder='' + $Builder.name', '''OmittedBuilder='' + $Builder.name'),
        @('''BuilderComputerName='' + $Builder.computer_name', '''OmittedComputer='' + $Builder.computer_name'),
        @('''BuilderHost='' + $Builder.host', '''OmittedHost='' + $Builder.host')
    )
    foreach ($mutation in $mutations) {
        $changed = $source.Replace($mutation[0], $mutation[1])
        Assert-Control ($changed -cne $source) 'Mutation did not change source.'
        . ([scriptblock]::Create($changed))
        $caught = $false
        try { Test-BuilderControls } catch { $caught = $true }
        Assert-Control $caught ('Builder guard mutation escaped: ' + $mutation[0])
        . ([scriptblock]::Create($source))
    }
} finally {
    $env:SAFEUPLOAD_BUILDER = $oldBuilder
    Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force
}
'ApprovedBuildersSelfCheck=PASS; controls=default,unknown,role,parity,name,uuid,mac,receipts; mutations=10'
