#requires -Version 5.1
# Parse the lab PowerShell on the Windows version used by the image, then run non-Hyper-V controls.
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Use Windows PowerShell 5.1.' }
$files = @(
    'Test-LabScripts.ps1', 'Test-LabGuest.ps1',
    'hyperv\New-LabVM.ps1', 'hyperv\New-LabVM.SelfCheck.ps1',
    'packer\answer\enable-openssh.ps1',
    'packer\answer\enable-winrm.ps1',
    'ansible\files\Assert-ImageBuildHost.ps1',
    'ansible\roles\lab_seed\files\lab-seed.ps1',
    'ansible\roles\lab_seed\files\Prepare-Oobe.ps1',
    'ansible\roles\lab_seed\files\New-OobeAnswer.ps1',
    'ansible\roles\lab_seed\files\Complete-Oobe.ps1',
    'ansible\roles\sanitize\files\safeupload-finalize.ps1'
)
foreach ($file in $files) {
    $tokens = $null; $errors = $null
    $path = Join-Path $PSScriptRoot $file
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw ($file + ': ' + ($errors.Message -join '; ')) }
    # Parsing alone cannot detect a native cmdlet prompting for a required parameter during unattended bootstrap.
    $firewallCalls = $ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'New-NetFirewallRule'
    }, $true)
    foreach ($call in $firewallCalls) {
        $required = @((Get-Command New-NetFirewallRule).ParameterSets | ForEach-Object {
            $_.Parameters | Where-Object { $_.IsMandatory -and $_.Name -eq 'DisplayName' }
        })
        if ($required.Count -eq 0) { throw 'Unexpected native firewall cmdlet signature.' }
        $names = @($call.CommandElements | Where-Object { $_ -is [Management.Automation.Language.CommandParameterAst] } |
            Select-Object -ExpandProperty ParameterName)
        if ($names -notcontains 'DisplayName') { throw "$file`: unattended firewall creation omits mandatory DisplayName." }
    }
    "$file`:ParseErrors=0;SHA256=$((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)"
}
'NativeFirewallSignature=PASS'
# These roles use literal win_shell scalars. Parse their embedded PowerShell as well as the .ps1 files, without
# requiring Python or a YAML module on a colleague's Windows host. Refuse unsupported scalar styles explicitly.
$embeddedCount = 0
foreach ($file in Get-ChildItem (Join-Path $PSScriptRoot 'ansible\roles') -Filter '*.yml' -Recurse) {
    $lines = [IO.File]::ReadAllLines($file.FullName)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch '^(\s*)ansible\.windows\.win_shell:\s*(.*)$') { continue }
        $indent = $Matches[1].Length
        $body = $Matches[2]
        if ($body -match '^\|[-+]?$') {
            $block = @()
            $j = $i + 1
            while ($j -lt $lines.Count) {
                $line = $lines[$j]
                $spaces = $line.Length - $line.TrimStart().Length
                if ($line.Trim() -and $spaces -le $indent) { break }
                $block += $line
                $j++
            }
            $nonempty = @($block | Where-Object { $_.Trim() })
            if ($nonempty.Count -eq 0) { throw 'Empty embedded PowerShell block.' }
            $padding = $nonempty[0].Length - $nonempty[0].TrimStart().Length
            $body = ($block | ForEach-Object { if ($_.Trim()) { $_.Substring($padding) } else { '' } }) -join "`n"
            $i = $j - 1
        } elseif (-not $body -or $body -match '^[>"'']' -or $body.Contains('{{')) {
            throw ('Unsupported win_shell scalar in ' + $file.FullName)
        }
        $tokens = $null; $errors = $null
        $null = [Management.Automation.Language.Parser]::ParseInput($body, [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw ($file.FullName + ': ' + ($errors.Message -join '; ')) }
        $embeddedCount++
    }
}
if ($embeddedCount -eq 0) { throw 'No embedded PowerShell was discovered.' }
'EmbeddedPowerShellParse=PASS;Count=' + $embeddedCount
# Native .NET XML check of the private per-instance answer. Windows Setup itself is exercised only by a first boot.
$probe = 'Probe-' + [guid]::NewGuid().ToString('N')
[xml]$generated = & "$PSScriptRoot\ansible\roles\lab_seed\files\New-OobeAnswer.ps1" -Password $probe `
    -TemplatePath "$PSScriptRoot\ansible\roles\sanitize\files\safeupload-firstboot.xml"
$ns = New-Object Xml.XmlNamespaceManager($generated.NameTable)
$ns.AddNamespace('u', 'urn:schemas-microsoft-com:unattend')
$ns.AddNamespace('wcm', 'http://schemas.microsoft.com/WMIConfig/2002/State')
$shellPath = '/u:unattend/u:settings[@pass="oobeSystem"]/u:component[@name="Microsoft-Windows-Shell-Setup"]'
$account = $generated.SelectSingleNode("$shellPath/u:UserAccounts/u:LocalAccounts/u:LocalAccount[@wcm:action='add']", $ns)
$autoLogon = $generated.SelectSingleNode("$shellPath/u:AutoLogon[u:Enabled='true' and u:LogonCount='1' and u:Username='vika']", $ns)
if ($generated.SelectNodes('/u:unattend/u:settings', $ns).Count -ne 1 -or $null -eq $account -or $null -eq $autoLogon -or
    $account.SelectSingleNode('u:Name', $ns).InnerText -ne 'vika' -or $account.SelectSingleNode('u:Group', $ns).InnerText -ne 'Administrators' -or
    $account.SelectSingleNode('u:Password/u:Value', $ns).InnerText -ne $probe -or
    $autoLogon.SelectSingleNode('u:Password/u:Value', $ns).InnerText -ne $probe -or
    [regex]::Matches($generated.OuterXml, $probe).Count -ne 2) { throw 'Unexpected per-instance OOBE answer.' }
'OobeAnswer=PASS'
& "$PSScriptRoot\hyperv\New-LabVM.SelfCheck.ps1"
if ($env:COMPUTERNAME -ine 'SU-LAB-BUILD') {
    $refused = $false
    try { & "$PSScriptRoot\ansible\files\Assert-ImageBuildHost.ps1" -ExpectedUuid '11111111-2222-4333-8444-555555555555' | Out-Null } catch {
        if ($_.Exception.Message -like 'Image configuration is allowed only*') { $refused = $true } else { throw }
    }
    if (-not $refused) { throw 'Image playbook guard accepted a non-build host.' }
    'ImageHostGuard=REFUSED_NON_BUILD_HOST'
    $refused = $false
    try { & "$PSScriptRoot\ansible\roles\lab_seed\files\Prepare-Oobe.ps1" | Out-Null } catch {
        if ($_.Exception.Message -like 'OOBE preparation is allowed only*') { $refused = $true } else { throw }
    }
    if (-not $refused) { throw 'OOBE script accepted an ordinary host.' }
    'OobeGuard=REFUSED_NON_SETUP_HOST'
}
'PSVersion=' + $PSVersionTable.PSVersion
'LabPowerShellGate=PASS'
