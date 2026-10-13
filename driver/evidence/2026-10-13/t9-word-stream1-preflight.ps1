$CleanupPlan=@'
[{"label": "t9-formula1", "name": "normal-release", "archiveSha256": "170B072FA5DE6320E9B44FEE899D267DC57E63CE21AD0F855F42FA1B8C253E91", "manifestSha256": "A68FC27E2D97266F1797C5280E47ECD07EB76820F9C924D1E2F30EECEE6241E0", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "8FABD06A95705069FF071CBFAF1E94CAFCD007BA68AB214A48839CE7A26DEC4D"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "708B1C1C0031E2B18EAC2B9BB69BA4130816A6E2F0C939EE9F8D8C13C4D66E58"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "9244EB7432CCE7C09D97875B5B7CBDA0E5B49D70401F62E18C569DC9AC54BE55"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "7F97CB57D1B6838BD421FDB3CA5C0960536570816ACE6D82D95DE6F4FA9C61CC"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "F1164457C85BAFB2799305A5DCAEDDA0A7580D3226240108E7DE178526DF3436"}]}, {"label": "t9-formula1", "name": "feature-release", "archiveSha256": "F071593CF06C4B71B2DA2CC5D25B1D687376E844E043669EF3C40E8700FB2B7D", "manifestSha256": "B2038215CBD67C39F77E5D04FA3A58520174C75CBFF418532D98C132C945471E", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "440D4AC9CEBE106DC195C6F78B05C0C0E469CC6ED20D50A4C6A247F5CF6C53DA"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "073237B3E64B8D2242EE7FE9DE5728C332ED16FCFC3B6471566A1D7584C926E0"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "0556D25A13F5229BB39003F88CF6CAB22754CE9C9885C4B0D7D0BE70B106CB01"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "5FD941AF8D475F3F6E0043601E3650C449A8125D15ED6E3005737FC644FC7128"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "7E6AEF0B309E8C72C51921F80B4A9D084221C42D6D984CCF44CE9D1C5D2C245D"}]}]
'@ | ConvertFrom-Json
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or
    -not @(Get-NetAdapter | Where-Object { $_.MacAddress -eq '52-54-00-63-87-7A' }).Count) {
    throw 'Wrong builder; cleanup refused.'
}
# $CleanupPlan is supplied from the retained host plan. Every ZIP was validated
# there against its manifest and original matrix summary before this action.
if (-not $CleanupPlan -or $CleanupPlan.Count -ne 2) { throw 'Unexpected cleanup plan.' }
$before = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace
$targets = @()
foreach ($item in $CleanupPlan) {
    if ($item.label -notin @('t9-formula1') -or
        $item.name -notin @('normal-release', 'feature-release')) { throw 'Unexpected build label/profile.' }
    $run = Join-Path 'C:\Users\vika\Documents' ('exact-agent-matrix-' + $item.label)
    $out = Join-Path $run 'out'
    $publish = Join-Path $out ($item.name + '-publish')
    $archive = Join-Path $out ($item.name + '-service-publish.zip')
    $manifest = Join-Path $out ($item.name + '-package-manifest.txt')
    foreach ($parent in @('C:\Users\vika\Documents', $run, $out)) {
        if ((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Cleanup parent is a reparse point.'
        }
    }
    foreach ($file in @($archive, $manifest)) {
        if ((Get-Item -LiteralPath $file).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Retained package input is a reparse point.'
        }
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $item.archiveSha256 -or
        (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ne $item.manifestSha256) {
        throw 'Remote retained package differs from verified host evidence.'
    }
    if (-not (Test-Path -LiteralPath $publish)) { throw 'Expected unpacked duplicate is absent.' }
    if ((Get-Item -LiteralPath $publish).Attributes -band [IO.FileAttributes]::ReparsePoint -or
        @(Get-ChildItem -LiteralPath $publish -Recurse -Force | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        }).Count) { throw 'Unpacked publication copy contains a reparse point.' }
    $actual = @(Get-ChildItem -LiteralPath $publish -Recurse -File -Force)
    if ($actual.Count -ne $item.files.Count) { throw 'Unpacked file inventory differs from retained package.' }
    $expected = @{}
    foreach ($file in $item.files) {
        if ($file.name -notmatch '^[A-Za-z0-9_.-]+$' -or $file.name -in @('.', '..') -or
            $file.sha256 -notmatch '^[A-F0-9]{64}$' -or $expected.ContainsKey($file.name)) {
            throw 'Invalid or duplicate unpacked package member.'
        }
        $expected.Add($file.name, $file.sha256)
    }
    foreach ($file in $actual) {
        $relative = $file.FullName.Substring($publish.Length + 1).Replace('\', '/')
        if (-not $expected.ContainsKey($relative) -or
            (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $expected[$relative]) {
            throw 'Unpacked publication copy is not an exact retained package duplicate.'
        }
    }
    if (@(Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -and $_.CommandLine.IndexOf($run, [StringComparison]::OrdinalIgnoreCase) -ge 0
    }).Count) { throw 'A process still references the completed build.' }
    $targets += [pscustomobject]@{ Publish = $publish; Archive = $archive; Manifest = $manifest; Item = $item }
}
# All scopes and hashes are checked before deleting any duplicate. Source,
# archives, manifests, summaries and test/build receipts stay in place.
foreach ($target in $targets) {
    Remove-Item -LiteralPath $target.Publish -Recurse -Force
    if (Test-Path -LiteralPath $target.Publish) { throw 'Unpacked duplicate remains.' }
    if ((Get-FileHash -LiteralPath $target.Archive -Algorithm SHA256).Hash -ne $target.Item.archiveSha256 -or
        (Get-FileHash -LiteralPath $target.Manifest -Algorithm SHA256).Hash -ne $target.Item.manifestSha256) {
        throw 'Retained package input changed during duplicate cleanup.'
    }
    Write-Output ('UNPACKED_DUPLICATE_REMOVED=' + $target.Item.label + '/' + $target.Item.name)
}
$after = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace
Write-Output "SCOPED_GENERATED_CLEANUP=PASS directories=$($targets.Count) free_before=$before free_after=$after source_packages_evidence_retained=True"
