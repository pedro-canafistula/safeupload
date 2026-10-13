$CleanupPlan=@'
[{"label": "t9-word-stream3", "name": "normal-release", "archiveSha256": "AB53DB88A1749C69EC3E25A4316AF1548C1689FEB11E3FBFA763A1B454103BE0", "manifestSha256": "9E3388ECFFB5AF9F2FFF9595E324666AF2E45646128607A4D071365F91051141", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "5CD12637855D3CC87228B4E8CC3DDCC178B7C38EED1737EE397F793E0D5A7E0F"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "19309CAAAA3C1D187222436DF70D31744C0D24074DED322185EC951E539075FE"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "725EB925D4EF4AC792C789C054943B559EC2F880219298921CB3CB318EFE47A6"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "FD3F0292CC5D03B8FF12E4DDE0F7C58DB60C357385083BC7E2726F0E5009FE4E"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "E2B3195D27D9314681A5217A980996B0B8B786C92F23A7D70445A90CCD977AD8"}]}, {"label": "t9-word-stream3", "name": "feature-release", "archiveSha256": "FAF387D1564E27FFF39F6A0F115CBF52EDEB5D6A61A52859ED428EEE73287E6A", "manifestSha256": "1B0EAB47C1ABF9BBF00B96D65E7BCB50AEE4CA404E1B56E9C6B44239615097D1", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "0A2B6845DF10B98FCC77EACCBC7D8B8432EFCC349D507BA479BFF2523019CA7D"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "2139F555E5C2319CB1AA55465895E7C8C268B8BCBF8B43850C8CB8242EFECE72"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "9F42F79A52A42F5582A681E29ADC4B2C58D631A363B9361B8033F85570308BA9"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "64AE8B888F039B85BB03402A089CC0C8A6B90A84DB28750365A86A7F0466440E"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "619E91A312B35C02F1D6CB526D176C9ED84C29F2AB2299606AEEBB709E0108D6"}]}]
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
    if ($item.label -notin @('t9-word-stream3') -or
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
