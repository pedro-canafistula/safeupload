$CleanupPlan=@'
[{"label": "t9-sheet-stream1", "name": "normal-release", "archiveSha256": "89CCD4B532BBB97241D4BF193AF5A14C3E8D4281FDFD311313F1D76D57FCE77B", "manifestSha256": "3D20856E778F39EE3C074F326D97431734042041AEF24AC3C0E45B4DC4B28004", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "B5DB9073DC8D0D5EB8FFA15968A9E6FAE5475F0823E551CF5965546695B12C45"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "BEFEF7392CCD2C2F893D1F54C4E1290B7F9BB0117DFCD703F384D9F777484E25"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "E21020FF971F33F6243AA3545F91C28D5D6B43ECC444AD55566FCD517C6C4B6D"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "267761D42E0EDF10F087A78FFAFBCB47D8B0C7CAFBFD675B48225C426C1DA5DA"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "EBA1C99CC39B9C441A2BBDD65015F80ECD5CAD930BC5723A3333E420C0B977F5"}]}, {"label": "t9-sheet-stream1", "name": "feature-release", "archiveSha256": "D2B7412E350F1353DD0A224219B3EC4641E1AF8E05F6FA70A99B92885878F42F", "manifestSha256": "8D40ABACAD170401C86FBE15C458DA3DC4DF5ED3C5990B3EBC3831F70780A6A3", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "DDE8412D4F9C442D54C3E63308C26DD636210B20BAB1D4FC8762B7AF767E0F89"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "B802908EC75CBEF88005437B8B7F6C22C9A550968B1269158A35DCDDD29DE33D"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "11CC173D0C46F531BC8D6547E4F659E5181E624C5700C536D33B220002726A19"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "6797B44E39F6A3CB78D78092E571ACB2CCA6B949CF1077899EF694555725DDBC"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "3075C8781FD21281B5B316D81F9CC85B8FD17E419EFBBC5BCE1CABC2D32ADF3D"}]}]
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
    if ($item.label -notin @('t9-sheet-stream1') -or
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
