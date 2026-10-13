$CleanupPlan=@'
[{"label": "t5-bound-service3", "name": "normal-release", "archiveSha256": "0A57F18B752C54B7C415AE91A18733CA53F7233C0A22D022E37BD9E340014E8E", "manifestSha256": "FC14F2FF3F59CF494BD030BA27B993DF01B3067EA262A51DFFD79849690BDD91", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "8D74332B694A6AAE9A4F4E66E92465FA9FB5C92B54C8CA29F2B622BF074AC20B"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "7168EAC9DAE5C8DD9B74C9E90C5DF05B939C6F4286C2EB02F83F741162A0C9F6"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "EDC41A7BD1A6CEEE14A0F5F6954851E5266BF9953A9560B81419469438DF3137"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "8C3F865D9365C65C91249EB42879CDCC6359E66ADBEAF34744C7E61D1867495A"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "D768B2E92D42B13F3880EBEB5608FDC864C3FEBBEF55DB7A4C7E1603BC7D5DDA"}]}, {"label": "t5-bound-service3", "name": "feature-release", "archiveSha256": "1C78186BF9524FF4CCD8ED652149A79090C27AC39E3434F736778FE87DD3C99B", "manifestSha256": "137624AC6CBCBB2A1649B4C97AE39F8286D8053BC171874227ECAD3DDB7ECD1A", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "72134CE5ACA2B9FC480ADA9338A23C10BFA0EEA060673BDA37D6DA2CCAB0C45B"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "8FCC68C6FAF1008648F0406970FB0637ED2DC8C8F6B1F387B326A1F5ABDEDF6C"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "C8D9A30064B84C3566AA8B0E83FD66FDC48623497AC8136C67A3609D52A039C7"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "50046C643AB3962FAF49D9363D410146CD3C62EB1FEA7C9207B72DD3A3134328"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "DB2684A727AC9229CA7F376F8DF62E26B84F68DCA21DD5D802EBA1BED25151BF"}]}]
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
    if ($item.label -notin @('t5-bound-service3') -or
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
