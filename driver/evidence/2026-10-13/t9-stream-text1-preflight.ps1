$CleanupPlan=@'
[{"label": "t11-head-reads1", "name": "normal-release", "archiveSha256": "294E00B81E5E4DFF2163E1FC924A184A8AE7CD376F8DC22BF2CCDFE7E1FC3EAF", "manifestSha256": "EEF0809A2E15FB34A0FDF2516B0FEE44DB2B161F0E2DC0A9CCEE68A020543442", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "BB218F033BD71CCF7F441F71A19E1A38393436438ACE1571AF3665FA4AEE352B"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "FC7B0FFAAB92B15FE8FF20B424B7A88AEB97DDA89C08BE4613B29278AF931A4C"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "DD2714D76C5CCDD3FC24485156CBF1B0A325D034FD365FC6F08C81E33D12FD5C"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "F2B54295198A8EC31DAB3D0B1103A44E0A57655F636FA3F5132105D0069CCE7B"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "D7FF8967B1CFE775C855A05DD1E94F4483E1B862390E0C74274A1345C7201639"}]}, {"label": "t11-head-reads1", "name": "feature-release", "archiveSha256": "36F63C8E3CFE4833A4E4149893F6F5B5619CB459FB1462513AF273AD7A204886", "manifestSha256": "3D63458F9A49B33DE3837726BBFA6CBCAA468ADC577CB0FE7FA5572408F6BE2E", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "E8B9C41C472A68120782B0322B17A39E4DC8990AFD2E858A9C6237F4EBBDDD06"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "5783B4EC2AA0801F8797AD736C5DFF711A7E5E2C7CDDF65FEAAD1F7B87F1CAEA"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "0227B910CA5DEB94D981A0D9FA39CDD499BAEA757156EB0458FD2A8F686A289D"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "AA300A2E8DDBB8A3EA5577B820B6D6747379CF06B1D40412B9E44009FE60403B"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "09B8E3F209382C531950A0F5AE1425EC82DA6492E764FE78249D2917698C3D8B"}]}]
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
    if ($item.label -notin @('t11-head-reads1') -or
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
