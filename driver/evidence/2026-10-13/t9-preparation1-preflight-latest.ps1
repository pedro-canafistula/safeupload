$CleanupPlan=@'
[{"label": "t9-office-payload1", "name": "normal-release", "archiveSha256": "D6EAAF9E7742AA3EA51840E8507D35CA3CCA78B9F794C27A0229A206FA195632", "manifestSha256": "C1B7A22163616E1AEEEF92BC009DF595E9D2CFDA7B8ED222880CC5C5B84E70BD", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "8DC8FE41C56FD34EA056204E6FCB8C47CAAEFFB7438D9E9283A4C27C2C09F1A1"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "F863C3486868453B21322FCB0A05BDC2495FD6C6A5B781E630C6A12B59ED03FF"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "3ED2A8577DECFD002D450CC73B3B0308484EFC4F8BA73FDA1F1464F13D1C9551"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "56BD22FA5E67C2CFDCEAA6DCE6795134C5F9317C9392ABAC9A9580AD67903DA2"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "18C41FB74D490DF9C03C4A9C7C2C01538DABA22A6045C559DAAF1DC53E677999"}]}, {"label": "t9-office-payload1", "name": "feature-release", "archiveSha256": "25D7E028CB941FA7E995370B3ECFC9B873717830646DE20E91938116447B7EB1", "manifestSha256": "8B9CA84E1D8776712377B94F4C6A2F6AA1591355453A4B95DF6F66844F08EDB6", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "A45FD5EF092982041E2CD72783F701134ACD563BA8FFE0B1CBE9394DF4AF0246"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "1F82CCBFBFD6F2892E02858848F10F4209FF6DE166BBDAC84C293EBDE0D13377"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "B3058BD40DBC8C3221B3C4A3DFE8277D44578D3EA3973E692188521A111A1219"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "D3E61974DB576F47EA7DC672C1ECF97EBD5E841B0D33742BDF17FD12BE4B5DC7"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "610C60622E846B98FB559974BD9C21C0D850E999EC9BD5AAFF8F8F5D18CF3ED3"}]}]
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
    if ($item.label -notin @('t9-office-payload1') -or
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
