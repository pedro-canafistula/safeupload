$CleanupPlan=@'
[{"label": "t5-native-volume1", "name": "normal-release", "archiveSha256": "838394BE702BACC340E7C40DCE953701A980D25DAF105254365EE4EAE06517C8", "manifestSha256": "959C9D9572BE61C36E4BB79EC54EF6FAF896AFE378450A227566A75C3B96932B", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "F43869CB7BCE4B921BB74C15D88FA08050D0795F442D25BABDE6F9717549EF2F"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "A2CCB18CA2D657F8E2D2B47C12A4E2237D58C65D257BC94991B8ED9D3F39BCAB"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "748A83EE60FF498F408384E95BC49E81C6D6AFC2DC93A4239E4A0D47C0792A32"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "0ECAB7E95E224720D914C1F3B81D4ADD3E8F07CB6775692FAE05CBF7E7F2D5B9"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "15D93B24721678E532EF9A63B43D3B424B573EE67E443AEC6F869970F9F1AA83"}]}, {"label": "t5-native-volume1", "name": "feature-release", "archiveSha256": "FA62A5062B6C1650A65C8D19A4EED208E919130C934A812A93AF381390F3A325", "manifestSha256": "BB792E349443D0D1EADB741A7ECA05F1E61090A635965A3B4AFD260971794008", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "A2227D9CA2519C8F0E0EDFE02681A55961452256A5BBBA44374316449FA87241"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "B579F56DA434313878ABFBF924134412BA163DD9F64C69725F220450E9CBCE6C"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "96C253CB423AD0BD03005B2783F7E48C8F5D34BD778C095E1FF76B4636A8FEA6"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "EE70BE49921234CA7EF9CAF6EF18116687ADBD6997EC2CA3D0BD0E0D81DDA569"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "1B02629A44F5EB6A67A15C21D14C71DC2B5C6C845AD19AE2EEEF97454081E4F5"}]}, {"label": "t5-ordinary-highwater1", "name": "normal-release", "archiveSha256": "7C2EF7E6E44507E235E1C463AE2DD324596312855548D601EAA7463B5C90D799", "manifestSha256": "EF85055244623BAC93C9F27A2B2C160C549F232E59071B6460DE1525B9B83A5A", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "5429C11DE0CD7F62A1CF3AB89982EBC8C70EBFC749F35C9C4C91949E729CAAE8"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "02127002AAB56A1C031993B6880EC427E7EEF085CAB764878125A159D166216E"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "9BFCEF49B6D1C0A444471BFDD45D84308913EB4679CED1387A0E631175C70843"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "11541C876779785EEB817BAB2171D5A32D002FE9581146F52E1E2D39FCA2940A"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "386CD25F83306E56DBC84F33155EDA0B1AEF79BDB7A4FA001753F6D1D95AC8DB"}]}, {"label": "t5-ordinary-highwater1", "name": "feature-release", "archiveSha256": "91AC4602D8FD8330ACB7A4E76C9DB4DBD5D0E6F24805C7A5080BA363D37BBB20", "manifestSha256": "3BF89B866CFB5AF15AED1FD8817B2D5C11DD238184F8F06CA5F722276ACE9D34", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "9CEE92D02404B17A6367ECAD947F6CE9DF9E8636857B8A52ECB5B0DD4A0C29F1"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "EBD2F750B893404644710FBFA4B32CCFFF8408EC05F76FA3304E570F489B2F5B"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "1A20EBAF5F3369A4C10B6E0DD49F3DFAF9E2CC99B83E8B78AE8407D8D9AE7D43"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "276C0F0A24EA3D8FB511A0D12016D994D33B4DB01119A9EF08ADE1E8B4093C52"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "B829B14CB226C2B4E539E39801400734720FF4638A9AA2749B7FCDAF6AFDF3DD"}]}]
'@ | ConvertFrom-Json
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or
    -not @(Get-NetAdapter | Where-Object { $_.MacAddress -eq '52-54-00-63-87-7A' }).Count) {
    throw 'Wrong builder; cleanup refused.'
}
# $CleanupPlan is supplied from the retained host plan. Every ZIP was validated
# there against its manifest and original matrix summary before this action.
if (-not $CleanupPlan -or $CleanupPlan.Count -ne 4) { throw 'Unexpected cleanup plan.' }
$before = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace
$targets = @()
foreach ($item in $CleanupPlan) {
    if ($item.label -notin @('t5-native-volume1', 't5-ordinary-highwater1') -or
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
