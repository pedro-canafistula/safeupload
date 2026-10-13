$CleanupPlan=@'
[{"label": "t5-native-query2", "name": "normal-release", "archiveSha256": "956AC78E5A7A932C7031FD3DA379820681A3FCBF421F4B9D3EF3C3BFC9906627", "manifestSha256": "8D61CDD269EA4A29C5E0DCB0BA8456057CFBE0E189D1442BF4D6C457117BC62C", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "4D885F1A8BEAB5BD43B4A8CDCDC49B1EBAEDD4D83D9347BA5C55ADE3BA798346"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "4886D4DF410D1149770B15E1C95CC45E527146CEA160341EC1783DCA222E00B2"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "F75846C3488DC77FE8E4EAB8A040179782934B4F2B439E1E6BC3CF8DB81C49A1"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "7E207E69EC0C81B9CF39474BACD2E9DCCDE2529519F9280486832525A3501DBF"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "FB03751E34ED3C05562DA2DD58474410B545E4C614ADE2F8F325D5C647F23F22"}]}, {"label": "t5-native-query2", "name": "feature-release", "archiveSha256": "4F3A3553A610DF2859C164948B3E43917987108C4301CD05B544A0EEC43BBAA6", "manifestSha256": "8BE763E97712BF24EF958FA0D6648FD1E04D136EECC8663E91F10D35D4E1B518", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "10D7506576D882C628D8DDD875D6123FAEF6E4EC5FD65BF11AD5550554D30655"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "16C3A662B474DC3612590607DF521A7942194FD4B52EDCC356341F7F53C99E58"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "9B17C5DDBB149B91683FB389327225207103100841A85303093E6C693AB18203"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "5D9676263FF7E1EBA1A0CAE3A516531637AC4D20576C53257F6223A523BF72F4"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "1C8E4A8CC1836025EA0ED6F0210A62C83A91B857FA9D072988A947D86B0CA459"}]}, {"label": "t5-native-startup2", "name": "normal-release", "archiveSha256": "B593C3714181CFE837BC2E5A4B5650C58D69BA334B8464FD56FF0D7F72B1282E", "manifestSha256": "B14BD9DAAAD7D708568B34D2B8F1972CF8FCB5394314C204E53EB3DF3C83FC15", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "A0F03804D099437A4B16C602F86E817BE5DA758B4473AF05A4B59C13228102B1"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "749B96E8102B46DFCE0AE797CB321B1D9F0C6098EE611D5E7D966CDBB4A5B493"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "476978E54EA33B4A2C3AC08D08E52E38530F21D34E942EBE1E3D10CCDFAC8387"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "D0BF1B9F1A4BE86A304C6E07E357072ADAF96CEA3818015F408817E74CEAF692"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "951822550C1E8EC3046DB0023F8977B584F44659FA8EA255AD015ED081C01A0B"}]}, {"label": "t5-native-startup2", "name": "feature-release", "archiveSha256": "ACC03ECD853768BFA77004983A483540FDC7DA1B0724840AFF829CDFAE7B4CBD", "manifestSha256": "FCD4E174E73C6BF0E16E28985730837012E910D9ACE23F53E59D288FC307E01C", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "B8D28EDCC4820D505F035161CD9511E4DD23A6C037C259411CCC3EE9105BC027"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "0F2CB719C4506BC22864D93508E5202CBE96367F0C29DC07269F6BC902B5D739"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "7DCA367036A154E75874C4D0461AB52C2C3F78517185BE34F2F94BB4F1BF5CAF"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "140A3717320F0A7F412076D491D27AA273BEEE33E5A9F8CDE737ED71A0846BD5"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "DDC1784926E0C11A3E28406BC604BA71D7FA9FA4F7A5E7F9A259A0C3730985A4"}]}]
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
    if ($item.label -notin @('t5-native-query2', 't5-native-startup2') -or
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
