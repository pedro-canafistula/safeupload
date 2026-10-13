$CleanupPlan=@'
[{"label": "t5-native-lifecycle3", "name": "normal-release", "archiveSha256": "FA5D6B11F79BB75CA61E7B9A623949961AB9BB3394AF7C8C0323E911204ED470", "manifestSha256": "7E058DA2931BB1001771F8945C8DA84847924E6640030A0A0E2D26992D62268B", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "0AC350D85D02AD3C17F5EF5F494A8AAEE5F00BA8976998C01795EFE1365DADFC"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "EDBA1F99B9DD9ED1917C7A0B6BF50EE28450D31514D92D186FEAAA9F0937836D"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "C2C1B1EE2ADCDE01B8028703C562FE13C9B316780903B464E8837B12CB290D9A"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "802D65CFD097C1376A600BE49FF077872C4367CE0586719E0F11A5E693B39967"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "66093748A33928EE356C0DF66599F107C1B81061A08E234EA64C142C66DCDF8D"}]}, {"label": "t5-native-lifecycle3", "name": "feature-release", "archiveSha256": "C2217C7A68CF74434684164493824CDEF30977DB0D806E079D84F542B250CD46", "manifestSha256": "96D542F79A62DC534D53626DBB7008F2679BD1CAE9F83192467619ACB4C8CA87", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "6B9CFDB82F47697D44099FC99E966146D824161FE9B26F079AC1E7B845B794CB"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "81CD8EB9D34596E382FFAB800FD136F99231BE42F8AA6736FB81047453B094A6"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "3B2E977F2DC210D74BCD18D76D97A1F63235326EA30A9AEA71C0DDF61DC0273E"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "9A4C25C51D34BC83070EC444DC38F830F7808607B9B239D10C421614D7DD14D1"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "0BE723749855C1924D225124B8F3B6B38CD2C580BD1E43B8F6E92EF9C706E3B6"}]}, {"label": "t5-native-recovery2", "name": "normal-release", "archiveSha256": "B822E77F1953971A5F9575709B6B665A84D590DE65441B0B5891D3E6630260ED", "manifestSha256": "966B15F49C163E66BEE2E17171CF8B5EE41FD1E6C6BADCB34AE6F5EF7835C36E", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "A73BE2B2CBB07CDBE648EF33614D742C93D4A5BE91B6CB4B0AF1A8816CC26A99"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "BC2A4F566562BA2B7DB7A5D63C08C411F7A7032CEA91982AA365E1316499B1DE"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "EF5E3BFF86810A3584F1AF9965F8EC898B2BD804008C49F1F335DEFAC6FA1315"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "5A83C0A1ADDF0B770F0F7663A229BEFB8257B7F7953E0259BB895E1C166A1BF2"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "FFCA076B45E68713D1C7D62E78E149C89C705B764F86F8965695E899619CEB38"}]}, {"label": "t5-native-recovery2", "name": "feature-release", "archiveSha256": "ED055A11C14635C270952F603FEB9F7A841C43D54D97CE1503C789F045DD5745", "manifestSha256": "FCE92ACBC733ABB5EF665595CEBA251ABD8967489385083E6DCEF2898AC28D6B", "files": [{"name": "appsettings.json", "sha256": "ADE4FAA45582090F6A8FD302D353C51A43C70386016363B33754AEC9FBA5535E"}, {"name": "SafeUpload.Agent.Core.pdb", "sha256": "CFE154DF6B1BDAA45505A55B321A9DBB89780FCAF08C5B571454091B2466E351"}, {"name": "SafeUpload.Agent.Minifilter.pdb", "sha256": "ED589A21BA7C1750FA2BEFBFF133BE696995857713ADA1143B97716A4632DCBF"}, {"name": "SafeUpload.Agent.Network.pdb", "sha256": "929A1121843426983A914C915F4BBF8F413C54332A4F42FF8D56D7E71E9F41C8"}, {"name": "SafeUpload.Agent.Service.exe", "sha256": "66AF6926A91FCB17BD95DA07721FE5399A325C8C3289CAEFCE51E1429B0499B6"}, {"name": "SafeUpload.Agent.Service.pdb", "sha256": "947263E7744C3FF35BA88D3DC63EBCBD624B55C007C6C968167DEFF0A1FBF8DE"}]}]
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
    if ($item.label -notin @('t5-native-lifecycle3', 't5-native-recovery2') -or
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
