<# Run from the debugger VM's isolated checkout. No install/deploy action. #>
param(
    [string] $OutputDirectory = (Join-Path $env:USERPROFILE 'Documents\owned-milestone'),
    [string] $CertificateThumbprint
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$msbuild = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
$rules = 'C:\Program Files (x86)\Windows Kits\10\CodeAnalysis\DriverRecommendedRules.ruleset'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
Push-Location $root
try {
    # Native x64 MSBuild selects the x64 WDK API extractor. The x86
    # extractor rejects optimized x64 binaries with ERROR_BAD_EXE_FORMAT.
    foreach ($configuration in @('Debug','Release')) {
        foreach ($feature in @('false','true')) {
            $label = if ($feature -eq 'true') { 'owned-feature' } else { 'normal' }
            if ($configuration -eq 'Release') { $label += '-release' }
            $log = Join-Path $OutputDirectory ($label + '-wdk.txt')
            & $msbuild driver\SafeUpload.Minifilter\SafeUpload.Minifilter.vcxproj /t:Rebuild `
                "/p:Configuration=$configuration" /p:Platform=x64 /warnaserror "/p:SafeUploadStagingPrototype=$feature" `
                /p:RunCodeAnalysis=true /p:EnablePREfast=true "/p:CodeAnalysisRuleSet=$rules" > $log 2>&1
            if ($LASTEXITCODE -ne 0) { Get-Content $log -Tail 40 | Out-Host; throw "$label WDK build failed." }
            Get-Content $log -Tail 5 | Out-Host
            Copy-Item "driver\SafeUpload.Minifilter\x64\$configuration\SafeUpload.sys" (Join-Path $OutputDirectory ($label + '.sys')) -Force
        }
    }
    $driver = Join-Path $OutputDirectory 'SafeUpload-stage-prototype.sys'
    Copy-Item (Join-Path $OutputDirectory 'owned-feature.sys') $driver -Force
    if ($CertificateThumbprint) {
        & 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe' sign `
            /fd sha256 /sha1 $CertificateThumbprint $driver
        if ($LASTEXITCODE -ne 0) { throw 'Driver test signing failed.' }
    }
    Get-FileHash -LiteralPath $driver -Algorithm SHA256 | Format-List | Out-Host
    $log = Join-Path $OutputDirectory 'agent-tests.txt'
    & dotnet test agente\SafeUpload.Agent.Tests\SafeUpload.Agent.Tests.csproj --nologo `
        --logger 'trx;LogFileName=owned-tests.trx' --results-directory $OutputDirectory > $log 2>&1
    if ($LASTEXITCODE -ne 0) { Get-Content $log -Tail 60 | Out-Host; throw 'Agent tests failed.' }
    Get-Content $log -Tail 6 | Out-Host
    $publish = Join-Path $OutputDirectory 'service'
    $log = Join-Path $OutputDirectory 'service-build.txt'
    & dotnet publish agente\SafeUpload.Agent.Service\SafeUpload.Agent.Service.csproj -c Release `
        -r win-x64 --self-contained true -o $publish --nologo > $log 2>&1
    if ($LASTEXITCODE -ne 0) { Get-Content $log -Tail 40 | Out-Host; throw 'Service build failed.' }
    Compress-Archive -Path (Join-Path $publish '*') -DestinationPath (Join-Path $OutputDirectory 'stage-service-publish.zip') -Force
}
finally { Pop-Location }
