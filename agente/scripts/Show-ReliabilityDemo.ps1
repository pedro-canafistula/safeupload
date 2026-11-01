param([switch]$Video, [int]$Port = 18081, [switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$project = Join-Path $root 'agente/SafeUpload.Agent.ContractSmoke/SafeUpload.Agent.ContractSmoke.csproj'
$jar = Join-Path $root 'web/back/target/backend-0.1.0.jar'
if (-not (Test-Path -LiteralPath $jar)) { throw 'Compile o backend: mvn -B -f web/back/pom.xml package -DskipTests' }
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    throw "Porta $Port já está ocupada. Escolha outra com -Port."
}
if (-not $SkipBuild) {
    & dotnet build $project --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw 'Build da demonstração falhou.' }
}
$demoRoot = Join-Path ([IO.Path]::GetTempPath()) ('safeupload-demo-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $demoRoot | Out-Null
$url = "http://127.0.0.1:$Port/agent/"
$server = $null
function Start-DemoBackend {
    param([string]$Label)
    $process = Start-Process java -WindowStyle Hidden -PassThru -ArgumentList @(
        '-jar', ('"' + $jar + '"'), "--server.port=$Port", '--server.address=127.0.0.1',
        '--spring.datasource.url=jdbc:h2:mem:reliability', '--spring.jpa.hibernate.ddl-auto=create-drop'
    ) -RedirectStandardOutput (Join-Path $demoRoot "$Label.out.log") -RedirectStandardError (Join-Path $demoRoot "$Label.err.log")
    try {
        for ($attempt = 0; $attempt -lt 45; $attempt++) {
            if ($process.HasExited) { throw "Backend terminou. Veja $demoRoot" }
            try { Invoke-RestMethod ($url + 'policy') -TimeoutSec 1 | Out-Null; return $process }
            catch { Start-Sleep -Milliseconds 500 }
        }
        throw 'Backend não iniciou no prazo.'
    } catch { if (-not $process.HasExited) { Stop-Process -Id $process.Id }; throw }
}
function Show-Phase {
    param([string]$Phase)
    & dotnet run --no-build --project $project -- --reliability-demo $Phase $demoRoot $url
    if ($LASTEXITCODE -ne 0) { throw "Demonstração falhou: $Phase" }
    if ($Video) { Start-Sleep -Seconds 9 }
}
try {
    $server = Start-DemoBackend 'online'
    Show-Phase 'online'
    Stop-Process -Id $server.Id
    $server.WaitForExit()
    $server = $null
    Show-Phase 'offline'
    $server = Start-DemoBackend 'recover'
    Show-Phase 'recover'
    Write-Host "Evidências preservadas: $demoRoot"
} finally {
    if ($null -ne $server -and -not $server.HasExited) { Stop-Process -Id $server.Id }
}
