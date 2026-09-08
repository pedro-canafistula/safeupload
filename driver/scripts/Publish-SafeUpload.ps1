#Requires -Version 5.1
<#
.SYNOPSIS
    Builds, signs and packages the SafeUpload minifilter. Runs on the
    DEVELOPMENT VM only.

.DESCRIPTION
    Automates part A of DEPLOY.md: build, sign the driver, generate and sign
    the catalog, and write a manifest the target VM verifies against.

    Three things this script exists to get right, because all three have
    already gone wrong by hand:

    - Signing order. The catalog stores the hash of the files listed in the
      INF, so the .sys has to be signed BEFORE Inf2Cat runs. Doing it the
      other way round produces a catalog that does not match the driver.

    - Which hash to trust. Signing embeds a certificate and changes the
      file, so the build output and the packaged artifact have different
      hashes. The manifest records the hash of the SIGNED artifact, which is
      the only one worth comparing on the target.

    - Where the key lives. Signing happens from the certificate store, by
      thumbprint. No .pfx and no password: the .pfx is only useful for
      signing from a different machine.

.PARAMETER Configuration
    Debug (default) or Release.

.PARAMETER PackageDirectory
    Where the signed artifacts and the manifest are written.

.PARAMETER CertificateSubject
    Subject of the test signing certificate to look for in
    Cert:\CurrentUser\My.

.PARAMETER Analyze
    Also run Code Analysis with the driver rules. Slower.

.PARAMETER Serve
    After packaging, serve the package directory over HTTP so the target VM
    can pull it.

.PARAMETER Port
    Port for -Serve. Default 8000.

.EXAMPLE
    .\Publish-SafeUpload.ps1 -Serve

.EXAMPLE
    .\Publish-SafeUpload.ps1 -Configuration Release -Analyze
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug',

    [string] $PackageDirectory = 'C:\safeupload-pkg',

    [string] $CertificateSubject = 'CN=SafeUpload Test Signing',

    [switch] $Analyze,

    [switch] $Serve,

    [int] $Port = 8000,

    [string] $AdvertiseAddress,

    # Onde os resultados enviados pela VM alvo sao gravados. FORA do
    # diretorio servido de proposito: o que e servido por HTTP e legivel por
    # qualquer coisa na rede local, e um relatorio de execucao carrega
    # caminho de arquivo, nome de maquina e o que foi bloqueado.
    [string] $ResultsDirectory = 'C:\safeupload-resultados'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$KitRoot = 'C:\Program Files (x86)\Windows Kits\10'
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$SolutionPath = Join-Path $RepoRoot 'driver\SafeUpload.Driver.sln'
$InfPath = Join-Path $RepoRoot 'driver\SafeUpload.Minifilter\SafeUpload.inf'
$BuildOutput = Join-Path $RepoRoot "driver\x64\$Configuration"

# The probe is the battery's client: it shares Protocol.cs, FilterPort.cs
# and PolicyBuilder.cs with SafeUpload.Agent.Service, so the marshalling
# under test is the marshalling the product uses. What it does NOT share is
# the decision - the service runs InspectionService and the real rules,
# while the probe answers by a trivial one. That split is deliberate: a
# battery whose client ran the real rules would make every failure
# ambiguous between driver and agent.
$AgentProject = Join-Path $RepoRoot "agente\SafeUpload.Minifilter.Probe\SafeUpload.Minifilter.Probe.csproj"
$AgentPublish = Join-Path $RepoRoot "agente\SafeUpload.Minifilter.Probe\bin\Release\net10.0-windows\win-x64\publish"

# O servico de verdade: mesmo protocolo, mas quem decide e o InspectionService
# com as regras RN-001 a RN-004. Vai no pacote para a bateria poder exercitar
# a cadeia inteira, e nao so o driver contra um cliente trivial.
#
# Arquivo unico e autocontido, nao AOT: o servico usa DI e OpenXml, que o AOT
# poda mal. Autocontido resolve o mesmo problema pelo outro caminho - a VM alvo
# continua sem precisar de runtime .NET instalado. Comprimido sao 38 MB num
# arquivo so; sem PublishSingleFile seriam 231 arquivos e 86 MB, que o
# manifesto baixaria um a um.
$ServiceProject = Join-Path $RepoRoot "agente\SafeUpload.Agent.Service\SafeUpload.Agent.Service.csproj"
$ServicePublish = Join-Path $RepoRoot "agente\SafeUpload.Agent.Service\bin\Release\net10.0-windows\win-x64\publish"
$FixtureProject = Join-Path $RepoRoot "agente\SafeUpload.Fixtures\SafeUpload.Fixtures.csproj"
$FixtureDirectory = Join-Path $PackageDirectory "fixtures"

# Quanto conteudo vai nos .docx e .xlsx de teste.
#
# 40000 produz um .docx de ~126 KB e um .xlsx de ~229 KB, que custam 640 ms e
# 971 ms para extrair e varrer. O numero foi escolhido para ficar ACIMA do
# antigo prazo fixo de 500 ms: com fixture menor a bateria passaria mesmo se
# alguem voltasse a constante, e o teste nao defenderia nada. Documento de 100
# a 200 KB tambem e o tamanho de um contrato ou planilha de verdade.
$FixtureBulk = 40000

function Write-Step {
    param([string] $Text)
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Stop-WithMessage {
    param([string] $Text)
    Write-Host "ERRO: $Text" -ForegroundColor Red
    exit 1
}

function Resolve-MSBuild {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'

    if (-not (Test-Path $vswhere)) {
        Stop-WithMessage 'vswhere.exe nao encontrado. Visual Studio esta instalado?'
    }

    $installPath = & $vswhere -latest -products * -property installationPath | Select-Object -First 1

    if (-not $installPath) {
        Stop-WithMessage 'Nenhuma instalacao do Visual Studio encontrada.'
    }

    $candidate = Join-Path $installPath 'MSBuild\Current\Bin\MSBuild.exe'

    if (-not (Test-Path $candidate)) {
        Stop-WithMessage "MSBuild.exe nao encontrado em $candidate"
    }

    return $candidate
}

function Resolve-KitTool {
    <#
        Finds a Windows Kits tool without hard-coding the SDK version:
        newest version that actually contains the tool wins.
    #>
    param(
        [Parameter(Mandatory)] [string] $Architecture,
        [Parameter(Mandatory)] [string] $ToolName
    )

    $binRoot = Join-Path $KitRoot 'bin'

    $versions = Get-ChildItem $binRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^10\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version] $_.Name } -Descending

    foreach ($version in $versions) {
        $candidate = Join-Path $version.FullName "$Architecture\$ToolName"
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    Stop-WithMessage "$ToolName ($Architecture) nao encontrado em $binRoot. O WDK esta instalado?"
}

function Get-SigningCertificate {
    $matches = @(Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $CertificateSubject -and $_.HasPrivateKey })

    if ($matches.Count -eq 0) {
        Write-Host ''
        Write-Host "Nenhum certificado com assunto '$CertificateSubject' e chave privada." -ForegroundColor Red
        Write-Host 'Crie um seguindo a secao A.4 do DEPLOY.md.' -ForegroundColor Red
        exit 1
    }

    if ($matches.Count -gt 1) {
        Write-Host ''
        Write-Host "Mais de um certificado com assunto '$CertificateSubject':" -ForegroundColor Red
        $matches | ForEach-Object { Write-Host "  $($_.Thumbprint)  expira $($_.NotAfter)" }
        Write-Host 'Remova os antigos ou passe -CertificateSubject mais especifico.' -ForegroundColor Red
        exit 1
    }

    $certificate = $matches[0]

    if ($certificate.NotAfter -lt (Get-Date)) {
        Stop-WithMessage "O certificado $($certificate.Thumbprint) expirou em $($certificate.NotAfter)."
    }

    return $certificate
}

function Invoke-Checked {
    <#
        Runs a native tool and stops the script when it fails. Native
        executables do not raise, so $LASTEXITCODE has to be inspected by
        hand or a failure passes silently and corrupts everything downstream.
    #>
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [string] $Description
    )

    $output = & $FilePath @Arguments 2>&1

    if ($LASTEXITCODE -ne 0) {
        $output | ForEach-Object { Write-Host "  $_" }
        Stop-WithMessage "$Description falhou (codigo $LASTEXITCODE)."
    }

    return $output
}

# ---------------------------------------------------------------------------

Write-Step "Ferramentas"

$msbuild = Resolve-MSBuild
$signtool = Resolve-KitTool -Architecture 'x64' -ToolName 'signtool.exe'
$inf2cat = Resolve-KitTool -Architecture 'x86' -ToolName 'Inf2Cat.exe'
$certificate = Get-SigningCertificate

Write-Host "  MSBuild     : $msbuild"
Write-Host "  signtool    : $signtool"
Write-Host "  Inf2Cat     : $inf2cat"
Write-Host "  Certificado : $($certificate.Thumbprint)  (expira $($certificate.NotAfter.ToString('yyyy-MM-dd')))"

# ---------------------------------------------------------------------------

Write-Step "Compilando $Configuration x64"

$buildArguments = @(
    $SolutionPath,
    '/t:Rebuild',
    "/p:Configuration=$Configuration",
    '/p:Platform=x64',
    '/nologo',
    '/v:minimal'
)

if ($Analyze) {
    $ruleset = Join-Path $KitRoot 'CodeAnalysis\DriverRecommendedRules.ruleset'
    $buildArguments += @('/p:RunCodeAnalysis=true', '/p:EnablePREfast=true', "/p:CodeAnalysisRuleSet=$ruleset")
    Write-Host '  Com Code Analysis (regras de driver).'
}

# Not $buildOutput: PowerShell variable names are case insensitive, so that
# would silently overwrite $BuildOutput, the path this script needs later.
$buildLog = & $msbuild @buildArguments 2>&1

if ($LASTEXITCODE -ne 0) {
    $buildLog | ForEach-Object { Write-Host "  $_" }
    Stop-WithMessage 'A compilacao falhou.'
}

# The projects build with /WX, so any warning is already an error. This
# catches warnings raised outside the compiler, by MSBuild itself.
$warnings = @($buildLog | Select-String -Pattern ': warning ')

if ($warnings.Count -gt 0) {
    Write-Host '  Avisos na compilacao:' -ForegroundColor Yellow
    $warnings | ForEach-Object { Write-Host "    $($_.Line.Trim())" -ForegroundColor Yellow }
}

# ---------------------------------------------------------------------------

Write-Step 'Compilando a sonda do driver (Native AOT)'

# Native AOT, not a framework-dependent build: the target VM has no .NET
# runtime and is not going to get one. A framework-dependent binary dies
# there in the loader without printing anything, which is exactly how the
# C inspector failed on VCRUNTIME140D.dll.
#
# The MSVC linker that AOT invokes calls vswhere.exe, which is NOT on PATH
# by default even with Visual Studio installed. Without this the publish
# fails with "'vswhere.exe' is not recognized" attributed to link.exe - a
# message that names neither the cause nor the fix.
$vsInstaller = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'

if (Test-Path $vsInstaller) {
    $env:PATH = "$vsInstaller;$env:PATH"
}

$agentLog = & dotnet publish $AgentProject -c Release --nologo 2>&1

if ($LASTEXITCODE -ne 0) {
    $agentLog | ForEach-Object { Write-Host "  $_" }
    Stop-WithMessage 'A compilacao da sonda falhou.'
}

$agentExe = Join-Path $AgentPublish 'SafeUpload.Probe.exe'

if (-not (Test-Path $agentExe)) {
    Stop-WithMessage "A sonda nao foi produzida em $agentExe."
}

# Proves the managed structures still match the C_ASSERTs in Protocol.h.
# Cheap, needs no driver, and catches a contract drift here rather than on
# the target machine as a corrupted path.
$verify = & $agentExe --verify 2>&1

if ($LASTEXITCODE -ne 0) {
    $verify | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    Stop-WithMessage 'A sonda nao confere com o contrato do driver.'
}

Write-Host "  SafeUpload.Probe.exe ($([math]::Round((Get-Item $agentExe).Length / 1KB)) KB, nativo)"
Write-Host '  Contrato conferido contra Protocol.h.'

# ---------------------------------------------------------------------------

Write-Step 'Compilando o servico do agente (autocontido)'

$serviceLog = & dotnet publish $ServiceProject -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true --nologo 2>&1

if ($LASTEXITCODE -ne 0) {
    $serviceLog | ForEach-Object { Write-Host "  $_" }
    Stop-WithMessage 'A compilacao do servico falhou.'
}

$serviceExe = Join-Path $ServicePublish 'SafeUpload.Agent.Service.exe'

if (-not (Test-Path $serviceExe)) {
    Stop-WithMessage "O servico nao foi produzido em $serviceExe."
}

Write-Host "  SafeUpload.Agent.Service.exe ($([math]::Round((Get-Item $serviceExe).Length / 1MB, 1)) MB, autocontido)"

# ---------------------------------------------------------------------------

Write-Step 'Gerando os arquivos de teste (.docx e .xlsx)'

# Gerados aqui, nao na VM alvo: la nao ha Office nem SDK, e montar Open XML a
# mao em PowerShell seria codigo de teste mais fragil que o que ele testa.
#
# A ferramenta tambem MEDE, com os mesmos extratores que o servico usa, e
# falha quando nenhum achado sai dos arquivos que deveriam ter CPF. Um
# fixture que nao dispara nada faria a bateria passar por engano.
# Compilado e chamado direto, sem `dotnet run`: o `--` que separa os
# argumentos do SDK dos da aplicacao e consumido pelo PowerShell, que tem seu
# proprio significado para ele, e a ferramenta acaba recebendo argumentos
# trocados. O sintoma foi silencioso - os arquivos saiam com o tamanho padrao,
# no diretorio errado, sem erro nenhum.
$fixtureBuild = & dotnet build $FixtureProject -c Release --nologo -v quiet 2>&1

if ($LASTEXITCODE -ne 0) {
    $fixtureBuild | ForEach-Object { Write-Host "  $_" }
    Stop-WithMessage 'A compilacao do gerador de arquivos de teste falhou.'
}

$fixtureExe = Join-Path (Split-Path $FixtureProject) 'bin\Release\net10.0\SafeUpload.Fixtures.exe'

if (-not (Test-Path $fixtureExe)) {
    Stop-WithMessage "O gerador nao foi produzido em $fixtureExe."
}

$fixtureLog = & $fixtureExe $FixtureDirectory $FixtureBulk 2>&1

$fixtureLog | ForEach-Object { Write-Host "  $_" }

if ($LASTEXITCODE -ne 0) {
    Stop-WithMessage 'A geracao dos arquivos de teste falhou.'
}

Write-Host '  Compilado sem erros.' -ForegroundColor Green

# ---------------------------------------------------------------------------

Write-Step "Montando o pacote em $PackageDirectory"

if (-not (Test-Path $PackageDirectory)) {
    New-Item -ItemType Directory -Path $PackageDirectory -Force | Out-Null
}

# A stale catalog from a previous run would be signed and look valid while
# describing a driver that no longer exists.
Get-ChildItem $PackageDirectory -Filter '*.cat' -ErrorAction SilentlyContinue | Remove-Item -Force

$sources = @(
    (Join-Path $BuildOutput 'SafeUpload.sys'),
    (Join-Path $AgentPublish 'SafeUpload.Probe.exe'),
    (Join-Path $ServicePublish 'SafeUpload.Agent.Service.exe'),
    (Join-Path $FixtureDirectory 'contrato-com-cpf.docx'),
    (Join-Path $FixtureDirectory 'contrato-sem-nada.docx'),
    (Join-Path $FixtureDirectory 'planilha-com-cpf.xlsx'),
    $InfPath,

    # Served alongside the artifacts so the target VM always pulls the
    # version of the test script that matches this package, rather than
    # whatever copy happens to be sitting on its disk.
    (Join-Path $PSScriptRoot 'Invoke-SafeUploadTest.ps1')
)

foreach ($source in $sources) {
    if (-not (Test-Path $source)) {
        Stop-WithMessage "Artefato esperado nao existe: $source"
    }

    # A PowerShell script that does not parse is worse than a missing one:
    # it is published, downloaded, and fails on the target machine with an
    # error that says nothing about where it came from.
    if ([IO.Path]::GetExtension($source) -eq '.ps1') {

        $parseErrors = $null
        $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref] $null, [ref] $parseErrors)

        if ($parseErrors -and $parseErrors.Count -gt 0) {
            foreach ($parseError in $parseErrors) {
                Write-Host "  linha $($parseError.Extent.StartLineNumber): $($parseError.Message)" -ForegroundColor Red
            }
            Stop-WithMessage "$(Split-Path -Leaf $source) nao e sintaticamente valido."
        }

        # Variable names are case insensitive, so $foo and $Foo are the same
        # storage. Two spellings in one script means either a typo or, worse,
        # two different intents sharing a slot - which is how a path variable
        # ends up holding build output and a loop bound ends up holding an
        # array. Both have already happened here.
        $variableNames = $scriptAst.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.VariableExpressionAst] },
            $true) | ForEach-Object { $_.VariablePath.UserPath }

        $collisions = $variableNames |
            Group-Object { $_.ToLowerInvariant() } |
            Where-Object { @($_.Group | Select-Object -Unique).Count -gt 1 }

        if ($collisions) {
            foreach ($collision in $collisions) {
                Write-Host "  colisao de maiusculas: $(@($collision.Group | Select-Object -Unique) -join ' / ')" -ForegroundColor Red
            }
            Stop-WithMessage "$(Split-Path -Leaf $source) tem variaveis que diferem so em maiusculas."
        }
    }

    Copy-Item $source $PackageDirectory -Force
    Write-Host "  $(Split-Path -Leaf $source)"
}

# ---------------------------------------------------------------------------

Write-Step 'Assinando o driver'

# Before the catalog, never after: the catalog hashes the files the INF
# lists, and signing changes the .sys.
Invoke-Checked -FilePath $signtool -Description 'signtool sign (.sys)' -Arguments @(
    'sign', '/v', '/fd', 'sha256', '/sha1', $certificate.Thumbprint,
    (Join-Path $PackageDirectory 'SafeUpload.sys')
) | Out-Null

Write-Host '  SafeUpload.sys assinado.' -ForegroundColor Green

Write-Step 'Gerando o catalogo'

$catalogOutput = Invoke-Checked -FilePath $inf2cat -Description 'Inf2Cat' -Arguments @(
    "/driver:$PackageDirectory", '/os:10_x64'
)

$catalogPath = Join-Path $PackageDirectory 'safeupload.cat'

if (-not (Test-Path $catalogPath)) {
    $catalogOutput | ForEach-Object { Write-Host "  $_" }
    Stop-WithMessage 'Inf2Cat terminou sem gerar o catalogo.'
}

Write-Host '  safeupload.cat gerado.' -ForegroundColor Green

Write-Step 'Assinando o catalogo'

Invoke-Checked -FilePath $signtool -Description 'signtool sign (.cat)' -Arguments @(
    'sign', '/v', '/fd', 'sha256', '/sha1', $certificate.Thumbprint, $catalogPath
) | Out-Null

Write-Host '  safeupload.cat assinado.' -ForegroundColor Green

# ---------------------------------------------------------------------------

Write-Step 'Arquivando simbolos'

# Every publish produces a different binary, and a dump is only readable with
# the .pdb of the exact build that crashed. Overwriting symbols each time
# means that by the time a crash is investigated, the symbols for it are
# already gone - which is exactly what happened with the first bugcheck of
# this driver.
#
# Keyed by the hash of the signed .sys, so a dump can always be matched back
# to its symbols.
$symbolKey = (Get-FileHash (Join-Path $PackageDirectory 'SafeUpload.sys') -Algorithm SHA256).Hash.Substring(0, 16)
$symbolDirectory = Join-Path $PackageDirectory "symbols\$symbolKey"

New-Item -ItemType Directory -Path $symbolDirectory -Force | Out-Null

Copy-Item (Join-Path $PackageDirectory 'SafeUpload.sys') $symbolDirectory -Force
Copy-Item (Join-Path $BuildOutput 'SafeUpload.pdb') $symbolDirectory -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $AgentPublish 'SafeUpload.Probe.pdb') $symbolDirectory -Force -ErrorAction SilentlyContinue

$commit = (& git -C $RepoRoot rev-parse --short HEAD 2>&1)

Set-Content -Path (Join-Path $symbolDirectory 'build.txt') -Encoding UTF8 -Value @(
    "sha256  $((Get-FileHash (Join-Path $PackageDirectory 'SafeUpload.sys') -Algorithm SHA256).Hash)"
    "commit  $commit"
    "config  $Configuration"
    "data    $((Get-Date).ToUniversalTime().ToString('o')) UTC"
)

Write-Host "  symbols\$symbolKey  (commit $commit)"

Write-Step 'Certificado e ponto de entrada'

# The certificate's public half travels with the package: the target VM needs
# it in Root and TrustedPublisher. The .pfx deliberately does not.
$cerPath = Join-Path $PackageDirectory 'SafeUploadTest.cer'
Export-Certificate -Cert $certificate -FilePath $cerPath -Force | Out-Null
Write-Host '  SafeUploadTest.cer exportado (parte publica).'

# Address the target VM will reach this machine on. Baked into bootstrap.ps1
# so the operator does not have to type a URL twice.
if (-not $AdvertiseAddress) {
    $AdvertiseAddress = @(Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Sort-Object -Property InterfaceMetric |
        Select-Object -ExpandProperty IPAddress -First 1)
}

if (-not $AdvertiseAddress) {
    Stop-WithMessage 'Nenhum endereco IPv4 utilizavel. Passe -AdvertiseAddress.'
}

$sourceUrl = "http://${AdvertiseAddress}:$Port"

# The bootstrap is what the operator runs on the target VM. It carries the
# URL, fetches the current test script and hands control to it as a file, so
# that the script's #Requires -RunAsAdministrator still applies - it would be
# ignored if the script were merely piped into Invoke-Expression.
$bootstrap = @"
# Gerado por Publish-SafeUpload.ps1 em $((Get-Date).ToUniversalTime().ToString('o')) UTC.
# Nao edite: este arquivo e reescrito a cada publicacao.
`$ErrorActionPreference = 'Stop'

`$sourceUrl = '$sourceUrl'
`$target = Join-Path `$env:TEMP 'Invoke-SafeUploadTest.ps1'

Write-Host "Baixando o script de teste de `$sourceUrl ..." -ForegroundColor Cyan
Invoke-WebRequest "`$sourceUrl/Invoke-SafeUploadTest.ps1" -OutFile `$target -UseBasicParsing

# Escopo de processo apenas, e nao exige elevacao: evita que uma politica de
# execucao restritiva impeca rodar o script recem-baixado.
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

& `$target -SourceUrl `$sourceUrl
"@

$bootstrapPath = Join-Path $PackageDirectory 'bootstrap.ps1'

# UTF-8 WITHOUT a byte order mark. Set-Content -Encoding UTF8 writes one on
# Windows PowerShell, and this file is fetched with Invoke-RestMethod and fed
# to Invoke-Expression: the BOM survives as a literal character and the first
# statement fails with "the term 'i»¿#' is not recognized".
[System.IO.File]::WriteAllText($bootstrapPath, $bootstrap, (New-Object System.Text.UTF8Encoding($false)))

Write-Host '  bootstrap.ps1 gerado.'

Write-Step 'Manifesto'

# bootstrap.ps1 is deliberately absent: it is the entry point, and nothing
# can verify itself before it runs.
$artifactNames = @(
    'SafeUpload.sys',
    'SafeUpload.inf',
    'safeupload.cat',
    'SafeUpload.Probe.exe',
    'SafeUpload.Agent.Service.exe',
    'contrato-com-cpf.docx',
    'contrato-sem-nada.docx',
    'planilha-com-cpf.xlsx',
    'SafeUploadTest.cer',
    'Invoke-SafeUploadTest.ps1'
)
$artifacts = @()

foreach ($name in $artifactNames) {
    $path = Join-Path $PackageDirectory $name
    $item = Get-Item $path
    $hash = (Get-FileHash $path -Algorithm SHA256).Hash

    $artifacts += [pscustomobject]@{
        name   = $name
        length = $item.Length
        sha256 = $hash
    }

    Write-Host ("  {0,-26} {1,8} bytes  {2}" -f $name, $item.Length, $hash.Substring(0, 16))
}

$manifest = [pscustomobject]@{
    configuration = $Configuration
    builtUtc      = (Get-Date).ToUniversalTime().ToString('o')
    thumbprint    = $certificate.Thumbprint
    files         = $artifacts
}

$manifestPath = Join-Path $PackageDirectory 'manifest.json'
$manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $manifestPath -Encoding UTF8

Write-Host "  manifest.json escrito." -ForegroundColor Green

# ---------------------------------------------------------------------------

Write-Host ''
Write-Host 'Pacote pronto.' -ForegroundColor Green
Write-Host ''

if (-not $Serve) {
    Write-Host 'Para servir para a VM alvo:'
    Write-Host '  .\Publish-SafeUpload.ps1 -Serve'
    return
}

Write-Step "Servindo $PackageDirectory na porta $Port"

Write-Host ''
Write-Host '  Na VM alvo, em um PowerShell ELEVADO, um comando so:' -ForegroundColor Yellow
Write-Host ''
Write-Host "    iex (irm $sourceUrl/bootstrap.ps1)" -ForegroundColor Green
Write-Host ''
Write-Host '  Ele baixa a versao atual do script de teste, executa, e devolve' -ForegroundColor DarkGray
Write-Host '  o relatorio para ca no fim - sem captura de tela no meio.' -ForegroundColor DarkGray
Write-Host '  Para opcoes (-SkipSmokeTest, -SkipDownload), rode depois:' -ForegroundColor DarkGray
Write-Host '    & $env:TEMP\Invoke-SafeUploadTest.ps1 -SkipDownload -SkipSmokeTest' -ForegroundColor DarkGray

$firewallRule = 'SafeUpload deploy (temp)'

if (-not (Get-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue)) {
    try {
        New-NetFirewallRule -DisplayName $firewallRule -Direction Inbound -Protocol TCP `
            -LocalPort $Port -Action Allow -ErrorAction Stop | Out-Null
        Write-Host "  Regra de firewall '$firewallRule' criada." -ForegroundColor Green
    }
    catch {
        Write-Host "  Nao foi possivel criar a regra de firewall (falta elevacao?)." -ForegroundColor Yellow
        Write-Host '  Se a VM alvo nao conectar, e isto.' -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host 'Ctrl+C para parar o servidor.'
Write-Host ''

Write-Host "  Resultados da VM alvo serao gravados em $ResultsDirectory." -ForegroundColor Green
Write-Host ''

& python (Join-Path $PSScriptRoot 'serve.py') $PackageDirectory $ResultsDirectory $Port
