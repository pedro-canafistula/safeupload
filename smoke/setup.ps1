# Runs as the VM administrator: installs SafeUpload from C:\Users\vika\Documents\su with a test policy.
$ErrorActionPreference = 'Stop'
$su = 'C:\Users\vika\Documents\su'
Expand-Archive -LiteralPath "$su\pkg.zip" -DestinationPath "$su\pkg" -Force
Expand-Archive -LiteralPath "$su\driver.zip" -DestinationPath "$su\driver" -Force
New-Item -ItemType Directory -Force -Path C:\T5 | Out-Null

# A test share; the agent publishes to it as SYSTEM (here over the loopback).
New-Item -ItemType Directory -Force -Path C:\Compartilhado | Out-Null
if (-not (Get-SmbShare -Name Compartilhado -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name Compartilhado -Path C:\Compartilhado -FullAccess 'Everyone' | Out-Null
}
& icacls.exe C:\Compartilhado /grant 'Everyone:(OI)(CI)M' | Out-Null

# Test policy: a local folder and a share protected, USB protected, justification allowed; the clipboard blocks pastes
# into egress apps, one custom rule ("Projeto Atlas"), and web inspection on with one exception domain (web-test.ps1).
New-Item -ItemType Directory -Force -Path C:\ProgramData\SafeUpload | Out-Null
$policy = @'
{
  "version": 2,
  "activeCategories": ["Cpf", "Cnpj", "PaymentCard", "Password", "Secret", "CustomRule"],
  "monitoredScopes": {
    "extensions": [".txt", ".csv", ".docx", ".xlsx", ".pdf", ".pptx", ".zip"],
    "destinationPaths": ["C:\\SafeUpload\\Envios", "\\\\localhost\\Compartilhado"],
    "removableDrives": true,
    "networkPaths": false
  },
  "overrideAllowed": true,
  "excludedProcesses": ["System", "SafeUpload.Agent.App"],
  "clipboard": { "mode": "Block" },
  "customRulesFormat": 1,
  "customRules": [ { "id": 1, "revision": 1, "name": "Projeto Atlas", "alert": false,
    "when": { "all": [ { "words": ["projeto atlas"] },
                       { "pattern": "CT\\-[0-9][0-9][0-9][0-9]\\/[0-9][0-9]", "ignoreCase": true, "min": 2 } ] } } ],
  "web": { "inspect": true, "exceptionDomains": ["excecao.safeupload.test"] }
}
'@
[IO.File]::WriteAllText('C:\ProgramData\SafeUpload\policy.json', $policy, (New-Object Text.UTF8Encoding($false)))
& "$su\scripts\Protect-SafeUploadPolicy.ps1" -PolicyPath C:\ProgramData\SafeUpload\policy.json | Out-Null

& "$su\scripts\Install-SafeUploadAgent.ps1" -PackagePath "$su\pkg" -DriverPath "$su\driver" -WinFspMsi "$su\winfsp.msi" -AdminBaseUrl ''
