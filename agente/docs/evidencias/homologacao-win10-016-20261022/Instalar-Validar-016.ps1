#Requires -Version 5.1
param([switch]$PreflightOnly)
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Restrito ao clone de homologacao.'
$root=Join-Path $env:ProgramFiles 'SafeUpload\Agent'
$data=Join-Path $env:ProgramData 'SafeUpload'
$queue=Join-Path $data 'queue.jsonl'
$policy=Join-Path $data 'policy.json'
$installer=Join-Path $PSScriptRoot 'SafeUploadAgent-0.1.6-win-x64-setup.exe'
$manifest=Get-Content (Join-Path $PSScriptRoot 'payload-manifest-016.json') -Raw | ConvertFrom-Json
$installed=Get-Content (Join-Path $root 'setup\installation.json') -Raw | ConvertFrom-Json
Require ((Get-FileHash $installer -Algorithm SHA256).Hash -eq '44D7A2751696F6B873CD50D15F1343829E268BCCF153677D744FD67521C6499C') 'Instalador divergente.'
Require ($manifest.version -eq '0.1.6' -and $manifest.commit -eq '0e9e05d1562f64d3b384a2426307d3644c9340f3' -and -not $manifest.sourceDirty) 'Manifesto divergente.'
Require ($installed.version -eq '0.1.5' -and $installed.commit -eq '3fa6986b938903f9abbafc0f696f1a043124672d' -and $installed.mode -eq 'FileSystemWatcher' -and [string]::IsNullOrEmpty($installed.adminBaseUrl)) 'Instalacao anterior inesperada.'
Require (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload')) 'Driver presente; ensaio interrompido.'
$service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
Require ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem' -and $service.PathName.StartsWith(('"'+(Join-Path $root 'service\SafeUpload.Agent.Service.exe')+'" '))) 'Servico inesperado.'
Require ((Get-FileHash (Join-Path $root 'service\SafeUpload.Agent.Service.dll') -Algorithm SHA256).Hash -eq '0880F288BF7F61310284BFD8C94CA5B001A8DCD61B7A4B5A004A07C29AE002E8') 'DLL anterior do servico divergente.'
Require ((Get-FileHash (Join-Path $root 'ui\SafeUpload.Agent.App.dll') -Algorithm SHA256).Hash -eq '96FA8DB54ED9B272681AEF36D82A196EC0E547C485A7D1A755384B731014D1DC') 'DLL anterior da UI divergente.'
if($PreflightOnly){[ordered]@{result='preflight-passed';installedVersion=$installed.version;candidateVersion=$manifest.version;service=$service.State;payloadFiles=@($manifest.files).Count} | ConvertTo-Json;return}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
Require (([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao local necessaria.'
$results=Join-Path $PSScriptRoot ('instalacao-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
New-Item -ItemType Directory -Path $results | Out-Null
$state=[ordered]@{result='running';vmUuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;startedAtUtc=[DateTime]::UtcNow.ToString('o');previousVersion=$installed.version;candidateVersion=$manifest.version;candidateCommit=$manifest.commit;uiStatus='pending';steps=@()}
function Save-State{$state | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $results 'result.json') -Encoding UTF8}
Save-State
try {
    Stop-Service SafeUploadAgent
    (Get-Service SafeUploadAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
    $state.queueHashBefore=(Get-FileHash $queue -Algorithm SHA256).Hash
    $state.policyHashBefore=(Get-FileHash $policy -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $queue -Destination (Join-Path $results 'queue-before.jsonl')
    Copy-Item -LiteralPath $policy -Destination (Join-Path $results 'policy-before.json')
    $uiPath=Join-Path $root 'ui\SafeUpload.Agent.App.exe'
    $oldUi=@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'" | Where-Object ExecutablePath -eq $uiPath)
    $state.stoppedUiPids=@($oldUi | ForEach-Object ProcessId)
    foreach($ui in $oldUi){Stop-Process -Id $ui.ProcessId -ErrorAction Stop}
    $uninstaller=Join-Path $root 'unins000.exe'
    Require ([IO.Path]::GetFullPath($uninstaller) -eq 'C:\Program Files\SafeUpload\Agent\unins000.exe') 'Destino da remocao inesperado.'
    $remove=Start-Process $uninstaller -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+(Join-Path $results 'uninstall-015.log')+'"'))
    Require ($remove.ExitCode -eq 0) ('Remocao falhou: '+$remove.ExitCode)
    Require (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent')) 'Servico anterior permanece registrado.'
    Require (-not (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) 'Startup anterior permanece registrado.'
    $state.queueHashAfterUninstall=(Get-FileHash $queue -Algorithm SHA256).Hash
    $state.policyHashAfterUninstall=(Get-FileHash $policy -Algorithm SHA256).Hash
    Require ($state.queueHashBefore -eq $state.queueHashAfterUninstall -and $state.policyHashBefore -eq $state.policyHashAfterUninstall) 'Remocao alterou dados.'
    $state.steps+='0.1.5 removed; service/startup absent and queue/policy hashes preserved'
    Save-State
    $setup=Start-Process $installer -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-','/MODE=FileSystemWatcher',('/LOG="'+(Join-Path $results 'install-016.log')+'"'))
    Require ($setup.ExitCode -eq 0) ('Instalacao falhou: '+$setup.ExitCode)
    $new=Get-Content (Join-Path $root 'setup\installation.json') -Raw | ConvertFrom-Json
    Require ($new.version -eq $manifest.version -and $new.commit -eq $manifest.commit -and $new.mode -eq 'FileSystemWatcher' -and [string]::IsNullOrEmpty($new.adminBaseUrl)) 'Proveniencia nova inesperada.'
    $newService=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
    Require ($newService.State -eq 'Running' -and $newService.StartName -eq 'LocalSystem') 'Novo servico inativo ou identidade divergente.'
    $state.installedFilesChecked=0
    foreach($entry in $manifest.files){
        $path=[IO.Path]::GetFullPath((Join-Path $root $entry.path))
        Require ($path.StartsWith(([IO.Path]::GetFullPath($root)+'\'),[StringComparison]::OrdinalIgnoreCase)) 'Caminho de payload fora da instalacao.'
        Require ((Get-FileHash $path -Algorithm SHA256).Hash -eq $entry.sha256) ('Hash instalado divergente: '+$entry.path)
        $state.installedFilesChecked++
    }
    $state.queueHashAfterInstall=(Get-FileHash $queue -Algorithm SHA256).Hash
    $state.policyHashAfterInstall=(Get-FileHash $policy -Algorithm SHA256).Hash
    Require ($state.queueHashBefore -eq $state.queueHashAfterInstall -and $state.policyHashBefore -eq $state.policyHashAfterInstall) 'Nova instalacao alterou dados anteriores.'
    $state.servicePid=$newService.ProcessId
    $state.steps+='0.1.6 installed; payload hashes matched and queue/policy unchanged'
    $state.result='installation-and-data-preservation-passed-ui-pending'
}catch{$state.result='failed';$state.error=$_.Exception.Message}
finally{
    $remaining=Get-Service SafeUploadAgent -ErrorAction SilentlyContinue
    if($remaining -and $remaining.Status -eq 'Stopped'){try{Start-Service SafeUploadAgent;$state.recovery='existing-service-started'}catch{$state.recovery=$_.Exception.Message}}
    $state.finishedAtUtc=[DateTime]::UtcNow.ToString('o')
    Save-State
}
