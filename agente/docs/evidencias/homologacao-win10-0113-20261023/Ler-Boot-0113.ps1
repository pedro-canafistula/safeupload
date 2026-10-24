#Requires -Version 5.1
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Clone inesperado.'
$installed=Get-Content 'C:\Program Files\SafeUpload\Agent\setup\installation.json' -Raw|ConvertFrom-Json
Require ($installed.version -eq '0.1.13' -and $installed.commit -eq '008b4e367a1269bbc3b9d003e62bc1419ca0ef40') 'Versao inesperada.'
$until=[DateTime]::UtcNow.AddSeconds(60)
$ui=@();while([DateTime]::UtcNow -lt $until){$ui=@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'");if($ui.Count -eq 1){break};Start-Sleep -Seconds 2}
Require ($ui.Count -eq 1 -and $ui[0].ExecutablePath -eq 'C:\Program Files\SafeUpload\Agent\ui\SafeUpload.Agent.App.exe' -and $ui[0].SessionId -eq 1) 'UI automatica ausente ou inesperada.'
$parent=Get-CimInstance Win32_Process -Filter ('ProcessId='+$ui[0].ParentProcessId)
Require ($parent.Name -eq 'explorer.exe' -and $parent.SessionId -eq $ui[0].SessionId) 'UI nao iniciada por Explorer da sessao.'
$service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
Require ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem') 'Servico nao iniciou automaticamente.'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
Require (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Conferir com token sem elevacao.'
$pipe=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent',[IO.Pipes.PipeDirection]::In,[IO.Pipes.PipeOptions]::Asynchronous)
$reader=$null
try{
 $pipe.Connect(5000);$reader=[IO.StreamReader]::new($pipe);$status=$null;$history=$null
 for($i=0;$i -lt 6;$i++){$t=$reader.ReadLineAsync();Require ($t.Wait(5000)) 'Timeout no pipe';$m=$t.Result|ConvertFrom-Json;if($m.type -eq 'status'){$status=$m};if($m.type -eq 'history'){$history=$m};if($status -and $history){break}}
 Require ($status -and $history -and $history.available -and $status.auditOnly -and $status.policyVersion -eq 1 -and $status.protectionActive) 'Estado operacional divergente.'
 $events=@($history.events);Require ($events.Count -eq 21 -and @($events.eventId|Select-Object -Unique).Count -eq 21) 'Historico divergente.'
 [ordered]@{result='boot-startup-and-user-pipe-passed';collectedAtUtc=[DateTime]::UtcNow.ToString('o');bootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;administrator=$false;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;service=$service|Select-Object State,StartName,ProcessId;ui=$ui[0]|Select-Object ProcessId,ParentProcessId,CreationDate,SessionId;explorer=$parent|Select-Object ProcessId,CreationDate,SessionId;uiDelayAfterExplorerMs=($ui[0].CreationDate-$parent.CreationDate).TotalMilliseconds;status=$status;history=$history}|ConvertTo-Json -Depth 14
}finally{if($reader){$reader.Dispose()};$pipe.Dispose()}

