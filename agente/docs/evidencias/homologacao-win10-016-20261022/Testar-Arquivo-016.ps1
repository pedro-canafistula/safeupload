#Requires -Version 5.1
# O chamador define $testKind como Clean ou Cpf; somente dados sinteticos.
$ErrorActionPreference='Stop'
if($testKind -notin @('Clean','Cpf')){throw 'Cenario inesperado'}
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '3a9992db-4644-405c-b642-9766edd10650'){throw 'Clone inesperado'}
$installed=Get-Content 'C:\Program Files\SafeUpload\Agent\setup\installation.json' -Raw | ConvertFrom-Json
if($installed.version -ne '0.1.6' -or $installed.commit -ne '0e9e05d1562f64d3b384a2426307d3644c9340f3' -or $installed.mode -ne 'FileSystemWatcher'){throw 'Versao inesperada'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$administrator=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($administrator){throw 'Executar fixture como usuario sem elevacao'}
$name='homologacao-016-'+$testKind.ToLowerInvariant()+'-'+[Guid]::NewGuid().ToString('N')+'.txt'
$path=Join-Path 'C:\SafeUpload\Escopo Monitorado' $name
$content=if($testKind -eq 'Cpf'){'CPF de teste: 529.982.247-25'}else{'Relatorio sintetico sem dados pessoais.'}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes($content)
$pipe=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent',[IO.Pipes.PipeDirection]::In,[IO.Pipes.PipeOptions]::Asynchronous)
$reader=$null
try {
    $pipe.Connect(5000)
    $reader=[IO.StreamReader]::new($pipe)
    $status=$null;$history=$null
    for($i=0;$i -lt 5;$i++){
        $line=$reader.ReadLineAsync()
        if(-not $line.Wait(5000)){throw 'Timeout lendo estado inicial'}
        $message=$line.Result | ConvertFrom-Json
        if($message.type -eq 'status'){$status=$message}
        if($message.type -eq 'history'){$history=$message}
        if($status -and $history){break}
    }
    if(-not $status -or -not $history -or -not $history.available -or -not $status.auditOnly){throw 'Estado inicial inesperado'}
    [IO.File]::WriteAllBytes($path,$bytes)
    $deadline=[DateTime]::UtcNow.AddSeconds(20)
    $eventMessage=$null
    while([DateTime]::UtcNow -lt $deadline){
        $line=$reader.ReadLineAsync()
        $remaining=[int][Math]::Max(1,($deadline-[DateTime]::UtcNow).TotalMilliseconds)
        if(-not $line.Wait($remaining)){throw 'Sem notificacao da fixture'}
        if($null -eq $line.Result){throw 'Pipe encerrado'}
        $message=$line.Result | ConvertFrom-Json
        if($message.type -eq 'event' -and $message.event.fileName -eq $name){$eventMessage=$message;break}
    }
    if(-not $eventMessage){throw 'Evento nao recebido'}
    $expected=if($testKind -eq 'Cpf'){'Blocked'}else{'Approved'}
    if($eventMessage.event.verdict -ne $expected -or $eventMessage.event.sizeBytes -ne $bytes.Length){throw 'Veredito ou tamanho divergente'}
    $moved=@(Get-ChildItem 'C:\SafeUpload\_bloqueados' -File -Filter ([IO.Path]::GetFileNameWithoutExtension($name)+'-*.txt'))
    if($testKind -eq 'Cpf'){
        if(-not $eventMessage.quarantined -or (Test-Path $path) -or $moved.Count -ne 1){throw 'Movimentacao nao confirmada'}
        if([IO.File]::ReadAllText($moved[0].FullName) -ne $content){throw 'Conteudo movido divergente'}
        if($eventMessage.event.categories -notcontains 'Cpf'){throw 'CPF ausente'}
    }else{
        if($eventMessage.quarantined -or -not (Test-Path $path) -or $moved.Count -ne 0){throw 'Arquivo limpo movido indevidamente'}
    }
    [ordered]@{
        result='fixture-and-notification-passed-ui-observation-pending'
        collectedAtUtc=[DateTime]::UtcNow.ToString('o')
        testKind=$testKind
        administrator=$administrator
        processSession=[Diagnostics.Process]::GetCurrentProcess().SessionId
        initialHistoryCount=@($history.events).Count
        fileName=$name
        event=$eventMessage
        sourceExists=(Test-Path $path)
        quarantinedFile=@($moved | Select-Object Name,FullName,Length)
    } | ConvertTo-Json -Depth 12
}finally{if($reader){$reader.Dispose()};$pipe.Dispose()}
