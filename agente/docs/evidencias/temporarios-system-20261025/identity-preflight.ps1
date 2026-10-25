#Requires -Version 7.5
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepositoryRoot, [string]$OutputPath)
$ErrorActionPreference='Stop'
if($OutputPath -and (Test-Path -LiteralPath $OutputPath)){throw 'Output exists.'}
$path=Join-Path $RepositoryRoot 'agente/installer/tests/Test-InstallerSmoke.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $path).Path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Smoke syntax errors.'}
$definition=@($ast.FindAll({param($n)
    $n -is [Management.Automation.Language.StringConstantExpressionAst] -and
    $n.Value.Contains('public static class SafeUploadInstallerPipeIdentity')
},$true))
if($definition.Count -ne 1){throw 'Identity helper missing or ambiguous.'}
if(-not ('SafeUploadInstallerPipeIdentity' -as [type])){Add-Type -TypeDefinition $definition[0].Value}
$name='SafeUpload.Identity.Preflight.'+[Guid]::NewGuid().ToString('N')
$server=[IO.Pipes.NamedPipeServerStream]::new($name,[IO.Pipes.PipeDirection]::InOut,1,
    [IO.Pipes.PipeTransmissionMode]::Byte,[IO.Pipes.PipeOptions]::Asynchronous)
$client=[IO.Pipes.NamedPipeClientStream]::new('.',$name,[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
try{
    $connected=$server.WaitForConnectionAsync()
    $client.Connect(5000)
    if(-not $connected.Wait(5000)){throw 'Owned pipe did not connect.'}
    [uint32]$observedServerPid=0
    if(-not [SafeUploadInstallerPipeIdentity]::GetNamedPipeServerProcessId($client.SafePipeHandle,[ref]$observedServerPid)){
        throw 'Native pipe peer query failed.'
    }
    if($observedServerPid -ne [Environment]::ProcessId){throw 'Owned pipe peer PID mismatch.'}
    $result=[ordered]@{status='passed';collectedUtc=[DateTime]::UtcNow.ToString('o');observedServerPid=$observedServerPid;
        expectedServerPid=[Environment]::ProcessId;nativePeerPidMatched=$true;systemServiceQualified=$false;
        serviceInstalled=$false;vmStarted=$false;note='Owned isolated pipe only, not SCM or SYSTEM qualification.'}
    $json=$result|ConvertTo-Json -Depth 4
    if($OutputPath){
        $stream=[IO.File]::Open($OutputPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes($json);$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
    }
    $json
}finally{$client.Dispose();$server.Dispose()}
