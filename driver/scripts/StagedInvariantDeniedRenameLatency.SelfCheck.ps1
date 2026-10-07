#requires -Version 5.1
# Real native ABI stimulus on the builder, using a disposable ACL-denied target.
# It proves the actor's 101 native denial sequences, never driver qualification.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse failed'}
$definition=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-WriterBody'},$false))
if($definition.Count -ne 1){throw 'Missing writer body'}
Invoke-Expression $definition[0].Extent.Text
$shared=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-B02JustificationClientBody'},$false))
if($shared.Count -ne 1){throw 'Shared justification client unavailable'}
Invoke-Expression $shared[0].Extent.Text
$body=Get-WriterBody;$tokens=$null;$errors=$null
$actorAst=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Actor parse failed'}
$native=@($actorAst.FindAll({param($node)$node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value -like '*public static class SUWriter*'},$true))
if($native.Count -ne 1){throw 'Unique native actor definition missing'}
Add-Type -TypeDefinition $native[0].Value
$root=Join-Path ([IO.Path]::GetTempPath()) ('SafeUpload-C05-native-control-'+[guid]::NewGuid().ToString('N'))
$destination=Join-Path $root 'denied';$source=Join-Path $root 'source.txt';$target=Join-Path $destination 'absent.txt'
$hasher=[Security.Cryptography.SHA256]::Create();$count=0
try{
    $null=New-Item -ItemType Directory -Path $destination
    $bytes=[Text.Encoding]::ASCII.GetBytes(('C05 native test source'+"`n").PadRight(12288,'Q'))
    [IO.File]::WriteAllBytes($source,$bytes);$digest=[BitConverter]::ToString($hasher.ComputeHash($bytes))
    $null=& icacls.exe $destination /deny '*S-1-1-0:(W)'
    if($LASTEXITCODE -ne 0){throw 'Disposable target ACL setup failed'}
    for($round=0;$round -le 100;$round++){
        $h=[IntPtr]::Zero;$call=$null;$calls=@()
        try{
            $h=[SUWriter]::OpenHeld($source,[uint32]3,$true,[ref]$call);$calls+=$call
            if($call.NativeCode -ne 0){throw ('Physical source open failed: '+$call.NativeCode)}
            if([BitConverter]::ToString($hasher.ComputeHash([SUWriter]::ReadPrivate($h,$bytes.Length))) -cne $digest){throw 'Source before denial differs'}
            $calls+=[SUWriter]::Rename($h,$target)
            if($calls[-1].NativeCode -ne 5){throw ('Expected native access denied, observed '+$calls[-1].NativeCode)}
            if([BitConverter]::ToString($hasher.ComputeHash([SUWriter]::ReadPrivate($h,$bytes.Length))) -cne $digest){throw 'Source after denial differs'}
        }finally{if($h -ne [IntPtr]::Zero -and $h -ne [IntPtr]::new(-1)){$calls+=[SUWriter]::CloseHeld($h)}}
        if(($calls.Class -join ',') -cne 'writer-open,rename-ex,close' -or ($calls.NativeCode -join ',') -cne '0,5,0' -or @($calls|Where-Object {$_.EndQpc -lt $_.StartQpc}).Count -or (Test-Path -LiteralPath $target)){throw 'Native denied-rename sequence/target mismatch'}
        $count++
    }
    'DeniedRenameNativeControl=PASS;Rounds='+$count+';Qualification=False'
}finally{
    $hasher.Dispose()
    if(Test-Path -LiteralPath $destination){$null=& icacls.exe $destination /remove:d '*S-1-1-0'}
    if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}
}
