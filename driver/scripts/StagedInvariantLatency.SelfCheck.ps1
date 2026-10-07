#requires -Version 5.1
# Native API stimulus control on builder only. Not product qualification or a
# budget receipt: elevated builder token/build differs from the fixed debuggee.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse failed'}
$fn=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-WriterBody'},$false))
if($fn.Count -ne 1){throw 'Unique actor body unavailable'}
Invoke-Expression $fn[0].Extent.Text
$body=Get-WriterBody;$tokens=$null;$errors=$null
$actorAst=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Actor parse failed'}
$native=@($actorAst.FindAll({param($node)$node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value -like '*public static class SUWriter*'},$true))
if($native.Count -ne 1){throw 'Unique native helper unavailable'}
Add-Type -TypeDefinition $native[0].Value
$directory=Join-Path ([IO.Path]::GetTempPath()) ('sol-latency-native-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $directory
$bytes=[Text.Encoding]::ASCII.GetBytes(('Benign native latency stimulus control').PadRight(12288,'P'))
$hasher=[Security.Cryptography.SHA256]::Create()
try{
    $digest=[BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','')
    foreach($kind in @('cached','mapped','overwrite','replacement')){
        $count=0;$target=Join-Path $directory ($kind+'.txt')
        if($kind -cin @('overwrite','replacement')){[IO.File]::WriteAllBytes($target,$bytes)}
        for($round=0;$round -le 100;$round++){
            $h=[IntPtr]::Zero;$section=[IntPtr]::Zero;$view=[IntPtr]::Zero;$calls=@();$call=$null
            $path=if($kind -cin @('cached','mapped','replacement')){Join-Path $directory ($kind+'-'+$round.ToString('D3')+'.txt')}else{$target}
            try{
                $disposition=if($kind -ceq 'overwrite'){[uint32]5}else{[uint32]1}
                $h=[SUWriter]::OpenHeld($path,$disposition,($kind -ceq 'replacement'),[ref]$call);$calls+= $call
                if($call.NativeCode -ne 0){throw ('Native open:'+ $call.NativeCode)}
                if($kind -ceq 'mapped'){
                    $section=[SUWriter]::CreateMapping($h,$bytes.Length,[ref]$call);$calls+= $call
                    if($call.NativeCode -ne 0){throw ('Native mapping:'+ $call.NativeCode)}
                    $view=[SUWriter]::Map($section,$bytes.Length,[ref]$call);$calls+= $call
                    if($call.NativeCode -ne 0){throw ('Native view:'+ $call.NativeCode)}
                    $call=[SUWriter]::CloseHeld($h);$call.Class='close-source';$calls+= $call;$h=[IntPtr]::Zero
                    $calls+= [SUWriter]::StoreView($view,$bytes);$calls+= [SUWriter]::FlushView($view,$bytes.Length)
                    $actual=[SUWriter]::ReadView($view,$bytes.Length)
                }else{
                    $calls+= [SUWriter]::WriteHeld($h,$bytes);$calls+= [SUWriter]::FlushHeld($h)
                    if($kind -ceq 'replacement'){$calls+= [SUWriter]::Rename($h,$target)}
                    $actual=[SUWriter]::ReadPrivate($h,$bytes.Length)
                }
                if([BitConverter]::ToString($hasher.ComputeHash($actual)).Replace('-','') -cne $digest){throw 'Native whole private image differs'}
            }finally{
                if($view -ne [IntPtr]::Zero){$calls+= [SUWriter]::Unmap($view)}
                if($section -ne [IntPtr]::Zero){$calls+= [SUWriter]::CloseSection($section)}
                if($h -ne [IntPtr]::Zero -and $h -ne [IntPtr]::new(-1)){$calls+= [SUWriter]::CloseHeld($h)}
            }
            foreach($c in $calls){if($c.NativeCode -ne 0 -or $c.EndQpc -lt $c.StartQpc){throw ('Native status/QPC failure:'+ $c.Class+':'+$c.NativeCode)}}
            $count++
        }
        Write-Output ('NativeLatencyStimulus='+$kind+';CompleteRounds='+$count+';PASS;Qualification=False')
    }
}finally{
    $hasher.Dispose()
    Remove-Item -LiteralPath $directory -Recurse -Force
}
Write-Output 'NativeLatencyStimulusGate=PASS;Qualification=False'
