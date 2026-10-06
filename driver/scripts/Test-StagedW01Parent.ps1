#requires -Version 5.1
#requires -RunAsAdministrator
<# W01/A05 transport/restoration diagnostic only. The child exclusively owns
   arm/write/release/disarm. No finally block restores a possibly pending run.
   Host stages hash-pinned inputs and launches each phase as SYSTEM. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','AfterBoot','Finalize')][string]$Phase,
    [Parameter(Mandatory=$true)][ValidatePattern('^boot-start-w01-[A-Za-z0-9-]+$')][string]$RunName,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunGuid,
    [Parameter(Mandatory=$true)][string]$InputManifestFile,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedInputManifestSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedFeatureSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedLowerSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedInspectorSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedStimulusSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedClientSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedChildSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedObserverSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSuiteSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedServicePackageSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedServiceTreeSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedBytesSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedOriginalDriverSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedOriginalPolicySha256,
    [Parameter(Mandatory=$true)][string]$CheckpointName,
    [Parameter(Mandatory=$true)][string]$CheckpointOverlay,
    [Parameter(Mandatory=$true)][string]$CheckpointReceiptFile,
    [ValidateRange(120,600)][int]$CompletionSeconds=240
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$documents=Split-Path -Parent $PSCommandPath
$stateDirectory=Join-Path $documents ('SafeUpload-w01-state-'+$RunGuid)
$statePath=Join-Path $stateDirectory 'state.clixml'
$evidenceDirectory=Join-Path $documents ($RunName+'-artifacts')
$childEvidence=Join-Path $evidenceDirectory 'child'
$fixtureRoot='C:\SafeUpload-rv4-w01-files-'+$RunGuid
$controlParent='C:\SafeUpload-rv4-w01-control-'+$RunGuid
$protectedRoot='C:\SafeUpload-rv4-w01-protected-'+$RunGuid
$target=Join-Path $fixtureRoot ('rv4-w01-target-'+$RunGuid+'.bin')
$control=Join-Path $protectedRoot 'protected-control.bin'
$receiptRoot=Join-Path $controlParent ('SafeUpload-rv4-w01-'+$RunGuid)
$childTask='SafeUpload-StagedTest-W01-'+$RunGuid
$policyPath='C:\ProgramData\SafeUpload\policy.json'
$installedDriver='C:\Windows\System32\drivers\SafeUpload.sys'
$lowerBinary='C:\Windows\System32\drivers\SafeUploadSectionFault.sys'
$lowerKey='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadSectionFault'
$upperKey='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload'
$parametersKey=Join-Path $upperKey 'Parameters'
$agentKey='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
$serviceDirectory=Join-Path $stateDirectory 'service'
$state=$null
function Write-Bytes([string]$Path,[byte[]]$Bytes,[switch]$New) {
    $mode=if($New){[IO.FileMode]::CreateNew}else{[IO.FileMode]::Create}
    $s=[IO.FileStream]::new($Path,$mode,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try{$s.Write($Bytes,0,$Bytes.Length);$s.Flush($true)}finally{$s.Dispose()}
}
function Write-Text([string]$Path,[string]$Text,[switch]$New){Write-Bytes $Path ([Text.UTF8Encoding]::new($false).GetBytes($Text)) -New:$New}
function Save-State {Write-Text $statePath ([Management.Automation.PSSerializer]::Serialize($state,32))}
function Save-Json([string]$Leaf,$Value){Write-Text (Join-Path $evidenceDirectory $Leaf) ($Value|ConvertTo-Json -Depth 32)}
function Boot-Id {(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}
function Assert-Hash([string]$Path,[string]$Hash){if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -cne $Hash.ToUpperInvariant()){throw ('Hash mismatch: '+$Path)}}
function Native([string]$Exe,[string[]]$Arguments,[int[]]$Allowed=@(0)) {
    $output=& $Exe @Arguments 2>&1|Out-String;$code=$LASTEXITCODE
    if($Allowed -notcontains $code){throw ($Exe+' exit='+$code+' '+$output)}
    return $output
}
function Assert-NoReparse([string]$Path) {
    $pathNow=[IO.Path]::GetFullPath($Path)
    while($pathNow){
        if(((Get-Item -LiteralPath $pathNow -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse ancestor: '+$pathNow)}
        $parent=Split-Path -Parent $pathNow
        if($parent -ceq $pathNow){break};$pathNow=$parent
    }
}
function Set-PrivateAcl([string]$Path,[bool]$Directory) {
    $a=if($Directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
    $a.SetAccessRuleProtection($true,$false)
    $a.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
    $a.SetGroup([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $flags=if($Directory){[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit}else{[Security.AccessControl.InheritanceFlags]::None}
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){
        $a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,$flags,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $a
    # Windows adds the auto-inherited flag (D:P -> D:PAI) once the descriptor is applied; the owner, group, protection and every ACE must match exactly.
    $expectedSddl=$a.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
    if((Get-SecuritySddl $Path $Directory) -replace 'D:(P?)AI\(','D:$1(' -cne ($expectedSddl -replace 'D:(P?)AI\(','D:$1(')){throw 'Private ACL readback mismatch'}
}
function Assert-ReplacementAcl([string]$Path) {
    # A private child DACL alone cannot override DELETE_CHILD on an ancestor.
    # Inspect every ancestor too; trusted privileged principals remain trusted.
    $trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $current=[IO.Path]::GetFullPath($Path);$rows=@();$isExact=$true
    while($current){
        $acl=Get-Acl -LiteralPath $current
        $danger=[Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership -bor [Security.AccessControl.FileSystemRights]::WriteAttributes
        if($isExact){$danger=$danger -bor [Security.AccessControl.FileSystemRights]::WriteData}
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
            if(($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0){continue}
            if($rule.AccessControlType -eq 'Allow' -and $trusted -notcontains $rule.IdentityReference.Value -and ($rule.FileSystemRights -band $danger) -ne 0){throw ('Untrusted replacement rights on '+$current+' for '+$rule.IdentityReference.Value)}
        }
        $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if($trusted -notcontains $owner){throw ('Untrusted ancestor owner: '+$current)}
        $rows+=@{Path=$current;Sddl=(Get-SecuritySddl $current ((Get-Item -LiteralPath $current).PSIsContainer))}
        $parent=Split-Path -Parent $current;if($parent -ceq $current){break};$current=$parent;$isExact=$false
    }
    return $rows
}
function Restore-Acl([string]$Path,[string]$Sddl,[bool]$Directory) {
    $a=if($Directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
    $a.SetSecurityDescriptorSddlForm($Sddl);Set-Acl -LiteralPath $Path -AclObject $a
    if((Get-SecuritySddl $Path $Directory) -cne $Sddl){throw ('Restored ACL mismatch: '+$Path)}
}
function Signed([string]$Path,[string]$Hash) {
    Assert-Hash $Path $Hash;$sig=Get-AuthenticodeSignature -LiteralPath $Path
    Save-Json ('signature-'+[IO.Path]::GetFileName($Path)+'.json') @{Path=$Path;Hash=$Hash;Status=[string]$sig.Status;Signer=$sig.SignerCertificate.Thumbprint}
    if([string]$sig.Status -cne 'Valid' -or $sig.SignerCertificate.Thumbprint -cne '220DD82C37FCF36048D59E4F10113185D81D5DC7'){throw 'Signed artifact not trusted/pinned on guest'}
}
function Lower-Absent {
    $inventory=Native 'fltmc.exe' @('filters')
    $services=@(Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUploadSectionFault'")
    $absent=-not(Test-Path -LiteralPath $lowerBinary) -and -not(Test-Path -LiteralPath $lowerKey) -and $services.Count -eq 0 -and $inventory -notmatch '(?m)^SafeUploadSectionFault\s'
    return @{Absent=$absent;Inventory=$inventory;Services=$services}
}
function Driver-Path([string]$Value) {
    $path=[Environment]::ExpandEnvironmentVariables($Value.Trim('"'))
    foreach($prefix in @('\??\','\\?\')){if($path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){$path=$path.Substring($prefix.Length)}}
    $root='\SystemRoot\'
    if($path.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){$path=Join-Path $env:SystemRoot $path.Substring($root.Length)}
    if($path.StartsWith('System32\',[StringComparison]::OrdinalIgnoreCase)){$path=Join-Path $env:SystemRoot $path}
    return [IO.Path]::GetFullPath($path)
}
function Driver-ServiceEvidence {
    $upper=@(Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'")
    $lower=@(Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUploadSectionFault'")
    Save-Json 'driver-services-afterboot.json' @{Upper=$upper;Lower=$lower}
    if($upper.Count -ne 1 -or $lower.Count -ne 1 -or $upper[0].State -cne 'Running' -or $upper[0].StartMode -cne 'Boot' -or $lower[0].State -cne 'Running' -or $lower[0].StartMode -cne 'Manual' -or (Driver-Path $upper[0].PathName) -ine $installedDriver -or (Driver-Path $lower[0].PathName) -ine $lowerBinary){throw 'Boot/manual SCM state or exact artifact path mismatch'}
}
function Verifier-Evidence([string]$Label,[switch]$Active) {
    $q=Native 'verifier.exe' @('/query') @(0,2);$s=Native 'verifier.exe' @('/querysettings') @(0,2)
    Save-Json ('verifier-'+$Label+'.json') @{Active=$q;Settings=$s}
    if($Active){
        foreach($name in @('SafeUpload.sys','SafeUploadSectionFault.sys')){
            # A one-boot Verifier configuration is consumed by the boot that applied it, so /querysettings no longer names the drivers; the live /query module list and exact flags are the evidence here.
            if(@([regex]::Matches($q,'(?im)^\s*MODULE:\s+'+[regex]::Escape($name)+'\s+\(load:\s*[1-9][0-9]*\s*/\s*unload:\s*0\)')).Count -ne 1){throw ('Active Verifier missing: '+$name)}
        }
        $flags=@([regex]::Matches($q,'(?im)^\s*Verifier Flags:\s+0x([0-9a-f]+)\s*$'))
        if($flags.Count -ne 1 -or [Convert]::ToUInt32($flags[0].Groups[1].Value,16) -ne $state.VerifierFlags){throw 'Active Verifier flags mismatch'}
    }
    return @{Active=$q;Settings=$s}
}
function Memory-VerifierSnapshot {
    $key=Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management';$snapshot=@{}
    foreach($name in $key.GetValueNames()){if($name -match '^Verif'){$snapshot[$name]=@{Kind=$key.GetValueKind($name).ToString();Value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}}}
    return $snapshot
}
function File-Identity([string]$Path) {
    Assert-NoReparse $Path;$ancestorAcls=Assert-ReplacementAcl $Path;$h=[SafeUploadSectionFaultClient]::OpenAttributes($Path)
    try{
        $id=[SafeUploadSectionFaultClient]::Identity($h)
        $r=@{CanonicalPath=[IO.Path]::GetFullPath($Path);Identity=$id;VolumeSerialHex=$id.Substring(0,16);FileIdHex=$id.Substring(16);FinalPath=[W01Native]::Final($h);NtVolume=[SafeUploadSectionFaultClient]::VolumeForHandle($h);Hardlinks=[W01Native]::Links($h);Length=(Get-Item -LiteralPath $Path).Length;Sha256=(Get-FileHash -LiteralPath $Path).Hash;Sddl=(Get-SecuritySddl $Path $false);NoReparseAncestors=$true}
        if($r.Hardlinks -ne 1 -or $r.FinalPath -ine ('\\?\'+$r.CanonicalPath)){throw 'Native single-link/final canonical path mismatch'}
        $r.AncestorAcls=$ancestorAcls;return $r
    }finally{$h.Dispose()}
}
function Inventory([string]$Label,[bool]$WithLower) {
    $rows=@([SafeUploadSectionFaultClient]::Inventory($state.TargetIdentity.NtVolume));Save-Json ('inventory-'+$Label+'.json') $rows
    foreach($name in @('SafeUpload','SafeUploadSectionFault')){
        $found=@($rows|Where-Object Filter -ceq $name)
        if($name -ceq 'SafeUploadSectionFault' -and -not $WithLower){if($found.Count -ne 0){throw 'Lower unexpectedly attached'};continue}
        $altitude=if($name -ceq 'SafeUpload'){'321410'}else{'321409'}
        if($found.Count -ne 1 -or $found[0].Altitude -cne $altitude -or $found[0].Volume -cne $state.TargetIdentity.NtVolume){throw 'Exact same-volume inventory mismatch'}
    }
}
function Inspect([string]$Command,[string]$Leaf) {
    # No process termination on deadline. A stalled inspector leaves the phase
    # task alive; the host transport deadline records recovery without stopping it.
    $p=Start-Process -FilePath $inputs.Inspector.Path -ArgumentList $Command -PassThru -RedirectStandardOutput (Join-Path $evidenceDirectory $Leaf) -RedirectStandardError (Join-Path $evidenceDirectory ($Leaf+'.err'))
    $null=$p.Handle
    if(-not $p.WaitForExit(10000)){throw ('Inspector pending, PID='+$p.Id)}
    if($p.ExitCode -ne 0){throw 'Inspector failed'}
    return [IO.File]::ReadAllText((Join-Path $evidenceDirectory $Leaf))
}
function Register-UnlimitedTask([string]$Name,[string]$Launcher) {
    if(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue){throw 'Owned task collision'}
    $a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$Launcher+'"')
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $Name -Action $a -Principal $principal -Settings $settings|Out-Null
    if((Get-ScheduledTask -TaskName $Name).Settings.ExecutionTimeLimit -notin @('PT0S','P0D')){throw 'Task execution limit is not unlimited'}
}
function Literal([string]$Text){return "'"+$Text.Replace("'","''")+"'"}
function Read-Receipt([string]$Name) {
    $text=[IO.File]::ReadAllText((Join-Path $receiptRoot ($Name+'.receipt')));$r=@{}
    foreach($line in ($text -split "`n")){
        if(-not $line.Trim()){continue};$parts=$line.TrimEnd("`r").Split(@('='),2)
        if($parts.Count -ne 2 -or $r.ContainsKey($parts[0])){throw 'Incomplete/duplicate receipt'};$r[$parts[0]]=$parts[1]
    }
    if($r.Schema -cne 'Rv4W01StimulusDraft/1' -or $r.RunGuid -cne $RunGuid){throw 'Foreign receipt'}
    return $r
}
function Recovery([string]$Reason) {
    if($null -eq $state){$state=@{RunName=$RunName;RunGuid=$RunGuid}}
    $state.RecoveryRequired=$true;$state.RecoveryReason=$Reason
    $procs=@(Get-CimInstance Win32_Process|Where-Object {$_.CommandLine -like ('*'+$RunGuid+'*') -or $_.Name -eq 'SafeUpload.Agent.Service.exe'}|Select-Object ProcessId,ParentProcessId,CreationDate,Name,CommandLine)
    $lower='Unknown: child may own the sole port; parent does not connect while pending'
    $generation='Unknown';$childRecovery=$null
    foreach($leaf in @('recovery-required.json','disarm-recovery-required.json','rv4-w01-diagnostic.json')){
        $path=Join-Path $childEvidence $leaf
        if(Test-Path -LiteralPath $path){try{$childRecovery=[IO.File]::ReadAllText($path)|ConvertFrom-Json;$arms=@($childRecovery.Events|Where-Object Name -eq 'armed');if($arms.Count -eq 1){$generation=$arms[0].Generation};if($null -ne $childRecovery.LastLowerStatus){$lower=$childRecovery.LastLowerStatus}}catch{}}
    }
    if(Test-Path -LiteralPath $stateDirectory){Save-State};Save-Json 'RecoveryRequired.json' @{RecoveryRequired=$true;Reason=$Reason;RunName=$RunName;RunGuid=$RunGuid;Pids=$procs;ArmGeneration=$generation;LowerStatus=$lower;ChildRecovery=$childRecovery;Checkpoint=$CheckpointName;Overlay=$CheckpointOverlay;Utc=[DateTime]::UtcNow.ToString('o');Verdict='W01/A05 INCONCLUSIVE';Phase4='NOT_QUALIFIED'}
    'GUEST_RECOVERY_REQUIRED=True';'W01/A05 INCONCLUSIVE';'Phase4=NOT_QUALIFIED'
}
function Start-PolicyAgent {
    # Same real agent service/event protocol as admission New-ExpandedPolicyForFixture /
    # Start-TestAgentAndWaitForPolicy, without their error-path termination helper.
    if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0){throw 'Pre-existing agent'}
    $ready=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,'Global\SafeUploadServiceReady')
    try{
        [void]$ready.Reset()
        $bin='"'+(Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe')+'" --Interception:Mode=Minifilter --Interception:StagingPrototype=true'
        if($state.OriginalAgent.Exists){$null=Native 'sc.exe' @('config','SafeUploadAgent','binPath=',$bin,'start=','demand','obj=','LocalSystem')}
        else{$null=Native 'sc.exe' @('create','SafeUploadAgent','binPath=',$bin,'start=','demand','obj=','LocalSystem');$state.AgentCreated=$true;Save-State}
        $state.AgentTouched=$true;Save-State
        $null=Native 'sc.exe' @('sidtype','SafeUploadAgent','unrestricted')
        $null=Native 'sc.exe' @('start','SafeUploadAgent')
        if(-not $ready.WaitOne([TimeSpan]::FromSeconds(45))){throw 'Agent policy acceptance unavailable; preserve running service'}
        $svc=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
        if($svc.State -cne 'Running' -or $svc.StartName -cne 'LocalSystem' -or $svc.ProcessId -eq 0){throw 'Agent SYSTEM service proof failed'}
        Save-Json 'policy-agent.json' @{Pid=$svc.ProcessId;Path=$svc.PathName;StartName=$svc.StartName;ReadyEvent=$true;Utc=[DateTime]::UtcNow.ToString('o')}
    }finally{$ready.Dispose()}
}
function Test-TerminalState {
    if($null -eq $state -or $state.RecoveryRequired -ne $false -or $state.ChildStarted -ne $true){return $false}
    try{
        $task=Get-ScheduledTask -TaskName $childTask
        if($task.State -cne 'Ready'){return $false}
        $done=[IO.File]::ReadAllText((Join-Path $childEvidence 'child-exited.json'))|ConvertFrom-Json
        $d=[IO.File]::ReadAllText((Join-Path $childEvidence 'rv4-w01-diagnostic.json'))|ConvertFrom-Json
        if($done.RunGuid -cne $RunGuid -or $done.BootId -cne (Boot-Id) -or $done.Exited -ne $true -or $d.RunGuid -cne $RunGuid -or $d.RecoveryRequired -ne $false -or $d.WriterExited -ne $true -or $null -eq $d.WriterPid){return $false}
        if(Get-Process -Id ([int]$done.Pid) -ErrorAction SilentlyContinue){return $false}
        if(Get-Process -Id ([int]$d.WriterPid) -ErrorAction SilentlyContinue){return $false}
        if((Test-Path -LiteralPath (Join-Path $receiptRoot 'recovery-required.receipt')) -or (Test-Path -LiteralPath (Join-Path $childEvidence 'recovery-required.json')) -or (Test-Path -LiteralPath (Join-Path $childEvidence 'disarm-recovery-required.json'))){return $false}
        $opened=Read-Receipt 'opened';$completed=Read-Receipt 'completed';$closed=Read-Receipt 'closed'
        if($opened.ProcessId -cne [string]$d.WriterPid -or $opened.FileId128Hex -cne $state.TargetIdentity.FileIdHex -or $opened.VolumeSerialHex -cne $state.TargetIdentity.VolumeSerialHex -or $completed.CompletionSource -cne 'IOCP' -or $completed.DeadlineExceeded -cne 'False'){return $false}
        $arms=@($d.Events|Where-Object Name -eq 'armed');$posts=@($d.Events|Where-Object Name -eq 'lower-post')
        if($arms.Count -ne 1 -or $posts.Count -ne 1){return $false}
        # This pinned receipt is published after native disarm/rundown, port
        # disposal and writer readback. Parent NEVER owns a lower control port.
        $status=$d.LowerDisarmTerminal
        if($null -eq $status -or $status.CurrentHeld -ne 0 -or $status.Mode -ne 0 -or $status.ArmedFileObject -ne 0 -or $status.LowerPosts -ne 1 -or [string]$status.ArmGeneration -cne [string]$arms[0].Generation){return $false}
        Save-Json 'terminal-state.json' @{DiagnosticExited=$true;WriterExited=$true;RecoveryRequired=$false;LowerPostDisarmTerminal=$true;Child=$d;ChildExit=$done;Lower=$status;Opened=$opened;Completed=$completed;Closed=$closed}
        $state.Terminal=$true;Save-State;return $true
    }catch{
        Save-Json 'terminal-observation-error.json' @{Error=$_.Exception.ToString()}
        return $false
    }
}
function Freeze-Artifacts {
    $frozen=Join-Path $evidenceDirectory 'frozen';New-Item -ItemType Directory -Path $frozen|Out-Null
    $null=Inspect '--admission-trace' 'parent-unfiltered-upper-trace.jsonl'
    $null=Inspect '--promotion-trace' 'parent-unfiltered-promotion-trace.jsonl'
    Copy-Item -LiteralPath $childEvidence -Destination (Join-Path $frozen 'child') -Recurse
    Copy-Item -LiteralPath $receiptRoot -Destination (Join-Path $frozen 'receipts') -Recurse
    Copy-Item -LiteralPath $stateDirectory -Destination (Join-Path $frozen 'state') -Recurse
    foreach($file in @(Get-ChildItem -LiteralPath $evidenceDirectory -File)){Copy-Item -LiteralPath $file.FullName -Destination $frozen}
    $manifest=@(Get-ChildItem -LiteralPath $frozen -File -Recurse|Sort-Object FullName|ForEach-Object {@{Path=$_.FullName.Substring($frozen.Length+1);Length=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
    Save-Json 'frozen-manifest.json' $manifest
    $state.Frozen=$true;Save-State
}
function Restore-TerminalRun {
    # SAFETY DOMINATOR: every service stop, unload, deletion and reset lives
    # below this fresh terminal predicate. There are no restoration call sites
    # in catches/finally. Freeze precedes any mutation of diagnostic artifacts.
    if(-not(Test-TerminalState)){throw 'Restoration refused: terminal predicate false'}
    if($state.Frozen -ne $true){throw 'Restoration refused: evidence not frozen'}
    if($state.AgentTouched){
        $null=Native 'sc.exe' @('stop','SafeUploadAgent') @(0,1062)
        $deadline=[DateTime]::UtcNow.AddSeconds(45)
        do{$svc=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'";if($svc.State -ceq 'Stopped'){break};Start-Sleep -Milliseconds 200}while([DateTime]::UtcNow -lt $deadline)
        if($svc.State -cne 'Stopped' -or @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0){throw 'Agent did not stop naturally'}
        if($state.OriginalAgent.Exists){
            $start=switch([int]$state.OriginalAgent.Start){2{'auto'}3{'demand'}4{'disabled'}default{throw 'Unsupported original agent start'}}
            $null=Native 'sc.exe' @('config','SafeUploadAgent','binPath=',$state.OriginalAgent.ImagePath,'start=',$start,'obj=',$state.OriginalAgent.ObjectName)
            New-ItemProperty -LiteralPath $agentKey -Name ImagePath -PropertyType $state.OriginalAgent.ImagePathKind -Value $state.OriginalAgent.ImagePath -Force|Out-Null
            $sidtype=if($state.OriginalAgent.ServiceSidType -eq 1){'unrestricted'}elseif(-not $state.OriginalAgent.ServiceSidTypePresent -or $state.OriginalAgent.ServiceSidType -eq 0){'none'}else{throw 'Unsupported original agent SID type'}
            $null=Native 'sc.exe' @('sidtype','SafeUploadAgent',$sidtype)
            if(-not $state.OriginalAgent.ServiceSidTypePresent){Remove-ItemProperty -LiteralPath $agentKey -Name ServiceSidType}
        }else{$null=Native 'sc.exe' @('delete','SafeUploadAgent')}
    }
    $null=Native 'fltmc.exe' @('unload','SafeUploadSectionFault')
    $null=Native 'sc.exe' @('delete','SafeUploadSectionFault')
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    while((Test-Path -LiteralPath $lowerKey) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100}
    if(Test-Path -LiteralPath $lowerKey){throw 'Lower registry retained; preserve binary'}
    Remove-Item -LiteralPath $lowerBinary -Force
    if(-not (Lower-Absent).Absent){throw 'Lower cleanup not complete'}
    $null=Native 'sc.exe' @('config','SafeUpload','start=','demand')
    $null=Native 'fltmc.exe' @('unload','SafeUpload')
    Assert-Hash (Join-Path $stateDirectory 'SafeUpload.original.sys') $ExpectedOriginalDriverSha256
    Write-Bytes $installedDriver ([IO.File]::ReadAllBytes((Join-Path $stateDirectory 'SafeUpload.original.sys')))
    Restore-Acl $installedDriver $state.OriginalDriverSddl $false
    Assert-Hash $installedDriver $ExpectedOriginalDriverSha256
    Write-Bytes $policyPath ([Convert]::FromBase64String($state.OriginalPolicyBase64))
    Restore-Acl $policyPath $state.OriginalPolicyFileSddl $false
    Restore-Acl (Split-Path -Parent $policyPath) $state.OriginalPolicyDirectorySddl $true
    Assert-Hash $policyPath $ExpectedOriginalPolicySha256
    Remove-Item -LiteralPath (Join-Path $parametersKey 'BootPolicy') -Recurse -Force
    $key=Get-Item -LiteralPath $parametersKey
    if(@(Get-ChildItem -LiteralPath $parametersKey).Count -ne 0 -or $key.GetValueNames().Count -ne 0){throw 'Unexpected Parameters residue; retain'}
    Remove-Item -LiteralPath $parametersKey
    # Original baseline has NO verified drivers. Global reset therefore restores
    # the exact baseline and resets BOTH named boot selections for reboot 2.
    $null=Native 'verifier.exe' @('/reset') @(0,2)
    # Restore the original persisted Verifier values, including boot mode.
    $memoryKey='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $current=Memory-VerifierSnapshot
    foreach($name in $current.Keys){if(-not $state.OriginalMemoryVerifier.ContainsKey($name)){Remove-ItemProperty -LiteralPath $memoryKey -Name $name}}
    foreach($name in $state.OriginalMemoryVerifier.Keys){$v=$state.OriginalMemoryVerifier[$name];New-ItemProperty -LiteralPath $memoryKey -Name $name -PropertyType $v.Kind -Value $v.Value -Force|Out-Null}
    Unregister-ScheduledTask -TaskName $childTask -Confirm:$false
    foreach($root in @($fixtureRoot,$controlParent,$protectedRoot)){
        Assert-NoReparse $root;Remove-Item -LiteralPath $root -Recurse -Force
        if(Test-Path -LiteralPath $root){throw 'Owned root residue'}
    }
    $state.Restored=$true;$state.AfterBootId=Boot-Id;Save-State
    Save-Json 'restoration.json' @{SafeTerminalGate=$true;Frozen=$true;NeedsRestorationReboot=$true;Verdict='INCONCLUSIVE'}
}

function Get-SecuritySddl([string] $Path, [bool] $Directory) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group -bor
        [Security.AccessControl.AccessControlSections]::Access
    return $acl.GetSecurityDescriptorSddlForm($sections)
}


function Set-ProtectedPolicyAcl {
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
    $directoryAcl.SetAccessRuleProtection($true, $false)
    $directoryAcl.SetOwner($systemSid)
    $childFlags = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid, [Security.AccessControl.FileSystemRights]::FullControl, $childFlags,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    $directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid, [Security.AccessControl.FileSystemRights]::FullControl, $childFlags,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath (Split-Path -Parent $policyPath) -AclObject $directoryAcl -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $policyPath)) {
        $created = [IO.File]::Open($policyPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        $created.Dispose()
    }
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.SetOwner($systemSid)
    $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]::None, [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow))
    $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]::None, [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $policyPath -AclObject $fileAcl -ErrorAction Stop

    foreach ($item in @(
        [pscustomobject]@{ Path = (Split-Path -Parent $policyPath); IsDirectory = $true },
        [pscustomobject]@{ Path = $policyPath; IsDirectory = $false }
    )) {
        $actual = Get-Acl -LiteralPath $item.Path -ErrorAction Stop
        $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        $ownerSid = $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $expectedFlags = if ($item.IsDirectory) { $childFlags } else { [Security.AccessControl.InheritanceFlags]::None }
        $hasSystem = $false
        $hasAdministrators = $false
        if ($ownerSid -ne $systemSid.Value -or -not $actual.AreAccessRulesProtected -or $rules.Count -ne 2) {
            throw "Protected policy ACL read-back failed: $($item.Path) must be SYSTEM-owned with two explicit ACEs and a protected DACL."
        }
        foreach ($rule in $rules) {
            if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
                $rule.InheritanceFlags -ne $expectedFlags -or
                $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
                throw "Protected policy ACL read-back found a non-exact ACE: $($item.Path)"
            }
            if ($rule.IdentityReference.Value -eq $systemSid.Value) { $hasSystem = $true }
            elseif ($rule.IdentityReference.Value -eq $administratorsSid.Value) { $hasAdministrators = $true }
            else { throw "Protected policy ACL read-back found an unexpected trustee: $($item.Path)" }
        }
        if (-not $hasSystem -or -not $hasAdministrators) {
            throw "Protected policy ACL read-back is missing SYSTEM or Administrators: $($item.Path)"
        }
    }
    Write-Output 'PolicyAclVerified=True;Trustees=SYSTEM,Administrators;InheritedAces=0'
}



function Get-BootPolicyReadback {
$path = 'SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters\BootPolicy'
$parentPath = 'SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters'
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $false)
if ($null -eq $key) { throw 'BootPolicy key missing.' }
$parent = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parentPath, $false)
if ($null -eq $parent) { $key.Dispose(); throw 'Parameters key missing.' }
function Test-ExactSystemTiAcl($registryKey) {
    $security = $registryKey.GetAccessControl([Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access)
    $owner = $security.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $rulesOk = ($rules.Count -eq 2)
    $sidSet = @()
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
            $rule.RegistryRights -ne [Security.AccessControl.RegistryRights]::FullControl) { $rulesOk = $false }
        $sidSet += $rule.IdentityReference.Value
    }
    $expected = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    return ($owner -eq 'S-1-5-18' -and $security.AreAccessRulesProtected -and $rulesOk -and
        (($sidSet | Sort-Object) -join ';') -eq (($expected | Sort-Object) -join ';'))
}
try {
    $record = $key.GetValue('Scopes', $null)
    $pendingPresent = $key.GetValueNames() -contains 'PendingScopes'
    if ($record -isnot [byte[]]) { throw 'Scopes is not REG_BINARY.' }
    $policyAclValid = Test-ExactSystemTiAcl $key
    $parametersAclValid = Test-ExactSystemTiAcl $parent
    $prefixes = @()
    $prefix = ''
    if ($record.Length -ne 16656) { throw 'Scopes has the wrong record size.' }
    $prefixCount = [BitConverter]::ToUInt32($record, 8)
    if ($prefixCount -gt 32) { throw 'Scopes prefix count exceeds the fixed record capacity.' }
    for ($scopeIndex = 0; $scopeIndex -lt $prefixCount; $scopeIndex++) {
        $scopePrefix = ''
        $slotStart = 16 + ($scopeIndex * 520)
        for ($i = $slotStart; $i -lt ($slotStart + 520); $i += 2) {
            $codeUnit = [BitConverter]::ToUInt16($record, $i)
            if ($codeUnit -eq 0) { break }
            $scopePrefix += [char]$codeUnit
        }
        $prefixes += $scopePrefix
    }
    if ($prefixes.Count -gt 0) { $prefix = $prefixes[0] }
    $result = [ordered]@{
        AclValid = $policyAclValid -and $parametersAclValid
        BootPolicyAclValid = $policyAclValid
        ParametersAclValid = $parametersAclValid
        Owner = $key.GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier]).Value
        RecordBytes = $record.Length
        RecordBase64 = [Convert]::ToBase64String($record)
        DriverStart = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload' -ErrorAction Stop).Start
        PrefixCount = $prefixCount
        Flags = [BitConverter]::ToUInt32($record, 12)
        StructSize = [BitConverter]::ToUInt32($record, 4)
        Version = [BitConverter]::ToUInt32($record, 0)
        PendingPresent = $pendingPresent
        Prefix = $prefix
        Prefixes = @($prefixes)
    }
    $value = [pscustomobject]$result
}
finally { $key.Dispose(); $parent.Dispose() }

return $value
}

# Validate all host-pinned inputs on EVERY phase, independently of local hashes.
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'SYSTEM parent required'}
$platform=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if($env:COMPUTERNAME -cne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D' -or $platform.CurrentBuildNumber -ne '19045' -or $platform.UBR -ne 2965){throw 'Wrong debuggee'}
Assert-Hash $PSCommandPath $ExpectedSuiteSha256
Assert-Hash (Join-Path $documents $InputManifestFile) $ExpectedInputManifestSha256
$inputs=[IO.File]::ReadAllText((Join-Path $documents $InputManifestFile))|ConvertFrom-Json
foreach($property in $inputs.PSObject.Properties){
    $v=$property.Value
    if([IO.Path]::GetFileName($v.Leaf) -cne $v.Leaf -or $v.Hash -notmatch '^[A-F0-9]{64}$'){throw 'Unsafe manifest record'}
    $v|Add-Member -NotePropertyName Path -NotePropertyValue (Join-Path $documents $v.Leaf)
    Assert-Hash $v.Path $v.Hash
}
foreach($binding in @(@('Upper',$ExpectedFeatureSha256),@('Lower',$ExpectedLowerSha256),@('Inspector',$ExpectedInspectorSha256),@('Stimulus',$ExpectedStimulusSha256),@('Client',$ExpectedClientSha256),@('Child',$ExpectedChildSha256),@('Observer',$ExpectedObserverSha256),@('Suite',$ExpectedSuiteSha256),@('AgentPackage',$ExpectedServicePackageSha256),@('ExpectedBytes',$ExpectedBytesSha256))){
    if($inputs.($binding[0]).Hash -cne $binding[1].ToUpperInvariant()){throw 'Parameter/manifest pin mismatch'}
}
Add-Type -Path $inputs.Client.Path
Add-Type -TypeDefinition @'
using System;using System.Text;using System.ComponentModel;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class W01Native {
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int c,byte[] b,uint n);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder b,uint n,uint f);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint QueryDosDevice(string n,StringBuilder b,int c);
 public static uint Links(SafeFileHandle h){byte[] b=new byte[24];if(!GetFileInformationByHandleEx(h,1,b,24))throw new Win32Exception(Marshal.GetLastWin32Error());return BitConverter.ToUInt32(b,16);}
 public static string Final(SafeFileHandle h){StringBuilder b=new StringBuilder(4096);uint n=GetFinalPathNameByHandleW(h,b,4096,0);if(n==0||n>=4096)throw new Win32Exception(Marshal.GetLastWin32Error());return b.ToString();}
 public static string Device(){StringBuilder b=new StringBuilder(1024);if(QueryDosDevice("C:",b,1024)==0)throw new Win32Exception(Marshal.GetLastWin32Error());return b.ToString().Split('\0')[0];}
}
'@
if($Phase -eq 'Prepare'){
    foreach($path in @($stateDirectory,$evidenceDirectory,$fixtureRoot,$controlParent,$protectedRoot,$parametersKey)){if(Test-Path -LiteralPath $path){throw ('Pre-existing state: '+$path)}}
    New-Item -ItemType Directory -Path $stateDirectory,$evidenceDirectory,$childEvidence|Out-Null
    Set-PrivateAcl $stateDirectory $true;Set-PrivateAcl $evidenceDirectory $true
    try{
        $verified=@{};foreach($property in $inputs.PSObject.Properties){$verified[$property.Name]=(Get-FileHash -LiteralPath $property.Value.Path).Hash}
        Save-Json 'input-staging-verified.json' @{RunName=$RunName;RunGuid=$RunGuid;Hashes=$verified;ManifestSha256=$ExpectedInputManifestSha256}
        if([IO.Path]::GetFileName($CheckpointReceiptFile) -cne $CheckpointReceiptFile){throw 'Unsafe checkpoint receipt leaf'}
        $checkpoint=[IO.File]::ReadAllText((Join-Path $documents $CheckpointReceiptFile))
        Write-Text (Join-Path $evidenceDirectory 'checkpoint-wrapper.txt') $checkpoint
        if(-not $checkpoint.Contains($CheckpointName) -or -not $checkpoint.Contains($CheckpointOverlay)){throw 'Wrapper checkpoint identity differs; refuse Prepare'}
        Assert-Hash $installedDriver $ExpectedOriginalDriverSha256;Assert-Hash $policyPath $ExpectedOriginalPolicySha256
        Signed $inputs.Upper.Path $ExpectedFeatureSha256;Signed $inputs.Lower.Path $ExpectedLowerSha256
        $lowerBaseline=Lower-Absent;Save-Json 'lower-absent-baseline.json' $lowerBaseline
        if(-not $lowerBaseline.Absent){throw 'Lower baseline not empty'}
        $verifier=Verifier-Evidence 'original'
        if($verifier.Active -notmatch 'No drivers are currently verified' -or $verifier.Settings -notmatch 'Verifier Flags:\s+0x00000000'){throw 'Original Verifier must be off'}
        $memory=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        if($memory.VerifyDriverLevel -or $memory.VerifyDrivers){throw 'Original Verifier configured'}
        $upper=Get-ItemProperty $upperKey
        if($upper.Start -ne 3 -or $upper.ErrorControl -ne 1 -or $upper.Group -cne 'FSFilter Anti-Virus' -or $upper.Type -ne 2 -or @($upper.DependOnService).Count -ne 1 -or @($upper.DependOnService)[0] -cne 'FltMgr' -or (Native 'fltmc.exe' @('filters')) -match '(?m)^SafeUpload\s'){throw 'Original upper service invariant failed'}
        if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0){throw 'Original agent running'}
        $originalAgent=@{Exists=(Test-Path -LiteralPath $agentKey)}
        if($originalAgent.Exists){
            $av=Get-ItemProperty $agentKey;$svc=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
            if($svc.State -cne 'Stopped' -or $av.ObjectName -cne 'LocalSystem' -or $av.Start -notin @(2,3,4)){throw 'Original agent service unsupported'}
            foreach($key in @('ImagePath','Start','ObjectName','ServiceSidType')){$originalAgent[$key]=$av.$key}
            $originalAgent.ServiceSidTypePresent=$av.PSObject.Properties.Name -contains 'ServiceSidType'
            $originalAgent.ImagePathKind=(Get-Item $agentKey).GetValueKind('ImagePath').ToString()
        }
        $volume=@(Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'")
        if($volume.Count -ne 1 -or $volume[0].DriveType -ne 3 -or $volume[0].FileSystem -cne 'NTFS' -or $volume[0].BlockSize -ne 4096){throw 'Expected one fixed C: NTFS/4096 volume'}
        $state=@{RunName=$RunName;RunGuid=$RunGuid;Inputs=$PSBoundParameters;PrepareBootId=(Boot-Id);VolumeGuid=$volume[0].DeviceID;RecoveryRequired=$false;ChildStarted=$false;Restored=$false;Frozen=$false;AgentTouched=$false;OriginalAgent=$originalAgent;OriginalUpper=@{Start=$upper.Start;ErrorControl=$upper.ErrorControl;Group=$upper.Group;Type=$upper.Type;DependOnService=$upper.DependOnService;ImagePath=$upper.ImagePath};OriginalVerifier=$verifier;OriginalMemoryVerifier=(Memory-VerifierSnapshot);OriginalDriverSddl=(Get-SecuritySddl $installedDriver $false);OriginalPolicyBase64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($policyPath));OriginalPolicyFileSddl=(Get-SecuritySddl $policyPath $false);OriginalPolicyDirectorySddl=(Get-SecuritySddl (Split-Path -Parent $policyPath) $true)}
        Save-State
        if($originalAgent.Exists){$null=Native 'sc.exe' @('config','SafeUploadAgent','start=','demand')}
        Write-Bytes (Join-Path $stateDirectory 'SafeUpload.original.sys') ([IO.File]::ReadAllBytes($installedDriver)) -New
        Assert-Hash (Join-Path $stateDirectory 'SafeUpload.original.sys') $ExpectedOriginalDriverSha256
        New-Item -ItemType Directory -Path $fixtureRoot,$controlParent,$protectedRoot,$serviceDirectory|Out-Null
        foreach($root in @($fixtureRoot,$controlParent,$protectedRoot)){Set-PrivateAcl $root $true;Assert-NoReparse $root}
        $bytes=[IO.File]::ReadAllBytes($inputs.ExpectedBytes.Path)
        if($bytes.Length -lt 8192 -or $bytes.Length % 4096 -ne 0){throw 'Aligned expected image invalid'}
        foreach($file in @($target,$control)){Write-Bytes $file $bytes -New;Set-PrivateAcl $file $false}
        $state.TargetIdentity=File-Identity $target;$state.ControlIdentity=File-Identity $control
        if($state.TargetIdentity.Identity -ceq $state.ControlIdentity.Identity -or $state.TargetIdentity.NtVolume -cne $state.ControlIdentity.NtVolume -or $state.TargetIdentity.Sha256 -cne $ExpectedBytesSha256){throw 'Distinct exact fixture identities not proven'}
        Save-State;Save-Json 'fixture-identities.json' @{Target=$state.TargetIdentity;Control=$state.ControlIdentity;VolumeGuid=$state.VolumeGuid}
        Expand-Archive -LiteralPath $inputs.AgentPackage.Path -DestinationPath $serviceDirectory
        $tree=@(Get-ChildItem -LiteralPath $serviceDirectory -File -Recurse|ForEach-Object {(Get-FileHash -LiteralPath $_.FullName).Hash+'  '+$_.FullName.Substring($serviceDirectory.Length+1).Replace('\','/')})
        [Array]::Sort($tree,[StringComparer]::Ordinal)
        $sha=[Security.Cryptography.SHA256]::Create()
        try{$treeHash=([BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes(($tree -join "`n")+"`n")))).Replace('-','')}finally{$sha.Dispose()}
        if($treeHash -cne $ExpectedServiceTreeSha256){throw 'Service tree pin mismatch'}
        Set-ProtectedPolicyAcl
        $policy=@{version=1;activeCategories=@('Cpf');monitoredScopes=@{extensions=@('.bin');destinationPaths=@($protectedRoot);removableDrives=$false;networkPaths=$false};maxFileSizeMb=20;inspectionTimeoutSeconds=5;failOpen=$false;excludedProcesses=@('System','SafeUpload.Agent.App');auditOnly=$false;overrideAllowed=$false}
        Write-Text $policyPath ($policy|ConvertTo-Json -Depth 10)
        Write-Bytes $installedDriver ([IO.File]::ReadAllBytes($inputs.Upper.Path));Assert-Hash $installedDriver $ExpectedFeatureSha256
        Write-Bytes $lowerBinary ([IO.File]::ReadAllBytes($inputs.Lower.Path)) -New
        $null=Native 'sc.exe' @('create','SafeUploadSectionFault','type=','filesys','start=','demand','binPath=',$lowerBinary,'group=','FSFilter Anti-Virus','depend=','FltMgr')
        $instances=Join-Path $lowerKey 'Instances';$instance=Join-Path $instances 'SectionFault Test'
        New-Item -Path $instance -Force|Out-Null
        New-ItemProperty $instances DefaultInstance -PropertyType String -Value 'SectionFault Test'|Out-Null
        New-ItemProperty $instance Altitude -PropertyType String -Value '321409'|Out-Null
        New-ItemProperty $instance Flags -PropertyType DWord -Value 1|Out-Null
        $seed=Start-Process -FilePath (Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe') -ArgumentList '--seed-boot-policy' -WorkingDirectory $serviceDirectory -PassThru -RedirectStandardOutput (Join-Path $evidenceDirectory 'seed.out') -RedirectStandardError (Join-Path $evidenceDirectory 'seed.err')
        $null=$seed.Handle;$state.SeedPid=$seed.Id;Save-State
        if(-not $seed.WaitForExit(120000) -or $seed.ExitCode -ne 0){throw 'Product seed pending/failed; retain process'}
        $readback=Get-BootPolicyReadback
        $expected=New-Object byte[] 16656
        [BitConverter]::GetBytes([uint32]1).CopyTo($expected,0);[BitConverter]::GetBytes([uint32]16656).CopyTo($expected,4);[BitConverter]::GetBytes([uint32]1).CopyTo($expected,8)
        $prefix=[W01Native]::Device()+$protectedRoot.Substring(2);$pb=[Text.Encoding]::Unicode.GetBytes($prefix)
        if($pb.Length -gt 518){throw 'Scope too long'};[Array]::Copy($pb,0,$expected,16,$pb.Length)
        $state.ExpectedBootRecord=[Convert]::ToBase64String($expected);Save-State
        Save-Json 'boot-policy-prepare.json' $readback
        if(-not $readback.AclValid -or $readback.PendingPresent -or $readback.RecordBase64 -cne $state.ExpectedBootRecord -or $readback.DriverStart -ne 3 -or (Native 'fltmc.exe' @('filters')) -match '(?m)^SafeUpload\s' -or @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0){throw 'Exact seeded boot record/ACL/no-load mismatch'}
        $null=Native 'sc.exe' @('config','SafeUpload','start=','boot')
        if((Get-ItemProperty $upperKey).Start -ne 0){throw 'Boot start readback mismatch'}
        $null=Native 'verifier.exe' @('/standard','/driver','SafeUpload.sys','SafeUploadSectionFault.sys') @(0,2)
        $null=Native 'verifier.exe' @('/bootmode','oneboot') @(0,2)
        $v=Verifier-Evidence 'prepare';$flags=@([regex]::Matches($v.Settings,'(?im)^Verifier Flags:\s+0x([0-9a-f]+)\s*$'))
        if($flags.Count -ne 1){throw 'Verifier configured flags ambiguous'};$state.VerifierFlags=[Convert]::ToUInt32($flags[0].Groups[1].Value,16)
        foreach($name in @('SafeUpload.sys','SafeUploadSectionFault.sys')){if($v.Settings -notmatch [regex]::Escape($name)){throw 'Both boot Verifiers must be configured'}}
        if($state.VerifierFlags -eq 0){throw 'Verifier flags zero'};Save-State
        'W01_PREPARED=True'
    }catch{Recovery ($_.Exception.ToString());return}
}elseif($Phase -eq 'AfterBoot'){
    $state=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($statePath))
    try{
        if($state.RunName -cne $RunName -or $state.RunGuid -cne $RunGuid -or $state.RecoveryRequired -ne $false -or $state.ChildStarted){throw 'State foreign/recovery/repeated AfterBoot'}
        if((Boot-Id) -ceq $state.PrepareBootId -or (Get-ItemProperty $upperKey).Start -ne 0){throw 'Boot identity/start not proven'}
        Signed $installedDriver $ExpectedFeatureSha256;Signed $lowerBinary $ExpectedLowerSha256
        $r=Get-BootPolicyReadback;Save-Json 'boot-policy-afterboot.json' $r
        if(-not $r.AclValid -or $r.RecordBase64 -cne $state.ExpectedBootRecord -or $r.PendingPresent -or $r.Prefix -cne ([W01Native]::Device()+$protectedRoot.Substring(2))){throw 'Actual boot scope mismatch'}
        Inventory 'boot-upper' $false
        $null=Native 'fltmc.exe' @('load','SafeUploadSectionFault')
        $null=Native 'fltmc.exe' @('attach','SafeUploadSectionFault','C:')
        Inventory 'attached' $true
        Driver-ServiceEvidence
        $null=Verifier-Evidence 'active-both' -Active
        $volumeStatus=(Inspect '--admission-volume-status' 'boot-volume-status.json')|ConvertFrom-Json
        $vg=[regex]::Match($state.VolumeGuid,'\{[0-9a-fA-F-]+\}').Value
        $vs=@($volumeStatus.admissionVolumes|Where-Object {$_.volumeGuidStatus -eq 0 -and ([string]$_.volumeGuid).ToLowerInvariant().Contains($vg.ToLowerInvariant())})
        if($vg.Length -eq 0 -or $vs.Count -ne 1 -or $volumeStatus.bootPolicyState -ne 1 -or $volumeStatus.writerGlobalUnknown -ne 0 -or $vs[0].trustState -ne 3 -or $vs[0].canaryState -ne 2 -or $vs[0].contextStatus -ne 0 -or ($vs[0].setupFlags -band 4) -eq 0 -or $vs[0].instanceWritersUntracked -ne 0 -or $vs[0].instanceRegistryUnknownReasons -cne '0x00000000'){throw 'Boot volume trust/readiness/Unknown not proven; no child/write'}
        $null=Inspect ('--admission-probe "'+$control+'"') 'protected-control-probe.json'
        $snapshot=(Inspect '--activating-status' 'protected-control-status.json')|ConvertFrom-Json
        $entries=@($snapshot.entries|Where-Object fileId -ceq $state.ControlIdentity.FileIdHex)
        $sb=New-Object byte[] 8;for($i=0;$i -lt 8;$i++){$sb[$i]=[Convert]::ToByte($state.ControlIdentity.VolumeSerialHex.Substring($i*2,2),16)}
        $serial='0x'+([BitConverter]::ToUInt64($sb,0)).ToString('X16')
        if($snapshot.activatingStatus -ne $true -or $entries.Count -ne 1 -or $entries[0].volumeSerial -cne $serial -or $entries[0].state -cne 'Protected' -or $entries[0].unknownReasons -cne '0x00000000' -or $entries[0].H -ne 0 -or $entries[0].W -ne 0){throw 'Exact Protected control with H=W=0 unavailable; no child/write'}
        foreach($pair in @(@($target,$state.TargetIdentity),@($control,$state.ControlIdentity))){$actual=File-Identity $pair[0];if($actual.Identity -cne $pair[1].Identity -or $actual.Sha256 -cne $pair[1].Sha256 -or $actual.Sddl -cne $pair[1].Sddl){throw 'Fixture replaced before child'}}
        $childParams=@{RunGuid=$RunGuid;FixtureRoot=$fixtureRoot;ControlParent=$controlParent;Target=$target;ExpectedBytesFile=$inputs.ExpectedBytes.Path;ExpectedBytesSha256=$ExpectedBytesSha256;VolumeGuid=$state.VolumeGuid;VolumeSerialHex=$state.TargetIdentity.VolumeSerialHex;FileIdHex=$state.TargetIdentity.FileIdHex;Offset='0';StimulusExe=$inputs.Stimulus.Path;ClientSource=$inputs.Client.Path;InspectorExe=$inputs.Inspector.Path;ObserverModule=$inputs.Observer.Path;EvidenceDirectory=$childEvidence;ExpectedStimulusSha256=$ExpectedStimulusSha256;ExpectedClientSha256=$ExpectedClientSha256;ExpectedInspectorSha256=$ExpectedInspectorSha256;ExpectedObserverSha256=$ExpectedObserverSha256;ProtectedControlFileIdHex=$state.ControlIdentity.FileIdHex}
        $command='& '+(Literal $inputs.Child.Path)
        foreach($key in @($childParams.Keys|Sort-Object)){$command+=' -'+$key+' '+(Literal ([string]$childParams[$key]))}
        $launcher=Join-Path $stateDirectory 'child-launcher.ps1'
        $script='$ErrorActionPreference=''Stop''; $exitCode=0;try {'+"`n"+$command+"`n"+'}catch{$exitCode=1;$_|Out-String|Set-Content -Encoding UTF8 -LiteralPath '+(Literal (Join-Path $childEvidence 'child-error.txt'))+'}'+"`n"
        $script+='$r=@{RunGuid='+(Literal $RunGuid)+';Pid=$PID;Exited=$true;BootId=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString(''o'');ExitCode=$exitCode};$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($r|ConvertTo-Json));$s=[IO.FileStream]::new('+(Literal (Join-Path $childEvidence 'child-exited.json'))+',[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough);try{$s.Write($bytes,0,$bytes.Length);$s.Flush($true)}finally{$s.Dispose()};exit $exitCode'
        Write-Text $launcher $script -New;Register-UnlimitedTask $childTask $launcher
        $state.ChildStarted=$true;Save-State;Start-ScheduledTask -TaskName $childTask
        $opened=$null;$deadline=[DateTime]::UtcNow.AddSeconds(20)
        do{try{$opened=Read-Receipt 'opened'}catch{};if($null -ne $opened){break};Start-Sleep -Milliseconds 50}while([DateTime]::UtcNow -lt $deadline)
        if($null -eq $opened -or $opened.FileId128Hex -cne $state.TargetIdentity.FileIdHex -or $opened.VolumeSerialHex -cne $state.TargetIdentity.VolumeSerialHex -or $opened.Offset -cne '0' -or $opened.Length -cne '4096'){throw 'Durable exact opened receipt unavailable'}
        $activationStarted=[DateTime]::UtcNow
        $state.WriterPid=[int]$opened.ProcessId;Save-State;Save-Json 'parent-opened.json' $opened
        # Receipt published while writer is blocked; only CHILD writes write.request.
        $bytes=[IO.File]::ReadAllBytes($policyPath);Write-Bytes (Join-Path $evidenceDirectory 'policy-before-expansion.json') $bytes -New
        $policy=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
        if(@($policy.monitoredScopes.destinationPaths).Count -ne 1 -or $policy.monitoredScopes.destinationPaths[0] -cne $protectedRoot){throw 'Unexpected boot policy scope'}
        $policy.monitoredScopes.destinationPaths=@($policy.monitoredScopes.destinationPaths)+@($fixtureRoot)
        Write-Text $policyPath ($policy|ConvertTo-Json -Depth 10)
        Start-PolicyAgent
        if([DateTime]::UtcNow -gt $activationStarted.AddSeconds(60)){throw 'Activation parent budget exceeded; child owns 75-second barrier'}
        Save-Json 'policy-expanded.json' ([IO.File]::ReadAllText($policyPath)|ConvertFrom-Json)
        $deadline=[DateTime]::UtcNow.AddSeconds($CompletionSeconds)
        do{
            if(Test-TerminalState){break}
            if($state.RecoveryRequired){break}
            Start-Sleep -Milliseconds 250
        }while([DateTime]::UtcNow -lt $deadline)
        if(-not(Test-TerminalState)){Recovery 'Completion deadline: diagnostic/writer/lower terminal state pending or unknown';return}
        Freeze-Artifacts
        Restore-TerminalRun
        'W01_CASE_COMPLETED=True';'W01_RESTORED=True';'W01/A05 INCONCLUSIVE';'Phase4=NOT_QUALIFIED'
    }catch{Recovery ($_.Exception.ToString());return}
}else{
    $state=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($statePath))
    try{
        if($state.RunName -cne $RunName -or $state.RunGuid -cne $RunGuid -or $state.Restored -ne $true -or $state.RecoveryRequired -ne $false -or (Boot-Id) -ceq $state.AfterBootId){throw 'Safe restoration/reboot absent'}
        if(-not (Lower-Absent).Absent){throw 'Lower service/binary/registry/filter residue'}
        Assert-Hash $installedDriver $ExpectedOriginalDriverSha256;Assert-Hash $policyPath $ExpectedOriginalPolicySha256
        $u=Get-ItemProperty $upperKey
        foreach($key in @('Start','ErrorControl','Group','Type','ImagePath')){if($u.$key -cne $state.OriginalUpper[$key]){throw ('Upper service not restored: '+$key)}}
        if(($u.DependOnService -join ';') -cne ($state.OriginalUpper.DependOnService -join ';') -or (Native 'fltmc.exe' @('filters')) -match '(?m)^SafeUpload\s' -or (Test-Path -LiteralPath $parametersKey)){throw 'Upper attachment/registry residue'}
        foreach($root in @($fixtureRoot,$controlParent,$protectedRoot)){if(Test-Path -LiteralPath $root){throw 'Owned root residue'}}
        if(Get-ScheduledTask -TaskName $childTask -ErrorAction SilentlyContinue){throw 'Child task residue'}
        if($state.OriginalAgent.Exists){
            $a=Get-ItemProperty $agentKey
            foreach($key in @('ImagePath','Start','ObjectName','ServiceSidType')){if($a.$key -cne $state.OriginalAgent[$key]){throw ('Original agent not restored: '+$key)}}
            if((Get-Item $agentKey).GetValueKind('ImagePath').ToString() -cne $state.OriginalAgent.ImagePathKind -or (Get-Service SafeUploadAgent).Status -ne 'Stopped'){throw 'Original agent kind/status mismatch'}
        }elseif(Test-Path -LiteralPath $agentKey){throw 'Owned agent service residue'}
        $v=Verifier-Evidence 'final'
        $memory=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        if($v.Active -notmatch 'No drivers are currently verified' -or $v.Settings -notmatch 'Verifier Flags:\s+0x00000000' -or $memory.VerifyDriverLevel -or $memory.VerifyDrivers){throw 'Both Verifiers not restored off'}
        $mv=Memory-VerifierSnapshot
        if((($mv.Keys|Sort-Object) -join ';') -cne (($state.OriginalMemoryVerifier.Keys|Sort-Object) -join ';')){throw 'Persisted Verifier inventory differs'}
        foreach($name in $mv.Keys){if($mv[$name].Kind -cne $state.OriginalMemoryVerifier[$name].Kind -or ($mv[$name].Value|ConvertTo-Json -Compress) -cne ($state.OriginalMemoryVerifier[$name].Value|ConvertTo-Json -Compress)){throw 'Persisted Verifier values differ'}}
        if((Get-SecuritySddl $installedDriver $false) -cne $state.OriginalDriverSddl -or (Get-SecuritySddl $policyPath $false) -cne $state.OriginalPolicyFileSddl -or (Get-SecuritySddl (Split-Path -Parent $policyPath) $true) -cne $state.OriginalPolicyDirectorySddl){throw 'Original ACL not restored'}
        Copy-Item -LiteralPath $statePath -Destination (Join-Path $evidenceDirectory 'final-lifecycle.clixml')
        # No pending actor survives safe restoration; state removal is confined
        # to Finalize after the independently changed restoration boot identity.
        Remove-Item -LiteralPath $stateDirectory -Recurse -Force
        $baseline=& $inputs.Baseline.Path -ExpectedOriginal $ExpectedOriginalDriverSha256 -ExpectedPolicy $ExpectedOriginalPolicySha256|Out-String
        Write-Text (Join-Path $evidenceDirectory 'independent-guest-baseline.txt') $baseline
        if(@($baseline -split '[\r\n]+'|Where-Object {$_ -ceq 'BaselineClean=True'}).Count -ne 1){throw 'Independent baseline not clean'}
        Save-Json 'case.json' @{RunName=$RunName;RunGuid=$RunGuid;Verdict='W01/A05 INCONCLUSIVE';Phase4='NOT_QUALIFIED';GuestRestorationVerified=$true;IndependentExternalBaseline='Host must join wrapper pre/post receipts';Inputs=$state.Inputs;BootIds=@($state.PrepareBootId,$state.AfterBootId,(Boot-Id))}
        'W01_FINAL_STATE=True';'W01/A05 INCONCLUSIVE';'Phase4=NOT_QUALIFIED'
    }catch{Recovery ($_.Exception.ToString());return}
}
