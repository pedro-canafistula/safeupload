#requires -Version 5.1
#requires -RunAsAdministrator
<# WP3 seed lifecycle. Completion sentinels describe transport/restoration, NOT
   protection. Finalize exports one provisional case.json; the host makes the
   single authoritative export after the wrapper's independent remote baseline.
   Missing lower-ledger/live-taint or incomplete notification coverage cannot PASS. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','AfterBoot','Finalize')][string]$Phase,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9-]+$')][string]$CaseId,
    [Parameter(Mandatory=$true)][ValidateSet('ordinary','runtime-verifier','boot-verifier')][string]$Mode,
    [Parameter(Mandatory=$true)][ValidatePattern('^boot-start-invariant-[A-Za-z0-9-]+$')][string]$RunName,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedFeatureSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedInspectorSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedServicePackageSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedOriginalPolicySha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedTableSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedObserverSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedHelperSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSuiteSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedServiceTreeSha256,
    [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedSignerThumbprint='220DD82C37FCF36048D59E4F10113185D81D5DC7',
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$FeatureDriverFileName,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$InspectorFileName,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$TableFileName,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$ObserverFileName,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$HelperFileName,
    # Diagnostic-only C02 hold extension, pinned in state/provenance; never qualifies.
    [ValidateSet(0,600)][int]$MappedStackDiagnosticSeconds=0,
    # Separate evidence experiment; never qualifies its functional case.
    [ValidateSet(0,1)][int]$DedicatedUnheldLatency=0,
    # Internal SYSTEM startup coordinator; only AfterBoot accepts this switch.
    [switch]$StartupProbe
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
$documents=Split-Path -Parent $PSCommandPath
$stateDirectory=Join-Path $documents ('SafeUpload-invariant-state-'+$RunName)
$statePath=Join-Path $stateDirectory 'state.clixml'
$evidenceDirectory=Join-Path $documents ($RunName+'-artifacts')
$trialPath=Join-Path $evidenceDirectory 'trial.clixml'
$bootTask='SafeUpload-StagedTest-Invariant-'+$RunName
$writerTask='SafeUpload-StagedTest-Writer-'+$RunName
$policyPath='C:\ProgramData\SafeUpload\policy.json'
$registryService='SYSTEM\CurrentControlSet\Services\SafeUpload'
$parametersKey="HKLM:\$registryService\Parameters"
$installedDriver='C:\Windows\System32\drivers\SafeUpload.sys'
$originalDriverHash='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$featureDriver=Join-Path $documents $FeatureDriverFileName
$inspectorPath=Join-Path $documents $InspectorFileName
$serviceDirectory=Join-Path $stateDirectory 'service'
$protectedDirectory='C:\SafeUploadInvariant-'+$RunName
$externalDirectory=$protectedDirectory+'-external'
$actorDirectory=Join-Path $stateDirectory 'actor'

function Write-DurableFile([string]$Path,[string]$Text,[switch]$New) {
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text)
    $fm=if($New){[IO.FileMode]::CreateNew}else{[IO.FileMode]::Create}
    $stream=[IO.FileStream]::new($Path,$fm,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
}
function Set-ActorBatchLogon([string]$Sid,[bool]$Grant) {
    # A new standard user lacks "log on as a batch job", so its password-logon writer task never starts
    # (S00 attempt 4: LastTaskResult 0x00041303, no identity). Grant it for the run; revoke before the user is removed, or the
    # right outlives the account as an orphaned SID grant.
    if (-not ('SUActorLsa' -as [type])) {
        Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.Security.Principal;
public static class SUActorLsa {
  [StructLayout(LayoutKind.Sequential)] struct US { public ushort Length, MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct OA { public int Length; public IntPtr a, b; public uint c; public IntPtr d, e; }
  [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr s, ref OA o, uint access, out IntPtr h);
  [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr h, byte[] sid, US[] rights, uint n);
  [DllImport("advapi32.dll")] static extern uint LsaRemoveAccountRights(IntPtr h, byte[] sid, bool all, US[] rights, uint n);
  [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr h);
  [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint s);
  public static uint Set(string sidText, string right, bool add) {
    var sid = new SecurityIdentifier(sidText); byte[] b = new byte[sid.BinaryLength]; sid.GetBinaryForm(b, 0);
    OA o = new OA(); o.Length = Marshal.SizeOf(typeof(OA)); IntPtr h;
    uint s = LsaOpenPolicy(IntPtr.Zero, ref o, 0x811, out h); if (s != 0) return LsaNtStatusToWinError(s);
    US u = new US(); u.Buffer = Marshal.StringToHGlobalUni(right); u.Length = (ushort)(right.Length * 2); u.MaximumLength = (ushort)(u.Length + 2);
    try { s = add ? LsaAddAccountRights(h, b, new[]{u}, 1) : LsaRemoveAccountRights(h, b, false, new[]{u}, 1); }
    finally { Marshal.FreeHGlobal(u.Buffer); LsaClose(h); }
    return s == 0 ? 0 : LsaNtStatusToWinError(s);
  }
}
"@
    }
    $code = [SUActorLsa]::Set($Sid, 'SeBatchLogonRight', $Grant)
    # Revoking a right the SID no longer holds (ERROR_FILE_NOT_FOUND) is already the desired end state.
    if ($code -ne 0 -and -not ((-not $Grant) -and $code -eq 2)) { throw ('SeBatchLogonRight ' + $(if ($Grant) { 'grant' } else { 'revoke' }) + ' failed: ' + $code) }
}
function Save-State($Value,[string]$Path) { Write-DurableFile $Path ([Management.Automation.PSSerializer]::Serialize($Value,32)) }
function Load-State([string]$Path) {
    # The observation task and AfterBoot share state.clixml; a read can meet the other's
    # write handle or a partial file (run c01b1). Retry briefly on a monotonic clock.
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($true){
        try{return [Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($Path))}
        catch{if($watch.ElapsedMilliseconds -ge 10000 -or -not (Test-Path -LiteralPath $Path)){throw};Start-Sleep -Milliseconds 50}
    }
}
function Wait-WriterIdentity([string]$Path,[int]$Seconds=60) {
    # Existence is not publication: CreateNew exposes the name before the writer
    # has flushed/closed it. Allow its write handle and retry partial CLIXML too.
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long](($Seconds)*[Diagnostics.Stopwatch]::Frequency));$reason='File not published.'
    do {
        $stream=$null;$reader=$null
        try {
            $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
                ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            $reader=[IO.StreamReader]::new($stream)
            $actor=[Management.Automation.PSSerializer]::Deserialize($reader.ReadToEnd())
            if($null -eq $actor.Pid -or [string]::IsNullOrWhiteSpace($actor.Sid) -or
                [string]::IsNullOrWhiteSpace($actor.BootId)){throw 'Incomplete writer identity.'}
            return $actor
        }catch{$reason=$_.Exception.Message}
        finally{if($null -ne $reader){$reader.Dispose()}elseif($null -ne $stream){$stream.Dispose()}}
        Start-Sleep -Milliseconds 100
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    throw ('Writer identity unavailable after bounded retry: '+$Path+'; '+$reason)
}
function Get-BootId { $env:COMPUTERNAME+'/'+(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
function Get-ErrorChain($Exception) {
    $chain=@();for($ex=$Exception;$null -ne $ex;$ex=$ex.InnerException){
        $native=$null;$ntStatus=$null;if($ex -is [ComponentModel.Win32Exception]){$native=$ex.NativeErrorCode}
        if($null -ne $ex.PSObject.Properties['NativeCode']){$native=$ex.NativeCode}
        if($null -ne $ex.PSObject.Properties['NativeNtStatus']){$ntStatus=$ex.NativeNtStatus}
        $chain+= [pscustomobject]@{Type=$ex.GetType().FullName;Message=$ex.Message;HResult=$ex.HResult;NativeCode=$native;NativeNtStatus=$ntStatus;Stack=$ex.StackTrace}
    };return ,$chain
}
function Assert-Hash([string]$Path,[string]$Hash) {
    if([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Hash) -or
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -cne $Hash.ToUpperInvariant()){throw "Input hash mismatch: $Path"}
}
function Assert-Platform {
    $w=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if($env:COMPUTERNAME -cne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D' -or
        $w.CurrentBuildNumber -ne '19045' -or $w.UBR -ne 2965){throw 'Wrong debuggee/platform'}
}
function ConvertTo-PowerShellLiteral([string]$Value){$Value.Replace("'","''")}
# Every auxiliary task gets its own durable envelope and retained stdout/stderr.
# Never accept scheduling success, an empty exit code or a stale completion.
function Wait-TaskCompletion([string]$Task,[string]$Done,[string]$Token,[int]$Seconds=240) {
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long](($Seconds)*[Diagnostics.Stopwatch]::Frequency))
    do {
        $t=Get-ScheduledTask -TaskName $Task -ErrorAction Stop
        if((Test-Path -LiteralPath $Done) -and $t.State -ne 'Running'){break}
        Start-Sleep -Milliseconds 200
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    if(-not(Test-Path -LiteralPath $Done) -or $t.State -eq 'Running'){throw "Task completion unavailable: $Task"}
    $doneRecord=Load-State $Done
    $info=Get-ScheduledTaskInfo -TaskName $Task
    if($doneRecord.Token -cne $Token -or $doneRecord.BootId -cne (Get-BootId) -or
        $null -eq $doneRecord.ExitCode -or $doneRecord.ExitCode -ne 0 -or $info.LastTaskResult -ne 0){
        throw "Task failed: $Task; LastTaskResult=$($info.LastTaskResult); $($doneRecord | Out-String)"
    }
    return $doneRecord
}
function New-TaskLauncher([string]$Body,[string]$Token,[string]$Done) {
    $prefix="function Write-DurableFile { ${function:Write-DurableFile} }`nfunction Get-BootId { ${function:Get-BootId} }`n"
    $preamble=@'
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$code=0;$chain=@();$value=$null
try {
'@
    $suffix=@'
} catch {
    'ScriptError='+$_.Exception.ToString()
    $code=1;for($ex=$_.Exception;$null -ne $ex;$ex=$ex.InnerException){$chain+=@{Type=$ex.GetType().FullName;Message=$ex.Message;HResult=$ex.HResult;Stack=$ex.StackTrace}}
} finally {
    $record=@{Token='__TOKEN__';BootId=(Get-BootId);ExitCode=$code;Errors=$chain;Value=$value;CompletedQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
    Write-DurableFile '__DONE__' ([Management.Automation.PSSerializer]::Serialize($record,32)) -New
}
exit $code
'@
    $suffix=$suffix.Replace('__TOKEN__',$Token).Replace('__DONE__',(ConvertTo-PowerShellLiteral $Done))
    return $prefix+$preamble+"`n"+$Body+"`n"+$suffix
}
function Register-SystemTask([string]$Name,[string]$Launcher,[switch]$AtStartup,[ValidateRange(1,240)][int]$ExecutionMinutes=15) {
    if(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue){throw 'Task collision'}
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$Launcher+'"')
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes($ExecutionMinutes))
    $args=@{TaskName=$Name;Action=$action;Principal=$principal;Settings=$settings}
    if($AtStartup){$args.Trigger=New-ScheduledTaskTrigger -AtStartup}
    Register-ScheduledTask @args | Out-Null
}
function Invoke-SystemBody([string]$Body) {
    $token=[guid]::NewGuid().ToString('N');$name='SafeUpload-StagedTest-System-'+$token
    $launcher=Join-Path $stateDirectory ($token+'.ps1');$done=Join-Path $evidenceDirectory ($token+'.completion.clixml')
    Write-DurableFile $launcher (New-TaskLauncher $Body $token $done) -New
    try {Register-SystemTask $name $launcher;Start-ScheduledTask -TaskName $name;return (Wait-TaskCompletion $name $done $token 240).Value}
    finally {if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){Stop-ScheduledTask -TaskName $name;Unregister-ScheduledTask -TaskName $name -Confirm:$false}}
}
function Invoke-CapturedProcess([string]$Exe,[string]$Arguments,[string]$Prefix,[int]$Timeout=45000,[string]$WorkingDirectory) {
    $p=$null
    try {
        $start=@{FilePath=$Exe;ArgumentList=$Arguments;PassThru=$true;WindowStyle='Hidden';RedirectStandardOutput=($Prefix+'.out');RedirectStandardError=($Prefix+'.err')}
        if(-not [string]::IsNullOrWhiteSpace($WorkingDirectory)){$start.WorkingDirectory=$WorkingDirectory}
        $p=Start-Process @start
        $null=$p.Handle
        if(-not $p.WaitForExit($Timeout)){throw 'Child process timed out'}
        $p.WaitForExit();if($null -eq $p.ExitCode){throw 'Child process exit code absent'}
        if($p.ExitCode -ne 0){throw "Child process failed: $($p.ExitCode); $([IO.File]::ReadAllText($Prefix+'.err'))"}
        return [IO.File]::ReadAllText($Prefix+'.out')
    }finally {if($null -ne $p){if(-not $p.HasExited){$p.Kill();$p.WaitForExit()};$p.Dispose()}}
}
function Get-ServiceTreeHash {
    $lines=@(Get-ChildItem -LiteralPath $serviceDirectory -File -Recurse | ForEach-Object {
        $rel=$_.FullName.Substring($serviceDirectory.Length+1).Replace('\','/')
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash+'  '+$rel
    })
    [Array]::Sort($lines,[StringComparer]::Ordinal)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n")+"`n")
    $hash=[Security.Cryptography.SHA256]::Create();try {return ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','')}finally{$hash.Dispose()}
}
function Invoke-ProductSeed {
    $body="function Invoke-CapturedProcess { ${function:Invoke-CapturedProcess} }`n"
    $body+='$value=Invoke-CapturedProcess '+"'"+(ConvertTo-PowerShellLiteral (Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe'))+"' '--seed-boot-policy' '"+(ConvertTo-PowerShellLiteral (Join-Path $evidenceDirectory 'product-seed'))+"'"
    $body+=" -WorkingDirectory '"+(ConvertTo-PowerShellLiteral $serviceDirectory)+"'"
    $null=Invoke-SystemBody $body
    'BootPolicySeed=product-mode;ExitCode:0;PASS'
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


function Set-AgentServiceStart([object] $StartValue) {
    if ($null -eq $StartValue) { return }
    $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
    if (-not (Test-Path -LiteralPath $serviceKey)) { throw 'SafeUploadAgent service disappeared before its start type was restored.' }
    $startName = switch ([int]$StartValue) {
        2 { 'auto' }
        3 { 'demand' }
        4 { 'disabled' }
        default { throw "Unsupported original SafeUploadAgent start value: $StartValue" }
    }
    & sc.exe config SafeUploadAgent start= $startName | Out-Host
    if ($LASTEXITCODE -ne 0 -or (Get-ItemProperty -LiteralPath $serviceKey).Start -ne [int]$StartValue) {
        throw "Could not set SafeUploadAgent start type to $startName."
    }
}


function Set-DemandStartAndRestoreDriver {
    & sc.exe config SafeUpload start= demand | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not restore SafeUpload to demand start.' }
    $loaded = (& fltmc.exe filters 2>&1 | Out-String) -match '(?m)^SafeUpload\s'
    if ($loaded) {
        & fltmc.exe unload SafeUpload | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Test filter refused unload; original driver bytes were retained in the state directory.' }
    }
    $backup=Join-Path $stateDirectory 'SafeUpload.original.sys'
    if(Test-Path -LiteralPath $backup){Copy-StagedOriginalDriver $backup $installedDriver}
    else{Assert-Hash $installedDriver $originalDriverHash}
    if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $originalDriverHash) {
        throw 'Original driver hash did not restore.'
    }
}

function Restore-PolicyFile {
    $state = Load-State $statePath
    if (-not $state.OriginalPolicyBase64) { throw 'Prepare state does not contain the required original policy bytes.' }
    [IO.File]::WriteAllBytes($policyPath, [Convert]::FromBase64String($state.OriginalPolicyBase64))
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group -bor
        [Security.AccessControl.AccessControlSections]::Access
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetSecurityDescriptorSddlForm([string]$state.OriginalPolicyFileSddl, $sections)
    Set-Acl -LiteralPath $policyPath -AclObject $fileAcl -ErrorAction Stop
    $directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
    $directoryAcl.SetSecurityDescriptorSddlForm([string]$state.OriginalPolicyDirectorySddl, $sections)
    Set-Acl -LiteralPath (Split-Path -Parent $policyPath) -AclObject $directoryAcl -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $policyPath)) { throw 'Original policy file is missing after restoration.' }
    $actual = (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedOriginalPolicySha256.ToUpperInvariant()) { throw 'Original policy hash failed restoration.' }
}


function Get-BootPolicyReadback {
    $body = @'
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
'@
    return Invoke-SystemBody $body
}
function Get-WriterBody {
$body=@'
$env:TEMP='__TEMP__';$env:TMP=$env:TEMP
Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class SUCall {
 public string Class; public int NativeCode; public long StartQpc,EndQpc; public int Trial; public bool Cold;
}
public static class SUWriter {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetNamedPipeServerProcessId(SafePipeHandle h,out uint pid);
 public const int FileRenameInfoEx = 22;
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteFile(IntPtr h,byte[] b,uint n,out uint w,IntPtr o);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushFileBuffers(IntPtr h);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(IntPtr h,byte[] b,uint n,out uint r,IntPtr o);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileSizeEx(IntPtr h,out long size);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetFilePointerEx(IntPtr h,long d,out long p,uint m);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileMappingW(IntPtr h,IntPtr sa,uint protect,uint high,uint low,string name);
 [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr MapViewOfFile(IntPtr h,uint access,uint high,uint low,UIntPtr length);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushViewOfFile(IntPtr p,UIntPtr length);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool UnmapViewOfFile(IntPtr p);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetFileInformationByHandle(IntPtr h,int kind,IntPtr info,uint size);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr h,int c,out int v,int n,out int r);
 public static bool Elevated(IntPtr token) { int v,r; if(!GetTokenInformation(token,20,out v,4,out r))throw new Win32Exception(Marshal.GetLastWin32Error());return v!=0; }
 static SUCall Call(string c,int code,long start,long end,int trial) {return new SUCall{Class=c,NativeCode=code,StartQpc=start,EndQpc=end,Trial=trial,Cold=trial==0};}
 public static IntPtr OpenHeld(string path,out SUCall call) {
  return OpenHeld(path,1,false,out call);
 }
 public static IntPtr OpenHeld(string path,uint disposition,bool rename,out SUCall call) {
  long start=Stopwatch.GetTimestamp();var h=CreateFileW(path,0xC0000000u|(rename?0x10000u:0u),7,IntPtr.Zero,disposition,0x80,IntPtr.Zero);
  int code=h==new IntPtr(-1)?Marshal.GetLastWin32Error():0;
  call=Call("writer-open",code,start,Stopwatch.GetTimestamp(),0);return h;
 }
 public static SUCall WriteHeld(IntPtr h,byte[] bytes) {
  uint written;long start=Stopwatch.GetTimestamp();bool ok=WriteFile(h,bytes,(uint)bytes.Length,out written,IntPtr.Zero);
  int code=ok?(written==bytes.Length?0:29):Marshal.GetLastWin32Error();return Call("cached-write",code,start,Stopwatch.GetTimestamp(),0);
 }
 public static SUCall FlushHeld(IntPtr h) {
  long start=Stopwatch.GetTimestamp();bool ok=FlushFileBuffers(h);int code=ok?0:Marshal.GetLastWin32Error();return Call("flush",code,start,Stopwatch.GetTimestamp(),0);
 }
 public static byte[] ReadPrivate(IntPtr h,int length) {
  long size;if(!GetFileSizeEx(h,out size))throw new Win32Exception(Marshal.GetLastWin32Error());
  if(size!=length)throw new System.IO.IOException("Private EOF differs from the whole expected image.");
  long position;if(!SetFilePointerEx(h,0,out position,0))throw new Win32Exception(Marshal.GetLastWin32Error());
  byte[] bytes=new byte[length];uint read;if(!ReadFile(h,bytes,(uint)length,out read,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());
  if(read!=length)throw new System.IO.IOException("Private read was short.");return bytes;
 }
 public static SUCall CloseHeld(IntPtr h) {
  long start=Stopwatch.GetTimestamp();bool ok=CloseHandle(h);int code=ok?0:Marshal.GetLastWin32Error();return Call("close",code,start,Stopwatch.GetTimestamp(),0);
 }
 public static IntPtr CreateMapping(IntPtr h,int length,out SUCall call) {
  long start=Stopwatch.GetTimestamp();IntPtr section=CreateFileMappingW(h,IntPtr.Zero,4,0,(uint)length,null);
  call=Call("create-mapping",section==IntPtr.Zero?Marshal.GetLastWin32Error():0,start,Stopwatch.GetTimestamp(),0);return section;
 }
 public static IntPtr Map(IntPtr section,int length,out SUCall call) {
  long start=Stopwatch.GetTimestamp();IntPtr view=MapViewOfFile(section,2,0,0,new UIntPtr((uint)length));
  call=Call("map-view",view==IntPtr.Zero?Marshal.GetLastWin32Error():0,start,Stopwatch.GetTimestamp(),0);return view;
 }
 public static SUCall StoreView(IntPtr view,byte[] bytes) {
  long start=Stopwatch.GetTimestamp();Marshal.Copy(bytes,0,view,bytes.Length);return Call("mapped-store",0,start,Stopwatch.GetTimestamp(),0);
 }
 public static SUCall FlushView(IntPtr view,int length) {
  long start=Stopwatch.GetTimestamp();bool ok=FlushViewOfFile(view,new UIntPtr((uint)length));
  return Call("flush-view",ok?0:Marshal.GetLastWin32Error(),start,Stopwatch.GetTimestamp(),0);
 }
 public static byte[] ReadView(IntPtr view,int length) {byte[] bytes=new byte[length];Marshal.Copy(view,bytes,0,length);return bytes;}
 public static SUCall Unmap(IntPtr view) {
  long start=Stopwatch.GetTimestamp();bool ok=UnmapViewOfFile(view);return Call("unmap-view",ok?0:Marshal.GetLastWin32Error(),start,Stopwatch.GetTimestamp(),0);
 }
 public static SUCall CloseSection(IntPtr section) {
  SUCall call=CloseHeld(section);call.Class="close-section";return call;
 }
 public static SUCall Rename(IntPtr h,string destination) {
  // FILE_RENAME_INFO_EX: DWORD Flags, aligned HANDLE RootDirectory (NULL),
  // DWORD FileNameLength, UTF-16 FileName. Works in 32- and 64-bit actors.
  byte[] name=System.Text.Encoding.Unicode.GetBytes(destination);
  int root=IntPtr.Size==8?8:4,length=root+IntPtr.Size,offset=length+4;
  int size=offset+name.Length+2;IntPtr info=Marshal.AllocHGlobal(size);
  try {
   for(int n=0;n<size;n++)Marshal.WriteByte(info,n,0);
   Marshal.WriteInt32(info,0,3); // REPLACE_IF_EXISTS | POSIX_SEMANTICS
   Marshal.WriteIntPtr(info,root,IntPtr.Zero);Marshal.WriteInt32(info,length,name.Length);Marshal.Copy(name,0,IntPtr.Add(info,offset),name.Length);
   long start=Stopwatch.GetTimestamp();bool ok=SetFileInformationByHandle(h,FileRenameInfoEx,info,(uint)size);
   return Call("rename-ex",ok?0:Marshal.GetLastWin32Error(),start,Stopwatch.GetTimestamp(),0);
  }finally{Marshal.FreeHGlobal(info);}
 }
 public static SUCall[] Attempt(string path,byte[] bytes,bool create,int trial) {
  var results=new System.Collections.Generic.List<SUCall>();
  long start=Stopwatch.GetTimestamp(); IntPtr h=CreateFileW(path,0x40000000,7,IntPtr.Zero,create?1u:3u,0x80,IntPtr.Zero);
  long end=Stopwatch.GetTimestamp();int code=h==new IntPtr(-1)?Marshal.GetLastWin32Error():0;
  results.Add(Call(code==0?"writer-open":"writer-open-deny",code,start,end,trial));
  if(code!=0)return results.ToArray();
  try {
   uint written;start=Stopwatch.GetTimestamp();bool ok=WriteFile(h,bytes,(uint)bytes.Length,out written,IntPtr.Zero);
   end=Stopwatch.GetTimestamp();code=ok?(written==bytes.Length?0:29):Marshal.GetLastWin32Error();results.Add(Call("cached-write",code,start,end,trial));
   start=Stopwatch.GetTimestamp();ok=FlushFileBuffers(h);end=Stopwatch.GetTimestamp();code=ok?0:Marshal.GetLastWin32Error();results.Add(Call("flush",code,start,end,trial));
  }finally{start=Stopwatch.GetTimestamp();bool ok=CloseHandle(h);end=Stopwatch.GetTimestamp();code=ok?0:Marshal.GetLastWin32Error();results.Add(Call("close",code,start,end,trial));}
  return results.ToArray();
 }
}
"@
$config=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText('__CONFIG__'))
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $actor=@{Pid=$PID;Sid=$identity.User.Value;Elevated=[SUWriter]::Elevated($identity.Token);
        IsAdministrator=(@($identity.Groups | Where-Object Value -eq 'S-1-5-32-544').Count -gt 0);
        SessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId;BootId=(Get-BootId)}
    if($config.CachedCase){
        $actor.Profile=[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        if([string]::IsNullOrWhiteSpace($actor.Profile)){
            # Batch-logon tasks run without a loaded profile; the registered profile is what the service uses.
            $registered=Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$identity.User.Value) -ErrorAction SilentlyContinue
            if($null -ne $registered){$actor.Profile=[Environment]::ExpandEnvironmentVariables([string]$registered.ProfileImagePath)}
        }
        if([string]::IsNullOrWhiteSpace($actor.Profile)){throw 'Actor profile unavailable for hand-back contract H'}
        $handBackRoot=Join-Path $actor.Profile 'SafeUpload\_bloqueados'
        function Get-ActorHandBack {
            $files=@()
            if(Test-Path -LiteralPath $handBackRoot){
                foreach($file in @(Get-ChildItem -LiteralPath $handBackRoot -Force)){
                    if($file.PSIsContainer){throw 'Unexpected directory in actor hand-back location'}
                    $files+=@{Path=$file.FullName;Length=$file.Length;Sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}
                }
            };return ,$files
        }
        $actor.HandBackBefore=Get-ActorHandBack
    }
    if($actor.Elevated -or $actor.IsAdministrator -or $actor.Sid -cne $config.ActorSid){throw 'Writer token is not the expected standard user'}
    Write-DurableFile '__IDENTITY__' ([Management.Automation.PSSerializer]::Serialize($actor,32)) -New
    function Wait-ActorBarrier([string]$Leaf) {
        $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long](180*[Diagnostics.Stopwatch]::Frequency))
        while(-not(Test-Path -LiteralPath (Join-Path $config.CoordinationDirectory $Leaf))){
            if(Test-Path -LiteralPath (Join-Path $config.CoordinationDirectory 'cancel')){throw ('Observer cancelled before barrier: '+$Leaf)}
            if([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline){throw ('Writer barrier timed out after 180 seconds: '+$Leaf)};Start-Sleep -Milliseconds 10
        }
        if(Test-Path -LiteralPath (Join-Path $config.CoordinationDirectory 'cancel')){throw ('Observer cancelled at barrier: '+$Leaf)}
    }
    function Save-ActorReceipt([string]$Leaf,$Calls,$Digest,$Fields) {
        if($config.DedicatedUnheldLatency -and $receiptPrefix){$Leaf=$receiptPrefix+$Leaf}
        $receipt=@{Pid=$PID;Sid=$actor.Sid;BootId=$actor.BootId;Token=$config.Token;Calls=@($Calls);PrivateSha256=$Digest;Qpc=[Diagnostics.Stopwatch]::GetTimestamp();ReleasedQpc=$releasedQpc}
        foreach($key in $Fields.Keys){$receipt[$key]=$Fields[$key]}
        Write-DurableFile (Join-Path $config.CoordinationDirectory $Leaf) ([Management.Automation.PSSerializer]::Serialize($receipt,32)) -New
    }
    if($config.CachedCase -and $null -ne $config.SeedBaseBase64){
        Wait-ActorBarrier 'seed-go'
        $releasedQpc=[Diagnostics.Stopwatch]::GetTimestamp();$seedCalls=@();$seedHandle=[IntPtr]::Zero;$openCall=$null
        try{
            $seedHandle=[SUWriter]::OpenHeld($config.Target,[ref]$openCall);$seedCalls+= $openCall
            if($openCall.NativeCode -ne 0){throw ('Approved B seed open failed: Win32='+$openCall.NativeCode)}
            $seedCalls+= [SUWriter]::WriteHeld($seedHandle,[Convert]::FromBase64String($config.SeedBaseBase64))
            $seedCalls+= [SUWriter]::FlushHeld($seedHandle)
        }finally{
            if($seedHandle -ne [IntPtr]::Zero -and $seedHandle -ne [IntPtr]::new(-1)){$seedCalls+= [SUWriter]::CloseHeld($seedHandle)}
            Save-ActorReceipt 'seed-closed.clixml' $seedCalls $null @{}
        }
        if(@($seedCalls | Where-Object NativeCode -ne 0).Count){throw 'Approved B seed native write/flush/close failed'}
    }
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((180)*[Diagnostics.Stopwatch]::Frequency))
    while(-not(Test-Path -LiteralPath '__GO__')){if($config.CachedCase -and (Test-Path -LiteralPath (Join-Path $config.CoordinationDirectory 'cancel'))){throw 'Observer cancelled before main operation'};if([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline){throw 'Writer barrier timed out'};Start-Sleep -Milliseconds 10}
    $releasedQpc=[Diagnostics.Stopwatch]::GetTimestamp()
    $calls=@()
    if($config.CachedCase){
        $allCalls=@();$rounds=if($config.DedicatedUnheldLatency){101}else{1}
        for($round=0;$round -lt $rounds;$round++){
        $calls=@();$receiptPrefix=if($config.DedicatedUnheldLatency){'round-'+$round.ToString('D3')+'-'}else{''}
        $roundTarget=$config.Target;$roundTemp=$config.TempTarget
        if($config.DedicatedUnheldLatency){
            if($config.WriterKind -cin @('cached','mapped')){$roundTarget=Join-Path ([IO.Path]::GetDirectoryName($config.Target)) ('latency-'+$round.ToString('D3')+'.txt')}
            if($config.WriterKind -ceq 'replacement'){$roundTemp=Join-Path ([IO.Path]::GetDirectoryName($config.TempTarget)) ('latency-'+$round.ToString('D3')+'.tmp.txt')}
        }
        $h=[IntPtr]::Zero;$section=[IntPtr]::Zero;$view=[IntPtr]::Zero;$privateDigest=$null;$openCall=$null
        try {
            $bytes=[Convert]::FromBase64String($config.Payloads[0])
            $openPath=if($config.WriterKind -ceq 'replacement'){$roundTemp}elseif($config.WriterKind -ceq 'external-rename'){$config.Source}else{$roundTarget}
            $disposition=if($config.WriterKind -ceq 'overwrite'){[uint32]5}elseif($config.WriterKind -ceq 'external-rename'){[uint32]3}else{[uint32]1}
            $rename=$config.WriterKind -cin @('replacement','external-rename')
            Save-ActorReceipt 'native-open-start.clixml' $calls $null @{Phase='open'}
            $h=[SUWriter]::OpenHeld($openPath,$disposition,$rename,[ref]$openCall);$calls+= $openCall
            if($openCall.NativeCode -ne 0){throw ('Owned/physical source open failed: Win32='+$openCall.NativeCode)}
            if($config.WriterKind -ceq 'mapped'){
            Save-ActorReceipt 'native-create-section-start.clixml' $calls $null @{Phase='create-section'}
                $nativeCall=$null;$section=[SUWriter]::CreateMapping($h,$bytes.Length,[ref]$nativeCall);$calls+= $nativeCall
                if($nativeCall.NativeCode -ne 0){throw ('CreateFileMapping PAGE_READWRITE failed: Win32='+$nativeCall.NativeCode)}
            Save-ActorReceipt 'native-map-view-start.clixml' $calls $null @{Phase='map-view'}
                $view=[SUWriter]::Map($section,$bytes.Length,[ref]$nativeCall);$calls+= $nativeCall
                if($nativeCall.NativeCode -ne 0){throw ('MapViewOfFile failed: Win32='+$nativeCall.NativeCode)}
                # Store AFTER the source closes: the view and section are the only remaining upper references.
            Save-ActorReceipt 'native-close-source-start.clixml' $calls $null @{Phase='close-source'}
                $closeCall=[SUWriter]::CloseHeld($h);$closeCall.Class='close-source';$calls+= $closeCall
                if($closeCall.NativeCode -ne 0){throw ('Source close failed: Win32='+$closeCall.NativeCode)};$h=[IntPtr]::Zero
            Save-ActorReceipt 'native-mapped-store-start.clixml' $calls $null @{Phase='mapped-store'}
                $calls+= [SUWriter]::StoreView($view,$bytes)
                Save-ActorReceipt 'native-flush-view-start.clixml' $calls $null @{Phase='flush-view'}
                $calls+= [SUWriter]::FlushView($view,$bytes.Length)
                Save-ActorReceipt 'native-read-view-start.clixml' $calls $null @{Phase='read-view'}
                $privateBytes=[SUWriter]::ReadView($view,$bytes.Length)
            }else{
                if($config.WriterKind -cne 'external-rename'){$calls+= [SUWriter]::WriteHeld($h,$bytes);$calls+= [SUWriter]::FlushHeld($h)}
                $privateBytes=[SUWriter]::ReadPrivate($h,$bytes.Length)
            }
            if(@($calls | Where-Object NativeCode -ne 0).Count){throw 'Native store/flush failed; see held/closed operation receipt'}
            $hash=[Security.Cryptography.SHA256]::Create()
            try{$privateDigest=[BitConverter]::ToString($hash.ComputeHash($privateBytes)).Replace('-','')}finally{$hash.Dispose()}
            Save-ActorReceipt 'held.clixml' $calls $privateDigest @{WriterKind=$config.WriterKind;SourceClosed=($h -eq [IntPtr]::Zero);ViewLive=($view -ne [IntPtr]::Zero);SectionLive=($section -ne [IntPtr]::Zero)}
            if($rename){
                if(-not $config.DedicatedUnheldLatency){Wait-ActorBarrier 'rename'}
                $calls+= [SUWriter]::Rename($h,$roundTarget)
                $hash=[Security.Cryptography.SHA256]::Create()
                try{$privateDigest=[BitConverter]::ToString($hash.ComputeHash([SUWriter]::ReadPrivate($h,$bytes.Length))).Replace('-','')}finally{$hash.Dispose()}
                Save-ActorReceipt 'renamed.clixml' $calls $privateDigest @{}
            }
            if(-not $config.DedicatedUnheldLatency){Wait-ActorBarrier 'close'}
        } finally {
            if($view -ne [IntPtr]::Zero){$calls+= [SUWriter]::Unmap($view)}
            if($section -ne [IntPtr]::Zero){$calls+= [SUWriter]::CloseSection($section)}
            if($h -ne [IntPtr]::Zero -and $h -ne [IntPtr]::new(-1)){$calls+= [SUWriter]::CloseHeld($h)}
            if($config.DedicatedUnheldLatency){foreach($call in $calls){$call.Trial=$round;$call.Cold=($round -eq 0)}}
            Save-ActorReceipt 'closed.clixml' $calls $privateDigest @{Trial=$round;Held=$false;Target=$roundTarget;OpenPath=$openPath;WriterKind=$config.WriterKind}
        }
        $allCalls+= $calls
        if($config.DedicatedUnheldLatency){Wait-ActorBarrier ('round-'+$round.ToString('D3')+'-next')}
        }
        $calls=$allCalls
        if(-not $config.DedicatedUnheldLatency){
        $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((180)*[Diagnostics.Stopwatch]::Frequency))
        while(-not(Test-Path -LiteralPath (Join-Path $config.CoordinationDirectory 'inspect-handback'))){if([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline){throw 'Cached writer hand-back barrier timed out after 180 seconds'};Start-Sleep -Milliseconds 10}
        }
        $handBackAfter=Get-ActorHandBack
        $windowReceipt=$null
        if($config.BlockWindowClosure -and -not $config.DedicatedUnheldLatency){
            Save-ActorReceipt 'handback-open.clixml' $calls $privateDigest @{Files=$handBackAfter;Held=$false}
            $windowConfig=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText((Join-Path $config.CoordinationDirectory 'window-config.clixml')))
            if($windowConfig.Token -cne $config.Token -or $windowConfig.DeadlineQpc -le [Diagnostics.Stopwatch]::GetTimestamp()){throw 'Invalid BLOCK window QPC deadline/token'}
            $windowCommandPath=Join-Path $config.CoordinationDirectory 'window-complete.clixml'
            while(-not(Test-Path -LiteralPath $windowCommandPath)){
                if(Test-Path -LiteralPath (Join-Path $config.CoordinationDirectory 'cancel')){throw 'BLOCK window cancelled'}
                if([Diagnostics.Stopwatch]::GetTimestamp() -ge $windowConfig.DeadlineQpc){throw 'BLOCK window actor QPC timeout'}
                Start-Sleep -Milliseconds 100
            }
            $command=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($windowCommandPath))
            if($command.Token -cne $config.Token){throw 'BLOCK window completion token mismatch'}
            $result=@{NativeCode=$null;Reply=$null;StartQpc=[Diagnostics.Stopwatch]::GetTimestamp();SkippedReason=$command.SkippedReason}
            if($command.Submit){
__CACHED_REAL_PIPE_CLIENT__
            }
            $result.EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();$result.Files=Get-ActorHandBack
            Save-ActorReceipt 'window-receipt.clixml' $calls $privateDigest $result
            $windowReceipt=$result
        }
        $value=@{Actor=$actor;Calls=$calls;PrivateSha256=$privateDigest;HandBackAfter=$handBackAfter;AfterWindowClosure=$windowReceipt;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;ReleasedQpc=$releasedQpc;Held=$false}
    }else{
    # One cold attempt followed by 100 calls without per-call test holds. Payload
    # generation, serialization, observer waits and process startup are not timed.
    for($trial=0;$trial -le 100;$trial++) {
        $bytes=[Convert]::FromBase64String($config.Payloads[$trial])
        $calls+= [SUWriter]::Attempt($config.Target,$bytes,$config.CreateNew,$trial)
    }
    $value=@{Actor=$actor;Calls=$calls;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;ReleasedQpc=$releasedQpc;Held=$false}
    }
}finally{$identity.Dispose()}
'@
    return $body.Replace('__CACHED_REAL_PIPE_CLIENT__',(Get-B02JustificationClientBody 'SUWriter'))
}
function Flush-InvariantSetupVolume {
    $before=[StagedInvariant.Native]::ResolveGuid($protectedDirectory)
    if($before -cne $state.VolumeGuid){throw 'Setup flush volume identity mismatch'}
    $volumes=@(Get-Volume -FilePath $protectedDirectory -ErrorAction Stop)
    if($volumes.Count -ne 1 -or $volumes[0].FileSystem -ine 'NTFS' -or $volumes[0].DriveType -ine 'Fixed'){throw 'Setup flush requires exact fixed NTFS volume'}
    $start=[Diagnostics.Stopwatch]::GetTimestamp()
    $volumes[0] | Write-VolumeCache -ErrorAction Stop | Out-Null
    $end=[Diagnostics.Stopwatch]::GetTimestamp()
    if([StagedInvariant.Native]::ResolveGuid($protectedDirectory) -cne $before){throw 'Setup flush volume changed'}
    return @{Purpose='TrustedSetupBeforeObservation';VolumeGuid=$before;StartQpc=$start;EndQpc=$end;QpcFrequency=[Diagnostics.Stopwatch]::Frequency}
}
# After the observation window, before the final raw capture: NTFS writes a new file's MFT record lazily,
# so raw and FSCTL identities disagree until it does (b17r1 C02: raw sequence 1, cached 3). Flushing can only
# make the final check stricter: any cached unapproved byte would then be on disk for the observer to see.
function Flush-InvariantFinalVolume {
    $receipt=Flush-InvariantSetupVolume
    $receipt.Purpose='FinalAfterObservationWindow'
    return $receipt
}
function Get-ActivatingWriterBody {
$body=@'
Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SUActivationNative {
 public static IntPtr FileHandle = new IntPtr(-1);
 public static IntPtr SectionHandle = IntPtr.Zero;
 public static IntPtr View = IntPtr.Zero;
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="CreateFileMappingW")] static extern IntPtr CreateFileMappingW(IntPtr h,IntPtr sa,uint protect,uint high,uint low,string name);
 [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr MapViewOfFile(IntPtr h,uint access,uint high,uint low,UIntPtr length);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool UnmapViewOfFile(IntPtr p);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushViewOfFile(IntPtr p,UIntPtr length);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushFileBuffers(IntPtr h);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteFile(IntPtr h,byte[] b,uint n,out uint w,IntPtr o);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetFilePointerEx(IntPtr h,long d,out long p,uint m);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetEndOfFile(IntPtr h);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr h,int c,out int v,int n,out int r);
 public static bool Elevated(IntPtr token) { int v,r; if(!GetTokenInformation(token,20,out v,4,out r)) throw new Win32Exception(Marshal.GetLastWin32Error()); return v!=0; }
 static int Error() { int e=Marshal.GetLastWin32Error(); return e==0?1:e; }
 static bool Seek(IntPtr h,long offset) { long p; return SetFilePointerEx(h,offset,out p,0); }
 public static int CreateHolder(string path,byte[] seed,string kind,out bool sourceClosed) {
  sourceClosed=false; FileHandle=CreateFileW(path,0xC0000000u,7,IntPtr.Zero,3,0x80,IntPtr.Zero);
  if(FileHandle==new IntPtr(-1)) return Error();
  if(!Seek(FileHandle,seed.Length)) return Error(); if(!SetEndOfFile(FileHandle)) return Error();
  if(!Seek(FileHandle,0)) return Error(); uint written;
  if(!WriteFile(FileHandle,seed,(uint)seed.Length,out written,IntPtr.Zero)) return Error();
  if(written!=(uint)seed.Length) return 29;
  if(!FlushFileBuffers(FileHandle)) return Error();
  if(kind=="handle") return 0;
  SectionHandle=CreateFileMappingW(FileHandle,IntPtr.Zero,4,0,0,null);
  if(SectionHandle==IntPtr.Zero) return Error();
  if(kind=="view") { View=MapViewOfFile(SectionHandle,2,0,0,new UIntPtr((uint)seed.Length)); if(View==IntPtr.Zero) return Error(); }
  if(!CloseHandle(FileHandle)) return Error(); FileHandle=new IntPtr(-1); sourceClosed=true; return 0;
 }
 public static int MapLate(uint length) { if(SectionHandle==IntPtr.Zero) return 6; View=MapViewOfFile(SectionHandle,2,0,0,new UIntPtr(length)); return View==IntPtr.Zero?Error():0; }
 public static int LastSeekCode = 0;
 public static int WriteFileAt(long offset,byte[] bytes) { LastSeekCode=0; if(FileHandle==new IntPtr(-1)) return 6; if(!Seek(FileHandle,offset)) { LastSeekCode=Error(); return LastSeekCode; } uint written; if(!WriteFile(FileHandle,bytes,(uint)bytes.Length,out written,IntPtr.Zero)) return Error(); return written==(uint)bytes.Length?0:29; }
 public static int WriteViewAt(long offset,byte[] bytes) { if(View==IntPtr.Zero || offset<0 || offset>Int32.MaxValue) return 487; Marshal.Copy(bytes,0,IntPtr.Add(View,(int)offset),bytes.Length); return 0; }
 public static int FlushView() { return View!=IntPtr.Zero && FlushViewOfFile(View,UIntPtr.Zero)?0:Error(); }
 public static int FlushHolderFile() { return FileHandle!=new IntPtr(-1) && FlushFileBuffers(FileHandle)?0:6; }
 public static int NewWritableOpen(string path) { IntPtr h=CreateFileW(path,0x40000000u,7,IntPtr.Zero,3,0x80,IntPtr.Zero); if(h==new IntPtr(-1)) return Error(); return CloseHandle(h)?0:Error(); }
 public static int NewWritableSection(string path,out int sourceOpenCode) {
  sourceOpenCode=0;
  IntPtr source=FileHandle; bool closeSource=false;
  if(source==new IntPtr(-1)) { source=CreateFileW(path,0x80000000u,7,IntPtr.Zero,3,0x80,IntPtr.Zero); if(source==new IntPtr(-1)) { sourceOpenCode=Error(); return sourceOpenCode; } closeSource=true; }
  IntPtr section=CreateFileMappingW(source,IntPtr.Zero,4,0,0,null); int result=section==IntPtr.Zero?Error():0;
  if(section!=IntPtr.Zero) CloseHandle(section); if(closeSource) CloseHandle(source); return result;
 }
 public static int StageWrite(string path,long offset,byte[] bytes,out int flushCode,out int closeCode,out long bytesWritten) {
  flushCode=0; closeCode=0; bytesWritten=0; IntPtr h=CreateFileW(path,0x40000000u,7,IntPtr.Zero,3,0x80,IntPtr.Zero);
  if(h==new IntPtr(-1)) return Error(); int result=0;
  try {
   if(!Seek(h,offset)) result=Error();
   else { uint written; if(!WriteFile(h,bytes,(uint)bytes.Length,out written,IntPtr.Zero)) result=Error();
    else { bytesWritten=written; if(written!=(uint)bytes.Length) result=29; else if(!FlushFileBuffers(h)) { flushCode=Error(); result=flushCode; } }
   }
  } finally { if(!CloseHandle(h)) { closeCode=Error(); if(result==0) result=closeCode; } }
  return result;
 }
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr source,IntPtr handle,IntPtr target,out IntPtr copy,uint access,bool inherit,uint options);
 public static int DuplicateHolder(int pid,out long source,out long remote) {
  source=FileHandle.ToInt64();remote=0;if(FileHandle==new IntPtr(-1))return 6;
  IntPtr process=OpenProcess(0x40,false,pid);if(process==IntPtr.Zero)return Error();
  try {IntPtr copy;if(!DuplicateHandle(GetCurrentProcess(),FileHandle,process,out copy,0,false,2))return Error();remote=copy.ToInt64();return 0;}
  finally{CloseHandle(process);}
 }
 public static int AdoptHolder(long value) {
  if(FileHandle!=new IntPtr(-1) || value<=0)return 6;
  FileHandle=new IntPtr(value);long position;if(!SetFilePointerEx(FileHandle,0,out position,1)){return Error();}return 0;
 }
 public static int Position(long offset,bool query,out long position) {
  position=-1;if(FileHandle==new IntPtr(-1))return 6;
  return SetFilePointerEx(FileHandle,query?0:offset,out position,query?1u:0u)?0:Error();
 }
 public static int StageWriteHeld(string path,long offset,byte[] bytes,out long written) {
  written=0;if(FileHandle!=new IntPtr(-1))return 6;
  FileHandle=CreateFileW(path,0xC0000000u,7,IntPtr.Zero,3,0x80,IntPtr.Zero);
  if(FileHandle==new IntPtr(-1))return Error();if(!Seek(FileHandle,offset))return Error();
  uint count;if(!WriteFile(FileHandle,bytes,(uint)bytes.Length,out count,IntPtr.Zero))return Error();
  written=count;if(count!=bytes.Length)return 29;return FlushHolderFile();
 }
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(IntPtr h,byte[] b,uint n,out uint r,IntPtr o);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileSizeEx(IntPtr h,out long size);
 public static string HolderDigest(int length) {
  long size;if(FileHandle==new IntPtr(-1) || !GetFileSizeEx(FileHandle,out size) || size!=length || !Seek(FileHandle,0))throw new InvalidOperationException("Private held image length/seek failed");
  byte[] bytes=new byte[length];uint count;if(!ReadFile(FileHandle,bytes,(uint)length,out count,IntPtr.Zero) || count!=length)throw new InvalidOperationException("Private held read incomplete");
  using(var hash=System.Security.Cryptography.SHA256.Create()){return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-","");}
 }
 public static int ReleaseHolder() {
  int result=0; if(View!=IntPtr.Zero){if(!UnmapViewOfFile(View)) result=Error();View=IntPtr.Zero;}
  if(SectionHandle!=IntPtr.Zero){if(!CloseHandle(SectionHandle) && result==0) result=Error();SectionHandle=IntPtr.Zero;}
  if(FileHandle!=new IntPtr(-1)){if(!CloseHandle(FileHandle) && result==0) result=Error();FileHandle=new IntPtr(-1);}
  return result;
 }
}
"@
$config=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText('__CONFIG__'))
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$commandSequence=1;$workerError=$null
function Save-ActivationActorState($Value,[string]$Path,[switch]$New){$fm=if($New){[IO.FileMode]::CreateNew}else{[IO.FileMode]::Create};$stream=[IO.FileStream]::new($Path,$fm,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough);try{$writer=[IO.StreamWriter]::new($stream);$writer.Write([Management.Automation.PSSerializer]::Serialize($Value,32));$writer.Flush();$stream.Flush($true)}finally{$stream.Dispose()}}
try {
 $actor=@{Pid=$PID;Sid=$identity.User.Value;Elevated=[SUActivationNative]::Elevated($identity.Token);IsAdministrator=(@($identity.Groups|Where-Object Value -eq 'S-1-5-32-544').Count -gt 0);SessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId;BootId=(Get-BootId)}
 if($actor.Elevated -or $actor.IsAdministrator -or $actor.Sid -cne $config.ActorSid){throw 'Activation holder token is not the expected standard user'}
 Save-ActivationActorState $actor '__IDENTITY__' -New
 while($true){
  $commandDirectory=if($config.CommandDirectory){$config.CommandDirectory}else{$config.ActorDirectory}
  $commandPath=Join-Path $commandDirectory ('command-'+$commandSequence.ToString('D4')+'.clixml')
  if(-not(Test-Path -LiteralPath $commandPath)){Start-Sleep -Milliseconds 10;continue}
  $command=Load-State $commandPath;if($command.Sequence -ne $commandSequence -or [string]::IsNullOrWhiteSpace($command.Action)){throw 'Activation command sequence/action mismatch'};$result=@{Sequence=$command.Sequence;Action=$command.Action;Pid=$PID;BootId=(Get-BootId);QpcFrequency=[Diagnostics.Stopwatch]::Frequency;StartQpc=[Diagnostics.Stopwatch]::GetTimestamp();NativeCode=$null;FlushCode=$null;Calls=@();Error=$null}
  try {
   switch($command.Action){
    'create-holder' {$closed=$false;$result.NativeCode=[SUActivationNative]::CreateHolder($config.Target,[Convert]::FromBase64String($config.PBase64),$config.HolderKind,[ref]$closed);$result.SourceHandleClosed=$closed;$result.HolderCreated=($result.NativeCode -eq 0)}
    'duplicate-holder' {$source=[long]0;$remote=[long]0;$result.NativeCode=[SUActivationNative]::DuplicateHolder([int]$command.TargetPid,[ref]$source,[ref]$remote);$result.SourceHandle=$source;$result.RemoteHandle=$remote;$result.TargetPid=[int]$command.TargetPid}
    'adopt-holder' {$result.NativeCode=[SUActivationNative]::AdoptHolder([long]$command.RemoteHandle);$result.RemoteHandle=[long]$command.RemoteHandle;$result.HolderCreated=($result.NativeCode -eq 0)}
    'position-holder' {$position=[long]-1;$result.NativeCode=[SUActivationNative]::Position([long]$command.Offset,[bool]$command.Query,[ref]$position);$result.Position=$position}
    'staged-write-held' {$written=[long]0;$bytes=[Convert]::FromBase64String($command.PayloadBase64);$result.NativeCode=[SUActivationNative]::StageWriteHeld($config.Target,[long]$command.Offset,$bytes,[ref]$written);$result.BytesWritten=$written;if($result.NativeCode -eq 0){$result.PrivateSha256=[SUActivationNative]::HolderDigest([int]$config.ImageLength)};$result.HolderCreated=($result.NativeCode -eq 0)}
    'probe-new-writers' {$sectionOpen=[int]0;$result.OpenCode=[SUActivationNative]::NewWritableOpen($config.Target);$result.SectionCode=[SUActivationNative]::NewWritableSection($config.Target,[ref]$sectionOpen);$result.SectionSourceOpenCode=$sectionOpen;$result.NativeCode=0}
    'map-late' {$result.NativeCode=[SUActivationNative]::MapLate([uint32]$config.ImageLength);$result.Mapped=($result.NativeCode -eq 0)}
    'write-old' {
     foreach($change in $command.Changes){$bytes=[Convert]::FromBase64String($change.BytesBase64);$start=[Diagnostics.Stopwatch]::GetTimestamp();$code=if($config.HolderKind -eq 'handle'){[SUActivationNative]::WriteFileAt([long]$change.Offset,$bytes)}else{[SUActivationNative]::WriteViewAt([long]$change.Offset,$bytes)};$end=[Diagnostics.Stopwatch]::GetTimestamp();$seekCode=[SUActivationNative]::LastSeekCode;$result.Calls+=@{Offset=[long]$change.Offset;Length=$bytes.Length;PayloadSha256=$change.PayloadSha256;NativeCode=$code;SeekCode=$seekCode;StartQpc=$start;EndQpc=$end;Paging=($config.HolderKind -ne 'handle')};if($code -ne 0){throw ('Old holder write failed: Win32 '+$code+'; seek Win32 '+$seekCode)}}
     if($config.HolderKind -eq 'handle'){$result.FlushCode=[SUActivationNative]::FlushHolderFile()}else{$result.FlushCode=[SUActivationNative]::FlushView()};if($result.FlushCode -ne 0){throw ('Old holder flush failed: Win32 '+$result.FlushCode)};$result.NativeCode=0
    }
    'staged-write' {$bytes=[Convert]::FromBase64String($command.PayloadBase64);$start=[Diagnostics.Stopwatch]::GetTimestamp();$closeCode=[int]0;$flush=[int]0;$written=[long]0;$code=[SUActivationNative]::StageWrite($config.Target,[long]$command.Offset,$bytes,[ref]$flush,[ref]$closeCode,[ref]$written);$end=[Diagnostics.Stopwatch]::GetTimestamp();$result.NativeCode=$code;$result.FlushCode=$flush;$result.CloseCode=$closeCode;$result.BytesWritten=$written;$result.Calls+=@{Class='staged-write';NativeCode=$code;FlushCode=$flush;CloseCode=$closeCode;Length=$bytes.Length;PayloadSha256=$command.PayloadSha256;StartQpc=$start;EndQpc=$end};if($code -ne 0){throw ('Post-protection staged write failed: Win32 '+$code)}}
    'release-holder' {$result.NativeCode=[SUActivationNative]::ReleaseHolder();$result.HolderReleased=($result.NativeCode -eq 0);if($result.NativeCode -ne 0){throw ('Holder release failed: Win32 '+$result.NativeCode)}}
    'exit-worker' {$result.NativeCode=[SUActivationNative]::ReleaseHolder();$result.HolderReleased=($result.NativeCode -eq 0);$result.ExitWorker=$true}
    default {throw ('Unknown actor action: '+$command.Action)}
   }
  }catch{$result.Error=$_.Exception.ToString();$workerError=$result.Error;Write-Output ('ScriptError='+$result.Error)}
  $result.EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();$replyPath=Join-Path $config.ActorDirectory ('reply-'+$commandSequence.ToString('D4')+'.clixml');Save-ActivationActorState $result $replyPath -New
  $commandSequence++;if($result.ExitWorker){break}
 }
}catch{$workerError=$_.Exception.ToString();Write-Output ('ScriptError='+$workerError);try{[IO.File]::WriteAllText('__SCRIPT_ERROR__',$workerError)}catch{}}
finally{try{[void][SUActivationNative]::ReleaseHolder()}catch{};$identity.Dispose()}
'@
return ("function Load-State { ${function:Load-State} }`n"+$body)
}
function Publish-ActivationActorCommand($State,[string]$Action,$Fields,[string]$ActorKey='Primary') {
    $slot=$null;$directory=$actorDirectory;$replyDirectory=$actorDirectory
    if($null -ne $State.ActivationActors){
        if(-not $State.ActivationActors.ContainsKey($ActorKey)){throw 'Unknown activation actor route'}
        $slot=$State.ActivationActors[$ActorKey];$replyDirectory=$slot.Directory;$directory=if($slot.CommandDirectory){$slot.CommandDirectory}else{$slot.Directory};$sequence=[int]$slot.NextSequence
    }else{if($ActorKey -cne 'Primary'){throw 'Secondary activation actor route missing'};$sequence=[int]$State.ActorNextSequence}
    $commandPath=Join-Path $directory ('command-'+$sequence.ToString('D4')+'.clixml')
    $value=@{Sequence=$sequence;Action=$Action}
    if($null -ne $Fields){foreach($key in $Fields.Keys){$value[$key]=$Fields[$key]}}
    Save-State $value $commandPath
    if($null -ne $slot){$slot.NextSequence=$sequence+1}else{$State.ActorNextSequence=$sequence+1}
    Save-State $State $statePath
    $replyPath=Join-Path $replyDirectory ('reply-'+$sequence.ToString('D4')+'.clixml')
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((30)*[Diagnostics.Stopwatch]::Frequency))
    do {if(Test-Path -LiteralPath $replyPath){$reply=Load-State $replyPath;if($reply.Sequence -ne $sequence -or $reply.Action -cne $Action -or $reply.BootId -cne (Get-BootId) -or ($null -ne $slot -and $slot.ExpectedPid -ne $reply.Pid)){throw 'Activation actor reply sequence/boot/PID mismatch'};if($reply.Error){throw ('Activation actor '+$Action+' failed: '+$reply.Error)};return $reply};Start-Sleep -Milliseconds 20}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    throw ('Activation actor timeout: action='+$Action+'; sequence='+$sequence+'; no reply after 30s')
}
function Get-ActivationActorIdentity([string]$ActorKey='Primary') {
    $directory=$actorDirectory;$launcher=Join-Path $stateDirectory 'writer.ps1';$taskName=$writerTask
    if($null -ne $state.ActivationActors){
        if(-not $state.ActivationActors.ContainsKey($ActorKey)){throw 'Unknown activation identity route'}
        $slot=$state.ActivationActors[$ActorKey];$directory=$slot.Directory;$launcher=$slot.Launcher;$taskName=$slot.Task
    }elseif($ActorKey -cne 'Primary'){throw 'Secondary activation identity route missing'}
    $identity=Wait-WriterIdentity (Join-Path $directory 'identity.clixml') 60
    if($identity.Sid -cne $state.ActorSid -or $identity.Elevated -or $identity.IsAdministrator -or $identity.Pid -eq $PID -or $identity.BootId -cne (Get-BootId)){throw 'Activation holder identity/session/token proof mismatch'}
    $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$identity.Pid) -ErrorAction Stop
    if($null -eq $process -or $process.SessionId -ne $identity.SessionId -or $process.CommandLine -notlike ('*'+$launcher+'*')){throw 'Activation holder OS process provenance mismatch'}
    $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
    if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $state.ActorSid){throw 'Activation holder OS process owner SID mismatch'}
    if($null -ne $state.ActivationActors){$slot.ExpectedPid=[int]$identity.Pid;Save-State $state $statePath}
    return [pscustomobject]@{Pid=$identity.Pid;Sid=$identity.Sid;Elevated=$identity.Elevated;IsAdministrator=$identity.IsAdministrator;
        SessionId=$identity.SessionId;BootId=$identity.BootId;OwnerSid=$owner.Sid;CommandLine=$process.CommandLine;
        Task=(Get-ScheduledTask -TaskName $taskName | Select-Object TaskName,Principal,State)}
}
function Get-NtDevicePath([string]$DosPath) {
    if(-not('SUActivationDevice' -as [type])){Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;using System.Text;public static class SUActivationDevice{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern uint QueryDosDevice(string n,StringBuilder b,int c);}' }
    $drive=[IO.Path]::GetPathRoot($DosPath).TrimEnd('\');$builder=[Text.StringBuilder]::new(2048)
    if([SUActivationDevice]::QueryDosDevice($drive,$builder,$builder.Capacity) -eq 0){throw ('QueryDosDevice failed for '+$drive+': '+[Runtime.InteropServices.Marshal]::GetLastWin32Error())}
    return $builder.ToString().Split([char]0)[0]+$DosPath.Substring(2)
}
function Invoke-ActivationInspector([string]$Argument,[string]$Prefix,[int]$Timeout=45000) {
    $previous=$env:SAFEUPLOAD_STAGED_PROOF_PROXY
    try {
        if($state.AgentServiceStarted){$env:SAFEUPLOAD_STAGED_PROOF_PROXY='1'}else{Remove-Item Env:SAFEUPLOAD_STAGED_PROOF_PROXY -ErrorAction SilentlyContinue}
        return Invoke-CapturedProcess $inspectorPath $Argument $Prefix $Timeout
    }finally{
        if($null -eq $previous){Remove-Item Env:SAFEUPLOAD_STAGED_PROOF_PROXY -ErrorAction SilentlyContinue}else{$env:SAFEUPLOAD_STAGED_PROOF_PROXY=$previous}
    }
}
function Get-ActivationTaintCounters([string]$Tag) {
    $start=[Diagnostics.Stopwatch]::GetTimestamp()
    $prefix=Join-Path $evidenceDirectory ('activation-taint-'+$Tag+'-'+[guid]::NewGuid().ToString('N'))
    $text=Invoke-ActivationInspector '--counters' $prefix 45000;$values=@{}
    foreach($field in @('TaintsRecorded','TaintLookups','TaintHits','RenamesFromTainted')){
        $matches=@([regex]::Matches($text,('(?m)^'+$field+'\s*:\s*([0-9]{1,20})\s*$')))
        if($matches.Count -ne 1){throw ('Missing/ambiguous actual taint counter: '+$field)}
        $value=[decimal]::Parse($matches[0].Groups[1].Value,[Globalization.CultureInfo]::InvariantCulture)
        if($value -gt [decimal]::Parse('18446744073709551615',[Globalization.CultureInfo]::InvariantCulture)){throw 'Taint counter exceeds wire uint64'}
        $values[$field]=$value.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    return @{StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();QpcFrequency=[Diagnostics.Stopwatch]::Frequency;BootId=(Get-BootId);Values=$values;Raw=$text;StdOutPath=$prefix+'.out';StdErrPath=$prefix+'.err';Scope='MachineWideDiagnostic;NoTargetAttribution'}
}
function Get-ActivationTaintCounterDelta($Before,$After) {
    if($Before.BootId -cne $After.BootId -or $Before.EndQpc -gt $After.StartQpc){throw 'Taint counter receipt ordering/boot mismatch'}
    $deltas=@{};$unchanged=$true
    foreach($field in @('TaintsRecorded','TaintLookups','TaintHits','RenamesFromTainted')){
        $a=[decimal]::Parse($Before.Values[$field],[Globalization.CultureInfo]::InvariantCulture);$b=[decimal]::Parse($After.Values[$field],[Globalization.CultureInfo]::InvariantCulture)
        if($b -lt $a){throw ('Taint counter reset/wrapped: '+$field)}
        $delta=$b-$a;$deltas[$field]=$delta.ToString([Globalization.CultureInfo]::InvariantCulture);$unchanged=$unchanged -and $delta -eq 0
    }
    return @{Status='OK';Before=$Before;After=$After;Deltas=$deltas;NoCounterChanges=$unchanged;LiveTestDisableTaint='Unavailable';ProvesNoTaintDecision=$false}
}
function Get-ActivationInspectorJson([string]$Argument,[string]$Tag) {
    $prefix=Join-Path $evidenceDirectory ('activation-'+$Tag+'-'+[guid]::NewGuid().ToString('N'))
    $out=Invoke-ActivationInspector $Argument $prefix 45000
    $lines=@($out -split "`r?`n" | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
    if($lines.Count -ne 1){throw ('Inspector output was not one JSON record: '+$Argument)}
    $record=$lines[0]|ConvertFrom-Json -ErrorAction Stop
    return [pscustomobject]@{Record=$record;Raw=$out;StdErrPath=$prefix+'.err';StdOutPath=$prefix+'.out';Qpc=[Diagnostics.Stopwatch]::GetTimestamp()}
}
function Get-ActivationEpochStatus([string]$Tag) { return (Get-ActivationInspectorJson '--epoch-status' $Tag).Record }
function Get-ActivationWriterState([string]$Tag) { return (Get-ActivationInspectorJson '--writer-state-status' $Tag).Record }
function Get-ActivationEntry([string]$Path,[string]$Tag) { return (Get-ActivationInspectorJson ('--registry-entry "'+$Path+'"') $Tag) }
function Get-ActivationFullPendingEntry([string]$NtPath,[string]$FileId,[string]$Tag) {
    $snapshot=Get-ActivationInspectorJson '--activating-status' $Tag
    $allEntries=@($snapshot.Record.entries)
    if($snapshot.Record.activatingStatus -ne $true -or
        ($snapshot.Record.totalEntries -isnot [int] -and $snapshot.Record.totalEntries -isnot [long]) -or
        $snapshot.Record.totalEntries -ne $allEntries.Count){throw 'Activating snapshot complete machine-wide count mismatch'}
    $entries=@($allEntries | Where-Object {$_.path -ieq $NtPath -and $_.fileId -ieq $FileId})
    return [pscustomobject]@{Snapshot=$snapshot;Entries=$entries}
}
function Get-ActivationPendingEntry([string]$NtPath,[string]$FileId,[string]$Tag,[string]$DosPath) {
    if([string]::IsNullOrWhiteSpace($DosPath)){throw 'Exact-target activation diagnostic requires explicit DOS path'}
    $snapshot=Get-ActivationInspectorJson ('--activating-target "'+$DosPath+'"') $Tag
    $record=$snapshot.Record;$allEntries=@($record.entries)
    if($record.activatingTarget -isnot [bool] -or -not $record.activatingTarget -or
        $record.requestedPath -ine $NtPath -or
        ($record.matchCount -isnot [int] -and $record.matchCount -isnot [long]) -or
        $record.matchCount -notin @(0,1) -or $record.matchCount -ne $allEntries.Count -or
        ($record.flags -isnot [int] -and $record.flags -isnot [long]) -or $record.flags -ne 0 -or
        ($record.policyGeneration -isnot [int] -and $record.policyGeneration -isnot [long]) -or $record.policyGeneration -le 0){
        throw 'Exact-target activation diagnostic identity/count/global-uncertainty mismatch'
    }
    foreach($entry in $allEntries){
        foreach($field in @('generation','H','C','T','W')){
            if(($entry.$field -isnot [int] -and $entry.$field -isnot [long]) -or $entry.$field -lt 0){throw ('Invalid exact-target counter '+$field)}
        }
        if($entry.path -ine $NtPath -or $entry.fileId -notmatch '^[0-9a-fA-F]{32}$' -or
            $entry.S -cnotin @('NO','YES','Unknown')){throw 'Invalid exact-target entry identity or section state'}
    }
    $entries=@($allEntries | Where-Object {$_.path -ieq $NtPath -and $_.fileId -ieq $FileId})
    return [pscustomobject]@{Snapshot=$snapshot;Entries=$entries;QualificationScope='ExactTargetPointSample;NotMachineWideOrInterval'}
}
function Receive-ActivationStatusFrame($Capture,[string]$Line) {
    if([string]::IsNullOrWhiteSpace($Line) -or $Line.Length -gt 65536){throw 'Service notification stream ended or returned an invalid frame'}
    $record=$Line|ConvertFrom-Json -ErrorAction Stop
    if($record.type -ceq 'status'){
        $Capture.Last=$record;$Capture.LastQpc=[Diagnostics.Stopwatch]::GetTimestamp();$Capture.Sequence++
        $receipt=@{Value=$record;ReceiptQpc=$Capture.LastQpc;Sequence=$Capture.Sequence;ConnectionId=$Capture.ConnectionId;FirstConnectionSnapshot=($Capture.Sequence -eq 1);HolderLive=[bool]$script:ActivationHolderLive}
        if(@($script:ActivationNotificationHistory).Count -ge 4096){throw 'Notification status history cap reached'}
        $script:ActivationNotificationHistory+=@($receipt)
        if($script:ActivationHolderLive -and $null -ne $script:ActivationCandidateGeneration -and $record.protectionActive -eq $true -and $record.admissionCoverage -ceq 'Ready' -and
            $null -ne $record.nativePolicyGeneration -and [uint32]$record.nativePolicyGeneration -eq $script:ActivationCandidateGeneration){$script:ActivationObservedPrematureReady+=@($receipt)}
    }elseif($null -eq $Capture.Last){throw 'First service pipe record is not current StatusNotification'}
}
function Close-ActivationNotificationCapture {
    $capture=$script:ActivationNotificationCapture
    if($null -eq $capture){return}
    try {
        if($null -ne $capture.Reader){
            for($n=0;$n -lt 64;$n++){
                if($null -eq $capture.ReadTask){$capture.ReadTask=$capture.Reader.ReadLineAsync()}
                if(-not $capture.ReadTask.IsCompleted){break}
                $line=$capture.ReadTask.GetAwaiter().GetResult();$capture.ReadTask=$null
                if($null -eq $line){break}
                Receive-ActivationStatusFrame $capture $line
                if($n -eq 63){throw 'Notification closure drain cap reached; capture incomplete'}
            }
        }
    }finally{
        try {
            # Close the native pipe first; do not dispose a reader with unjoined I/O.
            $capture.Pipe.Dispose()
            if($null -ne $capture.Reader){
                for($n=0;$n -lt 64;$n++){
                    if($null -eq $capture.ReadTask){$capture.ReadTask=$capture.Reader.ReadLineAsync()}
                    try{$null=$capture.ReadTask.Wait(1000)}catch{if(-not $capture.ReadTask.IsCompleted){throw}}
                    if(-not $capture.ReadTask.IsCompleted){throw 'Notification read did not complete after checked pipe closure.'}
                    if($capture.ReadTask.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){
                        $line=$capture.ReadTask.GetAwaiter().GetResult();$capture.ReadTask=$null
                        if($null -eq $line){break}
                        Receive-ActivationStatusFrame $capture $line
                    }elseif($capture.ReadTask.IsFaulted){
                        $failure=$capture.ReadTask.Exception.GetBaseException()
                        if($failure -isnot [IO.IOException] -and $failure -isnot [ObjectDisposedException]){throw $failure}
                        break
                    }else{break}
                    if($n -eq 63){throw 'Notification post-close buffer drain cap reached; capture incomplete'}
                }
            }
        }finally{
            try{if($null -ne $capture.Reader){$capture.Reader.Dispose()}}finally{$script:ActivationNotificationCapture=$null}
        }
    }
}
function Get-ActivationProductStatus([string]$Tag,[int]$TimeoutMs=5000,[switch]$FirstSnapshotOnly) {
    if(-not('SUActivationPipeProof' -as [type])){Add-Type -TypeDefinition @'
using System;using System.ComponentModel;using Microsoft.Win32.SafeHandles;using System.Runtime.InteropServices;
public static class SUActivationPipeProof{[DllImport("kernel32.dll",SetLastError=true)]public static extern bool GetNamedPipeServerProcessId(SafePipeHandle h,out uint pid);}
'@}
    $start=[Diagnostics.Stopwatch]::GetTimestamp();$deadline=$start+[long]($TimeoutMs*[Diagnostics.Stopwatch]::Frequency/1000)
    try {
        if($null -eq $script:ActivationNotificationCapture){
            $pipe=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent',[IO.Pipes.PipeDirection]::In,[IO.Pipes.PipeOptions]::Asynchronous)
            $script:ActivationNotificationCapture=@{Pipe=$pipe;Reader=$null;ReadTask=$null;Last=$null;LastQpc=$null;Sequence=0;ServerPid=$null;ServerSid=$null;ConnectionId=[guid]::NewGuid().ToString('N')}
            $pipe.Connect($TimeoutMs)
            $serverPid=[uint32]0;if(-not [SUActivationPipeProof]::GetNamedPipeServerProcessId($pipe.SafePipeHandle,[ref]$serverPid) -or $serverPid -eq 0){throw 'Service notification pipe server PID unavailable'}
            $server=Get-CimInstance Win32_Process -Filter ('ProcessId='+$serverPid) -ErrorAction Stop
            if($null -eq $server -or $server.Name -cne 'SafeUpload.Agent.Service.exe'){throw 'Notification pipe server image mismatch'}
            $owner=Invoke-CimMethod -InputObject $server -MethodName GetOwnerSid -ErrorAction Stop
            if($owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18'){throw 'Notification pipe server is not LocalSystem'}
            $script:ActivationNotificationCapture.ServerPid=$serverPid;$script:ActivationNotificationCapture.ServerSid=$owner.Sid
            $script:ActivationNotificationCapture.Reader=[IO.StreamReader]::new($pipe,[Text.Encoding]::UTF8,$false,4096,$true)
        }
        $capture=$script:ActivationNotificationCapture;$beforeSequence=$capture.Sequence;$drained=0
        do {
            if($null -eq $capture.ReadTask){$capture.ReadTask=$capture.Reader.ReadLineAsync()}
            $remaining=[int][Math]::Max(0,[Math]::Min($TimeoutMs,($deadline-[Diagnostics.Stopwatch]::GetTimestamp())*1000/[Diagnostics.Stopwatch]::Frequency))
            if(-not $capture.ReadTask.Wait($remaining)){break}
            $line=$capture.ReadTask.GetAwaiter().GetResult();$capture.ReadTask=$null
            Receive-ActivationStatusFrame $capture $line;$drained++
            if($FirstSnapshotOnly -and $null -ne $capture.Last){break}
            if($drained -ge 64){throw 'Notification frame drain cap reached; status capture incomplete'}
            # Drain already queued frames, then retain the pending read for the next call.
            $capture.ReadTask=$capture.Reader.ReadLineAsync()
            if(-not $capture.ReadTask.IsCompleted){break}
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        if($null -eq $capture.Last){throw 'No authenticated status publication received within the QPC deadline'}
        return [pscustomobject]@{Status=$(if($capture.Sequence -eq $beforeSequence){'INCONCLUSIVE'}else{'OK'});Reason=$(if($capture.Sequence -eq $beforeSequence){'No newly received status; retained stream state is not a current snapshot.'}else{$null});Tag=$Tag;StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();QpcFrequency=[Diagnostics.Stopwatch]::Frequency;BootId=(Get-BootId);ServerPid=$capture.ServerPid;ServerSid=$capture.ServerSid;Value=$capture.Last;
            StatusReceiptQpc=$capture.LastQpc;StatusSequence=$capture.Sequence;ConnectionId=$capture.ConnectionId;FirstConnectionSnapshot=($beforeSequence -eq 0 -and $capture.Sequence -eq 1);RetainedStreamState=($capture.Sequence -eq $beforeSequence);WholeIntervalLossFree=$false}
    }catch{
        $reason=$_.Exception.Message;try{Close-ActivationNotificationCapture}catch{$reason+='; closure: '+$_.Exception.Message}
        return [pscustomobject]@{Status='INCONCLUSIVE';TransportInvalidated=$true;Tag=$Tag;Reason=$reason;StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();BootId=(Get-BootId);QpcFrequency=[Diagnostics.Stopwatch]::Frequency}
    }
}
function Get-ActivationCurrentProductStatus([string]$Tag,[int]$TimeoutMs=5000) {
    Close-ActivationNotificationCapture
    return Get-ActivationProductStatus $Tag $TimeoutMs -FirstSnapshotOnly
}
function Wait-ActivationProductStatus([string]$ExpectedCoverage,[uint32]$PolicyGeneration,[int]$Seconds,[string]$Tag) {
    Close-ActivationNotificationCapture
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long](($Seconds)*[Diagnostics.Stopwatch]::Frequency));$last=$null;$reason='No newly received service status.'
    do {$last=Get-ActivationProductStatus $Tag 3000;if($last.TransportInvalidated){throw ('Notification capture invalidated: '+$last.Reason)};if($last.Status -eq 'OK'){
        $s=$last.Value
        if($s.protectionActive -and $s.admissionCoverage -eq $ExpectedCoverage -and $null -ne $s.nativePolicyGeneration -and [uint32]$s.nativePolicyGeneration -eq $PolicyGeneration){return $last}
        if($s.protectionActive -eq $true -and $s.admissionCoverage -eq 'Ready' -and $ExpectedCoverage -eq 'Pending' -and $null -ne $s.nativePolicyGeneration -and [uint32]$s.nativePolicyGeneration -eq $PolicyGeneration){$reason='Service reported Ready while the pre-scope holder was still live.'}
        else{$reason=('Current service status did not match '+$ExpectedCoverage+' for policy generation '+$PolicyGeneration+': coverage='+$s.admissionCoverage+'; reason='+$s.admissionCoverageReason+'; nativeGeneration='+$s.nativePolicyGeneration)}
    }else{$reason=$last.Reason};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    throw ('Service readiness timeout ('+$ExpectedCoverage+'): '+$reason)
}
function Get-ActivationRawDifference($Baseline,$Sample,[string]$Path) {
    $base=@($Baseline.Images | Where-Object {$_.Role -eq 'Current' -and $_.Path -ieq $Path -and -not $_.Absent})
    $after=@($Sample.Captures | ForEach-Object {$_.Images} | Where-Object {$_.Role -eq 'Current' -and $_.Path -ieq $Path -and -not $_.Absent})
    if($base.Count -ne 1 -or $after.Count -ne 1){return [pscustomobject]@{Status='INCONCLUSIVE';Reason='Raw current image absent or ambiguous.';DifferingBytes=$null}}
    $b=$base[0];$a=$after[0]
    if($b.Identity.FileId -cne $a.Identity.FileId -or $b.Length -ne $a.Length -or $b.Runs.Count -ne $a.Runs.Count){return [pscustomobject]@{Status='INCONCLUSIVE';Reason='Destination identity, length, or allocation-run count changed between the raw capture checkpoints.';DifferingBytes=$null}}
    for($i=0;$i -lt $b.Runs.Count;$i++){if($b.Runs[$i].Vcn -ne $a.Runs[$i].Vcn -or $b.Runs[$i].NextVcn -ne $a.Runs[$i].NextVcn -or $b.Runs[$i].Lcn -ne $a.Runs[$i].Lcn){return [pscustomobject]@{Status='INCONCLUSIVE';Reason='Destination extent map changed between the raw capture checkpoints.';DifferingBytes=$null}}}
    $baseRuns=@($b.Containers | Where-Object Kind -eq 'DATA' | Sort-Object Offset);$afterRuns=@($a.Containers | Where-Object Kind -eq 'DATA' | Sort-Object Offset)
    if($baseRuns.Count -eq 0 -or $baseRuns.Count -ne $afterRuns.Count){return [pscustomobject]@{Status='INCONCLUSIVE';Reason='Raw DATA extent coverage incomplete or changed.';DifferingBytes=$null}}
    [long]$diff=0
    for($i=0;$i -lt $baseRuns.Count;$i++){
        $x=$baseRuns[$i];$y=$afterRuns[$i]
        if($x.Offset -ne $y.Offset -or $x.Length -ne $y.Length){return [pscustomobject]@{Status='INCONCLUSIVE';Reason='Raw DATA extent offset/length changed.';DifferingBytes=$null}}
        $xb=[IO.File]::ReadAllBytes($x.Artifact.Path);$yb=[IO.File]::ReadAllBytes($y.Artifact.Path)
        if($xb.Length -ne $yb.Length){return [pscustomobject]@{Status='INCONCLUSIVE';Reason='Raw DATA artifact length changed.';DifferingBytes=$null}}
        for($j=0;$j -lt $xb.Length;$j++){if($xb[$j] -ne $yb[$j]){$diff++}}
    }
    return [pscustomobject]@{Status='OK';Reason='Complete raw DATA extent comparison.';DifferingBytes=$diff;BeforeSha256=$b.Sha256;AfterSha256=$a.Sha256;FileId=$b.Identity.FileId;ExtentCount=$baseRuns.Count}
}
function ConvertFrom-ActivationTrace([string]$Raw,[string]$FileId) {
    $records=@()
    foreach($line in @($Raw -split "`r?`n" | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})){
        try{$records+=@($line|ConvertFrom-Json -ErrorAction Stop)}catch{throw ('Admission trace JSON parse failed: '+$_.Exception.Message)}
    }
    $summaries=@($records|Where-Object {$null -ne $_.summary});if($summaries.Count -ne 1){throw 'Admission trace summary missing or ambiguous'}
    $entries=@($records|Where-Object {$null -ne $_.sequence -and $_.fileId -ieq $FileId})
    if([uint64]$summaries[0].lostEntries -ne 0 -or [uint64]$summaries[0].cursor -ne [uint64]$summaries[0].snapshotSequence+1){throw 'Admission trace lost/overwritten or incomplete sequence'}
    $writeEnds=@($entries|Where-Object {$_.event -eq 'w_end' -and $_.ioStatus -eq '0x00000000' -and ([Convert]::ToUInt32($_.completionFlags.Substring(2),16) -band 1) -ne 0})
    $pairs=@();foreach($end in $writeEnds){$begin=@($entries|Where-Object {$_.event -eq 'w_begin' -and [uint64]$_.ticketSequence -eq [uint64]$end.ticketSequence -and $_.writeOffset -eq $end.writeOffset -and $_.writeLength -eq $end.writeLength});if($begin.Count -eq 1){$pairs+=@{Begin=$begin[0];End=$end}}}
    return [pscustomobject]@{Summary=$summaries[0];Entries=$entries;CompletedWritePairs=$pairs;PayloadSha256Available=$false;Reason='Diagnostic W_BEGIN/W_END records carry file ID, offset, length, status and completion, but no lower payload digest.'}
}
function ConvertFrom-ActivationPromotionTrace([string]$Raw,[string]$FileId) {
    $records=@()
    foreach($line in @($Raw -split "`r?`n" | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})){
        try{$records+=@($line|ConvertFrom-Json -ErrorAction Stop)}catch{throw ('Promotion trace JSON parse failed: '+$_.Exception.Message)}
    }
    if(@($records|Where-Object {$_.promotionTraceError -or $_.promotionTraceIncomplete}).Count){throw 'Promotion trace reported a gap or protocol error'}
    $summary=@($records|Where-Object {$null -ne $_.promotionTraceSummary});$batches=@($records|Where-Object {$null -ne $_.promotionTraceBatch})
    if($summary.Count -ne 1 -or -not $summary[0].completeSnapshot -or $batches.Count -eq 0){throw 'Promotion trace complete snapshot summary missing'}
    foreach($batch in $batches){if([uint64]$batch.lostEvents -ne 0 -or [uint64]$batch.overwrittenEvents -ne 0 -or [uint32]$batch.flags -ne 0){throw 'Promotion trace lost/overwritten evidence'} }
    $entries=@($records|Where-Object {$_.promotionTraceEntry -and $_.fileId -ieq $FileId})
    return [pscustomobject]@{Summary=$summary[0];Batches=$batches;Entries=$entries;RawRecords=$records}
}
function Get-LatencyVerdict($Calls,$Classes,[long]$Frequency) {
    $result=@()
    foreach($class in $Classes){
        $raw=@($Calls | Where-Object Class -ceq $class | ForEach-Object {
            [pscustomobject]@{Trial=$_.Trial;Cold=$_.Cold;NativeCode=$_.NativeCode;StartQpc=$_.StartQpc;EndQpc=$_.EndQpc;Ms=1000.0*($_.EndQpc-$_.StartQpc)/$Frequency}
        })
        $unheld=@($raw | Where-Object {-not $_.Cold} | Sort-Object Ms)
        $p95=$null;$max=$null;$verdict='INCONCLUSIVE'
        if($raw.Count -gt 0){$max=($raw | Measure-Object Ms -Maximum).Maximum}
        if($unheld.Count -ge 100){$p95=$unheld[[int][Math]::Ceiling(.95*$unheld.Count)-1].Ms;$verdict='PASS'}
        if(@($raw | Where-Object {$_.Ms -lt 0}).Count -gt 0){$verdict='INCONCLUSIVE'}
        if(($null -ne $p95 -and $p95 -gt 250) -or ($null -ne $max -and $max -gt 1000)){$verdict='FAIL'}
        $result+= [pscustomobject]@{Class=$class;Verdict=$verdict;UnheldCount=$unheld.Count;P95Ms=$p95;MaxMs=$max;Samples=$raw}
    };return ,$result
}
function Get-VerifierEvidence([string]$Tag,[switch]$RequireMode) {
    $active=(& verifier.exe /query 2>&1 | Out-String);$activeExit=$LASTEXITCODE
    $settings=(& verifier.exe /querysettings 2>&1 | Out-String);$settingsExit=$LASTEXITCODE
    Write-DurableFile (Join-Path $evidenceDirectory ($Tag+'-verifier-active.txt')) $active -New
    Write-DurableFile (Join-Path $evidenceDirectory ($Tag+'-verifier-settings.txt')) $settings -New
    if($activeExit -notin @(0,2) -or $settingsExit -notin @(0,2)){throw 'Verifier readback failed'}
    $flags=@([regex]::Matches($active,'(?im)^Verifier Flags:\s+0x([0-9a-f]+)\s*$') | ForEach-Object {[Convert]::ToUInt32($_.Groups[1].Value,16)})
    if($RequireMode){
        if($Mode -eq 'ordinary'){
            if($active -notmatch 'No drivers are currently verified' -or $settings -notmatch 'Verifier Flags:\s+0x00000000'){throw 'Ordinary mode has active/configured Verifier'}
        }elseif($active -notmatch 'SafeUpload\.sys' -or $flags.Count -ne 1 -or $flags[0] -eq 0){throw 'Required active Verifier missing'}
        elseif($Mode -eq 'runtime-verifier' -and $flags[0] -ne 0x13B){throw 'Runtime Verifier must read back exact 0x13B'}
        elseif($Mode -eq 'boot-verifier' -and ($null -eq $state.BootVerifierFlags -or $flags[0] -ne $state.BootVerifierFlags)){throw 'Active boot Verifier flags differ from configured exact flags'}
    }
    return [pscustomobject]@{Active=$active;Settings=$settings;ActiveFlags=$flags;ActiveExit=$activeExit;SettingsExit=$settingsExit;RuntimeDriverEntryUnchecked=($Mode -eq 'runtime-verifier')}
}
function Get-Readiness {
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((180)*[Diagnostics.Stopwatch]::Frequency))
    do {
        $out=Invoke-CapturedProcess $inspectorPath '--admission-volume-status' (Join-Path $evidenceDirectory ('status-'+[guid]::NewGuid().ToString('N')))
        $status=$out | ConvertFrom-Json
        $volume=@(Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'")
        if($volume.Count -ne 1){throw 'Boot volume ambiguous'}
        $guid=$volume[0].DeviceID
        $entries=@($status.admissionVolumes | Where-Object { $_.volumeGuidStatus -eq 0 -and ([string]$_.volumeGuid).ToLowerInvariant().Contains(([regex]::Match($guid,'\{[0-9a-fA-F-]+\}').Value).ToLowerInvariant()) })
        $filter=(& fltmc.exe instances -f SafeUpload 2>&1 | Out-String);$filterExit=$LASTEXITCODE
        if($entries.Count -eq 1 -and $status.bootPolicyState -eq 1 -and $entries[0].trustState -eq 3 -and $entries[0].canaryState -eq 2 -and
            ($entries[0].setupFlags -band 4) -ne 0 -and $filterExit -eq 0 -and $filter -match '(?m)\bC:\s'){
            return [pscustomobject]@{BootId=(Get-BootId);Qpc=[Diagnostics.Stopwatch]::GetTimestamp();QpcFrequency=[Diagnostics.Stopwatch]::Frequency;
                Utc=[DateTime]::UtcNow.ToString('o');VolumeGuid=$guid;Status=$status;Entry=$entries[0];FilterInstances=$filter;FilterReady=$true}
        }
        Start-Sleep -Milliseconds 200
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    throw 'Durable readiness unavailable: valid BootPolicy/newly-mounted/canary/trust/filter required'
}
function Get-ExpectedCheckpoint($Baseline,[string]$PhaseName,[long]$Sequence) {
    $storage=@();$dirs=@()
    foreach($image in $Baseline.Images){
        if($image.Role -eq 'Parent'){$dirs+=@{Path=$image.Path;Entries=$image.DirectoryEntries;SecurityId=$image.SecurityId;Sddl=$image.Sddl}}
        elseif($image.Role -eq 'Current'){
            if($image.Absent){$storage+=@{Path=$image.Path;Kind='Absent'}}
            else{
                $raw=[ordered]@{};$api=[ordered]@{}
                foreach($field in @('Attributes','Creation','Modified','Changed','Accessed','Links')){$raw[$field]=$image.RawMetadata.$field;$api[$field]=$image.Identity.$field}
                $storage+= [pscustomobject]@{Path=$image.Path;Kind='Final';Version='Baseline';FileId=$image.Identity.FileId;Generation=0;ZeroPadding=$false;
                    Metadata=[pscustomobject]@{Raw=[pscustomobject]$raw;Api=[pscustomobject]$api;SecurityId=$image.SecurityId;Sddl=$image.Sddl;VolumeGuid=$Baseline.Geometry.Guid;
                        AccessWindowStartFileTime=$Baseline.CaptureStartedFileTime;
                        AccessRule=$row.MetadataExpectations.Accessed;AccessReason=$row.MetadataExpectations.AccessReason}}
            }
        }
    }
    return [pscustomobject]@{Phase=$PhaseName;OperationSequence=$Sequence;State=$row.ExpectedTimeline[2];Storage=$storage;Directories=$dirs;ReadDenials=@()}
}
function ConvertFrom-NtfsLastAccessOutput([string]$Text,[int]$ExitCode) {
    $matches=[regex]::Matches($Text,'(?m)^\s*DisableLastAccess\s*=\s*([0-3])\s*\((User|System) Managed, (Enabled|Disabled)\)\s*$')
    if($ExitCode -ne 0 -or $matches.Count -ne 1){return [pscustomobject]@{Value=$null;Management=$null;UpdatesDisabled=$null}}
    return [pscustomobject]@{Value=[int]$matches[0].Groups[1].Value;Management=$matches[0].Groups[2].Value;UpdatesDisabled=($matches[0].Groups[3].Value -ceq 'Disabled')}
}
function Get-LastAccessEvidence {
    $text=(& fsutil.exe behavior query disablelastaccess 2>&1 | Out-String);$code=$LASTEXITCODE
    $parsed=ConvertFrom-NtfsLastAccessOutput $text $code
    return [pscustomobject]@{Command='fsutil.exe behavior query disablelastaccess';Output=$text;ExitCode=$code;
        Value=$parsed.Value;Management=$parsed.Management;UpdatesDisabled=$parsed.UpdatesDisabled;
        BootId=(Get-BootId);VolumeGuid=$state.VolumeGuid;Qpc=[Diagnostics.Stopwatch]::GetTimestamp();
        RegistryValue=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem').NtfsDisableLastAccessUpdate;
        Note='Query only: set disablelastaccess changes machine policy and may require reboot. No default is assumed.'}
}
function Initialize-ServiceEvidenceReader {
    if('SUProofFile' -as [type]){return}
    # Separate harness helper. Nothing in the NTFS decoder is modified.
    Add-Type -TypeDefinition @'
using System; using System.IO; using System.Collections.Generic; using System.ComponentModel;
using System.Runtime.InteropServices; using System.Security.AccessControl; using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public sealed class SUProofObject : IDisposable {
 public SafeFileHandle Handle; public string Path, Sddl, Owner; public bool Directory;
 public void Dispose() { if(Handle!=null) Handle.Dispose(); }
}
public sealed class SUProofTail { public byte[] Bytes; public long Offset; }
public static class SUProofFile {
 [StructLayout(LayoutKind.Sequential)] struct Info { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write; public uint Volume,High,Low,Links,IdHigh,IdLow; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle h,int type,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr sd);
 [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr sd);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr source,SafeFileHandle h,IntPtr target,out SafeFileHandle copy,uint access,bool inherit,uint options);
 public static SUProofObject Open(string path,bool directory,bool protect) { return Open(path,directory,protect,false,false); }
 public static SUProofObject Open(string path,bool directory,bool protect,bool live,bool trustedAdminOwner) {
  var h=CreateFile(path,0x80020000u,directory?3u:(live?7u:1u),IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  if(h.IsInvalid){int e=Marshal.GetLastWin32Error();h.Dispose();throw new Win32Exception(e,"Service evidence open failed: "+path+"; "+new Win32Exception(e).Message);}
  try {
   Info i;if(!GetFileInformationByHandle(h,out i))throw new Win32Exception(Marshal.GetLastWin32Error());
   if((i.Attributes&0x400)!=0 || ((i.Attributes&0x10)!=0)!=directory || (!directory && i.Links!=1))throw new IOException("Reparse/type/link-count journal object rejected.");
   IntPtr owner,group,dacl,sacl,sd;uint code=GetSecurityInfo(h,1,7,out owner,out group,out dacl,out sacl,out sd);
   if(code!=0)throw new Win32Exception((int)code);
   // FileSecurity treats this as a non-container and loses OI/CI inheritance
   // flags while projecting access rules. Decode directories as containers.
   FileSystemSecurity security=directory?(FileSystemSecurity)new DirectorySecurity():new FileSecurity();try{byte[] bytes=new byte[GetSecurityDescriptorLength(sd)];Marshal.Copy(sd,bytes,0,bytes.Length);security.SetSecurityDescriptorBinaryForm(bytes);}finally{LocalFree(sd);}
   string sid=security.GetOwner(typeof(SecurityIdentifier)).Value;
   if(protect) {
    if((sid!="S-1-5-18" && (!trustedAdminOwner || sid!="S-1-5-32-544")) || !security.AreAccessRulesProtected)throw new IOException("Trusted owner and protected DACL required.");
    var rules=security.GetAccessRules(true,true,typeof(SecurityIdentifier));bool system=false,admin=false;
    if(rules.Count!=2)throw new IOException("Exact private SYSTEM/Administrators DACL required.");
    foreach(FileSystemAccessRule r in rules) {
     string trustee=r.IdentityReference.Value;
     if(r.AccessControlType!=AccessControlType.Allow || r.IsInherited || r.FileSystemRights!=FileSystemRights.FullControl ||
       r.PropagationFlags!=PropagationFlags.None || r.InheritanceFlags!=(directory?(InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit):InheritanceFlags.None))throw new IOException("Non-exact journal ACE.");
     if(trustee=="S-1-5-18" && !system)system=true;else if(trustee=="S-1-5-32-544" && !admin)admin=true;else throw new IOException("Unexpected journal trustee.");
    }
    if(!system || !admin)throw new IOException("Missing private journal trustee.");
   }
   return new SUProofObject{Handle=h,Path=path,Directory=directory,Owner=sid,Sddl=security.GetSecurityDescriptorSddlForm(AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access)};
  }catch(Exception ex){h.Dispose();throw new IOException("Service evidence object rejected: "+path+"; "+ex.Message,ex);}
 }
 public static byte[] Read(SUProofObject o,int maximum) {
  // The same authenticated handle supplies all bytes; no path reopen/ACL repair.
  SafeFileHandle copy;if(!DuplicateHandle(GetCurrentProcess(),o.Handle,GetCurrentProcess(),out copy,0,false,2))throw new Win32Exception(Marshal.GetLastWin32Error());
  using(var stream=new FileStream(copy,FileAccess.Read,4096,false)) {
   if(stream.Length>maximum)throw new IOException("Product evidence size bound exceeded.");
   byte[] b=new byte[(int)stream.Length];int offset=0,n;while(offset<b.Length && (n=stream.Read(b,offset,b.Length-offset))>0)offset+=n;
   if(offset!=b.Length || stream.Length!=b.Length)throw new IOException("Short/unstable product evidence read.");return b;
  }
 }
 public static SUProofTail ReadTail(SUProofObject o,int maximum) {
  // A fixed suffix is only a transfer-discovery hint. Round qualification
  // still uses the complete authenticated manifest retained in a snapshot.
  SafeFileHandle copy;if(!DuplicateHandle(GetCurrentProcess(),o.Handle,GetCurrentProcess(),out copy,0,false,2))throw new Win32Exception(Marshal.GetLastWin32Error());
  using(var stream=new FileStream(copy,FileAccess.Read,4096,false)) {
   long length=stream.Length;if(length>4194304)throw new IOException("Notification segment size bound exceeded.");
   long offset=Math.Max(0,length-maximum);stream.Position=offset;
   byte[] b=new byte[(int)(length-offset)];int total=0,n;
   while(total<b.Length && (n=stream.Read(b,total,b.Length-total))>0)total+=n;
   if(total!=b.Length)throw new IOException("Short notification tail read.");
   return new SUProofTail{Bytes=b,Offset=offset};
  }
 }
}
'@
}
function ConvertFrom-NotificationRecord($Segments,[byte[]]$HeadBytes) {
    $entries=@();$utf8=[Text.UTF8Encoding]::new($false,$true);$sha=[Security.Cryptography.SHA256]::Create()
    try {
        foreach($segment in $Segments){
            [byte[]]$bytes=$segment.Bytes
            if($bytes.Length -eq 0 -or $bytes.Length -gt 4194304 -or $bytes[$bytes.Length-1] -ne 10){throw 'Notification segment empty, oversized, or partial.'}
            $start=0
            for($i=0;$i -lt $bytes.Length;$i++){
                if($bytes[$i] -ne 10){continue}
                $length=$i-$start
                if($length -le 0 -or $length -ge 16384){throw 'Invalid notification line size.'}
                $text=$utf8.GetString($bytes,$start,$length);$entry=$text | ConvertFrom-Json
                if($entry.Version -ne 1 -or $entry.Sequence -le 0 -or $null -eq $entry.DroppedThroughSequence -or $entry.DroppedThroughSequence -lt 0 -or
                    $entry.DroppedThroughSequence -ge $entry.Sequence -or [string]::IsNullOrWhiteSpace($entry.BootId) -or
                    [string]::IsNullOrWhiteSpace($entry.Utc) -or $null -eq $entry.Qpc -or $entry.Qpc -lt 0 -or $entry.QpcFrequency -le 0 -or
                    $entry.PreviousSha256 -cnotmatch '^[0-9A-F]{64}$' -or $entry.Kind -cnotin @('Start','Heartbeat','Stop','Rotation','Transfer','Event','Status')){throw 'Invalid notification identity/time/kind.'}
                $utcText=if($entry.Utc -is [DateTime]){$entry.Utc.ToString('o')}else{[string]$entry.Utc}
                if([guid]::Parse($entry.InstanceId) -eq [guid]::Empty -or [DateTimeOffset]::Parse($utcText).Offset -ne [TimeSpan]::Zero){throw 'Invalid notification instance or UTC.'}
                if($entry.Kind -ceq 'Transfer' -and ([guid]::Parse($entry.TransferId) -eq [guid]::Empty -or $entry.Phase -cnotin @('Analyzing','Released','Blocked','Retained'))){throw 'Invalid transfer notification.'}
                if($entry.Kind -ceq 'Event' -and ([guid]::Parse($entry.EventId) -eq [guid]::Empty -or $entry.Phase -cnotin @('Approved','Blocked','AllowedWithoutInspection','Retained'))){throw 'Invalid event notification.'}
                $hash=([BitConverter]::ToString($sha.ComputeHash($bytes,$start,$length))).Replace('-','')
                if($entries.Count){
                    $prior=$entries[$entries.Count-1]
                    if($entry.Sequence -ne $prior.Entry.Sequence+1 -or $entry.PreviousSha256 -cne $prior.Hash){throw 'Notification sequence/hash chain gap.'}
                    if($entry.DroppedThroughSequence -lt $prior.Entry.DroppedThroughSequence -or
                        ($entry.DroppedThroughSequence -ne $prior.Entry.DroppedThroughSequence -and $entry.Kind -cne 'Rotation')){throw 'Unannounced notification rotation loss.'}
                }
                $entries+= [pscustomobject]@{Entry=$entry;Hash=$hash;Artifact=$segment.Artifact};$start=$i+1
            }
        }
        if($entries.Count -eq 0 -or $HeadBytes.Length -gt 4096){throw 'Missing or oversized notification head.'}
        $head=$utf8.GetString($HeadBytes) | ConvertFrom-Json
        $first=$entries[0].Entry;$last=$entries[$entries.Count-1]
        if($first.Sequence -ne $last.Entry.DroppedThroughSequence+1 -or
            ($first.Sequence -eq 1 -and $first.PreviousSha256 -cne ('0'*64))){throw 'Unannounced retained-prefix loss.'}
        if($head.Version -ne 1 -or $head.Sequence -ne $last.Entry.Sequence -or $head.Sha256 -cne $last.Hash){throw 'Notification tail truncation/head mismatch.'}
        return [pscustomobject]@{Entries=$entries;Head=$head}
    }finally{$sha.Dispose()}
}
function Get-NotificationTailCoverage($Tail,[string]$BootId,[long]$Frequency,[long]$MinimumQpc) {
    # Input is already the complete authenticated chain. Historical bytes remain
    # evidence, but cannot establish a current-boot notification window.
    if($Tail.BootId -cne $BootId){return [pscustomobject]@{Status='INCONCLUSIVE';HistoricalTail=$true;RecordedBootId=$Tail.BootId;Reason=('Authenticated historical notification tail: recorded='+$Tail.BootId+'; required='+$BootId+'. No current-boot heartbeat coverage.')}}
    if($Tail.QpcFrequency -ne $Frequency){throw 'Notification tail QPC frequency mismatch.'}
    if($Tail.Qpc -lt $MinimumQpc){return [pscustomobject]@{Status='INCONCLUSIVE';HistoricalTail=$false;RecordedBootId=$Tail.BootId;Reason=('Authenticated notification tail precedes snapshot fence: tailQpc='+$Tail.Qpc+'; minimumQpc='+$MinimumQpc+'. No heartbeat covers the fence.')}}
    return [pscustomobject]@{Status='OK';HistoricalTail=$false;RecordedBootId=$Tail.BootId;Reason='Authenticated notification record covers snapshot fence.'}
}
function Get-NotificationFenceWaitDecision($Coverage,[long]$NowQpc,[long]$DeadlineQpc) {
    # Coverage is produced only by the authenticated reader and retains the
    # same boot/frequency/fence requirements used by assertion evaluation.
    if($Coverage.Status -cnotin @('OK','INCONCLUSIVE')){throw 'Invalid notification fence coverage status.'}
    if($NowQpc -gt $DeadlineQpc){return 'TimedOut'}
    if($Coverage.Status -ceq 'OK'){return 'Covered'}
    if($NowQpc -ge $DeadlineQpc){return 'TimedOut'}
    return 'Wait'
}

function Get-NotificationInventoryDecision([string[]]$Names,[long]$NowQpc,$Wait) {
    $unknown=@($Names | Where-Object {$_ -cnotin @('emissions.jsonl','previous.jsonl','head.json','writer.lock')})
    $missing=@(@('emissions.jsonl','head.json','writer.lock') | Where-Object {$Names -cnotcontains $_})
    $onlyHead=$unknown.Count -eq 1 -and $unknown[0] -ceq 'head.tmp' -and $missing.Count -eq 0
    if($onlyHead -and ($null -eq $Wait.StartQpc -or $Wait.Cleared)){
        $Wait.StartQpc=$NowQpc;$Wait.DeadlineQpc=[Math]::Min($Wait.OuterDeadlineQpc,$NowQpc+[long](5*$Wait.QpcFrequency))
        $Wait.Cleared=$false;$Wait.TimedOut=$false
        $Wait.Windows+=@([ordered]@{StartQpc=$Wait.StartQpc;DeadlineQpc=$Wait.DeadlineQpc;EndQpc=$null;DurationMs=$null;Cleared=$false;TimedOut=$false})
    }
    $decision='Accept';$reason=$null
    if($missing.Count -or ($unknown.Count -and -not $onlyHead)){$decision='Reject'}
    elseif($null -ne $Wait.StartQpc -and ($onlyHead -or -not $Wait.Cleared) -and $NowQpc -ge $Wait.DeadlineQpc){$decision='Reject';$Wait.TimedOut=$true}
    elseif($onlyHead){$decision='Wait'}
    if($decision -cne 'Accept'){
        $reason='Missing/unrecognized notification record child. Unknown='+ (ConvertTo-Json -InputObject $unknown -Compress)+'; Missing='+ (ConvertTo-Json -InputObject $missing -Compress)
        if($Wait.TimedOut){$reason+='; head.tmp did not clear within the QPC-bounded 5 s wait.'}
    }
    $receipt=[pscustomobject]@{ReadQpc=$NowQpc;ChildNames=@($Names);UnknownChildNames=$unknown;MissingChildNames=$missing;Decision=$decision;Reason=$reason}
    $Wait.Observations+=@($receipt)
    if($null -ne $Wait.StartQpc -and (-not $Wait.Cleared -or $decision -cne 'Accept')){
        $Wait.EndQpc=$NowQpc;$Wait.DurationMs=1000.0*($NowQpc-$Wait.StartQpc)/$Wait.QpcFrequency;$Wait.Cleared=$decision -ceq 'Accept'
        $window=$Wait.Windows[$Wait.Windows.Count-1]
        $window.EndQpc=$Wait.EndQpc;$window.DurationMs=$Wait.DurationMs;$window.Cleared=$Wait.Cleared;$window.TimedOut=$Wait.TimedOut
    }
    return $receipt
}

function Get-NotificationSnapshot([string]$Tag,[string]$BootId,[long]$MinimumQpc) {
    $root=Split-Path -Parent $policyPath;$directory=Join-Path $root 'notifications'
    $start=[Diagnostics.Stopwatch]::GetTimestamp();$frequency=[Diagnostics.Stopwatch]::Frequency
    $deadline=$start+[long](30*$frequency);$readDeadline=$start+[long](4*$frequency);$reason='Notification record unavailable.'
    $wait=[ordered]@{StartQpc=$start;DeadlineQpc=$deadline;EndQpc=$null;QpcFrequency=$frequency;MinimumQpc=$MinimumQpc;
        TimeoutSeconds=30;PollMilliseconds=100;DurationMs=$null;Covered=$false;TimedOut=$false;Attempts=@()}
    $inventoryWait=[ordered]@{StartQpc=$null;DeadlineQpc=$null;OuterDeadlineQpc=$deadline;EndQpc=$null;QpcFrequency=$frequency;
        TimeoutSeconds=5;PollMilliseconds=25;DurationMs=$null;Cleared=$false;TimedOut=$false;Windows=@();Observations=@()}
    do {
        $held=@();$inventoryRetry=$false;$inventoryRejected=$false
        $snapshot=[ordered]@{Status='INCONCLUSIVE';LocationStatus='INCONCLUSIVE';LocationFiles=@();Directory=$directory;DirectoryExists=$null;ChildNames=@();AfterChildNames=@();UnknownChildNames=@();MissingChildNames=@();Objects=@();
            BootId=$BootId;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;MinimumQpc=$MinimumQpc;ReadQpc=$null;
            Entries=@();Head=$null;Artifacts=@();Errors=@();Reason=$reason;FenceWait=$wait;InventoryWait=$inventoryWait}
        try {
            Initialize-ServiceEvidenceReader
            # Pin ancestors; read live files with write/delete sharing so evidence
            # collection cannot cause the agent to fail closed. Hash/head and
            # size checks reject torn reads and retry without repairing files.
            $ancestors=@();for($cursor=$root; -not [string]::IsNullOrWhiteSpace($cursor);$cursor=[IO.Path]::GetDirectoryName($cursor)){$ancestors=@($cursor)+$ancestors}
            foreach($path in $ancestors){
                $obj=[SUProofFile]::Open($path,$true,($path -ceq $root));$held+=$obj;$snapshot.Objects+=@{Path=$path;Owner=$obj.Owner;Sddl=$obj.Sddl}
            }
            # Only claim absence after authenticating and pinning the parent.
            # The seed-only product invocation does not initialize this writer.
            $snapshot.DirectoryExists=Test-Path -LiteralPath $directory -ErrorAction Stop
            if(-not $snapshot.DirectoryExists){
                $snapshot.LocationStatus='OK'
                $snapshot.Reason='Authenticated notification directory absent: '+$directory+'. No durable emission coverage; --seed-boot-policy does not start the notification writer and seed trials require the agent down.'
                $snapshot.ReadQpc=[Diagnostics.Stopwatch]::GetTimestamp()
                $wait.Attempts+=@{ReadQpc=$snapshot.ReadQpc;Decision='Unavailable';Authenticated=$false;Reason=$snapshot.Reason}
                return [pscustomobject]$snapshot
            }
            $obj=[SUProofFile]::Open($directory,$true,$true,$false,$true);$held+=$obj;$snapshot.Objects+=@{Path=$directory;Owner=$obj.Owner;Sddl=$obj.Sddl}
            $names=@(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop | Select-Object -ExpandProperty Name)
            $snapshot.ChildNames=$names
            $inventory=Get-NotificationInventoryDecision $names ([Diagnostics.Stopwatch]::GetTimestamp()) $inventoryWait
            $snapshot.UnknownChildNames=$inventory.UnknownChildNames;$snapshot.MissingChildNames=$inventory.MissingChildNames
            if($inventory.Decision -cne 'Accept'){
                $inventoryRetry=$inventory.Decision -ceq 'Wait';$inventoryRejected=-not $inventoryRetry
                throw $inventory.Reason
            }
            $files=@{}
            foreach($name in @('previous.jsonl','emissions.jsonl','head.json','writer.lock')){
                if($names -contains $name){$obj=[SUProofFile]::Open((Join-Path $directory $name),$false,$true,$true,$true);$held+=$obj;$files[$name]=$obj;$snapshot.Objects+=@{Path=$obj.Path;Owner=$obj.Owner;Sddl=$obj.Sddl}}
            }
            if(([SUProofFile]::Read($files['writer.lock'],1)).Length -ne 0){throw 'Invalid notification writer lease.'}
            $segments=@();$headBytes=$null;$copies=@()
            $snapshot.LocationFiles=@(@{Name='writer.lock';Bytes=[byte[]]@()})
            foreach($name in @('previous.jsonl','emissions.jsonl','head.json')){
                if(-not $files.ContainsKey($name)){continue}
                $bound=if($name -ceq 'head.json'){4096}else{4194304}
                $bytes=[SUProofFile]::Read($files[$name],$bound)
                $artifact=Join-Path $evidenceDirectory ('notifications-'+$Tag+'-'+$name)
                $copies+=@{Name=$name;Path=$artifact;Bytes=$bytes}
                $snapshot.LocationFiles+=@{Name=$name;Bytes=$bytes}
                if($name -ceq 'head.json'){$headBytes=$bytes}else{$segments+=@{Bytes=$bytes;Artifact=$artifact}}
            }
            # Authenticate the complete raw location independently of durable coverage.
            $afterNames=@(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop | Select-Object -ExpandProperty Name | Sort-Object)
            $snapshot.AfterChildNames=$afterNames
            $inventory=Get-NotificationInventoryDecision $afterNames ([Diagnostics.Stopwatch]::GetTimestamp()) $inventoryWait
            $snapshot.UnknownChildNames=$inventory.UnknownChildNames;$snapshot.MissingChildNames=$inventory.MissingChildNames
            if($inventory.Decision -cne 'Accept'){
                $inventoryRetry=$inventory.Decision -ceq 'Wait';$inventoryRejected=-not $inventoryRetry
                throw $inventory.Reason
            }
            if((@($names | Sort-Object) -join '|') -cne ($afterNames -join '|')){throw 'Notification location inventory changed during read.'}
            $snapshot.LocationStatus='OK';$snapshot.ReadQpc=[Diagnostics.Stopwatch]::GetTimestamp()
            $record=ConvertFrom-NotificationRecord $segments $headBytes
            $tail=$record.Entries[$record.Entries.Count-1].Entry
            $snapshot.Entries=$record.Entries;$snapshot.Head=$record.Head
            $coverage=Get-NotificationTailCoverage $tail $BootId $snapshot.QpcFrequency $MinimumQpc
            $snapshot.Status=$coverage.Status;$snapshot.Reason=$coverage.Reason
            $snapshot.HistoricalTail=$coverage.HistoricalTail;$snapshot.RecordedBootId=$coverage.RecordedBootId
            $now=[Diagnostics.Stopwatch]::GetTimestamp();$decision=Get-NotificationFenceWaitDecision $coverage $now $deadline
            $wait.Attempts+=@{ReadQpc=$now;Decision=$decision;Authenticated=$true;TailQpc=$tail.Qpc;TailBootId=$tail.BootId;TailQpcFrequency=$tail.QpcFrequency;Reason=$coverage.Reason}
            $wait.Covered=$decision -ceq 'Covered';$wait.TimedOut=$decision -ceq 'TimedOut'
            if($wait.TimedOut -and $coverage.Status -ceq 'OK'){
                $snapshot.Status='INCONCLUSIVE';$snapshot.Reason='Authenticated notification fence coverage arrived after the QPC wait deadline.'
            }
            # Permit the same bounded torn-read retries after a valid short tail.
            $readDeadline=[Math]::Min($deadline,$now+[long](4*$frequency))
            # Retain only the terminal authenticated snapshot. Intermediate tail
            # QPCs are recorded above; polling does not repeatedly flush copies.
            foreach($copy in $copies){
                if($decision -ceq 'Wait'){continue}
                $stream=[IO.File]::Open($copy.Path,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::Read)
                try{$stream.Write($copy.Bytes,0,$copy.Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
                $snapshot.Artifacts+=@{Name=$copy.Name;Artifact=$copy.Path;Length=$copy.Bytes.Length;Sha256=(Get-FileHash -LiteralPath $copy.Path).Hash}
            }
            if($decision -cne 'Wait'){return [pscustomobject]$snapshot}
        }catch{
            $reason=$_.Exception.Message;$snapshot.Status='INCONCLUSIVE';$snapshot.Reason=$reason
            $wait.Covered=$false
            if($inventoryRetry){
                # Release all handles, then re-authenticate and re-read the entire
                # snapshot. A transient inventory alone is not a collector error.
                $wait.Attempts+=@{ReadQpc=[Diagnostics.Stopwatch]::GetTimestamp();Decision='HeadTmpWait';Authenticated=$false;Reason=$reason}
            }else{
                $snapshot.Errors=Get-ErrorChain $_.Exception
                $wait.Attempts+=@{ReadQpc=[Diagnostics.Stopwatch]::GetTimestamp();Decision='ReadError';Authenticated=$false;Reason=$reason}
                if($inventoryRejected -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $readDeadline){return [pscustomobject]$snapshot}
            }
        }
        finally{
            foreach($obj in $held){$obj.Dispose()}
            $wait.EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();$wait.DurationMs=1000.0*($wait.EndQpc-$start)/$frequency
        }
        # Sleep only within the remaining QPC budget.
        $pollDeadline=$deadline;$pollMs=100
        if($inventoryRetry){$pollDeadline=$inventoryWait.DeadlineQpc;$pollMs=$inventoryWait.PollMilliseconds}
        $remainingMs=[Math]::Max(0,1000.0*($pollDeadline-[Diagnostics.Stopwatch]::GetTimestamp())/$frequency)
        if($remainingMs -gt 0){Start-Sleep -Milliseconds ([int][Math]::Min($pollMs,[Math]::Ceiling($remainingMs)))}
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    if($inventoryRetry){
        $inventoryWait.TimedOut=$true;$inventoryWait.EndQpc=[Diagnostics.Stopwatch]::GetTimestamp()
        $inventoryWait.DurationMs=1000.0*($inventoryWait.EndQpc-$inventoryWait.StartQpc)/$frequency
        $window=$inventoryWait.Windows[$inventoryWait.Windows.Count-1];$window.EndQpc=$inventoryWait.EndQpc;$window.DurationMs=$inventoryWait.DurationMs;$window.TimedOut=$true
        $snapshot.Reason+='; head.tmp did not clear within the QPC-bounded 5 s wait.'
        $snapshot.Errors=Get-ErrorChain ([InvalidOperationException]::new($snapshot.Reason))
    }
    # Retain the last authenticated short read when the deadline elapsed in
    # the polling sleep, preserving its INCONCLUSIVE coverage reason.
    if($snapshot.Errors.Count -eq 0 -and $snapshot.Entries.Count -gt 0){
        $wait.TimedOut=$true
        foreach($copy in $copies){
            $stream=[IO.File]::Open($copy.Path,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            try{$stream.Write($copy.Bytes,0,$copy.Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
            $snapshot.Artifacts+=@{Name=$copy.Name;Artifact=$copy.Path;Length=$copy.Bytes.Length;Sha256=(Get-FileHash -LiteralPath $copy.Path).Hash}
        }
    }
    $wait.EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();$wait.DurationMs=1000.0*($wait.EndQpc-$start)/$frequency
    return [pscustomobject]$snapshot
}
function Test-NotificationWindow($Before,$After,$Fence,[bool]$WindowKnown) {
    try {
        $missing=@()
        if(-not $WindowKnown){$missing+='QPC operation window is not bound to service snapshots.'}
        foreach($item in @(@{Tag='before';Snapshot=$Before},@{Tag='after';Snapshot=$After})){
            if($null -eq $item.Snapshot){$missing+=('Notification '+$item.Tag+' snapshot missing.')}
            elseif($item.Snapshot.Status -cne 'OK'){$missing+=('Notification '+$item.Tag+' snapshot '+$item.Snapshot.Status+': '+$item.Snapshot.Reason)}
        }
        if($missing.Count){throw ($missing -join ' ')}
        if($Before.BootId -cne $Fence.BootId -or $After.BootId -cne $Fence.BootId -or
            $Before.QpcFrequency -ne $Fence.QpcFrequency -or $After.QpcFrequency -ne $Fence.QpcFrequency){throw 'Notification boot/frequency mismatch.'}
        $anchor=@($After.Entries | Where-Object {$_.Entry.Sequence -eq $Before.Head.Sequence -and $_.Hash -ceq $Before.Head.Sha256})
        if($anchor.Count -ne 1){throw 'Notification starting head disappeared/changed (including rotation past window).'}
        $range=@($After.Entries | Where-Object {$_.Entry.Sequence -ge $Before.Head.Sequence})
        if($range.Count -eq 0 -or $range[0].Entry.Qpc -gt $Fence.ReleasedQpc -or
            $range[$range.Count-1].Entry.Qpc -lt $Fence.CompletedQpc){throw 'Notification record does not bracket whole operation window.'}
        $instance=$range[0].Entry.InstanceId;$previous=$null
        foreach($item in $range){
            $entry=$item.Entry
            if($entry.BootId -cne $Fence.BootId -or $entry.QpcFrequency -ne $Fence.QpcFrequency -or
                $entry.InstanceId -cne $instance -or $entry.Kind -cin @('Start','Stop')){throw 'Notification service restart/stop or cross-boot coverage.'}
            if($null -ne $previous -and ($entry.Sequence -ne $previous.Entry.Sequence+1 -or $entry.PreviousSha256 -cne $previous.Hash -or
                $entry.Qpc -lt $previous.Entry.Qpc -or ($entry.Qpc-$previous.Entry.Qpc) -gt 5*$Fence.QpcFrequency)){throw 'Notification sequence/chain/QPC coverage gap.'}
            $previous=$item
        }
        if($range[$range.Count-1].Entry.Sequence -ne $After.Head.Sequence -or $range[$range.Count-1].Hash -cne $After.Head.Sha256){throw 'Notification final head mismatch.'}
        $emissions=@($range | Where-Object {$_.Entry.Kind -cin @('Transfer','Event','Status') -and $_.Entry.Qpc -ge $Fence.ReleasedQpc -and $_.Entry.Qpc -le $Fence.CompletedQpc})
        return [pscustomobject]@{Complete=$true;Reason='Authenticated continuous emission coverage with retained before/after heads.';Emissions=$emissions;FirstSequence=$range[0].Entry.Sequence;LastSequence=$range[$range.Count-1].Entry.Sequence}
    }catch{return [pscustomobject]@{Complete=$false;Reason=$_.Exception.Message;Emissions=@()}}
}

# Absence is a separate proof from the durable writer's heartbeat coverage.
# Trusted OS/SCM/audit APIs and privileged local actors are the trust boundary.
function Initialize-AgentExecutionReader {
    if('SUAgentExecution' -as [type]){return}
    Add-Type -TypeDefinition @'
using System; using System.Text; using System.Collections.Generic; using System.ComponentModel;
using System.Runtime.InteropServices; using System.Security.Principal; using System.Security.Cryptography;
public sealed class SUProcessProof { public int Pid; public string Image; public string[] TokenSids; }
public static class SUAgentExecution {
 [StructLayout(LayoutKind.Sequential)] struct SidAttributes { public IntPtr Sid; public uint Attributes; }
 [StructLayout(LayoutKind.Sequential)] struct TokenGroups { public uint Count; public SidAttributes First; }
 [StructLayout(LayoutKind.Sequential)] struct AuditPolicy { public Guid Subcategory; public uint Flags; public Guid Category; }
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder b,ref int n);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr h,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr h,int type,IntPtr buffer,int n,out int required);
 [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool AuditQuerySystemPolicy(Guid[] categories,uint count,out IntPtr policy);
 [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool AuditEnumeratePerUserPolicy(out IntPtr users);
 [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr buffer);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
 [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
 public static bool ServiceExists(string name) {
  IntPtr manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
  try {
   IntPtr service=OpenService(manager,name,4);
   if(service!=IntPtr.Zero){CloseServiceHandle(service);return true;}
   int error=Marshal.GetLastWin32Error();if(error==1060)return false;throw new Win32Exception(error);
  }finally{CloseServiceHandle(manager);}
 }
 static IntPtr TokenInfo(IntPtr t,int kind) {
  int size; GetTokenInformation(t,kind,IntPtr.Zero,0,out size);
  if(size<=0)throw new Win32Exception(Marshal.GetLastWin32Error());
  IntPtr b=Marshal.AllocHGlobal(size);
  if(!GetTokenInformation(t,kind,b,size,out size)){int e=Marshal.GetLastWin32Error();Marshal.FreeHGlobal(b);throw new Win32Exception(e);}return b;
 }
 public static SUProcessProof Process(int pid) {
  IntPtr p=OpenProcess(0x1000,false,pid);if(p==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());IntPtr t=IntPtr.Zero;
  try {
   var b=new StringBuilder(32768);int n=b.Capacity;if(!QueryFullProcessImageName(p,0,b,ref n))throw new Win32Exception(Marshal.GetLastWin32Error());
   if(!OpenProcessToken(p,8,out t))throw new Win32Exception(Marshal.GetLastWin32Error());
   var sids=new List<string>();IntPtr info=TokenInfo(t,1);
   try{sids.Add(new SecurityIdentifier(Marshal.ReadIntPtr(info)).Value);}finally{Marshal.FreeHGlobal(info);}
   info=TokenInfo(t,2);
   try {
    int count=Marshal.ReadInt32(info);int offset=(int)Marshal.OffsetOf(typeof(TokenGroups),"First");int size=Marshal.SizeOf(typeof(SidAttributes));
    for(int i=0;i<count;i++)sids.Add(new SecurityIdentifier(Marshal.ReadIntPtr(info,offset+i*size)).Value);
   }finally{Marshal.FreeHGlobal(info);}
   // Include restricted SIDs as well as user/groups; disabled groups still count.
   info=TokenInfo(t,11);
   try {
    int count=Marshal.ReadInt32(info);int offset=(int)Marshal.OffsetOf(typeof(TokenGroups),"First");int size=Marshal.SizeOf(typeof(SidAttributes));
    for(int i=0;i<count;i++)sids.Add(new SecurityIdentifier(Marshal.ReadIntPtr(info,offset+i*size)).Value);
   }finally{Marshal.FreeHGlobal(info);}
   return new SUProcessProof{Pid=pid,Image=b.ToString(),TokenSids=sids.ToArray()};
  }finally{if(t!=IntPtr.Zero)CloseHandle(t);CloseHandle(p);}
 }
 public static string ServiceSid(string name) {
  using(var sha=SHA1.Create()) {byte[] h=sha.ComputeHash(Encoding.Unicode.GetBytes(name.ToUpperInvariant()));string sid="S-1-5-80";for(int i=0;i<5;i++)sid+="-"+BitConverter.ToUInt32(h,i*4);return sid;}
 }
 public static uint[] Audit() {
  IntPtr p; Guid[] g={new Guid("0cce922b-69ae-11d9-bed3-505054503030")}; // Process Creation, including 4696.
  if(!AuditQuerySystemPolicy(g,1,out p))throw new Win32Exception(Marshal.GetLastWin32Error());uint flags;
  try{flags=((AuditPolicy)Marshal.PtrToStructure(p,typeof(AuditPolicy))).Flags;}finally{AuditFree(p);}
  if(!AuditEnumeratePerUserPolicy(out p))throw new Win32Exception(Marshal.GetLastWin32Error());
  try{return new uint[]{flags,(uint)Marshal.ReadInt32(p)};}finally{AuditFree(p);}
 }
}
'@
}
function Get-ProcessCreationAudit {
    Initialize-AgentExecutionReader
    $audit=[SUAgentExecution]::Audit()
    return [pscustomobject]@{CreationFlags=$audit[0];PerUserPolicyCount=$audit[1]}
}
function Set-ProcessCreationAudit([int]$Flags) {
    if($Flags -notin @(0,1,2,3,4)){throw 'Unsupported process-creation audit flags.'}
    $success=if(($Flags -band 1) -ne 0){'enable'}else{'disable'}
    $failure=if(($Flags -band 2) -ne 0){'enable'}else{'disable'}
    & auditpol.exe /set '/subcategory:{0cce922b-69ae-11d9-bed3-505054503030}' ('/success:'+$success) ('/failure:'+$failure) | Out-Host
    if($LASTEXITCODE -ne 0){throw 'auditpol process-creation policy update failed.'}
    $actual=Get-ProcessCreationAudit
    if($actual.CreationFlags -ne $Flags){throw ('Process-creation audit readback mismatch: expected='+$Flags+'; actual='+$actual.CreationFlags)}
    return $actual
}
function Get-AgentLogAnchor([string]$Name) {
    $start=[Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $log=Get-WinEvent -ListLog $Name -ErrorAction Stop
        if(-not $log.IsEnabled){throw 'Log disabled.'}
        $old=Get-WinEvent -LogName $Name -Oldest -MaxEvents 1 -ErrorAction Stop
        $last=Get-WinEvent -LogName $Name -MaxEvents 1 -ErrorAction Stop
        if($null -eq $old.RecordId -or $null -eq $last.RecordId -or $old.RecordId -gt $last.RecordId){throw 'First/last log record IDs missing or out of order.'}
        return [pscustomobject]@{Status='OK';Name=$Name;StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();
            OldestRecordId=$old.RecordId;NewestRecordId=$last.RecordId;NewestXml=$last.ToXml();SecurityDescriptor=$log.SecurityDescriptor}
    }catch{return [pscustomobject]@{Status='INCONCLUSIVE';Name=$Name;Reason=$_.Exception.Message;Errors=(Get-ErrorChain $_.Exception);StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp()}}
}
function Get-AgentExecutionSnapshot {
    $result=[ordered]@{Status='INCONCLUSIVE';BootId=(Get-BootId);QpcFrequency=[Diagnostics.Stopwatch]::Frequency;
        StartQpc=[Diagnostics.Stopwatch]::GetTimestamp();Errors=@();Processes=@();MinimalProcesses=@();CollectedByPid=$PID;Service=$null;Audit=$null;ServiceSid=$null;ImagePaths=@()}
    try {
        Initialize-AgentExecutionReader
        # Begin anchors precede inventory; end anchors follow it. Record-ID
        # ordering, rather than UTC filtering, overcovers the QPC case window.
        $result.SystemBegin=Get-AgentLogAnchor 'System';$result.SecurityBegin=Get-AgentLogAnchor 'Security'
        $result.InventoryStartQpc=[Diagnostics.Stopwatch]::GetTimestamp()
        try{$result.Audit=Get-ProcessCreationAudit}catch{$result.Errors+=('Audit policy: '+$_.Exception.Message)}
        # Identity does not depend on installation. The extracted package is
        # hash-pinned in Prepare; the service SID is deterministic for its name.
        $result.ImagePaths=@([IO.Path]::GetFullPath((Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe')))
        $result.ServiceSid=[SUAgentExecution]::ServiceSid('SafeUploadAgent')
        try {
            $exists=[SUAgentExecution]::ServiceExists('SafeUploadAgent')
            $result.Service=@{Name='SafeUploadAgent';Exists=$exists;QueryStatus='OK';QuerySource='OpenSCManager/OpenService';AbsenceError=$(if(-not $exists){1060}else{$null})}
            if($exists){
                $services=@(Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction Stop)
                if($services.Count -ne 1){throw 'Installed SCM service identity missing/ambiguous.'}
                $service=$services[0]
                foreach($field in @('DisplayName','State','ProcessId','PathName','StartMode')){$result.Service[$field]=$service.$field}
                $match=[regex]::Match($service.PathName,'^\s*(?:"(?<image>[A-Za-z]:\\[^"\r\n]+\.exe)"|(?<image>[A-Za-z]:\\[^\s"]+\.exe))(?:\s|$)','IgnoreCase')
                if(-not $match.Success){throw 'SCM agent image path unresolved/ambiguous.'}
                $result.ImagePaths=@([IO.Path]::GetFullPath($match.Groups['image'].Value))+$result.ImagePaths
            }
        }catch{$result.Errors+=('SCM query: '+$_.Exception.Message);if($null -ne $result.Service){$result.Service.QueryStatus='INCONCLUSIVE'}}
        # PID 0/4 are kernel pseudo/system processes, not user-mode emitters.
        # Any other vanished, protected or inaccessible process defeats proof.
        foreach($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)){
            if($process.ProcessId -in @(0,4)){continue}
            # 'Registry' and 'Memory Compression' are kernel-created minimal processes: no image, parent System, no user code, so they
            # cannot be the agent; they refuse full queries (notify6: "A device attached to the system is not functioning"). Recorded,
            # not inventoried. Any other unreadable process still defeats the proof.
            if($process.Name -in @('Registry','Memory Compression') -and [string]::IsNullOrEmpty($process.ExecutablePath) -and
               $process.ParentProcessId -eq 4){
                $result.MinimalProcesses+=@{Pid=$process.ProcessId;Name=$process.Name;ParentPid=4};continue
            }
            try{$result.Processes+=[SUAgentExecution]::Process([int]$process.ProcessId)}
            catch{$result.Errors+=('Process inventory PID '+$process.ProcessId+': '+$_.Exception.Message)}
        }
    }catch{$result.Errors+=$_.Exception.Message}
    finally {
        $result.InventoryEndQpc=[Diagnostics.Stopwatch]::GetTimestamp()
        if(@($result.Processes | Where-Object {$_.Pid -eq $PID}).Count -ne 1){$result.Errors+='Collector process missing/duplicated in inventory.'}
        # Even an incomplete SCM/audit/inventory read must retain end anchors.
        $result.SystemEnd=Get-AgentLogAnchor 'System';$result.SecurityEnd=Get-AgentLogAnchor 'Security'
    }
    if($result.Errors.Count -eq 0){$result.Status='OK'}
    $result.EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();$result.EndBootId=Get-BootId
    return [pscustomobject]$result
}
function ConvertFrom-AgentEventXml([string]$Xml,[string]$Channel) {
    [xml]$document=$Xml;$system=$document.Event.System
    if([string]$system.Channel -cne $Channel -or [string]::IsNullOrWhiteSpace([string]$system.Provider.Name) -or
        [string]$system.EventRecordID -notmatch '^\d+$'){throw ('Malformed '+$Channel+' event XML.')}
    $data=@{};$values=@()
    # The PowerShell XML adapter turns unnamed, text-only Data elements into
    # strings. Select the XML nodes directly so their InnerText is retained.
    foreach($node in @($document.SelectNodes('/*[local-name()="Event"]/*[local-name()="EventData"]/*[local-name()="Data"]'))){
        $values+=$node.InnerText;$field=$node.GetAttribute('Name')
        if(-not [string]::IsNullOrWhiteSpace($field)){$data[$field]=$node.InnerText}
    }
    return [pscustomobject]@{RecordId=[long]$system.EventRecordID;Id=[int]$system.EventID;Provider=[string]$system.Provider.Name;Data=$data;Values=$values;Xml=$Xml}
}
function Read-AgentLogWindow($Before,$After,[string]$Name) {
    try {
        foreach($edge in @(@{Tag='before';Anchor=$Before},@{Tag='after';Anchor=$After})){
            if($null -eq $edge.Anchor){throw ($Name+' '+$edge.Tag+' log anchor missing (collector did not publish it).')}
            if($edge.Anchor.Status -cne 'OK'){throw ($Name+' '+$edge.Tag+' log anchor '+$edge.Anchor.Status+': '+$edge.Anchor.Reason)}
        }
        if($null -eq $Before.NewestRecordId -or $null -eq $After.NewestRecordId -or
            $After.OldestRecordId -gt $Before.NewestRecordId -or $After.NewestRecordId -lt $Before.NewestRecordId){throw 'Log cleared/wrapped; starting record no longer retained.'}
        if(($After.NewestRecordId-$Before.NewestRecordId) -gt 20000){throw 'Log window exceeds 20000-record evidence bound.'}
        $query='*[System[EventRecordID >= '+$Before.NewestRecordId+' and EventRecordID <= '+$After.NewestRecordId+']]'
        $records=@(Get-WinEvent -LogName $Name -FilterXPath $query -MaxEvents 20002 -ErrorAction Stop | Sort-Object RecordId)
        $xmls=@($records | ForEach-Object {$_.ToXml()})
        $proof=[pscustomobject]@{Status='OK';Name=$Name;Before=$Before;After=$After;Xmls=$xmls;Reason='All-provider bounded record-ID window, with exact edge XML.'}
        # Retain raw XML as an artifact bound again by the host transfer check.
        $artifact=Join-Path $evidenceDirectory ('agent-absence-'+$Name+'.json')
        Write-DurableFile $artifact (ConvertTo-Json -InputObject $xmls -Depth 4 -Compress) -New
        $proof | Add-Member NoteProperty Artifact $artifact
        $proof | Add-Member NoteProperty Length (Get-Item -LiteralPath $artifact).Length
        $proof | Add-Member NoteProperty Sha256 (Get-FileHash -LiteralPath $artifact).Hash
        return $proof
    }catch{return [pscustomobject]@{Status='INCONCLUSIVE';Name=$Name;Reason=$_.Exception.Message;Xmls=@()}}
}
function Test-AgentLogContinuity($Proof,[string]$Name) {
    if($null -eq $Proof -or $Proof.Status -cne 'OK'){throw ($Name+' log evidence unavailable: '+$Proof.Reason)}
    $b=$Proof.Before;$a=$Proof.After
    if($b.Status -cne 'OK' -or $a.Status -cne 'OK' -or $null -eq $b.NewestRecordId -or $null -eq $a.NewestRecordId -or
        $null -eq $a.OldestRecordId -or $a.OldestRecordId -gt $b.NewestRecordId -or $a.NewestRecordId -lt $b.NewestRecordId -or
        ($a.NewestRecordId-$b.NewestRecordId) -gt 20000){throw ($Name+' log anchors missing, cleared, wrapped, or oversized.')}
    $events=@();$next=[long]$b.NewestRecordId
    foreach($xml in $Proof.Xmls){
        $event=ConvertFrom-AgentEventXml $xml $Name
        if($event.RecordId -ne $next){throw ($Name+' log record-ID gap/duplicate at '+$next+'.')}
        $next++;$events+=$event
    }
    if($next -ne $a.NewestRecordId+1 -or $events.Count -eq 0){throw ($Name+' log record-ID tail missing.')}
    if($events[0].Xml -cne $b.NewestXml -or $events[$events.Count-1].Xml -cne $a.NewestXml){throw ($Name+' log edge XML changed/reused.')}
    return ,$events
}
function Test-NotificationLocationUnchanged($Before,$After,$Fence) {
    $failures=@()
    foreach($pair in @(@{Tag='before';Snapshot=$Before},@{Tag='after';Snapshot=$After})){
        $s=$pair.Snapshot
        if($null -eq $s -or $s.LocationStatus -cne 'OK' -or $null -eq $s.DirectoryExists -or
            $s.BootId -cne $Fence.BootId -or $s.QpcFrequency -ne $Fence.QpcFrequency -or $null -eq $s.ReadQpc){
            $failures+=('Notification '+$pair.Tag+' location not authenticated: '+$s.Reason)
        }
    }
    if($failures.Count){return [pscustomobject]@{Complete=$false;Reason=$failures -join ' '}}
    if([string]::IsNullOrWhiteSpace($Before.Directory) -or $Before.ReadQpc -gt $Fence.ReleasedQpc -or $After.ReadQpc -lt $Fence.CompletedQpc -or
        $Before.Directory -ine $After.Directory){return [pscustomobject]@{Complete=$false;Reason='Notification location receipts do not bracket window or paths differ.'}}
    if($Before.DirectoryExists -ne $After.DirectoryExists){return [pscustomobject]@{Complete=$false;Reason='Notification record location appeared/disappeared.'}}
    if(-not $Before.DirectoryExists){return [pscustomobject]@{Complete=$true;Reason='Authenticated notification location absent at both edges.'}}
    # Raw same-handle bytes are compared even for stale/malformed records. The
    # current-boot durable coverage status is intentionally independent.
    $b=@($Before.LocationFiles);$a=@($After.LocationFiles)
    if($null -eq $Before.LocationFiles -or $null -eq $After.LocationFiles -or $b.Count -ne $a.Count -or
        @($b | ForEach-Object { $_.Name } | Sort-Object -Unique).Count -ne $b.Count -or @($a | ForEach-Object { $_.Name } | Sort-Object -Unique).Count -ne $a.Count){return [pscustomobject]@{Complete=$false;Reason='Notification location inventory missing/changed.'}}
    foreach($file in $b){
        $match=@($a | Where-Object {$_.Name -ceq $file.Name})
        if($match.Count -ne 1 -or $null -eq $file.Bytes -or $null -eq $match[0].Bytes -or
            [Convert]::ToBase64String([byte[]]$file.Bytes) -cne [Convert]::ToBase64String([byte[]]$match[0].Bytes)){
            return [pscustomobject]@{Complete=$false;Reason='Notification location bytes missing/changed: '+$file.Name}
        }
    }
    return [pscustomobject]@{Complete=$true;Reason='Authenticated notification location inventories byte-identical.'}
}
function Test-AgentDidNotRun($Before,$After,$Fence,[bool]$WindowKnown,$SystemLog,$SecurityLog,[switch]$R03Offline) {
    $failures=@();$scm=@();$creations=@();$scmFailures=@();$contradictions=@();$systemContinuous=$false;$scmWindowKnown=$WindowKnown
    if(-not $WindowKnown){$failures+='QPC operation window is not bound to service snapshots.'}
    $b=$Before.AgentExecution;$a=$After.AgentExecution
    $r03OfflineWindow=($R03Offline -and $CaseId -ceq 'R03' -and $Before.Tag -ceq 'r03-offline-before' -and $After.Tag -ceq 'r03-offline-after')
    foreach($pair in @(@{Tag='before';Snapshot=$b},@{Tag='after';Snapshot=$a})){
        $s=$pair.Snapshot
        if($null -eq $s){$failures+=('Agent '+$pair.Tag+' execution snapshot missing.');$scmWindowKnown=$false;continue}
        if($s.Status -cne 'OK'){$failures+=('Agent '+$pair.Tag+' inventory incomplete: '+($s.Errors -join '; '))}
        if($s.BootId -cne $Fence.BootId -or $s.EndBootId -cne $Fence.BootId -or $s.QpcFrequency -ne $Fence.QpcFrequency -or
            $null -eq $s.StartQpc -or $null -eq $s.EndQpc -or $s.StartQpc -gt $s.EndQpc){$failures+=('Agent '+$pair.Tag+' boot/QPC receipts missing/mismatched.');$scmWindowKnown=$false}
        if($null -eq $s.InventoryStartQpc -or $null -eq $s.InventoryEndQpc -or
            $s.InventoryStartQpc -lt $s.StartQpc -or $s.InventoryStartQpc -gt $s.InventoryEndQpc -or $s.InventoryEndQpc -gt $s.EndQpc){
            $failures+=('Agent '+$pair.Tag+' inventory QPC receipts missing/out of order.')
            $scmWindowKnown=$false
        }
        $service=$s.Service
        if($null -eq $service -or $service.Name -cne 'SafeUploadAgent' -or $service.QueryStatus -cne 'OK' -or
            $service.QuerySource -cne 'OpenSCManager/OpenService' -or $null -eq $service.Exists){
            $scmFailures+=('SCM SafeUploadAgent '+$pair.Tag+' query unauthenticated/missing.')
        }elseif(-not $service.Exists){
            if($service.AbsenceError -ne 1060){$scmFailures+=('SCM '+$pair.Tag+' absence lacks ERROR_SERVICE_DOES_NOT_EXIST.')}
        }elseif($service.State -cne 'Stopped' -or $null -eq $service.ProcessId -or $service.ProcessId -ne 0){
            $scmFailures+=('SCM SafeUploadAgent '+$pair.Tag+' state is not authenticated Stopped/PID 0.')
            if($service.State -ceq 'Running' -or $service.ProcessId -gt 0){$contradictions+=('Installed agent running at '+$pair.Tag+' edge.')}
        }
        if($r03OfflineWindow -and $service.StartMode -cne 'Disabled'){$failures+=('R03 offline agent '+$pair.Tag+' start mode is not Disabled.')}
        if($null -eq $s.Audit.CreationFlags -or ($s.Audit.CreationFlags -band 1) -eq 0 -or
            $null -eq $s.Audit.PerUserPolicyCount -or $s.Audit.PerUserPolicyCount -ne 0){$failures+=('Agent '+$pair.Tag+' process-creation success auditing missing/disabled or per-user overrides present.')}
        $requiredImages=if($service.Exists){2}else{1}
        if([string]::IsNullOrWhiteSpace($s.ServiceSid) -or @($s.ImagePaths).Count -lt $requiredImages -or $null -eq $s.Processes){$failures+=('Agent '+$pair.Tag+' image/SID/inventory identity missing.')}
        if($null -eq $s.CollectedByPid -or @($s.Processes | Where-Object Pid -eq $s.CollectedByPid).Count -ne 1){$failures+=('Agent '+$pair.Tag+' inventory lacks its collector process.')}
        foreach($process in $s.Processes){
            if([string]::IsNullOrWhiteSpace($process.Image) -or @($process.TokenSids).Count -eq 0){$failures+=('Agent '+$pair.Tag+' PID '+$process.Pid+' image/token SIDs unavailable.')}
            if($s.ImagePaths -icontains $process.Image -or $process.TokenSids -contains $s.ServiceSid){$failures+=('Agent image or service SID exists at '+$pair.Tag+' edge: PID '+$process.Pid+'.')}
        }
    }
    if($null -ne $b -and $null -ne $a){
        if($b.EndQpc -gt $Fence.ReleasedQpc -or $a.StartQpc -lt $Fence.CompletedQpc){$failures+='Agent inventory edges do not bracket whole operation window.';$scmWindowKnown=$false}
        if($b.ServiceSid -cne $a.ServiceSid -or ($b.ImagePaths -join '|') -ine ($a.ImagePaths -join '|') -or
            $b.Service.DisplayName -cne $a.Service.DisplayName -or $b.Service.PathName -cne $a.Service.PathName){$failures+='Agent SCM/image/SID identity changed between edges.'}
        if($b.Service.Exists -ne $a.Service.Exists -or ($b.Service.Exists -and
            ([string]::IsNullOrWhiteSpace($b.Service.DisplayName) -or [string]::IsNullOrWhiteSpace($b.Service.PathName)))){$scmFailures+='SCM installation/identity changed or missing between edges.'}
    }
    foreach($pair in @(@{Name='System';Proof=$SystemLog},@{Name='Security';Proof=$SecurityLog})){
        try {
            $events=Test-AgentLogContinuity $pair.Proof $pair.Name
            $begin=$b.($pair.Name+'Begin');$end=$a.($pair.Name+'End')
            if($null -eq $begin -or $null -eq $end -or
                $pair.Proof.Before.NewestXml -cne $begin.NewestXml -or $pair.Proof.After.NewestXml -cne $end.NewestXml -or
                $pair.Proof.Before.EndQpc -ne $begin.EndQpc -or $pair.Proof.After.StartQpc -ne $end.StartQpc){throw ($pair.Name+' log proof does not match execution snapshot anchors.')}
            # Anchors must enclose both process inventories, not merely the
            # operation timestamps; this closes edge sampling races.
            $first=$pair.Proof.Before;$last=$pair.Proof.After
            if($null -eq $first.EndQpc -or $null -eq $last.StartQpc -or $null -eq $first.StartQpc -or $null -eq $last.EndQpc -or
                $first.StartQpc -gt $first.EndQpc -or $last.StartQpc -gt $last.EndQpc -or
                $null -eq $b.InventoryStartQpc -or $null -eq $a.InventoryEndQpc -or
                $first.EndQpc -gt $b.InventoryStartQpc -or $last.StartQpc -lt $a.InventoryEndQpc){throw ($pair.Name+' log anchors do not enclose inventories.')}
            foreach($event in $events){
                if($pair.Name -ceq 'System'){
                    if(($event.Provider -ceq 'Microsoft-Windows-Eventlog' -and $event.Id -in @(104,1100,1101,1102,1104,1108)) -or
                        ($event.Provider -ceq 'EventLog' -and $event.Id -in @(6005,6006,6008))){throw ('System log clear/loss event '+$event.Id+' at record '+$event.RecordId+'.')}
                    if($event.Provider -ceq 'Service Control Manager'){
                        if($event.Values.Count -eq 0){throw ('SCM event without service identity at record '+$event.RecordId+'.')}
                        if(@($event.Values | Where-Object {$_ -ieq 'SafeUploadAgent' -or $_ -ieq $b.Service.DisplayName -or $_ -ieq $a.Service.DisplayName}).Count){
                            $scm+=$event
                            # Reject every agent SCM event (7036/7045/7040/errors
                            # etc.), rather than interpreting localized state text.
                            $scmFailures+=('SCM SafeUploadAgent activity '+$event.Id+' at record '+$event.RecordId+'.')
                            if($event.Id -in @(7036,7045)){
                                # State-change/install contradicts the strict SCM
                                # premise regardless of localized state wording.
                                $contradictions+=('Agent service state-change/install in window at System record '+$event.RecordId+'.')
                            }
                        }
                    }
                }else{
                    if(($event.Provider -ceq 'Microsoft-Windows-Eventlog' -and $event.Id -in @(1100,1101,1102,1104,1108)) -or
                        ($event.Provider -ceq 'Microsoft-Windows-Security-Auditing' -and $event.Id -in @(4719,4902,4906,4912,4696))){throw ('Security audit clear/loss/policy/token-change event '+$event.Id+' at record '+$event.RecordId+'.')}
                    if($event.Provider -ceq 'Microsoft-Windows-Security-Auditing' -and $event.Id -eq 4688){
                        $creations+=$event
                        if($b.ImagePaths -icontains $event.Data.NewProcessName -or $a.ImagePaths -icontains $event.Data.NewProcessName -or
                            $event.Data.SubjectUserSid -ceq $b.ServiceSid -or $event.Data.TargetUserSid -ceq $b.ServiceSid){$failures+=('Agent image/service SID process creation at Security record '+$event.RecordId+'.')}
                        # 4688 authenticates image/user, not group/restricted SIDs. Only the SCM assigns a per-service SID, and only to the
                        # service's own process when it starts that service. When authenticated SCM evidence shows the service absent at both
                        # edges (and any install in the window is already a contradiction above), no process can carry that SID except by a
                        # privileged token forgery, and administrators/SYSTEM are trusted by owner decision (MVP-PLAN). Only then is the group-SID
                        # gap closed. Other installed-service windows retain the conservative creation rule below. The image/user check
                        # above always applies.
                        $serviceNeverExisted=($null -ne $b.Service -and $null -ne $a.Service -and $b.Service.Exists -eq $false -and $a.Service.Exists -eq $false)
                        # R03 alone has an installed but disabled offline service. Apply the same trusted-SCM SID premise as the seed
                        # rows only with disabled/stopped/PID-zero edges and a continuous System window with no agent SCM activity.
                        # Image/user-SID creation checks above, full inventories, auditing and Security continuity still apply.
                        $r03ServiceDisabled=($r03OfflineWindow -and $systemContinuous -and $scmWindowKnown -and $scmFailures.Count -eq 0 -and
                            $b.Service.Exists -eq $true -and $a.Service.Exists -eq $true -and
                            $b.Service.StartMode -ceq 'Disabled' -and $a.Service.StartMode -ceq 'Disabled' -and
                            -not [string]::IsNullOrWhiteSpace($event.Data.NewProcessName) -and -not [string]::IsNullOrWhiteSpace($event.Data.SubjectUserSid))
                        if(-not ($serviceNeverExisted -or $r03ServiceDisabled)){
                            $failures+=('Process created between inventories at Security record '+$event.RecordId+'; 4688 lacks token group/restricted service-SID evidence.')
                        }
                    }
                }
            }
            if($pair.Name -ceq 'System'){$systemContinuous=$true}
        }catch{$failures+=$_.Exception.Message;if($pair.Name -ceq 'System'){$scmFailures+=$_.Exception.Message}}
    }
    foreach($snapshot in @($Before.Notifications,$After.Notifications)){
        foreach($item in $snapshot.Entries){
            $entry=$item.Entry
            if($entry.BootId -ceq $Fence.BootId -and $entry.QpcFrequency -eq $Fence.QpcFrequency -and
                $null -ne $entry.Qpc -and $entry.Qpc -ge $Fence.ReleasedQpc -and $entry.Qpc -le $Fence.CompletedQpc){
                $failures+=('Authenticated notification writer activity in window: sequence '+$entry.Sequence+'.')
            }
        }
    }
    if(-not $scmWindowKnown){$scmFailures+='SCM snapshots/window receipts incomplete.'}
    $failures+= $scmFailures
    $scmComplete=$systemContinuous -and $scmFailures.Count -eq 0 -and $scmWindowKnown
    $scmProof=[pscustomobject]@{Complete=$scmComplete;Verdict=$(if($contradictions.Count){'FAIL'}elseif($scmComplete){'PASS'}else{'INCONCLUSIVE'});
        Reason=$(if($contradictions.Count){$contradictions -join ' '}elseif($scmComplete -and -not $b.Service.Exists){'Authenticated SCM service absent at both edges, never installed in window; continuous System log.'}elseif($scmComplete){'Installed service stopped/PID 0 at both edges, with no SCM activity in continuous System log.'}else{$scmFailures -join ' '})}
    return [pscustomobject]@{Complete=($failures.Count -eq 0);Verdict=$(if($contradictions.Count){'FAIL'}elseif($failures.Count){'INCONCLUSIVE'}else{'PASS'});
        ScmProof=$scmProof;Reason=$(if($failures.Count){$failures -join ' '}else{'agent did not run in window'});
        Failures=$failures;ScmEvents=$scm;ProcessCreations=$creations;SystemLog=$SystemLog;SecurityLog=$SecurityLog;
        Limitations='Trusted kernel, SCM, audit transport and privileged actors; inventories inspect primary user/group/restricted SIDs, not thread impersonation. 4688 does not expose group SIDs; non-agent creations require the absent-service or R03 disabled-offline SCM premise. No claim about renamed/injected emitters, off-window activity or intermediate create/delete of notification files.'}
}

function Test-LatencyTransientIoError($Exception) {
    # Classify native codes, never localized messages or schema/ACL failures.
    for($ex=$Exception;$null -ne $ex;$ex=$ex.InnerException){
        if($ex -is [ComponentModel.Win32Exception] -and $ex.NativeErrorCode -in @(5,32,33)){return $true}
        if($ex.HResult -in @(-2147024891,-2147024864,-2147024863)){return $true}
        if($null -ne $ex.PSObject.Properties['NativeCode'] -and $ex.NativeCode -in @(5,32,33)){return $true}
    }
    return $false
}
function Invoke-LatencyJournalIo([scriptblock]$Body,[string]$Action,[string]$Path,$Retries,[long]$Deadline=0,[switch]$Enabled) {
    if(-not $Enabled){return (& $Body)}
    $start=[Diagnostics.Stopwatch]::GetTimestamp();$limit=$start+[long](2*[Diagnostics.Stopwatch]::Frequency)
    if($Deadline -gt 0){$limit=[Math]::Min($limit,$Deadline)}
    $failures=@()
    while($true){
        try{
            $value=& $Body
            foreach($failure in $failures){$failure.Outcome='Recovered';$failure.RecoveryQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
            return $value
        }catch{
            $now=[Diagnostics.Stopwatch]::GetTimestamp();$retryable=Test-LatencyTransientIoError $_.Exception
            $failure=[pscustomobject]@{Action=$Action;Path=$Path;StartQpc=$start;FailureQpc=$now;DeadlineQpc=$limit;
                Retryable=$retryable;Errors=(Get-ErrorChain $_.Exception);Outcome='Retrying';RecoveryQpc=$null}
            [void]$Retries.Add($failure);$failures+= $failure
            if(-not $retryable -or $now -ge $limit){
                foreach($item in $failures){$item.Outcome=if($retryable){'Persistent'}else{'NotRetryable'}}
                throw
            }
            Start-Sleep -Milliseconds ([int][Math]::Max(1,[Math]::Min(25,($limit-$now)*1000/[Diagnostics.Stopwatch]::Frequency)))
            if([Diagnostics.Stopwatch]::GetTimestamp() -ge $limit){foreach($item in $failures){$item.Outcome='Persistent'};throw}
        }
    }
}
function Get-ServiceSnapshot([string]$Tag,[switch]$JournalOnly,[switch]$RetryTransientJournal) {
    $result=[ordered]@{Status='INCONCLUSIVE';Tag=$Tag;BootId=(Get-BootId);QpcFrequency=[Diagnostics.Stopwatch]::Frequency;StartQpc=[Diagnostics.Stopwatch]::GetTimestamp();
        Journal=@();Objects=@();Errors=@();Retries=(New-Object 'Collections.Generic.List[object]');Application=@();AgentProcesses=@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.Service.exe'" | Select-Object ProcessId,CommandLine);}
    $held=@();$root=Split-Path -Parent $policyPath;$journal=Join-Path $root 'staging-journal'
    try {
        Initialize-ServiceEvidenceReader
        # Pin each ancestor without following reparses. Private root authenticates
        # an absent journal directory; never create/repair product evidence.
        $ancestors=@();for($cursor=$root; -not [string]::IsNullOrWhiteSpace($cursor);$cursor=[IO.Path]::GetDirectoryName($cursor)){$ancestors=@($cursor)+$ancestors}
        foreach($path in $ancestors){$obj=[SUProofFile]::Open($path,$true,($path -ceq $root));$held+=$obj;$result.Objects+=@{Path=$path;Owner=$obj.Owner;Sddl=$obj.Sddl}}
        $result.JournalAbsent=-not(Test-Path -LiteralPath $journal)
        if(-not $result.JournalAbsent) {
            # Same owner rule as the agent's RequireTrustedOwner: SYSTEM or BUILTIN\Administrators (notify2: the guest journal is
            # owned by Administrators and the stricter SYSTEM-only check rejected genuine evidence).
            $obj=[SUProofFile]::Open($journal,$true,$true,$false,$true);$held+=$obj;$result.Objects+=@{Path=$journal;Owner=$obj.Owner;Sddl=$obj.Sddl}
            foreach($file in @(Get-ChildItem -LiteralPath $journal -Force | Sort-Object Name)) {
                if($file.Name -notmatch '^[0-9a-f]{32}\.json$'){throw ('Unrecognized journal child; snapshot is not complete. Name='+$file.Name+'; Attributes='+[string]$file.Attributes)}
                $read=Invoke-LatencyJournalIo {
                    $obj=[SUProofFile]::Open($file.FullName,$false,$true,([bool]$JournalOnly -or [bool]$RetryTransientJournal),$true)
                    try{[pscustomobject]@{Bytes=[SUProofFile]::Read($obj,131072);Owner=$obj.Owner;Sddl=$obj.Sddl}}finally{$obj.Dispose()}
                } 'SnapshotRead' $file.FullName $result.Retries -Enabled:$RetryTransientJournal
                $bytes=$read.Bytes
                $leaf='service-'+$Tag+'-'+$file.Name;$copy=Join-Path $evidenceDirectory $leaf
                if($RetryTransientJournal -and (Test-Path -LiteralPath $copy)){throw ('Snapshot artifact already exists: '+$copy)}
                $copyHash=Invoke-LatencyJournalIo {
                    # Retry overwrites only this attempt's partial artifact; retain
                    # exactly one durable copy of the same authenticated bytes.
                    $fileMode=if($RetryTransientJournal){[IO.FileMode]::Create}else{[IO.FileMode]::CreateNew}
                    $stream=[IO.File]::Open($copy,$fileMode,[IO.FileAccess]::Write,[IO.FileShare]::Read)
                    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
                    (Get-FileHash -LiteralPath $copy -ErrorAction Stop).Hash
                } 'SnapshotCopy' $copy $result.Retries -Enabled:$RetryTransientJournal
                # Collection authenticates and retains ALL bytes. Schema interpretation
                # belongs to delta evaluation; a legacy entry must not truncate inventory.
                $result.Journal+= [pscustomobject]@{Path=$file.FullName;Owner=$read.Owner;Sddl=$read.Sddl;Sha256=$copyHash;
                    Artifact=$copy;Length=$bytes.Length;Bytes=$bytes}
            }
        }
        $result.Status='OK'
    }catch{$result.Errors+=Get-ErrorChain $_.Exception}
    finally{foreach($obj in $held){$obj.Dispose()}}
    if($JournalOnly){$result.EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();return [pscustomobject]$result}
    # Record IDs delimit all providers in Application; provider absence is an
    # empty query result, not proof that a notification was never emitted.
    try {
        $oldest=Get-WinEvent -LogName Application -Oldest -MaxEvents 1 -ErrorAction Stop
        $newest=Get-WinEvent -LogName Application -MaxEvents 1 -ErrorAction Stop
        $result.Application=[pscustomobject]@{Status='OK';OldestRecordId=$oldest.RecordId;NewestRecordId=$newest.RecordId;
            NewestXml=$newest.ToXml();OldestXml=$oldest.ToXml();Log=(Get-WinEvent -ListLog Application | Select-Object LogName,IsEnabled,LogMode,RecordCount,MaximumSizeInBytes,SecurityDescriptor)}
    }catch{$result.Application=[pscustomobject]@{Status='INCONCLUSIVE';Errors=(Get-ErrorChain $_.Exception)}}
    $result.AgentExecution=Get-AgentExecutionSnapshot
    $result.Notifications=Get-NotificationSnapshot $Tag $result.BootId $result.StartQpc
    $result.EndQpc=[Diagnostics.Stopwatch]::GetTimestamp()
    Save-State $result (Join-Path $evidenceDirectory ('service-'+$Tag+'.clixml'))
    return [pscustomobject]$result
}
function Test-ServiceJournalStateReachable([int]$State,[bool]$SealedOnce) {
    # StagedTransferJournal.IsTransitionAllowed. SealAsync has the same
    # Allocated/Unsealed -> Sealed edges; a committed sealed rename returns
    # to Sealed. Snapshots cannot attest the actual intermediate transitions.
    $edges=@(@(0,1),@(0,8),@(8,1),@(1,2),@(1,7),@(2,3),@(2,6),@(6,2),@(2,7),@(3,7),@(3,4),@(4,5),@(4,7),@(7,2),@(2,1))
    $pending=@(@{State=0;Sealed=$false});$seen=@{}
    while($pending.Count){
        $current=$pending[0];$pending=@($pending | Select-Object -Skip 1)
        $key=([string]$current.State)+':'+$current.Sealed
        if($seen.ContainsKey($key)){continue};$seen[$key]=$true
        if($current.State -eq $State -and $current.Sealed -eq $SealedOnce){return $true}
        foreach($edge in $edges){if($edge[0] -eq $current.State){$pending+=@{State=$edge[1];Sealed=($current.Sealed -or $edge[1] -eq 1)}}}
    }
    return $false
}
function Assert-ServiceManifestPath($Path) {
    if($Path -isnot [string] -or [string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 511 -or
        $Path -notmatch '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+\\)' -or $Path -match '[/]|\\$|\\\.\.?($|\\)'){
        throw 'Invalid product manifest path.'
    }
    # Use the agent's Windows normalization check on Windows. The lexical
    # checks above also allow the pure adapter self-check on Linux.
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and
        ([string]::IsNullOrEmpty([IO.Path]::GetFileName($Path)) -or [IO.Path]::GetFullPath($Path) -ine $Path)){
        throw 'Invalid product manifest path normalization.'
    }
}
function ConvertFrom-ServiceJournalRecord($Record) {
    try {
        if($null -eq $Record.Bytes){throw 'Retained journal bytes missing.'}
        if($Record.Bytes.Length -gt 131072){throw 'Journal manifest exceeds the qualified size bound.'}
        $entry=[Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$Record.Bytes) | ConvertFrom-Json -ErrorAction Stop
        $leaf=($Record.Path -split '[\\/]')[-1]
        if($leaf -cnotmatch '^[0-9a-f]{32}\.json$'){throw 'Invalid manifest filename.'}
        $id=[guid]::ParseExact($leaf.Substring(0,32),'N')
        # Require the schema emitted by the current writer for NEW entries.
        # Older schemas remain opaque when they predate the case window.
        foreach($name in @('Transfer','State','Sha256Hex','UpdatedAtUtc','SealedOnce','DestinationGeneration','NamespaceTombstones','PendingRename','LastRenameTransactionId','LastRenameDestination','LastRenameCommitted')){
            if($null -eq $entry.PSObject.Properties[$name]){throw ('Missing current journal field: '+$name+'.')}
        }
        if($id -eq [guid]::Empty -or $null -eq $entry.Transfer -or [guid]$entry.Transfer.TransferId -ne $id){throw 'Invalid product journal Transfer.TransferId.'}
        foreach($numeric in @(@{Name='Transfer.ProcessId';Value=$entry.Transfer.ProcessId;Min=1;Max=[int]::MaxValue},
            @{Name='Transfer.Destination';Value=$entry.Transfer.Destination;Min=0;Max=4},@{Name='State';Value=$entry.State;Min=0;Max=8},
            @{Name='DestinationGeneration';Value=$entry.DestinationGeneration;Min=0;Max=[long]::MaxValue},
            @{Name='LastRenameTransactionId';Value=$entry.LastRenameTransactionId;Min=0;Max=[uint64]::MaxValue})){
            if($null -eq $numeric.Value -or $numeric.Value -is [string] -or $numeric.Value -is [bool] -or $numeric.Value -is [double] -or $numeric.Value -is [single] -or
                ([string]$numeric.Value -notmatch '^\d+$') -or [decimal]$numeric.Value -lt $numeric.Min -or [decimal]$numeric.Value -gt $numeric.Max){
                throw ('Invalid product journal '+$numeric.Name+'.')
            }
        }
        if($null -ne $entry.Transfer.SessionId -and ($entry.Transfer.SessionId -is [string] -or $entry.Transfer.SessionId -is [double] -or $entry.Transfer.SessionId -is [single] -or
            [string]$entry.Transfer.SessionId -notmatch '^\d+$' -or [decimal]$entry.Transfer.SessionId -gt [uint32]::MaxValue)){throw 'Invalid product journal Transfer.SessionId.'}
        if($entry.Transfer.ProcessName -isnot [string] -or [string]::IsNullOrWhiteSpace($entry.Transfer.ProcessName) -or $entry.Transfer.ProcessName.Length -gt 63){throw 'Invalid product journal Transfer.ProcessName.'}
        if([string]::IsNullOrWhiteSpace($entry.UpdatedAtUtc) -or [DateTimeOffset]::Parse($entry.UpdatedAtUtc) -eq [DateTimeOffset]::MinValue){throw 'Invalid journal update timestamp.'}
        if($entry.SealedOnce -isnot [bool] -or $entry.LastRenameCommitted -isnot [bool]){throw 'Invalid journal seal/rename boolean.'}
        if(($null -ne $entry.Sha256Hex -and ($entry.Sha256Hex -isnot [string] -or $entry.Sha256Hex -cnotmatch '^[0-9a-fA-F]{64}$')) -or
            ($entry.State -in @(1,2,3,4,5,6) -and -not $entry.SealedOnce) -or
            ($entry.State -in @(0,8) -and $entry.SealedOnce) -or ($entry.State -in @(4,5) -and $null -eq $entry.Sha256Hex)){
            throw 'Invalid product seal/publication evidence.'
        }
        if(-not (Test-ServiceJournalStateReachable $entry.State $entry.SealedOnce)){throw 'Journal state/seal cannot be reached through current agent transitions.'}
        $destinations=@(Get-ServiceDestinationPaths $entry)
        foreach($path in @($entry.Transfer.StagePath)+$destinations){Assert-ServiceManifestPath $path}
        return [pscustomobject]@{Path=$Record.Path;Entry=$entry;StateName=@('Allocated','Sealed','Inspecting','Approved','Publishing','Released','Blocked','Retained','Unsealed')[[int]$entry.State];DestinationPaths=$destinations}
    }catch{throw ('Invalid new product journal manifest '+$Record.Path+': '+$_.Exception.Message)}
}
function Test-ServiceJournalDelta($Before,$After,[bool]$WindowKnown) {
    $failures=@();$findings=@();$records=@();$new=@()
    if(-not $WindowKnown){$failures+='QPC operation fence missing or not bracketed by service snapshots; see OperationFence and snapshot QPC receipts.'}
    foreach($item in @(@{Tag='before';Snapshot=$Before},@{Tag='after';Snapshot=$After})){
        if($null -eq $item.Snapshot){$failures+=('Journal '+$item.Tag+' snapshot missing.')}
        elseif($item.Snapshot.Status -cne 'OK'){
            $failures+=('Journal '+$item.Tag+' snapshot '+$item.Snapshot.Status+': '+(@($item.Snapshot.Errors | ForEach-Object {$_.Message}) -join ' / '))
        }
        foreach($group in @($item.Snapshot.Journal | Group-Object Path)){
            if($group.Count -gt 1){$findings+=('Duplicate journal path in '+$item.Tag+' snapshot: '+$group.Name)}
        }
    }
    foreach($prior in $Before.Journal){
        $matching=@($After.Journal | Where-Object Path -ieq $prior.Path)
        if($matching.Count -ne 1){
            $message='Prior journal manifest disappeared or duplicated: '+$prior.Path
            if($After.Status -ceq 'OK'){$findings+=$message}else{$failures+=$message}
            $records+=@{Path=$prior.Path;Classification='pre-existing, missing or duplicated'};continue
        }
        if($null -eq $prior.Bytes -or $null -eq $matching[0].Bytes){
            $failures+=('Retained bytes unavailable for pre-existing journal entry: '+$prior.Path)
            $records+=@{Path=$prior.Path;Classification='pre-existing, byte comparison unavailable'};continue
        }
        if([Convert]::ToBase64String([byte[]]$prior.Bytes) -cne [Convert]::ToBase64String([byte[]]$matching[0].Bytes)){
            $findings+=('Pre-existing journal entry changed: '+$prior.Path)
            $records+=@{Path=$prior.Path;Classification='pre-existing, modified'}
        }else{$records+=@{Path=$prior.Path;Classification='pre-existing, unchanged';BeforeArtifact=$prior.Artifact;AfterArtifact=$matching[0].Artifact}}
    }
    foreach($record in $After.Journal){
        if(@($Before.Journal | Where-Object Path -ieq $record.Path).Count){continue}
        # A partial BEFORE inventory cannot establish when a file appeared;
        # never misclassify an uncollected legacy file as new current schema.
        if($Before.Status -cne 'OK'){
            $failures+=('Journal entry creation window unknown: '+$record.Path)
            $records+=@{Path=$record.Path;Classification='creation window unknown'};continue
        }
        if($null -eq $record.Bytes){
            $failures+=('Retained bytes unavailable for new journal entry: '+$record.Path)
            $records+=@{Path=$record.Path;Classification='new, bytes unavailable'};continue
        }
        try{
            $parsed=ConvertFrom-ServiceJournalRecord $record;$new+=$parsed
            $records+=@{Path=$record.Path;Classification='new, current schema and reachable state';StateName=$parsed.StateName}
        }catch{
            $findings+=$_.Exception.Message;$records+=@{Path=$record.Path;Classification='new, invalid';Reason=$_.Exception.Message}
        }
    }
    return [pscustomobject]@{Complete=($failures.Count -eq 0 -and $findings.Count -eq 0);Failures=$failures;Findings=$findings;Entries=$records;NewEntries=$new}
}
function Get-ServiceDestinationPaths($Entry) {
    $paths=@($Entry.Transfer.DestinationPath)
    if($null -ne $Entry.PendingRename){
        if($null -eq $Entry.PendingRename.TransactionId -or $Entry.PendingRename.TransactionId -is [string] -or $Entry.PendingRename.TransactionId -is [double] -or $Entry.PendingRename.TransactionId -is [single] -or
            [string]$Entry.PendingRename.TransactionId -notmatch '^\d+$' -or [decimal]$Entry.PendingRename.TransactionId -le 0 -or
            [decimal]$Entry.PendingRename.TransactionId -gt [uint64]::MaxValue -or $Entry.PendingRename.SealedVersion -isnot [bool] -or
            $Entry.PendingRename.SealedVersion -ne $Entry.SealedOnce){throw 'Invalid pending journal rename.'}
        $paths+=$Entry.PendingRename.DestinationPath
    }
    if($null -ne $Entry.LastRenameDestination){$paths+=$Entry.LastRenameDestination}
    if(($Entry.LastRenameTransactionId -eq 0 -and ($null -ne $Entry.LastRenameDestination -or $Entry.LastRenameCommitted)) -or
        ($Entry.LastRenameTransactionId -ne 0 -and $null -eq $Entry.LastRenameDestination)){throw 'Invalid completed journal rename.'}
    $count=0
    for($name=$Entry.NamespaceTombstones;$null -ne $name;$name=$name.Previous){
        if(++$count -gt 16 -or $null -eq $name.Generation -or $name.Generation -is [string] -or $name.Generation -is [double] -or $name.Generation -is [single] -or
            [string]$name.Generation -notmatch '^\d+$' -or [decimal]$name.Generation -le 0 -or [decimal]$name.Generation -gt [long]::MaxValue){throw 'Invalid journal namespace history.'}
        $paths+=$name.DestinationPath
    }
    return $paths
}
function Test-ServiceFixtureEntry($Record) {
    # Include committed/pending rename names, so rename-away cannot erase a hit.
    foreach($path in @(Get-ServiceDestinationPaths $Record.Entry)){
        if($path.StartsWith($protectedDirectory+'\',[StringComparison]::OrdinalIgnoreCase)){return $true}
    }
    return $false
}
function Get-ServiceTimeline($Before,$After,$Fence,[switch]$R03Offline) {
    $assertions=@();$events=@();$eventStatus='INCONCLUSIVE';$eventReason='Application log anchors unavailable.'
    try {
        if($Before.Application.Status -cne 'OK' -or $After.Application.Status -cne 'OK' -or $Before.BootId -cne $After.BootId -or
            $After.Application.OldestRecordId -gt $Before.Application.NewestRecordId -or $After.Application.NewestRecordId -lt $Before.Application.NewestRecordId){throw 'Application log cleared/wrapped or anchors unavailable.'}
        # Re-read the exact starting anchor to detect clear/reuse, not just IDs.
        $anchor=@(Get-WinEvent -LogName Application -FilterXPath ("*[System[EventRecordID="+$Before.Application.NewestRecordId+"]]"))
        if($anchor.Count -ne 1 -or $anchor[0].ToXml() -cne $Before.Application.NewestXml){throw 'Application starting anchor changed/disappeared.'}
        $query="*[System[Provider[@Name='SafeUpload.Agent.Service'] and EventRecordID > "+$Before.Application.NewestRecordId+" and EventRecordID <= "+$After.Application.NewestRecordId+"]]"
        $queryErrors=@();$records=@(Get-WinEvent -LogName Application -FilterXPath $query -ErrorAction SilentlyContinue -ErrorVariable queryErrors | Sort-Object RecordId)
        if(@($queryErrors | Where-Object {$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'}).Count){throw 'Application provider query failed.'}
        foreach($record in $records){$events+=@{RecordId=$record.RecordId;Provider=$record.ProviderName;Id=$record.Id;Utc=$record.TimeCreated.ToUniversalTime().ToString('o');
            Xml=$record.ToXml();Message=$record.Message;UserSid=$(if($null -ne $record.UserId){$record.UserId.Value}else{$null});ProcessId=$record.ProcessId;
            Authentication='Windows Application provider XML; diagnostic only, not notification emission evidence'}}
        $eventStatus='OK';$eventReason='Application anchors retained; exact provider/RecordID window read. Notification expectations use the separate protected durable record.'
    }catch{$eventReason=$_.Exception.Message}
    $windowKnown=($Fence.Complete -eq $true -and -not [string]::IsNullOrWhiteSpace($Fence.BootId) -and $Fence.QpcFrequency -gt 0 -and
        $null -ne $Before.StartQpc -and $null -ne $Before.EndQpc -and $null -ne $After.StartQpc -and $null -ne $After.EndQpc -and
        $null -ne $Fence.ReleasedQpc -and $null -ne $Fence.CompletedQpc -and
        $Before.BootId -ceq $Fence.BootId -and $After.BootId -ceq $Fence.BootId -and
        $Before.QpcFrequency -eq $Fence.QpcFrequency -and $After.QpcFrequency -eq $Fence.QpcFrequency -and
        $Before.StartQpc -le $Before.EndQpc -and $Before.EndQpc -le $Fence.ReleasedQpc -and
        $Fence.ReleasedQpc -le $Fence.CompletedQpc -and $Fence.CompletedQpc -le $After.StartQpc -and $After.StartQpc -le $After.EndQpc)
    $journalDelta=Test-ServiceJournalDelta $Before $After $windowKnown
    $journalKnown=$journalDelta.Complete
    $journalFailures=@($journalDelta.Failures)+@($journalDelta.Findings)
    $new=@($journalDelta.NewEntries | Where-Object {Test-ServiceFixtureEntry $_})
    $deltaVerdict=if($journalDelta.Findings.Count){'FAIL'}elseif($journalKnown){'PASS'}else{'INCONCLUSIVE'}
    $assertions+=@{Name='JournalDelta';Verdict=$deltaVerdict;Reason=$(if($journalKnown){'Authenticated byte delta; all pre-existing entries unchanged; all new entries satisfy current schema and reachable state.'}else{$journalFailures -join ' '})}
    foreach($expectation in $row.JournalExpectations) {
        $verdict='INCONCLUSIVE';$reason=$journalFailures -join ' '
        $bad=@($new | Where-Object {if($expectation -ceq 'NoApproved'){$_.StateName -in @('Approved','Publishing','Released')}elseif($expectation -ceq 'NoReleased'){$_.StateName -ceq 'Released'}else{$false}})
        if($journalKnown){
            if($expectation -ceq 'NoNewTransfer'){$verdict=if($new.Count){'FAIL'}else{'PASS'};$reason='Before/after authenticated product manifest inventory; new fixture transfers='+$new.Count}
            elseif($expectation -in @('NoApproved','NoReleased')){
                if($bad.Count){$verdict='FAIL';$reason='Authenticated fixture manifest contradicts '+$expectation}
                elseif($new.Count -eq 0){$verdict='PASS';$reason='No new fixture transfer and all pre-existing entries byte-identical; therefore no fixture '+$expectation.Substring(2)+' transition.'}
                else{$reason='Latest-state manifests are not an append-only transition history; an intermediate state cannot be excluded.'}
            }else{$reason='Unsupported journal expectation: '+$expectation}
        }
        # A trusted partial snapshot can still contain a positive contradiction.
        if($bad.Count){$verdict='FAIL';$reason='Authenticated fixture manifest contradicts '+$expectation+'; incomplete coverage cannot hide positive evidence.'}
        if($expectation -ceq 'NoNewTransfer' -and $windowKnown -and $Before.Status -ceq 'OK' -and $new.Count){$verdict='FAIL';$reason='Authenticated new fixture manifest contradicts NoNewTransfer.'}
        if($journalDelta.Findings.Count){$verdict='FAIL';$reason=$journalDelta.Findings -join ' '}
        $assertions+=@{Name='JournalExpectation';Expectation=$expectation;Verdict=$verdict;Reason=$reason}
    }
    $notificationProof=Test-NotificationWindow $Before.Notifications $After.Notifications $Fence $windowKnown
    $agentAbsence=$null;$locationUnchanged=$null
    $allowAgentAbsence=($CaseId -cne 'R03' -or ($R03Offline -and $Before.Tag -ceq 'r03-offline-before' -and $After.Tag -ceq 'r03-offline-after'))
    if(-not $notificationProof.Complete -and $allowAgentAbsence){
        $systemLog=Read-AgentLogWindow $Before.AgentExecution.SystemBegin $After.AgentExecution.SystemEnd 'System'
        $securityLog=Read-AgentLogWindow $Before.AgentExecution.SecurityBegin $After.AgentExecution.SecurityEnd 'Security'
        $agentAbsence=Test-AgentDidNotRun $Before $After $Fence $windowKnown $systemLog $securityLog -R03Offline:$R03Offline
        $assertions+=@{Name='AgentAbsenceScm';Verdict=$agentAbsence.ScmProof.Verdict;Reason=$agentAbsence.ScmProof.Reason}
        $locationUnchanged=Test-NotificationLocationUnchanged $Before.Notifications $After.Notifications $Fence
        if($agentAbsence.Complete -and $locationUnchanged.Complete){
            $notificationProof=[pscustomobject]@{Complete=$true;Reason='agent did not run in window';Emissions=@();Source='AgentDidNotRunAndUnchangedLocation'}
        }else{
            $notificationProof.Reason+=' Agent absence proof: '+$agentAbsence.Reason+' Notification location proof: '+$locationUnchanged.Reason
        }
    }
    foreach($expectation in $row.NotificationExpectations){
        $verdict='INCONCLUSIVE';$reason=$notificationProof.Reason
        if($notificationProof.Complete){
            $bad=@();$supported=$true
            switch -CaseSensitive ($expectation) {
                'NoNotification' {$bad=@($notificationProof.Emissions)}
                'None' {$bad=@($notificationProof.Emissions)}
                'ExpectedNone' {$bad=@($notificationProof.Emissions)}
                'NoRelease' {$bad=@($notificationProof.Emissions | Where-Object {($_.Entry.Kind -ceq 'Transfer' -and $_.Entry.Phase -ceq 'Released') -or ($_.Entry.Kind -ceq 'Event' -and $_.Entry.Phase -cin @('Approved','AllowedWithoutInspection'))})}
                # Approval/release/hand-back are the concrete current contract
                # states, including legacy audit-event notifications.
                'NoApproval' {$bad=@($notificationProof.Emissions | Where-Object {($_.Entry.Kind -ceq 'Transfer' -and $_.Entry.Phase -ceq 'Released') -or ($_.Entry.Kind -ceq 'Event' -and $_.Entry.Phase -ceq 'Approved')})}
                'NoHandBack' {$bad=@($notificationProof.Emissions | Where-Object {($_.Entry.Kind -ceq 'Transfer' -and $_.Entry.Phase -cin @('Blocked','Retained')) -or ($_.Entry.Kind -ceq 'Event' -and $_.Entry.Phase -cin @('Blocked','Retained'))})}
                default {$supported=$false;$reason='Unsupported notification expectation: '+$expectation}
            }
            if($supported -and $verdict -eq 'INCONCLUSIVE'){$verdict=if($bad.Count){'FAIL'}else{'PASS'}}
            if($supported -and $notificationProof.Source -ceq 'AgentDidNotRunAndUnchangedLocation'){$reason='agent did not run in window'}
            elseif($supported){$reason='Authenticated emission chain covers whole operation window; '+$expectation+' matching emissions='+$bad.Count+'. Scope is all agent emissions (conservative for fixture negatives).'}
        }
        $assertions+=@{Name='NotificationExpectation';Expectation=$expectation;Verdict=$verdict;Reason=$reason}
    }
    $verdict=if(@($assertions | Where-Object Verdict -eq 'FAIL').Count){'FAIL'}elseif(@($assertions | Where-Object Verdict -eq 'INCONCLUSIVE').Count){'INCONCLUSIVE'}else{'PASS'}
    $timelineReason=if($verdict -eq 'PASS'){'Per-expectation results from authenticated product journal snapshots and whole-window notification proof; see ServiceEvidence.'}
        else{@($assertions | Where-Object Verdict -ne 'PASS' | ForEach-Object {$_.Reason} | Select-Object -Unique) -join ' '}
    $assertions+=@{Name='ActualServiceTimelines';Verdict=$verdict;Reason=$timelineReason}
    $result=[pscustomobject]@{Source='AuthenticatedAgentJournalAndNotificationRecord';NotificationProof=$notificationProof;AgentAbsenceProof=$agentAbsence;NotificationLocationProof=$locationUnchanged;NotificationEmissions=$notificationProof.Emissions;TrustBoundary='SYSTEM-owned policy; SYSTEM or Administrators-owned journal/notification record; exact protected SYSTEM/Administrators DACL, no reparses, single-link bounded manifests, same-handle ACL and bytes; OS process/token/SCM/audit APIs trusted; privileged local actors trusted';
        Before=$Before;After=$After;OperationFence=$Fence;WindowBound=$windowKnown;JournalDelta=$journalDelta;JournalFailures=$journalFailures;ApplicationStatus=$eventStatus;ApplicationReason=$eventReason;ApplicationEvents=$events;Assertions=$assertions}
    Save-State $result (Join-Path $evidenceDirectory 'service-timeline.clixml')
    return $result
}
function Assert-ActorProcess($Actor) {
    $process=Get-CimInstance Win32_Process -Filter ("ProcessId="+$Actor.Pid) -ErrorAction Stop
    if($null -eq $process -or $process.SessionId -ne $Actor.SessionId -or
        $process.CommandLine -notlike ('*'+(Join-Path $stateDirectory 'writer.ps1')+'*')){throw 'Writer process/session provenance mismatch'}
    $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
    if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $state.ActorSid){throw 'OS writer SID provenance mismatch'}
    if(@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object {$_.SID.Value -ceq $state.ActorSid}).Count -ne 0){throw 'Writer has administrator membership'}
    return [pscustomobject]@{Pid=$process.ProcessId;SessionId=$process.SessionId;OwnerSid=$owner.Sid;CommandLine=$process.CommandLine;Task=(Get-ScheduledTask -TaskName $writerTask | Select-Object TaskName,Principal,State)}
}
function Test-CachedJournalSequence($Transitions,[string]$Outcome,[string]$Digest,$RenameCommit=$null) {
    $assertions=@();$expected=@(if($Outcome -ceq 'APPROVE'){@('Allocated','Sealed','Inspecting','Approved','Publishing','Released')}else{@('Allocated','Sealed','Inspecting','Blocked')})
    $names=@($Transitions | ForEach-Object {$_.StateName})
    $missing=@($expected | Where-Object {$names -cnotcontains $_})
    $bad=@($names | Where-Object {$_ -cnotin $expected})
    $position=-1;$ordered=$true
    foreach($name in $names){$next=[array]::IndexOf($expected,$name);if($next -le $position){$ordered=$false};$position=$next}
    # The manifest's durable, service-validated state history records every transition; prefer it to polling.
    $history=@(if(@($Transitions).Count){$Transitions[-1].History | Where-Object {$null -ne $_}}else{@()})
    if($history.Count){
        $exact=($history -join ',') -ceq ($expected -join ',')
        $assertions+=@{Name='C01JournalOrder';Verdict=$(if($exact){'PASS'}elseif($bad.Count -or -not $ordered -or ($expected[0..([Math]::Min($history.Count,$expected.Count)-1)] -join ',') -cne ($history[0..([Math]::Min($history.Count,$expected.Count)-1)] -join ',')){'FAIL'}else{'INCONCLUSIVE'});
            Reason=('Durable history='+($history -join ' -> ')+'; expected='+($expected -join ' -> ')+'; polled='+($names -join ' -> '));Transitions=$Transitions}
    }else{
    $assertions+=@{Name='C01JournalOrder';Verdict=$(if($bad.Count -or -not $ordered){'FAIL'}elseif($missing.Count){'INCONCLUSIVE'}else{'PASS'});
        Reason=('Observed='+($names -join ' -> ')+'; missing='+($missing -join ',')+'. Latest-state journal polling cannot reconstruct skipped transitions.');Transitions=$Transitions}
    }
    $sealed=@($Transitions | Where-Object {$_.SealedOnce -and $null -ne $_.Sha256Hex})
    $wrong=@($sealed | Where-Object {$_.Sha256Hex -cne $Digest})
    $assertions+=@{Name='C01SealedDigest';Verdict=$(if($wrong.Count){'FAIL'}elseif($sealed.Count){'PASS'}else{'INCONCLUSIVE'});Reason='Every observed sealed digest must equal independently generated whole image A.'}
    $identities=@($Transitions | Where-Object {$null -ne $_.TransferId} | ForEach-Object {([string]$_.TransferId)+':'+$_.DestinationGeneration} | Sort-Object -Unique)
    if($identities.Count -gt 1){
        # A native replacement moves ONE transfer between independent source
        # and target generation slots. Require its observed committed manifest,
        # never waive generation identity just because this is a rename case.
        $valid=$null -ne $RenameCommit -and $RenameCommit.Verified -eq $true
        $targetSeen=$false
        foreach($transition in $Transitions){
            if($transition.TransferId -ine $RenameCommit.TransferId){$valid=$false}
            if($transition.DestinationGeneration -eq $RenameCommit.TargetGeneration){$targetSeen=$true}
            elseif($transition.DestinationGeneration -ne $RenameCommit.SourceGeneration -or $targetSeen){$valid=$false}
        }
        $assertions+=@{Name='C01JournalIdentity';Verdict=$(if($valid -and $targetSeen){'PASS'}else{'FAIL'});Reason='Only one proven committed rename may advance from the source generation to the reserved target generation; transfer ID stays exact.';RenameCommit=$RenameCommit}
    }
    return ,$assertions
}
function Test-CachedNotifications($Proof,[string]$TransferId,[int]$SessionId,[string]$Outcome,[string]$Digest,$HandBack=$null) {
    $assertions=@();$correlated=@($Proof.Emissions | ForEach-Object {$_.Entry} | Where-Object {
        ($_.Kind -ceq 'Transfer' -and $_.TransferId -ieq $TransferId) -or ($_.Kind -ceq 'Event' -and $_.EventId -ieq $TransferId)})
    $entries=@($correlated | Where-Object Kind -ceq 'Transfer')
    $wanted=if($Outcome -ceq 'APPROVE'){'Released'}else{'Blocked'}
    $found=@($entries | Where-Object {$_.Phase -ceq $wanted})
    $bad=@($correlated | Where-Object {($_.TargetSessionId -ne $SessionId) -or ($Outcome -ceq 'BLOCK' -and $_.Phase -cin @('Approved','Publishing','Released')) -or
        ($Outcome -ceq 'APPROVE' -and ($_.Phase -ceq 'Blocked' -or -not [string]::IsNullOrWhiteSpace($_.HandBackPath)))})
    $assertions+=@{Name='C01OutcomeNotification';Verdict=$(if($bad.Count){'FAIL'}elseif(-not $Proof.Complete){'INCONCLUSIVE'}elseif(-not $found.Count){'FAIL'}else{'PASS'});
        Reason=('Required='+$wanted+'; matching='+$found.Count+'; contradictory/session mismatch='+$bad.Count+'; '+$Proof.Reason)}
    $digests=@($found | Where-Object {-not [string]::IsNullOrWhiteSpace($_.Sha256Hex)})
    $wrong=@($digests | Where-Object Sha256Hex -cne $Digest)
    $label=if($Outcome -ceq 'APPROVE'){'C01ReleasedNotificationDigest'}else{'C01BlockedNotificationDigest'}
    $assertions+=@{Name=$label;Verdict=$(if($wrong.Count){'FAIL'}elseif($digests.Count -eq $found.Count -and $found.Count -and $Proof.Complete){'PASS'}else{'INCONCLUSIVE'});
        Reason=($wanted+' notification requires exact whole-image digest; present='+$digests.Count+'; matching outcome emissions='+$found.Count+'; coverage='+$Proof.Complete+'. Missing digest/coverage cannot be supplied by journal correlation.')}
    if($Outcome -ceq 'BLOCK'){
        $paths=@($found | Where-Object {-not [string]::IsNullOrWhiteSpace($_.HandBackPath)})
        $verified=@($HandBack.Files | Where-Object {$_.Sha256 -ceq $Digest -and $_.SingleLink -eq $true -and $_.NoReparse -eq $true})
        $wrong=@($paths | Where-Object {$_.HandBackPath -cnotin $verified.Path})
        $verdict=if($null -ne $HandBack -and $wrong.Count){'FAIL'}elseif($null -eq $HandBack -or $paths.Count -ne $found.Count -or -not $found.Count -or -not $Proof.Complete){'INCONCLUSIVE'}else{'PASS'}
        $assertions+=@{Name='C01BlockedNotificationHandBackPath';Verdict=$verdict;
            Reason=('Every Blocked emission must name the exact independently verified actor hand-back file; paths='+$paths.Count+'; verified='+$verified.Count+'. Missing hand-back/notification coverage remains INCONCLUSIVE.')}
    };return ,$assertions
}
function Get-CachedJournalObservation([string]$Tag,$Actor,[string[]]$Paths=@(),[string[]]$ExcludedIds=@(),[switch]$RetryTransientJournal) {
    if(-not $Paths.Count){$Paths=@((Join-Path $protectedDirectory 'cached.txt'));if($cachedKind -ceq 'replacement'){$Paths+= (Join-Path $protectedDirectory 'save.tmp.txt')}}
    $snapshot=Get-ServiceSnapshot $Tag -JournalOnly -RetryTransientJournal:$RetryTransientJournal
    $entries=@();$errors=@($snapshot.Errors)
    foreach($record in $snapshot.Journal){
        if(@($trial.ServiceBefore.Journal | Where-Object Path -ieq $record.Path).Count){continue}
        try {
            $parsed=ConvertFrom-ServiceJournalRecord $record
            if($parsed.Entry.Transfer.TransferId -iin $ExcludedIds){continue}
            if(@($parsed.DestinationPaths | Where-Object {$_ -iin $paths}).Count){
                if($parsed.Entry.Transfer.ProcessId -ne $Actor.Pid -or $parsed.Entry.Transfer.SessionId -ne $Actor.SessionId){throw 'C01 transfer writer PID/session mismatch'}
                $historyNames=@($parsed.Entry.StateHistory | Where-Object {$null -ne $_} | ForEach-Object {@('Allocated','Sealed','Inspecting','Approved','Publishing','Released','Blocked','Retained','Unsealed')[[int]$_.State]})
                $entries+= [pscustomobject]@{StateName=$parsed.StateName;State=[int]$parsed.Entry.State;TransferId=$parsed.Entry.Transfer.TransferId;History=$historyNames;
                    SealedOnce=$parsed.Entry.SealedOnce;Sha256Hex=$parsed.Entry.Sha256Hex;DestinationGeneration=$parsed.Entry.DestinationGeneration;
                    UpdatedAtUtc=$parsed.Entry.UpdatedAtUtc;StartQpc=$snapshot.StartQpc;EndQpc=$snapshot.EndQpc;Artifact=$record.Artifact;Record=$record}
            }
        }catch{$errors+=Get-ErrorChain $_.Exception}
    }
    return [pscustomobject]@{Status=$(if($snapshot.Status -ceq 'OK' -and -not $errors.Count){'OK'}else{'INCONCLUSIVE'});Entries=$entries;Errors=$errors;Snapshot=$snapshot}
}
function Get-LatencyTransferHints($Tails,[string]$BootId,[string]$InstanceId,[long]$MinimumQpc,[long]$Frequency,[int]$SessionId,$ExcludedIds=@{}) {
    # Authenticated bounded suffixes discover names only. They are neither a
    # complete emission chain nor qualifying round evidence. Partial boundary
    # lines are ignored until the next poll; complete malformed lines fail.
    if(@($Tails).Count -gt 2){throw 'Latency notification tail count exceeds bound'}
    $ids=@{};$utf8=[Text.UTF8Encoding]::new($false,$true)
    foreach($tail in $Tails){
        [byte[]]$bytes=$tail.Bytes
        if($null -eq $bytes -or $bytes.Length -gt 65536 -or $tail.Offset -lt 0){throw 'Invalid latency notification tail bound'}
        $start=0;$skipFirst=$tail.Offset -gt 0
        for($i=0;$i -lt $bytes.Length;$i++){
            if($bytes[$i] -ne 10){continue}
            if($skipFirst){$start=$i+1;$skipFirst=$false;continue}
            $length=$i-$start
            if($length -le 0 -or $length -ge 16384){throw 'Invalid latency notification line size'}
            $entry=$utf8.GetString($bytes,$start,$length) | ConvertFrom-Json -ErrorAction Stop;$start=$i+1
            if($entry.Version -ne 1 -or $entry.Kind -cnotin @('Start','Heartbeat','Stop','Rotation','Transfer','Event','Status') -or
                $null -eq $entry.Qpc -or $entry.Qpc -lt 0 -or [string]::IsNullOrWhiteSpace($entry.BootId)){throw 'Invalid latency notification hint'}
            if($entry.BootId -cne $BootId -or $entry.Qpc -lt $MinimumQpc){continue}
            if($entry.InstanceId -cne $InstanceId -or $entry.QpcFrequency -ne $Frequency -or $entry.Kind -cin @('Start','Stop')){throw 'Latency notification service instance/clock changed'}
            if($entry.Kind -cne 'Transfer' -or $null -eq $entry.TargetSessionId -or $entry.TargetSessionId -ne $SessionId){continue}
            $id=[guid]::Parse($entry.TransferId)
            if($id -eq [guid]::Empty -or $entry.Phase -cnotin @('Analyzing','Released','Blocked','Retained')){throw 'Invalid latency notification transfer hint'}
            $key=$id.ToString('D')
            if(-not $ExcludedIds.ContainsKey($key)){$ids[$key]=$true}
        }
    }
    return @($ids.Keys)
}
function ConvertFrom-LatencyManifestRecord($Record,$Actor,[string[]]$Paths,[string]$TransferId,[string]$Digest) {
    $parsed=ConvertFrom-ServiceJournalRecord $Record;$transfer=$parsed.Entry.Transfer
    if([guid]$transfer.TransferId -ne [guid]$TransferId){throw 'Dedicated completion transfer ID mismatch'}
    if(-not @($parsed.DestinationPaths | Where-Object {$_ -iin $Paths}).Count){return $null}
    if($transfer.ProcessId -ne $Actor.Pid -or $transfer.SessionId -ne $Actor.SessionId -or $transfer.RequestorSid -cne $Actor.Sid){throw 'Dedicated completion actor PID/session/SID mismatch'}
    if($parsed.StateName -cin @('Blocked','Retained','Unsealed')){throw ('Dedicated expected APPROVE but observed '+$parsed.StateName)}
    $history=@($parsed.Entry.StateHistory | Where-Object {$null -ne $_} | ForEach-Object {@('Allocated','Sealed','Inspecting','Approved','Publishing','Released','Blocked','Retained','Unsealed')[[int]$_.State]})
    if($parsed.StateName -ceq 'Released' -and (-not $parsed.Entry.SealedOnce -or $parsed.Entry.Sha256Hex -cne $Digest -or
        ($history -join ',') -cne 'Allocated,Sealed,Inspecting,Approved,Publishing,Released')){throw 'Dedicated Released whole-image/history evidence missing'}
    return [pscustomobject]@{StateName=$parsed.StateName;State=[int]$parsed.Entry.State;TransferId=$transfer.TransferId;History=$history;
        SealedOnce=$parsed.Entry.SealedOnce;Sha256Hex=$parsed.Entry.Sha256Hex;DestinationGeneration=$parsed.Entry.DestinationGeneration;
        UpdatedAtUtc=$parsed.Entry.UpdatedAtUtc;StartQpc=$Record.StartQpc;EndQpc=$Record.EndQpc;Artifact=$Record.Artifact;Record=$Record}
}
function Get-LatencyCompletionObservation($Probe,$Actor,[string[]]$Paths,[string]$Digest,[long]$Deadline,$ExcludedIds) {
    $held=@();$root=Split-Path -Parent $policyPath;$journal=Join-Path $root 'staging-journal';$start=[Diagnostics.Stopwatch]::GetTimestamp()
    try{
        Initialize-ServiceEvidenceReader
        $ancestors=@();for($cursor=$root; -not [string]::IsNullOrWhiteSpace($cursor);$cursor=[IO.Path]::GetDirectoryName($cursor)){$ancestors=@($cursor)+$ancestors}
        foreach($path in $ancestors){$held+= [SUProofFile]::Open($path,$true,($path -ceq $root))}
        $held+= [SUProofFile]::Open($journal,$true,$true,$false,$true)
        $ids=@($Probe.TransferId | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
        if(-not $ids.Count){
            $directory=Join-Path $root 'notifications';$held+= [SUProofFile]::Open($directory,$true,$true,$false,$true);$tails=@()
            foreach($name in @('previous.jsonl','emissions.jsonl')){
                $path=Join-Path $directory $name
                $tail=Invoke-LatencyJournalIo {
                    $obj=$null
                    try{
                        try{$obj=[SUProofFile]::Open($path,$false,$true,$true,$true)}catch{
                            # Optional previous segment, or active name briefly
                            # absent during rotation. These are discovery hints.
                            for($ex=$_.Exception;$null -ne $ex;$ex=$ex.InnerException){if($ex -is [ComponentModel.Win32Exception] -and $ex.NativeErrorCode -in @(2,3)){return $null}}
                            throw
                        }
                        [SUProofFile]::ReadTail($obj,65536)
                    }finally{if($null -ne $obj){$obj.Dispose()}}
                } 'CompletionTailRead' $path $Probe.Retries $Deadline -Enabled
                if($null -ne $tail){$tails+= $tail;$Probe.TailBytesRead+=$tail.Bytes.Length}
            }
            $ids=@(Get-LatencyTransferHints $tails $Probe.BootId $Probe.InstanceId $Probe.MinimumQpc $Probe.QpcFrequency $Actor.SessionId $ExcludedIds)
        }
        $matches=@()
        foreach($id in $ids){
            if([Diagnostics.Stopwatch]::GetTimestamp() -ge $Deadline){throw 'Dedicated completion QPC deadline expired'}
            $path=Join-Path $journal (([guid]$id).ToString('N')+'.json')
            $record=Invoke-LatencyJournalIo {
                $obj=[SUProofFile]::Open($path,$false,$true,$true,$true)
                try{[pscustomobject]@{Path=$path;Bytes=[SUProofFile]::Read($obj,131072);Owner=$obj.Owner;Sddl=$obj.Sddl;
                    StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();Artifact=$null}}finally{$obj.Dispose()}
            } 'CompletionManifestRead' $path $Probe.Retries $Deadline -Enabled
            $Probe.ManifestReads++
            $entry=ConvertFrom-LatencyManifestRecord $record $Actor $Paths $id $Digest
            if($null -ne $entry){$matches+= $entry}
        }
        if($matches.Count -gt 1){throw 'Dedicated round has ambiguous transfers'}
        if($matches.Count){$Probe.TransferId=$matches[0].TransferId;return $matches[0]}
        return $null
    }finally{foreach($obj in $held){$obj.Dispose()}}
}
function Capture-CachedSample($Context,$Baseline,[string]$PhaseName,[long]$Sequence,[string]$TargetPath=(Join-Path $protectedDirectory 'cached.txt')) {
    $sample=Capture-InvariantSample $Context $Baseline $PhaseName $Sequence
    # The shared observer records raw absence via the parent index, but only
    # opens supplemental readers for existing files. C01 also needs both
    # native fresh opens to attest ERROR_FILE_NOT_FOUND for an absent final.
    $targets=@(@{Path=$TargetPath;Property='C01Readers'})
    if($CaseId -ceq 'R01'){$targets+=@{Path=(Join-Path $protectedDirectory 'offline-new.txt');Property='R01OfflineReaders'}}
    foreach($target in $targets){
        $readers=@();$path=$target.Path
        foreach($raw in @($false,$true)){
            try{$reader=[StagedInvariant.Native]::Fresh($path,$raw,$Context.Geometry.Alignment);$readers+=@{Unbuffered=$raw;Status='OK';Result=$reader;NativeCode=0}}
            catch{
                $code=$null;for($ex=$_.Exception;$null -ne $ex;$ex=$ex.InnerException){if($null -ne $ex.PSObject.Properties['NativeCode']){$code=$ex.NativeCode}}
                $readers+=@{Unbuffered=$raw;Status='ERROR';NativeCode=$code;ErrorChain=(Get-ErrorChain $_.Exception);Reason=$_.Exception.ToString()}
            }
        }
        $sample | Add-Member NoteProperty $target.Property $readers
    }
    return $sample
}
function Test-CachedImage($Image,$Geometry,[byte[]]$Expected,[string]$Label) {
    $assertions=@();$digest=[StagedInvariant.Native]::Hash($Expected)
    if($Image.Absent){return ,@(@{Name=($Label+'Image');Verdict='FAIL';Reason='Expected whole image absent in raw parent index.'})}
    if($null -eq $Image.Length -or [string]::IsNullOrWhiteSpace($Image.Sha256)){return ,@(@{Name=($Label+'Image');Verdict='INCONCLUSIVE';Reason='Raw image length or digest unavailable.'})}
    $good=$Image.Length -eq $Expected.Length -and $Image.Sha256 -ceq $digest
    $assertions+=@{Name=($Label+'Image');Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Raw logical length and SHA-256 must equal the complete independent image.'}
    try{
        $logical=[IO.File]::ReadAllBytes($Image.LogicalArtifact.Path)
        if($logical.Length -ne $Image.LogicalArtifact.Length -or [StagedInvariant.Native]::Hash($logical) -cne $Image.LogicalArtifact.Sha256){throw 'Raw logical artifact hash/length mismatch'}
        $assertions+=@{Name=($Label+'LogicalBytes');Verdict=$(if([StagedInvariant.Native]::CountDifferences($Expected,$logical)){'FAIL'}else{'PASS'});Reason='Retained whole raw logical artifact compared byte for byte to independent image.'}
    }catch{$assertions+=@{Name=($Label+'LogicalBytes');Verdict='INCONCLUSIVE';Reason=$_.Exception.Message}}
    $covered=0;$ranges=@()
    foreach($container in @($Image.Containers | Where-Object Kind -ceq 'DATA')){
        try{
            $raw=[IO.File]::ReadAllBytes($container.Artifact.Path)
            if($raw.Length -ne $container.Artifact.Length -or [StagedInvariant.Native]::Hash($raw) -cne $container.Artifact.Sha256){throw 'Retained raw extent hash/length mismatch'}
            $run=@($Image.Runs | Where-Object {$_.Lcn -ge 0 -and $container.Offset -ge $_.Lcn*$Geometry.Cluster -and $container.Offset+$container.Length -le ($_.Lcn+$_.Clusters)*$Geometry.Cluster})
            if($run.Count -ne 1){throw 'Cannot position raw extent in exactly one VCN run'}
            $offset=$run[0].Vcn*$Geometry.Cluster+$container.Offset-$run[0].Lcn*$Geometry.Cluster
            if($offset -lt 0 -or $offset+$raw.Length -gt $Expected.Length){throw 'Raw allocation outside exact cluster-aligned image; no slack oracle available'}
            $want=New-Object byte[] $raw.Length;[Array]::Copy($Expected,[long]$offset,$want,[long]0,[long]$raw.Length)
            $different=[StagedInvariant.Native]::CountDifferences($want,$raw);$covered+=$raw.Length;$ranges+=@{Offset=$offset;Length=$raw.Length}
            $assertions+=@{Name=($Label+'RawExtent');Verdict=$(if($different){'FAIL'}else{'PASS'});Reason=('Raw extent at '+$container.Offset+'; differing bytes='+$different);ForbiddenByteCount=$different}
        }catch{$assertions+=@{Name=($Label+'RawExtent');Verdict='INCONCLUSIVE';Reason=$_.Exception.Message}}
    }
    $end=0;$contiguous=$true
    foreach($range in @($ranges | Sort-Object Offset)){if($range.Offset -ne $end){$contiguous=$false};$end=$range.Offset+$range.Length}
    if($covered -ne $Expected.Length -or -not $contiguous -or $end -ne $Expected.Length){$assertions+=@{Name=($Label+'RawExtentCoverage');Verdict='INCONCLUSIVE';Reason=('Expected '+$Expected.Length+' allocated data bytes; compared '+$covered+'; complete VCN coverage without gaps/overlap='+$contiguous)}}
    return ,$assertions
}
function Test-CachedSample($Sample,$Baseline,[bool]$Released,[byte[]]$ImageA,[byte[]]$ImageB=$null,[string]$TargetPath=(Join-Path $protectedDirectory 'cached.txt')) {
    $assertions=@();$path=$TargetPath;$leaf=[IO.Path]::GetFileName($path)
    $expected=$ImageB;if($Released){$expected=$ImageA}
    if($null -ne $expected){$expected=[byte[]]$expected;$digest=[StagedInvariant.Native]::Hash($expected)}else{$digest=$null}
    $base=@($Baseline.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ceq $path -and -not $_.Absent})
    if($Sample.Status -cne 'OK'){$assertions+=@{Name='C01RawCapture';Verdict='INCONCLUSIVE';Reason=('Incomplete raw sample '+$Sample.Phase+': '+($Sample.Error | Out-String))}}
    foreach($capture in $Sample.Captures){
        foreach($image in @($capture.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ceq $path})){
            if($null -eq $expected){
                $assertions+=@{Name='C01RawFinalAbsent';Verdict=$(if($image.Absent){'PASS'}else{'FAIL'});Reason=('Raw final must remain absent in '+$Sample.Phase);Sequence=$Sample.Sequence}
            }else{
                $label=if($Released){'C01Released'}else{'C01Base'}
                $assertions+=Test-CachedImage $image $Baseline.Geometry $expected $label
                if($null -ne $ImageB){
                    if($base.Count -ne 1 -or $null -eq $image.Identity.FileId){$assertions+=@{Name='C01FinalIdentity';Verdict='INCONCLUSIVE';Reason='Baseline/current final file identity unavailable.'}}
                    else{
                        $same=$base[0].Identity.FileId -ceq $image.Identity.FileId
                        $assertions+=@{Name='C01FinalIdentity';Verdict=$(if($same -ne $Released){'PASS'}else{'FAIL'});Reason='Protected B keeps its file ID until approval; POSIX publication must create a new A file ID.'}
                    }
                }
            }
        }
        foreach($parent in @($capture.Images | Where-Object Role -ceq 'Parent')){
            $before=@($Baseline.Images | Where-Object {$_.Role -ceq 'Parent' -and $_.Path -ceq $parent.Path})
            if($before.Count -ne 1){$assertions+=@{Name='C01PublicListing';Verdict='INCONCLUSIVE';Reason=('No unique raw baseline parent for '+$parent.Path)};continue}
            if($null -eq $parent.DirectoryEntries -or $null -eq $before[0].DirectoryEntries){$assertions+=@{Name='C01PublicListing';Verdict='INCONCLUSIVE';Reason='Raw parent or baseline directory entries unavailable.'};continue}
            $actual=@($parent.DirectoryEntries | Where-Object {$_.Name -notin @('.','..')})
            $old=@($before[0].DirectoryEntries | Where-Object {$_.Name -notin @('.','..')})
            $extras=@($actual | Where-Object {$_.Name -cnotin $old.Name -and (-not $Released -or $_.Name -cne $leaf)})
            $missing=@($old | Where-Object {$_.Name -cnotin $actual.Name})
            $changed=@($old | Where-Object {
                $prior=$_
                if($Released -and $prior.Name -ceq $leaf){$false}else{@($actual | Where-Object {$_.Name -ceq $prior.Name -and $_.Reference -eq $prior.Reference -and $_.Eof -eq $prior.Eof -and $_.Attributes -eq $prior.Attributes}).Count -ne 1}
            })
            $assertions+=@{Name='C01PublicListing';Verdict=$(if($extras.Count -or $missing.Count -or $changed.Count){'FAIL'}else{'PASS'});Reason=('Raw names/IDs: unexpected='+($extras.Name -join ',')+'; missing='+($missing.Name -join ',')+'; changed='+($changed.Name -join ','));Sequence=$Sample.Sequence}
        }
        if($null -ne $ImageB){
            $retained=@($capture.Images | Where-Object {$base.Count -eq 1 -and $_.Role -ceq ('Retained:'+$base[0].Identity.FileId)})
            if($retained.Count -ne 1){$assertions+=@{Name='C01RetainedBase';Verdict='INCONCLUSIVE';Reason='Exactly one retained physical B identity/raw capture required.'}}
            else{$assertions+=Test-CachedImage $retained[0] $Baseline.Geometry $ImageB 'C01RetainedBase'}
            $oldReaders=@($capture.Readers | Where-Object {$_.Role -ceq 'Retained' -and $base.Count -eq 1 -and $_.FileId -ceq $base[0].Identity.FileId})
            if($oldReaders.Count -ne 1 -or $oldReaders[0].Status -cne 'OK'){$assertions+=@{Name='C01RetainedBaseReader';Verdict='INCONCLUSIVE';Reason='Held independent physical B reader missing/failed; '+($oldReaders.Error | Out-String)}}
            else{$assertions+=@{Name='C01RetainedBaseReader';Verdict=$(if($oldReaders[0].Result.Digest -ceq [StagedInvariant.Native]::Hash($ImageB) -and $oldReaders[0].Result.Length -eq $ImageB.Length){'PASS'}else{'FAIL'});Reason='Old reader sharing DELETE still returns whole B after replacement.'}}
        }
    }
    if(-not @($Sample.Captures | ForEach-Object {$_.Images} | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ceq $path}).Count){$assertions+=@{Name='C01RawFinalCoverage';Verdict='INCONCLUSIVE';Reason='No raw final/absence image retained.'}}
    if(-not @($Sample.Captures | ForEach-Object {$_.Images} | Where-Object Role -ceq 'Parent').Count){$assertions+=@{Name='C01RawListingCoverage';Verdict='INCONCLUSIVE';Reason='No raw parent-directory listing retained.'}}
    foreach($reader in $Sample.C01Readers){
        $good=if($null -ne $expected){$reader.Status -ceq 'OK' -and $reader.Result.Digest -ceq $digest -and $reader.Result.Length -eq $expected.Length}else{$reader.Status -ceq 'ERROR' -and $reader.NativeCode -eq 2}
        $verdict=if($good){'PASS'}elseif($reader.Status -ceq 'OK' -or $reader.NativeCode -eq 2){'FAIL'}else{'INCONCLUSIVE'}
        $assertions+=@{Name='C01IndependentReader';Verdict=$verdict;Reason=('Uncached='+$reader.Unbuffered+'; expected='+$(if($null -ne $expected){'whole image '+$digest}else{'Win32:2'})+'; native='+$reader.NativeCode+'; '+$reader.Reason);Sequence=$Sample.Sequence}
    }
    if(@($Sample.C01Readers).Count -ne 2 -or @($Sample.C01Readers | Where-Object Unbuffered).Count -ne 1){$assertions+=@{Name='C01ReaderCoverage';Verdict='INCONCLUSIVE';Reason='Exactly one fresh and one uncached receipt required.'}}
    return ,$assertions
}
function Test-CachedActorCalls($Calls,[string]$Kind,[long]$ReadyQpc,[long]$CloseQpc) {
    $expected=@(switch -CaseSensitive ($Kind){
        'mapped' {'writer-open';'create-mapping';'map-view';'close-source';'mapped-store';'flush-view';'unmap-view';'close-section'}
        'replacement' {'writer-open';'cached-write';'flush';'rename-ex';'close'}
        'external-rename' {'writer-open';'rename-ex';'close'}
        default {'writer-open';'cached-write';'flush';'close'}
    })
    $assertions=@();$bad=@($Calls | Where-Object {$want=if($Kind -ceq 'external-rename' -and $_.Class -ceq 'rename-ex'){5}else{0};$null -ne $_.NativeCode -and $_.NativeCode -ne $want})
    $complete=@($Calls).Count -eq $expected.Count -and -not @($Calls | Where-Object {$null -eq $_.NativeCode -or $null -eq $_.StartQpc -or $null -eq $_.EndQpc}).Count
    $ordered=($Calls.Class -join ',') -ceq ($expected -join ',');$previous=$ReadyQpc
    foreach($call in $Calls){if($call.StartQpc -lt $previous -or $call.EndQpc -lt $call.StartQpc){$ordered=$false};$previous=$call.EndQpc}
    $release=@($Calls | Where-Object {$_.Class -cin @('close','unmap-view','close-section')})
    if(@($release | Where-Object StartQpc -lt $CloseQpc).Count){$ordered=$false}
    $assertions+=@{Name='ExactNativeStatus';Verdict=$(if($bad.Count){'FAIL'}elseif(-not $complete){'INCONCLUSIVE'}elseif(-not $ordered){'FAIL'}else{'PASS'});
        Reason=('Required ordered calls='+($expected -join ',')+'; external rename alone requires Win32:5, all other calls Win32:0; missing receipt fields='+(-not $complete)+'; readiness/release QPC order='+$ordered);Calls=$Calls}
    return ,$assertions
}
function Get-CachedBlockTiming($Entry,[DateTimeOffset]$NowUtc,[long]$StartQpc,[long]$Frequency) {
    $m=$Entry.Manifest
    if($NowUtc.Offset -ne [TimeSpan]::Zero -or $Frequency -le 0 -or $StartQpc -lt 0){throw 'Invalid BLOCK timing anchor'}
    $expiry=[DateTimeOffset]::Parse([string]$m.JustificationExpiresAtUtc)
    $blocked=@($m.StateHistory | Where-Object State -eq 6)
    if($blocked.Count -ne 1 -or $expiry.Offset -ne [TimeSpan]::Zero){throw 'BLOCK expiry/history unavailable or ambiguous'}
    $began=[DateTimeOffset]::Parse([string]$blocked[0].OccurredAtUtc)
    $seconds=($expiry-$began).TotalSeconds;$remaining=($expiry-$NowUtc).TotalSeconds
    if($seconds -le 0 -or $remaining -le 0){throw 'No live product justification window at the open checkpoint'}
    return @{StartQpc=$StartQpc;AnchorUtc=$NowUtc.ToString('o');QpcFrequency=$Frequency;BlockedAtUtc=$began.ToString('o');ExpiresAtUtc=$expiry.ToString('o');WindowSeconds=$seconds;RemainingSeconds=$remaining;
        MarginSeconds=120;RuntimeGraceSeconds=15;RuntimeDeadlineQpc=($StartQpc+[long][Math]::Ceiling(($remaining+15)*$Frequency));
        DeadlineQpc=($StartQpc+[long][Math]::Ceiling(($remaining+120)*$Frequency));ActorDeadlineQpc=($StartQpc+[long][Math]::Ceiling(($remaining+180)*$Frequency))}
}
function Test-CachedBlockManifest($Entry,$Open,$Actor,[string]$Digest,[switch]$RequireClosed,[switch]$RequireDeleted) {
    $m=$Entry.Manifest;$o=$Open.Manifest;$reason='Exact actor/version remains Blocked; verified hand-back; no Approved/Publishing/Released; product expiry and cleanup prerequisites preserved.'
    $good=$Entry.StateName -ceq 'Blocked' -and $Entry.TransferId -ieq $Open.TransferId -and $Entry.SealedOnce -eq $true -and $Entry.Sha256Hex -ceq $Digest -and
        $m.Transfer.ProcessId -eq $Actor.Pid -and $m.Transfer.RequestorSid -ceq $Actor.Sid -and $m.Transfer.SessionId -eq $Actor.SessionId -and
        $m.Transfer.StagePath -ceq $o.Transfer.StagePath -and $m.Transfer.DestinationPath -ceq $o.Transfer.DestinationPath -and
        $m.DestinationGeneration -eq $o.DestinationGeneration -and $m.BlockedPolicyVersion -eq $o.BlockedPolicyVersion -and $m.BlockedPolicyVersion -gt 0 -and
        $m.HandbackState -eq 2 -and -not [string]::IsNullOrWhiteSpace($m.HandbackPath) -and $m.HandbackPath -ceq $o.HandbackPath -and
        $null -ne $m.HandbackLength -and $m.HandbackLength -eq $o.HandbackLength -and $m.Sha256Hex -ceq $Digest -and
        $m.JustificationWindowClosed -is [bool] -and $m.StageDeleted -is [bool] -and $m.StageCleanupStarted -is [bool] -and
        ($Entry.History -join ',') -ceq 'Allocated,Sealed,Inspecting,Blocked'
    try{
        $expiry=[DateTimeOffset]::Parse([string]$o.JustificationExpiresAtUtc);$currentExpiry=[DateTimeOffset]::Parse([string]$m.JustificationExpiresAtUtc)
        $updated=[DateTimeOffset]::Parse([string]$m.UpdatedAtUtc)
        $good=$good -and $expiry.Offset -eq [TimeSpan]::Zero -and $currentExpiry -eq $expiry -and $updated.Offset -eq [TimeSpan]::Zero
        if($RequireClosed){$good=$good -and $m.JustificationWindowClosed -eq $true -and $updated -ge $expiry}
        else{$good=$good -and $m.JustificationWindowClosed -eq $false -and $m.StageDeleted -eq $false -and $m.StageCleanupStarted -eq $false}
        if($RequireDeleted){$good=$good -and $RequireClosed -and $m.StageDeleted -eq $true -and $m.StageCleanupStarted -eq $false}
    }catch{$good=$false;$reason+=' Missing/invalid UTC expiry or receipt time.'}
    return @{Name=$(if($RequireDeleted){'C01BlockedAuditedStageCleanup'}elseif($RequireClosed){'C01JustificationWindowClosedAfterExpiry'}else{'C01BlockedWindowOpenStageNotDeleted'});Verdict=$(if($good){'PASS'}else{'FAIL'});Reason=$reason;Evidence=$Entry}
}
function Get-CachedBlockJournal($Trial,$Actor,[string]$TransferId) {
    # The before/after collectors still inventory the complete journal. During
    # expiry polling authenticate only the known manifest, so an unrelated
    # product temporary replacement cannot truncate this targeted observation.
    $id=[guid]::Parse($TransferId);if($id -eq [guid]::Empty){throw 'Invalid BLOCK transfer ID'}
    $root=Split-Path -Parent $policyPath;$journal=Join-Path $root 'staging-journal';$path=Join-Path $journal ($id.ToString('N')+'.json')
    $held=@();$obj=$null;$start=[Diagnostics.Stopwatch]::GetTimestamp()
    try{
        Initialize-ServiceEvidenceReader
        $ancestors=@();for($cursor=$root;-not [string]::IsNullOrWhiteSpace($cursor);$cursor=[IO.Path]::GetDirectoryName($cursor)){$ancestors=@($cursor)+$ancestors}
        foreach($ancestor in $ancestors){$held+=[SUProofFile]::Open($ancestor,$true,($ancestor -ceq $root))}
        $held+=[SUProofFile]::Open($journal,$true,$true,$false,$true)
        $obj=[SUProofFile]::Open($path,$false,$true,$true,$true);$bytes=[SUProofFile]::Read($obj,131072)
        $artifact=Join-Path $evidenceDirectory ('service-block-window-'+[guid]::NewGuid().ToString('N')+'-'+$id.ToString('N')+'.json')
        $stream=[IO.File]::Open($artifact,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        $record=[pscustomobject]@{Path=$path;Owner=$obj.Owner;Sddl=$obj.Sddl;Sha256=(Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash;Artifact=$artifact;Length=$bytes.Length;Bytes=$bytes}
        $parsed=ConvertFrom-ServiceJournalRecord $record;$m=$parsed.Entry
        if($m.Transfer.ProcessId -ne $Actor.Pid -or $m.Transfer.SessionId -ne $Actor.SessionId -or $m.Transfer.RequestorSid -cne $Actor.Sid){throw 'BLOCK exact manifest actor binding mismatch'}
        $end=[Diagnostics.Stopwatch]::GetTimestamp()
        $snapshot=[pscustomobject]@{Status='OK';Source='AuthenticatedExactTransferManifestOnly;NotWholeJournalInventory';StartQpc=$start;EndQpc=$end;BootId=(Get-BootId);QpcFrequency=[Diagnostics.Stopwatch]::Frequency;Journal=@($record)}
        $Trial.JournalSnapshots+=$snapshot
        return [pscustomobject]@{StateName=$parsed.StateName;TransferId=$m.Transfer.TransferId;SealedOnce=$m.SealedOnce;Sha256Hex=$m.Sha256Hex;History=@($m.StateHistory | ForEach-Object {@('Allocated','Sealed','Inspecting','Approved','Publishing','Released','Blocked','Retained','Unsealed')[[int]$_.State]});Manifest=$m;Artifact=$artifact;Record=$record;StartQpc=$start;EndQpc=$end}
    }finally{if($null -ne $obj){$obj.Dispose()};foreach($handle in $held){$handle.Dispose()}}
}
function Get-CachedJustificationServer {
    $svc=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction Stop
    if($svc.State -cne 'Running' -or $svc.ProcessId -eq 0 -or $svc.StartName -cne 'LocalSystem'){throw 'BLOCK justification SCM provenance mismatch'}
    $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$svc.ProcessId) -ErrorAction Stop
    $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
    if($owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18' -or $process.Name -cne 'SafeUpload.Agent.Service.exe'){throw 'BLOCK justification server OS provenance mismatch'}
    return @{Pid=$svc.ProcessId;OwnerSid=$owner.Sid;CommandLine=$process.CommandLine;Qpc=[Diagnostics.Stopwatch]::GetTimestamp()}
}
function Restart-CachedBlockAgent($Timing) {
    $before=Get-CachedJustificationServer;$stop=[Diagnostics.Stopwatch]::GetTimestamp()
    Stop-Service SafeUploadAgent -ErrorAction Stop
    $deadline=[Math]::Min($Timing.DeadlineQpc,($stop+[long](30*$Timing.QpcFrequency)))
    do{$svc=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'";if($svc.State -ceq 'Stopped' -and $svc.ProcessId -eq 0){break};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    if($svc.State -cne 'Stopped' -or $svc.ProcessId -ne 0){throw 'BLOCK expiry recovery service stop QPC timeout'}
    $stopped=[Diagnostics.Stopwatch]::GetTimestamp();$ready=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,'Global\SafeUploadServiceReady')
    try{
        [void]$ready.Reset();$start=[Diagnostics.Stopwatch]::GetTimestamp();Start-Service SafeUploadAgent -ErrorAction Stop
        $deadline=[Math]::Min($Timing.DeadlineQpc,($start+[long](45*$Timing.QpcFrequency)));$signaled=$false
        do{$signaled=$ready.WaitOne(100);if($signaled){break}}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        if(-not $signaled){throw 'BLOCK expiry recovery service Ready QPC timeout'}
        $after=Get-CachedJustificationServer
        if($after.Pid -eq $before.Pid){throw 'BLOCK expiry recovery did not replace the service process'}
        return @{Before=$before;After=$after;StopRequestedQpc=$stop;StoppedQpc=$stopped;StartRequestedQpc=$start;ReadyQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
    }finally{$ready.Dispose()}
}
function Test-CachedBlockNotificationWindow($Before,$After,$Fence,$Restart) {
    if($null -eq $Restart){return Test-NotificationWindow $Before $After $Fence $true}
    # Keep the single-instance validator unchanged. This adapter accepts exactly
    # the SCM-proven Stop->Start pair, with uninterrupted durable hash/sequence
    # coverage and the same heartbeat bound outside that stopped interval.
    try{
        if($Before.Status -cne 'OK' -or $After.Status -cne 'OK' -or $Before.BootId -cne $Fence.BootId -or $After.BootId -cne $Fence.BootId -or
            $Before.QpcFrequency -ne $Fence.QpcFrequency -or $After.QpcFrequency -ne $Fence.QpcFrequency -or
            $Restart.Before.OwnerSid -cne 'S-1-5-18' -or $Restart.After.OwnerSid -cne 'S-1-5-18' -or $Restart.Before.Pid -eq $Restart.After.Pid -or
            $Restart.StopRequestedQpc -gt $Restart.StoppedQpc -or $Restart.StoppedQpc -gt $Restart.StartRequestedQpc -or $Restart.StartRequestedQpc -gt $Restart.ReadyQpc){throw 'BLOCK restart notification identity/SCM fence unavailable'}
        $anchor=@($After.Entries | Where-Object {$_.Entry.Sequence -eq $Before.Head.Sequence -and $_.Hash -ceq $Before.Head.Sha256})
        $range=@($After.Entries | Where-Object {$_.Entry.Sequence -ge $Before.Head.Sequence})
        if($anchor.Count -ne 1 -or -not $range.Count -or $range[0].Entry.Qpc -gt $Fence.ReleasedQpc -or $range[-1].Entry.Qpc -lt $Fence.CompletedQpc){throw 'BLOCK restart notification head/window loss'}
        $previous=$null;$stops=0;$starts=0;$instance=$range[0].Entry.InstanceId
        foreach($item in $range){
            $e=$item.Entry
            if($e.BootId -cne $Fence.BootId -or $e.QpcFrequency -ne $Fence.QpcFrequency){throw 'BLOCK restart cross-boot/frequency'}
            $pair=$null -ne $previous -and $previous.Entry.Kind -ceq 'Stop' -and $e.Kind -ceq 'Start'
            if($null -ne $previous -and ($e.Sequence -ne $previous.Entry.Sequence+1 -or $e.PreviousSha256 -cne $previous.Hash -or $e.Qpc -lt $previous.Entry.Qpc -or
                (-not $pair -and $e.Qpc-$previous.Entry.Qpc -gt 5*$Fence.QpcFrequency))){throw 'BLOCK restart notification sequence/hash/QPC gap'}
            if($e.Kind -ceq 'Stop'){
                $stops++;if($stops -ne 1 -or $e.InstanceId -cne $instance -or $e.Qpc -lt $Restart.StopRequestedQpc -or $e.Qpc -gt $Restart.StoppedQpc){throw 'BLOCK restart unexpected Stop'}
            }elseif($e.Kind -ceq 'Start'){
                $starts++;if(-not $pair -or $starts -ne 1 -or $e.InstanceId -ceq $instance -or $e.Qpc -lt $Restart.StartRequestedQpc -or $e.Qpc -gt $Restart.ReadyQpc){throw 'BLOCK restart unexpected Start'};$instance=$e.InstanceId
            }elseif($e.InstanceId -cne $instance -or ($null -ne $previous -and $previous.Entry.Kind -ceq 'Stop')){throw 'BLOCK restart emission without live instance'}
            $previous=$item
        }
        if($stops -ne 1 -or $starts -ne 1 -or $range[-1].Entry.Sequence -ne $After.Head.Sequence -or $range[-1].Hash -cne $After.Head.Sha256){throw 'BLOCK restart boundary/final head missing'}
        return [pscustomobject]@{Complete=$true;Reason='Authenticated chained emissions across exactly one SCM-proven service restart.';Emissions=@($range | Where-Object {$_.Entry.Kind -cin @('Transfer','Event','Status') -and $_.Entry.Qpc -ge $Fence.ReleasedQpc -and $_.Entry.Qpc -le $Fence.CompletedQpc})}
    }catch{return [pscustomobject]@{Complete=$false;Reason=$_.Exception.Message;Emissions=@()}}
}
function Test-CachedBlockNoRelease($Proof,[string]$TransferId) {
    $released=@($Proof.Emissions | Where-Object {$_.Entry.TransferId -ieq $TransferId -and $_.Entry.Kind -cin @('Transfer','Event') -and $_.Entry.Phase -ceq 'Released'})
    return @{Name='C01AfterClosedWindowNoReleased';Verdict=$(if($released.Count){'FAIL'}elseif($Proof.Complete){'PASS'}else{'INCONCLUSIVE'});Reason=('Authenticated notification fence covers the complete BLOCK operation, expiry, cleanup and late submission; Released count='+$released.Count+'; '+$Proof.Reason)}
}
function Invoke-CachedBlockWindow($Trial,$Actor,$Context,$Baseline,$Terminal,[byte[]]$ImageA,[byte[]]$ImageB,[long]$Sequence) {
    $started=[Diagnostics.Stopwatch]::GetTimestamp()
    $evidence=@{RequiredAssertions=@();StartQpc=$started;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;Timing=$null;Open=$null;Closed=$null;Cleanup=$null;Final=$null;Restart=$null;Samples=@();Mode='RuntimePublisherLoop250ms';LateJustification=$null}
    $Trial.BlockWindowClosure=$evidence
    try{
        $handbackDeadline=$started+[long](10*[Diagnostics.Stopwatch]::Frequency)
        do{$open=Get-CachedBlockJournal $Trial $Actor $Terminal.TransferId;if($open.Manifest.HandbackState -eq 2 -or $open.Manifest.HandbackState -eq 3){break};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $handbackDeadline)
        $evidence.Open=$open
        $check=Test-CachedBlockManifest $open $open $Actor ([StagedInvariant.Native]::Hash($ImageA));$Trial.Assertions+=$check;$evidence.RequiredAssertions+=$check
        if($check.Verdict -cne 'PASS'){throw 'BLOCK open window/verified hand-back prerequisites not proved'}
        $timing=Get-CachedBlockTiming $open ([DateTimeOffset]::UtcNow) ([Diagnostics.Stopwatch]::GetTimestamp()) ([Diagnostics.Stopwatch]::Frequency);$evidence.Timing=$timing
        Write-DurableFile (Join-Path $actorDirectory 'window-config.clixml') ([Management.Automation.PSSerializer]::Serialize(@{Token=$state.WriterToken;DeadlineQpc=$timing.ActorDeadlineQpc},32)) -New
        Write-DurableFile (Join-Path $actorDirectory 'inspect-handback') $RunName -New
        $receipt=Wait-WriterIdentity (Join-Path $actorDirectory 'handback-open.clixml') 30
        if($receipt.Pid -ne $Actor.Pid -or $receipt.Sid -cne $Actor.Sid -or $receipt.BootId -cne $Actor.BootId -or $receipt.Token -cne $state.WriterToken){throw 'BLOCK open hand-back actor receipt mismatch'}
        $Trial.HandBack=Get-CachedHandBack $Actor $receipt.Files ([StagedInvariant.Native]::Hash($ImageA)) $ImageA.Length;$Trial.Assertions+=@($Trial.HandBack.Assertions);$evidence.RequiredAssertions+=@($Trial.HandBack.Assertions)
        $snapshot=Read-InvariantPrivateSnapshot -Context $Context -Path $open.Manifest.Transfer.StagePath
        $evidence.OpenStage=$snapshot
        $bytes=[IO.File]::ReadAllBytes($snapshot.LogicalArtifact.Path)
        $Trial.Assertions+=@{Name='C01BlockedOpenSnapshotByteExact';Verdict=$(if($snapshot.Length -eq $ImageA.Length -and [StagedInvariant.Native]::CountDifferences($ImageA,$bytes) -eq 0){'PASS'}else{'FAIL'});Reason='Private snapshot retained byte for byte while verified hand-back window is open.'}
        $confirmed=Get-CachedBlockJournal $Trial $Actor $Terminal.TransferId;$Trial.Assertions+=Test-CachedBlockManifest $confirmed $open $Actor ([StagedInvariant.Native]::Hash($ImageA));$evidence.OpenAfterReads=$confirmed
        do{
            if([Diagnostics.Stopwatch]::GetTimestamp() -ge $timing.DeadlineQpc){throw 'BLOCK expiry + 120-second margin QPC timeout'}
            $entry=Get-CachedBlockJournal $Trial $Actor $Terminal.TransferId
            $closed=$entry.Manifest.JustificationWindowClosed -eq $true
            $check=Test-CachedBlockManifest $entry $open $Actor ([StagedInvariant.Native]::Hash($ImageA)) -RequireClosed:$closed
            $Trial.Assertions+=$check;$evidence.RequiredAssertions+=$check;if($check.Verdict -cne 'PASS'){throw 'BLOCK window/version changed or premature closure/cleanup'}
            if($closed -and $null -eq $evidence.Closed){
                $evidence.Closed=$entry;$evidence.ClosureTimeLowerBoundUtc=$timing.ExpiresAtUtc;$evidence.ClosedJournalUpdatedAtUtc=$entry.Manifest.UpdatedAtUtc;$evidence.ClosureObservedUtc=[DateTimeOffset]::UtcNow.ToString('o')
                # Cleanup may replace UpdatedAtUtc before the next collector poll.
                # Never relabel a cleanup timestamp as an exact closure timestamp.
                $evidence.ClosureTimeSource=if(-not $entry.Manifest.StageCleanupStarted -and -not $entry.Manifest.StageDeleted){'JournalCloseJustificationWindowUpdatedAtUtc'}else{'NonForcedCloseExpiryLowerBound;JournalUpdatedAtUtcIsSubsequentCleanupReceipt'}
            }
            $Sequence++;$sample=Capture-CachedSample $Context $Baseline $(if($closed){'BlockWindowClosed'}else{'BlockWindowExpiryWait'}) $Sequence;$evidence.Samples+=$sample
            $rawChecks=Test-CachedSample $sample $Baseline $false $ImageA $ImageB;$Trial.Assertions+=@($rawChecks);$evidence.RequiredAssertions+=@($rawChecks)
            if($closed -and $entry.Manifest.StageDeleted -eq $true){$evidence.Cleanup=$entry;break}
            if($null -eq $evidence.Restart -and [Diagnostics.Stopwatch]::GetTimestamp() -ge $timing.RuntimeDeadlineQpc -and [DateTimeOffset]::UtcNow -ge [DateTimeOffset]::Parse($timing.ExpiresAtUtc)){
                $evidence.Restart=Restart-CachedBlockAgent $timing;$evidence.Mode='ExpiredServiceRecovery'
            }
            Start-Sleep -Milliseconds 250
        }while($true)
        if([Diagnostics.Stopwatch]::GetTimestamp() -ge $timing.DeadlineQpc){throw 'BLOCK cleanup receipt arrived after its QPC deadline'}
        $Trial.Assertions+=Test-CachedBlockManifest $evidence.Cleanup $open $Actor ([StagedInvariant.Native]::Hash($ImageA)) -RequireClosed -RequireDeleted
        $evidence.CleanupAudit=@{Source='ProtectedProductJournal/CompleteStageCleanupAsync';Artifact=$evidence.Cleanup.Artifact;Sha256=$evidence.Cleanup.Record.Sha256;UpdatedAtUtc=$evidence.Cleanup.Manifest.UpdatedAtUtc;SeparateSuccessEvent='NotEmittedByProduct'}
        $evidence.StageAbsence=Read-InvariantPrivateAbsence -Context $Context -Path $open.Manifest.Transfer.StagePath
        $submit=$false;$skip='Actor has no owning interactive WTS session; post-closure real-pipe submission skipped.'
        if($Actor.SessionId -gt 0){$session=Get-InvariantActorSession;$Actor | Add-Member NoteProperty OwnerSid $Trial.ActorProvenance.OwnerSid -Force;$binding=Test-InvariantInteractiveActor $session $Actor;$Trial.Assertions+=$binding;if($binding.Verdict -cne 'PASS'){throw 'BLOCK late justification interactive actor binding failed'};$submit=$true;$skip=$null}
        $server=Get-CachedJustificationServer;$evidence.JustificationServer=$server
        Write-DurableFile (Join-Path $actorDirectory 'window-complete.clixml') ([Management.Automation.PSSerializer]::Serialize(@{Token=$state.WriterToken;Submit=$submit;SkippedReason=$skip;TransferId=$Terminal.TransferId;ServerPid=$server.Pid},32)) -New
        $late=Wait-WriterIdentity (Join-Path $actorDirectory 'window-receipt.clixml') 30;$evidence.LateJustification=$late
        if($late.Pid -ne $Actor.Pid -or $late.Sid -cne $Actor.Sid -or $late.Token -cne $state.WriterToken -or $late.BootId -cne $Actor.BootId -or $late.StartQpc -lt $evidence.StageAbsence.EndQpc){throw 'BLOCK late justification receipt/fence mismatch'}
        if($submit){$Trial.Assertions+=@{Name='C01AfterClosureJustificationRejected';Verdict=$(if($late.NativeCode -eq 0 -and $late.Reply -ceq 'rejected' -and $late.ServerPid -eq $server.Pid -and $late.TransferId -ieq $Terminal.TransferId){'PASS'}else{'FAIL'});Reason='Owning interactive actor uses the B02 real pipe and authenticated product server; closed transfer must be rejected.';Evidence=$late}}
        $evidence.LateSubmissionStatus=if($submit){'Submitted'}else{'Skipped: '+$skip}
        $Trial.HandBackAfterClosure=Get-CachedHandBack $Actor $late.Files ([StagedInvariant.Native]::Hash($ImageA)) $ImageA.Length 'handback-after-window';$Trial.Assertions+=@($Trial.HandBackAfterClosure.Assertions);$evidence.RequiredAssertions+=@($Trial.HandBackAfterClosure.Assertions)
        $matching=@($Trial.HandBackAfterClosure.Files | Where-Object Path -ceq $open.Manifest.HandbackPath)
        $exact=$matching.Count -eq 1 -and [StagedInvariant.Native]::CountDifferences($ImageA,[IO.File]::ReadAllBytes($matching[0].Artifact)) -eq 0
        $Trial.Assertions+=@{Name='C01HandBackSurvivesCleanupByteExact';Verdict=$(if($exact){'PASS'}else{'FAIL'});Reason='Same journal-bound hand-back survives cleanup and late submission, readable by the owner and byte-exact A.'}
        $evidence.Final=Get-CachedBlockJournal $Trial $Actor $Terminal.TransferId;$finalCheck=Test-CachedBlockManifest $evidence.Final $open $Actor ([StagedInvariant.Native]::Hash($ImageA)) -RequireClosed -RequireDeleted;$Trial.Assertions+=$finalCheck
        $evidence.FinalStageAbsence=Read-InvariantPrivateAbsence -Context $Context -Path $open.Manifest.Transfer.StagePath
        $Sequence++;$sample=Capture-CachedSample $Context $Baseline 'AfterClosedWindowLateJustification' $Sequence;$evidence.Samples+=$sample;$rawChecks=Test-CachedSample $sample $Baseline $false $ImageA $ImageB;$Trial.Assertions+=@($rawChecks);$evidence.RequiredAssertions+=@($rawChecks)
        $good=-not @($evidence.RequiredAssertions | Where-Object Verdict -cne 'PASS').Count -and $finalCheck.Verdict -ceq 'PASS' -and $exact -and $evidence.StageAbsence.Absent -eq $true -and $evidence.FinalStageAbsence.Absent -eq $true -and
            -not @($Trial.Assertions | Where-Object {$_.Verdict -cne 'PASS' -and $_.Name -cin @('C01BlockedWindowOpenStageNotDeleted','C01BlockedOpenSnapshotByteExact','C01JustificationWindowClosedAfterExpiry','C01BlockedAuditedStageCleanup','C01AfterClosureJustificationRejected')}).Count
        $Trial.Assertions+=@{Name='C01HandBackWindowClosureAndRestart';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason=('Product expiry-derived QPC wait; mode='+$evidence.Mode+'; authenticated closed and StageDeleted journal receipts; stage absent twice; hand-back byte-exact; unchanged destination checked in raw/fresh/uncached samples; late submission='+$evidence.LateSubmissionStatus+'. Exact closure timestamp exists only if its intermediate manifest was captured.');Evidence=$evidence}
    }catch{$Trial.Assertions+=@{Name='C01HandBackWindowClosureAndRestart';Verdict='INCONCLUSIVE';Reason=$_.Exception.ToString();Evidence=$evidence};throw}
    finally{$evidence.EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();$evidence.DurationMs=1000.0*($evidence.EndQpc-$started)/$evidence.QpcFrequency;Save-State $evidence (Join-Path $evidenceDirectory 'block-window-closure.clixml')}
}
function Test-CachedHandBackAcl([string]$Sddl,[string]$Sid) {
    $security=[Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    $rules=@($security.DiscretionaryAcl);$trustees=@($rules | ForEach-Object {$_.SecurityIdentifier.Value})
    if(($security.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0 -or $rules.Count -ne 2 -or
        (@($trustees | Sort-Object) -join ';') -cne (@($Sid,'S-1-5-18' | Sort-Object) -join ';')){return $false}
    foreach($rule in $rules){if($rule.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or
        ([int]$rule.AceFlags -band [int][Security.AccessControl.AceFlags]::Inherited) -ne 0 -or ($rule.AccessMask -band 1) -eq 0){return $false}}
    return $true
}
function Get-CachedHandBack($Actor,$OwnerFiles,[string]$Digest,[int]$Length,[string]$ArtifactLabel='handback') {
    $assertions=@();$objects=@();$root=Join-Path $Actor.Profile 'SafeUpload\_bloqueados';$held=@();$new=@()
    try {
        Initialize-ServiceEvidenceReader
        $ancestors=@();for($cursor=$Actor.Profile; -not [string]::IsNullOrWhiteSpace($cursor);$cursor=[IO.Path]::GetDirectoryName($cursor)){$ancestors=@($cursor)+$ancestors}
        foreach($path in $ancestors){$held+= [SUProofFile]::Open($path,$true,$false)}
        foreach($path in @((Join-Path $Actor.Profile 'SafeUpload'),$root)){
            if(Test-Path -LiteralPath $path){$held+= [SUProofFile]::Open($path,$true,$false)}else{
                return [pscustomobject]@{Root=$root;Files=@();Assertions=@(@{Name='C01HandBack';Verdict=$(if($row.Outcome -ceq 'BLOCK'){'FAIL'}else{'PASS'});Reason=('Actor hand-back location absent: '+$path)});SecondUserAccess='NotChecked: harness owns one standard user only'}
            }
        }
        $before=@($Actor.HandBackBefore);$files=@(Get-ChildItem -LiteralPath $root -Force)
        foreach($file in $files){
            if($file.PSIsContainer){throw 'Unexpected hand-back subdirectory'}
            $obj=[SUProofFile]::Open($file.FullName,$false,$false);$held+=$obj
            $bytes=[SUProofFile]::Read($obj,20971520);$hash=[StagedInvariant.Native]::Hash($bytes)
            $artifact=Join-Path $evidenceDirectory ($ArtifactLabel+'-'+$objects.Count+'.bin')
            $stream=[IO.File]::Open($artifact,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
            $objects+=@{Path=$file.FullName;Owner=$obj.Owner;Sddl=$obj.Sddl;Length=$bytes.Length;Sha256=$hash;SingleLink=$true;NoReparse=$true;Artifact=$artifact}
            $prior=@($before | Where-Object Path -ceq $file.FullName)
            if($prior.Count){if($prior[0].Sha256 -cne $hash -or $prior[0].Length -ne $bytes.Length){$assertions+=@{Name='C01HandBackNoOverwrite';Verdict='FAIL';Reason=('Existing hand-back changed: '+$file.FullName)}};continue}
            $new+=$file.FullName
            $owner=@($OwnerFiles | Where-Object Path -ceq $file.FullName)
            $good=$bytes.Length -eq $Length -and $hash -ceq $Digest -and $obj.Owner -in @($Actor.Sid,'S-1-5-18') -and (Test-CachedHandBackAcl $obj.Sddl $Actor.Sid) -and
                $owner.Count -eq 1 -and $owner[0].Sha256 -ceq $Digest -and $owner[0].Length -eq $Length
            $assertions+=@{Name='C01HandBackH';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason=('Exact A/owner access/only owner+SYSTEM explicit ACL/single link/no reparse: '+$file.FullName)}
        }
        $good=if($row.Outcome -ceq 'BLOCK'){$new.Count -eq 1}else{$new.Count -eq 0}
        $assertions+=@{Name='C01HandBackCount';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason=('New actor hand-back files='+$new.Count+'; required='+$(if($row.Outcome -ceq 'BLOCK'){1}else{0}))}
    }catch{$assertions+=@{Name='C01HandBackH';Verdict=$(if($_.Exception.ToString() -like '*Reparse/type/link-count*' -or $_.Exception.Message -ceq 'Unexpected hand-back subdirectory'){'FAIL'}else{'INCONCLUSIVE'});Reason=$_.Exception.ToString()}}
    finally{foreach($obj in $held){$obj.Dispose()}}
    return [pscustomobject]@{Root=$root;Files=$objects;Assertions=$assertions;SecondUserAccess='NotChecked: harness owns one standard user only';SafeRelativeCreation='NotChecked: product creation receipt unavailable';WindowClosureAndRestart='Collected separately for C01/C03/C04 BLOCK from product expiry/cleanup receipts'}
}
function Save-CachedProductState {
    $backup=Join-Path $stateDirectory 'product-backup'
    New-Item -ItemType Directory -Path $backup | Out-Null
    $body="function Get-SecuritySddl { ${function:Get-SecuritySddl} }`n"
    $body+=@'
$root='C:\ProgramData\SafeUpload';$backup='__BACKUP__';$records=@();$roots=@('staging','staging-journal','notifications','queue.jsonl')
foreach($leaf in $roots){
    $path=Join-Path $root $leaf
    if(-not(Test-Path -LiteralPath $path)){continue}
    $items=@(Get-Item -LiteralPath $path -Force)
    if($items[0].PSIsContainer){$items+=@(Get-ChildItem -LiteralPath $path -Recurse -Force)}
    foreach($item in $items){
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Product backup contains reparse point; preserve baseline'}
        $rel=$item.FullName.Substring($root.Length+1);$copy=Join-Path $backup $rel
        if($item.PSIsContainer){New-Item -ItemType Directory -Path $copy -Force | Out-Null}else{[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($copy));Copy-Item -LiteralPath $item.FullName -Destination $copy}
        $records+=@{Relative=$rel;Directory=$item.PSIsContainer;Sddl=(Get-SecuritySddl $item.FullName $item.PSIsContainer);
            Hash=$(if(-not $item.PSIsContainer){(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash}else{$null})}
    }
}
$value=@{Roots=$roots;Records=$records}
'@
    return Invoke-SystemBody ($body.Replace('__BACKUP__',(ConvertTo-PowerShellLiteral $backup)))
}
function Restore-CachedProductState {
    if($null -eq $state.CachedProductBackup){return}
    if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'Cannot restore product files while the agent is running; preserve backup'}
    $body="function Get-SecuritySddl { ${function:Get-SecuritySddl} }`n"
    $body+=@'
$state=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText('__STATE__'))
$root='C:\ProgramData\SafeUpload';$backup='__BACKUP__'
# Restore in place: remove only items the run created, rewrite surviving files' bytes (keeping their
# security descriptor), recreate only removed items, and apply a saved ACL only where it differs.
# Delete-and-recopy changed DACL control flags on queue.jsonl (run c01a, 2026-10-06).
$known=@{};foreach($record in $state.CachedProductBackup.Records){$known[$record.Relative]=$record}
foreach($leaf in $state.CachedProductBackup.Roots){
    $path=Join-Path $root $leaf;if(-not(Test-Path -LiteralPath $path)){continue}
    $items=@(Get-Item -LiteralPath $path -Force);if($items[0].PSIsContainer){$items+=@(Get-ChildItem -LiteralPath $path -Recurse -Force)}
    foreach($item in @($items | Sort-Object { $_.FullName.Length } -Descending)){
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Product restoration found a reparse point: '+$item.FullName)}
        $rel=$item.FullName.Substring($root.Length+1)
        if(-not $known.ContainsKey($rel) -or $known[$rel].Directory -ne $item.PSIsContainer){Remove-Item -LiteralPath $item.FullName -Recurse -Force}
    }
}
foreach($record in @($state.CachedProductBackup.Records | Sort-Object { $_.Relative.Length })){
    $path=Join-Path $root $record.Relative;$existed=Test-Path -LiteralPath $path
    if($record.Directory){if(-not $existed){New-Item -ItemType Directory -Path $path | Out-Null}}
    else{
        $bytes=[IO.File]::ReadAllBytes((Join-Path $backup $record.Relative))
        if($existed){$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$stream.SetLength(0);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}}
        else{[IO.File]::WriteAllBytes($path,$bytes)}
        if((Get-FileHash -LiteralPath $path).Hash -cne $record.Hash){throw ('Product restoration hash mismatch: '+$path)}
    }
}
foreach($record in @($state.CachedProductBackup.Records | Sort-Object { $_.Relative.Length } -Descending)){
    $path=Join-Path $root $record.Relative
    if((Get-SecuritySddl $path $record.Directory) -ceq $record.Sddl){continue}
    $acl=if($record.Directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
    $acl.SetSecurityDescriptorSddlForm($record.Sddl);Set-Acl -LiteralPath $path -AclObject $acl
}
foreach($leaf in $state.CachedProductBackup.Roots){
    $path=Join-Path $root $leaf;$expected=@($state.CachedProductBackup.Records | Where-Object {$_.Relative -ceq $leaf -or $_.Relative.StartsWith($leaf+'\')})
    $actual=@();if(Test-Path -LiteralPath $path){$actual=@(Get-Item -LiteralPath $path -Force);if($actual[0].PSIsContainer){$actual+=@(Get-ChildItem -LiteralPath $path -Recurse -Force)}}
    if($actual.Count -ne $expected.Count){throw ('Product restoration inventory mismatch: '+$leaf)}
    foreach($record in $expected){
        $restored=Join-Path $root $record.Relative
        if((Get-SecuritySddl $restored $record.Directory) -cne $record.Sddl){throw ('Product restoration ACL mismatch: '+$restored)}
        if(-not $record.Directory -and (Get-FileHash -LiteralPath $restored).Hash -cne $record.Hash){throw ('Product restoration content mismatch: '+$restored)}
    }
}
$value='ProductStateRestored'
'@
    $null=Invoke-SystemBody ($body.Replace('__STATE__',(ConvertTo-PowerShellLiteral $statePath)).Replace('__BACKUP__',(ConvertTo-PowerShellLiteral (Join-Path $stateDirectory 'product-backup'))))
}
function Restore-CachedAgent {
    if($null -eq $state.CachedAgent -or $state.CachedAgentRestored){return}
    $service=Get-Service SafeUploadAgent -ErrorAction SilentlyContinue
    if($null -ne $service -and $service.Status -ne 'Stopped'){
        Stop-Service SafeUploadAgent -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
    }
    if($state.CachedAgent.ServiceCreated){
        & sc.exe delete SafeUploadAgent | Out-Host;$deleteExit=$LASTEXITCODE
        # 1060: already gone; 1072: already marked for deletion (removed when the last handle closes).
        if($deleteExit -notin @(0,1060,1072)){throw ('C01 service removal failed: sc.exe '+$deleteExit)}
    }
    else{Restore-StagedAgentService 'SafeUploadAgent' 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent' $state.CachedAgent.OriginalService}
    $state.CachedAgentRestored=$true;Save-State $state $statePath
}
function Invoke-CachedBaseSeed($Actor,[byte[]]$ImageB,[long]$ReadyQpc) {
    $seed=[ordered]@{ImageB=@{Length=$ImageB.Length;Sha256=[StagedInvariant.Native]::Hash($ImageB)};Assertions=@();Transitions=@();Before=$trial.ServiceBefore;After=$null;Receipt=$null;TransferId=$null}
    $trial.JournalSnapshots+= $seed.Before
    Write-DurableFile (Join-Path $actorDirectory 'seed-go') $RunName -New
    $receipt=Wait-WriterIdentity (Join-Path $actorDirectory 'seed-closed.clixml') 60;$seed.Receipt=$receipt
    if($receipt.Pid -ne $Actor.Pid -or $receipt.Sid -cne $Actor.Sid -or $receipt.BootId -cne $Actor.BootId -or $receipt.Token -cne $state.WriterToken){throw 'Approved B seed receipt identity/token mismatch'}
    $seed.Assertions+=Test-CachedActorCalls $receipt.Calls 'cached' $ReadyQpc 0
    if(@($seed.Assertions | Where-Object Verdict -cne 'PASS').Count){$trial.SeedBase=$seed;$trial.Assertions+=@($seed.Assertions);throw 'Approved B seed native evidence failed/incomplete; see SeedBase receipt'}
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long](120*[Diagnostics.Stopwatch]::Frequency));$number=0;$terminal=$null
    do{
        $poll=Get-CachedJournalObservation ('seed-'+$number) $Actor;$number++;$trial.JournalSnapshots+= $poll.Snapshot
        if($poll.Status -cne 'OK'){$seed.Assertions+=@{Name='SeedJournalPoll';Verdict='INCONCLUSIVE';Reason=($poll.Errors | Out-String)}}
        if($poll.Entries.Count -gt 1){throw 'Approved B seed has multiple new transfers'}
        foreach($entry in $poll.Entries){
            if($seed.Transitions.Count -and $seed.Transitions[0].TransferId -ine $entry.TransferId){throw 'Approved B seed transfer identity changed'}
            if(-not $seed.Transitions.Count -or $seed.Transitions[-1].State -ne $entry.State){$seed.Transitions+= $entry}
            if($entry.StateName -ceq 'Released'){$terminal=$entry}
            if($entry.StateName -cin @('Blocked','Retained')){$seed.Assertions+=@{Name='SeedApproveB';Verdict='FAIL';Reason=('Benign B unexpectedly '+$entry.StateName)};break}
        }
        if($null -ne $terminal -or @($seed.Assertions | Where-Object Verdict -ceq 'FAIL').Count){break};Start-Sleep -Milliseconds 50
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    $seed.Assertions+=Test-CachedJournalSequence $seed.Transitions 'APPROVE' $seed.ImageB.Sha256
    if($null -eq $terminal){$trial.SeedBase=$seed;$trial.Assertions+=@($seed.Assertions);throw 'Approved B seed did not reach Released within 120 seconds; no unapproved baseline fallback'}
    $seed.TransferId=$terminal.TransferId
    $fence=[pscustomobject]@{Complete=$true;BootId=$Actor.BootId;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;ReleasedQpc=$receipt.ReleasedQpc;CompletedQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
    # Released is durable before its asynchronous notification. Keep bounded,
    # authenticated snapshots until that exact transfer's emission arrives.
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long](10*[Diagnostics.Stopwatch]::Frequency));$number=0
    do{
        $seed.After=Get-ServiceSnapshot ('seed-after-'+$number);$number++;$trial.JournalSnapshots+= $seed.After
        $proof=Test-NotificationWindow $seed.Before.Notifications $seed.After.Notifications $fence $true
        if(@($proof.Emissions | Where-Object {$_.Entry.Kind -ceq 'Transfer' -and $_.Entry.TransferId -ieq $terminal.TransferId -and $_.Entry.Phase -ceq 'Released'}).Count){break};Start-Sleep -Milliseconds 100
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    $seed.NotificationProof=$proof;$seed.Assertions+=Test-CachedNotifications $proof $terminal.TransferId $Actor.SessionId 'APPROVE' $seed.ImageB.Sha256
    foreach($assertion in $seed.Assertions){$assertion.Name='SeedB'+$assertion.Name}
    return $seed
}
function Test-CachedNamespaceCommit($Entry,$Trial,[string]$Source,[string]$Target) {
    $parsed=ConvertFrom-ServiceJournalRecord $Entry.Record;$journal=$parsed.Entry;$tombstones=@()
    for($t=$journal.NamespaceTombstones;$null -ne $t;$t=$t.Previous){$tombstones+= $t}
    $sourceGeneration=$Trial.JournalTransitions[0].DestinationGeneration
    $baseGeneration=$Trial.SeedBase.Transitions[-1].DestinationGeneration
    $good=$journal.LastRenameCommitted -eq $true -and $journal.LastRenameTransactionId -gt 0 -and $journal.LastRenameDestination -ieq $Target -and
        $journal.Transfer.DestinationPath -ieq $Target -and $null -eq $journal.PendingRename -and $journal.DestinationGeneration -eq ($baseGeneration+1) -and
        @($tombstones | Where-Object {$_.DestinationPath -ieq $Source -and $_.Generation -eq ($sourceGeneration+1)}).Count -eq 1
    return [pscustomobject]@{Verified=$good;TransferId=$Entry.TransferId;SourceGeneration=$sourceGeneration;TargetGeneration=$Entry.DestinationGeneration;TransactionId=$journal.LastRenameTransactionId;Artifact=$Entry.Artifact;
        Assertion=@{Name='C04CommittedNamespace';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Same held transfer commits target and durable source tombstone with exact source/target reserved generations, positive transaction, no pending rename.';Manifest=$Entry.Artifact}}
}
function Add-CachedHeldJournal($Trial,$Actor,[string]$Tag,[bool]$Renamed=$false) {
    $poll=Get-CachedJournalObservation $Tag $Actor;$Trial.JournalSnapshots+= $poll.Snapshot
    if($cachedDenial){
        $Trial.Assertions+=@{Name='C05NoHeldTransfer';Verdict=$(if($poll.Entries.Count){'FAIL'}elseif($poll.Status -ceq 'OK'){'PASS'}else{'INCONCLUSIVE'});Reason=('External physical handle must allocate no private transfer; observed='+$poll.Entries.Count+'; '+($poll.Errors | Out-String))};return
    }
    if($poll.Status -cne 'OK' -or $poll.Entries.Count -ne 1){$Trial.Assertions+=@{Name='C01HeldJournal';Verdict='INCONCLUSIVE';Reason=('Expected one authenticated Allocated transfer while held; observed='+$poll.Entries.Count+'; '+($poll.Errors | Out-String))}}
    if($poll.Entries.Count -gt 1){$Trial.Assertions+=@{Name='C01HeldJournalIdentity';Verdict='FAIL';Reason='More than one owned transfer for a single held writer.'}}
    foreach($entry in $poll.Entries){
        if($Trial.JournalTransitions.Count -and $Trial.JournalTransitions[0].TransferId -ine $entry.TransferId){$Trial.Assertions+=@{Name='C01HeldJournalIdentity';Verdict='FAIL';Reason='Held writer transfer identity changed.'}}
        if(-not $Trial.JournalTransitions.Count -or $Trial.JournalTransitions[-1].State -ne $entry.State){$Trial.JournalTransitions+= $entry}
        $Trial.Assertions+=@{Name='C01SealAfterClose';Verdict=$(if($entry.State -eq 0 -and -not $entry.SealedOnce){'PASS'}else{'FAIL'});Reason=('Held upper references must remain Allocated/unsealed; observed '+$entry.StateName)}
        if($Renamed -and $cachedKind -ceq 'replacement'){
            $Trial.NamespaceCommit=Test-CachedNamespaceCommit $entry $Trial (Join-Path $protectedDirectory 'save.tmp.txt') (Join-Path $protectedDirectory 'cached.txt')
            $Trial.Assertions+= $Trial.NamespaceCommit.Assertion
        }
    }
}
function Capture-CachedExternalSample($Context,$Baseline,[string]$PhaseName,[long]$Sequence,[byte[]]$Image) {
    $path=Join-Path $externalDirectory 'source.txt'
    $sample=Capture-CachedSample $Context $Baseline $PhaseName $Sequence $path
    $trial.ExternalSource.Samples+= $sample
    $trial.Assertions+=Test-CachedSample $sample $Baseline $false $Image $Image $path
    return $sample
}
function Invoke-DedicatedLatencyObservation($Trial,$Actor,$Ready,$Context,[string]$Digest,[int]$Length) {
    $Trial.DedicatedLatency=@{Complete=$false;Held=$false;Rounds=@();Digest=$Digest;Length=$Length;QpcFrequency=[Diagnostics.Stopwatch]::Frequency}
    # Released manifests precede their notifications. A delayed emission must
    # not select an earlier transfer at a reused overwrite/replacement path.
    # Build the baseline exclusion once, then use constant-time ID lookups.
    $knownIds=@();$knownIdSet=@{};$previousQpc=$Ready.Qpc
    foreach($record in $Trial.ServiceBefore.Journal){
        $leaf=($record.Path -split '[\\/]')[-1]
        if($leaf -cmatch '^[0-9a-f]{32}\.json$'){$knownIdSet[([guid]::ParseExact($leaf.Substring(0,32),'N')).ToString('D')]=$true}
    }
    $notificationTail=@($Trial.ServiceBefore.Notifications.Entries)[-1].Entry
    if($Trial.ServiceBefore.Status -cne 'OK' -or $Trial.ServiceBefore.Notifications.LocationStatus -cne 'OK' -or
        $null -eq $notificationTail -or $notificationTail.BootId -cne $Context.BootId -or
        $notificationTail.QpcFrequency -ne [Diagnostics.Stopwatch]::Frequency){throw 'Dedicated authenticated before-run discovery anchor unavailable'}
    # Publish barriers by rename only after the durable write is closed. Name
    # existence must never let native calls overlap a barrier/snapshot Flush.
    $barrier=Join-Path $actorDirectory 'go';Write-DurableFile ($barrier+'.pending') $RunName -New
    $nativeNotBeforeQpc=[Diagnostics.Stopwatch]::GetTimestamp();$Trial.DedicatedLatency.InitialIoCompletedQpc=$nativeNotBeforeQpc
    [IO.File]::Move(($barrier+'.pending'),$barrier)
    for($round=0;$round -le 100;$round++){
        $prefix='round-'+$round.ToString('D3')+'-'
        $target=Join-Path $protectedDirectory $(if($cachedKind -cin @('cached','mapped')){'latency-'+$round.ToString('D3')+'.txt'}else{'cached.txt'})
        $openPath=if($cachedKind -ceq 'replacement'){Join-Path $protectedDirectory ('latency-'+$round.ToString('D3')+'.tmp.txt')}else{$target}
        $closed=Wait-WriterIdentity (Join-Path $actorDirectory ($prefix+'closed.clixml')) 60
        $roundRecord=@{Trial=$round;Receipt=$closed;PrivateReceipt=$null;Terminal=$null;PublicationVerifiedQpc=$null;ValidationStatus='Incomplete';
            NativeNotBeforeQpc=$nativeNotBeforeQpc;Snapshot=$null;SnapshotCompletedQpc=$null;IoCompletedQpc=$null;PublicReaders=@();CompletionProbe=$null}
        $Trial.DedicatedLatency.Rounds+= $roundRecord
        $Trial.Operations+= @($closed.Calls)
        if($closed.Pid -ne $Actor.Pid -or $closed.Sid -cne $Actor.Sid -or $closed.BootId -cne $Context.BootId -or $closed.Token -cne $state.WriterToken -or
            $closed.Trial -ne $round -or $closed.Held -ne $false -or $closed.Target -cne $target -or $closed.OpenPath -cne $openPath -or $closed.WriterKind -cne $cachedKind -or $closed.PrivateSha256 -cne $Digest){throw ('Dedicated latency round receipt mismatch: '+$round)}
        $calls=@($closed.Calls)
        if(($calls.Class -join ',') -cne ($row.LatencyClasses -join ',')){throw ('Dedicated native class sequence incomplete: '+$round)}
        foreach($call in $calls){
            if($call.NativeCode -ne 0 -or $call.Trial -ne $round -or $call.Cold -ne ($round -eq 0) -or
                $call.StartQpc -lt $previousQpc -or $call.StartQpc -lt $nativeNotBeforeQpc -or $call.EndQpc -lt $call.StartQpc -or $call.EndQpc -gt $closed.Qpc){throw ('Dedicated native status/QPC mismatch: '+$round)}
            $previousQpc=$call.EndQpc
        }
        $held=Wait-WriterIdentity (Join-Path $actorDirectory ($prefix+'held.clixml')) 1
        $roundRecord.PrivateReceipt=$held
        if($held.Pid -ne $Actor.Pid -or $held.Sid -cne $Actor.Sid -or $held.BootId -cne $Context.BootId -or $held.Token -cne $state.WriterToken -or $held.PrivateSha256 -cne $Digest){throw 'Dedicated private image provenance mismatch'}
        if($cachedKind -ceq 'mapped' -and (-not $held.SourceClosed -or -not $held.ViewLive -or -not $held.SectionLive)){throw 'Dedicated mapped lifetime contract incomplete'}
        $terminal=$null;$deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](120*[Diagnostics.Stopwatch]::Frequency)
        $probe=@{TransferId=$null;BootId=$Context.BootId;InstanceId=$notificationTail.InstanceId;MinimumQpc=$calls[0].StartQpc;
            QpcFrequency=[Diagnostics.Stopwatch]::Frequency;PollCount=0;TailBytesRead=0L;ManifestReads=0;DeadlineQpc=$deadline;Retries=(New-Object 'Collections.Generic.List[object]')}
        $roundRecord.CompletionProbe=$probe
        do {
            $probe.PollCount++
            $entry=Get-LatencyCompletionObservation $probe $Actor @($target,$openPath) $Digest $deadline $knownIdSet
            if($null -ne $entry -and $entry.StateName -ceq 'Released'){$terminal=$entry}
            if($null -ne $terminal){break};Start-Sleep -Milliseconds 50
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        if($null -eq $terminal){throw ('Dedicated Released completion QPC deadline expired: '+$round)}
        # Exactly one full retained authenticated journal snapshot per terminal
        # round. Discovery hints cannot qualify any sample or replace this proof.
        $poll=Get-CachedJournalObservation ($prefix+'terminal') $Actor @($target,$openPath) $knownIds -RetryTransientJournal
        $Trial.JournalSnapshots+= $poll.Snapshot;$roundRecord.Snapshot=$poll.Snapshot;$roundRecord.SnapshotCompletedQpc=$poll.Snapshot.EndQpc
        if($poll.Status -cne 'OK' -or $poll.Entries.Count -ne 1){throw ('Dedicated authenticated terminal journal incomplete/ambiguous: '+($poll.Errors | Out-String))}
        $record=$poll.Entries[0].Record
        $record | Add-Member NoteProperty StartQpc $poll.Snapshot.StartQpc -Force
        $record | Add-Member NoteProperty EndQpc $poll.Snapshot.EndQpc -Force
        $terminal=ConvertFrom-LatencyManifestRecord $record $Actor @($target) $probe.TransferId $Digest
        if($null -eq $terminal -or $terminal.StateName -cne 'Released'){throw 'Dedicated retained terminal manifest differs from completion detection'}
        $roundRecord.Terminal=$terminal
        foreach($raw in @($false,$true)){
            $reader=Invoke-LatencyJournalIo {[StagedInvariant.Native]::Fresh($target,$raw,$Context.Geometry.Alignment)} 'PublicImageRead' $target $probe.Retries -Enabled
            $roundRecord.PublicReaders+= [pscustomobject]@{Unbuffered=$raw;Result=$reader;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
            if($reader.Status -cne 'OK' -or $reader.Length -ne $Length -or $reader.Digest -cne $Digest){throw 'Dedicated exact public whole image differs'}
        }
        $roundRecord.PublicationVerifiedQpc=[Diagnostics.Stopwatch]::GetTimestamp();$roundRecord.ValidationStatus='Complete'
        $knownIds+= $terminal.TransferId
        $knownIdSet[([guid]$terminal.TransferId).ToString('D')]=$true
        # No native holder is live here. Release next repetition only after the
        # authenticated product transfer has reached exact Released image A.
        $barrier=Join-Path $actorDirectory ($prefix+'next');Write-DurableFile ($barrier+'.pending') $RunName -New
        $nativeNotBeforeQpc=[Diagnostics.Stopwatch]::GetTimestamp();$roundRecord.IoCompletedQpc=$nativeNotBeforeQpc;$previousQpc=$nativeNotBeforeQpc
        [IO.File]::Move(($barrier+'.pending'),$barrier)
    }
    $writer=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken 60
    if($writer.ExitCode -ne 0 -or $writer.Value.Held -ne $false -or $writer.Value.Actor.Pid -ne $Actor.Pid -or $writer.Value.Actor.Sid -cne $Actor.Sid -or
        $writer.Value.Actor.BootId -cne $Context.BootId -or $writer.Value.Calls.Count -ne $Trial.Operations.Count){throw 'Dedicated final actor completion mismatch'}
    $Trial.Latency=Get-LatencyVerdict $Trial.Operations $row.LatencyClasses $writer.Value.QpcFrequency
    foreach($class in $Trial.Latency){
        foreach($sample in $class.Samples){$sample | Add-Member NoteProperty Held $false}
        $warm=@($class.Samples | Where-Object {-not $_.Cold} | Sort-Object Ms)
        if($warm.Count -eq 100){$class.P95Ms=$warm[[int][Math]::Ceiling(.95*$warm.Count)-1].Ms;$class.Verdict=if($class.P95Ms -le 250 -and $class.MaxMs -le 1000){'PASS'}else{'FAIL'}}
    }
    $Trial.DedicatedLatency.Complete=$true
    return $writer
}

function Invoke-CachedObservation {
    $caseStartedQpc=[Diagnostics.Stopwatch]::GetTimestamp()
    $externalContext=$null;$externalBaseline=$null;$externalSequence=0;$imageB=$null;$terminal=$null;$context=$null;$baseline=$null;$disposal=$null;$samples=@();$predicateSamples=@();$checkpoints=@();$writer=$null;$agent=$null;$readyEvent=$null;$actor=$null;$agentStartLocal=$null
    $trial=[ordered]@{Errors=@();Approvals=@();Permits=@();Journal=@();JournalSnapshots=@();JournalTransitions=@();Notifications=@();Operations=@();Latency=@();Assertions=@();Verdict='INCONCLUSIVE';ForbiddenByteCount=$null}
    try {
        Assert-Hash $installedDriver $ExpectedFeatureSha256
        if((Get-ItemProperty "HKLM:\$registryService").Start -ne 0 -or (Get-BootId) -ceq $state.PrepareBootId){throw 'C01 requires a new boot with Start=0'}
        if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'Unexpected agent before C01 startup'}
        if($Mode -eq 'runtime-verifier'){& verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host;if($LASTEXITCODE -ne 0){throw 'Runtime Verifier arm failed'}}
        $trial.VerifierBefore=Get-VerifierEvidence 'before' -RequireMode
        $ready=Get-Readiness;$trial.Readiness=$ready
        $agentStartLocal=[DateTime]::Now.AddSeconds(-1)
        $readyEvent=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,'Global\SafeUploadServiceReady');[void]$readyEvent.Reset()
        # Debug-level service events (publisher steps) reach the event log for diagnosis (run c01i hung in Publishing).
        $agent=Start-StagedTestAgent $serviceDirectory (Join-Path $evidenceDirectory 'agent') -Arguments '--Logging:EventLog:LogLevel:Default=Debug'
        # Persist recovery receipt before waiting for policy readiness.
        $state.CachedAgent=@{ServiceCreated=$agent.ServiceCreated;OriginalService=$agent.OriginalService};Save-State $state $statePath
        if(-not $readyEvent.WaitOne([TimeSpan]::FromSeconds(45))){
            # The service logs each coverage transition with its reason; keep them as the diagnosis.
            try{Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$agentStartLocal} -ErrorAction Stop | Where-Object ProviderName -match 'SafeUpload' |
                ForEach-Object {$_.TimeCreated.ToString('o')+' '+$_.ProviderName+' '+$_.LevelDisplayName+' '+($_.Message -replace '\s+',' ')} |
                Set-Content -LiteralPath (Join-Path $evidenceDirectory 'agent-events.txt') -Encoding UTF8}catch{}
            # The port takes one connection: stop the agent, then read the driver's own view of the
            # coverage receipt and writer registry. Restore-CachedAgent accepts a stopped service.
            try{Stop-Service SafeUploadAgent -ErrorAction Stop;(Get-Service SafeUploadAgent).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))}catch{}
            foreach($query in '--admission-coverage','--activating-status','--registry-status'){
                try{[void](Invoke-CapturedProcess $inspectorPath $query (Join-Path $evidenceDirectory ('ready-timeout'+$query)))}catch{}
            }
            throw 'C01 agent policy/coverage Ready signal timed out after 45 seconds'
        }
        $readback=Get-BootPolicyReadback
        if($ready.VolumeGuid -cne $state.VolumeGuid -or $readback.RecordBase64 -cne $state.ExpectedBootRecord -or -not $readback.AclValid -or $readback.PendingPresent){throw 'C01 dedicated fixed-NTFS policy/volume readback mismatch'}
        $trial.Policy=@{SeedRecord=$readback;LiveFlags=$null;TaintDisabledConfirmed=$false}
        Write-DurableFile (Join-Path $evidenceDirectory 'readiness.json') ($ready | ConvertTo-Json -Depth 32) -New
        $trial.ServiceBefore=Get-ServiceSnapshot 'before' -RetryTransientJournal:([bool]$state.DedicatedUnheldLatency);$trial.LastAccessBefore=Get-LastAccessEvidence
        $context=Open-InvariantObserver $ready.VolumeGuid $protectedDirectory (Join-Path $evidenceDirectory 'raw') $CaseId
        if($context.Status -cne 'OK'){throw ($context.Error | Out-String)}
        Start-ScheduledTask -TaskName $writerTask
        $actor=Wait-WriterIdentity (Join-Path $actorDirectory 'identity.clixml');$trial.Actor=$actor
        if($actor.Sid -cne $state.ActorSid -or $actor.Elevated -or $actor.IsAdministrator -or $actor.Pid -eq $PID -or $actor.BootId -cne $context.BootId){throw 'Cached actor token/boot provenance invalid'}
        $trial.ActorProvenance=Assert-ActorProcess $actor
        $profiles=@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $actor.Sid)
        if($profiles.Count -ne 1 -or $profiles[0].LocalPath -ine $actor.Profile){throw 'Actor profile does not match OS SID profile binding'}
        if(@($trial.ServiceBefore.Journal | Where-Object {try{(ConvertFrom-ServiceJournalRecord $_).DestinationPaths -icontains (Join-Path $protectedDirectory 'cached.txt')}catch{$false}}).Count){throw 'Final already claimed in pre-case service journal'}
        if($cachedExisting){
            $imageB=[Convert]::FromBase64String($state.CachedBaseBase64)
            $trial.SeedBase=Invoke-CachedBaseSeed $actor $imageB $ready.Qpc;$trial.Assertions+=@($trial.SeedBase.Assertions)
            if(@($trial.SeedBase.Assertions | Where-Object Verdict -cne 'PASS').Count){throw 'Approved B seed evidence incomplete/failed; no main mutation attempted'}
            $trial.SetupCacheFlush=Flush-InvariantSetupVolume
            # Exclude the proven Released B transfer from the A window, never a dirty baseline.
            $trial.ServiceBefore=Get-ServiceSnapshot 'before-A' -RetryTransientJournal:([bool]$state.DedicatedUnheldLatency);$trial.LastAccessBefore=Get-LastAccessEvidence
        }
        $expected=@{'marker.bin'=[Convert]::FromBase64String($state.BaselineBase64);'cached.txt'=$imageB};$names=@('marker.bin','cached.txt')
        if($cachedKind -ceq 'replacement'){$expected['save.tmp.txt']=$null;$names+= 'save.tmp.txt'}
        if($CaseId -ceq 'R01'){$expected['offline-new.txt']=$null;$names+= 'offline-new.txt'}
        # LastAccess window starts BEFORE the raw capture it covers (c01n).
        $captureStartedFileTime=[DateTime]::UtcNow.ToFileTimeUtc()
        $baseline=Capture-InvariantBaseline $context $names $expected
        $baseline | Add-Member NoteProperty CaptureStartedFileTime $captureStartedFileTime
        if($baseline.Status -cne 'OK'){throw ($baseline.Error | Out-String)}
        $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID);$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
        if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $context.ObserverSid){throw 'Observer OS SID mismatch'}
        $trial.Platform=@{Build=$context.Build;BootId=$context.BootId;ObserverPid=$context.ObserverPid;ObserverSid=$context.ObserverSid;
            ObserverProcess=@{Pid=$process.ProcessId;OwnerSid=$owner.Sid;SessionId=$process.SessionId;CommandLine=$process.CommandLine}}
        $trial.Geometry=$context.Geometry;$trial.DecoderVersion=$context.DecoderVersion;$trial.ObserverModuleSha256=$context.ModuleSha256
        $imageA=[Convert]::FromBase64String($state.CachedImageBase64);$digest=[StagedInvariant.Native]::Hash($imageA);$trial.ImageA=@{Sha256=$digest;Length=$imageA.Length;Fixture=$state.CachedFixture}
        if($DedicatedUnheldLatency){
            $trial.Assertions+=@{Name='DedicatedLatencyOnly';Verdict='INCONCLUSIVE';Reason='Separate unheld native latency experiment; no functional protection qualification.'}
            $writer=Invoke-DedicatedLatencyObservation $trial $actor $ready $context $digest $imageA.Length
            $trial.LastAccessAfter=Get-LastAccessEvidence
            $trial.ServiceAfter=Get-ServiceSnapshot 'latency-after' -RetryTransientJournal;$trial.Journal=$trial.ServiceAfter.Journal
            $trial.VerifierAfter=Get-VerifierEvidence 'after' -RequireMode
            return
        }
        if($cachedDenial){
            $trial.ExternalSource=@{Baseline=$null;Samples=@();Disposal=$null}
            $externalContext=Open-InvariantObserver $ready.VolumeGuid $externalDirectory (Join-Path $evidenceDirectory 'raw-external') $CaseId
            if($externalContext.Status -cne 'OK'){throw ('External source observer: '+($externalContext.Error | Out-String))}
            $sourceCaptureStart=[DateTime]::UtcNow.ToFileTimeUtc()
            $externalBaseline=Capture-InvariantBaseline $externalContext @('source.txt') @{'source.txt'=$imageA}
            $externalBaseline | Add-Member NoteProperty CaptureStartedFileTime $sourceCaptureStart
            $trial.ExternalSource.Baseline=$externalBaseline
            if($externalBaseline.Status -cne 'OK'){throw ('External source baseline: '+($externalBaseline.Error | Out-String))}
        }
        $sequence=1;$sample=Capture-CachedSample $context $baseline 'BeforeOperation' $sequence;$samples+= $sample;$predicateSamples+= $sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence
        $trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA $imageB
        if($cachedDenial){$externalSequence++;$null=Capture-CachedExternalSample $externalContext $externalBaseline 'BeforeOperation' $externalSequence $imageA}
        Write-DurableFile (Join-Path $actorDirectory 'go') $RunName -New
        $heldWaitSeconds=60
        if($MappedStackDiagnosticSeconds -ne 0){
            $heldWaitSeconds=$MappedStackDiagnosticSeconds
            $trial.Assertions+=@{Name='C02StackDiagnosticOnly';Verdict='INCONCLUSIVE';Reason='Diagnostic actor hold extension is not functional or latency qualification.'}
            Write-DurableFile (Join-Path $evidenceDirectory 'stack-diagnostic-ready.clixml') ([Management.Automation.PSSerializer]::Serialize(@{
                RunName=$RunName;CaseId=$CaseId;Mode=$Mode;Actor=$actor;StartedQpc=[Diagnostics.Stopwatch]::GetTimestamp();
                WaitSeconds=$heldWaitSeconds;SuiteSha256=$ExpectedSuiteSha256;DiagnosticOnly=$true},32)) -New
        }
        $held=Wait-WriterIdentity (Join-Path $actorDirectory 'held.clixml') $heldWaitSeconds
        if($held.Pid -ne $actor.Pid -or $held.Sid -cne $actor.Sid -or $held.Token -cne $state.WriterToken -or $held.BootId -cne $context.BootId){throw 'Held receipt identity/token mismatch'}
        $trial.HeldReceipt=$held;$trial.Operations=@($held.Calls)
        if($CaseId -ceq 'R01'){
            $initialDigest=[StagedInvariant.Native]::Hash([Convert]::FromBase64String($state.R01InitialBase64))
            $trial.Assertions+=@{Name='R01InitialPrivateRead';Verdict=$(if($held.PrivateSha256 -ceq $initialDigest){'PASS'}else{'FAIL'});Reason='Held private handle contains the distinct initial whole image before stop.'}
        }else{
        $trial.Assertions+=@{Name='C01PrivateRead';Verdict=$(if($null -eq $held.PrivateSha256){'INCONCLUSIVE'}elseif($held.PrivateSha256 -ceq $digest){'PASS'}else{'FAIL'});Reason='Whole private handle/view (or external physical source) read must equal A after flush.'}
        }
        if($cachedKind -ceq 'mapped'){
            $trial.Assertions+=@{Name='C02SourceClosedViewLive';Verdict=$(if($null -eq $held.SourceClosed -or $null -eq $held.ViewLive -or $null -eq $held.SectionLive){'INCONCLUSIVE'}elseif($held.SourceClosed -and $held.ViewLive -and $held.SectionLive){'PASS'}else{'FAIL'});Reason='Source file handle is closed; PAGE_READWRITE section and writable view remain live during all held samples.'}
        }
        for($n=0;$n -lt 3;$n++){
            Add-CachedHeldJournal $trial $actor ('held-'+$n)
            $heldPhase=if($cachedKind -ceq 'mapped'){'SourceClosedViewHeld'}elseif($cachedKind -cin @('replacement','external-rename')){'BeforeRenameHandleHeld'}else{'FlushedHandleHeld'}
            $sequence++;$sample=Capture-CachedSample $context $baseline $heldPhase $sequence;$samples+= $sample;$predicateSamples+= $sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence
            $trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA $imageB
            if($cachedDenial){$externalSequence++;$null=Capture-CachedExternalSample $externalContext $externalBaseline $heldPhase $externalSequence $imageA}
            Start-Sleep -Milliseconds 10
        }
        if($CaseId -ceq 'R01'){
            $trial.R01Restart=Invoke-R01AllocatedRestart $trial $actor $context $baseline $imageA $sequence
            foreach($sample in $trial.R01Restart.Samples){
                $sequence=$sample.Sequence;$samples+=$sample;$predicateSamples+=$sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence
                $trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA
            }
        }
        if($CaseId -ceq 'B01'){
            $sentinel=Invoke-B01HeldAttack $trial $actor $context
            $externalContext=$sentinel.Context;$externalBaseline=$sentinel.Baseline
        }
        if($cachedKind -cin @('replacement','external-rename')){
            $trial.RenameBarrierQpc=[Diagnostics.Stopwatch]::GetTimestamp();Write-DurableFile (Join-Path $actorDirectory 'rename') $RunName -New
            $renamed=Wait-WriterIdentity (Join-Path $actorDirectory 'renamed.clixml') 60
            if($renamed.Pid -ne $actor.Pid -or $renamed.Sid -cne $actor.Sid -or $renamed.BootId -cne $actor.BootId -or $renamed.Token -cne $state.WriterToken){throw 'Rename receipt identity/token mismatch'}
            $trial.RenameReceipt=$renamed;$trial.Operations=@($renamed.Calls);$renameCalls=@($renamed.Calls | Where-Object Class -ceq 'rename-ex')
            $wantedCode=if($cachedDenial){5}else{0}
            $verdict=if($renameCalls.Count -ne 1 -or $null -eq $renameCalls[0].NativeCode){'INCONCLUSIVE'}elseif($renameCalls[0].NativeCode -ne $wantedCode -or $renameCalls[0].StartQpc -lt $trial.RenameBarrierQpc){'FAIL'}else{'PASS'}
            $trial.Assertions+=@{Name='NativeRenameStatus';Verdict=$verdict;Reason=('FileRenameInfoEx REPLACE_IF_EXISTS|POSIX via old held source: expected Win32:'+ $wantedCode+'; receipt count='+$renameCalls.Count)}
            $trial.Assertions+=@{Name='C01PrivateReadAfterRename';Verdict=$(if($null -eq $renamed.PrivateSha256){'INCONCLUSIVE'}elseif($renamed.PrivateSha256 -ceq $digest){'PASS'}else{'FAIL'});Reason='Held source image remains exact A after the native rename attempt.'}
            for($n=0;$n -lt 3;$n++){
                Add-CachedHeldJournal $trial $actor ('renamed-held-'+$n) $true
                $sequence++;$sample=Capture-CachedSample $context $baseline 'AfterRenameHandleHeld' $sequence;$samples+= $sample;$predicateSamples+= $sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence
                $trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA $imageB
                if($cachedDenial){$externalSequence++;$null=Capture-CachedExternalSample $externalContext $externalBaseline 'AfterDeniedRename' $externalSequence $imageA}
            }
        }
        $trial.CloseBarrierQpc=[Diagnostics.Stopwatch]::GetTimestamp();Write-DurableFile (Join-Path $actorDirectory 'close') $RunName -New
        $closed=Wait-WriterIdentity (Join-Path $actorDirectory 'closed.clixml') 60
        if($closed.Pid -ne $actor.Pid -or $closed.Token -cne $state.WriterToken -or $closed.Sid -cne $actor.Sid -or $closed.BootId -cne $context.BootId){throw 'C01 close receipt identity/token mismatch'}
        $trial.ClosedReceipt=$closed;$trial.Operations=@($closed.Calls)
        if($CaseId -ceq 'R01'){$trial.Assertions+=Test-R01ActorCalls $trial.Operations $ready.Qpc $trial.CloseBarrierQpc}
        else{$trial.Assertions+=Test-CachedActorCalls $trial.Operations $cachedKind $ready.Qpc $trial.CloseBarrierQpc}
        if($cachedDenial){
            $poll=Get-CachedJournalObservation 'denied-after-close' $actor;$trial.JournalSnapshots+= $poll.Snapshot
            $trial.Assertions+=@{Name='C05NoTransfer';Verdict=$(if($poll.Entries.Count){'FAIL'}elseif($poll.Status -ceq 'OK'){'PASS'}else{'INCONCLUSIVE'});Reason=('Denied external rename allocates no transfer; '+($poll.Errors | Out-String))}
        }else{
        $wanted=if($row.Outcome -ceq 'APPROVE'){'Released'}else{'Blocked'};$deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((120)*[Diagnostics.Stopwatch]::Frequency));$pollNumber=0;$terminal=$null
        do {
            $poll=Get-CachedJournalObservation ('outcome-'+$pollNumber) $actor;$trial.JournalSnapshots+= $poll.Snapshot;$pollNumber++
            if($poll.Status -cne 'OK'){$trial.Assertions+=@{Name='C01JournalPoll';Verdict='INCONCLUSIVE';Reason=($poll.Errors | Out-String)}}
            if($poll.Entries.Count -gt 1){throw 'C01 destination has multiple transfer manifests'}
            foreach($entry in $poll.Entries){
                if($trial.JournalTransitions.Count -and $trial.JournalTransitions[0].TransferId -ine $entry.TransferId){throw 'C01 transfer identity changed while waiting'}
                if(-not $trial.JournalTransitions.Count -or $trial.JournalTransitions[-1].State -ne $entry.State){$trial.JournalTransitions+= $entry}
                if($entry.StateName -ceq $wanted){$terminal=$entry}
                if($CaseId -ceq 'B01' -and $null -ne $terminal){
                    $manifest=(ConvertFrom-ServiceJournalRecord $entry.Record).Entry
                    if($manifest.HandbackState -ne 3){$terminal=$null}
                }
            }
            $sequence++;$sample=Capture-CachedSample $context $baseline 'OutcomeWait' $sequence;$samples+= $sample
            if($CaseId -ceq 'R01'){$trial.Assertions+=Test-R01OutcomeSample $sample $baseline $imageA}
            if($row.Outcome -ceq 'BLOCK'){$predicateSamples+= $sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence;$trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA $imageB}
            if($CaseId -ceq 'B01'){Add-B01SentinelSample $trial $externalContext $externalBaseline 'HandBackWait'}
            if($null -ne $terminal){break};Start-Sleep -Milliseconds 10
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        if($CaseId -ceq 'R01'){$trial.Assertions+=Test-R01JournalSequence $trial.JournalTransitions $digest}
        else{$trial.Assertions+=Test-CachedJournalSequence $trial.JournalTransitions $row.Outcome $digest $trial.NamespaceCommit}
        if($null -eq $terminal){throw ('C01 journal timeout after 120 seconds: expected '+$wanted+'; last observed='+($trial.JournalTransitions.StateName -join ' -> '))}
        $trial.TransferId=$terminal.TransferId
        # Allow asynchronous post-Blocked hand-back work a bounded grace period.
        # No service copy is fabricated by the harness.
        if($row.Outcome -ceq 'BLOCK'){
            $blockedEntry=ConvertFrom-ServiceJournalRecord $terminal.Record
            if($CaseId -ceq 'B01'){$trial.Assertions+=Test-B01FailedHandBack $blockedEntry.Entry $digest $actor.Sid}
            try{
                $stage=Read-InvariantPrivateSnapshot -Context $context -Path $blockedEntry.Entry.Transfer.StagePath
                $trial.BlockedStageSnapshot=$stage
                $trial.Assertions+=@{Name='C01BlockedStageRetained';Verdict=$(if($stage.Length -eq $imageA.Length -and $stage.Sha256 -ceq $digest){'PASS'}else{'FAIL'});Reason=('Bounded sealed private snapshot remains present and equals exact A; MetadataSource='+$stage.MetadataSource+'; full repeated bytes and exact file-reference/sequence/name/parent stability checked. Cached metadata is not claimed as on-disk proof; no stage-file open bypasses the product gate.');Evidence=$stage}
            }catch{$trial.Assertions+=@{Name='C01BlockedStageRetained';Verdict='INCONCLUSIVE';Reason=$_.Exception.ToString()}}
            if($CaseId -cne 'B01'){
            $handBackDeadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((10)*[Diagnostics.Stopwatch]::Frequency));$handBackRoot=Join-Path $actor.Profile 'SafeUpload\_bloqueados'
            do{if(Test-Path -LiteralPath $handBackRoot){if(@(Get-ChildItem -LiteralPath $handBackRoot -File -Force).Count){break}};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $handBackDeadline)
            }
        }
        }
        if($CaseId -cin @('C01-block-absent','C03-block-existing','C04-block')){
            try{Invoke-CachedBlockWindow $trial $actor $context $baseline $terminal $imageA $imageB $sequence}
            finally{
                foreach($windowSample in $trial.BlockWindowClosure.Samples){$samples+=$windowSample;$predicateSamples+=$windowSample;$checkpoints+=Get-ExpectedCheckpoint $baseline $windowSample.Phase $windowSample.Sequence}
                $sequence+=$trial.BlockWindowClosure.Samples.Count
            }
        }else{Write-DurableFile (Join-Path $actorDirectory 'inspect-handback') $RunName -New}
        $writer=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken 60
        if($CaseId -ceq 'B01'){
            Add-B01SentinelSample $trial $externalContext $externalBaseline 'FinalQuiescence'
            $trial.HandBack=@{Root=$trial.B01Attack.Root;Files=@();Failure='handback_failed';Sentinel=$trial.ExternalSource}
        }elseif($null -eq $trial.HandBack){
        $trial.HandBack=Get-CachedHandBack $actor $writer.Value.HandBackAfter $digest $imageA.Length;$trial.Assertions+=@($trial.HandBack.Assertions)
        }
        if($row.Outcome -ceq 'BLOCK' -and $CaseId -cne 'B01'){
            if($CaseId -cin @('C01-block-absent','C03-block-existing','C04-block')){
                $trial.Assertions+=Invoke-CachedSecondUserDenial $actor $trial.HandBack $digest
            }else{
            $trial.Assertions+=@{Name='C01HandBackSecondUserAccess';Verdict='INCONCLUSIVE';Reason='Contract H second standard-user denial is untested; harness owns one standard user only.'}
            }
            $trial.Assertions+=@{Name='C01HandBackSafeRelativeCreation';Verdict='INCONCLUSIVE';Reason='Contract H safe relative-to-verified-handle creation receipt unavailable; final no-reparse/single-link checks alone do not attest creation.'}
            if($CaseId -cnotin @('C01-block-absent','C03-block-existing','C04-block')){$trial.Assertions+=@{Name='C01HandBackWindowClosureAndRestart';Verdict='INCONCLUSIVE';Reason='Expiry closure adapter currently covers C01/C03/C04 BLOCK only.'}}
        }
        $trial.FinalCacheFlush=Flush-InvariantFinalVolume
        $sequence++;$sample=Capture-CachedSample $context $baseline 'FinalQuiescence' $sequence;$samples+= $sample
        $trial.Assertions+=Test-CachedSample $sample $baseline ($row.Outcome -ceq 'APPROVE') $imageA $imageB
        if($row.Outcome -ceq 'BLOCK' -or $cachedDenial){$predicateSamples+= $sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence}
        if($cachedDenial){$externalSequence++;$null=Capture-CachedExternalSample $externalContext $externalBaseline 'FinalQuiescence' $externalSequence $imageA}
        $trial.Latency=Get-LatencyVerdict $trial.Operations $row.LatencyClasses $writer.Value.QpcFrequency
        $trial.Repetitions=$row.Repetitions;$trial.OperationClassTimeline=$row.StatusClasses
        if($CaseId -cnotin @('R01','B01')){$trial.Assertions+=@{Name='C01UnheldLatency';Verdict='INCONCLUSIVE';Reason='One coordinated functional write only; 100 unheld latency repetitions deferred.'}}
        $trial.LastAccessAfter=Get-LastAccessEvidence
        $fence=[pscustomobject]@{Complete=$true;BootId=$context.BootId;QpcFrequency=$writer.Value.QpcFrequency;ReleasedQpc=$writer.Value.ReleasedQpc;CompletedQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
        $trial.ServiceAfter=Get-ServiceSnapshot 'after'
        $delta=Test-ServiceJournalDelta $trial.ServiceBefore $trial.ServiceAfter $true
        if($CaseId -ceq 'R01'){
            $fence.ReleasedQpc=$trial.R01PostRestartBefore.EndQpc
            $proof=Test-NotificationWindow $trial.R01PostRestartBefore.Notifications $trial.ServiceAfter.Notifications $fence $true
            $trial.Assertions+=Test-R01ReleasedOnce $terminal $proof $actor.SessionId $digest
        }else{        $proof=Test-CachedBlockNotificationWindow $trial.ServiceBefore.Notifications $trial.ServiceAfter.Notifications $fence $trial.BlockWindowClosure.Restart
        if($null -ne $trial.BlockWindowClosure){
            $noRelease=Test-CachedBlockNoRelease $proof $terminal.TransferId;$trial.Assertions+=$noRelease
            $trial.BlockWindowClosure.NotificationProof=$proof;$trial.BlockWindowClosure.RequiredAssertions+=$noRelease
            $umbrella=@($trial.Assertions | Where-Object Name -ceq 'C01HandBackWindowClosureAndRestart')
            if($umbrella.Count -ne 1){throw 'BLOCK closure umbrella assertion missing or duplicated'}
            if($noRelease.Verdict -ceq 'FAIL'){$umbrella[0].Verdict='FAIL'}elseif($noRelease.Verdict -cne 'PASS' -and $umbrella[0].Verdict -ceq 'PASS'){$umbrella[0].Verdict='INCONCLUSIVE'}
            $umbrella[0].Reason+=' Notification no-release proof='+$noRelease.Verdict+'.'
            Save-State $trial.BlockWindowClosure (Join-Path $evidenceDirectory 'block-window-closure.clixml')
        }
}

        $trial.ServiceEvidence=@{JournalDelta=$delta;NotificationProof=$proof;OperationFence=$fence;TrustBoundary='Existing SYSTEM/Administrators same-handle proof adapters'}
        $trial.Journal=$trial.ServiceAfter.Journal;$trial.Notifications=$proof.Emissions
        $trial.Assertions+=@{Name='JournalDelta';Verdict=$(if($delta.Findings.Count){'FAIL'}elseif($delta.Complete){'PASS'}else{'INCONCLUSIVE'});Reason=(@($delta.Failures)+@($delta.Findings) -join '; ')}
        if($cachedDenial){
            $trial.ServiceEvidence=Get-ServiceTimeline $trial.ServiceBefore $trial.ServiceAfter $fence;$trial.Assertions+=@($trial.ServiceEvidence.Assertions)
            $trial.Assertions+=@{Name='C05NoAnyNewTransfer';Verdict=$(if($delta.NewEntries.Count){'FAIL'}elseif($delta.Complete){'PASS'}else{'INCONCLUSIVE'});Reason=('Physical external source and denied target rename must create no transfer anywhere in the authenticated journal window; new entries='+$delta.NewEntries.Count+'; '+(@($delta.Failures)+@($delta.Findings) -join '; '))}
            $trial.Assertions+=@{Name='C05DenialLedger';Verdict='INCONCLUSIVE';Reason='Win32:5 is recorded on the exact native rename with a successful physical source open/read; exact driver denial reason/lower-admission ledger unavailable.'}
        }elseif($CaseId -ceq 'B01'){
            $trial.Assertions+=Test-B01FailureNotification $proof $terminal.TransferId $actor.SessionId $digest
            $trial.B01FailureLog=Read-AgentLogWindow $trial.ServiceBefore.Application $trial.ServiceAfter.Application 'Application'
            if($trial.B01FailureLog.Artifact){$trial.JournalSnapshots+=@{Journal=@($trial.B01FailureLog)}}
            $trial.Assertions+=Test-B01FailureAudit $trial.B01FailureLog $terminal.TransferId
        }
        else{$trial.Assertions+=Test-CachedNotifications $proof $terminal.TransferId $actor.SessionId $row.Outcome $digest $trial.HandBack}
        $trial.VerifierAfter=Get-VerifierEvidence 'after' -RequireMode
    }catch{'ScriptError='+$_.Exception.ToString();$trial.Errors+=Get-ErrorChain $_.Exception;$trial.Assertions+=@{Name='C01Execution';Verdict='INCONCLUSIVE';Reason=($_.Exception.Message+'; '+$_.ScriptStackTrace)}}
    finally {
        if($null -ne $agentStartLocal){
            try{Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$agentStartLocal} -ErrorAction Stop | Where-Object ProviderName -match 'SafeUpload' |
                Sort-Object TimeCreated | ForEach-Object {$_.TimeCreated.ToString('o')+' '+$_.ProviderName+' '+$_.LevelDisplayName+' '+($_.Message -replace '\s+',' ')} |
                Set-Content -LiteralPath (Join-Path $evidenceDirectory 'agent-events-final.txt') -Encoding UTF8}catch{}
        }
        if($null -ne $actor){
            foreach($leaf in @('cancel','close','inspect-handback')){try{if(-not(Test-Path -LiteralPath (Join-Path $actorDirectory $leaf))){Write-DurableFile (Join-Path $actorDirectory $leaf) $RunName -New}}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
            if($null -eq $writer){
                try{
                    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long](15*[Diagnostics.Stopwatch]::Frequency))
                    while((Get-ScheduledTask -TaskName $writerTask).State -eq 'Running' -and [Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline){Start-Sleep -Milliseconds 100}
                    if((Get-ScheduledTask -TaskName $writerTask).State -eq 'Running'){Stop-ScheduledTask -TaskName $writerTask;throw 'Actor did not complete cooperative cancellation within 15 seconds; task stopped, native release evidence incomplete'}
                }catch{$trial.Errors+=Get-ErrorChain $_.Exception;$trial.Assertions+=@{Name='ActorQuiescence';Verdict='INCONCLUSIVE';Reason=$_.Exception.ToString()}}
            }
            try{
                if(Test-Path -LiteralPath (Join-Path $actorDirectory 'closed.clixml')){
                    $receipt=Wait-WriterIdentity (Join-Path $actorDirectory 'closed.clixml') 1
                    if($receipt.Pid -eq $actor.Pid -and $receipt.Token -ceq $state.WriterToken -and $receipt.BootId -ceq $actor.BootId){
                        $trial.Operations=@($receipt.Calls)
                        if(@($receipt.Calls | Where-Object {$want=if($cachedDenial -and $_.Class -ceq 'rename-ex'){5}else{0};$_.NativeCode -ne $want}).Count){$trial.Assertions+=@{Name='ExactNativeStatus';Verdict='FAIL';Reason=('Unexpected native failure: '+(@($receipt.Calls | ForEach-Object {$_.Class+'=Win32:'+$_.NativeCode}) -join '; '))}}
                    }
                }
            }catch{$trial.Errors+=Get-ErrorChain $_.Exception}
        }
        if($null -ne $externalContext -and $externalContext.Status -ceq 'OK'){
            $externalDisposal=Close-InvariantObserver $externalContext;$trial.ExternalSource.Disposal=$externalDisposal
            if($externalDisposal.Status -cne 'OK'){$trial.Assertions+=@{Name=$(if($CaseId -ceq 'B01'){'B01SentinelDisposal'}else{'C05SourceDisposal'});Verdict='INCONCLUSIVE';Reason=('External observer disposal failed: '+($externalDisposal.Error | Out-String))}}
        }elseif($cachedDenial){$trial.Assertions+=@{Name='C05SourceCoverage';Verdict='INCONCLUSIVE';Reason='External raw/fresh/uncached observer or baseline unavailable; see execution error.'}}
        if($null -ne $context -and $context.Status -ceq 'OK'){$disposal=Close-InvariantObserver $context}
        if($null -ne $readyEvent){$readyEvent.Dispose()}
        try{Restore-CachedAgent}catch{$trial.Errors+=Get-ErrorChain $_.Exception;$trial.Assertions+=@{Name='C01AgentRestoration';Verdict='INCONCLUSIVE';Reason=$_.Exception.ToString()}}
        $trial.Baseline=$baseline;$trial.Samples=$samples;$trial.PredicateSamples=$predicateSamples;$trial.Disposal=$disposal
        if($CaseId -ceq 'R01'){
            foreach($sample in $samples){$trial.Assertions+=Test-R01OfflineAbsent $sample $baseline (Join-Path $protectedDirectory 'offline-new.txt')}
            if(-not $samples.Count){$trial.Assertions+=@{Name='R01OfflineNewCoverage';Verdict='INCONCLUSIVE';Reason='No raw/fresh/uncached offline create-name absence samples retained.'}}
        }
        $trial.WriterFence=@{Complete=($null -ne $writer -and $writer.ExitCode -eq 0);BootId=$writer.BootId;QpcFrequency=$writer.Value.QpcFrequency;ReleasedQpc=$writer.Value.ReleasedQpc;CompletedQpc=$writer.CompletedQpc;ExpectedAttempts=1}
        $trial.LastAccessPolicy=@{Status=$(if($null -ne $trial.LastAccessBefore.Value -and $null -ne $trial.LastAccessAfter.Value){'OK'}else{'INCONCLUSIVE'});Before=$trial.LastAccessBefore;After=$trial.LastAccessAfter}
        $trial.MutationLedger=@{Complete=$false;Overflow=$false;Entries=@();Source='Unavailable: existing lower admission/completion adapter'}
        $trial.ExpectedTimeline=@{ForbiddenBlocks=@($state.ForbiddenBlocks | ForEach-Object {,[Convert]::FromBase64String($_)});Checkpoints=$checkpoints;AllowedMutations=@();ExpectedDenials=@();
            WriterIdentities=@($trial.Actor | Where-Object {$null -ne $_});Operations=$trial.Operations;WriterFence=$trial.WriterFence;LastAccessPolicy=$trial.LastAccessPolicy;
            ExternalEvidence=@{Build=$trial.Platform.Build;PrepareBootId=$state.PrepareBootId;ActiveBootId=$trial.Platform.BootId;ObserverPid=$trial.Platform.ObserverPid;ObserverSid=$trial.Platform.ObserverSid;ObserverProcess=$trial.Platform.ObserverProcess;ActorProvenance=$trial.ActorProvenance;Restoration=@{Known=$false}}}
        if($null -ne $baseline -and $predicateSamples.Count){
            # S01's exact retained-artifact forbidden block / raw extent predicate.
            # APPROVE covers pre-close samples here; post-close bytes are compared
            # above, without inventing an authenticated publication permit.
            $trial.Predicate=Test-NoUnapprovedByte $baseline @() $predicateSamples $trial.MutationLedger $trial.ExpectedTimeline
            $trial.ForbiddenByteCount=$trial.Predicate.ForbiddenByteCount;$trial.Assertions+=@($trial.Predicate.Assertions)
            # Explicit sum: Windows PowerShell 5.1 Measure-Object rejects a property name on hashtable input (run c01m).
            foreach($assertion in @($trial.Assertions)){
                if($assertion -is [Collections.IDictionary] -and $assertion['Name'] -clike '*RawExtent' -and $assertion.Contains('ForbiddenByteCount')){
                    $trial.ForbiddenByteCount+= [long]$assertion['ForbiddenByteCount']
                }
            }
        }
        if($cachedDenial -and $null -ne $externalBaseline -and $externalBaseline.Status -ceq 'OK' -and $trial.ExternalSource.Samples.Count){
            $sourceCheckpoints=@($trial.ExternalSource.Samples | ForEach-Object {$cp=Get-ExpectedCheckpoint $externalBaseline $_.Phase $_.Sequence;$cp.State='Unscoped';$cp})
            $sourceTimeline=@{ForbiddenBlocks=@();Checkpoints=$sourceCheckpoints;AllowedMutations=@();ExpectedDenials=@();
                WriterIdentities=@($actor);Operations=$trial.Operations;WriterFence=$trial.WriterFence;LastAccessPolicy=$trial.LastAccessPolicy;ExternalEvidence=$trial.ExpectedTimeline.ExternalEvidence}
            $sourcePredicate=Test-NoUnapprovedByte $externalBaseline @() $trial.ExternalSource.Samples $trial.MutationLedger $sourceTimeline
            $trial.ExternalSource.Predicate=$sourcePredicate
            if($null -ne $trial.ForbiddenByteCount -and $null -ne $sourcePredicate.ForbiddenByteCount){$trial.ForbiddenByteCount+=[long]$sourcePredicate.ForbiddenByteCount}
            foreach($assertion in $sourcePredicate.Assertions){$assertion.Name='C05Source'+$assertion.Name};$trial.Assertions+=@($sourcePredicate.Assertions)
        }
        $trial.Assertions+=@{Name='LiveTaintFlags';Verdict='INCONCLUSIVE';Reason='Live TEST_DISABLE_TAINT readback unavailable; BootPolicy.Flags is not a live proof.'}
        $trial.Assertions+=@{Name='C01PublicationAndTemporalCoverage';Verdict='INCONCLUSIVE';Reason='Lower mutation ledger, authenticated permit/snapshot grant and continuous coverage unavailable. APPROVE post-close samples are retained but cannot establish pre-permit absence from latest-state polling.'}
        if($null -eq $trial.ServiceEvidence){$trial.Assertions+=@{Name='ActualServiceTimelines';Verdict='INCONCLUSIVE';Reason='C01 authenticated service window incomplete; see exact execution error and partial journal artifacts.'}}
        if($null -eq $disposal -or $disposal.Status -cne 'OK'){$trial.Assertions+=@{Name='Disposal';Verdict='INCONCLUSIVE';Reason='Checked observer disposal missing/failed.'}}
        # Shared C01 evaluators retain stable names for their self-check fixtures;
        # exports name the actual expanded family, including C05 source checks.
        foreach($assertion in $trial.Assertions){if($assertion.Name -clike 'C01*' -and $assertion.Name -cne 'C01HandBackWindowClosureAndRestart'){$assertion.Name=$cachedFamily+$assertion.Name.Substring(3)}}
        $trial.Verdict=if(@($trial.Assertions | Where-Object Verdict -ceq 'FAIL').Count -or @($trial.Latency | Where-Object Verdict -ceq 'FAIL').Count){'FAIL'}else{'INCONCLUSIVE'}
        $trial.CaseDurationMs=1000.0*([Diagnostics.Stopwatch]::GetTimestamp()-$caseStartedQpc)/[Diagnostics.Stopwatch]::Frequency
        Save-State $trial $trialPath
    }
}
function Invoke-SeedObservation {
    $context=$null;$samples=@();$checkpoints=@();$baseline=$null;$disposal=$null;$writer=$null
    $trial=[ordered]@{Errors=@();Approvals=@();Permits=@();Journal=@();Notifications=@();Operations=@();Latency=@();Assertions=@();Verdict='INCONCLUSIVE';ForbiddenByteCount=0}
    try {
        Assert-Hash $installedDriver $ExpectedFeatureSha256
        if((Get-ItemProperty "HKLM:\$registryService").Start -ne 0){throw 'Driver must remain boot-start'}
        if((Get-BootId) -ceq $state.PrepareBootId){throw 'Activating reboot not observed'}
        if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0){throw 'Agent must be absent during seed attempts'}
        if($Mode -eq 'runtime-verifier'){
            & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
            if($LASTEXITCODE -ne 0){throw 'Runtime Verifier arm failed'}
        }
        $trial.VerifierBefore=Get-VerifierEvidence 'before' -RequireMode
        $ready=Get-Readiness
        $readback=Get-BootPolicyReadback
        if($ready.VolumeGuid -cne $state.VolumeGuid -or $readback.RecordBase64 -cne $state.ExpectedBootRecord){throw 'Boot volume/scope identity changed'}
        if($CaseId -ne 'S00-observer-control'){
            $nt=Invoke-SystemBody @'
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;using System.Text;public static class SUDevice{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern uint QueryDosDevice(string n,StringBuilder b,int c);}'
$b=[Text.StringBuilder]::new(1024);if([SUDevice]::QueryDosDevice('C:',$b,1024) -eq 0){throw 'QueryDosDevice failed'}
$value=$b.ToString().Split([char]0)[0]
'@
            if($readback.Prefix -cne ($nt+$protectedDirectory.Substring(2))){throw 'NT scope renumbered across boot; cannot claim protected fixture'}
        }

        Write-DurableFile (Join-Path $evidenceDirectory 'readiness.json') ($ready | ConvertTo-Json -Depth 32) -New
        $trial.Readiness=$ready
        $trial.ServiceBefore=Get-ServiceSnapshot 'before'
        $trial.LastAccessBefore=Get-LastAccessEvidence
        if($CaseId -eq 'S00-observer-control'){
            Start-ScheduledTask -TaskName $writerTask
            $identityPath=Join-Path $actorDirectory 'identity.clixml'
            $trial.ActorProvenance=Assert-ActorProcess (Wait-WriterIdentity $identityPath)
            Write-DurableFile (Join-Path $actorDirectory 'go') $RunName -New
            $writer=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken
            $trial.Actor=$writer.Value.Actor
            # Known control writes are legitimate setup and are flushed before
            # independently expected baseline capture. Every later sample equals B.
        }
        $context=Open-InvariantObserver $ready.VolumeGuid $protectedDirectory (Join-Path $evidenceDirectory 'raw') $CaseId
        if($context.Status -ne 'OK'){throw ($context.Error | Out-String)}
        $expected=@{'marker.bin'=[Convert]::FromBase64String($state.BaselineBase64);'new.bin'=$null}
        $captureStarted=[DateTime]::UtcNow.ToFileTimeUtc()
        $baseline=Capture-InvariantBaseline $context @('marker.bin','new.bin') $expected
        $baseline | Add-Member NoteProperty CaptureStartedFileTime $captureStarted
        $trial.DecoderVersion=$context.DecoderVersion;$trial.ObserverModuleSha256=$context.ModuleSha256
        $observerProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)
        $observerOwner=Invoke-CimMethod -InputObject $observerProcess -MethodName GetOwnerSid
        if($observerOwner.ReturnValue -ne 0 -or $observerOwner.Sid -cne $context.ObserverSid){throw 'OS observer SID mismatch'}
        $trial.Geometry=$context.Geometry;$trial.Platform=@{Build=$context.Build;BootId=$context.BootId;ObserverPid=$context.ObserverPid;ObserverSid=$context.ObserverSid;
            ObserverProcess=@{Pid=$observerProcess.ProcessId;OwnerSid=$observerOwner.Sid;SessionId=$observerProcess.SessionId;CommandLine=$observerProcess.CommandLine}}
        if($baseline.Status -ne 'OK'){throw ($baseline.Error | Out-String)}
        $seq=1;$checkpoints+=Get-ExpectedCheckpoint $baseline 'BeforeOperation' $seq
        $samples+=Capture-InvariantSample $context $baseline 'BeforeOperation' $seq
        if($CaseId -ne 'S00-observer-control'){Start-ScheduledTask -TaskName $writerTask}
        $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((60)*[Diagnostics.Stopwatch]::Frequency))
        # S00 is complete now; its completion envelope owns the final identity.
        $actor=if($CaseId -eq 'S00-observer-control'){$writer.Value.Actor}else{Wait-WriterIdentity (Join-Path $actorDirectory 'identity.clixml')}
        if($actor.Sid -cne $state.ActorSid -or $actor.Elevated -or $actor.IsAdministrator -or $actor.Pid -eq $PID -or $actor.BootId -cne $context.BootId){throw 'Actor provenance invalid'}
        $trial.Actor=$actor
        if($CaseId -ne 'S00-observer-control'){$trial.ActorProvenance=Assert-ActorProcess $actor;Write-DurableFile (Join-Path $actorDirectory 'go') $RunName -New}
        do {
            $seq++;$checkpoints+=Get-ExpectedCheckpoint $baseline 'Continuous' $seq
            $samples+=Capture-InvariantSample $context $baseline 'Continuous' $seq
            # Full-pass and gap QPC intervals are later checked against all actor attempts.
            Start-Sleep -Milliseconds 10
            if([Diagnostics.Stopwatch]::GetTimestamp() -gt ($deadline+[long](120*[Diagnostics.Stopwatch]::Frequency))){throw 'Writer completion unavailable'}
        }while(-not(Test-Path -LiteralPath (Join-Path $actorDirectory 'completion.clixml')))
        $writer=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken
        $trial.Operations=$writer.Value.Calls
        $trial.OperationClassTimeline=$row.StatusClasses;$trial.Repetitions=$row.Repetitions
        $trial.Policy=@{SeedRecord=$readback;LiveFlags=$null;TaintDisabledConfirmed=$false}
        $trial.Coverage=@{RequiredBeforeAfterEachOperation=$false;ContinuousTargetMs=10;LowerLedgerComplete=$false;ObserverSelfChecksOnThisArtifact=$false}
        $trial.Latency=Get-LatencyVerdict $trial.Operations $row.LatencyClasses $writer.Value.QpcFrequency
        $seq++;$checkpoints+=Get-ExpectedCheckpoint $baseline 'AfterOperation' $seq
        $samples+=Capture-InvariantSample $context $baseline 'AfterOperation' $seq
        $trial.FinalCacheFlush=Flush-InvariantFinalVolume
        $seq++;$checkpoints+=Get-ExpectedCheckpoint $baseline 'FinalQuiescence' $seq
        $samples+=Capture-InvariantSample $context $baseline 'FinalQuiescence' $seq
        $trial.LastAccessAfter=Get-LastAccessEvidence
        $trial.ServiceAfter=Get-ServiceSnapshot 'after'
        $serviceFence=[pscustomobject]@{Complete=($writer.ExitCode -eq 0 -and $writer.Value.Held -eq $false);BootId=$writer.BootId;
            QpcFrequency=$writer.Value.QpcFrequency;ReleasedQpc=$writer.Value.ReleasedQpc;CompletedQpc=$writer.CompletedQpc}
        $trial.ServiceEvidence=Get-ServiceTimeline $trial.ServiceBefore $trial.ServiceAfter $serviceFence
        $trial.Journal=$trial.ServiceAfter.Journal;$trial.Notifications=$trial.ServiceEvidence.NotificationEmissions
        $trial.Assertions+=@($trial.ServiceEvidence.Assertions)
        $trial.VerifierAfter=Get-VerifierEvidence 'after' -RequireMode
        for($n=0;$n -le 100;$n++){
            $calls=@($trial.Operations | Where-Object Trial -eq $n)
            $good=if($CaseId -eq 'S00-observer-control'){
                $calls.Count -eq 4 -and @($calls | Where-Object NativeCode -ne 0).Count -eq 0
            }else{$calls.Count -eq 1 -and $calls[0].Class -ceq 'writer-open-deny' -and $calls[0].NativeCode -eq 5}
            $trial.Assertions+=@{Name='ExactNativeStatus';Trial=$n;Verdict=$(if($good){'PASS'}else{'FAIL'});Reason=($row.StatusClasses -join ';')}
        }
        if($trial.Operations[0].StartQpc -lt $ready.Qpc){throw 'Attempt precedes durable readiness'}
    }catch{$trial.Errors+=Get-ErrorChain $_.Exception}
    finally {
        if($null -ne $context -and $context.Status -eq 'OK'){$disposal=Close-InvariantObserver $context}
        $trial.Baseline=$baseline;$trial.Samples=$samples;$trial.Disposal=$disposal
        $trial.WriterFence=[pscustomobject]@{Complete=($null -ne $writer -and $writer.ExitCode -eq 0 -and $writer.Value.Held -eq $false);
            BootId=$writer.BootId;QpcFrequency=$writer.Value.QpcFrequency;ReleasedQpc=$writer.Value.ReleasedQpc;CompletedQpc=$writer.CompletedQpc;ExpectedAttempts=101}
        $trial.LastAccessPolicy=[pscustomobject]@{Status=$(if($null -ne $trial.LastAccessBefore.Value -and $null -ne $trial.LastAccessAfter.Value){'OK'}else{'INCONCLUSIVE'});Before=$trial.LastAccessBefore;After=$trial.LastAccessAfter}
        # No fabricated lower entries, actor-free bypass or live Flags proof.
        $trial.MutationLedger=@{Complete=$false;Overflow=$false;FirstSequence=0;LastSequence=0;Entries=@();Source='Unavailable: driver lower admission/completion mutation ledger readback; user-mode calls cannot substitute'}
        $trial.ExpectedTimeline=@{ForbiddenBlocks=@($state.ForbiddenBlocks | ForEach-Object {,[Convert]::FromBase64String($_)});
            Checkpoints=$checkpoints;AllowedMutations=@();ExpectedDenials=@();WriterIdentities=@($trial.Actor | Where-Object {$null -ne $_});
            Operations=$trial.Operations;WriterFence=$trial.WriterFence;LastAccessPolicy=$trial.LastAccessPolicy;
            ExternalEvidence=[pscustomobject]@{Build=$trial.Platform.Build;PrepareBootId=$state.PrepareBootId;ActiveBootId=$trial.Platform.BootId;
                ObserverPid=$trial.Platform.ObserverPid;ObserverSid=$trial.Platform.ObserverSid;ObserverProcess=$trial.Platform.ObserverProcess;
                ActorProvenance=$trial.ActorProvenance;Restoration=@{Known=$false}}}
        if($null -ne $baseline){$trial.CadenceProof=Test-InvariantCadence $baseline $samples $trial.Operations $trial.WriterFence;$trial.ExpectedTimeline.CadenceProof=$trial.CadenceProof}
        if($null -ne $baseline -and $samples.Count -gt 0){
            $trial.Predicate=Test-NoUnapprovedByte $baseline @() $samples $trial.MutationLedger $trial.ExpectedTimeline
            $trial.ForbiddenByteCount=$trial.Predicate.ForbiddenByteCount
            $trial.Assertions+=@($trial.Predicate.Assertions)
        }
        $trial.Assertions+=@{Name='LiveTaintFlags';Verdict='INCONCLUSIVE';Reason='Driver Inspector does not expose live TEST_DISABLE_TAINT flag readback; registry BootPolicy.Flags does not attest live Flags. WP4 makes no driver changes.'}
        if($null -eq $trial.ServiceEvidence){$trial.Assertions+=@{Name='ActualServiceTimelines';Verdict='INCONCLUSIVE';Reason='Service before/after evidence collection did not complete; see Errors and service snapshot artifacts.'}}
        if($null -eq $disposal -or $disposal.Status -ne 'OK'){$trial.Assertions+=@{Name='Disposal';Verdict='INCONCLUSIVE';Reason='Checked observer disposal missing or failed'}}
        $trial.Verdict=if(@($trial.Assertions | Where-Object Verdict -eq 'FAIL').Count -gt 0 -or @($trial.Latency | Where-Object Verdict -eq 'FAIL').Count -gt 0){'FAIL'}else{'INCONCLUSIVE'}
        Save-State $trial $trialPath
    }
}
function Add-ActivationAssertion($Trial,[string]$Name,[string]$Verdict,[string]$Reason,$Evidence) {
    $item=[ordered]@{Name=$Name;Verdict=$Verdict;Reason=$Reason}
    if($null -ne $Evidence){$item.Evidence=$Evidence}
    $Trial.Assertions+=@([pscustomobject]$item)
}
function Get-ActivationSha256([byte[]]$Bytes) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','')}
    finally{$sha.Dispose()}
}
function Get-ActivationOwnedStagePathProof($Transfer) {
    $stagePath=[string]$Transfer.StagePath
    $stageRoot=[IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $policyPath) 'staging')).TrimEnd('\')
    try{$fullPath=[IO.Path]::GetFullPath($stagePath)}catch{return [pscustomobject]@{Verdict='FAIL';Reason='Journal StagePath is not a valid full path.';Path=$stagePath}}
    if([IO.Path]::GetDirectoryName($fullPath) -ine $stageRoot -or [IO.Path]::GetFileName($fullPath) -cnotmatch '^[0-9a-f]{32}\.txt$'){
        return [pscustomobject]@{Verdict='FAIL';Reason='Journal StagePath is outside the exact product staging root or has an unexpected allocator filename.';Path=$fullPath;ExpectedRoot=$stageRoot}
    }
    return [pscustomobject]@{Verdict='PASS';Reason='Authenticated journal StagePath is under the exact product staging root and has the allocator GUID plus .txt name.';Path=$fullPath;ExpectedRoot=$stageRoot}
}
function Get-ActivationHandBackInventory($Actor) {
    $profiles=@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $Actor.Sid)
    if($profiles.Count -ne 1){throw 'Exact actor OS profile unavailable for no-hand-back checkpoint'}
    $root=Join-Path $profiles[0].LocalPath 'SafeUpload\_bloqueados'
    $files=@();if(Test-Path -LiteralPath $root){foreach($file in @(Get-ChildItem -LiteralPath $root -Force)){if($file.PSIsContainer){throw 'Unexpected hand-back inventory directory'};$files+=@{Path=$file.FullName;Length=$file.Length;Sha256=(Get-FileHash -LiteralPath $file.FullName).Hash}}}
    return [pscustomobject]@{Root=$root;Sid=$Actor.Sid;Files=$files;Qpc=[Diagnostics.Stopwatch]::GetTimestamp();BootId=(Get-BootId)}
}
function Test-ActivationChildWindow($Trial,$Before,$After,$Mutation,$HandBackBefore,$HandBackAfter,[string]$Target,$Primary,$Child) {
    $window=$Before.Status -ceq 'OK' -and $After.Status -ceq 'OK' -and $Before.BootId -ceq $After.BootId -and
        $Before.EndQpc -le $Mutation.StartQpc -and $Mutation.EndQpc -le $After.StartQpc
    $delta=Test-ServiceJournalDelta $Before $After $window
    $exact=@($delta.NewEntries | Where-Object {$_.DestinationPaths -contains $Target})
    $verdict=if($exact.Count -or $delta.Findings.Count){'FAIL'}elseif($delta.Complete){'PASS'}else{'INCONCLUSIVE'}
    Add-ActivationAssertion $Trial 'NoJournalAtChildMutationCheckpoints' $verdict 'Authenticated before/after journal checkpoints contain no new exact-destination transfer from any PID; transient whole-window coverage is separately recorded INCONCLUSIVE.' @{Before=$Before;After=$After;Delta=$delta;Exact=$exact}
    $known=$HandBackBefore.Sid -ceq $Child.Sid -and $HandBackAfter.Sid -ceq $Child.Sid -and $HandBackBefore.Root -ceq $HandBackAfter.Root -and
        $HandBackBefore.BootId -ceq $Child.BootId -and $HandBackAfter.BootId -ceq $Child.BootId -and $HandBackBefore.Qpc -le $Mutation.StartQpc -and $HandBackAfter.Qpc -ge $Mutation.EndQpc
    $noCopies=$HandBackBefore.Files.Count -eq 0 -and $HandBackAfter.Files.Count -eq 0
    Add-ActivationAssertion $Trial 'NoHandBackAtChildMutationCheckpoints' $(if(-not $known){'INCONCLUSIVE'}elseif($noCopies){'PASS'}else{'FAIL'}) 'Fresh exact OS actor profile contains no hand-back before/after the child mutation; whole-interval transient emission coverage remains separately unqualified.' @{Before=$HandBackBefore;After=$HandBackAfter}
    $Trial.ChildWindow=@{Before=$Before;After=$After;Mutation=$Mutation;HandBackBefore=$HandBackBefore;HandBackAfter=$HandBackAfter;JournalDelta=$delta}
}

function Get-ActivationPhysicalObjectProof([int]$PrimaryPid,[long]$SourceHandle,[int]$ChildPid,[long]$RemoteHandle) {
    if(-not ('SUActivationObjects' -as [type])){Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using System.ComponentModel;
public static class SUActivationObjects {
 [DllImport("ntdll.dll")]static extern int NtQuerySystemInformation(int c,IntPtr b,int n,out int length);
 [DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool LookupPrivilegeValueW(string system,string name,out long luid);
 [StructLayout(LayoutKind.Sequential,Pack=4)]struct Privilege {public uint Count;public long Luid;public uint Attributes;}
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref Privilege p,int n,IntPtr old,IntPtr len);
 public static void EnableDebug(){IntPtr token;if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Win32Exception(Marshal.GetLastWin32Error());try{long luid;if(!LookupPrivilegeValueW(null,"SeDebugPrivilege",out luid))throw new Win32Exception(Marshal.GetLastWin32Error());Privilege p=new Privilege{Count=1,Luid=luid,Attributes=2};if(!AdjustTokenPrivileges(token,false,ref p,0,IntPtr.Zero,IntPtr.Zero)||Marshal.GetLastWin32Error()!=0)throw new Win32Exception(Marshal.GetLastWin32Error());}finally{CloseHandle(token);}}
 public static string[] Query(int primary,long source,int child,long remote){
  if(IntPtr.Size!=8||primary<=0||child<=0||primary==child||source<=0||remote<=0)throw new InvalidOperationException("Unsupported identity/architecture");
  EnableDebug();int size=1048576;IntPtr buffer=IntPtr.Zero;
  try{int returned=0,status;
   while(true){buffer=Marshal.AllocHGlobal(size);status=NtQuerySystemInformation(64,buffer,size,out returned);if(status==0)break;Marshal.FreeHGlobal(buffer);buffer=IntPtr.Zero;if(status!=unchecked((int)0xc0000004)||size>=67108864)throw new InvalidOperationException("Handle inventory NTSTATUS "+status.ToString("X8"));size=Math.Max(size*2,returned);if(size>67108864)throw new InvalidOperationException("Handle inventory bound");}
   if(returned<16||returned>size)throw new InvalidOperationException("Handle inventory length");long count=Marshal.ReadInt64(buffer);if(count<0||count>(returned-16)/40)throw new InvalidOperationException("Handle inventory count");
   long a=0,b=0;int ac=0,bc=0,at=0,bt=0;
   for(long i=0;i<count;i++){int offset=checked(16+(int)i*40);long pid=Marshal.ReadInt64(buffer,offset+8),handle=Marshal.ReadInt64(buffer,offset+16);if(pid==primary&&handle==source){a=Marshal.ReadInt64(buffer,offset);at=(ushort)Marshal.ReadInt16(buffer,offset+30);ac++;}if(pid==child&&handle==remote){b=Marshal.ReadInt64(buffer,offset);bt=(ushort)Marshal.ReadInt16(buffer,offset+30);bc++;}}
   if(ac!=1||bc!=1||a==0||b==0||a!=b||at==0||at!=bt)throw new InvalidOperationException("Distinct PID handles do not identify one nonzero kernel object");
   return new string[]{"0x"+unchecked((ulong)a).ToString("X16"),at.ToString(),count.ToString()};
  }finally{if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);}
 }
}
'@}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{
        $start=[Diagnostics.Stopwatch]::GetTimestamp();$values=[SUActivationObjects]::Query($PrimaryPid,$SourceHandle,$ChildPid,$RemoteHandle)
        return [pscustomobject]@{Status='OK';Source='NtQuerySystemInformation/SystemExtendedHandleInformation';CollectedBySid=$identity.User.Value;CollectedByPid=$PID;BootId=(Get-BootId);QpcFrequency=[Diagnostics.Stopwatch]::Frequency;StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();PrimaryPid=$PrimaryPid;SourceHandle=$SourceHandle;ChildPid=$ChildPid;RemoteHandle=$RemoteHandle;Object=$values[0];ObjectTypeIndex=[int]$values[1];InventoryCount=[long]$values[2]}
    }finally{$identity.Dispose()}
}

function Initialize-ActivationDuplicate($Trial,$Primary) {
    Start-ScheduledTask -TaskName $state.ActivationActors.Duplicate.Task
    $child=Get-ActivationActorIdentity 'Duplicate'
    if($child.Pid -eq $Primary.Pid -or $child.Sid -cne $Primary.Sid -or $child.SessionId -ne $Primary.SessionId -or $child.BootId -cne $Primary.BootId){throw 'Duplicate actor is not a distinct standard-user process in the same bound session/boot'}
    $Trial.DuplicateActor=$child
    $duplicate=Publish-ActivationActorCommand $state 'duplicate-holder' @{TargetPid=$child.Pid}
    if($duplicate.NativeCode -ne 0 -or $duplicate.SourceHandle -le 0 -or $duplicate.RemoteHandle -le 0 -or $duplicate.TargetPid -ne $child.Pid){throw ('Native cross-process DuplicateHandle failed: '+$duplicate.NativeCode)}
    $adopt=Publish-ActivationActorCommand $state 'adopt-holder' @{RemoteHandle=$duplicate.RemoteHandle} 'Duplicate'
    if($adopt.NativeCode -ne 0 -or -not $adopt.HolderCreated -or $adopt.RemoteHandle -ne $duplicate.RemoteHandle){throw 'Child did not adopt the exact native remote handle'}
    $parentPosition=Publish-ActivationActorCommand $state 'position-holder' @{Offset=[long]317;Query=$false}
    $childQuery=Publish-ActivationActorCommand $state 'position-holder' @{Offset=[long]0;Query=$true} 'Duplicate'
    $childPosition=Publish-ActivationActorCommand $state 'position-holder' @{Offset=[long]619;Query=$false} 'Duplicate'
    $parentQuery=Publish-ActivationActorCommand $state 'position-holder' @{Offset=[long]0;Query=$true}
    $good=$parentPosition.NativeCode -eq 0 -and $childQuery.NativeCode -eq 0 -and $childPosition.NativeCode -eq 0 -and $parentQuery.NativeCode -eq 0 -and
        $parentPosition.Position -eq 317 -and $childQuery.Position -eq 317 -and $childPosition.Position -eq 619 -and $parentQuery.Position -eq 619
    $physical=Get-ActivationPhysicalObjectProof $Primary.Pid $duplicate.SourceHandle $child.Pid $duplicate.RemoteHandle
    $physicalArtifact=Join-Path $evidenceDirectory 'activation-trusted-physical-object.json'
    Write-DurableFile $physicalArtifact ($physical | ConvertTo-Json -Depth 16) -New
    $physicalRecord=@{Artifact=$physicalArtifact;Length=(Get-Item -LiteralPath $physicalArtifact).Length;Sha256=(Get-FileHash -LiteralPath $physicalArtifact).Hash;Entry=$physical}
    if($physical.CollectedBySid -cne 'S-1-5-18'){throw 'Actual physicalFO proof collector must be SYSTEM'}
    $Trial.DuplicateSetup=@{PhysicalObjectProof=$physical;PhysicalObjectArtifact=$physicalRecord;Primary=$Primary;Child=$child;Duplicate=$duplicate;Adopt=$adopt;ParentPosition=$parentPosition;ChildQuery=$childQuery;ChildPosition=$childPosition;ParentQuery=$parentQuery;SameFileObject=$good}
    Add-ActivationAssertion $Trial 'CrossProcessSameFileObject' $(if($good){'PASS'}else{'FAIL'}) 'SYSTEM extended-handle inventory proves both distinct standard-user PID/handle pairs identify one nonzero physical file object; two-way actor position receipts independently diagnose native duplicate stimulus.' $Trial.DuplicateSetup
    if(-not $good){throw 'Duplicated handles did not share the same two-way file position'}
    return $child
}
function Test-ActivationDuplicateCleanup($Trace,$OldWrites,$Child,$Release) {
    # Caller clears the authenticated trace immediately before the final close.
    # The kernel trace timestamp is FILETIME, whereas actor times are QPC.
    # Bind the loss-free post-clear receipt to actual PID and physical file
    # object; never compare unrelated clock domains.
    $cleanup=@($Trace.Entries | Where-Object event -ceq 'file_cleanup')
    $objects=@($OldWrites.CompletedWritePairs | ForEach-Object {$_.Begin.targetFileObject} | Sort-Object -Unique)
    $good=$Release.NativeCode -eq 0 -and $Release.HolderReleased -and $Release.Pid -eq $Child.Pid -and $Release.BootId -ceq $Child.BootId -and
        $cleanup.Count -eq 1 -and $objects.Count -eq 1 -and $objects[0] -cmatch '^0x[0-9A-Fa-f]{16}$' -and $objects[0] -cne '0x0000000000000000' -and
        $cleanup[0].targetFileObject -ceq $objects[0] -and [uint32]$cleanup[0].pid -eq [uint32]$Child.Pid
    return [pscustomobject]@{Verdict=$(if($good){'PASS'}else{'INCONCLUSIVE'});Reason='Loss-free post-clear target trace has exactly one final child-PID cleanup matching the physical file object that accepted old child writes.';Release=$Release;Trace=$Trace;OldWrites=$OldWrites;KernelTimestampDomain='FILETIME';ActorTimestampDomain='QPC'}
}

function Test-ActivationRawWholeImage($Sample,[string]$Path,[byte[]]$Expected) {
    $images=@($Sample.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ieq $Path -and -not $_.Absent})
    if($Sample.Status -cne 'OK' -or $images.Count -ne 1){return [pscustomobject]@{Verdict='INCONCLUSIVE';Reason='Exact current whole raw image unavailable.'}}
    try{
        $image=$images[0];$actual=[IO.File]::ReadAllBytes($image.LogicalArtifact.Path)
        if($actual.Length -ne $image.LogicalArtifact.Length -or (Get-ActivationSha256 $actual) -cne $image.LogicalArtifact.Sha256){throw 'Retained raw whole-image artifact length/hash mismatch'}
        $different=[Math]::Abs($actual.Length-$Expected.Length);for($i=0;$i -lt [Math]::Min($actual.Length,$Expected.Length);$i++){if($actual[$i] -ne $Expected[$i]){$different++}}
        $good=$different -eq 0
        return [pscustomobject]@{Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Complete retained raw logical bytes equal independently constructed expected image.';DifferingBytes=$different;Image=$image;ExpectedSha256=(Get-ActivationSha256 $Expected)}
    }catch{return [pscustomobject]@{Verdict='INCONCLUSIVE';Reason=$_.Exception.Message}}
}

function Invoke-ActivationApprovedSave($Trial,$Actor,$Context,$Baseline,$PromotionSample,[byte[]]$ImageU,[string]$Target) {
    $before=Get-ServiceSnapshot 'a04-before-approved-held-save';$Trial.ServiceBefore=$before
    $payload=[Text.Encoding]::ASCII.GetBytes(('APPROVE-A04-'+$RunName).PadRight(96,'Q'));$offset=[long]([int]($ImageU.Length/2)+256)
    if($offset+$payload.Length -gt $ImageU.Length){throw 'A04 approved payload exceeds the independently constructed image'}
    $imageA=[byte[]]$ImageU.Clone();[Array]::Copy($payload,0,$imageA,[int]$offset,$payload.Length);$digest=Get-ActivationSha256 $imageA
    $held=Publish-ActivationActorCommand $state 'staged-write-held' @{Offset=$offset;PayloadBase64=[Convert]::ToBase64String($payload)}
    $good=$held.NativeCode -eq 0 -and $held.HolderCreated -and $held.BytesWritten -eq $payload.Length -and $held.PrivateSha256 -ceq $digest
    Add-ActivationAssertion $Trial 'PostPromotionHeldOwnedWrite' $(if($good){'PASS'}else{'FAIL'}) 'Standard-user owned open/write/flush remains held and whole private bytes equal independently constructed benign A.' @{Receipt=$held;ExpectedSha256=$digest}
    if(-not $good){throw 'A04 held owned write/image failed'}
    $allocated=$null;$number=0;$deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](15*[Diagnostics.Stopwatch]::Frequency)
    do{
        $poll=Get-CachedJournalObservation ('a04-held-'+$number) $Actor @($Target);$number++;$Trial.JournalSnapshots+= $poll.Snapshot
        if($poll.Entries.Count -gt 1){throw 'A04 held save has ambiguous transfers'}
        if($poll.Status -ceq 'OK' -and $poll.Entries.Count -eq 1){$allocated=$poll.Entries[0];break};Start-Sleep -Milliseconds 50
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    $heldNoApproval=$null -ne $allocated -and $allocated.StateName -ceq 'Allocated' -and -not $allocated.SealedOnce
    Add-ActivationAssertion $Trial 'HeldOwnedSaveNoApproval' $(if($null -eq $allocated){'INCONCLUSIVE'}elseif($heldNoApproval){'PASS'}else{'FAIL'}) 'Exact current actor transfer remains mutable Allocated while the post-promotion native source handle is live.' $allocated
    if(-not $heldNoApproval){throw 'A04 did not prove the exact held save stayed Allocated'}
    $heldSample=Capture-InvariantSample $Context $Baseline 'A04OwnedHandleHeldBeforeApproval' 4
    $heldRaw=Test-ActivationRawWholeImage $heldSample $Target $ImageU
    $Trial.ForbiddenByteCount=$heldRaw.DifferingBytes
    Add-ActivationAssertion $Trial 'PostPromotionRawDestinationUnchanged' $heldRaw.Verdict 'Complete successful retained raw whole image remains exact U while benign A is held before approval.' $heldRaw
    if($heldRaw.Verdict -cne 'PASS'){throw 'A04 pre-approval complete raw destination proof failed/incomplete'}
    $close=Publish-ActivationActorCommand $state 'release-holder' $null
    if($close.NativeCode -ne 0 -or -not $close.HolderReleased){throw 'A04 owned-save final close failed'}
    $terminal=$null;$number=0;$deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](120*[Diagnostics.Stopwatch]::Frequency);$transitions=@($allocated)
    do{
        $poll=Get-CachedJournalObservation ('a04-approved-'+$number) $Actor @($Target);$number++;$Trial.JournalSnapshots+= $poll.Snapshot
        if($poll.Status -cne 'OK'){Start-Sleep -Milliseconds 50;continue}
        if($poll.Entries.Count -gt 1){throw 'A04 approved save has ambiguous transfers'}
        foreach($entry in $poll.Entries){
            if($entry.TransferId -ine $allocated.TransferId){throw 'A04 owned transfer changed identity after close'}
            if($transitions[-1].State -ne $entry.State){$transitions+= $entry}
            if($entry.StateName -cin @('Blocked','Retained','Unsealed')){throw ('A04 benign save unexpectedly '+$entry.StateName)}
            if($entry.StateName -ceq 'Released'){$terminal=$entry}
        }
        if($null -ne $terminal){break};Start-Sleep -Milliseconds 50
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    $sequence=Test-CachedJournalSequence $transitions 'APPROVE' $digest
    foreach($assertion in $sequence){$assertion.Name='A04'+$assertion.Name.Substring(3)};$Trial.Assertions+= $sequence
    $released=$null -ne $terminal -and $terminal.SealedOnce -and $terminal.Sha256Hex -ceq $digest
    Add-ActivationAssertion $Trial 'OwnedStreamJournalForExactDestination' $(if($released){'PASS'}else{'INCONCLUSIVE'}) 'Exact same standard-user benign owned transfer reaches actual Released with complete Approved publication history and whole A digest.' @{Held=$allocated;Close=$close;Terminal=$terminal;Transitions=$transitions}
    Add-ActivationAssertion $Trial 'PostPromotionUnapprovedWriteRoutedToOwnedStream' $(if($released){'PASS'}else{'INCONCLUSIVE'}) 'The post-promotion native write used a private owned stream while held, then actual service APPROVE published exact A after close.' @{Held=$held;Terminal=$terminal}
    if(-not $released){throw 'A04 approved owned save did not reach Released within 120 seconds'}
    $final=Capture-InvariantSample $Context $Baseline 'A04FinalReleasedImage' 5
    $whole=Test-ActivationRawWholeImage $final $Target $imageA
    Add-ActivationAssertion $Trial 'ApprovedFinalRawImageA' $whole.Verdict $whole.Reason $whole
    $Trial.ApprovedSave=@{Before=$before;Held=$held;Allocated=$allocated;Close=$close;Terminal=$terminal;ImageA=@{Length=$imageA.Length;Sha256=$digest};Final=$final;RawHeldDifference=$difference}
    $Trial.ServiceAfter=Get-ServiceSnapshot 'a04-after-approved-save'
    Add-ActivationAssertion $Trial 'A04PublicationAndTemporalCoverage' 'INCONCLUSIVE' 'Held and final whole-byte checkpoints plus actual service history do not supply a complete lower mutation/permit ledger for every instant.' $null
    return [pscustomobject]@{Samples=@($heldSample,$final)}
}

function Invoke-ActivationObservation {
    $script:ActivationNotificationHistory=@();$script:ActivationObservedPrematureReady=@();$script:ActivationHolderLive=$false;$script:ActivationCandidateGeneration=$null
    $context=$null;$agent=$null;$baseline=$null;$samples=@();$actorStarted=$false;$duplicateStarted=$false;$duplicateActor=$null;$traceEnabled=$false
    $trial=[ordered]@{Errors=@();Assertions=@();Samples=@();Operations=@();Verdict='INCONCLUSIVE';ForbiddenByteCount=$null;Reasons=@()}
    $target=Join-Path $protectedDirectory 'marker.txt';$relativeName='marker.txt';$actor=$null
    try {
        Assert-Hash $installedDriver $ExpectedFeatureSha256
        if((Get-BootId) -ceq $state.PrepareBootId){throw 'Activating reboot not observed before A case.'}
        if((Get-ItemProperty "HKLM:\$registryService").Start -ne 0){throw 'A case requires the boot-start driver.'}
        if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0){throw 'Agent must be absent until the pre-scope holder is live.'}
        # Runtime Verifier is armed by the observation itself, as for seeds and C01 (run a01r1 stopped here).
        if($Mode -eq 'runtime-verifier'){
            & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
            if($LASTEXITCODE -ne 0){throw 'Runtime Verifier arm failed'}
        }
        $trial.VerifierBefore=Get-VerifierEvidence 'activation-before' -RequireMode
        $ready=Get-Readiness
        if($ready.VolumeGuid -cne $state.VolumeGuid){throw 'A case volume identity changed across boot.'}
        $boot=Get-BootPolicyReadback
        if($boot.RecordBase64 -cne $state.ExpectedBootRecord -or $boot.PendingPresent -or $boot.PrefixCount -ne 0){throw 'A case did not boot from the exact empty-scope policy.'}
        $trial.ReadinessBefore=$ready;$trial.BootPolicyBefore=$boot
        $context=Open-InvariantObserver $ready.VolumeGuid $protectedDirectory (Join-Path $evidenceDirectory 'raw') $CaseId
        if($context.Status -ne 'OK'){throw ('Activation raw observer open failed: '+($context.Error | Out-String))}
        $observerProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID) -ErrorAction Stop
        $observerOwner=Invoke-CimMethod -InputObject $observerProcess -MethodName GetOwnerSid -ErrorAction Stop
        if($observerOwner.ReturnValue -ne 0 -or $observerOwner.Sid -cne $context.ObserverSid -or $context.ObserverSid -cne 'S-1-5-18'){throw 'Activation raw observer OS identity mismatch.'}
        $trial.Platform=@{Build=$context.Build;BootId=$context.BootId;ObserverPid=$context.ObserverPid;ObserverSid=$context.ObserverSid;
            ObserverProcess=@{Pid=$observerProcess.ProcessId;OwnerSid=$observerOwner.Sid;SessionId=$observerProcess.SessionId;CommandLine=$observerProcess.CommandLine}}

        $clearPrefix=Join-Path $evidenceDirectory ('activation-trace-clear-'+[guid]::NewGuid().ToString('N'))
        $null=Invoke-ActivationInspector '--admission-trace-clear' $clearPrefix 45000
        $enablePrefix=Join-Path $evidenceDirectory ('activation-trace-enable-'+[guid]::NewGuid().ToString('N'))
        $null=Invoke-ActivationInspector '--admission-trace-enable-sections-lifetime' $enablePrefix 45000
        $traceEnabled=$true

        Start-ScheduledTask -TaskName $writerTask
        $actor=Get-ActivationActorIdentity
        $actorStarted=$true
        $trial.Actor=$actor
        $trial.ActorProvenance=@{Pid=$actor.Pid;SessionId=$actor.SessionId;OwnerSid=$actor.OwnerSid;CommandLine=$actor.CommandLine;Task=$actor.Task}
        $state.ActivationActorPid=[int]$actor.Pid;Save-State $state $statePath
        $holder=Publish-ActivationActorCommand $state 'create-holder' $null
        if(-not $holder.HolderCreated -or $holder.NativeCode -ne 0){throw ('Pre-scope holder creation failed: Win32 '+$holder.NativeCode)}
        $expectClosed=($CaseId -cnotin @('A01','A04'))
        if([bool]$holder.SourceHandleClosed -ne $expectClosed){throw ('Holder source-handle state mismatch for '+$CaseId)}
        $script:ActivationHolderLive=$true
        $trial.HolderSetup=@{CaseId=$CaseId;Pid=$actor.Pid;Sid=$actor.Sid;SessionId=$actor.SessionId;HolderKind=$row.Variant;
            SourceHandleClosed=$holder.SourceHandleClosed;CreateQpc=$holder.StartQpc;CompleteQpc=$holder.EndQpc;NativeCode=$holder.NativeCode}

        if($CaseId -ceq 'A04'){$duplicateStarted=$true;$duplicateActor=Initialize-ActivationDuplicate $trial $actor}
        $trial.SetupCacheFlush=Flush-InvariantSetupVolume
        $pBytes=[Convert]::FromBase64String($state.BaselineBase64)
        $expectedImages=@{};$expectedImages[$relativeName]=$pBytes
        $baseline=Capture-InvariantBaseline $context @($relativeName) $expectedImages
        if($baseline.Status -ne 'OK'){throw ('Raw P capture before the epoch swap failed: '+($baseline.Error | Out-String))}
        $pImage=@($baseline.Images | Where-Object {$_.Role -eq 'Current' -and $_.Path -ieq $target -and -not $_.Absent})
        if($pImage.Count -ne 1 -or $pImage[0].Length -ne $pBytes.Length -or $pImage[0].Sha256 -cne (Get-ActivationSha256 $pBytes)){throw 'Raw pre-scope image P or exact target file identity missing.'}
        $fileId=[string]$pImage[0].Identity.FileId
        $ntPath=Get-NtDevicePath $target
        $trial.PreScopeP=@{Status=$baseline.Status;FileId=$fileId;DosPath=$target;NtPath=$ntPath;Length=$pImage[0].Length;Sha256=$pImage[0].Sha256;CaptureTime=$baseline.Time;Image=$pImage[0]}
        $samples+=Capture-InvariantSample $context $baseline 'PBeforeRuntimePolicyUpdate' 1
        if($samples[-1].Status -ne 'OK'){throw ('Raw P pre-epoch sample failed: '+($samples[-1].Error | Out-String))}
        Add-ActivationAssertion $trial 'PFlushedAndRawCapturedBeforeEpoch' 'PASS' 'Standard-user holder flushed P; independent raw extents matched the independently supplied P bytes before policy update.' $trial.PreScopeP

        try{$trial.TaintCounterBefore=Get-ActivationTaintCounters 'before-window'}catch{$trial.TaintCounterWindow=@{Status='INCONCLUSIVE';Reason=$_.Exception.Message;LiveTestDisableTaint='Unavailable';ProvesNoTaintDecision=$false}}
        $epochBefore=Get-ActivationEpochStatus 'before-policy-update'
        if($null -eq $epochBefore.policyGeneration -or $null -eq $epochBefore.epochGeneration){throw 'Pre-update policy/epoch generation missing.'}
        $runtimePolicy=Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -ErrorAction Stop
        if(@($runtimePolicy.monitoredScopes.destinationPaths).Count -ne 0){throw 'A case runtime policy did not start empty.'}
        $runtimePolicy.version=[int]$runtimePolicy.version+1
        $runtimePolicy.monitoredScopes.destinationPaths=@($protectedDirectory)
        Write-DurableFile $policyPath ($runtimePolicy | ConvertTo-Json -Depth 8)
        $agent=Start-StagedTestAgent $serviceDirectory (Join-Path $evidenceDirectory 'activation-agent') -Arguments '--Diagnostics:StagedProofProxy=true'
        $state.AgentServiceStarted=$true;$state.AgentServiceCreated=[bool]$agent.ServiceCreated;$state.AgentOriginalService=$agent.OriginalService
        Save-State $state $statePath

        $epochAfter=$null;$epochStable=$false;$epochReason='Admission epoch did not advance to a stable quiescent snapshot within 45s.'
        $epochDeadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((45)*[Diagnostics.Stopwatch]::Frequency));$lastEpochKey=$null
        do {
            try {
                $candidate=Get-ActivationEpochStatus 'after-policy-update'
                if([uint32]$candidate.policyGeneration -gt [uint32]$epochBefore.policyGeneration -and
                    [uint32]$candidate.epochGeneration -gt [uint32]$epochBefore.epochGeneration -and
                    [uint32]$candidate.activeCallbacks -eq 0 -and [uint32]$candidate.flags -eq 0){
                    $key=([string]$candidate.policyGeneration)+':'+[string]$candidate.epochGeneration
                    if($key -ceq $lastEpochKey){$epochAfter=$candidate;$epochStable=$true;break}
                    $lastEpochKey=$key
                }else{$lastEpochKey=$null;$epochReason=('Policy/epoch not advanced and quiescent: '+($candidate | ConvertTo-Json -Compress))}
            }catch{$epochReason=$_.Exception.Message;$lastEpochKey=$null}
            Start-Sleep -Milliseconds 100
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $epochDeadline)
        if($null -eq $epochAfter){$epochAfter=Get-ActivationEpochStatus 'last-after-policy-update'}
        $candidatePolicyGeneration=[uint32]$epochAfter.policyGeneration;$script:ActivationCandidateGeneration=$candidatePolicyGeneration
        $epochAdvanced=($epochStable -and [uint32]$epochAfter.policyGeneration -gt [uint32]$epochBefore.policyGeneration -and
            [uint32]$epochAfter.epochGeneration -gt [uint32]$epochBefore.epochGeneration -and
            [uint32]$epochAfter.activeCallbacks -eq 0 -and [uint32]$epochAfter.flags -eq 0)
        Add-ActivationAssertion $trial 'RuntimePendingUnionAndAdmissionEpoch' $(if($epochAdvanced){'PASS'}else{'FAIL'}) 'Runtime SafeUploadAgent startup runs MinifilterInterceptor.TryPushPolicy and BootPolicyRegistryWriter.Apply (pending union, authenticated SET_POLICY, durable commit/clear, final SET_POLICY); require stable advanced policy/epoch generations, flags zero and no active callbacks.' @{Before=$epochBefore;After=$epochAfter;Stable=$epochStable;TimeoutReason=$epochReason;CandidatePath=$target;ServicePid=$agent.Process.Id;ServiceCreated=$agent.ServiceCreated}

        $pendingStatus=$null;$pendingFailure=$null
        try{$pendingStatus=Wait-ActivationProductStatus 'Pending' $candidatePolicyGeneration 45 'while-holder-after-runtime-policy'}catch{$pendingFailure=$_.Exception.Message}

        if($null -ne $pendingStatus){
            $trial.ServicePending=$pendingStatus
            Add-ActivationAssertion $trial 'ServiceReadinessPendingWhileHolderLives' 'PASS'`
                'Authenticated current StatusNotification from the LocalSystem product pipe reported Pending for the accepted destination policy generation while the pre-scope holder remained live.'`
                @{Coverage=$pendingStatus.Value.admissionCoverage;Reason=$pendingStatus.Value.admissionCoverageReason;PolicyGeneration=$pendingStatus.Value.nativePolicyGeneration;ServerPid=$pendingStatus.ServerPid;ServerSid=$pendingStatus.ServerSid;Qpc=$pendingStatus.EndQpc}
        }else{
            $current=Get-ActivationCurrentProductStatus 'pending-timeout-current' 3000
            $knownReady=($current.Status -eq 'OK' -and $current.Value.protectionActive -eq $true -and $current.Value.admissionCoverage -eq 'Ready' -and $null -ne $current.Value.nativePolicyGeneration -and [uint32]$current.Value.nativePolicyGeneration -eq $candidatePolicyGeneration)
            Add-ActivationAssertion $trial 'ServiceReadinessPendingWhileHolderLives' $(if($knownReady){'FAIL'}else{'INCONCLUSIVE'})`
                $(if($knownReady){'Service reported Ready while a pre-scope writable holder was still live.'}else{'Pending status was not observed within 45s: '+$pendingFailure}) $current
        }

        $activating=Get-ActivationPendingEntry $ntPath $fileId 'live-holder' $target
        if($activating.Entries.Count -ne 1){
            Add-ActivationAssertion $trial 'ExactActivatingWriterEvidence' 'FAIL'`
                ('Exact-target activating diagnostic had '+$activating.Entries.Count+' exact path/file-ID matches; expected one Activating entry.') $activating.Snapshot.Record
            throw 'Target did not have one exact activating-status entry while its pre-scope holder lived.'
        }
        $entry=$activating.Entries[0]
        $holderStateGood=($activating.Snapshot.Record.policyGeneration -eq $candidatePolicyGeneration -and
            $activating.Snapshot.Record.matchCount -eq @($activating.Snapshot.Record.entries).Count -and
            $entry.state -ceq 'Activating' -and $entry.fileId -ieq $fileId -and $entry.path -ieq $ntPath -and
            [uint32]$entry.generation -gt 0 -and [uint32]$entry.W -eq 0 -and $entry.unknownReasons -ceq '0x00000000')
        if($CaseId -cin @('A01','A04')){$holderStateGood=$holderStateGood -and [uint32]$entry.H -gt 0 -and $entry.openerPids -contains [int]$actor.Pid}
        else{$holderStateGood=$holderStateGood -and $entry.S -ceq 'YES'}
        if($CaseId -ceq 'A04'){$holderStateGood=$holderStateGood -and [uint32]$entry.H -eq 1 -and [uint32]$entry.C -eq 0 -and [uint32]$entry.T -eq 0}
        $holderEvidenceReason=if($CaseId -cin @('A01','A04')){'Exact-target Inspector point sample identifies the exact NT path, stable file ID, policy generation, Activating state, H>0, and the standard-user actor opener PID.'}else{'Exact-target Inspector point sample identifies the exact NT path, stable file ID, policy generation, Activating state and S=YES; the actor process independently created and retains the view/section after closing its source handle.'}
        Add-ActivationAssertion $trial 'ExactActivatingWriterEvidence' $(if($holderStateGood){'PASS'}else{'FAIL'})`
            $holderEvidenceReason`
            @{Entry=$entry;Snapshot=$activating.Snapshot.Record;ExpectedNtPath=$ntPath;ExpectedFileId=$fileId;ActorPid=$actor.Pid}
        if(-not $holderStateGood){throw 'Exact Activating holder evidence did not match the case contract.'}

        if($CaseId -ceq 'A04'){
            $clearParent=Join-Path $evidenceDirectory 'activation-before-parent-close-clear'
            $null=Invoke-ActivationInspector '--admission-trace-clear' $clearParent 45000
            $parentClose=Publish-ActivationActorCommand $state 'release-holder' $null
            if($parentClose.NativeCode -ne 0 -or -not $parentClose.HolderReleased){throw 'Duplicated primary handle close failed'}
            $afterParent=Get-ActivationPendingEntry $ntPath $fileId 'after-parent-close' $target
            $parentTrace=ConvertFrom-ActivationTrace (Invoke-ActivationInspector '--admission-trace' (Join-Path $evidenceDirectory 'activation-parent-close-trace') 45000) $fileId
            $cleanup=@($parentTrace.Entries | Where-Object event -ceq 'file_cleanup')
            $parentGood=$afterParent.Entries.Count -eq 1 -and $afterParent.Entries[0].state -ceq 'Activating' -and
                [uint32]$afterParent.Entries[0].H -eq 1 -and [uint32]$afterParent.Entries[0].W -eq 0 -and [uint32]$afterParent.Entries[0].C -eq 0 -and [uint32]$afterParent.Entries[0].T -eq 0 -and
                $afterParent.Entries[0].unknownReasons -ceq '0x00000000' -and $afterParent.Entries[0].openerPids -contains [int]$actor.Pid -and $afterParent.Entries[0].openerPids -notcontains [int]$duplicateActor.Pid -and @($afterParent.Entries[0].openerPids).Count -eq 1 -and $cleanup.Count -eq 0
            $trial.ParentClose=@{Receipt=$parentClose;Snapshot=$afterParent;Trace=$parentTrace;ParentStillReportedAsOpener=$afterParent.Entries[0].openerPids -contains [int]$actor.Pid}
            Add-ActivationAssertion $trial 'ParentCloseKeepsSingleHAndActivating' $(if($parentGood){'PASS'}else{'FAIL'}) 'Closing the parent duplicate reference causes no target cleanup, keeps H=1 and Activating while the child owns the live file object; opener PID is not reported as current holder.' $trial.ParentClose
            if(-not $parentGood){throw 'Parent close triggered cleanup/promotion or lost duplicate lifetime evidence'}
        }
        $writerBefore=Get-ActivationWriterState 'before-new-writer-probes'
        $probeActorKey=if($CaseId -ceq 'A04'){'Duplicate'}else{'Primary'}
        $probe=Publish-ActivationActorCommand $state 'probe-new-writers' $null $probeActorKey
        $writerAfter=Get-ActivationWriterState 'after-new-writer-probes'
        $openDenied=([int]$probe.OpenCode -eq 5)
        Add-ActivationAssertion $trial 'NewWritableOpenDenied' $(if($openDenied){'PASS'}else{'FAIL'})`
            ('Standard-user CreateFileW(GENERIC_WRITE, OPEN_EXISTING) returned Win32 '+$probe.OpenCode+'; contract D requires exact access denied 5.') $probe
        $insertedDelta=[uint64]$writerAfter.sectionInFlightInserted-[uint64]$writerBefore.sectionInFlightInserted
        $failedDelta=[uint64]$writerAfter.sectionInFlightRemovedOnFailure-[uint64]$writerBefore.sectionInFlightRemovedOnFailure
        $sectionDenied=([int]$probe.SectionCode -eq 5)
        $sectionCallback=($insertedDelta -eq 1 -and $failedDelta -eq 1)
        if($sectionDenied -and [int]$probe.SectionSourceOpenCode -eq 0 -and $sectionCallback){$sectionVerdict='PASS';$sectionReason='The read-only source open succeeded, PAGE_READWRITE section creation returned exact Win32 access denied 5, and Inspector counters show the corresponding failed section-acquire callback.'}
        elseif($sectionDenied){$sectionVerdict='INCONCLUSIVE';$sectionReason='CreateFileMapping returned Win32 5, but the source-open result and/or exact section-acquire counter deltas do not attribute that denial to contract-D minifilter admission.'}
        else{$sectionVerdict='FAIL';$sectionReason=('New PAGE_READWRITE section attempt returned Win32 '+$probe.SectionCode+'; contract D requires access denied 5.')}
        Add-ActivationAssertion $trial 'NewWritableSectionDenied' $sectionVerdict $sectionReason`
            @{Probe=$probe;SectionInFlightInsertedDelta=$insertedDelta;SectionInFlightRemovedOnFailureDelta=$failedDelta;WriterStateBefore=$writerBefore;WriterStateAfter=$writerAfter}
        $sectionCallbackVerdict=if($sectionDenied -and [int]$probe.SectionSourceOpenCode -eq 0 -and $sectionCallback){'PASS'}elseif($sectionDenied){'INCONCLUSIVE'}else{'FAIL'}
        $sectionCallbackReason=if($sectionCallbackVerdict -eq 'PASS'){'Inspector section-acquire counters show exactly one acquire slot inserted and removed on the failed PAGE_READWRITE section request.'}elseif($sectionDenied -and [int]$probe.SectionSourceOpenCode -eq 5){'A02/A03 must close the original writable source handle; the new read-only source open was denied before a section-acquire callback could be attributed, so callback-specific D evidence is incomplete.'}elseif($sectionDenied){'The exact API denial was observed, but section-acquire counters do not isolate an acquire/reject callback for this request.'}else{'The new PAGE_READWRITE section request was not denied.'}
        Add-ActivationAssertion $trial 'NewWritableSectionAdmissionCallback' $sectionCallbackVerdict $sectionCallbackReason @{SourceOpenCode=$probe.SectionSourceOpenCode;SectionCode=$probe.SectionCode;SectionInFlightInsertedDelta=$insertedDelta;SectionInFlightRemovedOnFailureDelta=$failedDelta}
        $trial.NewWriterProbe=$probe
        $holderReadinessSamples=@()
        for($sampleIndex=0;$sampleIndex -lt 3;$sampleIndex++){$holderReadinessSamples+=Get-ActivationCurrentProductStatus ('holder-readiness-'+$sampleIndex) 3000;Start-Sleep -Milliseconds 200}
        $trial.ReadinessSamplesWhileHolder=@()
        if($null -ne $pendingStatus){$trial.ReadinessSamplesWhileHolder+=@($pendingStatus)}
        $trial.ReadinessSamplesWhileHolder+=@($holderReadinessSamples | Where-Object {$null -ne $_})

        if($CaseId -eq 'A03'){
            $lateMap=Publish-ActivationActorCommand $state 'map-late' $null
            Add-ActivationAssertion $trial 'FirstWritableViewCreatedAfterEpoch' $(if($lateMap.NativeCode -eq 0 -and $lateMap.Mapped){'PASS'}else{'FAIL'})`
                ('First MapViewOfFile after admission epoch returned Win32 '+$lateMap.NativeCode+'.') $lateMap
        }

        $clearOldPrefix=Join-Path $evidenceDirectory ('activation-old-write-trace-clear-'+[guid]::NewGuid().ToString('N'))
        $null=Invoke-ActivationInspector '--admission-trace-clear' $clearOldPrefix 45000
        $changes=@();$changeOffsets=@(64,[int]($pBytes.Length/2),($pBytes.Length-160));$changeIndex=0
        foreach($offset in $changeOffsets){$tag=('ACT-'+$CaseId+'-'+$RunName+'-'+$changeIndex);$payload=[Text.Encoding]::ASCII.GetBytes($tag.PadRight(96,'U'))
            $changes+=@{Offset=[long]$offset;BytesBase64=[Convert]::ToBase64String($payload);PayloadSha256=(Get-ActivationSha256 $payload);Length=$payload.Length};$changeIndex++}
        if($CaseId -ceq 'A04'){$childBefore=Get-ServiceSnapshot 'a04-before-child-write';$handBackBefore=Get-ActivationHandBackInventory $duplicateActor}
        # On failure keep the admission trace of the refused operation (file object, instance, SOP, IRP flags, W tickets).
        try{$oldWrite=Publish-ActivationActorCommand $state 'write-old' @{Changes=$changes} $probeActorKey}
        catch{try{$null=Invoke-ActivationInspector '--admission-trace' (Join-Path $evidenceDirectory 'activation-old-write-failure-trace') 45000}catch{};throw}
        if($CaseId -ceq 'A04'){$childAfter=Get-ServiceSnapshot 'a04-after-child-write';$handBackAfter=Get-ActivationHandBackInventory $duplicateActor;Test-ActivationChildWindow $trial $childBefore $childAfter $oldWrite $handBackBefore $handBackAfter $target $actor $duplicateActor}
        $trial.Operations+=@($oldWrite.Calls);$trial.OldHolderMutation=$oldWrite
        $oldApiGood=($oldWrite.NativeCode -eq 0 -and $oldWrite.FlushCode -eq 0 -and @($oldWrite.Calls | Where-Object NativeCode -ne 0).Count -eq 0)
        Add-ActivationAssertion $trial 'OldHolderMutationAllowedAndRecorded' $(if($oldApiGood){'PASS'}else{'FAIL'})`
            'Old pre-scope handle/view write calls and their required handle/view flush completed successfully while the exact file remained Activating.' $oldWrite
        $preProtectionSample=Capture-InvariantSample $context $baseline 'OldHolderMutationBeforeRelease' 2;$samples+=$preProtectionSample
        if($CaseId -ceq 'A04'){
            $expectedU=[byte[]]$pBytes.Clone()
            foreach($change in $changes){$patch=[Convert]::FromBase64String($change.BytesBase64);[Array]::Copy($patch,0,$expectedU,[int]$change.Offset,$patch.Length)}
            $wholeU=Test-ActivationRawWholeImage $preProtectionSample $target $expectedU
            Add-ActivationAssertion $trial 'ChildMutationExactRawU' $wholeU.Verdict $wholeU.Reason $wholeU
            $trial.ExpectedPreProtectionImage=@{Sha256=(Get-ActivationSha256 $expectedU);Length=$expectedU.Length}
            if($wholeU.Verdict -cne 'PASS'){throw 'Child pre-protection raw image did not prove exact P plus U'}
        }
        if($preProtectionSample.Status -ne 'OK'){Add-ActivationAssertion $trial 'PreProtectionRawMutation' 'INCONCLUSIVE' ('Raw sample after the old-holder write failed: '+($preProtectionSample.Error | Out-String)) $preProtectionSample}
        else{
            $preDifference=Get-ActivationRawDifference $baseline $preProtectionSample $target
            $trial.PreProtectionRawDifference=$preDifference
            $preVerdict=if($preDifference.Status -ne 'OK'){'INCONCLUSIVE'}elseif([long]$preDifference.DifferingBytes -gt 0){'PASS'}else{'INCONCLUSIVE'}
            $preReason=if($preDifference.Status -ne 'OK'){$preDifference.Reason}elseif([long]$preDifference.DifferingBytes -gt 0){'Raw allocated DATA extents changed before promotion; those allowed pre-protection bytes are recorded here and excluded from ForbiddenByteCount.'}else{'Old-holder API and lower write evidence exist, but this raw capture shows no persisted DATA-byte delta before release.'}
            Add-ActivationAssertion $trial 'PreProtectionRawMutation' $preVerdict $preReason $preDifference
        }
        $traceText=Invoke-ActivationInspector '--admission-trace' (Join-Path $evidenceDirectory 'activation-old-holder-admission-trace') 45000
        $trace=ConvertFrom-ActivationTrace $traceText $fileId
        $trial.OldHolderAdmissionTrace=$trace
        if($CaseId -ceq 'A04' -and @($trace.CompletedWritePairs | Where-Object {$_.Begin.targetFileObject -cne $trial.DuplicateSetup.PhysicalObjectProof.Object}).Count){throw 'Child lower writes did not target the trusted shared physical file object'}
        $lowerCorrelations=@()
        foreach($change in $changes){
            $matchingPairs=@()
            foreach($pair in $trace.CompletedWritePairs){
                $lowerStart=[uint64]$pair.Begin.writeOffset;$lowerEnd=$lowerStart+[uint64]$pair.Begin.writeLength
                $expectedStart=[uint64]$change.Offset;$expectedEnd=$expectedStart+[uint64]$change.Length
                $actorMatches=if($CaseId -ceq 'A04'){[uint32]$pair.Begin.pid -eq [uint32]$duplicateActor.Pid}else{($CaseId -ne 'A01' -or [uint32]$pair.Begin.pid -eq [uint32]$actor.Pid)}
                if($actorMatches -and [uint64]$pair.Begin.writeLength -gt 0 -and $lowerEnd -gt $expectedStart -and $lowerStart -lt $expectedEnd){$matchingPairs+=@($pair)}
            }
            $lowerCorrelations+=@{Offset=$change.Offset;Length=$change.Length;PayloadSha256=$change.PayloadSha256;SuccessfulLowerPairs=$matchingPairs}
        }
        $lowerWriteEvidence=(@($lowerCorrelations | Where-Object {$_.SuccessfulLowerPairs.Count -gt 0}).Count -eq $changes.Count)
        Add-ActivationAssertion $trial 'OldHolderLowerCompletion' $(if($lowerWriteEvidence){'PASS'}else{'INCONCLUSIVE'})`
            $(if($lowerWriteEvidence){'Loss-free admission trace contains paired successful lower W_BEGIN/W_END records for the exact target file ID whose byte ranges overlap every known user-mode mutation; A01 also matches the actor PID. A02/A03 accept paging-system PID for the retained section writes.'}else{'The loss-free trace did not correlate a successful lower W_BEGIN/W_END range to every known old-holder mutation on the exact target file ID; user-mode success does not replace lower completion evidence.'})`
            @{Trace=$trace;RangeCorrelations=$lowerCorrelations;PayloadSha256Available=$trace.PayloadSha256Available;ActorOperations=$oldWrite.Calls}
        if($CaseId -cne 'A04'){
        $traceDisablePrefix=Join-Path $evidenceDirectory ('activation-trace-disable-before-release-'+[guid]::NewGuid().ToString('N'))
        $null=Invoke-ActivationInspector '--admission-trace-disable' $traceDisablePrefix 45000
        $traceEnabled=$false
        }

        $activatingAfterWrite=Get-ActivationPendingEntry $ntPath $fileId 'after-old-holder-mutation' $target
        $afterWriteEntries=@($activatingAfterWrite.Entries)
        $stillActivating=($afterWriteEntries.Count -eq 1 -and $activatingAfterWrite.Snapshot.Record.policyGeneration -eq $candidatePolicyGeneration -and
            $afterWriteEntries[0].state -ceq 'Activating' -and $afterWriteEntries[0].fileId -ieq $fileId -and
            [uint32]$afterWriteEntries[0].W -eq 0 -and $afterWriteEntries[0].unknownReasons -ceq '0x00000000')
        if($CaseId -cin @('A01','A04')){$stillActivating=$stillActivating -and [uint32]$afterWriteEntries[0].H -gt 0 -and $afterWriteEntries[0].openerPids -contains [int]$actor.Pid}
        else{$stillActivating=$stillActivating -and $afterWriteEntries[0].S -ceq 'YES'}
        if($CaseId -ceq 'A04'){$stillActivating=$stillActivating -and [uint32]$afterWriteEntries[0].H -eq 1 -and [uint32]$afterWriteEntries[0].C -eq 0 -and [uint32]$afterWriteEntries[0].T -eq 0}
        Add-ActivationAssertion $trial 'OldHolderStillActivatingAfterMutation' $(if($stillActivating){'PASS'}else{'FAIL'}) 'After the tagged old-holder writes and flush completed, the exact same target remained Activating with its holder evidence and W drained to zero.' @{Entries=$afterWriteEntries;Snapshot=$activatingAfterWrite.Snapshot.Record;FileId=$fileId;ActorPid=$actor.Pid;Mutation=$oldWrite}
        if(-not $stillActivating){throw 'Target left Activating or lost exact holder evidence before the old holder was released.'}

        $holderStatusAfterWrite=Get-ActivationCurrentProductStatus 'holder-after-old-write' 3000
        if($holderStatusAfterWrite.Status -eq 'OK' -and $holderStatusAfterWrite.Value.protectionActive -eq $true -and $holderStatusAfterWrite.Value.admissionCoverage -eq 'Ready' -and $null -ne $holderStatusAfterWrite.Value.nativePolicyGeneration -and [uint32]$holderStatusAfterWrite.Value.nativePolicyGeneration -eq $candidatePolicyGeneration){
            Add-ActivationAssertion $trial 'ServiceNeverReadyAtSampleAfterMutation' 'FAIL' 'Service reported Ready while the old-holder mutation completed and the old holder still lived.' $holderStatusAfterWrite
        }
        $trial.ReadinessSamplesWhileHolder+=@($holderStatusAfterWrite)
        $readyWhileHeld=@($trial.ReadinessSamplesWhileHolder | Where-Object {$_.Status -eq 'OK' -and $_.Value.protectionActive -eq $true -and $_.Value.admissionCoverage -eq 'Ready' -and $null -ne $_.Value.nativePolicyGeneration -and [uint32]$_.Value.nativePolicyGeneration -eq $candidatePolicyGeneration})
        $unverifiedReadiness=@($trial.ReadinessSamplesWhileHolder | Where-Object {$_.Status -ne 'OK' -or [uint32]$_.Value.nativePolicyGeneration -ne $candidatePolicyGeneration -or -not $_.Value.protectionActive})
        $readinessSampleVerdict=if($readyWhileHeld.Count -gt 0){'FAIL'}elseif($pendingStatus -and $unverifiedReadiness.Count -eq 0){'PASS'}else{'INCONCLUSIVE'}
        $readinessSampleReason=if($readyWhileHeld.Count -gt 0){'At least one authenticated current service status reported Ready before last-holder release.'}elseif($readinessSampleVerdict -eq 'PASS'){'Every current status sample at the policy-acceptance, pre-mutation, and post-mutation checkpoints was authenticated, active, at the accepted generation, and non-Ready.'}else{'One or more holder-interval service status samples were missing, unauthenticated, inactive, or at another generation; sampled never-Ready evidence is incomplete.'}
        Add-ActivationAssertion $trial 'NoObservedReadyWhileHolderLives' $readinessSampleVerdict $readinessSampleReason @($trial.ReadinessSamplesWhileHolder | ForEach-Object {if($_.Status -eq 'OK'){@{Tag=$_.Tag;Coverage=$_.Value.admissionCoverage;Generation=$_.Value.nativePolicyGeneration;Qpc=$_.EndQpc}}else{@{Tag=$_.Tag;Status=$_.Status;Reason=$_.Reason}}})
        Close-ActivationNotificationCapture
        if($CaseId -ceq 'A04'){$null=Invoke-ActivationInspector '--admission-trace-clear' (Join-Path $evidenceDirectory 'activation-before-child-last-close-clear') 45000}
        $release=Publish-ActivationActorCommand $state 'release-holder' $null $probeActorKey
        if(-not $release.HolderReleased -or $release.NativeCode -ne 0){throw ('Last pre-scope holder release failed: Win32 '+$release.NativeCode)}
        $trial.LastHolderRelease=$release;$script:ActivationHolderLive=$false
        if($CaseId -ceq 'A04'){
            $lastTrace=ConvertFrom-ActivationTrace (Invoke-ActivationInspector '--admission-trace' (Join-Path $evidenceDirectory 'activation-child-last-close-trace') 45000) $fileId
            $cleanupProof=Test-ActivationDuplicateCleanup $lastTrace $trace $duplicateActor $release
            Add-ActivationAssertion $trial 'ChildLastCloseExactlyOneCleanup' $cleanupProof.Verdict $cleanupProof.Reason $cleanupProof
            $null=Invoke-ActivationInspector '--admission-trace-disable' (Join-Path $evidenceDirectory 'activation-child-close-trace-disable') 45000;$traceEnabled=$false
        }

        $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((90)*[Diagnostics.Stopwatch]::Frequency));$promoted=$null;$promotedGood=$false;$promotionReason='No registry-entry sample received after last-holder release.'
        do{
            try{$promoted=Get-ActivationEntry $target 'post-release-registry-entry';$r=$promoted.Record
                $promotedGood=($r.registryEntry -and $r.historyPresent -and $r.nameMatches -and $r.fileId -ieq $fileId -and $r.state -ceq 'Protected' -and $r.free -and
                    [uint32]$r.H -eq 0 -and $r.S -ceq 'NO' -and [uint32]$r.C -eq 0 -and [uint32]$r.T -eq 0 -and $r.unknownReasons -ceq '0x00000000')
                if($promotedGood){break}
                $promotionReason=('Latest exact entry: history='+$r.historyPresent+';fileId='+$r.fileId+';state='+$r.state+';free='+$r.free+';H='+$r.H+';S='+$r.S+';C='+$r.C+';T='+$r.T+';unknown='+$r.unknownReasons)
            }catch{$promotionReason=$_.Exception.Message}
            Start-Sleep -Milliseconds 150
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        if(-not $promotedGood){
            Add-ActivationAssertion $trial 'FreeAndProtectedAfterLastHolder' 'INCONCLUSIVE' ('90s promotion timeout after release; '+$promotionReason) $promoted
            throw ('Promotion timeout after last-holder release: '+$promotionReason)
        }
        Add-ActivationAssertion $trial 'FreeAndProtectedAfterLastHolder' 'PASS'`
            'Exact registry entry for the same file ID reached Protected/Free with H=0, S=NO, C=0, T=0 and no unknown reason after the last actor holder was released.' $promoted.Record

        $promotionText=Invoke-ActivationInspector '--promotion-trace' (Join-Path $evidenceDirectory 'activation-promotion-trace') 45000
        $promotionTrace=ConvertFrom-ActivationPromotionTrace $promotionText $fileId
        $promotionEdges=@($promotionTrace.Entries | Where-Object {[uint32]$_.stateBefore -eq 1 -and [uint32]$_.stateAfter -eq 2})
        $promotionExact=($promotionEdges.Count -eq 1 -and [uint32]$promotionEdges[0].Hsample -eq 0 -and
            [uint32]$promotionEdges[0].Wsample -eq 0 -and [uint32]$promotionEdges[0].Tsample -eq 0 -and
            [uint32]$promotionEdges[0].CforSopSample -eq 0 -and [uint32]$promotionEdges[0].unknownReasonsSample -eq 0)
        Add-ActivationAssertion $trial 'PromotionTraceForSameFileId' $(if($promotionExact){'PASS'}else{'FAIL'})`
            'Loss-free promotion trace contains exactly one ACTIVATING-to-PROTECTED edge for the same target file ID and records H/W/T/C-for-SOP zero and no unknown reason at the promotion sample.'`
            @{Trace=$promotionTrace;TargetEdges=$promotionEdges;RegistryEntry=$promoted.Record}
        if(-not $promotionExact){throw 'Exact promotion trace edge/sample missing or contradicted.'}
        Add-ActivationAssertion $trial 'LiveTaintFlags' 'INCONCLUSIVE'`
            'Inspector epoch status reports only admission-epoch flags; promotion trace reports TEST_DISABLE_TAINT as unavailable (0xffffffff). No driver command reads back live policy Flags.'`
            @{EpochStatus=$epochAfter;PromotionTraceTaintState=$promotionEdges[0].testDisableTaint}

        $readyStatus=$null;$readyFailure=$null
        try{$readyStatus=Wait-ActivationProductStatus 'Ready' $candidatePolicyGeneration 60 'after-protected-promotion'}catch{$readyFailure=$_.Exception.Message}
        if($null -ne $readyStatus){$trial.ServiceReady=$readyStatus;Add-ActivationAssertion $trial 'ServiceReadinessReadyAfterPromotion' 'PASS'`
            'Authenticated current LocalSystem StatusNotification reported Ready at the same accepted native policy generation after exact-file promotion.'`
            @{Coverage=$readyStatus.Value.admissionCoverage;Generation=$readyStatus.Value.nativePolicyGeneration;Reason=$readyStatus.Value.admissionCoverageReason;Qpc=$readyStatus.EndQpc;ServerPid=$readyStatus.ServerPid;ServerSid=$readyStatus.ServerSid}}
        else{
            $current=Get-ActivationCurrentProductStatus 'ready-timeout-current' 3000
            $knownDegraded=($current.Status -eq 'OK' -and $current.Value.protectionActive -eq $true -and $current.Value.admissionCoverage -eq 'Degraded' -and $null -ne $current.Value.nativePolicyGeneration -and [uint32]$current.Value.nativePolicyGeneration -eq $candidatePolicyGeneration)
            Add-ActivationAssertion $trial 'ServiceReadinessReadyAfterPromotion' $(if($knownDegraded){'FAIL'}else{'INCONCLUSIVE'})`
                $(if($knownDegraded){'Service remained Degraded after exact Protected/Free promotion: '+$current.Value.admissionCoverageReason}else{'Ready status was not observed within 60s after promotion: '+$readyFailure}) $current
        }

        $promotionSample=Capture-InvariantSample $context $baseline 'RawImageAtPromotion' 3;$samples+=$promotionSample
        if($promotionSample.Status -ne 'OK'){throw ('Raw image capture after promotion failed: '+($promotionSample.Error | Out-String))}
        $trial.RawPromotionImage=@{FileId=$fileId;Images=$promotionSample.Images;Capture=$promotionSample;AfterProtectedEntry=$promoted.Record;AfterServiceReady=$readyStatus}
        if($CaseId -ceq 'A04'){
            $promotionWhole=Test-ActivationRawWholeImage $promotionSample $target $expectedU
            Add-ActivationAssertion $trial 'PromotionStableExactU' $promotionWhole.Verdict $promotionWhole.Reason $promotionWhole
            if($promotionWhole.Verdict -cne 'PASS'){throw 'A04 promotion did not preserve exact final child U baseline'}
            $approved=Invoke-ActivationApprovedSave $trial $actor $context $baseline $promotionSample $expectedU $target
            $samples+=@($approved.Samples)
        }else{
        $serviceBefore=Get-ServiceSnapshot 'activation-before-unapproved-write'
        $trial.ServiceBefore=$serviceBefore
        if($serviceBefore.Status -ne 'OK'){Add-ActivationAssertion $trial 'PostPromotionOwnedStreamJournal' 'INCONCLUSIVE' ('Before-write product journal snapshot failed: '+(@($serviceBefore.Errors | ForEach-Object {$_.Message}) -join ' / ')) $serviceBefore.Errors}

        $stagePayload=[Text.Encoding]::ASCII.GetBytes(('POSTPROTECT-'+$CaseId+'-'+$RunName+' CPF: 529.982.247-25').PadRight(96,'Z'))
        $stageOffset=[long]([int]($pBytes.Length/2)+256)
        if($stageOffset+$stagePayload.Length -gt $pBytes.Length){$stageOffset=64}
        $stageStartStatus=Get-ActivationCurrentProductStatus 'ready-before-staged-write' 3000
        $stageReply=Publish-ActivationActorCommand $state 'staged-write' @{Offset=$stageOffset;PayloadBase64=[Convert]::ToBase64String($stagePayload);PayloadSha256=(Get-ActivationSha256 $stagePayload)}
        $trial.Operations+=@($stageReply.Calls);$trial.PostPromotionWrite=$stageReply
        $stageApiGood=($stageReply.NativeCode -eq 0 -and $stageReply.FlushCode -eq 0 -and $stageReply.CloseCode -eq 0 -and [long]$stageReply.BytesWritten -eq $stagePayload.Length)
        $stageSample=Capture-InvariantSample $context $baseline 'AfterUnapprovedPostPromotionWrite' 4;$samples+=$stageSample
        $samplesAfter=Get-ServiceSnapshot 'activation-after-unapproved-write'
        $trial.ServiceAfter=$samplesAfter
        $windowKnown=($serviceBefore.Status -ceq 'OK' -and $samplesAfter.Status -ceq 'OK' -and
            $serviceBefore.BootId -ceq $samplesAfter.BootId -and $serviceBefore.QpcFrequency -eq $samplesAfter.QpcFrequency -and
            $serviceBefore.EndQpc -le $stageReply.StartQpc -and $stageReply.EndQpc -le $samplesAfter.StartQpc -and
            $serviceBefore.BootId -ceq $stageReply.BootId -and $serviceBefore.QpcFrequency -eq $stageReply.QpcFrequency)
        $journalDelta=Test-ServiceJournalDelta $serviceBefore $samplesAfter $windowKnown
        $newTransfers=@($journalDelta.NewEntries | Where-Object {$_.Entry.Transfer.DestinationPath -ieq $target -and [int]$_.Entry.Transfer.ProcessId -eq [int]$actor.Pid})
        $stagePathProof=$null
        if($newTransfers.Count -eq 1){$stagePathProof=Get-ActivationOwnedStagePathProof $newTransfers[0].Entry.Transfer}
        $journalRouted=($journalDelta.Complete -and $newTransfers.Count -eq 1 -and $newTransfers[0].StateName -ceq 'Blocked' -and $stagePathProof.Verdict -ceq 'PASS')
        $journalPublished=@($newTransfers | Where-Object {$_.StateName -in @('Approved','Publishing','Released')}).Count -gt 0
        $trial.ServiceJournalProof=@{BeforeStatus=$serviceBefore.Status;AfterStatus=$samplesAfter.Status;WindowKnown=$windowKnown;Complete=$journalDelta.Complete;
            Failures=@($journalDelta.Failures);Findings=@($journalDelta.Findings);OwnedStagePath=$stagePathProof;NewExactActorTransfers=@($newTransfers | ForEach-Object {@{Path=$_.Entry.Transfer.DestinationPath;TransferId=$_.Entry.Transfer.TransferId;ProcessId=$_.Entry.Transfer.ProcessId;State=$_.StateName;StagePath=$_.Entry.Transfer.StagePath}})}
        if($journalRouted){Add-ActivationAssertion $trial 'OwnedStreamJournalForExactDestination' 'PASS'`
            'Authenticated current journal delta contains exactly one new transfer for the exact destination and standard-user actor PID; its state is Blocked and its StagePath is under the product staging root with the allocator GUID filename.' $trial.ServiceJournalProof}
        elseif($journalDelta.Findings.Count -gt 0){Add-ActivationAssertion $trial 'OwnedStreamJournalForExactDestination' 'FAIL' ('Authenticated new product journal evidence contradicts the current schema or route: '+(@($journalDelta.Findings) -join ' ')) $trial.ServiceJournalProof}
        elseif($journalPublished){Add-ActivationAssertion $trial 'OwnedStreamJournalForExactDestination' 'FAIL' 'Authenticated journal state is Approved, Publishing, or Released for the exact standard-user transfer.' $trial.ServiceJournalProof}
        elseif($stagePathProof -and $stagePathProof.Verdict -eq 'FAIL'){Add-ActivationAssertion $trial 'OwnedStreamJournalForExactDestination' 'FAIL' $stagePathProof.Reason $trial.ServiceJournalProof}
        elseif($stagePathProof -and $stagePathProof.Verdict -eq 'INCONCLUSIVE'){Add-ActivationAssertion $trial 'OwnedStreamJournalForExactDestination' 'INCONCLUSIVE' $stagePathProof.Reason $trial.ServiceJournalProof}
        elseif($journalDelta.Complete -and $newTransfers.Count -eq 1){Add-ActivationAssertion $trial 'OwnedStreamJournalForExactDestination' 'INCONCLUSIVE' ('The exact owned transfer is still '+$newTransfers[0].StateName+' at the complete after-snapshot; terminal Blocked state was not observed.') $trial.ServiceJournalProof}
        elseif($journalDelta.Complete){Add-ActivationAssertion $trial 'OwnedStreamJournalForExactDestination' 'FAIL' ('Complete journal delta did not contain exactly one transfer for '+$target+' by actor PID '+$actor.Pid+'.') $trial.ServiceJournalProof}
        else{Add-ActivationAssertion $trial 'OwnedStreamJournalForExactDestination' 'INCONCLUSIVE' ('Product journal delta incomplete: '+(@($journalDelta.Failures) -join ' ')) $trial.ServiceJournalProof}
        $routeVerdict=if(-not $stageApiGood){'FAIL'}elseif($journalRouted){'PASS'}elseif($journalPublished){'FAIL'}elseif($stagePathProof -and $stagePathProof.Verdict -eq 'FAIL'){'FAIL'}elseif($stagePathProof -and $stagePathProof.Verdict -eq 'INCONCLUSIVE'){'INCONCLUSIVE'}elseif($journalDelta.Complete -and $newTransfers.Count -eq 1){'INCONCLUSIVE'}elseif($journalDelta.Complete){'FAIL'}else{'INCONCLUSIVE'}
        $routeReason=if(-not $stageApiGood){'Post-promotion standard-user open/write/flush/close failed or reported a short write.'}elseif($journalRouted){'The standard-user post-promotion write completed; the exact current journal transfer is Blocked and its StagePath is under the product staging root.'}elseif($journalPublished){'The exact standard-user transfer reached Approved, Publishing, or Released; this contradicts the required unapproved blocked-write outcome.'}elseif($stagePathProof -and $stagePathProof.Verdict -ne 'PASS'){$stagePathProof.Reason}elseif($journalDelta.Complete -and $newTransfers.Count -eq 1){'The exact owned transfer is still '+$newTransfers[0].StateName+' at the complete after-snapshot checkpoint.'}elseif($journalDelta.Complete){'The complete current journal delta did not prove exactly one transfer for the exact destination and actor PID.'}else{'The post-promotion write completed, but the product journal window is incomplete: '+(@($journalDelta.Failures) -join ' ')}
        Add-ActivationAssertion $trial 'PostPromotionUnapprovedWriteRoutedToOwnedStream' $routeVerdict $routeReason @{Write=$stageReply;Journal=$trial.ServiceJournalProof}

        $trial.PostPromotionRawDifference=Get-ActivationRawDifference ([pscustomobject]@{Images=$promotionSample.Images}) $stageSample $target
        if($stageSample.Status -ne 'OK' -or $trial.PostPromotionRawDifference.Status -ne 'OK'){
            $trial.ForbiddenByteCount=$null
            Add-ActivationAssertion $trial 'PostPromotionRawDestinationUnchanged' 'INCONCLUSIVE'`
                ('Post-protection raw extent sample/comparison incomplete: '+$trial.PostPromotionRawDifference.Reason) $trial.PostPromotionRawDifference
        }else{
            $trial.ForbiddenByteCount=[long]$trial.PostPromotionRawDifference.DifferingBytes
            Add-ActivationAssertion $trial 'PostPromotionRawDestinationUnchanged' $(if($trial.ForbiddenByteCount -eq 0){'PASS'}else{'FAIL'})`
                $(if($trial.ForbiddenByteCount -eq 0){'Every raw allocated DATA extent matches the captured image at promotion after the unapproved staged write; ForbiddenByteCount counts post-Protected differences only.'}else{'Raw allocated DATA extent changed after Protected; ForbiddenByteCount counts those post-Protected differing bytes only.'}) $trial.PostPromotionRawDifference
        }
        if($stageStartStatus.Status -eq 'OK' -and $stageStartStatus.Value.protectionActive -eq $true -and $stageStartStatus.Value.admissionCoverage -eq 'Ready' -and $null -ne $stageStartStatus.Value.nativePolicyGeneration -and [uint32]$stageStartStatus.Value.nativePolicyGeneration -eq $candidatePolicyGeneration){
            Add-ActivationAssertion $trial 'ServiceStillReadyDuringOwnedWrite' 'PASS' 'Product readiness remained Ready at the accepted generation before the unapproved staged write.' $stageStartStatus
        }else{Add-ActivationAssertion $trial 'ServiceStillReadyDuringOwnedWrite' 'INCONCLUSIVE' 'Current service status immediately before the staged write was not a verified Ready status at the accepted generation.' $stageStartStatus}
        if($stageSample.Status -ne 'OK'){Add-ActivationAssertion $trial 'PostPromotionRawDestinationUnchanged' 'INCONCLUSIVE' ('Post-write raw observer sample failed: '+($stageSample.Error | Out-String)) $stageSample}

        }
        Add-ActivationAssertion $trial 'NeverReadyWholeHolderInterval' 'INCONCLUSIVE'`
            'Sampled current service pipe statuses were Pending, but StatusNotification has no file identity or holder counters and the durable notification record retains only notification kind; there is no loss-detecting per-file readiness event sequence for the full holder interval.'`
            @{Samples=@($trial.ReadinessSamplesWhileHolder | ForEach-Object {if($_.Status -eq 'OK'){@{Coverage=$_.Value.admissionCoverage;Generation=$_.Value.nativePolicyGeneration;Qpc=$_.EndQpc}}else{@{Status=$_.Status;Reason=$_.Reason}}});Source='MinifilterInterceptor.cs PublishAdmissionCoverageLoopAsync; AgentNotification.cs StatusNotification; NotificationRecord.cs'}
        $trial.ExpectedTimeline=@{CaseId=$CaseId;Points=@('Unscoped P flushed and raw captured','Runtime agent policy apply adds the one destination scope','Exact target remains Activating with actor holder evidence','New writable opens and section acquisition denied','Old holder mutation logged before release','Free/Protected after last holder release','Service Ready at accepted generation','Unapproved post-promotion write routed to an owned stream','Raw destination DATA extents unchanged after promotion');
            WriterIdentities=@($actor);ExternalEvidence=@{Build=$trial.Platform.Build;PrepareBootId=$state.PrepareBootId;ActiveBootId=$context.BootId;
                ObserverPid=$trial.Platform.ObserverPid;ObserverSid=$trial.Platform.ObserverSid;ObserverProcess=$trial.Platform.ObserverProcess;ActorProvenance=$trial.ActorProvenance};
            AllowedPreProtectionMutationBytes=$(if($null -ne $trial.PreProtectionRawDifference){$trial.PreProtectionRawDifference.DifferingBytes}else{$null});
            ForbiddenByteAccounting='PostPromotionRawDifference only; pre-protection bytes are excluded';TargetFileId=$fileId;TargetDosPath=$target;TargetNtPath=$ntPath}
        $trial.Reasons=@('StatusNotification and durable notification evidence do not provide a per-file H/S/C/T/W holder event sequence; whole-interval never-Ready proof is INCONCLUSIVE.','The admission trace binds successful lower write ranges to the exact file ID, and raw extents prove pre-protection mutation, but it carries no lower payload digest; exact U payload-content correlation is deferred.','Inspector promotion evidence reports TEST_DISABLE_TAINT unavailable (0xffffffff); required live-policy Flags readback remains INCONCLUSIVE.')
        $trial.Actor=$actor;$trial.ReadinessAfter=Get-ActivationCurrentProductStatus 'final-current-status' 3000
        $trial.VerifierAfter=Get-VerifierEvidence 'activation-after' -RequireMode
    }catch{
        $trial.Errors+=Get-ErrorChain $_.Exception
        if(@($trial.Assertions | Where-Object Name -eq 'ActivationObservationCompleted').Count -eq 0){Add-ActivationAssertion $trial 'ActivationObservationCompleted' 'INCONCLUSIVE' ('A case stopped at the first missing/invalid bounded observation: '+$_.Exception.Message) $null}
    }finally{
        try{Close-ActivationNotificationCapture}catch{$trial.Errors+=Get-ErrorChain $_.Exception;Add-ActivationAssertion $trial 'NotificationCaptureCleanup' 'INCONCLUSIVE' $_.Exception.Message $null}
        if($duplicateStarted){
            try{
                $duplicateExit=Publish-ActivationActorCommand $state 'exit-worker' $null 'Duplicate'
                $slot=$state.ActivationActors.Duplicate
                $duplicateCompletion=Wait-TaskCompletion $slot.Task (Join-Path $slot.Directory 'completion.clixml') $slot.Token 45
                if($duplicateExit.NativeCode -ne 0 -or -not $duplicateExit.HolderReleased){throw 'Duplicate actor release failed'}
                $trial.DuplicateCompletion=@{Receipt=$duplicateExit;Completion=$duplicateCompletion};$duplicateStarted=$false
            }catch{$trial.Errors+=Get-ErrorChain $_.Exception;Add-ActivationAssertion $trial 'DuplicateActorCleanup' 'INCONCLUSIVE' $_.Exception.Message $null}
        }
        if($actorStarted){
            try{$exitReply=Publish-ActivationActorCommand $state 'exit-worker' $null;$actorStarted=$false
                if(-not $exitReply.HolderReleased -or $exitReply.NativeCode -ne 0){throw ('Activation actor holder cleanup failed: Win32 '+$exitReply.NativeCode)}
                $completion=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken 45
                $trial.ActorTaskCompletion=@{ExitCode=$completion.ExitCode;BootId=$completion.BootId;HolderReleased=$exitReply.HolderReleased};$script:ActivationHolderLive=$false}
            catch{$trial.Errors+=Get-ErrorChain $_.Exception;Add-ActivationAssertion $trial 'ActorCleanup' 'INCONCLUSIVE' ('Could not prove the activation actor exited and released all handles: '+$_.Exception.Message) $null}
        }
        if($null -ne $trial.TaintCounterBefore){
            try{$trial.TaintCounterWindow=Get-ActivationTaintCounterDelta $trial.TaintCounterBefore (Get-ActivationTaintCounters 'after-window')}
            catch{$trial.TaintCounterWindow=@{Status='INCONCLUSIVE';Reason=$_.Exception.Message;Before=$trial.TaintCounterBefore;LiveTestDisableTaint='Unavailable';ProvesNoTaintDecision=$false}}
        }
        $trial.NotificationStatusHistory=@($script:ActivationNotificationHistory)
        if(@($script:ActivationObservedPrematureReady).Count -gt 0){Add-ActivationAssertion $trial 'NoObservedReadyWhileHolderLives' 'FAIL' 'Authenticated Ready frame was received for the accepted generation while the exact holder remained live; subsequent Pending cannot erase it.' @($script:ActivationObservedPrematureReady)}
        if($null -ne $agent){
            try{Stop-StagedTestAgent $agent;$state.AgentServiceStarted=$false;Save-State $state $statePath;$agent=$null}
            catch{$trial.Errors+=Get-ErrorChain $_.Exception;Add-ActivationAssertion $trial 'AgentServiceCleanup' 'INCONCLUSIVE' ('Could not stop/restore the test SafeUploadAgent service: '+$_.Exception.Message) $null}
        }
        if($traceEnabled){try{$disablePrefix=Join-Path $evidenceDirectory ('activation-trace-final-disable-'+[guid]::NewGuid().ToString('N'));$null=Invoke-ActivationInspector '--admission-trace-disable' $disablePrefix 45000;$traceEnabled=$false}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($null -ne $context -and $context.Status -eq 'OK'){$trial.Disposal=Close-InvariantObserver $context}
        else{$trial.Disposal=[pscustomobject]@{Status='INCONCLUSIVE';Reason='Raw observer was not opened successfully.'}}
        if($trial.Disposal.Status -ne 'OK'){Add-ActivationAssertion $trial 'Disposal' 'INCONCLUSIVE' 'Checked raw observer disposal is missing or failed.' $trial.Disposal}
        if(@($trial.Assertions | Where-Object Name -eq 'LiveTaintFlags').Count -eq 0){Add-ActivationAssertion $trial 'LiveTaintFlags' 'INCONCLUSIVE' 'No promotion/readback was available to verify current live TEST_DISABLE_TAINT flags.' $null}
        if(@($trial.Assertions | Where-Object Name -eq 'NeverReadyWholeHolderInterval').Count -eq 0){Add-ActivationAssertion $trial 'NeverReadyWholeHolderInterval' 'INCONCLUSIVE' 'No authenticated, loss-detecting per-file readiness event stream covers the holder interval.' $null}
        $trial.Baseline=$baseline;$trial.Samples=$samples
        $trial.Verdict=if(@($trial.Assertions | Where-Object Verdict -eq 'FAIL').Count -gt 0){'FAIL'}elseif(@($trial.Assertions | Where-Object Verdict -eq 'INCONCLUSIVE').Count -gt 0){'INCONCLUSIVE'}else{'PASS'}
        Save-State $trial $trialPath
        'ActivationCaseVerdict='+$trial.Verdict
    }
}
function Get-CachedSecondUserBody {
@'
$env:TEMP='__DIRECTORY__';$env:TMP=$env:TEMP
Add-Type -TypeDefinition @"
using System;using System.Diagnostics;using System.Runtime.InteropServices;
public static class SUSecondUser {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct FIND {
  public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
  public uint High,Low,Reserved1,Reserved2;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string Name;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=14)] public string Alternate;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr FindFirstFileW(string p,out FIND data);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool FindClose(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr h,int c,out int v,int n,out int r);
 public static bool Elevated(IntPtr token){int v,r;if(!GetTokenInformation(token,20,out v,4,out r))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return v!=0;}
 public static int Open(string path,bool write){
  IntPtr h=CreateFileW(path,write?0x40000000u:0x80000000u,7,IntPtr.Zero,3,0x80,IntPtr.Zero);
  if(h==new IntPtr(-1))return Marshal.GetLastWin32Error();CloseHandle(h);return 0;
 }
 public static int List(string folder){FIND data;IntPtr h=FindFirstFileW(folder+"\\*",out data);
  if(h==new IntPtr(-1))return Marshal.GetLastWin32Error();FindClose(h);return 0;
 }
}
"@
$directory='__DIRECTORY__';$token='__TOKEN__';$sid='__SID__'
function Wait-SecondBarrier([string]$Leaf){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while(-not(Test-Path -LiteralPath (Join-Path $directory $Leaf))){
        if(Test-Path -LiteralPath (Join-Path $directory 'cancel')){throw 'Second-user probe cancelled'}
        if($watch.ElapsedMilliseconds -ge 180000){throw ('Second-user barrier timeout: '+$Leaf)};Start-Sleep -Milliseconds 20
    }
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try{
    $actor=@{Pid=$PID;Sid=$identity.User.Value;Elevated=[SUSecondUser]::Elevated($identity.Token);IsAdministrator=(@($identity.Groups | Where-Object Value -eq 'S-1-5-32-544').Count -gt 0);
        SessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId;BootId=(Get-BootId)}
    if($actor.Sid -cne $sid -or $actor.Elevated -or $actor.IsAdministrator){throw 'Second-user standard token mismatch'}
    Write-DurableFile (Join-Path $directory 'identity.clixml') ([Management.Automation.PSSerializer]::Serialize($actor,32)) -New
    Wait-SecondBarrier 'probe-go'
    $probe=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText('__PROBE__'))
    $calls=@()
    foreach($kind in @('read','write','list')){
        $path=if($kind -ceq 'list'){$probe.Folder}else{$probe.File};$start=[Diagnostics.Stopwatch]::GetTimestamp()
        # Not $code: the task launcher's exit status variable shares this scope (b18r6 exited 5).
        $nativeCode=if($kind -ceq 'list'){[SUSecondUser]::List($path)}else{[SUSecondUser]::Open($path,($kind -ceq 'write'))}
        $calls+=@{Class=$kind;Path=$path;NativeCode=$nativeCode;StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
    }
    $value=@{Pid=$PID;Sid=$actor.Sid;BootId=$actor.BootId;Token=$token;Actor=$actor;Calls=$calls;Qpc=[Diagnostics.Stopwatch]::GetTimestamp()}
    Write-DurableFile (Join-Path $directory 'probe.clixml') ([Management.Automation.PSSerializer]::Serialize($value,32)) -New
    Wait-SecondBarrier 'finish'
}finally{$identity.Dispose()}
'@
}
function Initialize-CachedSecondUser {
    $name='su'+[guid]::NewGuid().ToString('N').Substring(0,12);$directory=Join-Path $stateDirectory 'second-user'
    $state.SecondUser=@{Name=$name;Sid=$null;Profile=$null;Directory=$directory;Task=($writerTask+'-second-user');Token=[guid]::NewGuid().ToString('N')}
    Save-State $state $statePath
    $password='Su!'+[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N')
    $user=New-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires
    $state.SecondUser.Sid=$user.SID.Value;Save-State $state $statePath
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name;Set-ActorBatchLogon $state.SecondUser.Sid $true
    if(@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object SID -eq $user.SID).Count){throw 'Second-user administrator membership'}
    $profile=[Text.StringBuilder]::new(260);$hr=[SUProfile]::CreateProfile($state.SecondUser.Sid,$name,$profile,260)
    if($hr -ne 0){throw ('Second-user profile creation failed: 0x'+$hr.ToString('X8'))}
    $state.SecondUser.Profile=$profile.ToString();Save-State $state $statePath
    New-Item -ItemType Directory -Path $directory | Out-Null
    & icacls.exe $stateDirectory /grant ('*'+$state.SecondUser.Sid+':RX') | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Second-user traversal ACL failed'}
    & icacls.exe $directory /grant ('*'+$state.SecondUser.Sid+':(OI)(CI)M') | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Second-user coordination ACL failed'}
    $launcher=Join-Path $stateDirectory 'second-user.ps1';$probe=Join-Path $stateDirectory 'second-user-probe.clixml'
    $body=(Get-CachedSecondUserBody).Replace('__DIRECTORY__',(ConvertTo-PowerShellLiteral $directory)).Replace('__SID__',$state.SecondUser.Sid).Replace('__TOKEN__',$state.SecondUser.Token).Replace('__PROBE__',(ConvertTo-PowerShellLiteral $probe))
    Write-DurableFile $launcher (New-TaskLauncher $body $state.SecondUser.Token (Join-Path $directory 'completion.clixml')) -New
    & icacls.exe $launcher /grant ('*'+$state.SecondUser.Sid+':R') | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Second-user launcher read ACL failed'}
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$launcher+'"')
    Register-ScheduledTask -TaskName $state.SecondUser.Task -Action $action -User ($env:COMPUTERNAME+'\'+$name) -Password $password -RunLevel Limited -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(5))) | Out-Null
    $password=$null
}
function Test-CachedSecondUserDenial($Receipt,$SecondActor,[string]$OwnerSid,[string]$Token,[string]$File,[string]$Folder,[long]$GoQpc) {
    $calls=@($Receipt.Calls);$good=$null -ne $Receipt -and $SecondActor.Sid -cne $OwnerSid -and -not $SecondActor.Elevated -and -not $SecondActor.IsAdministrator -and
        $Receipt.Pid -eq $SecondActor.Pid -and $Receipt.Sid -ceq $SecondActor.Sid -and $Receipt.BootId -ceq $SecondActor.BootId -and $Receipt.Token -ceq $Token -and
        ($calls.Class -join ',') -ceq 'read,write,list'
    $previous=$GoQpc
    foreach($call in $calls){
        $wanted=if($call.Class -ceq 'list'){$Folder}else{$File}
        if($call.Path -cne $wanted -or $null -eq $call.NativeCode -or $call.NativeCode -ne 5 -or $null -eq $call.StartQpc -or
            $call.StartQpc -lt $previous -or $null -eq $call.EndQpc -or $call.EndQpc -lt $call.StartQpc){$good=$false};$previous=$call.EndQpc
    }
    return @{Name='C01HandBackSecondUserAccess';Verdict=$(if($good -and $calls.Count -eq 3){'PASS'}else{'FAIL'});Reason=('Different standard user opens verified H for read/write and lists its folder: each requires Win32:5; observed '+(@($calls | ForEach-Object {$_.Class+'='+$_.NativeCode}) -join ', '));Evidence=$Receipt}
}
function Invoke-CachedSecondUserDenial($Actor,$HandBack,[string]$Digest) {
    $files=@($HandBack.Files | Where-Object {$_.Sha256 -ceq $Digest -and $_.NoReparse -eq $true -and $_.SingleLink -eq $true})
    if($files.Count -ne 1 -or @($HandBack.Assertions | Where-Object Verdict -cne 'PASS').Count){throw 'Second-user check requires one independently verified hand-back copy'}
    $owned=$state.SecondUser;if($null -eq $owned){throw 'Second-user preparation missing'}
    Save-State @{File=$files[0].Path;Folder=$HandBack.Root} (Join-Path $stateDirectory 'second-user-probe.clixml')
    & icacls.exe (Join-Path $stateDirectory 'second-user-probe.clixml') /grant ('*'+$owned.Sid+':R') | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Second-user probe read ACL failed'}
    Start-ScheduledTask -TaskName $owned.Task
    try{
        $second=Wait-WriterIdentity (Join-Path $owned.Directory 'identity.clixml') 60
        if($second.Sid -cne $owned.Sid -or $second.Sid -ceq $Actor.Sid -or $second.Elevated -or $second.IsAdministrator -or $second.BootId -cne $Actor.BootId){throw 'Second-user OS identity invalid'}
        $trial.SecondUser=@{Actor=$second;Provenance=(Get-CachedSecondUserProvenance $second)}
        $go=[Diagnostics.Stopwatch]::GetTimestamp();Write-DurableFile (Join-Path $owned.Directory 'probe-go') $RunName -New
        $receipt=Wait-WriterIdentity (Join-Path $owned.Directory 'probe.clixml') 60;$trial.SecondUser.Receipt=$receipt
        $assertion=Test-CachedSecondUserDenial $receipt $second $Actor.Sid $owned.Token $files[0].Path $HandBack.Root $go
        Write-DurableFile (Join-Path $owned.Directory 'finish') $RunName -New
        $trial.SecondUser.Completion=Wait-TaskCompletion $owned.Task (Join-Path $owned.Directory 'completion.clixml') $owned.Token 60
        $HandBack.SecondUserAccess=$receipt
        return $assertion
    }finally{
        foreach($leaf in @('cancel','finish')){if(-not(Test-Path -LiteralPath (Join-Path $owned.Directory $leaf))){Write-DurableFile (Join-Path $owned.Directory $leaf) $RunName -New}}
    }
}
function Get-CachedSecondUserProvenance($Actor) {
    $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$Actor.Pid) -ErrorAction Stop
    if($null -eq $process -or $process.SessionId -ne $Actor.SessionId -or $process.CommandLine -notlike ('*'+(Join-Path $stateDirectory 'second-user.ps1')+'*')){throw 'Second-user process/session provenance mismatch'}
    $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
    if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $state.SecondUser.Sid){throw 'Second-user OS SID mismatch'}
    if(@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object {$_.SID.Value -ceq $state.SecondUser.Sid}).Count){throw 'Second-user administrator membership'}
    return @{Pid=$process.ProcessId;SessionId=$process.SessionId;OwnerSid=$owner.Sid;CommandLine=$process.CommandLine;Task=(Get-ScheduledTask -TaskName $state.SecondUser.Task | Select-Object TaskName,Principal,State)}
}
function Remove-CachedSecondUserProfile([switch]$AfterReboot) {
    if($null -eq $state.SecondUser -or [string]::IsNullOrWhiteSpace($state.SecondUser.Sid)){return}
    $sid=$state.SecondUser.Sid
    if(-not $AfterReboot){
        foreach($process in @(Get-CimInstance Win32_Process)){
            try{$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop}catch{continue}
            if($owner.Sid -ceq $sid){Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue}
        }
        $watch=[Diagnostics.Stopwatch]::StartNew()
        while(@(Get-CimInstance Win32_UserProfile | Where-Object {$_.SID -ceq $sid -and $_.Loaded}).Count -and $watch.ElapsedMilliseconds -lt 90000){Start-Sleep -Milliseconds 500}
    }
    $profiles=@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $sid)
    if(@($profiles | Where-Object Loaded).Count){
        if($AfterReboot){throw 'Second-user profile loaded after restoration reboot'}
        $state.SecondUser.ProfileDeletionDeferred=$true;Save-State $state $statePath;return
    }
    foreach($profile in $profiles){Remove-CimInstance -InputObject $profile}
    if(@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $sid).Count -or ($state.SecondUser.Profile -and (Test-Path -LiteralPath $state.SecondUser.Profile))){throw 'Second-user profile residue'}
}
function Remove-CachedSecondUser {
    if($null -eq $state.SecondUser){return}
    if($state.SecondUser.Sid){Set-ActorBatchLogon $state.SecondUser.Sid $false}
    if(Get-LocalUser -Name $state.SecondUser.Name -ErrorAction SilentlyContinue){Remove-LocalUser -Name $state.SecondUser.Name}
    if(Get-LocalUser -Name $state.SecondUser.Name -ErrorAction SilentlyContinue){throw 'Second-user account residue'}
}
function Get-B01WriterBody {
    $body=(Get-WriterBody).Replace('180*[Diagnostics.Stopwatch]::Frequency','600*[Diagnostics.Stopwatch]::Frequency').Replace('((180)*[Diagnostics.Stopwatch]::Frequency)','((600)*[Diagnostics.Stopwatch]::Frequency)')
    $anchor="            if(-not `$config.DedicatedUnheldLatency){Wait-ActorBarrier 'close'}"
    if(([regex]::Matches($body,[regex]::Escape($anchor))).Count -ne 1){throw 'B01 held writer anchor missing/ambiguous'}
    $attack=@'
            Wait-ActorBarrier 'b01-junction-go'
            $attack=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText((Join-Path $config.CoordinationDirectory 'b01-attack.clixml')))
            $sentinel=$config.Source.Substring(0,$config.Source.LastIndexOf('\'))
            [IO.File]::WriteAllBytes((Join-Path $sentinel 'marker.txt'),[Convert]::FromBase64String($config.B01SentinelBase64))
            [IO.File]::WriteAllBytes((Join-Path $sentinel $attack.Leaf),[Convert]::FromBase64String($config.B01SentinelBase64))
            [void][IO.Directory]::CreateDirectory((Join-Path $actor.Profile 'SafeUpload'))
            [void][IO.Directory]::CreateDirectory($handBackRoot)
            # Only this actor's newly created, empty directory is replaced.
            [IO.Directory]::Delete($handBackRoot,$false)
            $junctionOutput=(& cmd.exe /d /c ('mklink /J "'+$handBackRoot+'" "'+$sentinel+'"') 2>&1 | Out-String);$junctionCode=$LASTEXITCODE
            $junction=Get-Item -LiteralPath $handBackRoot -Force
            Save-ActorReceipt 'b01-junction.clixml' $calls $privateDigest @{Root=$handBackRoot;Sentinel=$sentinel;Leaf=$attack.Leaf;ExitCode=$junctionCode;Output=$junctionOutput;
                Reparse=(($junction.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0);Target=@($junction.Target);Held=$true}
'@
    # Never follow the hostile hand-back path as an owner-verification read.
    return $body.Replace($anchor,($attack+"`n"+$anchor)).Replace('$handBackAfter=Get-ActorHandBack','$handBackAfter=@()')
}
function Test-B01JunctionReceipt($Receipt,$Actor,[string]$Token,[string]$Sentinel,[string]$Leaf,[long]$GoQpc) {
    $good=$null -ne $Receipt -and $Receipt.Pid -eq $Actor.Pid -and $Receipt.Sid -ceq $Actor.Sid -and $Receipt.BootId -ceq $Actor.BootId -and
        $Receipt.Token -ceq $Token -and $Receipt.Root -ceq (Join-Path $Actor.Profile 'SafeUpload\_bloqueados') -and $Receipt.Sentinel -ceq $Sentinel -and
        $Receipt.Leaf -ceq $Leaf -and $Receipt.ExitCode -eq 0 -and $Receipt.Reparse -eq $true -and $Receipt.Held -eq $true -and
        @($Receipt.Target).Count -eq 1 -and $Receipt.Target[0] -ieq $Sentinel -and $Receipt.Qpc -ge $GoQpc
    return @{Name='B01JunctionArmed';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Exact standard actor replaced its empty hand-back folder with the sentinel junction while private writer stays held.';Evidence=$Receipt}
}
function Test-B01FailedHandBack($Entry,[string]$Digest,[string]$Sid) {
    $good=$null -ne $Entry -and $Entry.State -eq 6 -and $Entry.SealedOnce -eq $true -and $Entry.Sha256Hex -ceq $Digest -and
        $Entry.Transfer.RequestorSid -ceq $Sid -and $Entry.HandbackState -eq 3 -and $Entry.HandbackFailureReason -ceq 'handback_failed' -and
        $null -eq $Entry.HandbackPath -and $Entry.StageDeleted -eq $false -and $Entry.StageCleanupStarted -eq $false -and
        ($Entry.StateHistory.State -join ',') -ceq '0,1,2,6'
    return @{Name='B01FailedHandBack';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Authenticated Blocked exact snapshot: HandbackState=Failed, handback_failed reason, null hand-back path, staging retained, no Approved/Released.';Evidence=$Entry}
}
function Test-B01FailureNotification($Proof,[string]$TransferId,[int]$SessionId,[string]$Digest) {
    $entries=@($Proof.Emissions | Where-Object {$_.Entry.Kind -ceq 'Transfer' -and $_.Entry.TransferId -ieq $TransferId})
    $blocked=@($entries | Where-Object {$_.Entry.Phase -ceq 'Blocked'})
    $bad=@($entries | Where-Object {$_.Entry.TargetSessionId -ne $SessionId -or $_.Entry.Phase -ceq 'Released' -or
        -not [string]::IsNullOrWhiteSpace($_.Entry.HandBackPath) -or ($_.Entry.Phase -ceq 'Blocked' -and $_.Entry.Sha256Hex -cne $Digest)})
    return @{Name='B01FailureNotification';Verdict=$(if($bad.Count){'FAIL'}elseif(-not $Proof.Complete){'INCONCLUSIVE'}elseif($blocked.Count){'PASS'}else{'FAIL'});Reason=('Product emits exact-session/digest Blocked with no verified hand-back path and no Released; '+$Proof.Reason);Evidence=$entries}
}
function Test-B01FailureAudit($Log,[string]$TransferId) {
    try{
        $events=@(Test-AgentLogContinuity $Log 'Application' | ForEach-Object {$_})
        $id=([guid]$TransferId).ToString('D');$pattern='Staged hand-back failed for '+[regex]::Escape($id)
        $found=@($events | Where-Object {$_.Provider -ceq 'SafeUpload.Agent.Service' -and ($_.Values -join ' ') -match $pattern})
        return @{Name='B01FailureAudit';Verdict=$(if($found.Count){'PASS'}else{'FAIL'});Reason='Existing record-ID/edge-XML Application reader requires the product hand-back failure warning for this exact transfer; wall clock is not used.';Evidence=$found}
    }catch{return @{Name='B01FailureAudit';Verdict='INCONCLUSIVE';Reason=$_.Exception.Message}}
}
function Test-B01SentinelSample($Sample,$Baseline,[byte[]]$Expected) {
    $assertions=@()
    if($Sample.Status -cne 'OK' -or -not @($Sample.Captures).Count){$assertions+=@{Name='B01SentinelCapture';Verdict='INCONCLUSIVE';Reason='Independent sentinel raw capture required.'}}
    foreach($capture in $Sample.Captures){
        foreach($original in @($Baseline.Images | Where-Object Role -ceq 'Current')){
            $images=@($capture.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ceq $original.Path})
            if($images.Count -ne 1){$assertions+=@{Name='B01SentinelCapture';Verdict='INCONCLUSIVE';Reason='One raw image for each pre-existing sentinel file required.'};continue}
            $assertions+=Test-CachedImage $images[0] $Baseline.Geometry $Expected 'B01Sentinel'
            $good=$images[0].Identity.FileId -ceq $original.Identity.FileId -and $images[0].SecurityId -eq $original.SecurityId -and $images[0].Sddl -ceq $original.Sddl
            foreach($field in @('Attributes','Creation','Modified','Changed','Links')){if($images[0].RawMetadata.$field -ne $original.RawMetadata.$field){$good=$false}}
            $assertions+=@{Name='B01SentinelIdentity';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Pre-existing sentinel files retain raw file ID, security and mutation metadata.';Evidence=$images[0]}
            $readers=@($capture.Readers | Where-Object Path -ceq $original.Path)
            foreach($reader in $readers){$assertions+=@{Name='B01SentinelReader';Verdict=$(if($reader.Status -cne 'OK'){'INCONCLUSIVE'}elseif($reader.Result.Length -eq $Expected.Length -and $reader.Result.Digest -ceq [StagedInvariant.Native]::Hash($Expected)){'PASS'}else{'FAIL'});Reason='Fresh and uncached sentinel bytes unchanged.';Evidence=$reader}}
            if($readers.Count -ne 2 -or @($readers | Where-Object Unbuffered).Count -ne 1){$assertions+=@{Name='B01SentinelReaderCoverage';Verdict='INCONCLUSIVE';Reason='Fresh and uncached sentinel readers required.'}}
        }
        $parents=@($capture.Images | Where-Object Role -ceq 'Parent');$originalParents=@($Baseline.Images | Where-Object Role -ceq 'Parent')
        foreach($parent in $parents){
            $old=@($originalParents | Where-Object Path -ceq $parent.Path)
            $before=@($old | ForEach-Object {$_.DirectoryEntries} | Where-Object {$_.Name -cnotin @('.','..')} | ForEach-Object {$_.Name+':'+$_.Reference+':'+$_.Eof+':'+$_.Attributes} | Sort-Object)
            $after=@($parent.DirectoryEntries | Where-Object {$_.Name -cnotin @('.','..')} | ForEach-Object {$_.Name+':'+$_.Reference+':'+$_.Eof+':'+$_.Attributes} | Sort-Object)
            $assertions+=@{Name='B01SentinelListing';Verdict=$(if($old.Count -ne 1 -or $null -eq $old[0].DirectoryEntries -or $null -eq $parent.DirectoryEntries){'INCONCLUSIVE'}elseif(($before -join '|') -ceq ($after -join '|')){'PASS'}else{'FAIL'});Reason='Exact raw sentinel names/IDs/sizes/attributes: no added file, subdirectory or service temporary, no deletion/overwrite.';Evidence=$parent}
        }
        if($parents.Count -ne $originalParents.Count -or -not $parents.Count){$assertions+=@{Name='B01SentinelListingCoverage';Verdict='INCONCLUSIVE';Reason='All raw sentinel parent listings required.'}}
    }
    return ,$assertions
}
function Invoke-B01HeldAttack($Trial,$Actor,$Context) {
    $initial=$Trial.JournalTransitions[0]
    if($Trial.JournalTransitions.Count -ne 1 -or $initial.StateName -cne 'Allocated' -or $initial.SealedOnce){throw 'B01 attack requires exact mutable Allocated transfer'}
    $leaf=([guid]$initial.TransferId).ToString('N')+'.txt'
    Save-State @{Leaf=$leaf} (Join-Path $actorDirectory 'b01-attack.clixml')
    $go=[Diagnostics.Stopwatch]::GetTimestamp();Write-DurableFile (Join-Path $actorDirectory 'b01-junction-go') $RunName -New
    $receipt=Wait-WriterIdentity (Join-Path $actorDirectory 'b01-junction.clixml') 60
    $Trial.Assertions+=Test-B01JunctionReceipt $receipt $Actor $state.WriterToken $externalDirectory $leaf $go
    if($Trial.Assertions[-1].Verdict -cne 'PASS'){throw 'B01 sentinel junction not armed by standard actor'}
    $junction=Get-Item -LiteralPath $receipt.Root -Force
    if(($junction.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -or @($junction.Target).Count -ne 1 -or @($junction.Target)[0] -ine $externalDirectory){throw 'B01 junction OS readback differs from actor receipt'}
    $Trial.B01Attack=$receipt;$Trial.SetupCacheFlush=Flush-InvariantSetupVolume
    $sentinelContext=Open-InvariantObserver $Context.Geometry.Guid $externalDirectory (Join-Path $evidenceDirectory 'raw-external') $CaseId
    if($sentinelContext.Status -cne 'OK'){throw ('B01 sentinel observer: '+($sentinelContext.Error | Out-String))}
    try{
        $bytes=[Convert]::FromBase64String($state.B01SentinelBase64)
        $baseline=Capture-InvariantBaseline $sentinelContext @('marker.txt',$leaf) @{'marker.txt'=$bytes;$leaf=$bytes}
        if($baseline.Status -cne 'OK'){throw ('B01 sentinel baseline: '+($baseline.Error | Out-String))}
        $sample=Capture-InvariantSample $sentinelContext $baseline 'BeforeHandBack' 1
        $Trial.ExternalSource=@{Baseline=$baseline;Samples=@($sample);Disposal=$null}
        $Trial.Assertions+=Test-B01SentinelSample $sample $baseline $bytes
        return @{Context=$sentinelContext;Baseline=$baseline}
    }catch{$null=Close-InvariantObserver $sentinelContext;throw}
}
function Add-B01SentinelSample($Trial,$Context,$Baseline,[string]$Phase) {
    $sample=Capture-InvariantSample $Context $Baseline $Phase ($Trial.ExternalSource.Samples.Count+1)
    $Trial.ExternalSource.Samples+=$sample
    $Trial.Assertions+=Test-B01SentinelSample $sample $Baseline ([Convert]::FromBase64String($state.B01SentinelBase64))
}
function Remove-B01Junction {
    # Delete the reparse entry only. Never recursively delete through its target
    # when removing the owned profile, including Prepare rollback/Finalize.
    if($CaseId -cne 'B01' -or [string]::IsNullOrWhiteSpace($state.ActorProfile)){return}
    $path=Join-Path $state.ActorProfile 'SafeUpload\_bloqueados'
    if(Test-Path -LiteralPath $path){
        $item=Get-Item -LiteralPath $path -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){[IO.Directory]::Delete($path,$false)}
    }
}
function Get-R01WriterBody {
    $body=(Get-WriterBody).Replace('180*[Diagnostics.Stopwatch]::Frequency','600*[Diagnostics.Stopwatch]::Frequency').Replace('((180)*[Diagnostics.Stopwatch]::Frequency)','((600)*[Diagnostics.Stopwatch]::Frequency)')
    # The first image differs from final A. Rewind the SAME private handle for
    # the second whole-image write; opening another handle would lose this test.
    $native=@'
 public static void RewindHeld(IntPtr h) {
  long position;if(!SetFilePointerEx(h,0,out position,0))throw new Win32Exception(Marshal.GetLastWin32Error());
 }
'@
    $body=$body.Replace(' public static SUCall CloseHeld(IntPtr h) {',($native+"`n public static SUCall CloseHeld(IntPtr h) {"))
    $body=$body.Replace('$bytes=[Convert]::FromBase64String($config.Payloads[0])','$bytes=[Convert]::FromBase64String($config.R01InitialBase64)')
    $anchor="            if(-not `$config.DedicatedUnheldLatency){Wait-ActorBarrier 'close'}"
    if(([regex]::Matches($body,[regex]::Escape($anchor))).Count -ne 1){throw 'R01 held writer anchor missing/ambiguous'}
    $offline=@'
            Wait-ActorBarrier 'r01-offline-go'
            $finalBytes=[Convert]::FromBase64String($config.Payloads[0])
            $offlineCalls=@([SUWriter]::Attempt($config.R01OfflineTarget,$finalBytes,$true,0))
            [SUWriter]::RewindHeld($h)
            $calls+= [SUWriter]::WriteHeld($h,$finalBytes);$calls+= [SUWriter]::FlushHeld($h)
            $hash=[Security.Cryptography.SHA256]::Create()
            try{$privateDigest=[BitConverter]::ToString($hash.ComputeHash([SUWriter]::ReadPrivate($h,$finalBytes.Length))).Replace('-','')}finally{$hash.Dispose()}
            Save-ActorReceipt 'r01-offline.clixml' $calls $privateDigest @{OfflineCalls=$offlineCalls;Target=$config.Target;OfflineTarget=$config.R01OfflineTarget;Held=$true}
'@
    return $body.Replace($anchor,($offline+"`n"+$anchor))
}
function Test-R01OfflineCalls($Receipt,$Actor,[string]$Token,[string]$Path,[long]$StoppedQpc,[string]$Digest,[string]$OfflinePath) {
    $denied=@($Receipt.OfflineCalls);$writes=@($Receipt.Calls | Select-Object -Last 2)
    $good=$null -ne $Receipt -and $Receipt.Pid -eq $Actor.Pid -and $Receipt.Sid -ceq $Actor.Sid -and $Receipt.BootId -ceq $Actor.BootId -and
        $Receipt.Token -ceq $Token -and $Receipt.Target -ceq $Path -and $Receipt.Held -eq $true -and $Receipt.PrivateSha256 -ceq $Digest -and
        -not [string]::IsNullOrWhiteSpace($OfflinePath) -and $OfflinePath -ine $Path -and $Receipt.OfflineTarget -ceq $OfflinePath -and
        $denied.Count -eq 1 -and $denied[0].Class -ceq 'writer-open-deny' -and $denied[0].NativeCode -eq 5 -and
        $denied[0].StartQpc -ge $StoppedQpc -and $denied[0].EndQpc -ge $denied[0].StartQpc -and
        ($writes.Class -join ',') -ceq 'cached-write,flush' -and -not @($writes | Where-Object {$null -eq $_.NativeCode -or $_.NativeCode -ne 0}).Count -and
        $writes[0].StartQpc -ge $denied[0].EndQpc -and $writes[0].EndQpc -ge $writes[0].StartQpc -and
        $writes[1].StartQpc -ge $writes[0].EndQpc -and $writes[1].EndQpc -ge $writes[1].StartQpc -and $Receipt.Qpc -ge $writes[1].EndQpc
    return @{Name='R01OfflineNativeCalls';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Same standard actor: CREATE_NEW with write access on a distinct absent protected name returns Win32:5, then held private whole-image write/flush Win32:0 after SCM Stopped; private read equals final A.';Evidence=$Receipt}
}
function Test-R01OfflineAbsent($Sample,$Baseline,[string]$Path) {
    # Reuse the raw absence and fresh/uncached Win32:2 checks. The ordinary
    # public listing can gain cached.txt during approved publication; this
    # separate create name must stay absent through final quiescence.
    $frame=@{Status=$Sample.Status;Error=$Sample.Error;Phase=$Sample.Phase;Sequence=$Sample.Sequence;Captures=$Sample.Captures;C01Readers=$Sample.R01OfflineReaders}
    $assertions=@(Test-CachedSample $frame $Baseline $false $null $null $Path | ForEach-Object {$_} | Where-Object Name -cne 'C01PublicListing')
    foreach($assertion in $assertions){$assertion.Name='R01OfflineNew'+$assertion.Name.Substring(3)}
    foreach($capture in $Sample.Captures){
        $parents=@($capture.Images | Where-Object {$_.Role -ceq 'Parent' -and $_.Path -ceq [IO.Path]::GetDirectoryName($Path)})
        $complete=$parents.Count -eq 1 -and $null -ne $parents[0].DirectoryEntries
        $present=@($parents | ForEach-Object {$_.DirectoryEntries} | Where-Object Name -ieq ([IO.Path]::GetFileName($Path)))
        $assertions+=@{Name='R01OfflineNewRawNameAbsent';Verdict=$(if($present.Count){'FAIL'}elseif($complete){'PASS'}else{'INCONCLUSIVE'});Reason=('Offline CREATE_NEW name must remain absent in the raw parent index in '+$Sample.Phase);Sequence=$Sample.Sequence}
    }
    return ,$assertions
}
function Test-R01HeldRecovery($Initial,$Recovered) {
    $good=$null -ne $Initial -and $null -ne $Recovered -and $Initial.StateName -ceq 'Allocated' -and -not $Initial.SealedOnce -and
        $Recovered.TransferId -ieq $Initial.TransferId -and $Recovered.DestinationGeneration -eq $Initial.DestinationGeneration -and
        $Recovered.StateName -ceq 'Unsealed' -and $Recovered.SealedOnce -eq $false -and $null -eq $Recovered.Sha256Hex -and
        ($Recovered.History -join ',') -ceq 'Allocated,Unsealed'
    return @{Name='R01HeldRecovery';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Authenticated exact transfer/generation recovers Allocated -> Unsealed while holder lives, without sealing, inspection or implicit approval.';Evidence=$Recovered}
}
function Test-R01HeldNotifications($Proof,[string]$TransferId) {
    $bad=@($Proof.Emissions | Where-Object {($_.Entry.TransferId -ieq $TransferId -or $_.Entry.EventId -ieq $TransferId) -and $_.Entry.Phase -cin @('Analyzing','Inspecting','Approved','Publishing','Released','Blocked','Retained')})
    return @{Name='R01NoHeldOutcomeNotification';Verdict=$(if($bad.Count){'FAIL'}elseif($Proof.Complete){'PASS'}else{'INCONCLUSIVE'});Reason=('No inspection/approval/publication/outcome notification before close; '+$Proof.Reason);Evidence=$bad}
}
function Test-R01JournalSequence($Transitions,[string]$Digest) {
    $last=$Transitions[-1];$expected='Allocated,Unsealed,Sealed,Inspecting,Approved,Publishing,Released'
    $sealed=@($Transitions | Where-Object SealedOnce)
    return ,@(
        @{Name='R01JournalOrder';Verdict=$(if(($last.History -join ',') -ceq $expected){'PASS'}else{'FAIL'});Reason='Durable history requires recovery, a fresh seal and real inspection, then exactly one release.';Evidence=$Transitions},
        @{Name='R01SealedDigest';Verdict=$(if($sealed.Count -and -not @($sealed | Where-Object Sha256Hex -cne $Digest).Count){'PASS'}else{'FAIL'});Reason='All observed sealed versions equal the final whole private image A.'},
        @{Name='R01JournalIdentity';Verdict=$(if($Transitions.Count -and -not @($Transitions | Where-Object {$_.TransferId -ine $last.TransferId -or $_.DestinationGeneration -ne $last.DestinationGeneration}).Count){'PASS'}else{'FAIL'});Reason='One exact transfer and destination generation across service restart, seal and release.'})
}
function Test-R01ActorCalls($Calls,[long]$ReadyQpc,[long]$CloseQpc) {
    # Retain C01's status/order/close fence evaluator, with the second write pair
    # checked independently above and stripped only for the shared four-call shape.
    $shape=($Calls.Class -join ',') -ceq 'writer-open,cached-write,flush,cached-write,flush,close'
    $assertions=@(@{Name='R01ActorCallShape';Verdict=$(if($shape){'PASS'}else{'FAIL'});Reason='Initial write/flush, offline rewrite/flush, then last handle close.';Evidence=$Calls})
    if($shape){$assertions+=Test-CachedActorCalls @($Calls[0],$Calls[1],$Calls[2],$Calls[5]) 'cached' $ReadyQpc $CloseQpc}
    return ,$assertions
}
function Test-R01OutcomeSample($Sample,$Baseline,[byte[]]$ImageA) {
    # Publication can race a poll. Each raw capture and each reader may show
    # absence or whole A; the final Released checkpoint still requires whole A.
    $assertions=@();$path=Join-Path $protectedDirectory 'cached.txt'
    foreach($capture in $Sample.Captures){
        $images=@($capture.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ceq $path})
        if($images.Count -ne 1){$assertions+=@{Name='R01OutcomeCapture';Verdict='INCONCLUSIVE';Reason='Exactly one raw N/absence image required.'};continue}
        $frame=@{Status=$Sample.Status;Phase=$Sample.Phase;Sequence=$Sample.Sequence;Captures=@($capture);C01Readers=@()}
        # Outcome polls may overlap the already approved publication temporary;
        # the shared exact public-listing check applies before close and at final.
        $assertions+=@(Test-CachedSample $frame $Baseline (-not $images[0].Absent) $ImageA | ForEach-Object {$_} | Where-Object {$_.Name -cnotin @('C01ReaderCoverage','C01PublicListing','C01RawListingCoverage')})
    }
    if($Sample.Status -cne 'OK' -or -not @($Sample.Captures).Count){$assertions+=@{Name='R01OutcomeCapture';Verdict='INCONCLUSIVE';Reason='Stable independent outcome capture required.'}}
    foreach($reader in $Sample.C01Readers){
        $good=($reader.Status -ceq 'ERROR' -and $reader.NativeCode -eq 2) -or ($reader.Status -ceq 'OK' -and $reader.Result.Length -eq $ImageA.Length -and $reader.Result.Digest -ceq [StagedInvariant.Native]::Hash($ImageA))
        $assertions+=@{Name='R01OutcomeReader';Verdict=$(if($good){'PASS'}elseif($reader.Status -ceq 'OK'){'FAIL'}else{'INCONCLUSIVE'});Reason='Fresh/uncached N is absent or exact final whole A.';Evidence=$reader}
    }
    if(@($Sample.C01Readers).Count -ne 2 -or @($Sample.C01Readers | Where-Object Unbuffered).Count -ne 1){$assertions+=@{Name='R01OutcomeReaderCoverage';Verdict='INCONCLUSIVE';Reason='Fresh and uncached receipts required.'}}
    return ,$assertions
}
function Test-R01ReleasedOnce($Terminal,$Proof,[int]$SessionId,[string]$Digest) {
    $released=@($Proof.Emissions | Where-Object {$_.Entry.Kind -ceq 'Transfer' -and $_.Entry.TransferId -ieq $Terminal.TransferId -and $_.Entry.Phase -ceq 'Released'})
    $good=$Proof.Complete -and @($Terminal.History | Where-Object {$_ -ceq 'Released'}).Count -eq 1 -and $released.Count -eq 1 -and
        $released[0].Entry.TargetSessionId -eq $SessionId -and $released[0].Entry.Sha256Hex -ceq $Digest
    return @{Name='R01ReleasedExactlyOnce';Verdict=$(if($good){'PASS'}elseif(-not $Proof.Complete){'INCONCLUSIVE'}else{'FAIL'});Reason='One durable Released transition and one authenticated exact-transfer/session/digest Released emission in the post-restart window.';Evidence=$released}
}
function Invoke-R01AllocatedRestart($Trial,$Actor,$Context,$Baseline,[byte[]]$ImageA,[long]$Sequence) {
    $initial=$Trial.JournalTransitions[0];$result=@{Samples=@();Initial=$initial}
    if($Trial.JournalTransitions.Count -ne 1 -or $initial.StateName -cne 'Allocated' -or $initial.SealedOnce){throw 'R01 stop requires exact mutable Allocated transfer'}
    $end=[Diagnostics.Stopwatch]::GetTimestamp();$beforeStop=Get-ServiceSnapshot 'r01-before-stop';$Trial.JournalSnapshots+=$beforeStop
    $fence=@{BootId=$Context.BootId;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;ReleasedQpc=$Trial.HeldReceipt.ReleasedQpc;CompletedQpc=$end}
    $proof=Test-NotificationWindow $Trial.ServiceBefore.Notifications $beforeStop.Notifications $fence $true
    $Trial.Assertions+=Test-R01HeldNotifications $proof $initial.TransferId;$Trial.R01BeforeStop=@{Snapshot=$beforeStop;Proof=$proof;Fence=$fence}
    $oldPid=@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.Service.exe'" | Select-Object -ExpandProperty ProcessId)
    Stop-Service SafeUploadAgent -ErrorAction Stop
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do{$service=Get-Service SafeUploadAgent;if($service.Status -eq 'Stopped'){break};Start-Sleep -Milliseconds 100}while($watch.ElapsedMilliseconds -lt 30000)
    $down=@{State=[string]$service.Status;Processes=@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.Service.exe'");Qpc=[Diagnostics.Stopwatch]::GetTimestamp()}
    $Trial.R01Down=$down;$Trial.Assertions+=@{Name='R01ServiceStopped';Verdict=$(if($down.State -ceq 'Stopped' -and -not $down.Processes.Count){'PASS'}else{'FAIL'});Reason='SCM Stopped and no service process before offline actor barrier.';Evidence=$down}
    if($Trial.Assertions[-1].Verdict -cne 'PASS'){throw 'R01 agent did not stop'}
    $result.Samples+=Capture-CachedSample $Context $Baseline 'R01AgentDownBeforeRewrite' (++$Sequence)
    Write-DurableFile (Join-Path $actorDirectory 'r01-offline-go') $RunName -New
    $receipt=Wait-WriterIdentity (Join-Path $actorDirectory 'r01-offline.clixml') 60;$Trial.R01Offline=$receipt
    $Trial.Assertions+=Test-R01OfflineCalls $receipt $Actor $state.WriterToken (Join-Path $protectedDirectory 'cached.txt') $down.Qpc ([StagedInvariant.Native]::Hash($ImageA)) (Join-Path $protectedDirectory 'offline-new.txt')
    $result.Samples+=Capture-CachedSample $Context $Baseline 'R01AgentDownAfterRewrite' (++$Sequence)
    $offline=Get-CachedJournalObservation 'r01-offline' $Actor;$Trial.JournalSnapshots+=$offline.Snapshot
    $Trial.Assertions+=@{Name='R01OfflineAllocated';Verdict=$(if($offline.Status -cne 'OK'){'INCONCLUSIVE'}elseif($offline.Entries.Count -eq 1 -and $offline.Entries[0].TransferId -ieq $initial.TransferId -and ($offline.Entries[0].History -join ',') -ceq 'Allocated' -and -not $offline.Entries[0].SealedOnce){'PASS'}else{'FAIL'});Reason='No new transfer or implicit offline seal/approval; original mutable Allocated manifest retained.';Evidence=$offline}
    $event=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,'Global\SafeUploadServiceReady')
    try{
        [void]$event.Reset();$Trial.R01RestartQpc=[Diagnostics.Stopwatch]::GetTimestamp();Start-Service SafeUploadAgent
        if(-not $event.WaitOne([TimeSpan]::FromSeconds(45))){throw 'R01 restarted agent Ready timed out'}
        $newPid=[int](Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'").ProcessId
        $status=Get-ActivationCurrentProductStatus 'r01-restarted-ready' 5000
        $assertion=Test-R03ServiceReady $status $newPid;$assertion.Name='R01RestartedServiceReady';$Trial.Assertions+=$assertion
        $Trial.Assertions+=@{Name='R01NewServiceProcess';Verdict=$(if($newPid -gt 0 -and $oldPid.Count -eq 1 -and $newPid -ne $oldPid[0]){'PASS'}else{'FAIL'});Reason='SCM and authenticated pipe bind a new SYSTEM service process after restart.';Evidence=$status}
    }finally{$event.Dispose();Close-ActivationNotificationCapture}
    $poll=Get-CachedJournalObservation 'r01-recovered-held' $Actor;$Trial.JournalSnapshots+=$poll.Snapshot
    if($poll.Status -cne 'OK' -or $poll.Entries.Count -ne 1){throw 'R01 recovered exact transfer unavailable'}
    $Trial.Assertions+=Test-R01HeldRecovery $initial $poll.Entries[0];$Trial.JournalTransitions+=$poll.Entries[0]
    $Trial.R01PostRestartBefore=Get-ServiceSnapshot 'r01-restarted-held';$Trial.JournalSnapshots+=$Trial.R01PostRestartBefore
    $heldProof=@{Complete=($Trial.R01PostRestartBefore.Notifications.Status -ceq 'OK');Reason=$Trial.R01PostRestartBefore.Notifications.Reason;
        Emissions=@($Trial.R01PostRestartBefore.Notifications.Entries | Where-Object {$_.Entry.Qpc -ge $Trial.R01RestartQpc})}
    $Trial.Assertions+=Test-R01HeldNotifications $heldProof $initial.TransferId
    $result.Samples+=Capture-CachedSample $Context $Baseline 'R01UnsealedHolderLive' (++$Sequence)
    return $result
}
function Initialize-R03DisabledAgent {
    # Retain the pre-case service receipt, rather than the disabled test configuration
    # Start-StagedTestAgent will see after boot. Common cached restoration owns it.
    $keyPath='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent';$original=$null
    $exists=Test-Path -LiteralPath $keyPath
    if($exists){
        $key=Get-Item -LiteralPath $keyPath;$values=Get-ItemProperty -LiteralPath $keyPath
        $original=@{ImagePath=$values.ImagePath;ImagePathKind=$key.GetValueKind('ImagePath').ToString();Start=$state.OriginalAgentStart;
            ObjectName=[string]$values.ObjectName;ServiceSidType=$(if($null -eq $values.PSObject.Properties['ServiceSidType']){0}else{[int]$values.ServiceSidType})}
    }
    $state.CachedAgent=@{ServiceCreated=(-not $exists);OriginalService=$original};Save-State $state $statePath
    if(-not $exists){
        $binary='"'+(Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe')+'" --Interception:Mode=Minifilter --Interception:StagingPrototype=true'
        & sc.exe create SafeUploadAgent binPath= $binary start= disabled obj= LocalSystem | Out-Host
        if($LASTEXITCODE -ne 0){throw 'R03 disabled boot service creation failed'}
    }else{Set-AgentServiceStart 4}
    if((Get-ItemProperty -LiteralPath $keyPath).Start -ne 4 -or (Get-Service SafeUploadAgent).Status -ne 'Stopped'){throw 'R03 requires installed disabled/stopped agent before boot'}
}
function Get-R03WriterBody {
    # Reuse C01's native cached writer, receipts and cancellation. Only this row
    # inserts two offline operations before its ordinary fresh-save go barrier.
    $body=(Get-WriterBody).Replace('180*[Diagnostics.Stopwatch]::Frequency','600*[Diagnostics.Stopwatch]::Frequency').Replace('((180)*[Diagnostics.Stopwatch]::Frequency)','((600)*[Diagnostics.Stopwatch]::Frequency)').Replace('after 180 seconds','after 600 seconds')
    $anchor='    if($config.CachedCase -and $null -ne $config.SeedBaseBase64){'
    if(([regex]::Matches($body,[regex]::Escape($anchor))).Count -ne 1){throw 'R03 cached actor insertion anchor missing/ambiguous'}
    $offline=@'
    Wait-ActorBarrier 'r03-offline-go'
    $bootReady=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText((Join-Path $config.CoordinationDirectory 'r03-readiness.clixml')))
    if($bootReady.BootId -cne $actor.BootId -or $bootReady.QpcFrequency -ne [Diagnostics.Stopwatch]::Frequency){throw 'R03 readiness boot/QPC mismatch'}
    $releasedQpc=[Diagnostics.Stopwatch]::GetTimestamp();$offlineAgentStart=[int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent').Start
    Save-ActorReceipt 'r03-readiness-recorded.clixml' @() $null @{Readiness=$bootReady;RecordedQpc=$releasedQpc;AgentStart=$offlineAgentStart}
    $offlineCalls=@();$offlineAttempts=@();$offlineBytes=[Convert]::FromBase64String($config.Payloads[0])
    foreach($mutation in @(@{Action='overwrite-B';Path=(Join-Path ([IO.Path]::GetDirectoryName($config.Target)) 'marker.bin');Disposition=[uint32]5},@{Action='create-N';Path=$config.Target;Disposition=[uint32]1})){
        $h=[IntPtr]::Zero;$openCall=$null;$attemptCalls=@()
        try{
            $h=[SUWriter]::OpenHeld($mutation.Path,$mutation.Disposition,$false,[ref]$openCall);$attemptCalls+= $openCall
            # On unexpected admission, actually try the requested mutation. Preserve
            # its positive contradiction and let the independent observer see it.
            if($openCall.NativeCode -eq 0){$attemptCalls+= [SUWriter]::WriteHeld($h,$offlineBytes);$attemptCalls+= [SUWriter]::FlushHeld($h)}
        }finally{if($h -ne [IntPtr]::Zero -and $h -ne [IntPtr]::new(-1)){$attemptCalls+= [SUWriter]::CloseHeld($h)}}
        $offlineCalls+= $attemptCalls;$offlineAttempts+=@{Action=$mutation.Action;Path=$mutation.Path;Calls=$attemptCalls}
    }
    Save-ActorReceipt 'r03-offline-closed.clixml' $offlineCalls $null @{Attempts=$offlineAttempts;Readiness=$bootReady;ReadinessRecordedQpc=$releasedQpc;AgentStart=$offlineAgentStart;HandBackAfter=(Get-ActorHandBack);CompletedQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
'@
    return $body.Replace($anchor,($offline+"`n"+$anchor))
}
function Test-R03OfflineCalls($Receipt,$Actor,$Readiness,[string]$Token,[string]$BasePath,[string]$NewPath,$Recorded) {
    $assertions=@();$complete=$null -ne $Receipt -and $null -ne $Receipt.Attempts -and @($Receipt.Attempts).Count -eq 2
    $bound=$complete -and $Receipt.Pid -eq $Actor.Pid -and $Receipt.Sid -ceq $Actor.Sid -and $Receipt.BootId -ceq $Actor.BootId -and
        $Receipt.Token -ceq $Token -and $Receipt.Readiness.BootId -ceq $Readiness.BootId -and $Receipt.Readiness.Qpc -eq $Readiness.Qpc -and
        $Receipt.Readiness.QpcFrequency -eq $Readiness.QpcFrequency -and $Receipt.ReadinessRecordedQpc -ge $Readiness.Qpc -and $Receipt.AgentStart -eq 4 -and
        $null -ne $Recorded -and $Recorded.Pid -eq $Actor.Pid -and $Recorded.Sid -ceq $Actor.Sid -and $Recorded.BootId -ceq $Actor.BootId -and
        $Recorded.Token -ceq $Token -and $Recorded.RecordedQpc -eq $Receipt.ReadinessRecordedQpc -and $Recorded.Readiness.Qpc -eq $Readiness.Qpc -and
        $Recorded.Readiness.BootId -ceq $Readiness.BootId -and $Recorded.Readiness.QpcFrequency -eq $Readiness.QpcFrequency -and $Recorded.AgentStart -eq 4 -and $Recorded.Qpc -ge $Recorded.RecordedQpc
    $previous=$Recorded.Qpc;$paths=@($BasePath,$NewPath);$actions=@('overwrite-B','create-N')
    for($i=0;$i -lt 2;$i++){
        $attempt=$null;if($complete){$attempt=$Receipt.Attempts[$i]};$calls=@($attempt.Calls)
        $bad=@($calls | Where-Object {$_.NativeCode -ne 5 -or $_.Class -cne 'writer-open'})
        $good=$bound -and $attempt.Action -ceq $actions[$i] -and $attempt.Path -ceq $paths[$i] -and $calls.Count -eq 1 -and
            $null -ne $calls[0].StartQpc -and $null -ne $calls[0].EndQpc -and $calls[0].StartQpc -ge $previous -and
            $calls[0].EndQpc -ge $calls[0].StartQpc -and $calls[0].EndQpc -le $Receipt.CompletedQpc
        $verdict=if($bad.Count){'FAIL'}elseif(-not $complete){'INCONCLUSIVE'}elseif($good){'PASS'}else{'FAIL'}
        $assertions+=@{Name=$(if($i -eq 0){'R03OfflineOverwriteRefused'}else{'R03OfflineCreateRefused'});Verdict=$verdict;Reason='Exact actor/token/boot/readiness binding; one Win32:5 cached write-open; no write/flush/close; ordered QPC.';Evidence=$attempt}
        if($calls.Count){$previous=$calls[-1].EndQpc}
    }
    return ,$assertions
}
function Test-R03ServiceReady($Status,[int]$AgentPid) {
    $good=$null -ne $Status -and $Status.Status -ceq 'OK' -and $Status.ServerPid -eq $AgentPid -and $Status.ServerSid -ceq 'S-1-5-18' -and
        $Status.Value.protectionActive -eq $true -and $Status.Value.admissionCoverage -ceq 'Ready' -and $Status.Value.nativePolicyGeneration -gt 0
    return @{Name='R03PolicyAcceptedCoverageReady';Verdict=$(if($good){'PASS'}elseif($null -eq $Status -or $Status.Status -cne 'OK'){'INCONCLUSIVE'}else{'FAIL'});Reason='Fresh product status from the exact SYSTEM agent PID: protectionActive, coverage Ready and positive native policy generation.';Evidence=$Status}
}
function Test-R03HandBackAbsent($Actor,$Receipt) {
    $known=$null -ne $Actor.HandBackBefore -and $null -ne $Receipt.HandBackAfter
    return @{Name='R03OfflineHandBackAbsent';Verdict=$(if(@($Actor.HandBackBefore).Count -or @($Receipt.HandBackAfter).Count){'FAIL'}elseif($known){'PASS'}else{'INCONCLUSIVE'});Reason='Fresh per-SID OS profile hand-back inventories before and after offline attempts are both empty.';Before=$Actor.HandBackBefore;After=$Receipt.HandBackAfter}
}
function Test-R03BaseSample($Sample,$Baseline,[byte[]]$ImageB,$LastAccessPolicy) {
    $assertions=@();$path=Join-Path $protectedDirectory 'marker.bin';$checkpoint=Get-ExpectedCheckpoint $Baseline $Sample.Phase $Sample.Sequence
    $expect=@($checkpoint.Storage | Where-Object Path -ceq $path)
    if($Sample.Status -cne 'OK' -or -not @($Sample.Captures).Count){$assertions+=@{Name='R03PrebootBCapture';Verdict='INCONCLUSIVE';Reason='Complete independent raw B capture required.'}}
    foreach($capture in $Sample.Captures){
        $images=@($capture.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ceq $path})
        if($images.Count -ne 1){$assertions+=@{Name='R03PrebootBCoverage';Verdict='INCONCLUSIVE';Reason='Exactly one raw B image required per capture.'};continue}
        $assertions+=Test-CachedImage $images[0] $Baseline.Geometry $ImageB 'R03PrebootB'
        $original=@($Baseline.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ceq $path -and -not $_.Absent})
        $assertions+=@{Name='R03PrebootBIdentity';Verdict=$(if($original.Count -ne 1 -or $null -eq $images[0].Identity.FileId){'INCONCLUSIVE'}elseif($original[0].Identity.FileId -ceq $images[0].Identity.FileId){'PASS'}else{'FAIL'});Reason='Preboot B retains its exact physical file identity through offline denial and online publication of N.'}
        if($expect.Count -eq 1){
            # Metadata evaluation is private to the existing observer module.
            $observerModule=(Get-Command Capture-InvariantSample).Module
            $assertions+= & $observerModule {param($Image,$Expectation,$Frame,$Policy) Test-InvariantMetadata $Image $Expectation $Frame $Policy} $images[0] $expect[0] $Sample $LastAccessPolicy
        }
        else{$assertions+=@{Name='R03PrebootBMetadata';Verdict='INCONCLUSIVE';Reason='B metadata expectation unavailable.'}}
        $readers=@($capture.Readers | Where-Object {$_.Path -ceq $path})
        foreach($reader in $readers){$assertions+=@{Name='R03PrebootBReader';Verdict=$(if($reader.Status -cne 'OK'){'INCONCLUSIVE'}elseif($reader.Result.Digest -ceq [StagedInvariant.Native]::Hash($ImageB) -and $reader.Result.Length -eq $ImageB.Length){'PASS'}else{'FAIL'});Reason='Independent fresh/uncached B reader still equals complete preboot B.';Evidence=$reader}}
        if($readers.Count -ne 2 -or @($readers | Where-Object Unbuffered).Count -ne 1){$assertions+=@{Name='R03PrebootBReaderCoverage';Verdict='INCONCLUSIVE';Reason='Fresh and uncached B receipts required.'}}
    }
    return ,$assertions
}
function Test-R03OutcomeSample($Sample,$Baseline,[byte[]]$ImageA) {
    # APPROVE may publish between the journal poll and raw capture. Accept only
    # absence or the complete A image here; final Released still requires A.
    $assertions=@();$path=Join-Path $protectedDirectory 'cached.txt';$seen=0
    foreach($capture in $Sample.Captures){
        foreach($image in @($capture.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ceq $path})){
            $seen++
            if($image.Absent){$assertions+=@{Name='R03OutcomeAbsent';Verdict='PASS';Reason='Raw N remains absent during inspection/publication polling.'}}
            else{$assertions+=Test-CachedImage $image $Baseline.Geometry $ImageA 'R03ObservedN'}
        }
    }
    if($Sample.Status -cne 'OK' -or -not $seen){$assertions+=@{Name='R03OutcomeCapture';Verdict='INCONCLUSIVE';Reason='Stable independent outcome sample is required.'}}
    foreach($reader in $Sample.C01Readers){
        $good=($reader.Status -ceq 'ERROR' -and $reader.NativeCode -eq 2) -or
            ($reader.Status -ceq 'OK' -and $reader.Result.Length -eq $ImageA.Length -and $reader.Result.Digest -ceq [StagedInvariant.Native]::Hash($ImageA))
        $assertions+=@{Name='R03OutcomeReader';Verdict=$(if($good){'PASS'}elseif($reader.Status -ceq 'OK'){'FAIL'}else{'INCONCLUSIVE'});Reason='Each fresh/uncached outcome open returns absent or whole A; no torn/spliced or different bytes.';Evidence=$reader}
    }
    if(@($Sample.C01Readers).Count -ne 2 -or @($Sample.C01Readers | Where-Object Unbuffered).Count -ne 1){$assertions+=@{Name='R03OutcomeReaderCoverage';Verdict='INCONCLUSIVE';Reason='One fresh and one uncached outcome receipt required.'}}
    return ,$assertions
}
function Invoke-R03Observation {
    $context=$null;$baseline=$null;$samples=@();$predicateSamples=@();$checkpoints=@();$writer=$null;$actor=$null;$readyEvent=$null;$terminal=$null;$offline=$null;$closed=$null
    $trial=[ordered]@{Errors=@();Assertions=@();Approvals=@();Permits=@();Journal=@();JournalSnapshots=@();JournalTransitions=@();Notifications=@();Operations=@();Latency=@();ForbiddenByteCount=$null;Verdict='INCONCLUSIVE'}
    try{
        Assert-Hash $installedDriver $ExpectedFeatureSha256
        if((Get-ItemProperty "HKLM:\$registryService").Start -ne 0 -or (Get-BootId) -ceq $state.PrepareBootId){throw 'R03 requires new boot with boot-start driver'}
        if((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent').Start -ne 4 -or (Get-Service SafeUploadAgent).Status -ne 'Stopped' -or @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'R03 agent must be disabled and absent'}
        if($Mode -ceq 'runtime-verifier'){& verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host;if($LASTEXITCODE -ne 0){throw 'Runtime Verifier arm failed'}}
        $trial.VerifierBefore=Get-VerifierEvidence 'before' -RequireMode
        $ready=Get-Readiness;$readback=Get-BootPolicyReadback
        if($ready.VolumeGuid -cne $state.VolumeGuid -or $readback.RecordBase64 -cne $state.ExpectedBootRecord -or -not $readback.AclValid -or $readback.PendingPresent -or $readback.Prefix -cne (Get-NtDevicePath $protectedDirectory)){throw 'R03 boot policy/volume/NT scope readback mismatch'}
        $trial.Readiness=$ready;$trial.Policy=@{SeedRecord=$readback;LiveFlags=$null;TaintDisabledConfirmed=$false}
        $actor=Wait-WriterIdentity (Join-Path $actorDirectory 'identity.clixml');$trial.Actor=$actor
        if($actor.Sid -cne $state.ActorSid -or $actor.BootId -cne $ready.BootId -or $actor.Elevated -or $actor.IsAdministrator -or $actor.Pid -eq $PID){throw 'R03 startup standard-user actor identity mismatch'}
        $trial.ActorProvenance=Assert-ActorProcess $actor
        $profiles=@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $actor.Sid)
        if($profiles.Count -ne 1 -or $profiles[0].LocalPath -ine $actor.Profile){throw 'R03 actor profile SID binding mismatch'}
        $trial.TaintCounterBefore=Get-ActivationTaintCounters 'r03-before'
        $trial.ServiceBefore=Get-ServiceSnapshot 'r03-offline-before';$trial.LastAccessBefore=Get-LastAccessEvidence
        $context=Open-InvariantObserver $ready.VolumeGuid $protectedDirectory (Join-Path $evidenceDirectory 'raw') $CaseId
        if($context.Status -cne 'OK'){throw ($context.Error | Out-String)}
        $imageB=[Convert]::FromBase64String($state.BaselineBase64);$imageA=[Convert]::FromBase64String($state.CachedImageBase64);$digest=[StagedInvariant.Native]::Hash($imageA)
        $trial.ImageA=@{Sha256=$digest;Length=$imageA.Length;Fixture=$state.CachedFixture}
        $captureStarted=[DateTime]::UtcNow.ToFileTimeUtc()
        $baseline=Capture-InvariantBaseline $context @('marker.bin','cached.txt') @{'marker.bin'=$imageB;'cached.txt'=$null}
        $baseline | Add-Member NoteProperty CaptureStartedFileTime $captureStarted
        if($baseline.Status -cne 'OK'){throw ($baseline.Error | Out-String)}
        $parents=@($baseline.Images | Where-Object {$_.Role -ceq 'Parent' -and $_.Path -ceq $protectedDirectory})
        $initialNames=@($parents | ForEach-Object {$_.DirectoryEntries} | Where-Object {$_.Name -cnotin @('.','..')})
        $trial.Assertions+=@{Name='R03PrebootDirectory';Verdict=$(if($parents.Count -ne 1 -or $null -eq $parents[0].DirectoryEntries){'INCONCLUSIVE'}elseif($initialNames.Count -eq 1 -and $initialNames[0].Name -ceq 'marker.bin'){'PASS'}else{'FAIL'});Reason='Initial raw protected directory contains only preboot B; N and every temporary name are absent.';Evidence=$parents}
        $trial.Geometry=$context.Geometry;$trial.DecoderVersion=$context.DecoderVersion;$trial.ObserverModuleSha256=$context.ModuleSha256
        $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID);$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
        if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $context.ObserverSid){throw 'R03 observer OS SID mismatch'}
        $trial.Platform=@{Build=$context.Build;BootId=$context.BootId;ObserverPid=$context.ObserverPid;ObserverSid=$context.ObserverSid;ObserverProcess=@{Pid=$process.ProcessId;OwnerSid=$owner.Sid;SessionId=$process.SessionId;CommandLine=$process.CommandLine}}
        $sequence=1;$sample=Capture-CachedSample $context $baseline 'BeforeOperation' $sequence;$samples+=$sample;$predicateSamples+=$sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence
        $trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA
        Save-State $ready (Join-Path $actorDirectory 'r03-readiness.clixml')
        Write-DurableFile (Join-Path $actorDirectory 'r03-offline-go') $RunName -New
        $offline=Wait-WriterIdentity (Join-Path $actorDirectory 'r03-offline-closed.clixml')
        $recorded=Wait-WriterIdentity (Join-Path $actorDirectory 'r03-readiness-recorded.clixml')
        $trial.OfflineReceipt=$offline;$trial.DurableActorReadiness=$recorded
        $trial.Assertions+=Test-R03OfflineCalls $offline $actor $ready $state.WriterToken (Join-Path $protectedDirectory 'marker.bin') (Join-Path $protectedDirectory 'cached.txt') $recorded
        $trial.Assertions+=Test-R03HandBackAbsent $actor $offline
        $trial.Operations=@($offline.Calls)
        $sequence++;$sample=Capture-CachedSample $context $baseline 'OfflineAfterOperation' $sequence;$samples+=$sample;$predicateSamples+=$sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence
        $trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA
        $trial.OfflineServiceAfter=Get-ServiceSnapshot 'r03-offline-after'
        $offlineFence=[pscustomobject]@{Complete=$true;BootId=$actor.BootId;QpcFrequency=$ready.QpcFrequency;ReleasedQpc=$offline.ReleasedQpc;CompletedQpc=$offline.CompletedQpc}
        $trial.OfflineServiceEvidence=Get-ServiceTimeline $trial.ServiceBefore $trial.OfflineServiceAfter $offlineFence -R03Offline
        $trial.Assertions+=@($trial.OfflineServiceEvidence.Assertions)
        $delta=$trial.OfflineServiceEvidence.JournalDelta
        $trial.Assertions+=@{Name='R03OfflineJournalUnchanged';Verdict=$(if($delta.NewEntries.Count -or $delta.Findings.Count){'FAIL'}elseif($delta.Complete){'PASS'}else{'INCONCLUSIVE'});Reason='All authenticated journal records unchanged; no new transfer anywhere while agent absent.';Evidence=$delta}
        $offlineAccess=Get-LastAccessEvidence
        $offlineAccessPolicy=@{Status=$(if($null -ne $trial.LastAccessBefore.Value -and $null -ne $offlineAccess.Value){'OK'}else{'INCONCLUSIVE'});Before=$trial.LastAccessBefore;After=$offlineAccess}
        foreach($offlineSample in $samples){$trial.Assertions+=Test-R03BaseSample $offlineSample $baseline $imageB $offlineAccessPolicy}
        # Refuse to start the online phase unless every offline core proof passed.
        if(@($trial.Assertions | Where-Object Verdict -cne 'PASS').Count){throw 'R03 offline core evidence failed/incomplete; no fresh save attempted'}
        $readyEvent=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,'Global\SafeUploadServiceReady');[void]$readyEvent.Reset()
        $agent=Start-StagedTestAgent $serviceDirectory (Join-Path $evidenceDirectory 'r03-agent') -Arguments '--Logging:EventLog:LogLevel:Default=Debug'
        if(-not $readyEvent.WaitOne([TimeSpan]::FromSeconds(45))){throw 'R03 agent policy/coverage Ready timed out'}
        $status=Get-ActivationCurrentProductStatus 'r03-online-ready' 5000
        $trial.Assertions+=Test-R03ServiceReady $status $agent.Process.Id
        if($trial.Assertions[-1].Verdict -cne 'PASS'){throw 'R03 fresh coverage Ready receipt missing/contradictory'}
        Close-ActivationNotificationCapture
        $onlinePolicy=Get-BootPolicyReadback
        if($onlinePolicy.RecordBase64 -cne $state.ExpectedBootRecord -or -not $onlinePolicy.AclValid -or $onlinePolicy.PendingPresent){throw 'R03 accepted policy differs from seeded scope'}
        $trial.OnlineServiceBefore=Get-ServiceSnapshot 'r03-online-before';$trial.ServiceBefore=$trial.OnlineServiceBefore
        $sequence++;$sample=Capture-CachedSample $context $baseline 'OnlineBeforeOperation' $sequence;$samples+=$sample;$predicateSamples+=$sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence
        $trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA
        Write-DurableFile (Join-Path $actorDirectory 'go') $RunName -New
        $held=Wait-WriterIdentity (Join-Path $actorDirectory 'held.clixml')
        if($held.Pid -ne $actor.Pid -or $held.Sid -cne $actor.Sid -or $held.Token -cne $state.WriterToken -or $held.BootId -cne $actor.BootId){throw 'R03 held receipt identity mismatch'}
        $trial.Assertions+=@{Name='R03PrivateRead';Verdict=$(if($held.PrivateSha256 -ceq $digest){'PASS'}else{'FAIL'});Reason='Fresh online private handle read equals exact approved candidate A.';Evidence=$held}
        for($i=0;$i -lt 3;$i++){
            Add-CachedHeldJournal $trial $actor ('r03-held-'+$i)
            $sequence++;$sample=Capture-CachedSample $context $baseline 'FlushedHandleHeld' $sequence;$samples+=$sample;$predicateSamples+=$sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence
            $trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA
        }
        $trial.CloseBarrierQpc=[Diagnostics.Stopwatch]::GetTimestamp();Write-DurableFile (Join-Path $actorDirectory 'close') $RunName -New
        $closed=Wait-WriterIdentity (Join-Path $actorDirectory 'closed.clixml')
        if($closed.Pid -ne $actor.Pid -or $closed.Sid -cne $actor.Sid -or $closed.Token -cne $state.WriterToken -or $closed.BootId -cne $actor.BootId){throw 'R03 close receipt identity mismatch'}
        $trial.ClosedReceipt=$closed;$trial.Operations+=@($closed.Calls)
        $trial.Assertions+=Test-CachedActorCalls $closed.Calls 'cached' $status.EndQpc $trial.CloseBarrierQpc
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](120*[Diagnostics.Stopwatch]::Frequency);$pollNumber=0
        do{
            $poll=Get-CachedJournalObservation ('r03-outcome-'+$pollNumber) $actor;$pollNumber++;$trial.JournalSnapshots+=$poll.Snapshot
            if($poll.Status -cne 'OK' -or $poll.Entries.Count -gt 1){throw 'R03 requires one authenticated fresh actor transfer'}
            foreach($entry in $poll.Entries){
                if($trial.JournalTransitions.Count -and $trial.JournalTransitions[0].TransferId -ine $entry.TransferId){throw 'R03 transfer identity changed'}
                if(-not $trial.JournalTransitions.Count -or $trial.JournalTransitions[-1].State -ne $entry.State){$trial.JournalTransitions+=$entry}
                if($entry.StateName -ceq 'Released'){$terminal=$entry}
            }
            $sequence++;$sample=Capture-CachedSample $context $baseline 'OutcomeWait' $sequence;$samples+=$sample
            $trial.Assertions+=Test-R03OutcomeSample $sample $baseline $imageA
            if($null -ne $terminal){break};Start-Sleep -Milliseconds 10
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        $trial.Assertions+=Test-CachedJournalSequence $trial.JournalTransitions 'APPROVE' $digest
        if($null -eq $terminal){throw 'R03 explicit save did not reach Released'}
        $trial.TransferId=$terminal.TransferId
        Write-DurableFile (Join-Path $actorDirectory 'inspect-handback') $RunName -New
        $writer=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken 60
        $trial.HandBack=Get-CachedHandBack $actor $writer.Value.HandBackAfter $digest $imageA.Length;$trial.Assertions+=@($trial.HandBack.Assertions)
        $sequence++;$sample=Capture-CachedSample $context $baseline 'FinalQuiescence' $sequence;$samples+=$sample
        $trial.Assertions+=Test-CachedSample $sample $baseline $true $imageA
        $trial.ServiceAfter=Get-ServiceSnapshot 'r03-online-after'
        $fence=[pscustomobject]@{Complete=($writer.ExitCode -eq 0);BootId=$actor.BootId;QpcFrequency=$ready.QpcFrequency;ReleasedQpc=$writer.Value.ReleasedQpc;CompletedQpc=$writer.CompletedQpc}
        $delta=Test-ServiceJournalDelta $trial.OnlineServiceBefore $trial.ServiceAfter $true
        $proof=Test-NotificationWindow $trial.OnlineServiceBefore.Notifications $trial.ServiceAfter.Notifications $fence $true
        $trial.ServiceEvidence=@{JournalDelta=$delta;NotificationProof=$proof;OperationFence=$fence};$trial.Journal=$trial.ServiceAfter.Journal;$trial.Notifications=$proof.Emissions
        $trial.Assertions+=@{Name='R03FreshTransferOnly';Verdict=$(if($delta.Findings.Count -or $delta.NewEntries.Count -ne 1){'FAIL'}elseif($delta.Complete -and $delta.NewEntries[0].Entry.Transfer.TransferId -ieq $terminal.TransferId){'PASS'}else{'INCONCLUSIVE'});Reason='Exactly one new authenticated transfer, bound to the fresh online actor save; no offline attempt is resumed.';Evidence=$delta}
        $trial.Assertions+=Test-CachedNotifications $proof $terminal.TransferId $actor.SessionId 'APPROVE' $digest $trial.HandBack
        $trial.VerifierAfter=Get-VerifierEvidence 'after' -RequireMode
    }catch{$trial.Errors+=Get-ErrorChain $_.Exception;$trial.Assertions+=@{Name='R03Execution';Verdict='INCONCLUSIVE';Reason=($_.Exception.Message+'; '+$_.ScriptStackTrace)}}
    finally{
        if($null -ne $actor -and $null -eq $writer){
            try{if(-not(Test-Path -LiteralPath (Join-Path $actorDirectory 'cancel'))){Write-DurableFile (Join-Path $actorDirectory 'cancel') $RunName -New};Stop-ScheduledTask -TaskName $writerTask}catch{$trial.Errors+=Get-ErrorChain $_.Exception}
        }
        try{Close-ActivationNotificationCapture;Restore-CachedAgent}catch{$trial.Errors+=Get-ErrorChain $_.Exception}
        if($null -ne $readyEvent){$readyEvent.Dispose()}
        try{
            $afterCounters=Get-ActivationTaintCounters 'r03-after';$trial.TaintCounterWindow=Get-ActivationTaintCounterDelta $trial.TaintCounterBefore $afterCounters
            $trial.Assertions+=@{Name='R03TaintCountersUnchanged';Verdict=$(if($trial.TaintCounterWindow.NoCounterChanges){'PASS'}else{'FAIL'});Reason='Actual machine-wide Inspector taint recorded/lookups/hits/tainted-renames counters have zero deltas over offline and online mutations.';Evidence=$trial.TaintCounterWindow}
        }catch{$trial.Assertions+=@{Name='R03TaintCountersUnchanged';Verdict='INCONCLUSIVE';Reason=$_.Exception.Message}}
        $trial.LastAccessAfter=Get-LastAccessEvidence
        $trial.LastAccessPolicy=@{Status=$(if($null -ne $trial.LastAccessBefore.Value -and $null -ne $trial.LastAccessAfter.Value){'OK'}else{'INCONCLUSIVE'});Before=$trial.LastAccessBefore;After=$trial.LastAccessAfter}
        if($null -ne $baseline){foreach($sample in $samples){$trial.Assertions+=Test-R03BaseSample $sample $baseline ([Convert]::FromBase64String($state.BaselineBase64)) $trial.LastAccessPolicy}}
        if($null -ne $context -and $context.Status -ceq 'OK'){$trial.Disposal=Close-InvariantObserver $context}
        else{$trial.Disposal=@{Status='INCONCLUSIVE';Reason='R03 observer unavailable'}}
        $trial.Baseline=$baseline;$trial.Samples=$samples;$trial.PredicateSamples=$predicateSamples
        $trial.WriterFence=@{Complete=($null -ne $writer -and $writer.ExitCode -eq 0);BootId=$actor.BootId;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;ReleasedQpc=$offline.ReleasedQpc;CompletedQpc=$writer.CompletedQpc;ExpectedAttempts=3}
        $trial.MutationLedger=@{Complete=$false;Overflow=$false;Entries=@();Source='Unavailable: existing lower mutation ledger'}
        $trial.ExpectedTimeline=@{ForbiddenBlocks=@($state.ForbiddenBlocks | ForEach-Object {,[Convert]::FromBase64String($_)});Checkpoints=$checkpoints;AllowedMutations=@();ExpectedDenials=@();WriterIdentities=@($actor | Where-Object {$null -ne $_});Operations=$trial.Operations;WriterFence=$trial.WriterFence;LastAccessPolicy=$trial.LastAccessPolicy;
            ExternalEvidence=@{Build=$trial.Platform.Build;PrepareBootId=$state.PrepareBootId;ActiveBootId=$trial.Platform.BootId;ObserverPid=$trial.Platform.ObserverPid;ObserverSid=$trial.Platform.ObserverSid;ObserverProcess=$trial.Platform.ObserverProcess;ActorProvenance=$trial.ActorProvenance;Restoration=@{Known=$false}}}
        if($null -ne $baseline -and $predicateSamples.Count){
            $trial.Predicate=Test-NoUnapprovedByte $baseline @() $predicateSamples $trial.MutationLedger $trial.ExpectedTimeline
            $trial.ForbiddenByteCount=$trial.Predicate.ForbiddenByteCount;$trial.Assertions+=@($trial.Predicate.Assertions)
            foreach($assertion in @($trial.Assertions)){if($assertion -is [Collections.IDictionary] -and $assertion['Name'] -clike '*RawExtent' -and $assertion.Contains('ForbiddenByteCount')){$trial.ForbiddenByteCount+=[long]$assertion['ForbiddenByteCount']}}
        }
        $trial.Assertions+=@{Name='LiveTaintFlags';Verdict='INCONCLUSIVE';Reason='Existing live flag adapter unavailable; actual zero taint counter window is separately required.'}
        $trial.Assertions+=@{Name='R03PublicationAndTemporalCoverage';Verdict='INCONCLUSIVE';Reason='Existing lower publication/permit ledger unavailable; post-close sampled raw/fresh/uncached images and final exact approved A retained.'}
        if($trial.Disposal.Status -cne 'OK'){$trial.Assertions+=@{Name='Disposal';Verdict='INCONCLUSIVE';Reason='Checked observer disposal missing/failed.'}}
        foreach($assertion in $trial.Assertions){if($assertion.Name -clike 'C01*'){$assertion.Name='R03'+$assertion.Name.Substring(3)}}
        $trial.Repetitions=$row.Repetitions;$trial.OperationClassTimeline=$row.StatusClasses
        $trial.Verdict=if(@($trial.Assertions | Where-Object Verdict -ceq 'FAIL').Count){'FAIL'}elseif(@($trial.Assertions | Where-Object Verdict -ceq 'INCONCLUSIVE').Count){'INCONCLUSIVE'}else{'PASS'}
        Save-State $trial $trialPath
    }
}
# Owner-selected Phase 4 core variants. Keep their actors/evaluators local so
# other row batches can merge without changing the existing Ready functions.
function Get-A05WriterBody {
    $body=Get-ActivatingWriterBody
    $branch=@'
    'a05-unpermitted-write' {
     $bytes=[Convert]::FromBase64String($command.PayloadBase64);$flush=[int]0;$close=[int]0;$written=[long]0
     $result.NativeCode=[SUActivationNative]::StageWrite($config.Target,[long]$command.Offset,$bytes,[ref]$flush,[ref]$close,[ref]$written)
     $result.FlushCode=$flush;$result.CloseCode=$close;$result.BytesWritten=$written
    }
'@
    $anchor="    default {throw ('Unknown actor action: '+`$command.Action)}"
    if(-not $body.Contains($anchor)){throw 'A05 actor template anchor missing'}
    return $body.Replace($anchor,($branch+"`n"+$anchor))
}
function Test-A05Holder($Snapshot,[string]$FileId,[string]$NtPath,[int]$ActorPid,[uint32]$Generation) {
    $entries=@($Snapshot.Entries)
    $good=$entries.Count -eq 1 -and $Snapshot.Snapshot.Record.policyGeneration -eq $Generation
    if($good){$e=$entries[0];$good=$e.fileId -ieq $FileId -and $e.path -ieq $NtPath -and $e.state -ceq 'Activating' -and [uint32]$e.generation -gt 0 -and
        [uint32]$e.H -gt 0 -and $e.openerPids -contains $ActorPid -and $null -ne $e.W -and [uint32]$e.W -eq 0 -and $e.unknownReasons -ceq '0x00000000'}
    return @{Name='A05HeldAtGate';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Control 26 must identify the same Activating file, generation and actor H>0, with completed W drained and no uncertainty.';Evidence=$Snapshot}
}
function Test-A05Promotion($Record,$Trace,[string]$FileId,[long]$ReleaseStartQpc,[long]$MutationEndQpc) {
    $edges=@($Trace.Entries | Where-Object {$_.fileId -ieq $FileId -and [uint32]$_.stateBefore -eq 1 -and [uint32]$_.stateAfter -eq 2})
    $good=$Record.registryEntry -eq $true -and $Record.historyPresent -eq $true -and $Record.nameMatches -eq $true -and
        $Record.fileId -ieq $FileId -and $Record.state -ceq 'Protected' -and $Record.free -eq $true -and
        $ReleaseStartQpc -gt 0 -and $MutationEndQpc -gt 0 -and $MutationEndQpc -le $ReleaseStartQpc -and $Record.H -eq 0 -and $Record.S -ceq 'NO' -and $Record.C -eq 0 -and $Record.T -eq 0 -and $Record.unknownReasons -ceq '0x00000000' -and $edges.Count -eq 1
    if($good){$e=$edges[0];$good=$e.Hsample -eq 0 -and $e.Wsample -eq 0 -and $e.Tsample -eq 0 -and $e.CforSopSample -eq 0 -and $e.unknownReasonsSample -eq 0 -and $e.qpc -ge $ReleaseStartQpc}
    return @{Name='A05FreeAndProtected';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Same-ID registry Free/Protected and one loss-free promotion edge must report H/S/C/T/W drained and no unknown reason.';Evidence=@{Record=$Record;Trace=$Trace}}
}
function Add-A05WholeSample($Trial,$Sample,$Baseline,[byte[]]$Expected,[string]$Target,[string]$Label) {
    $images=@($Sample.Captures | ForEach-Object {$_.Images} | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ieq $Target})
    if($Sample.Status -cne 'OK' -or $images.Count -ne 1){throw 'A05 exact current raw capture unavailable'}
    $checks=Test-CachedImage $images[0] $Baseline.Geometry $Expected $Label
    $Trial.Assertions+=@($checks)
    foreach($check in $checks){if($check.ContainsKey('ForbiddenByteCount') -and $Label -ceq 'A05AfterRefusal'){$Trial.ForbiddenByteCount+=[long]$check.ForbiddenByteCount}}
    $digest=Get-ActivationSha256 $Expected
    foreach($reader in $Sample.C01Readers){
        $ok=$reader.Status -ceq 'OK' -and $reader.Result.Digest -ceq $digest -and $reader.Result.Length -eq $Expected.Length
        Add-ActivationAssertion $Trial ($Label+'Reader') $(if($ok){'PASS'}elseif($reader.Status -ceq 'OK'){'FAIL'}else{'INCONCLUSIVE'}) 'Independent fresh and uncached whole reads must equal the exact P/U image.' $reader
    }
    if(@($Sample.C01Readers).Count -ne 2 -or @($Sample.C01Readers | Where-Object Unbuffered).Count -ne 1){throw 'A05 fresh/uncached reader coverage missing'}
    if(@($checks | Where-Object Verdict -cne 'PASS').Count -and $Label -cne 'A05AfterRefusal'){throw 'A05 exact pre-protection or stable baseline proof failed'}
}
function Invoke-A05Observation {
    $script:ActivationNotificationHistory=@();$script:ActivationObservedPrematureReady=@();$script:ActivationHolderLive=$false;$script:ActivationCandidateGeneration=$null
    $context=$null;$agent=$null;$actor=$null;$baseline=$null;$samples=@();$traceEnabled=$false
    $trial=[ordered]@{Errors=@();Assertions=@();Operations=@();Reasons=@();Verdict='INCONCLUSIVE';ForbiddenByteCount=$null;JournalSnapshots=@()}
    $target=Join-Path $protectedDirectory 'marker.txt'
    try{
        Assert-Hash $installedDriver $ExpectedFeatureSha256
        if((Get-BootId) -ceq $state.PrepareBootId -or (Get-ItemProperty "HKLM:\$registryService").Start -ne 0){throw 'A05 requires the new boot-start boot'}
        if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'A05 pre-scope agent must be absent'}
        if($Mode -ceq 'runtime-verifier'){& verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host;if($LASTEXITCODE -ne 0){throw 'Runtime Verifier arm failed'}}
        $trial.VerifierBefore=Get-VerifierEvidence 'a05-before' -RequireMode
        $ready=Get-Readiness;$boot=Get-BootPolicyReadback
        if($ready.VolumeGuid -cne $state.VolumeGuid -or $boot.RecordBase64 -cne $state.ExpectedBootRecord -or $boot.PendingPresent -or $boot.PrefixCount -ne 0 -or -not $boot.AclValid){throw 'A05 empty pre-scope boot policy mismatch'}
        $context=Open-InvariantObserver $ready.VolumeGuid $protectedDirectory (Join-Path $evidenceDirectory 'raw') $CaseId
        if($context.Status -cne 'OK'){throw 'A05 observer open failed'}
        $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID);$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
        if($owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18' -or $owner.Sid -cne $context.ObserverSid){throw 'A05 SYSTEM observer identity mismatch'}
        $trial.Platform=@{Build=$context.Build;BootId=$context.BootId;ObserverPid=$PID;ObserverSid=$owner.Sid;ObserverProcess=@{Pid=$PID;OwnerSid=$owner.Sid;SessionId=$process.SessionId;CommandLine=$process.CommandLine}}
        Start-ScheduledTask -TaskName $writerTask;$actor=Get-ActivationActorIdentity;$trial.Actor=$actor
        $trial.ActorProvenance=@{Pid=$actor.Pid;SessionId=$actor.SessionId;OwnerSid=$actor.OwnerSid;CommandLine=$actor.CommandLine;Task=$actor.Task}
        $holder=Publish-ActivationActorCommand $state 'create-holder' $null
        if($holder.NativeCode -ne 0 -or -not $holder.HolderCreated -or $holder.SourceHandleClosed){throw 'A05 physical handle holder failed'}
        $trial.HolderSetup=@{Pid=$actor.Pid;Sid=$actor.Sid;SessionId=$actor.SessionId;CreateQpc=$holder.StartQpc;CompleteQpc=$holder.EndQpc;SourceHandleClosed=$false}
        $script:ActivationHolderLive=$true
        $trial.SetupCacheFlush=Flush-InvariantSetupVolume
        $p=[Convert]::FromBase64String($state.BaselineBase64)
        $baseline=Capture-InvariantBaseline $context @('marker.txt') @{'marker.txt'=$p}
        if($baseline.Status -cne 'OK'){throw 'A05 durable raw P baseline unavailable'}
        $image=@($baseline.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ieq $target -and -not $_.Absent})
        if($image.Count -ne 1 -or $image[0].Sha256 -cne (Get-ActivationSha256 $p)){throw 'A05 P/file identity mismatch'}
        $fileId=[string]$image[0].Identity.FileId;$ntPath=Get-NtDevicePath $target
        $samples+=Capture-CachedSample $context $baseline 'A05PreScopeP' 1 $target
        Add-A05WholeSample $trial $samples[-1] $baseline $p $target 'A05PreScope'
        $oldJournalBefore=Get-ServiceSnapshot 'a05-before-old-writes' -JournalOnly;$trial.JournalSnapshots+=$oldJournalBefore
        $epochBefore=Get-ActivationEpochStatus 'a05-before-update'
        $trial.TaintCounterBefore=Get-ActivationTaintCounters 'a05-before'
        $policy=Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
        if(@($policy.monitoredScopes.destinationPaths).Count){throw 'A05 runtime policy not empty'}
        $policy.version=[int]$policy.version+1;$policy.monitoredScopes.destinationPaths=@($protectedDirectory)
        Write-DurableFile $policyPath ($policy | ConvertTo-Json -Depth 8)
        $agent=Start-StagedTestAgent $serviceDirectory (Join-Path $evidenceDirectory 'a05-agent') -Arguments '--Diagnostics:StagedProofProxy=true'
        $state.AgentServiceStarted=$true;$state.AgentServiceCreated=[bool]$agent.ServiceCreated;$state.AgentOriginalService=$agent.OriginalService;Save-State $state $statePath
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](45*[Diagnostics.Stopwatch]::Frequency);$epoch=$null
        do{
            $epoch=Get-ActivationEpochStatus 'a05-after-update'
            if($epoch.policyGeneration -gt $epochBefore.policyGeneration -and $epoch.epochGeneration -gt $epochBefore.epochGeneration -and $epoch.activeCallbacks -eq 0 -and $epoch.flags -eq 0){break}
            Start-Sleep -Milliseconds 100
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        if($epoch.policyGeneration -le $epochBefore.policyGeneration -or $epoch.epochGeneration -le $epochBefore.epochGeneration -or $epoch.activeCallbacks -ne 0 -or $epoch.flags -ne 0){throw 'A05 expanded admission epoch did not drain'}
        $generation=[uint32]$epoch.policyGeneration;$script:ActivationCandidateGeneration=$generation
        Add-ActivationAssertion $trial 'A05ExpandedGate' 'PASS' 'Authenticated runtime policy advanced the admission epoch with no active callbacks or failure flags.' @{Before=$epochBefore;After=$epoch}
        $pending=Wait-ActivationProductStatus 'Pending' $generation 45 'a05-holder-pending'
        Add-ActivationAssertion $trial 'A05PendingWhileHeld' 'PASS' 'Current authenticated product status is Pending at the expanded policy generation.' $pending
        $trial.Assertions+=Test-A05Holder (Get-ActivationPendingEntry $ntPath $fileId 'a05-at-gate' $target) $fileId $ntPath $actor.Pid $generation
        $probe=Publish-ActivationActorCommand $state 'probe-new-writers' $null
        Add-ActivationAssertion $trial 'A05NewWriterGateDenied' $(if($probe.OpenCode -eq 5 -and $probe.SectionCode -eq 5){'PASS'}else{'FAIL'}) 'Standard-user new writable open and section requests returned Win32:5 while the old H is live.' $probe
        $null=Invoke-ActivationInspector '--admission-trace-clear' (Join-Path $evidenceDirectory 'a05-clear')
        $null=Invoke-ActivationInspector '--admission-trace-enable-sections-lifetime' (Join-Path $evidenceDirectory 'a05-enable');$traceEnabled=$true
        $changes=@();$u=[byte[]]$p.Clone();$i=0
        foreach($offset in @(64,[int]($p.Length/2),($p.Length-160))){
            $bytes=[Text.Encoding]::ASCII.GetBytes(('A05-'+$RunName+'-'+$i).PadRight(96,'U'));$i++
            [Array]::Copy($bytes,0,$u,$offset,$bytes.Length)
            $changes+=@{Offset=[long]$offset;Length=$bytes.Length;BytesBase64=[Convert]::ToBase64String($bytes);PayloadSha256=(Get-ActivationSha256 $bytes)}
        }
        $mutation=Publish-ActivationActorCommand $state 'write-old' @{Changes=$changes};$trial.Operations+=@($mutation.Calls)
        Add-ActivationAssertion $trial 'A05OldWritesCompleted' $(if($mutation.NativeCode -eq 0 -and $mutation.FlushCode -eq 0 -and @($mutation.Calls | Where-Object NativeCode -ne 0).Count -eq 0){'PASS'}else{'FAIL'}) 'Retained physical file-object writes and flush succeeded before protection; U is an allowed pre-protection mutation.' $mutation
        $trace=ConvertFrom-ActivationTrace (Invoke-ActivationInspector '--admission-trace' (Join-Path $evidenceDirectory 'a05-old-write-trace')) $fileId
        $matched=$true
        foreach($change in $changes){
            $pairs=@($trace.CompletedWritePairs | Where-Object {$_.Begin.pid -eq $actor.Pid -and [long]$_.Begin.writeLength -gt 0 -and [long]$_.Begin.writeOffset -lt $change.Offset+$change.Length -and [long]$_.Begin.writeOffset+[long]$_.Begin.writeLength -gt $change.Offset})
            if(-not $pairs.Count){$matched=$false}
        }
        Add-ActivationAssertion $trial 'A05OldLowerCompletions' $(if($matched){'PASS'}else{'INCONCLUSIVE'}) 'Loss-free paired successful W_BEGIN/W_END for the actor and same file ID overlap every disjoint U range.' $trace
        $trial.Assertions+=Test-A05Holder (Get-ActivationPendingEntry $ntPath $fileId 'a05-after-U' $target) $fileId $ntPath $actor.Pid $generation
        $samples+=Capture-CachedSample $context $baseline 'A05AllowedPUWhileHeld' 2 $target
        Add-A05WholeSample $trial $samples[-1] $baseline $u $target 'A05AllowedPU'
        $oldJournalAfter=Get-ServiceSnapshot 'a05-after-old-writes' -JournalOnly;$trial.JournalSnapshots+=$oldJournalAfter
        $oldDelta=Test-ServiceJournalDelta $oldJournalBefore $oldJournalAfter ($oldJournalBefore.EndQpc -le $mutation.StartQpc -and $mutation.EndQpc -le $oldJournalAfter.StartQpc)
        Add-ActivationAssertion $trial 'A05OldWritesNoPublication' $(if($oldDelta.Complete -and -not $oldDelta.NewEntries.Count){'PASS'}else{'FAIL'}) 'Pre-scope physical P/U is not a service transfer or approved publication; authenticated journal bytes remain unchanged.' $oldDelta
        $heldStatus=Get-ActivationCurrentProductStatus 'a05-after-U-status' 5000
        Add-ActivationAssertion $trial 'A05StillPendingAfterU' $(if($heldStatus.Status -ceq 'OK' -and $heldStatus.Value.protectionActive -eq $true -and $heldStatus.Value.admissionCoverage -ceq 'Pending' -and $heldStatus.Value.nativePolicyGeneration -eq $generation){'PASS'}else{'FAIL'}) 'Service is still Pending after completed U with H live.' $heldStatus
        Close-ActivationNotificationCapture
        $release=Publish-ActivationActorCommand $state 'release-holder' $null;$trial.LastHolderRelease=$release;$script:ActivationHolderLive=$false
        if($release.NativeCode -ne 0 -or -not $release.HolderReleased){throw 'A05 last holder release failed'}
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](90*[Diagnostics.Stopwatch]::Frequency);$promoted=$null
        do{
            $promoted=Get-ActivationEntry $target 'a05-promotion'
            if($promoted.Record.state -ceq 'Protected' -and $promoted.Record.free){break};Start-Sleep -Milliseconds 150
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        $promotionTrace=ConvertFrom-ActivationPromotionTrace (Invoke-ActivationInspector '--promotion-trace' (Join-Path $evidenceDirectory 'a05-promotion-trace')) $fileId
        $trial.Assertions+=Test-A05Promotion $promoted.Record $promotionTrace $fileId $release.StartQpc $mutation.EndQpc
        if($trial.Assertions[-1].Verdict -cne 'PASS'){throw 'A05 Free/Protected promotion proof failed'}
        $readyStatus=Wait-ActivationProductStatus 'Ready' $generation 60 'a05-after-promotion'
        Add-ActivationAssertion $trial 'A05ReadyAfterDrain' 'PASS' 'Authenticated Ready status follows last-holder release and same-file Free/Protected evidence.' @{Release=$release;Status=$readyStatus;Promotion=$promoted}
        $samples+=Capture-CachedSample $context $baseline 'A05ProtectedStablePU' 3 $target
        Add-A05WholeSample $trial $samples[-1] $baseline $u $target 'A05StablePU'
        # Remove the real agent/port connection to make the requested mutation
        # unpermitted, using the same agent-down admission premise as S02.
        Close-ActivationNotificationCapture
        Stop-Service SafeUploadAgent -ErrorAction Stop;(Get-Service SafeUploadAgent).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
        if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'A05 agent still running at refusal barrier'}
        $state.AgentServiceStarted=$false;Save-State $state $statePath
        $trial.ServiceBefore=Get-ServiceSnapshot 'a05-before-refusal' -JournalOnly
        $blockedBytes=[Text.Encoding]::ASCII.GetBytes(('UNPERMITTED-A05-'+$RunName).PadRight(96,'Z'))
        $denied=Publish-ActivationActorCommand $state 'a05-unpermitted-write' @{Offset=[long]256;PayloadBase64=[Convert]::ToBase64String($blockedBytes)}
        $trial.PostPromotionWrite=$denied;$trial.ForbiddenByteCount=[long]0
        Add-ActivationAssertion $trial 'A05UnpermittedWriteRefused' $(if($denied.NativeCode -eq 5 -and $denied.BytesWritten -eq 0 -and $denied.StartQpc -ge $release.EndQpc){'PASS'}else{'FAIL'}) 'Post-Protected standard-user open/write attempt with agent down must return Win32:5 and write zero bytes.' $denied
        for($n=0;$n -lt 3;$n++){
            $samples+=Capture-CachedSample $context $baseline 'A05AfterRefusedWrite' ($samples.Count+1) $target
            Add-A05WholeSample $trial $samples[-1] $baseline $u $target 'A05AfterRefusal'
            $difference=Get-ActivationRawDifference ([pscustomobject]@{Images=$samples[2].Images}) $samples[-1] $target
            Add-ActivationAssertion $trial 'A05PostProtectionBaselineUnchanged' $(if($difference.Status -cne 'OK'){'FAIL'}elseif($difference.DifferingBytes){'FAIL'}else{'PASS'}) 'Post-refusal allocation/identity and every raw DATA byte equal the exact stable promotion baseline.' $difference
        }
        $trial.ServiceAfter=Get-ServiceSnapshot 'a05-after-refusal' -JournalOnly
        $delta=Test-ServiceJournalDelta $trial.ServiceBefore $trial.ServiceAfter ($trial.ServiceBefore.EndQpc -le $denied.StartQpc -and $denied.EndQpc -le $trial.ServiceAfter.StartQpc)
        Add-ActivationAssertion $trial 'A05NoPublicationOrTransfer' $(if($delta.Complete -and -not $delta.NewEntries.Count -and -not $delta.Findings.Count){'PASS'}else{'FAIL'}) 'Old physical writes and the refused protected attempt create no transfer or publication journal change.' $delta
        $terminalProof=Test-A05Promotion (Get-ActivationEntry $target 'a05-terminal').Record $promotionTrace $fileId $release.StartQpc $mutation.EndQpc
        $terminalProof.Name='A05TerminalProtected';$trial.Assertions+=$terminalProof
        $trial.VerifierAfter=Get-VerifierEvidence 'a05-after' -RequireMode
    }catch{$trial.Errors+=Get-ErrorChain $_.Exception;Add-ActivationAssertion $trial 'A05Execution' 'INCONCLUSIVE' ($_.Exception.Message+'; '+$_.ScriptStackTrace) $null}
    finally{
        try{Close-ActivationNotificationCapture}catch{$trial.Errors+=Get-ErrorChain $_.Exception}
        if($actor){try{$exit=Publish-ActivationActorCommand $state 'exit-worker' $null;$trial.ActorTaskCompletion=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken 45;if($exit.NativeCode -ne 0){throw 'A05 actor release failed'}}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($trial.TaintCounterBefore){try{$trial.TaintCounterWindow=Get-ActivationTaintCounterDelta $trial.TaintCounterBefore (Get-ActivationTaintCounters 'a05-after')}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($traceEnabled){try{$null=Invoke-ActivationInspector '--admission-trace-disable' (Join-Path $evidenceDirectory 'a05-disable')}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($agent){try{Stop-StagedTestAgent $agent;$state.AgentServiceStarted=$false;Save-State $state $statePath}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($context -and $context.Status -ceq 'OK'){$trial.Disposal=Close-InvariantObserver $context}
        $trial.Baseline=$baseline;$trial.Samples=$samples
        $trial.ExpectedTimeline=@{WriterIdentities=@($actor);ExternalEvidence=@{Build=$trial.Platform.Build;PrepareBootId=$state.PrepareBootId;ActiveBootId=$context.BootId;ObserverPid=$PID;ObserverSid=$trial.Platform.ObserverSid;ObserverProcess=$trial.Platform.ObserverProcess;ActorProvenance=$trial.ActorProvenance};AllowedPreProtectionImage='Exact P/U';ForbiddenByteAccounting='Only differences after Protected stable baseline'}
        Add-ActivationAssertion $trial 'NeverReadyWholeHolderInterval' 'INCONCLUSIVE' 'Existing sampled status/Control 26 checkpoints do not constitute the deferred per-file continuous readiness event stream.' $script:ActivationNotificationHistory
        if(@($script:ActivationObservedPrematureReady).Count){Add-ActivationAssertion $trial 'A05PrematureReady' 'FAIL' 'Authenticated Ready frame arrived while H was live.' $script:ActivationObservedPrematureReady}
        Add-ActivationAssertion $trial 'LiveTaintFlags' 'INCONCLUSIVE' 'Live policy flags unavailable; existing Inspector counters retained separately.' $trial.TaintCounterWindow
        Add-ActivationAssertion $trial 'A05PublicationAndTemporalCoverage' 'INCONCLUSIVE' 'Existing raw/fresh/uncached samples and lower completions do not provide continuous lower payload/permit proof.' $null
        $trial.Reasons=@('A05 core (a) only; P/U before promotion is allowed; protected mutation is attempted with the agent down and must be refused.')
        $trial.Verdict=if(@($trial.Assertions | Where-Object Verdict -ceq 'FAIL').Count){'FAIL'}else{'INCONCLUSIVE'}
        Save-State $trial $trialPath
    }
}
function Initialize-X01Fixture([int]$Size) {
    $b=[Text.Encoding]::ASCII.GetBytes(('X01 preboot B '+$RunName+"`n").PadRight($Size,'B'))
    $v1=[Text.Encoding]::ASCII.GetBytes(('X01 version one '+$RunName+"`nCPF 529.982.247-25`n").PadRight($Size,'U'))
    $v2=[Text.Encoding]::ASCII.GetBytes(('X01 latest benign '+$RunName+"`n").PadRight($Size,'V'))
    if($b.Length -ne $Size -or $v1.Length -ne $Size -or $v2.Length -ne $Size){throw 'X01 fixture length mismatch'}
    $state.X01Images=@{B=[Convert]::ToBase64String($b);V1=[Convert]::ToBase64String($v1);V2=[Convert]::ToBase64String($v2)}
    $stream=[IO.FileStream]::new((Join-Path $protectedDirectory 'cached.txt'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($b,0,$b.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Get-X01WriterBody([string]$Config,[string]$Directory) {
    return (Get-WriterBody).Replace('180*[Diagnostics.Stopwatch]::Frequency','600*[Diagnostics.Stopwatch]::Frequency').Replace('((180)*[Diagnostics.Stopwatch]::Frequency)','((600)*[Diagnostics.Stopwatch]::Frequency)').Replace('180 seconds','600 seconds').Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $Config)).Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $Directory 'identity.clixml'))).Replace('__GO__',(ConvertTo-PowerShellLiteral (Join-Path $Directory 'go'))).Replace('__TEMP__',(ConvertTo-PowerShellLiteral $Directory))
}
function Save-X01WriterConfig([string]$Path,[string]$Directory,[string]$Token,[string]$Image) {
    Save-State @{ActorSid=$state.ActorSid;Payloads=@($Image);CachedCase=$true;WriterKind='overwrite';SeedBaseBase64=$null;
        Token=$Token;CoordinationDirectory=$Directory;Target=(Join-Path $protectedDirectory 'cached.txt')} $Path
}
function Initialize-X01SecondActor([string]$Password) {
    $directory=Join-Path $actorDirectory 'latest';$null=New-Item -ItemType Directory -Path $directory
    $config=Join-Path $stateDirectory 'x01-latest-config.clixml';$launcher=Join-Path $stateDirectory 'x01-latest-writer.ps1';$token=[guid]::NewGuid().ToString('N')
    $state.ActivationActors=@{
        Primary=@{Directory=$actorDirectory;Launcher=(Join-Path $stateDirectory 'writer.ps1');Task=$writerTask;Token=$state.WriterToken;ExpectedPid=$null}
        Latest=@{Directory=$directory;Launcher=$launcher;Task=($writerTask+'-latest');Token=$token;ExpectedPid=$null}}
    Save-State $state $statePath
    Save-X01WriterConfig $config $directory $token $state.X01Images.V2
    Write-DurableFile $launcher (New-TaskLauncher (Get-X01WriterBody $config $directory) $token (Join-Path $directory 'completion.clixml')) -New
    foreach($path in @($config,$launcher)){& icacls.exe $path /grant ('*'+$state.ActorSid+':R') | Out-Host;if($LASTEXITCODE -ne 0){throw 'X01 actor input ACL failed'}}
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$launcher+'"')
    Register-ScheduledTask -TaskName $state.ActivationActors.Latest.Task -Action $action -User ($env:COMPUTERNAME+'\'+$state.ActorUser) -Password $Password -RunLevel Limited -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(15))) | Out-Null
}
function Test-X01Versions($First,$Latest,[string]$DigestV1,[string]$DigestV2) {
    $assertions=@();$distinct=-not [string]::IsNullOrWhiteSpace($First.TransferId) -and -not [string]::IsNullOrWhiteSpace($Latest.TransferId) -and $First.TransferId -ine $Latest.TransferId -and $First.DestinationGeneration -gt 0 -and $Latest.DestinationGeneration -gt $First.DestinationGeneration
    $assertions+=@{Name='X01AllocationOrder';Verdict=$(if($distinct){'PASS'}else{'FAIL'});Reason='Barrier-ordered manifests require two distinct transfers with strictly increasing destination generations.'}
    $h1=@($First.History);$h2=@($Latest.History)
    $blocked=$First.StateName -ceq 'Blocked' -and $First.SealedOnce -eq $true -and $First.Sha256Hex -ceq $DigestV1 -and ($h1 -join ',') -ceq 'Allocated,Sealed,Inspecting,Blocked'
    $released=$Latest.StateName -ceq 'Released' -and $Latest.SealedOnce -eq $true -and $Latest.Sha256Hex -ceq $DigestV2 -and ($h2 -join ',') -ceq 'Allocated,Sealed,Inspecting,Approved,Publishing,Released'
    $assertions+=@{Name='X01SupersededVersionNeverReleased';Verdict=$(if($blocked -and $distinct){'PASS'}else{'FAIL'});Reason='The superseded v1 durable history remains exactly Allocated/Sealed/Inspecting/Blocked, without approval/publication/release.';Evidence=$First}
    $assertions+=@{Name='X01LatestReleasedOnce';Verdict=$(if($released -and $distinct){'PASS'}else{'FAIL'});Reason='Latest v2 has its exact independently supplied digest and complete history with one Released transition.';Evidence=$Latest}
    return ,$assertions
}
function Test-X01PublicSequence($Receipts,[string]$DigestB,[string]$DigestV2,[int]$Length) {
    $assertions=@();$seen=@{};$begun=@{};$previous=@{};$channels=@('Raw','Fresh','Uncached');$bad=$false;$regressed=$false;$before=$false
    foreach($receipt in $Receipts){
        if($receipt.BeforePublication -isnot [bool] -or $null -eq $receipt.Sequence -or $receipt.Channel -cnotin $channels -or $receipt.Length -ne $Length -or $receipt.Digest -cnotin @($DigestB,$DigestV2)){$bad=$true;continue}
        if(-not $begun[$receipt.Channel] -and ($receipt.Digest -cne $DigestB -or -not $receipt.BeforePublication)){$bad=$true}
        if($begun[$receipt.Channel] -and $receipt.Sequence -lt $previous[$receipt.Channel]){$bad=$true}
        $begun[$receipt.Channel]=$true;$previous[$receipt.Channel]=$receipt.Sequence
        if($receipt.BeforePublication -and $receipt.Digest -cne $DigestB){$before=$true}
        if($seen[$receipt.Channel] -and $receipt.Digest -ceq $DigestB){$regressed=$true}
        if($receipt.Digest -ceq $DigestV2){$seen[$receipt.Channel]=$true}
    }
    $coverage=@($channels | Where-Object {-not $seen[$_]}).Count -eq 0 -and @($Receipts).Count -ge 6
    $assertions+=@{Name='X01PublicWholeImages';Verdict=$(if($bad){'FAIL'}elseif($coverage){'PASS'}else{'INCONCLUSIVE'});Reason='Every raw/fresh/uncached observation is one complete B or v2 image; all three channels must finish at v2. v1, torn and spliced digests are rejected.'}
    $assertions+=@{Name='X01PublicNeverRegresses';Verdict=$(if($regressed){'FAIL'}else{'PASS'});Reason='Each independent observation channel may advance B -> v2 only once and must never regress.'}
    $assertions+=@{Name='X01ReaderBeforePublication';Verdict=$(if($before){'FAIL'}else{'PASS'});Reason='All observations before the latest writer is released for seal/publication must be B.'}
    return ,$assertions
}
function Test-X01FinalListing($Sample,$Baseline,[string]$Target) {
    $parents=@($Sample.Images | Where-Object Role -ceq 'Parent')
    $current=@($Sample.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ieq $Target -and -not $_.Absent})
    $good=$parents.Count -eq 1 -and $current.Count -eq 1
    if($good){
        $old=@($Baseline.Images | Where-Object {$_.Role -ceq 'Parent' -and $_.Path -ieq $parents[0].Path})
        $actual=@($parents[0].DirectoryEntries | Where-Object {$_.Name -cnotin @('.','..')})
        $targetEntries=@($actual | Where-Object Name -ceq ([IO.Path]::GetFileName($Target)))
        $good=$old.Count -eq 1 -and $null -ne $parents[0].DirectoryEntries -and $null -ne $old[0].DirectoryEntries -and
            $targetEntries.Count -eq 1 -and $targetEntries[0].Eof -eq $current[0].Length -and
            (($actual.Name | Sort-Object) -join ',') -ceq ((@($old[0].DirectoryEntries | Where-Object {$_.Name -cnotin @('.','..')}).Name | Sort-Object) -join ',')
    }
    return @{Name='X01ExactlyOneFinalTarget';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Final raw parent has exactly one T and exactly the preboot name multiset; no user temp, duplicate or service temp remains.';Evidence=$parents}
}
function Add-X01PublicSample($Trial,$Context,$Baseline,[byte[]]$B,[byte[]]$V2,[bool]$BeforePublication,[string]$PhaseName) {
    $sample=Capture-CachedSample $Context $Baseline $PhaseName ($Trial.Samples.Count+1)
    $Trial.Samples+= $sample
    if($sample.Status -cne 'OK'){throw 'X01 raw observer capture incomplete'}
    $images=@($sample.Captures | ForEach-Object {$_.Images} | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ieq (Join-Path $protectedDirectory 'cached.txt')})
    if(-not $images.Count){throw 'X01 current raw target image missing'}
    foreach($image in $images){
    $expected=$B
    if(-not $BeforePublication -and $image.Sha256 -ceq [StagedInvariant.Native]::Hash($V2)){$expected=$V2}
    $checks=Test-CachedImage $image $Baseline.Geometry $expected 'X01Public'
    $Trial.Assertions+=@($checks)
    foreach($check in $checks){if($check.ContainsKey('ForbiddenByteCount')){$Trial.ForbiddenByteCount+=[long]$check.ForbiddenByteCount}}
    $Trial.PublicReceipts+=@{Channel='Raw';Digest=$image.Sha256;Length=$image.Length;BeforePublication=$BeforePublication;Sequence=$sample.Sequence}
    }
    foreach($reader in $sample.C01Readers){
        if($reader.Status -cne 'OK'){throw 'X01 independent reader failed'}
        $Trial.PublicReceipts+=@{Channel=$(if($reader.Unbuffered){'Uncached'}else{'Fresh'});Digest=$reader.Result.Digest;Length=$reader.Result.Length;BeforePublication=$BeforePublication;Sequence=$sample.Sequence}
    }
    if(@($sample.C01Readers).Count -ne 2 -or @($sample.C01Readers | Where-Object Unbuffered).Count -ne 1){throw 'X01 independent uncached/fresh reader coverage missing'}
    return $sample
}
function Get-X01Journal($Trial,$Actor,[string]$Tag,[string[]]$Exclude=@()) {
    $poll=Get-CachedJournalObservation $Tag $Actor @((Join-Path $protectedDirectory 'cached.txt')) $Exclude
    $Trial.JournalSnapshots+= $poll.Snapshot
    if($poll.Status -cne 'OK' -or $poll.Entries.Count -ne 1){throw ('X01 needs one exact actor transfer: '+($poll.Errors | Out-String))}
    return $poll.Entries[0]
}
function Test-X01Receipt($Receipt,$Actor,$Slot) {
    if($Receipt.Pid -ne $Actor.Pid -or $Receipt.Sid -cne $Actor.Sid -or $Receipt.Token -cne $Slot.Token -or $Receipt.BootId -cne $Actor.BootId){throw 'X01 receipt identity/token/boot mismatch'}
}
function Get-X01HandBack($Actor,$OwnerFiles,[string]$Digest,[int]$Length) {
    # Reuse C01's exact owner-read/ACL/no-reparse/single-link/byte proof with
    # the BLOCK outcome, without changing the immutable X01 row or C01 code.
    $row=@{Outcome='BLOCK'}
    return Get-CachedHandBack $Actor $OwnerFiles $Digest $Length
}
function Invoke-X01Observation {
    $context=$null;$agent=$null;$actors=@{};$baseline=$null;$first=$null;$latest=$null;$readyEvent=$null
    $trial=[ordered]@{Errors=@();Assertions=@();Operations=@();Samples=@();PublicReceipts=@();JournalSnapshots=@();Reasons=@();Verdict='INCONCLUSIVE';ForbiddenByteCount=$null}
    try{
        Assert-Hash $installedDriver $ExpectedFeatureSha256
        if((Get-BootId) -ceq $state.PrepareBootId -or (Get-ItemProperty "HKLM:\$registryService").Start -ne 0 -or @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'X01 requires a new boot-start boot and initially absent agent'}
        if($Mode -ceq 'runtime-verifier'){& verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host;if($LASTEXITCODE -ne 0){throw 'Runtime Verifier arm failed'}}
        $trial.VerifierBefore=Get-VerifierEvidence 'x01-before' -RequireMode;$ready=Get-Readiness
        $readyEvent=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,'Global\SafeUploadServiceReady');[void]$readyEvent.Reset()
        $agent=Start-StagedTestAgent $serviceDirectory (Join-Path $evidenceDirectory 'x01-agent') -Arguments '--Diagnostics:StagedProofProxy=true'
        $state.AgentServiceCreated=[bool]$agent.ServiceCreated;$state.AgentOriginalService=$agent.OriginalService;$state.AgentServiceStarted=$true;Save-State $state $statePath
        if(-not $readyEvent.WaitOne([TimeSpan]::FromSeconds(45))){throw 'X01 agent Ready timeout'}
        $boot=Get-BootPolicyReadback
        if($ready.VolumeGuid -cne $state.VolumeGuid -or $boot.RecordBase64 -cne $state.ExpectedBootRecord -or $boot.PendingPresent -or -not $boot.AclValid){throw 'X01 exact protected boot policy readback mismatch'}
        $trial.PolicyEpoch=Get-ActivationEpochStatus 'x01-policy'
        $trial.TaintCounterBefore=Get-ActivationTaintCounters 'x01-before'
        $context=Open-InvariantObserver $ready.VolumeGuid $protectedDirectory (Join-Path $evidenceDirectory 'raw') $CaseId
        if($context.Status -cne 'OK'){throw 'X01 independent raw observer unavailable'}
        $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID);$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
        if($owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18' -or $owner.Sid -cne $context.ObserverSid){throw 'X01 SYSTEM observer identity mismatch'}
        $trial.Platform=@{Build=$context.Build;BootId=$context.BootId;ObserverPid=$PID;ObserverSid=$owner.Sid;ObserverProcess=@{Pid=$PID;OwnerSid=$owner.Sid;SessionId=$process.SessionId;CommandLine=$process.CommandLine}}
        foreach($key in @('Primary','Latest')){
            $slot=$state.ActivationActors[$key];Start-ScheduledTask -TaskName $slot.Task;$actors[$key]=Get-ActivationActorIdentity $key
            $identity=Wait-WriterIdentity (Join-Path $slot.Directory 'identity.clixml')
            $profiles=@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $identity.Sid)
            if($profiles.Count -ne 1 -or $profiles[0].LocalPath -ine $identity.Profile){throw 'X01 profile does not match the OS SID binding'}
            $actors[$key] | Add-Member NoteProperty Profile $identity.Profile
            $actors[$key] | Add-Member NoteProperty HandBackBefore @($identity.HandBackBefore)
        }
        $actor=$actors.Primary;$trial.Actor=$actor;$trial.Actors=$actors
        $trial.ActorProvenance=@{Pid=$actor.Pid;OwnerSid=$actor.OwnerSid;SessionId=$actor.SessionId;CommandLine=$actor.CommandLine;Task=$actor.Task}
        Add-ActivationAssertion $trial 'X01TwoStandardUserProcesses' $(if($actor.Pid -ne $actors.Latest.Pid -and $actor.Sid -ceq $actors.Latest.Sid -and $actor.SessionId -eq $actors.Latest.SessionId){'PASS'}else{'FAIL'}) 'Two concurrently live limited task processes have independently verified OS PID, SID, session and launcher provenance.' $actors
        $b=[Convert]::FromBase64String($state.X01Images.B);$v1=[Convert]::FromBase64String($state.X01Images.V1);$v2=[Convert]::FromBase64String($state.X01Images.V2)
        $digest1=[StagedInvariant.Native]::Hash($v1);$digest2=[StagedInvariant.Native]::Hash($v2)
        $startFileTime=[DateTime]::UtcNow.ToFileTimeUtc()
        $baseline=Capture-InvariantBaseline $context @('marker.bin','cached.txt') @{'marker.bin'=[Convert]::FromBase64String($state.BaselineBase64);'cached.txt'=$b}
        $baseline | Add-Member NoteProperty CaptureStartedFileTime $startFileTime
        if($baseline.Status -cne 'OK'){throw 'X01 exact preboot B baseline unavailable'}
        $trial.ForbiddenByteCount=[long]0;$trial.ServiceBefore=Get-ServiceSnapshot 'x01-before'
        if($trial.ServiceBefore.Status -cne 'OK'){throw 'X01 authenticated initial service snapshot incomplete'}
        $null=Add-X01PublicSample $trial $context $baseline $b $v2 $true 'X01BeforeWriters'
        $slot=$state.ActivationActors.Primary
        Write-DurableFile (Join-Path $slot.Directory 'go') $RunName -New
        $held=Wait-WriterIdentity (Join-Path $slot.Directory 'held.clixml') 60;Test-X01Receipt $held $actor $slot
        Add-ActivationAssertion $trial 'X01V1PrivateImage' $(if($held.PrivateSha256 -ceq $digest1){'PASS'}else{'FAIL'}) 'Writer 1 cached truncate/overwrite reads its exact v1 privately while public T is B.' $held
        $allocated1=Get-X01Journal $trial $actor 'x01-v1-held'
        if($allocated1.StateName -cne 'Allocated' -or $allocated1.SealedOnce){throw 'X01 v1 sealed while its upper handle lived'}
        for($n=0;$n -lt 3;$n++){$null=Add-X01PublicSample $trial $context $baseline $b $v2 $true 'X01V1Held'}
        $closeBarrier1=[Diagnostics.Stopwatch]::GetTimestamp();Write-DurableFile (Join-Path $slot.Directory 'close') $RunName -New
        $closed1=Wait-WriterIdentity (Join-Path $slot.Directory 'closed.clixml') 60;Test-X01Receipt $closed1 $actor $slot
        $calls=Test-CachedActorCalls $closed1.Calls 'overwrite' $ready.Qpc $closeBarrier1;foreach($check in $calls){$check.Name='X01V1'+$check.Name};$trial.Assertions+=@($calls);$trial.Operations+=@($closed1.Calls)
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](120*[Diagnostics.Stopwatch]::Frequency);$number=0
        do{
            $first=Get-X01Journal $trial $actor ('x01-block-'+$number);$number++
            $null=Add-X01PublicSample $trial $context $baseline $b $v2 $true 'X01V1BlockWait'
            if($first.StateName -ceq 'Blocked'){break}
            if($first.StateName -cin @('Approved','Publishing','Released','Retained')){throw ('X01 v1 unexpected state '+$first.StateName)}
            Start-Sleep -Milliseconds 50
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        if($first.StateName -cne 'Blocked'){throw 'X01 v1 Blocked timeout'}
        # v1 remains a live process at its hand-back barrier. v2's allocation
        # follows the durable BLOCK so supersession cannot skip v1 inspection.
        $slot2=$state.ActivationActors.Latest;$actor2=$actors.Latest
        $trial.V2AllocationBarrierQpc=[Diagnostics.Stopwatch]::GetTimestamp();Write-DurableFile (Join-Path $slot2.Directory 'go') $RunName -New
        $held2=Wait-WriterIdentity (Join-Path $slot2.Directory 'held.clixml') 60;Test-X01Receipt $held2 $actor2 $slot2
        Add-ActivationAssertion $trial 'X01V2PrivateImage' $(if($held2.PrivateSha256 -ceq $digest2 -and $held2.Calls[0].StartQpc -ge $trial.V2AllocationBarrierQpc -and $closed1.Qpc -le $trial.V2AllocationBarrierQpc){'PASS'}else{'FAIL'}) 'Writer 2 starts only after v1 is durably Blocked and reads its exact v2 through its own upper handle.' $held2
        $allocated2=Get-X01Journal $trial $actor2 'x01-v2-held' @($first.TransferId)
        if($allocated2.StateName -cne 'Allocated' -or $allocated2.SealedOnce -or $allocated2.DestinationGeneration -le $first.DestinationGeneration){throw 'X01 latest allocated identity/generation invalid'}
        for($n=0;$n -lt 3;$n++){$null=Add-X01PublicSample $trial $context $baseline $b $v2 $true 'X01V2Held'}
        $closeBarrier2=[Diagnostics.Stopwatch]::GetTimestamp();Write-DurableFile (Join-Path $slot2.Directory 'close') $RunName -New
        $closed2=Wait-WriterIdentity (Join-Path $slot2.Directory 'closed.clixml') 60;Test-X01Receipt $closed2 $actor2 $slot2
        $calls=Test-CachedActorCalls $closed2.Calls 'overwrite' $ready.Qpc $closeBarrier2;foreach($check in $calls){$check.Name='X01V2'+$check.Name};$trial.Assertions+=@($calls);$trial.Operations+=@($closed2.Calls)
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](120*[Diagnostics.Stopwatch]::Frequency);$number=0
        do{
            $latest=Get-X01Journal $trial $actor2 ('x01-release-'+$number) @($first.TransferId)
            $first=Get-X01Journal $trial $actor ('x01-superseded-'+$number) @($allocated2.TransferId);$number++
            if($first.StateName -cne 'Blocked' -or @($first.History | Where-Object {$_ -cin @('Approved','Publishing','Released')}).Count){throw 'X01 superseded v1 entered publication'}
            $null=Add-X01PublicSample $trial $context $baseline $b $v2 $false 'X01LatestPublicationWait'
            if($latest.StateName -ceq 'Released'){break}
            if($latest.StateName -cin @('Blocked','Retained','Unsealed')){throw ('X01 v2 unexpected state '+$latest.StateName)}
            Start-Sleep -Milliseconds 50
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        if($latest.StateName -cne 'Released'){throw 'X01 v2 Released timeout'}
        $trial.Assertions+=Test-X01Versions $first $latest $digest1 $digest2
        # Give asynchronous hand-back and notification delivery the same bounded
        # grace as C01, then let the owning process read the service's exact copy.
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](10*[Diagnostics.Stopwatch]::Frequency);$number=0
        $fence=@{Complete=$true;BootId=$actor.BootId;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;ReleasedQpc=$held.ReleasedQpc;CompletedQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
        do{
            $trial.ServiceAfter=Get-ServiceSnapshot ('x01-final-'+$number);$number++
            $proof=Test-NotificationWindow $trial.ServiceBefore.Notifications $trial.ServiceAfter.Notifications $fence $true
            $notifications=@($proof.Emissions | ForEach-Object {$_.Entry})
            if($proof.Complete -and @($notifications | Where-Object {$_.TransferId -ieq $latest.TransferId -and $_.Phase -ceq 'Released'}).Count -and @($notifications | Where-Object {$_.TransferId -ieq $first.TransferId -and $_.Phase -ceq 'Blocked' -and $_.HandBackPath}).Count){break}
            $null=Add-X01PublicSample $trial $context $baseline $b $v2 $false 'X01FinalNotificationWait';Start-Sleep -Milliseconds 100
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        foreach($key in @('Primary','Latest')){
            $s=$state.ActivationActors[$key];Write-DurableFile (Join-Path $s.Directory 'inspect-handback') $RunName -New
            $completion=Wait-TaskCompletion $s.Task (Join-Path $s.Directory 'completion.clixml') $s.Token 60
            if($key -ceq 'Primary'){$trial.HandBack=Get-X01HandBack $actor $completion.Value.HandBackAfter $digest1 $v1.Length;$trial.Assertions+=@($trial.HandBack.Assertions | ForEach-Object {$_.Name='X01V1'+$_.Name.Substring(3);$_})}
        }
        $checks=Test-CachedNotifications $proof $first.TransferId $actor.SessionId 'BLOCK' $digest1 $trial.HandBack
        foreach($check in $checks){$check.Name='X01V1'+$check.Name.Substring(3)};$trial.Assertions+=@($checks)
        $checks=Test-CachedNotifications $proof $latest.TransferId $actor2.SessionId 'APPROVE' $digest2
        foreach($check in $checks){$check.Name='X01V2'+$check.Name.Substring(3)};$trial.Assertions+=@($checks)
        $final=Add-X01PublicSample $trial $context $baseline $b $v2 $false 'X01FinalQuiescence'
        $checks=Test-CachedSample $final $baseline $true $v2 $b
        foreach($check in $checks){$check.Name='X01Final'+$check.Name.Substring(3)};$trial.Assertions+=@($checks)
        $trial.Assertions+=Test-X01FinalListing $final $baseline (Join-Path $protectedDirectory 'cached.txt')
        $trial.Assertions+=Test-X01PublicSequence $trial.PublicReceipts ([StagedInvariant.Native]::Hash($b)) $digest2 $b.Length
        $status=Get-ActivationCurrentProductStatus 'x01-terminal' 5000
        Add-ActivationAssertion $trial 'X01TerminalProtectedReady' $(if($status.Status -ceq 'OK' -and $status.Value.protectionActive -eq $true -and $status.Value.admissionCoverage -ceq 'Ready' -and $status.Value.nativePolicyGeneration -eq $trial.PolicyEpoch.policyGeneration){'PASS'}else{'FAIL'}) 'Final authenticated service status is active/Ready at the unchanged protected scope generation after v2 release.' $status
        $trial.FirstVersion=$first;$trial.LatestVersion=$latest;$trial.VerifierAfter=Get-VerifierEvidence 'x01-after' -RequireMode
    }catch{$trial.Errors+=Get-ErrorChain $_.Exception;Add-ActivationAssertion $trial 'X01Execution' 'INCONCLUSIVE' ($_.Exception.Message+'; '+$_.ScriptStackTrace) $null}
    finally{
        foreach($key in @('Primary','Latest')){
            $slot=$state.ActivationActors[$key]
            foreach($leaf in @('cancel','close','inspect-handback')){try{if(-not(Test-Path -LiteralPath (Join-Path $slot.Directory $leaf))){Write-DurableFile (Join-Path $slot.Directory $leaf) $RunName -New}}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
            try{if((Get-ScheduledTask -TaskName $slot.Task).State -eq 'Running'){$null=Wait-TaskCompletion $slot.Task (Join-Path $slot.Directory 'completion.clixml') $slot.Token 30}}catch{$trial.Errors+=Get-ErrorChain $_.Exception}
        }
        if($trial.TaintCounterBefore){try{$trial.TaintCounterWindow=Get-ActivationTaintCounterDelta $trial.TaintCounterBefore (Get-ActivationTaintCounters 'x01-after')}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($context -and $context.Status -ceq 'OK'){$trial.Disposal=Close-InvariantObserver $context}
        if($readyEvent){$readyEvent.Dispose()}
        try{Close-ActivationNotificationCapture;if($agent){Stop-StagedTestAgent $agent;$state.AgentServiceStarted=$false;Save-State $state $statePath}}catch{$trial.Errors+=Get-ErrorChain $_.Exception}
        $trial.Baseline=$baseline
        $trial.ExpectedTimeline=@{WriterIdentities=@($actors.Primary,$actors.Latest);ExternalEvidence=@{Build=$trial.Platform.Build;PrepareBootId=$state.PrepareBootId;ActiveBootId=$context.BootId;ObserverPid=$PID;ObserverSid=$trial.Platform.ObserverSid;ObserverProcess=$trial.Platform.ObserverProcess;ActorProvenance=$trial.ActorProvenance};Points=@('Preboot B','v1 allocated/closed/Blocked','v2 allocated/held/closed','v1 stays Blocked; v2 Approved/Released','Exact v1 hand-back; exact final v2')}
        Add-ActivationAssertion $trial 'LiveTaintFlags' 'INCONCLUSIVE' 'Live policy flags unavailable; existing Inspector counters retained separately.' $trial.TaintCounterWindow
        Add-ActivationAssertion $trial 'X01PublicationAndTemporalCoverage' 'INCONCLUSIVE' 'Raw/fresh/uncached whole-image samples and durable version history do not supply the deferred continuous lower mutation/permit ledger.' $null
        $trial.Reasons=@('X01 core uses two live writer processes with v1 blocked before v2 allocation; no mixed/mapped or unheld race qualification.')
        $trial.Verdict=if(@($trial.Assertions | Where-Object Verdict -ceq 'FAIL').Count){'FAIL'}else{'INCONCLUSIVE'}
        Save-State $trial $trialPath
    }
}

# R02: the coordinated stop is after real policy finalization, with a clean H holder.
function Initialize-R02Fixture([byte[]]$Image) {
    $state.R02ScopeX=Join-Path $protectedDirectory 'X';$state.R02ScopeY=Join-Path $protectedDirectory 'Y'
    foreach($dir in @($state.R02ScopeX,$state.R02ScopeY)){
        $null=New-Item -ItemType Directory -Path $dir
        $stream=[IO.FileStream]::new((Join-Path $dir 'marker.txt'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
        try{$stream.Write($Image,0,$Image.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    }
}
function Get-R02WriterBody {
    $body=Get-ActivatingWriterBody
    $anchor="    default {throw ('Unknown actor action: '+`$command.Action)}"
    $branch=@'
    'r02-probe-path' {$result.NativeCode=[SUActivationNative]::NewWritableOpen([string]$command.Path);$result.Path=[string]$command.Path}
'@
    if(-not $body.Contains($anchor)){throw 'R02 actor template anchor missing'}
    return $body.Replace($anchor,($branch+"`n"+$anchor))
}
function Test-R02Held($Snapshot,[string]$FileId,[string]$NtPath,[int]$PidExpected,[uint32]$Generation) {
    $entries=@($Snapshot.Entries);$good=$entries.Count -eq 1 -and $Snapshot.Snapshot.Record.policyGeneration -eq $Generation
    if($good){$e=$entries[0];$good=$e.fileId -ieq $FileId -and $e.path -ieq $NtPath -and $e.state -ceq 'Activating' -and
        $null -ne $e.H -and $e.H -gt 0 -and $e.openerPids -contains $PidExpected -and $null -ne $e.W -and $e.W -eq 0 -and $e.unknownReasons -ceq '0x00000000'}
    return @{Name='R02ExactHeldY';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Control 26 identifies the same Y file, actor H>0, drained W and accepted generation without uncertainty.';Evidence=$Snapshot}
}
function Test-R02Protected($Record,[string]$FileId,[switch]$RequireFree) {
    $good=$Record.registryEntry -eq $true -and $Record.historyPresent -is [bool] -and $Record.nameMatches -eq $true -and
        $Record.fileId -ieq $FileId -and $Record.state -ceq 'Protected' -and
        $null -ne $Record.H -and $Record.H -eq 0 -and $Record.S -ceq 'NO' -and $null -ne $Record.C -and $Record.C -eq 0 -and
        $null -ne $Record.T -and $Record.T -eq 0 -and $Record.unknownReasons -ceq '0x00000000'
    if($RequireFree){$good=$good -and $Record.free -eq $true -and $Record.historyPresent -eq $true}
    return @{Name=$(if($RequireFree){'R02FreeAndProtected'}else{'R02XRemainsProtected'});Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Same-ID exact registry query proves Protected with H=0,S=NO,C=T=0 and no unknown reason; Y promotion additionally requires history and Free.';Evidence=$Record}
}
function Test-R02Pending($Status,[uint32]$Generation) {
    $good=$Status.Status -ceq 'OK' -and $Status.ServerSid -ceq 'S-1-5-18' -and $Status.Value.protectionActive -eq $true -and
        $Status.Value.nativePolicyGeneration -eq $Generation -and $Status.Value.admissionCoverage -ceq 'Pending'
    return @{Name='R02PendingWhileHolderLives';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Authenticated LocalSystem current status must remain active/Pending at the accepted generation while Y H is live.';Evidence=$Status}
}
function Add-R02Sample($Trial,$Context,$Baseline,[byte[]]$Expected,[string]$Label) {
    $sample=Capture-InvariantSample $Context $Baseline $Label ($Trial.Samples.Count+1);$Trial.Samples+= $sample
    if($sample.Status -cne 'OK'){throw 'R02 complete raw capture unavailable'}
    foreach($name in @('X\marker.txt','Y\marker.txt')){
        $target=Join-Path $protectedDirectory $name;$images=@($sample.Captures | ForEach-Object {$_.Images} | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ieq $target})
        if(-not $images.Count){throw 'R02 exact target raw image unavailable'}
        foreach($image in $images){
            $checks=Test-CachedImage $image $Baseline.Geometry $Expected ($Label+$name.Substring(0,1));$Trial.Assertions+=@($checks)
            foreach($check in $checks){if($check.ContainsKey('ForbiddenByteCount')){$Trial.ForbiddenByteCount+=[long]$check.ForbiddenByteCount}}
            $original=@($Baseline.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ieq $target})
            if($original.Count -ne 1 -or $original[0].Identity.FileId -ine $image.Identity.FileId){throw 'R02 raw target file identity changed'}
        }
        foreach($uncached in @($false,$true)){
            $reader=[StagedInvariant.Native]::Fresh($target,$uncached,$Context.Geometry.Alignment)
            $good=$reader.Length -eq $Expected.Length -and $reader.Digest -ceq (Get-ActivationSha256 $Expected)
            Add-ActivationAssertion $Trial ($Label+$name.Substring(0,1)+'Reader') $(if($good){'PASS'}else{'FAIL'}) 'Independent fresh and uncached readers must equal the exact baseline.' @{Path=$target;Unbuffered=$uncached;Result=$reader}
        }
    }
}
function Stop-R02AgentAtBarrier($Agent) {
    Close-ActivationNotificationCapture
    Stop-Service -Name $Agent.ServiceName -ErrorAction Stop
    $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](30*[Diagnostics.Stopwatch]::Frequency)
    do{$service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'";if($service.State -ceq 'Stopped' -and $service.ProcessId -eq 0 -and $Agent.Process.HasExited){break};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    if($service.State -cne 'Stopped' -or $service.ProcessId -ne 0 -or -not $Agent.Process.HasExited){throw 'R02 coordinated service stop timeout'}
    $state.AgentServiceStarted=$false;Save-State $state $statePath
    return @{State=$service.State;ProcessId=$service.ProcessId;OldPid=$Agent.Process.Id;OldProcessExited=$Agent.Process.HasExited;Qpc=[Diagnostics.Stopwatch]::GetTimestamp()}
}
function Invoke-R02Observation {
    $script:ActivationNotificationHistory=@();$script:ActivationObservedPrematureReady=@();$script:ActivationHolderLive=$false;$script:ActivationCandidateGeneration=$null
    $context=$null;$agent=$null;$actor=$null;$baseline=$null;$traceEnabled=$false
    $trial=[ordered]@{Errors=@();Assertions=@();Operations=@();Samples=@();Reasons=@();Verdict='INCONCLUSIVE';ForbiddenByteCount=$null}
    $x=Join-Path $state.R02ScopeX 'marker.txt';$y=Join-Path $state.R02ScopeY 'marker.txt'
    try{
        Assert-Hash $installedDriver $ExpectedFeatureSha256
        if((Get-BootId) -ceq $state.PrepareBootId -or (Get-ItemProperty "HKLM:\$registryService").Start -ne 0 -or @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'R02 requires a new boot-start boot with absent agent'}
        if($Mode -ceq 'runtime-verifier'){& verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host;if($LASTEXITCODE -ne 0){throw 'Runtime Verifier arm failed'}}
        $trial.VerifierBefore=Get-VerifierEvidence 'r02-before' -RequireMode;$ready=Get-Readiness;$boot=Get-BootPolicyReadback
        if($ready.VolumeGuid -cne $state.VolumeGuid -or $boot.RecordBase64 -cne $state.ExpectedBootRecord -or $boot.PendingPresent -or $boot.PrefixCount -ne 1 -or -not $boot.AclValid){throw 'R02 exact X-only boot policy mismatch'}
        $context=Open-InvariantObserver $ready.VolumeGuid $protectedDirectory (Join-Path $evidenceDirectory 'raw') $CaseId
        if($context.Status -cne 'OK'){throw 'R02 raw observer unavailable'}
        $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID);$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
        if($owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18' -or $owner.Sid -cne $context.ObserverSid){throw 'R02 SYSTEM observer provenance mismatch'}
        $trial.Platform=@{Build=$context.Build;BootId=$context.BootId;ObserverPid=$PID;ObserverSid=$owner.Sid;ObserverProcess=@{Pid=$PID;OwnerSid=$owner.Sid;SessionId=$process.SessionId;CommandLine=$process.CommandLine}}
        Start-ScheduledTask -TaskName $writerTask;$actor=Get-ActivationActorIdentity;$trial.Actor=$actor;$trial.ActorProvenance=$actor
        $holder=Publish-ActivationActorCommand $state 'create-holder' $null
        if($holder.NativeCode -ne 0 -or -not $holder.HolderCreated -or $holder.SourceHandleClosed){throw 'R02 clean pre-scope physical H holder failed'}
        $trial.HolderSetup=$holder;$script:ActivationHolderLive=$true;$trial.SetupCacheFlush=Flush-InvariantSetupVolume
        $p=[Convert]::FromBase64String($state.BaselineBase64);$baseline=Capture-InvariantBaseline $context @('X\marker.txt','Y\marker.txt') @{'X\marker.txt'=$p;'Y\marker.txt'=$p}
        if($baseline.Status -cne 'OK'){throw 'R02 raw baseline unavailable'}
        $xId=[string](@($baseline.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ieq $x})[0].Identity.FileId)
        $yId=[string](@($baseline.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ieq $y})[0].Identity.FileId);$ntY=Get-NtDevicePath $y
        $trial.ForbiddenByteCount=[long]0;Add-R02Sample $trial $context $baseline $p 'R02BeforeApply'
        $trial.Assertions+=Test-R02Protected (Get-ActivationEntry $x 'r02-x-before').Record $xId
        $before=Get-ActivationEpochStatus 'r02-before-apply';$trial.TaintCounterBefore=Get-ActivationTaintCounters 'r02-before'
        $policy=Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
        if(@($policy.monitoredScopes.destinationPaths).Count -ne 1 -or $policy.monitoredScopes.destinationPaths[0] -ine $state.R02ScopeX){throw 'R02 initial service policy is not X-only'}
        $policy.version=[int]$policy.version+1;$policy.monitoredScopes.destinationPaths=@($state.R02ScopeX,$state.R02ScopeY)
        Write-DurableFile $policyPath ($policy | ConvertTo-Json -Depth 8)
        $agent=Start-StagedTestAgent $serviceDirectory (Join-Path $evidenceDirectory 'r02-agent') -Arguments '--Diagnostics:StagedProofProxy=true'
        $state.AgentServiceStarted=$true;$state.AgentServiceCreated=$agent.ServiceCreated;$state.AgentOriginalService=$agent.OriginalService;Save-State $state $statePath
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](60*[Diagnostics.Stopwatch]::Frequency)
        $wantedPrefixes=@((Get-NtDevicePath $state.R02ScopeX),(Get-NtDevicePath $state.R02ScopeY));$applied=$false;$applyError=$null
        do{try{$epoch=Get-ActivationEpochStatus 'r02-applied';$committed=Get-BootPolicyReadback
            $applied=$epoch.policyGeneration -gt $before.policyGeneration -and $epoch.epochGeneration -gt $before.epochGeneration -and $epoch.flags -eq 0 -and $epoch.activeCallbacks -eq 0 -and -not $committed.PendingPresent -and $committed.AclValid -and
                ($committed.Prefixes -join ';') -ieq ($wantedPrefixes -join ';')
            if($applied){break}
        }catch{$applyError=$_.Exception.Message};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        Add-ActivationAssertion $trial 'R02PolicyFullyAppliedBeforeStop' $(if($applied){'PASS'}else{'FAIL'}) 'Real service policy startup advanced authenticated policy/epoch and durably finalized X+Y before the coordinated stop.' @{Before=$before;After=$epoch;BootPolicy=$committed;LastError=$applyError}
        if(-not $applied){throw 'R02 policy apply/finalization timeout'}
        $generation=[uint32]$epoch.policyGeneration;$script:ActivationCandidateGeneration=$generation
        $trial.Assertions+=Test-R02Held (Get-ActivationPendingEntry $ntY $yId 'r02-before-stop-y' $y) $yId $ntY $actor.Pid $generation
        $pending=Wait-ActivationProductStatus 'Pending' $generation 45 'r02-before-stop';$trial.Assertions+=Test-R02Pending $pending $generation
        $trial.ServiceBefore=Get-ServiceSnapshot 'r02-before-stop' -JournalOnly
        Add-R02Sample $trial $context $baseline $p 'R02AppliedHeld'
        if(@($trial.Assertions | Where-Object Verdict -cne 'PASS').Count){throw 'R02 coordinated stop prerequisites failed'}
        $trial.StopBarrier=Stop-R02AgentAtBarrier $agent
        Add-ActivationAssertion $trial 'R02AgentStoppedAtAppliedHeldBarrier' 'PASS' 'SCM Stopped, PID zero and original process exited after applied policy and exact held Y evidence.' $trial.StopBarrier
        $trial.Assertions+=Test-R02Protected (Get-ActivationEntry $x 'r02-x-down').Record $xId
        foreach($path in @($x,$y)){$probe=Publish-ActivationActorCommand $state 'r02-probe-path' @{Path=$path};$trial.Operations+= $probe
            Add-ActivationAssertion $trial 'R02DownNewWritableOpenRefused' $(if($probe.NativeCode -eq 5){'PASS'}else{'FAIL'}) 'The standard actor attempts a fresh writable open in X and Y while the service is stopped; both require Win32 5.' $probe}
        Add-R02Sample $trial $context $baseline $p 'R02ServiceDown'
        $null=Invoke-ActivationInspector '--admission-trace-clear' (Join-Path $evidenceDirectory 'r02-trace-clear');$null=Invoke-ActivationInspector '--admission-trace-enable-sections-lifetime' (Join-Path $evidenceDirectory 'r02-trace-enable');$traceEnabled=$true
        Start-Service -Name SafeUploadAgent
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](30*[Diagnostics.Stopwatch]::Frequency)
        do{$svc=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'";if($svc.State -ceq 'Running' -and $svc.ProcessId -ne 0){break};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        if($svc.State -cne 'Running' -or $svc.ProcessId -eq 0){throw 'R02 service restart timeout'}
        $agent.Process=Get-Process -Id ([int]$svc.ProcessId);$state.AgentServiceStarted=$true;Save-State $state $statePath
        $acceptedGeneration=$generation;$restartApplied=$false;$deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](60*[Diagnostics.Stopwatch]::Frequency)
        do{try{$epoch=Get-ActivationEpochStatus 'r02-restarted';$committed=Get-BootPolicyReadback
            if($epoch.policyGeneration -ge $acceptedGeneration -and $epoch.flags -eq 0 -and $epoch.activeCallbacks -eq 0 -and -not $committed.PendingPresent -and $committed.AclValid -and
                ($committed.Prefixes -join ';') -ieq ($wantedPrefixes -join ';')){
                $pending=Get-ActivationCurrentProductStatus 'r02-restarted-held' 3000
                if($pending.Status -ceq 'OK' -and $pending.Value.protectionActive -eq $true -and $pending.Value.nativePolicyGeneration -eq $epoch.policyGeneration -and $pending.Value.admissionCoverage -ceq 'Pending'){$restartApplied=$true;break}
            }
        }catch{$applyError=$_.Exception.Message};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        if(-not $restartApplied){throw ('R02 restarted X+Y policy/current Pending status unavailable: '+$applyError)}
        $generation=[uint32]$epoch.policyGeneration;$script:ActivationCandidateGeneration=$generation;$trial.Assertions+=Test-R02Pending $pending $generation
        $trial.Assertions+=Test-R02Held (Get-ActivationPendingEntry $ntY $yId 'r02-restarted-y' $y) $yId $ntY $actor.Pid $generation
        Add-R02Sample $trial $context $baseline $p 'R02RestartedHeld'
        $heldBeforeRelease=Test-R02Held (Get-ActivationPendingEntry $ntY $yId 'r02-before-release-y' $y) $yId $ntY $actor.Pid $generation
        $trial.Assertions+= $heldBeforeRelease
        $pendingBeforeRelease=Test-R02Pending (Get-ActivationCurrentProductStatus 'r02-before-release' 3000) $generation;$trial.Assertions+= $pendingBeforeRelease
        if($heldBeforeRelease.Verdict -cne 'PASS' -or $pendingBeforeRelease.Verdict -cne 'PASS'){throw 'R02 exact held/Pending proof failed before release'}
        Close-ActivationNotificationCapture
        if(@($script:ActivationNotificationHistory | Where-Object {$_.HolderLive -and $_.Value.admissionCoverage -ceq 'Ready'}).Count){throw 'R02 observed Ready while the holder lived'}
        $release=Publish-ActivationActorCommand $state 'release-holder' $null;$trial.LastHolderRelease=$release;$script:ActivationHolderLive=$false
        if($release.NativeCode -ne 0 -or -not $release.HolderReleased){throw 'R02 final H release failed'}
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](90*[Diagnostics.Stopwatch]::Frequency)
        do{$protected=Get-ActivationEntry $y 'r02-promoted';$free=Test-R02Protected $protected.Record $yId -RequireFree;if($free.Verdict -ceq 'PASS'){break};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        $trial.Assertions+= $free
        $trace=ConvertFrom-ActivationPromotionTrace (Invoke-ActivationInspector '--promotion-trace' (Join-Path $evidenceDirectory 'r02-promotion-trace')) $yId
        $edges=@($trace.Entries | Where-Object {$_.stateBefore -eq 1 -and $_.stateAfter -eq 2})
        $edgeGood=$edges.Count -eq 1 -and $edges[0].Hsample -eq 0 -and $edges[0].Wsample -eq 0 -and $edges[0].Tsample -eq 0 -and $edges[0].CforSopSample -eq 0 -and $edges[0].unknownReasonsSample -eq 0
        Add-ActivationAssertion $trial 'R02PromotionDrainedW' $(if($edgeGood){'PASS'}else{'FAIL'}) 'Loss-free same-file promotion edge records drained H/W/T/C and no uncertainty; registry separately proves S=NO/Free.' $trace
        if($free.Verdict -cne 'PASS' -or -not $edgeGood){throw 'R02 final Free/Protected proof failed'}
        $trial.ServiceReady=Wait-ActivationProductStatus 'Ready' $generation 60 'r02-final-ready'
        Add-ActivationAssertion $trial 'R02ReadyAfterRelease' 'PASS' 'Authenticated Ready at the restarted generation follows holder release and same-ID Free/Protected.' $trial.ServiceReady
        $trial.Assertions+=Test-R02Protected (Get-ActivationEntry $x 'r02-x-final').Record $xId
        Add-R02Sample $trial $context $baseline $p 'R02FinalProtected'
        $trial.ServiceAfter=Get-ServiceSnapshot 'r02-final' -JournalOnly;$delta=Test-ServiceJournalDelta $trial.ServiceBefore $trial.ServiceAfter $true
        Add-ActivationAssertion $trial 'R02NoHolderPublication' $(if($delta.Complete -and -not $delta.NewEntries.Count -and -not $delta.Findings.Count){'PASS'}else{'FAIL'}) 'Clean physical holder and refused opens create no new transfer or publication through restart.' $delta
        $trial.VerifierAfter=Get-VerifierEvidence 'r02-after' -RequireMode
    }catch{$trial.Errors+=Get-ErrorChain $_.Exception;Add-ActivationAssertion $trial 'R02Execution' 'INCONCLUSIVE' ($_.Exception.Message+'; '+$_.ScriptStackTrace) $null}
    finally{
        try{Close-ActivationNotificationCapture}catch{$trial.Errors+=Get-ErrorChain $_.Exception}
        $trial.NotificationStatusHistory=@($script:ActivationNotificationHistory)
        Add-ActivationAssertion $trial 'R02NoObservedReadyWhileHolderLives' $(if(@($trial.NotificationStatusHistory | Where-Object {$_.HolderLive -and $_.Value.admissionCoverage -ceq 'Ready'}).Count){'FAIL'}elseif($trial.LastHolderRelease){'PASS'}else{'INCONCLUSIVE'}) 'All authenticated current status frames collected at the applied and restarted holder checkpoints are non-Ready.' $trial.NotificationStatusHistory
        if($actor){try{$null=Publish-ActivationActorCommand $state 'exit-worker' $null;$trial.ActorTaskCompletion=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken 45}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($trial.TaintCounterBefore){try{$trial.TaintCounterWindow=Get-ActivationTaintCounterDelta $trial.TaintCounterBefore (Get-ActivationTaintCounters 'r02-after')}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($traceEnabled){try{$null=Invoke-ActivationInspector '--admission-trace-disable' (Join-Path $evidenceDirectory 'r02-trace-disable')}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($agent){try{
            $cleanupService=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
            if($cleanupService -and $cleanupService.ProcessId -gt 0){$agent.Process=Get-Process -Id ([int]$cleanupService.ProcessId)}
            Stop-StagedTestAgent $agent;$state.AgentServiceStarted=$false;Save-State $state $statePath
        }catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($context -and $context.Status -ceq 'OK'){$trial.Disposal=Close-InvariantObserver $context}
        $trial.Baseline=$baseline
        $trial.ExpectedTimeline=@{WriterIdentities=@($actor);Points=@($row.ExpectedTimeline);ExternalEvidence=@{Build=$trial.Platform.Build;PrepareBootId=$state.PrepareBootId;ActiveBootId=$context.BootId;ObserverPid=$PID;ObserverSid=$trial.Platform.ObserverSid;ObserverProcess=$trial.Platform.ObserverProcess;ActorProvenance=$trial.ActorProvenance}}
        Add-ActivationAssertion $trial 'LiveTaintFlags' 'INCONCLUSIVE' 'Live flags unavailable; existing Inspector counter window retained.' $trial.TaintCounterWindow
        Add-ActivationAssertion $trial 'NeverReadyWholeHolderInterval' 'INCONCLUSIVE' 'Current authenticated statuses are checkpoint evidence; loss-detecting per-file whole-interval readiness events are deferred.' $null
        Add-ActivationAssertion $trial 'R02PublicationAndTemporalCoverage' 'INCONCLUSIVE' 'Complete raw/fresh/uncached checkpoint images do not replace the deferred continuous mutation ledger.' $null
        $trial.Reasons=@('R02 core stops after finalized policy while a clean physical Y holder lives; all earlier/during-policy stop variants deferred.')
        $trial.Verdict=if(@($trial.Assertions | Where-Object Verdict -ceq 'FAIL').Count){'FAIL'}else{'INCONCLUSIVE'};Save-State $trial $trialPath
    }
}

# Disposable one-boot interactive actor. No LSA secret is created.
function Initialize-InvariantWts {
    if('SUInvariantWts' -as [type]){return}
    Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.ComponentModel;using System.Runtime.InteropServices;using System.Security.Principal;
public sealed class SUInvariantSession { public int SessionId;public int State;public string User;public string Domain;public string Sid;public int TokenSessionId; }
public static class SUInvariantWts {
 [StructLayout(LayoutKind.Sequential)] struct Session { public int Id;public IntPtr Name;public int State; }
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSEnumerateSessionsW(IntPtr server,int reserved,int version,out IntPtr sessions,out int count);
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQuerySessionInformationW(IntPtr server,int session,int kind,out IntPtr value,out int bytes);
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQueryUserToken(uint session,out IntPtr token);
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSLogoffSession(IntPtr server,int session,bool wait);
 [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr value);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr value);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,out int value,int bytes,out int needed);
 static string Query(int id,int kind) { IntPtr p;int bytes;if(!WTSQuerySessionInformationW(IntPtr.Zero,id,kind,out p,out bytes))throw new Win32Exception(Marshal.GetLastWin32Error());try{string text=Marshal.PtrToStringUni(p);return text==null?"":text;}finally{WTSFreeMemory(p);} }
 public static SUInvariantSession[] Read() {
  IntPtr p;int count;if(!WTSEnumerateSessionsW(IntPtr.Zero,0,1,out p,out count))throw new Win32Exception(Marshal.GetLastWin32Error());
  try { if(count<0 || count>256)throw new InvalidOperationException("WTS session count invalid");var list=new List<SUInvariantSession>();int size=Marshal.SizeOf(typeof(Session));
   for(int i=0;i<count;i++){var s=(Session)Marshal.PtrToStructure(IntPtr.Add(p,i*size),typeof(Session));if(s.Id<=0 || s.State==6)continue;var r=new SUInvariantSession{SessionId=s.Id,State=s.State,User=Query(s.Id,5),Domain=Query(s.Id,7),Sid="",TokenSessionId=-1};
    IntPtr token;if(WTSQueryUserToken((uint)s.Id,out token)){try{using(var identity=new WindowsIdentity(token)){r.Sid=identity.User.Value;}int actual,needed;if(!GetTokenInformation(token,12,out actual,4,out needed))throw new Win32Exception(Marshal.GetLastWin32Error());r.TokenSessionId=actual;}finally{CloseHandle(token);}}
    list.Add(r);
   }return list.ToArray();
  }finally{WTSFreeMemory(p);}
 }
 public static void Logoff(int id){if(!WTSLogoffSession(IntPtr.Zero,id,false))throw new Win32Exception(Marshal.GetLastWin32Error());}
}
'@
}
function Set-InvariantActorAutoLogon([string]$Password) {
    $key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $names=@('AutoAdminLogon','DefaultUserName','DefaultDomainName','DefaultPassword','AutoLogonCount')
    $existing=(Get-Item -LiteralPath $key).GetValueNames()
    if(@($names | Where-Object {$existing -contains $_}).Count){throw 'Pre-existing Winlogon autologon values; preserve them, do not overwrite'}
    # Persist ownership before any value is set, so partial Prepare failure rolls back.
    $state.ActorAutoLogonValues=$names;Save-State $state $statePath
    $values=@{AutoAdminLogon='1';DefaultUserName=$state.ActorUser;DefaultDomainName=$env:COMPUTERNAME;DefaultPassword=$Password}
    foreach($name in $values.Keys){$null=New-ItemProperty -LiteralPath $key -Name $name -Value $values[$name] -PropertyType String -Force}
    $null=New-ItemProperty -LiteralPath $key -Name AutoLogonCount -Value 1 -PropertyType DWord -Force
}
function Get-InvariantActorSession {
    Initialize-InvariantWts
    $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](120*[Diagnostics.Stopwatch]::Frequency)
    do{$sessions=@([SUInvariantWts]::Read() | Where-Object {$_.User -ieq $state.ActorUser -and $_.Domain -ieq $env:COMPUTERNAME})
        if($sessions.Count -eq 1 -and $sessions[0].State -eq 0 -and $sessions[0].SessionId -gt 0 -and $sessions[0].Sid -ceq $state.ActorSid -and $sessions[0].TokenSessionId -eq $sessions[0].SessionId){
            $state.ActorInteractiveSession=$sessions[0];Save-State $state $statePath;return $sessions[0]
        };Start-Sleep -Milliseconds 200
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    throw 'Disposable actor did not own one active WTS session with matching WTSQueryUserToken SID/session within 120s'
}
function Test-InvariantInteractiveActor($Session,$Actor) {
    $good=$Session.State -eq 0 -and $Session.SessionId -gt 0 -and $Session.TokenSessionId -eq $Session.SessionId -and
        -not [string]::IsNullOrWhiteSpace($Session.Sid) -and $Session.Sid -ceq $Actor.Sid -and $Session.SessionId -eq $Actor.SessionId -and
        $Actor.Elevated -eq $false -and $Actor.IsAdministrator -eq $false -and $Actor.OwnerSid -ceq $Session.Sid
    return @{Name='InteractiveActorWtsBinding';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='OS-verified limited actor PID/token must match the active owning WTSQueryUserToken SID and session.';Evidence=@{Session=$Session;Actor=$Actor}}
}
function Restore-InvariantActorAutoLogon {
    if(-not $state.ActorAutoLogonValues){return}
    # Remove credentials even if WTS logoff fails; preserve failure in restoration.
    $key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach($name in $state.ActorAutoLogonValues){Remove-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue}
    if(@($state.ActorAutoLogonValues | Where-Object {(Get-Item -LiteralPath $key).GetValueNames() -contains $_}).Count){throw 'Owned autologon value residue'}
    Initialize-InvariantWts
    $sessions=@([SUInvariantWts]::Read() | Where-Object {$_.User -ieq $state.ActorUser -and $_.Domain -ieq $env:COMPUTERNAME})
    foreach($session in $sessions){[SUInvariantWts]::Logoff($session.SessionId)}
    $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](60*[Diagnostics.Stopwatch]::Frequency)
    do{$remaining=@([SUInvariantWts]::Read() | Where-Object {$_.User -ieq $state.ActorUser -and $_.Domain -ieq $env:COMPUTERNAME});if(-not $remaining.Count){break};Start-Sleep -Milliseconds 200}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    if($remaining.Count){throw 'Owned interactive actor WTS session survived logoff'}
    Save-State @{ValuesRemoved=@($state.ActorAutoLogonValues);SessionIdsLoggedOff=@($sessions.SessionId);NoSessionRemains=$true;NoLsaSecretCreated=$true;Qpc=[Diagnostics.Stopwatch]::GetTimestamp()} (Join-Path $evidenceDirectory 'interactive-restoration.clixml')
}
function Invoke-InteractiveCachedObservation {
    $session=$null;$failure=$null
    try{$session=Get-InvariantActorSession}catch{$failure=Get-ErrorChain $_.Exception}
    if($failure){Save-State @{Errors=@($failure);Assertions=@(@{Name='InteractiveActorWtsBinding';Verdict='INCONCLUSIVE';Reason='Interactive boot prerequisite unavailable'});Verdict='INCONCLUSIVE';ForbiddenByteCount=$null} $trialPath;return}
    Invoke-CachedObservation
    $trial=Load-State $trialPath
    $actor=$trial.Actor
    $actor | Add-Member NoteProperty OwnerSid $trial.ActorProvenance.OwnerSid -Force
    $trial.Assertions+=Test-InvariantInteractiveActor $session $actor
    $trial.InteractiveSession=$session
    if(@($trial.Assertions | Where-Object Verdict -ceq 'FAIL').Count){$trial.Verdict='FAIL'}
    Save-State $trial $trialPath
}

function Initialize-B02Fixture([int]$Size) {
    $b=[Text.Encoding]::ASCII.GetBytes(('B02 preboot B '+$RunName+"`n").PadRight($Size,'B'))
    $v1=[Text.Encoding]::ASCII.GetBytes(('B02 v1 '+$RunName+"`nCPF 529.982.247-25`n").PadRight($Size,'U'))
    $v2=[Text.Encoding]::ASCII.GetBytes(('B02 v2 '+$RunName+"`nCPF 529.982.247-25`n").PadRight($Size,'V'))
    if($b.Length -ne $Size -or $v1.Length -ne $Size -or $v2.Length -ne $Size){throw 'B02 fixture length mismatch'}
    $state.B02Images=@{B=[Convert]::ToBase64String($b);V1=[Convert]::ToBase64String($v1);V2=[Convert]::ToBase64String($v2)}
    $stream=[IO.FileStream]::new((Join-Path $protectedDirectory 'cached.txt'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($b,0,$b.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Get-B02JustificationClientBody([string]$NativeType='SUActivationNative') {
(@'
     $pipe=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent.Justification',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
     $reader=$null;$writer=$null;$read=$null
     try{
      $pipe.Connect(3000);$serverPid=[uint32]0
      if(-not [__PIPE_NATIVE__]::GetNamedPipeServerProcessId($pipe.SafePipeHandle,[ref]$serverPid) -or $serverPid -ne [uint32]$command.ServerPid){throw 'Justification pipe server does not match the OS-verified product service PID'}
      $result.ServerPid=$serverPid;$result.TransferId=[string]$command.TransferId
      $encoding=[Text.UTF8Encoding]::new($false);$writer=[IO.StreamWriter]::new($pipe,$encoding,1024,$true);$writer.AutoFlush=$true
      $line=@{eventId=[string]$command.TransferId;justification='SafeUpload harness exact-version core'} | ConvertTo-Json -Compress
      $write=$writer.WriteLineAsync($line);if(-not $write.Wait(5000)){throw 'Justification request write timeout'};$write.GetAwaiter().GetResult()
      $reader=[IO.StreamReader]::new($pipe,$encoding,$false,1024,$true);$read=$reader.ReadLineAsync()
      if(-not $read.Wait(5000)){throw 'Justification response timeout'};$result.Reply=$read.GetAwaiter().GetResult()
      if($result.Reply -cnotin @('accepted','rejected')){throw 'Malformed real justification protocol reply'};$result.NativeCode=0
     }finally{$pipe.Dispose();if($read -and -not $read.IsCompleted){try{[void]$read.Wait(1000)}catch{}};if($read -and -not $read.IsCompleted){throw 'Justification read did not join after pipe close'};if($reader){$reader.Dispose()};if($writer){$writer.Dispose()}}
'@
).Replace('__PIPE_NATIVE__',$NativeType)
}
function Get-B02WriterBody {
    $body=Get-ActivatingWriterBody
    $native=@'
 public static int B02OverwriteHeld(string path,byte[] bytes,out long written) {
  written=0;if(FileHandle!=new IntPtr(-1))return 6;
  FileHandle=CreateFileW(path,0xC0000000u,7,IntPtr.Zero,5,0x80,IntPtr.Zero);
  if(FileHandle==new IntPtr(-1))return Error();uint count;
  if(!WriteFile(FileHandle,bytes,(uint)bytes.Length,out count,IntPtr.Zero))return Error();
  written=count;if(count!=bytes.Length)return 29;return FlushHolderFile();
 }
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetNamedPipeServerProcessId(SafePipeHandle h,out uint pid);
'@
    $nativeAnchor=' public static int ReleaseHolder() {'
    $profile=@'
 $actor.Profile=[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
 if([string]::IsNullOrWhiteSpace($actor.Profile)){throw 'Interactive actor profile unavailable'}
 $handBackRoot=Join-Path $actor.Profile 'SafeUpload\_bloqueados'
 function Get-B02OwnerFiles {
  $files=@();if(Test-Path -LiteralPath $handBackRoot){foreach($file in @(Get-ChildItem -LiteralPath $handBackRoot -Force)){
   if($file.PSIsContainer){throw 'Unexpected hand-back subdirectory'}
   $files+=@{Path=$file.FullName;Length=$file.Length;Sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}
  }};return ,$files
 }
 $actor.HandBackBefore=Get-B02OwnerFiles
'@
    $identityAnchor=" Save-ActivationActorState `$actor '__IDENTITY__' -New"
    $branch=@'
    'b02-overwrite-held' {
     $bytes=[Convert]::FromBase64String($command.PayloadBase64);$written=[long]0
     $result.NativeCode=[SUActivationNative]::B02OverwriteHeld($config.Target,$bytes,[ref]$written);$result.BytesWritten=$written
     $result.HolderCreated=($result.NativeCode -eq 0);if($result.HolderCreated){$result.PrivateSha256=[SUActivationNative]::HolderDigest($bytes.Length)}
    }
    'b02-handback' {$result.Files=Get-B02OwnerFiles;$result.NativeCode=0}
    'b02-justify' {
__B02_REAL_PIPE_CLIENT__
    }
'@
    $anchor="    default {throw ('Unknown actor action: '+`$command.Action)}"
    foreach($required in @($nativeAnchor,$identityAnchor,$anchor)){if(-not $body.Contains($required)){throw 'B02 actor template anchor missing'}}
    return $body.Replace($nativeAnchor,($native+"`n"+$nativeAnchor)).Replace($identityAnchor,($profile+"`n"+$identityAnchor)).Replace($anchor,($branch.Replace('__B02_REAL_PIPE_CLIENT__',(Get-B02JustificationClientBody))+"`n"+$anchor))
}
function Get-B02Journal($Trial,$Actor,[string]$Tag,[string[]]$Exclude=@()) {
    $poll=Get-CachedJournalObservation $Tag $Actor @((Join-Path $protectedDirectory 'cached.txt')) $Exclude;$Trial.JournalSnapshots+= $poll.Snapshot
    if($poll.Status -cne 'OK' -or $poll.Entries.Count -ne 1){throw ('B02 needs one exact actor transfer: '+($poll.Errors | Out-String))}
    $entry=$poll.Entries[0];$manifest=ConvertFrom-ServiceJournalRecord $entry.Record
    $entry | Add-Member NoteProperty Manifest $manifest.Entry
    return $entry
}
function Wait-B02Terminal($Trial,$Actor,[string]$Expected,[string[]]$Exclude=@()) {
    $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](120*[Diagnostics.Stopwatch]::Frequency);$n=0
    do{$entry=Get-B02Journal $Trial $Actor ('b02-'+$Expected+'-'+[guid]::NewGuid().ToString('N')) $Exclude
        if($entry.StateName -ceq $Expected){return $entry}
        if($entry.StateName -cin @('Blocked','Retained','Unsealed','Released') -and $entry.StateName -cne $Expected){throw ('B02 unexpected terminal '+$entry.StateName)}
        Start-Sleep -Milliseconds 100;$n++
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    throw ('B02 '+$Expected+' timeout')
}
function Test-B02Window($Entry,$Actor,[string]$Digest) {
    $m=$Entry.Manifest
    $good=$Entry.StateName -ceq 'Blocked' -and $Entry.SealedOnce -eq $true -and $Entry.Sha256Hex -ceq $Digest -and
        $m.JustificationWindowClosed -eq $false -and $null -ne $m.JustificationExpiresAtUtc -and $m.BlockedPolicyVersion -gt 0 -and
        $m.HandbackState -eq 2 -and $m.Sha256Hex -ceq $Digest -and -not [string]::IsNullOrWhiteSpace($m.HandbackPath) -and
        $m.Transfer.SessionId -eq $Actor.SessionId -and $m.Transfer.RequestorSid -ceq $Actor.Sid -and $m.Transfer.ProcessId -eq $Actor.Pid
    return @{Name='B02OwningSessionJustificationWindow';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Authenticated Blocked manifest must bind exact digest/PID/SID/session, verified hand-back and an open product justification window.';Evidence=$Entry}
}
function Test-B02Versions($First,$Latest,[string]$Digest1,[string]$Digest2) {
    $distinct=-not [string]::IsNullOrWhiteSpace($First.TransferId) -and -not [string]::IsNullOrWhiteSpace($Latest.TransferId) -and
        $First.TransferId -ine $Latest.TransferId -and $First.DestinationGeneration -gt 0 -and $Latest.DestinationGeneration -gt $First.DestinationGeneration -and $Digest1 -cne $Digest2
    $old=$First.StateName -ceq 'Blocked' -and $First.SealedOnce -eq $true -and $First.Sha256Hex -ceq $Digest1 -and ($First.History -join ',') -ceq 'Allocated,Sealed,Inspecting,Blocked'
    $new=$Latest.StateName -ceq 'Released' -and $Latest.SealedOnce -eq $true -and $Latest.Sha256Hex -ceq $Digest2 -and
        ($Latest.History -join ',') -ceq 'Allocated,Sealed,Inspecting,Blocked,Inspecting,Approved,Publishing,Released'
    return ,@(@{Name='B02DistinctLatestGeneration';Verdict=$(if($distinct){'PASS'}else{'FAIL'});Reason='v2 is a distinct later destination generation and digest.'},
        @{Name='B02StaleV1NeverPublished';Verdict=$(if($distinct -and $old){'PASS'}else{'FAIL'});Reason='v1 durable history stays exactly Blocked with its original digest; stale justification produces no inspection/approval/publication/release.';Evidence=$First},
        @{Name='B02LatestV2ReleasedOnce';Verdict=$(if($distinct -and $new){'PASS'}else{'FAIL'});Reason='Latest exact v2 traverses Blocked -> fresh Inspecting -> Approved -> Publishing -> Released exactly once.';Evidence=$Latest})
}
function Test-B02Notifications($Proof,[string]$FirstId,[string]$LatestId,[int]$SessionId,[string]$Digest1,[string]$Digest2) {
    $first=@($Proof.Emissions | ForEach-Object {$_.Entry} | Where-Object {$_.Kind -ceq 'Transfer' -and $_.TransferId -ieq $FirstId})
    $latest=@($Proof.Emissions | ForEach-Object {$_.Entry} | Where-Object {$_.Kind -ceq 'Transfer' -and $_.TransferId -ieq $LatestId})
    $blocked1=@($first | Where-Object Phase -ceq 'Blocked');$blocked2=@($latest | Where-Object Phase -ceq 'Blocked');$released=@($latest | Where-Object Phase -ceq 'Released')
    $good=$Proof.Complete -eq $true -and $blocked1.Count -eq 1 -and $blocked2.Count -eq 1 -and $released.Count -eq 1 -and
        @($first | Where-Object Phase -ceq 'Released').Count -eq 0 -and @(@($first)+@($latest) | Where-Object TargetSessionId -ne $SessionId).Count -eq 0
    if($good){$good=$blocked1[0].Sha256Hex -ceq $Digest1 -and $blocked2[0].Sha256Hex -ceq $Digest2 -and $released[0].Sha256Hex -ceq $Digest2 -and
        $blocked1[0].Sequence -lt $blocked2[0].Sequence -and $blocked2[0].Sequence -lt $released[0].Sequence}
    return @{Name='B02ExactVersionNotifications';Verdict=$(if($good){'PASS'}elseif(-not $Proof.Complete){'INCONCLUSIVE'}else{'FAIL'});Reason='Authenticated complete real emission sequence binds owner session and v1 Blocked -> v2 Blocked -> one v2 Released, with exact digests and no v1 release.';Evidence=$Proof}
}
function Get-B02HandBack($Actor,$OwnerFiles,[string]$Digest,[int]$Length,[string]$Label) {
    $evidenceDirectory=Join-Path $evidenceDirectory $Label;$null=New-Item -ItemType Directory -Path $evidenceDirectory
    return Get-X01HandBack $Actor $OwnerFiles $Digest $Length
}
function Invoke-B02Observation {
    $context=$null;$agent=$null;$actor=$null;$baseline=$null;$first=$null;$latest=$null;$readyEvent=$null
    $trial=[ordered]@{Errors=@();Assertions=@();Operations=@();Samples=@();PublicReceipts=@();JournalSnapshots=@();Reasons=@();Verdict='INCONCLUSIVE';ForbiddenByteCount=$null}
    try{
        Assert-Hash $installedDriver $ExpectedFeatureSha256
        if((Get-BootId) -ceq $state.PrepareBootId -or (Get-ItemProperty "HKLM:\$registryService").Start -ne 0 -or @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'B02 requires a new boot-start boot with initially absent agent'}
        $session=Get-InvariantActorSession;$trial.InteractiveSession=$session
        if($Mode -ceq 'runtime-verifier'){& verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host;if($LASTEXITCODE -ne 0){throw 'Runtime Verifier arm failed'}}
        $trial.VerifierBefore=Get-VerifierEvidence 'b02-before' -RequireMode;$ready=Get-Readiness;$boot=Get-BootPolicyReadback
        if($ready.VolumeGuid -cne $state.VolumeGuid -or $boot.RecordBase64 -cne $state.ExpectedBootRecord -or $boot.PendingPresent -or -not $boot.AclValid){throw 'B02 exact boot policy mismatch'}
        $readyEvent=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,'Global\SafeUploadServiceReady');[void]$readyEvent.Reset()
        $agent=Start-StagedTestAgent $serviceDirectory (Join-Path $evidenceDirectory 'b02-agent') -Arguments '--Diagnostics:StagedProofProxy=true'
        $state.AgentServiceStarted=$true;$state.AgentServiceCreated=$agent.ServiceCreated;$state.AgentOriginalService=$agent.OriginalService;Save-State $state $statePath
        if(-not $readyEvent.WaitOne([TimeSpan]::FromSeconds(45))){throw 'B02 agent Ready timeout'}
        $serverProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+$agent.Process.Id)
        $serverOwner=Invoke-CimMethod -InputObject $serverProcess -MethodName GetOwnerSid
        if($serverOwner.ReturnValue -ne 0 -or $serverOwner.Sid -cne 'S-1-5-18' -or $serverProcess.Name -cne 'SafeUpload.Agent.Service.exe'){throw 'B02 justification product server OS provenance mismatch'}
        $trial.JustificationServerProvenance=@{Pid=$agent.Process.Id;OwnerSid=$serverOwner.Sid;CommandLine=$serverProcess.CommandLine}
        $trial.TaintCounterBefore=Get-ActivationTaintCounters 'b02-before'
        $context=Open-InvariantObserver $ready.VolumeGuid $protectedDirectory (Join-Path $evidenceDirectory 'raw') $CaseId
        if($context.Status -cne 'OK'){throw 'B02 raw observer unavailable'}
        $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID);$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
        if($owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18' -or $owner.Sid -cne $context.ObserverSid){throw 'B02 SYSTEM observer provenance mismatch'}
        $trial.Platform=@{Build=$context.Build;BootId=$context.BootId;ObserverPid=$PID;ObserverSid=$owner.Sid;ObserverProcess=@{Pid=$PID;OwnerSid=$owner.Sid;SessionId=$process.SessionId;CommandLine=$process.CommandLine}}
        Start-ScheduledTask -TaskName $writerTask;$actor=Get-ActivationActorIdentity
        $identity=Wait-WriterIdentity (Join-Path $actorDirectory 'identity.clixml');$actor | Add-Member NoteProperty Profile $identity.Profile;$actor | Add-Member NoteProperty HandBackBefore @($identity.HandBackBefore)
        $trial.Actor=$actor;$trial.ActorProvenance=$actor;$trial.Assertions+=Test-InvariantInteractiveActor $session $actor
        if($trial.Assertions[-1].Verdict -cne 'PASS'){throw 'B02 interactive task token/session mismatch'}
        $b=[Convert]::FromBase64String($state.B02Images.B);$v1=[Convert]::FromBase64String($state.B02Images.V1);$v2=[Convert]::FromBase64String($state.B02Images.V2)
        $d1=Get-ActivationSha256 $v1;$d2=Get-ActivationSha256 $v2;$target=Join-Path $protectedDirectory 'cached.txt'
        $baseline=Capture-InvariantBaseline $context @('marker.bin','cached.txt') @{'marker.bin'=[Convert]::FromBase64String($state.BaselineBase64);'cached.txt'=$b}
        if($baseline.Status -cne 'OK'){throw 'B02 preboot raw B baseline unavailable'}
        $trial.ForbiddenByteCount=[long]0;$trial.ServiceBefore=Get-ServiceSnapshot 'b02-before'
        if($trial.ServiceBefore.Status -cne 'OK'){throw 'B02 initial authenticated service snapshot unavailable'}
        $null=Add-X01PublicSample $trial $context $baseline $b $v2 $true 'B02BeforeWrites'
        $writeStart=[Diagnostics.Stopwatch]::GetTimestamp()
        $exclude=@();$handbacks=@();$priorFiles=@($actor.HandBackBefore)
        foreach($version in @(@{Name='V1';Bytes=$v1;Digest=$d1},@{Name='V2';Bytes=$v2;Digest=$d2})){
            $held=Publish-ActivationActorCommand $state 'b02-overwrite-held' @{PayloadBase64=[Convert]::ToBase64String($version.Bytes)};$trial.Operations+= $held
            $good=$held.NativeCode -eq 0 -and $held.HolderCreated -and $held.BytesWritten -eq $version.Bytes.Length -and $held.PrivateSha256 -ceq $version.Digest
            Add-ActivationAssertion $trial ('B02'+$version.Name+'PrivateOverwrite') $(if($good){'PASS'}else{'FAIL'}) 'Interactive standard actor uses native TRUNCATE_EXISTING/write/flush and reads its exact whole private image while the upper handle lives.' $held
            if(-not $good){throw 'B02 private overwrite failed'}
            $allocated=Get-B02Journal $trial $actor ('b02-held-'+$version.Name) $exclude
            if($allocated.StateName -cne 'Allocated' -or $allocated.SealedOnce){throw 'B02 held mutable transfer was sealed early'}
            $null=Add-X01PublicSample $trial $context $baseline $b $v2 $true ('B02'+$version.Name+'Held')
            $close=Publish-ActivationActorCommand $state 'release-holder' $null;$trial.Operations+= $close
            if($close.NativeCode -ne 0 -or -not $close.HolderReleased){throw 'B02 upper source close failed'}
            $blocked=Wait-B02Terminal $trial $actor 'Blocked' $exclude
            # Blocked state can precede hand-back completion/Remember. Wait for
            # the authenticated manifest to expose its verified open window.
            $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](15*[Diagnostics.Stopwatch]::Frequency)
            do{$blocked=Get-B02Journal $trial $actor ('b02-window-'+[guid]::NewGuid().ToString('N')) $exclude;$window=Test-B02Window $blocked $actor $version.Digest;if($window.Verdict -ceq 'PASS'){break};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
            $window.Name='B02'+$version.Name+'OwningSessionWindow';$trial.Assertions+= $window
            if($window.Verdict -cne 'PASS'){throw 'B02 real service could not bind owning session/open justification window'}
            $null=Add-X01PublicSample $trial $context $baseline $b $v2 $true ('B02'+$version.Name+'Blocked')
            $ownerFiles=Publish-ActivationActorCommand $state 'b02-handback' $null
            $handbackActor=@{Sid=$actor.Sid;Profile=$actor.Profile;HandBackBefore=$priorFiles}
            $h=Get-B02HandBack $handbackActor $ownerFiles.Files $version.Digest $version.Bytes.Length ('b02-handback-'+$version.Name)
            foreach($check in $h.Assertions){$check.Name='B02'+$version.Name+$check.Name};$trial.Assertions+=@($h.Assertions);$handbacks+= $h
            if(@($h.Assertions | Where-Object Verdict -cne 'PASS').Count){throw 'B02 exact snapshot hand-back failed'}
            $priorFiles=@($ownerFiles.Files)
            if($version.Name -ceq 'V1'){$first=$blocked;$exclude=@($first.TransferId)}else{$latest=$blocked}
        }
        $stale=Publish-ActivationActorCommand $state 'b02-justify' @{TransferId=$first.TransferId;ServerPid=$agent.Process.Id};$trial.StaleSubmission=$stale
        Add-ActivationAssertion $trial 'B02RealStaleSubmissionRejected' $(if($stale.NativeCode -eq 0 -and $stale.Reply -ceq 'rejected'){ 'PASS' }else{ 'FAIL' }) 'The actual bidirectional justification pipe, authenticated to the service PID, rejects v1 from its owning interactive actor after v2 is Blocked.' $stale
        if($stale.Reply -cne 'rejected'){throw 'B02 stale v1 justification was accepted'}
        $first=Get-B02Journal $trial $actor 'b02-after-stale-v1' @($latest.TransferId);$latest=Get-B02Journal $trial $actor 'b02-after-stale-v2' @($first.TransferId)
        if($first.StateName -cne 'Blocked' -or $latest.StateName -cne 'Blocked' -or @($first.History+$latest.History | Where-Object {$_ -cin @('Approved','Publishing','Released')}).Count){throw 'B02 stale request changed publication state'}
        $null=Add-X01PublicSample $trial $context $baseline $b $v2 $true 'B02AfterStaleJustification'
        # The next real protocol request is the only publication-authorizing action.
        $accepted=Publish-ActivationActorCommand $state 'b02-justify' @{TransferId=$latest.TransferId;ServerPid=$agent.Process.Id};$trial.LatestSubmission=$accepted
        Add-ActivationAssertion $trial 'B02RealLatestSubmissionAccepted' $(if($accepted.NativeCode -eq 0 -and $accepted.Reply -ceq 'accepted'){'PASS'}else{'FAIL'}) 'The same interactive actor submits v2 through the real justification protocol and receives accepted after audited publication.' $accepted
        if($accepted.Reply -cne 'accepted'){throw 'B02 latest justification was rejected'}
        $latest=Wait-B02Terminal $trial $actor 'Released' @($first.TransferId);$first=Get-B02Journal $trial $actor 'b02-final-v1' @($latest.TransferId)
        $trial.Assertions+=Test-B02Versions $first $latest $d1 $d2
        $final=Add-X01PublicSample $trial $context $baseline $b $v2 $false 'B02FinalReleased'
        $checks=Test-X01PublicSequence $trial.PublicReceipts (Get-ActivationSha256 $b) $d2 $b.Length
        foreach($check in $checks){$check.Name=$check.Name.Replace('X01','B02')};$trial.Assertions+=@($checks)
        $listing=Test-X01FinalListing $final.Captures[-1] $baseline $target;$listing.Name='B02ExactlyOneFinalTarget';$trial.Assertions+= $listing
        $fenceEnd=[Diagnostics.Stopwatch]::GetTimestamp();Start-Sleep -Milliseconds 1200
        $trial.ServiceAfter=Get-ServiceSnapshot 'b02-after'
        $fence=@{Complete=$true;BootId=$context.BootId;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;ReleasedQpc=$writeStart;CompletedQpc=$fenceEnd}
        $proof=Test-NotificationWindow $trial.ServiceBefore.Notifications $trial.ServiceAfter.Notifications $fence $true
        $trial.Assertions+=Test-B02Notifications $proof $first.TransferId $latest.TransferId $actor.SessionId $d1 $d2
        foreach($check in $trial.Assertions){if($check.Name -clike 'X01Public*'){$check.Name=$check.Name.Replace('X01Public','B02Public')}}
        $trial.FirstVersion=$first;$trial.LatestVersion=$latest;$trial.HandBacks=$handbacks;$trial.VerifierAfter=Get-VerifierEvidence 'b02-after' -RequireMode
    }catch{$trial.Errors+=Get-ErrorChain $_.Exception;Add-ActivationAssertion $trial 'B02Execution' 'INCONCLUSIVE' ($_.Exception.Message+'; '+$_.ScriptStackTrace) $null}
    finally{
        if($actor){try{$null=Publish-ActivationActorCommand $state 'exit-worker' $null;$trial.ActorTaskCompletion=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken 45}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($trial.TaintCounterBefore){try{$trial.TaintCounterWindow=Get-ActivationTaintCounterDelta $trial.TaintCounterBefore (Get-ActivationTaintCounters 'b02-after')}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        if($context -and $context.Status -ceq 'OK'){$trial.Disposal=Close-InvariantObserver $context}
        if($readyEvent){$readyEvent.Dispose()}
        if($agent){try{Stop-StagedTestAgent $agent;$state.AgentServiceStarted=$false;Save-State $state $statePath}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
        $trial.Baseline=$baseline
        $trial.ExpectedTimeline=@{WriterIdentities=@($actor);Points=@($row.ExpectedTimeline);ExternalEvidence=@{Build=$trial.Platform.Build;PrepareBootId=$state.PrepareBootId;ActiveBootId=$context.BootId;ObserverPid=$PID;ObserverSid=$trial.Platform.ObserverSid;ObserverProcess=$trial.Platform.ObserverProcess;ActorProvenance=$trial.ActorProvenance}}
        Add-ActivationAssertion $trial 'LiveTaintFlags' 'INCONCLUSIVE' 'Live flags unavailable; existing Inspector counters retained.' $trial.TaintCounterWindow
        Add-ActivationAssertion $trial 'B02PublicationAndTemporalCoverage' 'INCONCLUSIVE' 'Raw/fresh/uncached whole-image samples and real journal/notification history do not supply the deferred continuous lower mutation/permit ledger.' $null
        $trial.Reasons=@('B02 core uses one interactive standard-user process, two sequential C03 overwrites, stale-v1 rejection and actual justified-v2 publication; other justification variants deferred.')
        $trial.Verdict=if(@($trial.Assertions | Where-Object Verdict -ceq 'FAIL').Count){'FAIL'}else{'INCONCLUSIVE'};Save-State $trial $trialPath
    }
}

function Restore-Suite([switch]$Rollback) {
    $errors=[Collections.Generic.List[string]]::new()
    $ownedTasks=@($bootTask,$writerTask)
    if($null -ne $state.SecondUser){$ownedTasks+=$state.SecondUser.Task}
    if($null -ne $state.ActivationActors){$ownedTasks+=@($state.ActivationActors.Values | ForEach-Object {$_.Task})}
    foreach($task in @($ownedTasks | Sort-Object -Unique)){
        try {if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){Stop-ScheduledTask -TaskName $task;Unregister-ScheduledTask -TaskName $task -Confirm:$false}
            if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Task residue'}}catch{$errors.Add($_.Exception.ToString())}
    }
    # Each restoration step is independent, but failed steps retain recovery state.
    $steps=@(
        @{Name='cached-agent';Action={Restore-CachedAgent}},
        @{Name='activation-test-service';Action={
            if($state.AgentServiceStarted){
                $service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction SilentlyContinue
                if($null -ne $service -and $service.State -ne 'Stopped'){
                    & sc.exe stop SafeUploadAgent | Out-Null
                    if($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1062){throw ('Could not stop leaked test SafeUploadAgent service: sc.exe '+$LASTEXITCODE)}
                    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((30)*[Diagnostics.Stopwatch]::Frequency))
                    do{$service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction SilentlyContinue
                        if($null -eq $service -or $service.State -eq 'Stopped'){break};Start-Sleep -Milliseconds 250
                    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
                    if($null -ne $service -and $service.State -ne 'Stopped'){throw 'Leaked test SafeUploadAgent did not stop within 30s.'}
                }
                if($state.AgentServiceCreated){
                    if($null -ne $service){& sc.exe delete SafeUploadAgent | Out-Null;if($LASTEXITCODE -ne 0){throw ('Could not delete leaked test service: sc.exe '+$LASTEXITCODE)}}
                }elseif($null -ne $service){
                    if($null -eq $state.AgentOriginalService){throw 'Original SafeUploadAgent configuration missing from recovery state.'}
                    Restore-StagedAgentService 'SafeUploadAgent' 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent' $state.AgentOriginalService
                }
                $state.AgentServiceStarted=$false;Save-State $state $statePath
            }
        }},
        @{Name='process-creation-audit';Action={
            if($null -eq $state.OriginalProcessCreationAudit){throw 'Original process-creation audit policy missing; preserve recovery state.'}
            $restored=Set-ProcessCreationAudit ([int]$state.OriginalProcessCreationAudit.CreationFlags)
            if($restored.PerUserPolicyCount -ne $state.OriginalProcessCreationAudit.PerUserPolicyCount){throw 'Per-user audit policy count changed during case.'}
            Save-State $restored (Join-Path $evidenceDirectory 'restored-process-creation-audit.clixml')
        }},
        @{Name='driver';Action={Set-DemandStartAndRestoreDriver}},
        # Policy first: it restores the product root's ACL, which product files inherit (run c01m).
        @{Name='policy';Action={Restore-PolicyFile}},
        @{Name='cached-product-state';Action={Restore-CachedProductState}},
        @{Name='registry';Action={
            $null=Invoke-SystemBody @'
$boot='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters\BootPolicy'
$parent='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters'
if(Test-Path -LiteralPath $boot){Remove-Item -LiteralPath $boot -Recurse -Force}
if(Test-Path -LiteralPath $parent){
    $key=Get-Item -LiteralPath $parent
    if(@(Get-ChildItem -LiteralPath $parent -Force).Count -ne 0 -or $key.GetValueNames().Count -ne 0){throw 'Unexpected registry residue; preserve'}
    Remove-Item -LiteralPath $parent -Force
}
$value='Removed'
'@
            if(Test-Path -LiteralPath $parametersKey){throw 'BootPolicy residue'}
        }},
        @{Name='verifier';Action={& verifier.exe /reset | Out-Host;if($LASTEXITCODE -notin @(0,2)){throw 'Verifier reset failed'}}},
        @{Name='b01-junction';Action={Remove-B01Junction}},
        @{Name='external-fixture';Action={if($state.ExternalDirectory -and (Test-Path -LiteralPath $state.ExternalDirectory)){Remove-Item -LiteralPath $state.ExternalDirectory -Recurse -Force};if($state.ExternalDirectory -and (Test-Path -LiteralPath $state.ExternalDirectory)){throw 'External fixture residue'}}},
        @{Name='fixture';Action={if(Test-Path -LiteralPath $protectedDirectory){Remove-Item -LiteralPath $protectedDirectory -Recurse -Force};if(Test-Path -LiteralPath $protectedDirectory){throw 'Fixture residue'}}},
        @{Name='service-package';Action={if(Test-Path -LiteralPath $serviceDirectory){Remove-Item -LiteralPath $serviceDirectory -Recurse -Force};if(Test-Path -LiteralPath $serviceDirectory){throw 'Service package residue'}}},
        @{Name='second-user-profile';Action={Remove-CachedSecondUserProfile}},
        @{Name='second-user-account';Action={Remove-CachedSecondUser}},
        @{Name='actor-interactive-session';Action={Restore-InvariantActorAutoLogon}},
        @{Name='actor-profile';Action={
            if(-not [string]::IsNullOrWhiteSpace($state.ActorSid)){
                # Windows unloads a profile asynchronously after the task's logon session ends (S00 attempt 5: "Owned user profile
                # still loaded"). End any process the actor still owns, then wait (bounded) for the unload before deleting it.
                foreach($process in @(Get-CimInstance Win32_Process)){
                    try{$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop}catch{continue}
                    if($owner.Sid -ceq $state.ActorSid){Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue}
                }
                $profileDeadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((90)*[Diagnostics.Stopwatch]::Frequency))
                while(@(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $state.ActorSid -and $_.Loaded }).Count -ne 0 -and
                      [Diagnostics.Stopwatch]::GetTimestamp() -lt $profileDeadline){Start-Sleep -Milliseconds 500}
                $profiles=@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $state.ActorSid)
                # Services can keep a batch logon's hive open for minutes even after its processes end (attempt 6: still loaded
                # after 90 s). Defer: Finalize runs after the restoration reboot, where no profile can be loaded, and deletes it.
                if(@($profiles | Where-Object Loaded).Count -ne 0){$state.ProfileDeletionDeferred=$true;Save-State $state $statePath;return}
                foreach($profile in $profiles){Remove-CimInstance -InputObject $profile}
                if(@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $state.ActorSid).Count -ne 0){throw 'Owned profile residue'}
            }
        }},
        @{Name='actor-user';Action={if($state.ActorSid){Set-ActorBatchLogon $state.ActorSid $false};if(Get-LocalUser -Name $state.ActorUser -ErrorAction SilentlyContinue){Remove-LocalUser -Name $state.ActorUser};if(Get-LocalUser -Name $state.ActorUser -ErrorAction SilentlyContinue){throw 'User residue'}}}
    )
    foreach($step in $steps){try{& $step.Action}catch{$errors.Add($step.Name+': '+$_.Exception.ToString())}}
    if($Rollback){try{Set-AgentServiceStart $state.OriginalAgentStart}catch{$errors.Add($_.Exception.ToString())}}
    Save-State @{Errors=@($errors);BootId=(Get-BootId);NeedsRestorationReboot=$true} (Join-Path $evidenceDirectory 'restoration.clixml')
    if($errors.Count -gt 0){throw ('Restoration needs attention; preserve state and checkpoint: '+($errors -join '; '))}
    if($Rollback){
        Copy-Item -LiteralPath $stateDirectory -Destination (Join-Path $evidenceDirectory 'rollback-state') -Recurse
        Remove-Item -LiteralPath $stateDirectory -Recurse -Force
        if(Test-Path -LiteralPath $stateDirectory){throw 'Rollback state residue'}
        'PrepareRollbackComplete=True;RestorationRebootRequired=True'
    }
}

Assert-Platform
Assert-Hash $PSCommandPath $ExpectedSuiteSha256
Assert-Hash (Join-Path $documents $TableFileName) $ExpectedTableSha256
Assert-Hash (Join-Path $documents $ObserverFileName) $ExpectedObserverSha256
Assert-Hash (Join-Path $documents $HelperFileName) $ExpectedHelperSha256
Assert-Hash $inspectorPath $ExpectedInspectorSha256
. (Join-Path $documents $HelperFileName)
Import-Module (Join-Path $documents $ObserverFileName) -Force -DisableNameChecking
$table=Import-PowerShellDataFile (Join-Path $documents $TableFileName)
$matchesRows=@($table.Cases | Where-Object CaseId -ceq $CaseId)
if($matchesRows.Count -ne 1){throw 'Unknown/duplicate CaseId'}
$row=$matchesRows[0]
foreach($field in $table.RowSchema.Required){if(-not $row.ContainsKey($field)){throw "Case schema missing $field"}}
$cachedCaseIds=@('C01-approve-absent','C01-block-absent','C02-approve-absent','C02-block-absent','C03-approve-existing','C03-block-existing','C04-approve','C04-block','C05-denied-external-rename')
$cachedCase=$CaseId -cin $cachedCaseIds
if($CaseId -cin @('R01','B01')){$cachedCase=$true} # Core variants reuse cached preparation and observation barriers.
if($CaseId -ceq 'R03'){$cachedCase=$true} # R03 reuses C01 preparation; its dispatch and assertions are separate.
$cachedFamily=$CaseId.Split('-')[0]
$cachedKind=switch -CaseSensitive ($cachedFamily){'C02'{'mapped'}'C03'{'overwrite'}'C04'{'replacement'}'C05'{'external-rename'}default{'cached'}}
$cachedExisting=$cachedKind -cin @('overwrite','replacement')
$cachedDenial=$cachedKind -ceq 'external-rename'
$activationCaseIds=@('A01','A02','A03','A04')
$isActivationCase=($CaseId -cin $activationCaseIds -or $CaseId -ceq 'A05')
$coreConcurrentCase=$CaseId -ceq 'X01'
$coreRestartPolicyCase=$CaseId -ceq 'R02'
$coreJustificationCase=$CaseId -ceq 'B02'
$interactiveActorCase=$coreJustificationCase -or $CaseId -cin @('C01-block-absent','C03-block-existing','C04-block')
if($row.Status -ne 'Ready' -or ($CaseId -notin @('S00-observer-control','S01-denied-write-after-boot','S02-agent-down-open-refused') -and -not $cachedCase -and -not $isActivationCase -and -not $coreConcurrentCase -and -not $coreRestartPolicyCase -and -not $coreJustificationCase)){'CaseStatus=NOT_READY';throw "Case $CaseId is not implemented"}
if($MappedStackDiagnosticSeconds -ne 0 -and ($CaseId -cnotin @('C02-approve-absent','C02-block-absent') -or $Mode -cne 'runtime-verifier')){throw 'Mapped stack diagnostic requires C02 runtime-Verifier'}
if($DedicatedUnheldLatency -and ($CaseId -cnotin @('C01-approve-absent','C02-approve-absent','C03-approve-existing','C04-approve') -or $MappedStackDiagnosticSeconds)){throw 'Dedicated latency requires an APPROVE C01-C04 case without stack diagnostics'}
if($StartupProbe -and $Phase -ne 'AfterBoot'){throw 'StartupProbe requires AfterBoot'}

if($Phase -eq 'Prepare'){
    if($StartupProbe){throw 'Invalid phase'}
    foreach($path in @($stateDirectory,$evidenceDirectory,$protectedDirectory,$externalDirectory,$parametersKey)){
        if(Test-Path -LiteralPath $path){throw "Pre-existing state: $path"}
    }
    Assert-Hash $installedDriver $originalDriverHash
    Assert-Hash $policyPath $ExpectedOriginalPolicySha256
    Assert-Hash $featureDriver $ExpectedFeatureSha256
    $signature=Get-AuthenticodeSignature -LiteralPath $featureDriver
    if($signature.Status.ToString() -cne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne $ExpectedSignerThumbprint.ToUpperInvariant()){throw ('Feature signature gate failed: require Valid signature and exact build signer '+$ExpectedSignerThumbprint+'; guest trust must be installed by orchestrator')}
    Assert-Hash (Join-Path $documents 'stage-service-publish.zip') $ExpectedServicePackageSha256
    if((Get-ItemProperty "HKLM:\$registryService").Start -ne 3 -or (& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s' -or
        @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0){throw 'Expected unloaded demand-start driver and stopped agent'}
    $originalAgentStart=$null
    $agentKey='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
    if(Test-Path -LiteralPath $agentKey){
        if((Get-Service SafeUploadAgent).Status -ne 'Stopped'){throw 'Agent service must be stopped'}
        $originalAgentStart=[int](Get-ItemProperty $agentKey).Start
    }
    $originalProcessCreationAudit=Get-ProcessCreationAudit
    if($originalProcessCreationAudit.CreationFlags -notin @(0,1,2,3,4) -or $originalProcessCreationAudit.PerUserPolicyCount -ne 0){throw 'Unsupported audit setting or per-user audit overrides present; preserve policy.'}
    New-Item -ItemType Directory -Path $stateDirectory,$evidenceDirectory | Out-Null
    $actorUser='sui'+[guid]::NewGuid().ToString('N').Substring(0,12)
    $volume=@(Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'")
    if($volume.Count -ne 1){throw 'Volume identity ambiguous'}
    # Get-Volume -DriveLetter C can return more than one object on this guest, which made $size an array (S01 wp4proof1:
    # op_Subtraction on Object[]). Take the cluster size from exactly one volume or fail.
    $cVolumes=@(Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'")
    if($cVolumes.Count -ne 1 -or [int]$cVolumes[0].BlockSize -le 0){throw ('Expected exactly one C: volume with a block size; found '+$cVolumes.Count)}
    $size=[int]$cVolumes[0].BlockSize*3
    $baseline=[Text.Encoding]::ASCII.GetBytes(('BASELINE-'+$RunName).PadRight($size,'B'))
    $state=@{CaseId=$CaseId;Mode=$Mode;RunName=$RunName;DedicatedUnheldLatency=$DedicatedUnheldLatency;MappedStackDiagnosticSeconds=$MappedStackDiagnosticSeconds;TableRevision=$table.TableRevision;PrepareBootId=(Get-BootId);
        OriginalAgentStart=$originalAgentStart;OriginalProcessCreationAudit=$originalProcessCreationAudit;OriginalPolicyBase64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($policyPath));
        OriginalPolicyDirectorySddl=(Get-SecuritySddl (Split-Path -Parent $policyPath) $true);OriginalPolicyFileSddl=(Get-SecuritySddl $policyPath $false);
        BaselineBase64=[Convert]::ToBase64String($baseline);VolumeGuid=$volume[0].DeviceID;ActorUser=$actorUser;
        WriterToken=[guid]::NewGuid().ToString('N');CoordinatorToken=[guid]::NewGuid().ToString('N');ForbiddenBlocks=@();Inputs=$PSBoundParameters}
    Save-State $state $statePath
    try {
        Backup-StagedTestDriver (Join-Path $stateDirectory 'SafeUpload.original.sys')
        # Restrict durable evidence and lifecycle state to trusted observers.
        & icacls.exe $stateDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Host
        if($LASTEXITCODE -ne 0){throw 'State ACL failed'}
        & icacls.exe $evidenceDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Evidence ACL failed'}
        # Change only Process Creation, retaining its prior failure setting.
        # Persist the prior policy before auditpol, including rollback failures.
        $enabledAudit=Set-ProcessCreationAudit (([int]$originalProcessCreationAudit.CreationFlags -band 2) -bor 1)
        if($enabledAudit.PerUserPolicyCount -ne 0){throw 'Per-user audit overrides appeared while enabling process creation.'}
        Save-State $enabledAudit (Join-Path $evidenceDirectory 'enabled-process-creation-audit.clixml')
        # Only an installed service has a start type to pin (as Test-StagedBootStart does); S00 attempt 3 threw here on a
        # guest without one.
        if ($null -ne $originalAgentStart) { Set-AgentServiceStart 3 }
        New-Item -ItemType Directory -Path $protectedDirectory,$actorDirectory,$serviceDirectory | Out-Null
        Expand-Archive -LiteralPath (Join-Path $documents 'stage-service-publish.zip') -DestinationPath $serviceDirectory
        if((Get-ServiceTreeHash) -cne $ExpectedServiceTreeSha256.ToUpperInvariant()){throw 'Extracted service tree hash mismatch'}
        if($CaseId -ceq 'R03'){Initialize-R03DisabledAgent}
        $password='Su!'+[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N')
        $user=New-LocalUser -Name $actorUser -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires
        $state.ActorSid=$user.SID.Value
        # Logon requires Users membership; explicitly prove absence of Administrators membership.
        Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $actorUser
        Set-ActorBatchLogon $state.ActorSid $true
        if(@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object SID -eq $user.SID).Count -ne 0){throw 'Actor administrator membership'}
        if($cachedCase -or $coreConcurrentCase -or $coreJustificationCase -or $CaseId -ceq 'A04'){
            # A batch-logon task gets no loaded profile (run c01h: empty UserProfile folder), but hand-back
            # contract H needs the profile a real user has after first logon. Create it explicitly; the
            # actor-profile restoration step removes it.
            if(-not ('SUProfile' -as [type])){Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;using System.Text;public static class SUProfile{[DllImport("userenv.dll",CharSet=CharSet.Unicode)]public static extern int CreateProfile(string sid,string user,StringBuilder path,uint cch);}'}
            $profilePath=[Text.StringBuilder]::new(260)
            $hr=[SUProfile]::CreateProfile($state.ActorSid,$actorUser,$profilePath,260)
            if($hr -ne 0){throw ('Actor profile creation failed: 0x'+$hr.ToString('X8'))}
            $state.ActorProfile=$profilePath.ToString()
        }
        if($CaseId -cin @('C01-block-absent','C03-block-existing','C04-block')){Initialize-CachedSecondUser}
        & icacls.exe $stateDirectory /grant ('*'+$state.ActorSid+':RX') | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Actor traversal ACL failed'}
        & icacls.exe $actorDirectory /grant ('*'+$state.ActorSid+':(OI)(CI)M') | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Actor coordination ACL failed'}
        & icacls.exe $protectedDirectory /grant ('*'+$state.ActorSid+':(OI)(CI)M') | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Fixture ACL failed'}
        # Establish the known fixture before reboot so raw NTFS metadata is
        # durable. The activation actor opens this same file while Unscoped,
        # rewrites/flushed P and retains its physical writable holder.
        $fixtureLeaf=if($isActivationCase){'marker.txt'}else{'marker.bin'}
        $stream=[IO.FileStream]::new((Join-Path $protectedDirectory $fixtureLeaf),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
        try{$stream.Write($baseline,0,$baseline.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        if($coreConcurrentCase){Initialize-X01Fixture $size}
        if($coreRestartPolicyCase){Initialize-R02Fixture $baseline}
        if($coreJustificationCase){Initialize-B02Fixture $size}
        $state.FixtureSddl=Get-SecuritySddl $protectedDirectory $true
        $scopes=if($coreRestartPolicyCase){@($state.R02ScopeX)}elseif($isActivationCase){@()}elseif($CaseId -eq 'S00-observer-control'){@()}else{@($protectedDirectory)}
        if($cachedCase -or $coreConcurrentCase -or $coreRestartPolicyCase -or $coreJustificationCase -or $CaseId -ceq 'A05'){$state.CachedProductBackup=Save-CachedProductState;Save-State $state $statePath}
        Set-ProtectedPolicyAcl
        $extensions=@(if($cachedCase -or $isActivationCase -or $coreConcurrentCase -or $coreRestartPolicyCase -or $coreJustificationCase){'.txt'}else{'.bin'})
        $policy=@{version=1;activeCategories=@('Cpf');monitoredScopes=@{extensions=$extensions;destinationPaths=@($scopes);removableDrives=$false;networkPaths=$false};
            maxFileSizeMb=20;inspectionTimeoutSeconds=5;failOpen=$false;excludedProcesses=@('System','SafeUpload.Agent.App');auditOnly=$false;overrideAllowed=($coreJustificationCase -or ($cachedCase -and $row.Outcome -ceq 'BLOCK'))}
        Write-DurableFile $policyPath ($policy | ConvertTo-Json -Depth 6)
        Copy-Item -LiteralPath $featureDriver -Destination $installedDriver
        Assert-Hash $installedDriver $ExpectedFeatureSha256
        Invoke-ProductSeed
        $readback=Get-BootPolicyReadback
        $expected=New-Object byte[] 16656
        [BitConverter]::GetBytes([uint32]1).CopyTo($expected,0);[BitConverter]::GetBytes([uint32]16656).CopyTo($expected,4)
        [BitConverter]::GetBytes([uint32]$scopes.Count).CopyTo($expected,8)
        if($scopes.Count -gt 0){
            # Resolve NT device identity at seed time and resolve it AGAIN at startup.
            $nt=Invoke-SystemBody @'
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;using System.Text;public static class SUDevice{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern uint QueryDosDevice(string n,StringBuilder b,int c);}'
$b=[Text.StringBuilder]::new(1024);if([SUDevice]::QueryDosDevice('C:',$b,1024) -eq 0){throw 'QueryDosDevice failed'}
$value=$b.ToString().Split([char]0)[0]
'@
            $scopeDos=if($coreRestartPolicyCase){$state.R02ScopeX}else{$protectedDirectory}
            $prefix=$nt+$scopeDos.Substring(2)
            $pb=[Text.Encoding]::Unicode.GetBytes($prefix);if($pb.Length -gt 518){throw 'Scope prefix too long'}
            [Array]::Copy($pb,0,$expected,16,$pb.Length)
        }
        $state.ExpectedBootRecord=[Convert]::ToBase64String($expected)
        if(-not $readback.AclValid -or $readback.PendingPresent -or $readback.RecordBase64 -cne $state.ExpectedBootRecord -or $readback.DriverStart -ne 3 -or
            @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0 -or (& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s'){throw 'Product seed exact bytes/ACL/Start/no-load readback failed'}
        'BootPolicyPrebootVerified=ParametersAcl:True;BootPolicyAcl:True;RecordBytes:16656;ExactRecord:True;PendingScopes:Absent;Start:3;PASS'
        $configPath=Join-Path $stateDirectory 'writer-config.clixml'
        if($coreRestartPolicyCase -or $coreJustificationCase){
            $state.ActorNextSequence=1
            $commands=Join-Path $stateDirectory 'core-commands';$null=New-Item -ItemType Directory -Path $commands
            & icacls.exe $commands /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' ('*'+$state.ActorSid+':(OI)(CI)RX') | Out-Host
            if($LASTEXITCODE -ne 0){throw 'Core trusted command directory ACL failed'}
            $state.ActivationActors=@{Primary=@{Directory=$actorDirectory;CommandDirectory=$commands;Launcher=(Join-Path $stateDirectory 'writer.ps1');Task=$writerTask;Token=$state.WriterToken;NextSequence=1;ExpectedPid=$null}}
            $target=if($coreRestartPolicyCase){Join-Path $state.R02ScopeY 'marker.txt'}else{Join-Path $protectedDirectory 'cached.txt'}
            Save-State @{ActorSid=$state.ActorSid;ActorDirectory=$actorDirectory;CommandDirectory=$commands;Target=$target;HolderKind='handle';PBase64=$state.BaselineBase64;ImageLength=$size} $configPath
            $writerBody=if($coreRestartPolicyCase){Get-R02WriterBody}else{Get-B02WriterBody}
            $writerBody=$writerBody.Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $configPath)).Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'identity.clixml'))).Replace('__SCRIPT_ERROR__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'script-error.txt')))
        }elseif($isActivationCase){
            $state.ActorNextSequence=1
            $holderKind=switch($CaseId){'A01'{'handle'}'A04'{'handle'}'A05'{'handle'}'A02'{'view'}default{'section'}}
            Save-State @{ActorSid=$state.ActorSid;ActorDirectory=$actorDirectory;Target=(Join-Path $protectedDirectory 'marker.txt');
                HolderKind=$holderKind;PBase64=$state.BaselineBase64;ImageLength=$size} $configPath
            $writerBody=if($CaseId -ceq 'A05'){Get-A05WriterBody}else{Get-ActivatingWriterBody}
            $writerBody=$writerBody.Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $configPath))
            $writerBody=$writerBody.Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'identity.clixml')))
            $writerBody=$writerBody.Replace('__SCRIPT_ERROR__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'script-error.txt')))
        }elseif($coreConcurrentCase){
            Save-X01WriterConfig $configPath $actorDirectory $state.WriterToken $state.X01Images.V1
            $writerBody=Get-X01WriterBody $configPath $actorDirectory
        }else{
            $payloads=@()
            for($i=0;$i -le 100;$i++){
                $bytes=[byte[]]$baseline.Clone()
                if($CaseId -ne 'S00-observer-control'){
                    foreach($offset in @(0,[int]($size/2),($size-128))){ # parenthesized: ',' binds tighter than '-' in PowerShell
                        $block=[Text.Encoding]::ASCII.GetBytes(('ATTEMPT-'+$RunName+'-trial-'+$i+'-offset-'+$offset).PadRight(128,'U'))
                        if($block.Length -ne 128){throw 'Forbidden block too long'}
                        [Array]::Copy($block,0,$bytes,$offset,128);$state.ForbiddenBlocks+=[Convert]::ToBase64String($block)
                    }
                };$payloads+=[Convert]::ToBase64String($bytes)
            }
            if($cachedCase){
                # .txt uses PlainTextExtractor. Only CPF is enabled, so benign
                # alphabetic padding is Approved and this valid-checkdigit test
                # CPF is Blocked by real DigitRules/CpfValidator inspection.
                $bytes=[Text.Encoding]::ASCII.GetBytes(($cachedFamily+' patterned benign image '+$RunName+"`n").PadRight($size,'P'))
                $state.ForbiddenBlocks=@()
                foreach($offset in @(0,[int]($size/2),($size-128))){
                    $block=[Text.Encoding]::ASCII.GetBytes(($cachedFamily+'-'+$RunName+'-offset-'+$offset+"`n").PadRight(128,'A'))
                    if($block.Length -ne 128){throw 'C01 patterned block exceeds 128 bytes'}
                    [Array]::Copy($block,0,$bytes,$offset,128);$state.ForbiddenBlocks+= [Convert]::ToBase64String($block)
                }
                if($row.Outcome -ceq 'BLOCK'){$sensitive=[Text.Encoding]::ASCII.GetBytes("`nCPF 529.982.247-25`n");[Array]::Copy($sensitive,0,$bytes,256,$sensitive.Length)}
                $state.CachedImageBase64=[Convert]::ToBase64String($bytes)
                $state.CachedFixture=if($row.Outcome -ceq 'BLOCK'){'PlainTextExtractor/Cpf; synthetic valid-checkdigit 529.982.247-25'}else{'PlainTextExtractor/Cpf; no CPF candidate'}
                $payloads=@($state.CachedImageBase64)
                if($cachedExisting){$baseBytes=[Text.Encoding]::ASCII.GetBytes(('Approved base B '+$RunName+"`n").PadRight([int]$cVolumes[0].BlockSize*4,'B'));$state.CachedBaseBase64=[Convert]::ToBase64String($baseBytes)}
                if($cachedDenial){
                    # This source is a durable physical file on the SAME NTFS volume, outside policy.
                    $state.ExternalDirectory=$externalDirectory;Save-State $state $statePath
                    New-Item -ItemType Directory -Path $externalDirectory | Out-Null
                    & icacls.exe $externalDirectory /grant ('*'+$state.ActorSid+':(OI)(CI)M') | Out-Host
                    if($LASTEXITCODE -ne 0){throw 'External fixture ACL failed'}
                    $stream=[IO.FileStream]::new((Join-Path $externalDirectory 'source.txt'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
                    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
                }
                if($CaseId -ceq 'B01'){
                    $state.B01SentinelBase64=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('B01 sentinel unchanged '+$RunName+"`n").PadRight($size,'S')))
                    $state.ExternalDirectory=$externalDirectory;Save-State $state $statePath
                    New-Item -ItemType Directory -Path $externalDirectory | Out-Null
                    & icacls.exe $externalDirectory /grant ('*'+$state.ActorSid+':(OI)(CI)M') | Out-Host
                    if($LASTEXITCODE -ne 0){throw 'B01 sentinel fixture ACL failed'}
                }
            }
            if($CaseId -ceq 'R01'){
                $state.R01InitialBase64=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('R01 initial private image '+$RunName+"`n").PadRight($size,'Q')))
            }
            Save-State @{ActorSid=$state.ActorSid;Payloads=$payloads;DedicatedUnheldLatency=([bool]$DedicatedUnheldLatency);CachedCase=$cachedCase;BlockWindowClosure=($CaseId -cin @('C01-block-absent','C03-block-existing','C04-block'));WriterKind=$cachedKind;SeedBaseBase64=$state.CachedBaseBase64;TempTarget=(Join-Path $protectedDirectory 'save.tmp.txt');Source=(Join-Path $externalDirectory 'source.txt');Token=$state.WriterToken;CoordinationDirectory=$actorDirectory;
                CreateNew=($CaseId -eq 'S02-agent-down-open-refused');Target=(Join-Path $protectedDirectory $(if($cachedCase){'cached.txt'}elseif($CaseId -eq 'S02-agent-down-open-refused'){'new.bin'}else{'marker.bin'}))} $configPath
            if($CaseId -cin @('R01','B01')){
                $coreConfig=Load-State $configPath
                if($CaseId -ceq 'R01'){
                    $coreConfig.R01InitialBase64=$state.R01InitialBase64;$coreConfig.R01OfflineTarget=Join-Path $protectedDirectory 'offline-new.txt'
                }else{$coreConfig.B01SentinelBase64=$state.B01SentinelBase64}
                Save-State $coreConfig $configPath
            }
            $writerBody=(Get-WriterBody).Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $configPath)).Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'identity.clixml'))).Replace('__GO__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'go'))).Replace('__TEMP__',(ConvertTo-PowerShellLiteral $actorDirectory))
            if($CaseId -ceq 'R01'){$writerBody=(Get-R01WriterBody).Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $configPath)).Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'identity.clixml'))).Replace('__GO__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'go'))).Replace('__TEMP__',(ConvertTo-PowerShellLiteral $actorDirectory))}
            if($CaseId -ceq 'B01'){$writerBody=(Get-B01WriterBody).Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $configPath)).Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'identity.clixml'))).Replace('__GO__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'go'))).Replace('__TEMP__',(ConvertTo-PowerShellLiteral $actorDirectory))}
            if($CaseId -ceq 'R03'){$writerBody=(Get-R03WriterBody).Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $configPath)).Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'identity.clixml'))).Replace('__GO__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'go'))).Replace('__TEMP__',(ConvertTo-PowerShellLiteral $actorDirectory))}
        }
        $writerLauncher=Join-Path $stateDirectory 'writer.ps1'
        Write-DurableFile $writerLauncher (New-TaskLauncher $writerBody $state.WriterToken (Join-Path $actorDirectory 'completion.clixml')) -New
        foreach($path in @($configPath,$writerLauncher)){
            & icacls.exe $path /grant ('*'+$state.ActorSid+':R') | Out-Host
            if($LASTEXITCODE -ne 0){throw 'Read-only writer input ACL failed'}
        }
        $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$writerLauncher+'"')
        $actorMinutes=if($coreRestartPolicyCase){15}elseif($DedicatedUnheldLatency){240}elseif($coreConcurrentCase -or $CaseId -ceq 'A05'){15}elseif($CaseId -ceq 'A04'){45}elseif($MappedStackDiagnosticSeconds -ne 0){15}elseif($cachedExisting){10}else{5}
        if($CaseId -cin @('R01','B01')){$actorMinutes=15}
        if($CaseId -ceq 'R03'){
            Register-ScheduledTask -TaskName $writerTask -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -User ($env:COMPUTERNAME+'\'+$actorUser) -Password $password -RunLevel Limited -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(15)) -MultipleInstances IgnoreNew) | Out-Null
        }elseif($interactiveActorCase){
            Set-InvariantActorAutoLogon $password
            $principal=New-ScheduledTaskPrincipal -UserId ($env:COMPUTERNAME+'\'+$actorUser) -LogonType Interactive -RunLevel Limited
            Register-ScheduledTask -TaskName $writerTask -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit $(if($interactiveActorCase -and $cachedCase -and -not $DedicatedUnheldLatency){[TimeSpan]::Zero}else{[TimeSpan]::FromMinutes(15)})) | Out-Null
        }else{
        Register-ScheduledTask -TaskName $writerTask -Action $action -User ($env:COMPUTERNAME+'\'+$actorUser) -Password $password -RunLevel Limited -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes($actorMinutes))) | Out-Null
        }
        if($CaseId -ceq 'A04'){
            $duplicateDirectory=Join-Path $actorDirectory 'duplicate';New-Item -ItemType Directory -Path $duplicateDirectory | Out-Null
            $primaryCommands=Join-Path $stateDirectory 'primary-commands';$duplicateCommands=Join-Path $stateDirectory 'duplicate-commands'
            foreach($directory in @($primaryCommands,$duplicateCommands)){
                $null=New-Item -ItemType Directory -Path $directory
                & icacls.exe $directory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' ('*'+$state.ActorSid+':(OI)(CI)RX') | Out-Host
                if($LASTEXITCODE -ne 0){throw 'Trusted command directory ACL failed'}
            }
            $primaryConfig=Load-State $configPath;$primaryConfig.CommandDirectory=$primaryCommands;Save-State $primaryConfig $configPath
            $duplicateConfig=Join-Path $stateDirectory 'duplicate-config.clixml';$duplicateLauncher=Join-Path $stateDirectory 'duplicate-writer.ps1'
            $state.ActivationActors=@{
                Primary=@{Directory=$actorDirectory;CommandDirectory=$primaryCommands;Launcher=$writerLauncher;Task=$writerTask;Token=$state.WriterToken;NextSequence=1;ExpectedPid=$null}
                Duplicate=@{Directory=$duplicateDirectory;CommandDirectory=$duplicateCommands;Launcher=$duplicateLauncher;Task=($writerTask+'-duplicate');Token=[guid]::NewGuid().ToString('N');NextSequence=1;ExpectedPid=$null}}
            Save-State $state $statePath
            Save-State @{ActorSid=$state.ActorSid;ActorDirectory=$duplicateDirectory;CommandDirectory=$duplicateCommands;Target=(Join-Path $protectedDirectory 'marker.txt');HolderKind='handle';PBase64=$state.BaselineBase64;ImageLength=$size} $duplicateConfig
            $duplicateBody=(Get-ActivatingWriterBody).Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $duplicateConfig)).Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $duplicateDirectory 'identity.clixml'))).Replace('__SCRIPT_ERROR__',(ConvertTo-PowerShellLiteral (Join-Path $duplicateDirectory 'script-error.txt')))
            Write-DurableFile $duplicateLauncher (New-TaskLauncher $duplicateBody $state.ActivationActors.Duplicate.Token (Join-Path $duplicateDirectory 'completion.clixml')) -New
            foreach($path in @($duplicateConfig,$duplicateLauncher)){& icacls.exe $path /grant ('*'+$state.ActorSid+':R') | Out-Host;if($LASTEXITCODE -ne 0){throw 'Duplicate actor input ACL failed'}}
            $duplicateAction=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$duplicateLauncher+'"')
            Register-ScheduledTask -TaskName $state.ActivationActors.Duplicate.Task -Action $duplicateAction -User ($env:COMPUTERNAME+'\'+$actorUser) -Password $password -RunLevel Limited -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(45))) | Out-Null
        }
        if($coreConcurrentCase){Initialize-X01SecondActor $password}
        $password=$null
        # Trusted coordinator launches this SAME pinned suite in a fresh process.
        $invoke="& '"+(ConvertTo-PowerShellLiteral $PSCommandPath)+"' -Phase AfterBoot -StartupProbe"
        foreach($key in @($PSBoundParameters.Keys | Sort-Object)){if($key -notin @('Phase','StartupProbe')){$invoke+=' -'+$key+" '"+(ConvertTo-PowerShellLiteral ([string]$PSBoundParameters[$key]))+"'"}}
        $launcher=Join-Path $stateDirectory 'startup.ps1'
        Write-DurableFile $launcher (New-TaskLauncher $invoke $state.CoordinatorToken (Join-Path $evidenceDirectory 'startup-completion.clixml')) -New
        $coordinatorMinutes=if($DedicatedUnheldLatency){240}elseif($CaseId -ceq 'A04'){45}else{15}
        Register-SystemTask $bootTask $launcher -AtStartup -ExecutionMinutes $(if($interactiveActorCase -and $cachedCase -and -not $DedicatedUnheldLatency){0}else{$coordinatorMinutes})
        & sc.exe config SafeUpload start= boot | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Start=0 configuration failed'}
        $svc=Get-ItemProperty "HKLM:\$registryService"
        if($svc.Start -ne 0 -or $svc.ErrorControl -ne 1 -or $svc.Group -cne 'FSFilter Anti-Virus' -or $svc.Type -ne 2 -or
            @($svc.DependOnService).Count -ne 1 -or @($svc.DependOnService)[0] -cne 'FltMgr'){throw 'Boot service configuration mismatch'}
        if($Mode -eq 'boot-verifier'){
            & verifier.exe /standard /driver SafeUpload.sys | Out-Host;if($LASTEXITCODE -notin @(0,2)){throw 'Boot Verifier configure failed'}
            & verifier.exe /bootmode oneboot | Out-Host;if($LASTEXITCODE -notin @(0,2)){throw 'Verifier oneboot failed'}
            $v=Get-VerifierEvidence 'prepare'
            if($v.Settings -notmatch 'SafeUpload\.sys' -or $v.Settings -notmatch 'Verifier Flags:\s+0x(?!0+\b)[0-9a-fA-F]+'){throw 'Configured boot Verifier absent'}
            $vf=@([regex]::Matches($v.Settings,'(?im)^Verifier Flags:\s+0x([0-9a-f]+)\s*$'))
            if($vf.Count -ne 1){throw 'Configured boot Verifier flags ambiguous'}
            $state.BootVerifierFlags=[Convert]::ToUInt32($vf[0].Groups[1].Value,16)
        }else{
            $v=Get-VerifierEvidence 'prepare'
            if($v.Active -notmatch 'No drivers are currently verified' -or $v.Settings -notmatch 'Verifier Flags:\s+0x00000000'){throw 'Ordinary/runtime preboot Verifier must be off'}
        }
        Save-State $state $statePath
        'CaseStatus=READY';'INVARIANT_PREPARED=True'
    }catch{
        'ScriptError='+$_.Exception.ToString()
        Write-DurableFile (Join-Path $evidenceDirectory 'prepare-error.txt') ($_.Exception.ToString()+"`n"+$_.ScriptStackTrace) -New
        try{Restore-Suite -Rollback}
        finally{
            Write-DurableFile (Join-Path $evidenceDirectory 'case.json') (@{Schema='StagedInvariantSuite/2';CaseId=$CaseId;Mode=$Mode;RunName=$RunName;
                Verdict='INCONCLUSIVE';CaseStatus='READY';AuthoritativeCaseExport=$false;Trials=@();Restoration=@{Known=$false};
                Reasons=@('Prepare failed; retained prepare-error and rollback artifacts; restoration reboot required')} | ConvertTo-Json -Depth 32) -New
        }
        throw
    }
}elseif($Phase -eq 'AfterBoot'){
    $state=Load-State $statePath
    if($state.DedicatedUnheldLatency -ne $DedicatedUnheldLatency){throw 'Dedicated latency parameter/state mismatch'}
    if($state.MappedStackDiagnosticSeconds -ne $MappedStackDiagnosticSeconds){throw 'Mapped diagnostic parameter/state mismatch'}
    if($state.CaseId -cne $CaseId -or $state.Mode -cne $Mode -or $state.RunName -cne $RunName){throw 'State identity mismatch'}
    if($StartupProbe){if($coreRestartPolicyCase){Invoke-R02Observation}elseif($coreJustificationCase){Invoke-B02Observation}elseif($interactiveActorCase){Invoke-InteractiveCachedObservation}elseif($CaseId -ceq 'R03'){Invoke-R03Observation}elseif($CaseId -ceq 'A05'){Invoke-A05Observation}elseif($coreConcurrentCase){Invoke-X01Observation}elseif($isActivationCase){Invoke-ActivationObservation}elseif($cachedCase){Invoke-CachedObservation}else{Invoke-SeedObservation};return}
    $observationError=$null
    try {
        $coordinatorWaitSeconds=if($DedicatedUnheldLatency){14460}elseif($CaseId -ceq 'A04'){2760}else{900}
        $null=Wait-TaskCompletion $bootTask (Join-Path $evidenceDirectory 'startup-completion.clixml') $state.CoordinatorToken $coordinatorWaitSeconds
        if(-not(Test-Path -LiteralPath $trialPath)){throw 'Completed startup task omitted trial'}
    }catch{$observationError=Get-ErrorChain $_.Exception;Save-State $observationError (Join-Path $evidenceDirectory 'startup-error.clixml')}
    finally {
        # StartupProbe updates actor/service recovery fields in its own process.
        # Re-read after its completion before restoration or those fields are lost.
        if($isActivationCase -or $cachedCase -or $coreConcurrentCase -or $coreRestartPolicyCase -or $coreJustificationCase){$state=Load-State $statePath}
        $state.AfterBootId=Get-BootId
        Save-State $state $statePath
        Restore-Suite
    }
    # Completion means evidence was collected or its absence recorded. Verdict is
    # solely case.json + independent baseline. Never emit the Phase 2 sentinel.
    'INVARIANT_CASE_COMPLETED=True';'INVARIANT_RESTORED=True'
}else{
    $state=Load-State $statePath
    if($state.DedicatedUnheldLatency -ne $DedicatedUnheldLatency){throw 'Dedicated latency parameter/state mismatch'}
    if($state.MappedStackDiagnosticSeconds -ne $MappedStackDiagnosticSeconds){throw 'Mapped diagnostic parameter/state mismatch'}
    if((Get-BootId) -ceq $state.AfterBootId -or [string]::IsNullOrWhiteSpace($state.AfterBootId)){throw 'Restoration reboot identity unavailable'}
    Assert-Hash $installedDriver $originalDriverHash;Assert-Hash $policyPath $ExpectedOriginalPolicySha256
    $finalAudit=Get-ProcessCreationAudit
    if($null -eq $state.OriginalProcessCreationAudit -or
        $finalAudit.CreationFlags -ne $state.OriginalProcessCreationAudit.CreationFlags -or
        $finalAudit.PerUserPolicyCount -ne $state.OriginalProcessCreationAudit.PerUserPolicyCount){throw 'Final process-creation audit policy residue'}
    Remove-B01Junction
    Remove-CachedSecondUserProfile -AfterReboot
    if($null -ne $state.SecondUser -and ((Get-LocalUser -Name $state.SecondUser.Name -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName $state.SecondUser.Task -ErrorAction SilentlyContinue))){throw 'Second-user final restoration residue'}
    if(-not [string]::IsNullOrWhiteSpace($state.ActorSid)){
        foreach($profile in @(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $state.ActorSid)){
            if($profile.Loaded){throw 'Actor profile loaded after the restoration reboot'}
            Remove-CimInstance -InputObject $profile
        }
        if(@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $state.ActorSid).Count -ne 0){throw 'Actor profile residue'}
    }
    if((Get-ItemProperty "HKLM:\$registryService").Start -ne 3 -or (& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s' -or
        (Test-Path -LiteralPath $parametersKey) -or (Test-Path -LiteralPath $protectedDirectory) -or (Test-Path -LiteralPath $externalDirectory) -or (Test-Path -LiteralPath $serviceDirectory) -or
        @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0 -or
        @(Get-ScheduledTask | Where-Object {$_.TaskName -eq $bootTask -or $_.TaskName -eq $writerTask -or ($CaseId -ceq 'A04' -and $_.TaskName -eq ($writerTask+'-duplicate')) -or ($coreConcurrentCase -and $_.TaskName -eq ($writerTask+'-latest'))}).Count -ne 0 -or
        (Get-LocalUser -Name $state.ActorUser -ErrorAction SilentlyContinue)){throw 'Final restoration residue'}
    $active=(& verifier.exe /query 2>&1 | Out-String);$settings=(& verifier.exe /querysettings 2>&1 | Out-String)
    if($active -notmatch 'No drivers are currently verified' -or $settings -notmatch 'Verifier Flags:\s+0x00000000'){throw 'Verifier not off after restoration reboot'}
    Set-AgentServiceStart $state.OriginalAgentStart
    if((Get-SecuritySddl $policyPath $false) -cne $state.OriginalPolicyFileSddl -or
        (Get-SecuritySddl (Split-Path -Parent $policyPath) $true) -cne $state.OriginalPolicyDirectorySddl){throw 'Restored policy ACL mismatch'}
    if($state.ActorAutoLogonValues){
        $names=(Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').GetValueNames()
        if(@($state.ActorAutoLogonValues | Where-Object {$names -contains $_}).Count){throw 'Final owned autologon residue'}
        Initialize-InvariantWts
        if(@([SUInvariantWts]::Read() | Where-Object {$_.User -ieq $state.ActorUser -and $_.Domain -ieq $env:COMPUTERNAME}).Count){throw 'Final actor WTS session residue'}
    }
    $trial=if(Test-Path -LiteralPath $trialPath){Load-State $trialPath}else{@{Verdict='INCONCLUSIVE';ForbiddenByteCount=$null;Reasons=@('Startup task did not export observations')}}
    if(-not $cachedCase -and -not $isActivationCase -and -not $coreConcurrentCase -and -not $coreRestartPolicyCase -and -not $coreJustificationCase -and $null -ne $trial.Baseline -and @($trial.Samples).Count -gt 0){
        $trial.Assertions=@($trial.Assertions | Where-Object {$trial.Predicate.Assertions.Name -notcontains $_.Name})
        $trial.Predicate=Test-NoUnapprovedByte $trial.Baseline @() $trial.Samples $trial.MutationLedger $trial.ExpectedTimeline
        $trial.Assertions+=@($trial.Predicate.Assertions)
        if($trial.Predicate.Verdict -eq 'FAIL'){$trial.Verdict='FAIL'}
        $trial.ForbiddenByteCount=$trial.Predicate.ForbiddenByteCount
    }
    $finalReasons=if(($isActivationCase -or $coreConcurrentCase -or $coreRestartPolicyCase -or $coreJustificationCase) -and $trial.Reasons.Count -gt 0){@($trial.Reasons)}else{@('Seed rows do not qualify Phase4; driver lower mutation ledger and live taint readback unavailable; notification absence requires authenticated durable coverage or whole-window agent absence plus an unchanged authenticated record location')}
    $result=[ordered]@{Schema='StagedInvariantSuite/2';TableRevision=$table.TableRevision;CaseRevision=$row.Revision;CaseId=$CaseId;Mode=$Mode;RunName=$RunName;
        Duration=@{CaseMs=$trial.CaseDurationMs;BlockWindowExtraMs=$trial.BlockWindowClosure.DurationMs};CaseStatus='READY';QualificationScope=$row.QualificationScope;Verdict=$trial.Verdict;ForbiddenByteCount=$trial.ForbiddenByteCount;Trials=@($trial);
        InputHashes=@{Table=$ExpectedTableSha256;Observer=$ExpectedObserverSha256;Suite=$ExpectedSuiteSha256;Helper=$ExpectedHelperSha256;
            Feature=$ExpectedFeatureSha256;Inspector=$ExpectedInspectorSha256;ServicePackage=$ExpectedServicePackageSha256;ServiceTree=$ExpectedServiceTreeSha256};
        BootIds=@{Prepare=$state.PrepareBootId;Active=$state.AfterBootId;Final=(Get-BootId)};Restoration=@{GuestChecks=$true;IndependentBaseline=$null;Known=$false;
            ProcessCreationAudit=@{Original=$state.OriginalProcessCreationAudit;Final=$finalAudit;Restored=$true}};
        AuthoritativeCaseExport=$false;Reasons=$(if($cachedCase){@('Functional/seed rows do not qualify full Phase4: lower mutation ledger, live taint and full temporal/permit evidence unavailable; C01-C05 use coordinated functional variants; second-user H access, safe creation receipts and unheld latency remain unqualified; C01/C03/C04 BLOCK collect expiry closure/cleanup and optional real-pipe late rejection')}else{$finalReasons});
        Load=@{ComputerSystem=(Get-CimInstance Win32_ComputerSystem | Select-Object NumberOfLogicalProcessors,TotalPhysicalMemory);Cpu=(Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores);Disk=(Get-Disk | Select-Object Number,FriendlyName,BusType);ObserverPriority=[string][Diagnostics.Process]::GetCurrentProcess().PriorityClass}}
    Copy-Item -LiteralPath $statePath -Destination (Join-Path $evidenceDirectory 'lifecycle.clixml')
    Copy-Item -LiteralPath $actorDirectory -Destination (Join-Path $evidenceDirectory 'actor') -Recurse
    Remove-Item -LiteralPath $stateDirectory -Recurse -Force
    if(Test-Path -LiteralPath $stateDirectory){throw 'State directory residue'}
    Write-DurableFile (Join-Path $evidenceDirectory 'case.json') ($result | ConvertTo-Json -Depth 32) -New
    'InvariantVerdict='+$result.Verdict
    'INVARIANT_FINAL_STATE=True'
}
}catch{
    'ScriptError='+$_.Exception.ToString()
    throw
}
