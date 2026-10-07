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
function Load-State([string]$Path) { [Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($Path)) }
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
        $native=$null;if($ex -is [ComponentModel.Win32Exception]){$native=$ex.NativeErrorCode}
        $chain+= [pscustomobject]@{Type=$ex.GetType().FullName;Message=$ex.Message;HResult=$ex.HResult;NativeCode=$native;Stack=$ex.StackTrace}
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
function Register-SystemTask([string]$Name,[string]$Launcher,[switch]$AtStartup) {
    if(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue){throw 'Task collision'}
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$Launcher+'"')
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(15))
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
@'
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
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteFile(IntPtr h,byte[] b,uint n,out uint w,IntPtr o);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushFileBuffers(IntPtr h);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(IntPtr h,byte[] b,uint n,out uint r,IntPtr o);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetFilePointerEx(IntPtr h,long d,out long p,uint m);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr h,int c,out int v,int n,out int r);
 public static bool Elevated(IntPtr token) { int v,r; if(!GetTokenInformation(token,20,out v,4,out r))throw new Win32Exception(Marshal.GetLastWin32Error());return v!=0; }
 static SUCall Call(string c,int code,long start,long end,int trial) {return new SUCall{Class=c,NativeCode=code,StartQpc=start,EndQpc=end,Trial=trial,Cold=trial==0};}
 public static IntPtr OpenHeld(string path,out SUCall call) {
  long start=Stopwatch.GetTimestamp();var h=CreateFileW(path,0xC0000000,7,IntPtr.Zero,1,0x80,IntPtr.Zero);
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
  long position;if(!SetFilePointerEx(h,0,out position,0))throw new Win32Exception(Marshal.GetLastWin32Error());
  byte[] bytes=new byte[length];uint read;if(!ReadFile(h,bytes,(uint)length,out read,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());
  if(read!=length)throw new System.IO.IOException("Private read was short.");return bytes;
 }
 public static SUCall CloseHeld(IntPtr h) {
  long start=Stopwatch.GetTimestamp();bool ok=CloseHandle(h);int code=ok?0:Marshal.GetLastWin32Error();return Call("close",code,start,Stopwatch.GetTimestamp(),0);
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
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((180)*[Diagnostics.Stopwatch]::Frequency))
    while(-not(Test-Path -LiteralPath '__GO__')){if([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline){throw 'Writer barrier timed out'};Start-Sleep -Milliseconds 10}
    $releasedQpc=[Diagnostics.Stopwatch]::GetTimestamp()
    $calls=@()
    if($config.CachedCase){
        $h=[IntPtr]::Zero;$privateDigest=$null;$openCall=$null
        try {
            $bytes=[Convert]::FromBase64String($config.Payloads[0])
            $h=[SUWriter]::OpenHeld($config.Target,[ref]$openCall);$calls+= $openCall
            if($openCall.NativeCode -ne 0){throw ('Cached create failed: Win32='+$openCall.NativeCode)}
            $calls+= [SUWriter]::WriteHeld($h,$bytes);$calls+= [SUWriter]::FlushHeld($h)
            if(@($calls | Where-Object NativeCode -ne 0).Count){throw 'Cached write/flush failed; see held/closed operation receipt'}
            $hash=[Security.Cryptography.SHA256]::Create()
            try{$privateDigest=[BitConverter]::ToString($hash.ComputeHash([SUWriter]::ReadPrivate($h,$bytes.Length))).Replace('-','')}finally{$hash.Dispose()}
            $held=@{Pid=$PID;Sid=$actor.Sid;BootId=$actor.BootId;Token=$config.Token;Calls=$calls;PrivateSha256=$privateDigest;Qpc=[Diagnostics.Stopwatch]::GetTimestamp();ReleasedQpc=$releasedQpc}
            Write-DurableFile (Join-Path $config.CoordinationDirectory 'held.clixml') ([Management.Automation.PSSerializer]::Serialize($held,32)) -New
            $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((180)*[Diagnostics.Stopwatch]::Frequency))
            while(-not(Test-Path -LiteralPath (Join-Path $config.CoordinationDirectory 'close'))){if([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline){throw 'Cached writer close barrier timed out after 180 seconds'};Start-Sleep -Milliseconds 10}
        } finally {
            if($h -ne [IntPtr]::Zero -and $h -ne [IntPtr]::new(-1)){$calls+= [SUWriter]::CloseHeld($h)}
            $closed=@{Pid=$PID;Sid=$actor.Sid;BootId=$actor.BootId;Token=$config.Token;Calls=$calls;Qpc=[Diagnostics.Stopwatch]::GetTimestamp();ReleasedQpc=$releasedQpc}
            Write-DurableFile (Join-Path $config.CoordinationDirectory 'closed.clixml') ([Management.Automation.PSSerializer]::Serialize($closed,32)) -New
        }
        $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((180)*[Diagnostics.Stopwatch]::Frequency))
        while(-not(Test-Path -LiteralPath (Join-Path $config.CoordinationDirectory 'inspect-handback'))){if([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline){throw 'Cached writer hand-back barrier timed out after 180 seconds'};Start-Sleep -Milliseconds 10}
        $handBackAfter=Get-ActorHandBack
        $value=@{Actor=$actor;Calls=$calls;PrivateSha256=$privateDigest;HandBackAfter=$handBackAfter;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;ReleasedQpc=$releasedQpc;Held=$false}
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
}
function Get-ActivatingWriterBody {
@'
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
  sourceClosed=false; FileHandle=CreateFileW(path,0xC0000000u,7,IntPtr.Zero,1,0x80,IntPtr.Zero);
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
 public static int WriteFileAt(long offset,byte[] bytes) { if(FileHandle==new IntPtr(-1)) return 6; if(!Seek(FileHandle,offset)) return Error(); uint written; if(!WriteFile(FileHandle,bytes,(uint)bytes.Length,out written,IntPtr.Zero)) return Error(); return written==(uint)bytes.Length?0:29; }
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
  $commandPath=Join-Path $config.ActorDirectory ('command-'+$commandSequence.ToString('D4')+'.clixml')
  if(-not(Test-Path -LiteralPath $commandPath)){Start-Sleep -Milliseconds 10;continue}
  $command=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($commandPath));$result=@{Sequence=$command.Sequence;Action=$command.Action;Pid=$PID;BootId=(Get-BootId);QpcFrequency=[Diagnostics.Stopwatch]::Frequency;StartQpc=[Diagnostics.Stopwatch]::GetTimestamp();NativeCode=$null;FlushCode=$null;Calls=@();Error=$null}
  try {
   switch($command.Action){
    'create-holder' {$closed=$false;$result.NativeCode=[SUActivationNative]::CreateHolder($config.Target,[Convert]::FromBase64String($config.PBase64),$config.HolderKind,[ref]$closed);$result.SourceHandleClosed=$closed;$result.HolderCreated=($result.NativeCode -eq 0)}
    'probe-new-writers' {$sectionOpen=[int]0;$result.OpenCode=[SUActivationNative]::NewWritableOpen($config.Target);$result.SectionCode=[SUActivationNative]::NewWritableSection($config.Target,[ref]$sectionOpen);$result.SectionSourceOpenCode=$sectionOpen;$result.NativeCode=0}
    'map-late' {$result.NativeCode=[SUActivationNative]::MapLate([uint32]$config.ImageLength);$result.Mapped=($result.NativeCode -eq 0)}
    'write-old' {
     foreach($change in $command.Changes){$bytes=[Convert]::FromBase64String($change.BytesBase64);$start=[Diagnostics.Stopwatch]::GetTimestamp();$code=if($config.HolderKind -eq 'handle'){[SUActivationNative]::WriteFileAt([long]$change.Offset,$bytes)}else{[SUActivationNative]::WriteViewAt([long]$change.Offset,$bytes)};$end=[Diagnostics.Stopwatch]::GetTimestamp();$result.Calls+=@{Offset=[long]$change.Offset;Length=$bytes.Length;PayloadSha256=$change.PayloadSha256;NativeCode=$code;StartQpc=$start;EndQpc=$end;Paging=($config.HolderKind -ne 'handle')};if($code -ne 0){throw ('Old holder write failed: Win32 '+$code)}}
     if($config.HolderKind -eq 'handle'){$result.FlushCode=[SUActivationNative]::FlushHolderFile()}else{$result.FlushCode=[SUActivationNative]::FlushView()};if($result.FlushCode -ne 0){throw ('Old holder flush failed: Win32 '+$result.FlushCode)};$result.NativeCode=0
    }
    'staged-write' {$bytes=[Convert]::FromBase64String($command.PayloadBase64);$start=[Diagnostics.Stopwatch]::GetTimestamp();$closeCode=[int]0;$code=[SUActivationNative]::StageWrite($config.Target,[long]$command.Offset,$bytes,[ref]$flush,[ref]$closeCode,[ref]$written);$end=[Diagnostics.Stopwatch]::GetTimestamp();$result.NativeCode=$code;$result.FlushCode=$flush;$result.CloseCode=$closeCode;$result.BytesWritten=$written;$result.Calls+=@{Class='staged-write';NativeCode=$code;FlushCode=$flush;CloseCode=$closeCode;Length=$bytes.Length;PayloadSha256=$command.PayloadSha256;StartQpc=$start;EndQpc=$end};if($code -ne 0){throw ('Post-protection staged write failed: Win32 '+$code)}}
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
}
function Publish-ActivationActorCommand($State,[string]$Action,$Fields) {
    $sequence=[int]$State.ActorNextSequence
    $commandPath=Join-Path $actorDirectory ('command-'+$sequence.ToString('D4')+'.clixml')
    $value=@{Sequence=$sequence;Action=$Action}
    if($null -ne $Fields){foreach($key in $Fields.Keys){$value[$key]=$Fields[$key]}}
    Save-State $value $commandPath
    $State.ActorNextSequence=$sequence+1;Save-State $State $statePath
    $replyPath=Join-Path $actorDirectory ('reply-'+$sequence.ToString('D4')+'.clixml')
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((30)*[Diagnostics.Stopwatch]::Frequency))
    do {if(Test-Path -LiteralPath $replyPath){$reply=Load-State $replyPath;if($reply.Sequence -ne $sequence){throw 'Activation actor reply sequence mismatch'};if($reply.Error){throw ('Activation actor '+$Action+' failed: '+$reply.Error)};return $reply};Start-Sleep -Milliseconds 20}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    throw ('Activation actor timeout: action='+$Action+'; sequence='+$sequence+'; no reply after 30s')
}
function Get-ActivationActorIdentity {
    $identity=Wait-WriterIdentity (Join-Path $actorDirectory 'identity.clixml') 60
    if($identity.Sid -cne $state.ActorSid -or $identity.Elevated -or $identity.IsAdministrator -or $identity.Pid -eq $PID -or $identity.BootId -cne (Get-BootId)){throw 'Activation holder identity/session/token proof mismatch'}
    $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$identity.Pid) -ErrorAction Stop
    if($null -eq $process -or $process.SessionId -ne $identity.SessionId -or $process.CommandLine -notlike ('*'+(Join-Path $stateDirectory 'activation-writer.ps1')+'*')){throw 'Activation holder OS process provenance mismatch'}
    $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
    if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $state.ActorSid){throw 'Activation holder OS process owner SID mismatch'}
    return [pscustomobject]@{Pid=$identity.Pid;Sid=$identity.Sid;Elevated=$identity.Elevated;IsAdministrator=$identity.IsAdministrator;
        SessionId=$identity.SessionId;BootId=$identity.BootId;OwnerSid=$owner.Sid;CommandLine=$process.CommandLine;
        Task=(Get-ScheduledTask -TaskName $writerTask | Select-Object TaskName,Principal,State)}
}
function Get-NtDevicePath([string]$DosPath) {
    if(-not('SUActivationDevice' -as [type])){Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;using System.Text;public static class SUActivationDevice{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern uint QueryDosDevice(string n,StringBuilder b,int c);}' }
    $drive=[IO.Path]::GetPathRoot($DosPath).TrimEnd('\');$builder=[Text.StringBuilder]::new(2048)
    if([SUActivationDevice]::QueryDosDevice($drive,$builder,$builder.Capacity) -eq 0){throw ('QueryDosDevice failed for '+$drive+': '+[Runtime.InteropServices.Marshal]::GetLastWin32Error())}
    return $builder.ToString().Split([char]0)[0]+$DosPath.Substring(2)
}
function Get-ActivationInspectorJson([string]$Argument,[string]$Tag) {
    $prefix=Join-Path $evidenceDirectory ('activation-'+$Tag+'-'+[guid]::NewGuid().ToString('N'))
    $out=Invoke-CapturedProcess $inspectorPath $Argument $prefix 45000
    $lines=@($out -split "`r?`n" | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
    if($lines.Count -ne 1){throw ('Inspector output was not one JSON record: '+$Argument)}
    $record=$lines[0]|ConvertFrom-Json -ErrorAction Stop
    return [pscustomobject]@{Record=$record;Raw=$out;StdErrPath=$prefix+'.err';StdOutPath=$prefix+'.out';Qpc=[Diagnostics.Stopwatch]::GetTimestamp()}
}
function Get-ActivationEpochStatus([string]$Tag) { return (Get-ActivationInspectorJson '--epoch-status' $Tag).Record }
function Get-ActivationWriterState([string]$Tag) { return (Get-ActivationInspectorJson '--writer-state-status' $Tag).Record }
function Get-ActivationEntry([string]$Path,[string]$Tag) { return (Get-ActivationInspectorJson ('--registry-entry "'+$Path+'"') $Tag) }
function Get-ActivationPendingEntry([string]$NtPath,[string]$FileId,[string]$Tag) {
    $snapshot=Get-ActivationInspectorJson '--activating-status' $Tag
    $entries=@($snapshot.Record.entries | Where-Object {$_.path -ieq $NtPath -and $_.fileId -ieq $FileId})
    return [pscustomobject]@{Snapshot=$snapshot;Entries=$entries}
}
function Get-ActivationProductStatus([string]$Tag,[int]$TimeoutMs=5000) {
    if(-not('SUActivationPipeProof' -as [type])){Add-Type -TypeDefinition @'
using System;using System.ComponentModel;using Microsoft.Win32.SafeHandles;using System.Runtime.InteropServices;
public static class SUActivationPipeProof{[DllImport("kernel32.dll",SetLastError=true)]public static extern bool GetNamedPipeServerProcessId(SafePipeHandle h,out uint pid);}
'@}
    $pipe=$null;$reader=$null;$start=[Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $pipe=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent',[IO.Pipes.PipeDirection]::In)
        $pipe.Connect($TimeoutMs);$pipe.ReadTimeout=$TimeoutMs
        $serverPid=[uint32]0;if(-not [SUActivationPipeProof]::GetNamedPipeServerProcessId($pipe.SafePipeHandle,[ref]$serverPid) -or $serverPid -eq 0){throw 'Service notification pipe server PID unavailable'}
        $server=Get-CimInstance Win32_Process -Filter ('ProcessId='+$serverPid) -ErrorAction Stop
        if($null -eq $server -or $server.Name -cne 'SafeUpload.Agent.Service.exe'){throw 'Notification pipe server image mismatch'}
        $owner=Invoke-CimMethod -InputObject $server -MethodName GetOwnerSid -ErrorAction Stop
        if($owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18'){throw 'Notification pipe server is not LocalSystem'}
        $reader=[IO.StreamReader]::new($pipe,[Text.Encoding]::UTF8,$false,4096,$true)
        $line=$reader.ReadLine();if([string]::IsNullOrWhiteSpace($line)){throw 'Service notification status line unavailable'}
        $status=$line|ConvertFrom-Json -ErrorAction Stop
        if($status.type -cne 'status'){throw 'First service pipe record is not current StatusNotification'}
        return [pscustomobject]@{Status='OK';Tag=$Tag;StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();QpcFrequency=[Diagnostics.Stopwatch]::Frequency;BootId=(Get-BootId);ServerPid=$serverPid;ServerSid=$owner.Sid;RawLine=$line;Value=$status}
    }catch{return [pscustomobject]@{Status='INCONCLUSIVE';Tag=$Tag;Reason=$_.Exception.Message;StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();BootId=(Get-BootId);QpcFrequency=[Diagnostics.Stopwatch]::Frequency}}
    finally{if($null -ne $reader){$reader.Dispose()};if($null -ne $pipe){$pipe.Dispose()}}
}
function Wait-ActivationProductStatus([string]$ExpectedCoverage,[uint32]$PolicyGeneration,[int]$Seconds,[string]$Tag) {
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long](($Seconds)*[Diagnostics.Stopwatch]::Frequency));$last=$null;$reason='No current service status received.'
    do {$last=Get-ActivationProductStatus $Tag 3000;if($last.Status -eq 'OK'){
        $s=$last.Value
        if($s.protectionActive -and $s.admissionCoverage -eq $ExpectedCoverage -and $null -ne $s.nativePolicyGeneration -and [uint32]$s.nativePolicyGeneration -eq $PolicyGeneration){return $last}
        if($s.admissionCoverage -eq 'Ready' -and $ExpectedCoverage -eq 'Pending'){$reason='Service reported Ready while the pre-scope holder was still live.'}
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
        if($unheld.Count -ge 100){$ordered=@($raw | Sort-Object Ms);$p95=$ordered[[int][Math]::Ceiling(.95*$ordered.Count)-1].Ms;$verdict='PASS'}
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
function Get-LastAccessEvidence {
    $text=(& fsutil.exe behavior query disablelastaccess 2>&1 | Out-String);$code=$LASTEXITCODE
    $matches=[regex]::Matches($text,'(?im)^\s*DisableLastAccess\s*=\s*([0-3])\b')
    return [pscustomobject]@{Command='fsutil.exe behavior query disablelastaccess';Output=$text;ExitCode=$code;
        Value=$(if($code -eq 0 -and $matches.Count -eq 1){[int]$matches[0].Groups[1].Value}else{$null});
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
function Get-NotificationSnapshot([string]$Tag,[string]$BootId,[long]$MinimumQpc) {
    $root=Split-Path -Parent $policyPath;$directory=Join-Path $root 'notifications'
    $deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((4)*[Diagnostics.Stopwatch]::Frequency));$reason='Notification record unavailable.'
    do {
        $held=@()
        $snapshot=[ordered]@{Status='INCONCLUSIVE';LocationStatus='INCONCLUSIVE';LocationFiles=@();Directory=$directory;DirectoryExists=$null;ChildNames=@();Objects=@();
            BootId=$BootId;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;MinimumQpc=$MinimumQpc;ReadQpc=$null;
            Entries=@();Head=$null;Artifacts=@();Errors=@();Reason=$reason}
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
                return [pscustomobject]$snapshot
            }
            $obj=[SUProofFile]::Open($directory,$true,$true,$false,$true);$held+=$obj;$snapshot.Objects+=@{Path=$directory;Owner=$obj.Owner;Sddl=$obj.Sddl}
            $names=@(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop | Select-Object -ExpandProperty Name)
            $snapshot.ChildNames=$names
            if($names -notcontains 'emissions.jsonl' -or $names -notcontains 'head.json' -or $names -notcontains 'writer.lock' -or
                @($names | Where-Object {$_ -cnotin @('emissions.jsonl','previous.jsonl','head.json','writer.lock')}).Count){throw 'Missing/unrecognized notification record child.'}
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
            if((@($names | Sort-Object) -join '|') -cne ($afterNames -join '|')){throw 'Notification location inventory changed during read.'}
            # Retain authenticated stale records too. Missing current-boot
            # coverage is an evaluation failure, not a reason to discard bytes.
            foreach($copy in $copies){
                $stream=[IO.File]::Open($copy.Path,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::Read)
                try{$stream.Write($copy.Bytes,0,$copy.Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
                $snapshot.Artifacts+=@{Name=$copy.Name;Artifact=$copy.Path;Length=$copy.Bytes.Length;Sha256=(Get-FileHash -LiteralPath $copy.Path).Hash}
            }
            $snapshot.LocationStatus='OK';$snapshot.ReadQpc=[Diagnostics.Stopwatch]::GetTimestamp()
            $record=ConvertFrom-NotificationRecord $segments $headBytes
            $tail=$record.Entries[$record.Entries.Count-1].Entry
            $snapshot.Entries=$record.Entries;$snapshot.Head=$record.Head
            if($tail.BootId -cne $BootId){throw ('Notification tail boot mismatch: recorded='+$tail.BootId+'; required='+$BootId+'. Agent-down seed cannot supply a current-boot heartbeat.')}
            if($tail.QpcFrequency -ne $snapshot.QpcFrequency){throw 'Notification tail QPC frequency mismatch.'}
            if($tail.Qpc -lt $MinimumQpc){throw ('Notification tail precedes snapshot fence: tailQpc='+$tail.Qpc+'; minimumQpc='+$MinimumQpc+'; tailKind='+$tail.Kind+'. Agent-down seed has no live notification writer.')}
            $snapshot.Status='OK';$snapshot.Reason='Authenticated notification record covers snapshot fence.'
            return [pscustomobject]$snapshot
        }catch{$reason=$_.Exception.Message;$snapshot.Reason=$reason;$snapshot.Errors=Get-ErrorChain $_.Exception}
        finally{foreach($obj in $held){$obj.Dispose()}}
        Start-Sleep -Milliseconds 100
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
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
    foreach($node in @($document.Event.EventData.Data)){
        if($null -eq $node){continue};$values+=$node.InnerText
        if(-not [string]::IsNullOrWhiteSpace([string]$node.Name)){$data[[string]$node.Name]=$node.InnerText}
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
function Test-AgentDidNotRun($Before,$After,$Fence,[bool]$WindowKnown,$SystemLog,$SecurityLog) {
    $failures=@();$scm=@();$creations=@();$scmFailures=@();$contradictions=@();$systemContinuous=$false;$scmWindowKnown=$WindowKnown
    if(-not $WindowKnown){$failures+='QPC operation window is not bound to service snapshots.'}
    $b=$Before.AgentExecution;$a=$After.AgentExecution
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
                        # gap closed; with the service installed it still defeats the proof. The image/user check above always applies.
                        $serviceNeverExisted=($null -ne $b.Service -and $null -ne $a.Service -and $b.Service.Exists -eq $false -and $a.Service.Exists -eq $false)
                        if(-not $serviceNeverExisted){
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
        Limitations='Trusted kernel, SCM, audit transport and privileged actors; inventories inspect primary user/group/restricted SIDs, not thread impersonation. 4688 does not expose group SIDs, so any creation defeats this proof. No claim about renamed/injected emitters, off-window activity or intermediate create/delete of notification files.'}
}

function Get-ServiceSnapshot([string]$Tag,[switch]$JournalOnly) {
    $result=[ordered]@{Status='INCONCLUSIVE';Tag=$Tag;BootId=(Get-BootId);QpcFrequency=[Diagnostics.Stopwatch]::Frequency;StartQpc=[Diagnostics.Stopwatch]::GetTimestamp();
        Journal=@();Objects=@();Errors=@();Application=@();AgentProcesses=@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.Service.exe'" | Select-Object ProcessId,CommandLine);}
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
                if($file.Name -notmatch '^[0-9a-f]{32}\.json$'){throw 'Unrecognized journal child; snapshot is not complete.'}
                $obj=[SUProofFile]::Open($file.FullName,$false,$true,[bool]$JournalOnly,$true)
                try{$bytes=[SUProofFile]::Read($obj,131072)}finally{$obj.Dispose()}
                $leaf='service-'+$Tag+'-'+$file.Name;$copy=Join-Path $evidenceDirectory $leaf
                $stream=[IO.File]::Open($copy,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
                try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
                # Collection authenticates and retains ALL bytes. Schema interpretation
                # belongs to delta evaluation; a legacy entry must not truncate inventory.
                $result.Journal+= [pscustomobject]@{Path=$file.FullName;Owner=$obj.Owner;Sddl=$obj.Sddl;Sha256=(Get-FileHash -LiteralPath $copy).Hash;
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
function Get-ServiceTimeline($Before,$After,$Fence) {
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
    if(-not $notificationProof.Complete){
        $systemLog=Read-AgentLogWindow $Before.AgentExecution.SystemBegin $After.AgentExecution.SystemEnd 'System'
        $securityLog=Read-AgentLogWindow $Before.AgentExecution.SecurityBegin $After.AgentExecution.SecurityEnd 'Security'
        $agentAbsence=Test-AgentDidNotRun $Before $After $Fence $windowKnown $systemLog $securityLog
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
function Test-CachedJournalSequence($Transitions,[string]$Outcome,[string]$Digest) {
    $assertions=@();$expected=if($Outcome -ceq 'APPROVE'){@('Allocated','Sealed','Inspecting','Approved','Publishing','Released')}else{@('Allocated','Sealed','Inspecting','Blocked')}
    $names=@($Transitions | ForEach-Object {$_.StateName})
    $missing=@($expected | Where-Object {$names -cnotcontains $_})
    $bad=@($names | Where-Object {$_ -cnotin $expected})
    $position=-1;$ordered=$true
    foreach($name in $names){$next=[array]::IndexOf($expected,$name);if($next -le $position){$ordered=$false};$position=$next}
    # The manifest's durable, service-validated state history records every transition; prefer it to polling.
    $history=if(@($Transitions).Count){@($Transitions[-1].History)}else{@()}
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
    if($identities.Count -gt 1){$assertions+=@{Name='C01JournalIdentity';Verdict='FAIL';Reason='Transfer ID/destination generation changed within one cached write.'}}
    return ,$assertions
}
function Test-CachedNotifications($Proof,[string]$TransferId,[int]$SessionId,[string]$Outcome,[string]$Digest) {
    $assertions=@();$correlated=@($Proof.Emissions | ForEach-Object {$_.Entry} | Where-Object {
        ($_.Kind -ceq 'Transfer' -and $_.TransferId -ieq $TransferId) -or ($_.Kind -ceq 'Event' -and $_.EventId -ieq $TransferId)})
    $entries=@($correlated | Where-Object Kind -ceq 'Transfer')
    $wanted=if($Outcome -ceq 'APPROVE'){'Released'}else{'Blocked'}
    $found=@($entries | Where-Object {$_.Phase -ceq $wanted})
    $bad=@($correlated | Where-Object {($_.TargetSessionId -ne $SessionId) -or ($Outcome -ceq 'BLOCK' -and $_.Phase -cin @('Approved','Publishing','Released')) -or ($Outcome -ceq 'APPROVE' -and $_.Phase -ceq 'Blocked')})
    $assertions+=@{Name='C01OutcomeNotification';Verdict=$(if($bad.Count){'FAIL'}elseif(-not $Proof.Complete){'INCONCLUSIVE'}elseif(-not $found.Count){'FAIL'}else{'PASS'});
        Reason=('Required='+$wanted+'; matching='+$found.Count+'; contradictory/session mismatch='+$bad.Count+'; '+$Proof.Reason)}
    if($Outcome -ceq 'APPROVE'){
        $digests=@($found | Where-Object {$null -ne $_.PSObject.Properties['Sha256Hex']})
        $assertions+=@{Name='C01ReleasedNotificationDigest';Verdict=$(if(@($digests | Where-Object Sha256Hex -cne $Digest).Count){'FAIL'}elseif($digests.Count -and $Proof.Complete){'PASS'}else{'INCONCLUSIVE'});
            Reason='Released must identify A digest. Current durable NotificationRecord and TransferNotification omit content digest; journal correlation alone does not satisfy this contract.'}
    }else{
        $paths=@($found | Where-Object {-not [string]::IsNullOrWhiteSpace($_.HandBackPath)})
        $assertions+=@{Name='C01BlockedNotificationHandBackPath';Verdict=$(if($paths.Count -and $Proof.Complete){'PASS'}else{'INCONCLUSIVE'});
            Reason='Blocked must identify verified actor hand-back path. Current notification adapter/contract has no hand-back path field.'}
    };return ,$assertions
}
function Get-CachedJournalObservation([string]$Tag,$Actor) {
    $snapshot=Get-ServiceSnapshot $Tag -JournalOnly
    $entries=@();$errors=@($snapshot.Errors)
    foreach($record in $snapshot.Journal){
        if(@($trial.ServiceBefore.Journal | Where-Object Path -ieq $record.Path).Count){continue}
        try {
            $parsed=ConvertFrom-ServiceJournalRecord $record
            if($parsed.DestinationPaths -icontains (Join-Path $protectedDirectory 'cached.txt')){
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
function Capture-CachedSample($Context,$Baseline,[string]$PhaseName,[long]$Sequence) {
    $sample=Capture-InvariantSample $Context $Baseline $PhaseName $Sequence
    # The shared observer records raw absence via the parent index, but only
    # opens supplemental readers for existing files. C01 also needs both
    # native fresh opens to attest ERROR_FILE_NOT_FOUND for an absent final.
    $readers=@();$path=Join-Path $protectedDirectory 'cached.txt'
    foreach($raw in @($false,$true)){
        try{$reader=[StagedInvariant.Native]::Fresh($path,$raw,$Context.Geometry.Alignment);$readers+=@{Unbuffered=$raw;Status='OK';Result=$reader;NativeCode=0}}
        catch{
            $code=$null;for($ex=$_.Exception;$null -ne $ex;$ex=$ex.InnerException){if($null -ne $ex.PSObject.Properties['NativeCode']){$code=$ex.NativeCode}}
            $readers+=@{Unbuffered=$raw;Status='ERROR';NativeCode=$code;Reason=$_.Exception.ToString()}
        }
    }
    $sample | Add-Member NoteProperty C01Readers $readers
    return $sample
}
function Test-CachedSample($Sample,$Baseline,[bool]$Released,[byte[]]$ImageA) {
    $assertions=@();$path=Join-Path $protectedDirectory 'cached.txt';$digest=[StagedInvariant.Native]::Hash($ImageA)
    if($Sample.Status -cne 'OK'){$assertions+=@{Name='C01RawCapture';Verdict='INCONCLUSIVE';Reason=('Incomplete raw sample '+$Sample.Phase+': '+($Sample.Error | Out-String))}}
    foreach($capture in $Sample.Captures){
        foreach($image in @($capture.Images | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ceq $path})){
            if(-not $Released){
                $assertions+=@{Name='C01RawFinalAbsent';Verdict=$(if($image.Absent){'PASS'}else{'FAIL'});Reason=('Raw final must remain absent in '+$Sample.Phase);Sequence=$Sample.Sequence}
            }elseif($image.Absent){$assertions+=@{Name='C01ReleasedImage';Verdict='FAIL';Reason='Released final absent in raw parent index.'}}
            else{
                $good=$image.Length -eq $ImageA.Length -and $image.Sha256 -ceq $digest
                $assertions+=@{Name='C01ReleasedImage';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason='Raw logical length and SHA-256 must equal all of A.'}
                try{
                    $logical=[IO.File]::ReadAllBytes($image.LogicalArtifact.Path)
                    if($logical.Length -ne $image.LogicalArtifact.Length -or [StagedInvariant.Native]::Hash($logical) -cne $image.LogicalArtifact.Sha256){throw 'Raw logical artifact hash/length mismatch'}
                    $assertions+=@{Name='C01ReleasedLogicalBytes';Verdict=$(if([StagedInvariant.Native]::CountDifferences($ImageA,$logical)){'FAIL'}else{'PASS'});Reason='Retained whole raw logical artifact compared byte for byte to independently generated A.'}
                }catch{$assertions+=@{Name='C01ReleasedLogicalBytes';Verdict='INCONCLUSIVE';Reason=$_.Exception.Message}}
                # Same VCN-to-volume extent positioning as Test-NoUnapprovedByte.
                # Fixture is exactly three clusters: no unexplained allocation slack.
                $covered=0
                foreach($container in @($image.Containers | Where-Object Kind -ceq 'DATA')){
                    try {
                        $raw=[IO.File]::ReadAllBytes($container.Artifact.Path)
                        if($raw.Length -ne $container.Artifact.Length -or [StagedInvariant.Native]::Hash($raw) -cne $container.Artifact.Sha256){throw 'Retained raw extent hash/length mismatch'}
                        $run=@($image.Runs | Where-Object {$_.Lcn -ge 0 -and $container.Offset -ge $_.Lcn*$Baseline.Geometry.Cluster -and $container.Offset+$container.Length -le ($_.Lcn+$_.Clusters)*$Baseline.Geometry.Cluster})
                        if($run.Count -ne 1){throw 'Cannot position C01 raw extent'}
                        $offset=$run[0].Vcn*$Baseline.Geometry.Cluster+$container.Offset-$run[0].Lcn*$Baseline.Geometry.Cluster
                        if($offset -lt 0 -or $offset+$raw.Length -gt $ImageA.Length){throw 'Raw allocation outside exact cluster-aligned A; no slack oracle available'}
                        $want=New-Object byte[] $raw.Length;[Array]::Copy($ImageA,[long]$offset,$want,[long]0,[long]$raw.Length)
                        $different=[StagedInvariant.Native]::CountDifferences($want,$raw);$covered+=$raw.Length
                        $assertions+=@{Name='C01ReleasedRawExtent';Verdict=$(if($different){'FAIL'}else{'PASS'});Reason=('Raw extent at '+$container.Offset+'; differing bytes='+$different);ForbiddenByteCount=$different}
                    }catch{$assertions+=@{Name='C01ReleasedRawExtent';Verdict='INCONCLUSIVE';Reason=$_.Exception.Message}}
                }
                if($covered -ne $ImageA.Length){$assertions+=@{Name='C01RawExtentCoverage';Verdict='INCONCLUSIVE';Reason=('Expected '+$ImageA.Length+' allocated data bytes; compared '+$covered)}}
            }
        }
        foreach($parent in @($capture.Images | Where-Object Role -ceq 'Parent')){
            $before=@($Baseline.Images | Where-Object {$_.Role -ceq 'Parent' -and $_.Path -ceq $parent.Path})[0]
            $actual=@($parent.DirectoryEntries | Where-Object {$_.Name -notin @('.','..')})
            $old=@($before.DirectoryEntries | Where-Object {$_.Name -notin @('.','..')})
            $extras=@($actual | Where-Object {$_.Name -cnotin $old.Name -and (-not $Released -or $_.Name -cne 'cached.txt')})
            $missing=@($old | Where-Object {$_.Name -cnotin $actual.Name})
            $changed=@($old | Where-Object {$prior=$_;@($actual | Where-Object {$_.Name -ceq $prior.Name -and $_.Reference -eq $prior.Reference -and $_.Eof -eq $prior.Eof -and $_.Attributes -eq $prior.Attributes}).Count -ne 1})
            $assertions+=@{Name='C01PublicListing';Verdict=$(if($extras.Count -or $missing.Count -or $changed.Count){'FAIL'}else{'PASS'});Reason=('Raw names/IDs: unexpected='+($extras.Name -join ',')+'; missing='+($missing.Name -join ',')+'; changed='+($changed.Name -join ','));Sequence=$Sample.Sequence}
        }
    }
    if(-not @($Sample.Captures | ForEach-Object {$_.Images} | Where-Object {$_.Role -ceq 'Current' -and $_.Path -ceq $path}).Count){$assertions+=@{Name='C01RawFinalCoverage';Verdict='INCONCLUSIVE';Reason='No raw final/absence image retained.'}}
    if(-not @($Sample.Captures | ForEach-Object {$_.Images} | Where-Object Role -ceq 'Parent').Count){$assertions+=@{Name='C01RawListingCoverage';Verdict='INCONCLUSIVE';Reason='No raw parent-directory listing retained.'}}
    foreach($reader in $Sample.C01Readers){
        $good=if($Released){$reader.Status -ceq 'OK' -and $reader.Result.Digest -ceq $digest -and $reader.Result.Length -eq $ImageA.Length}else{$reader.Status -ceq 'ERROR' -and $reader.NativeCode -eq 2}
        $verdict=if($good){'PASS'}elseif($reader.Status -ceq 'OK' -or $reader.NativeCode -eq 2){'FAIL'}else{'INCONCLUSIVE'}
        $assertions+=@{Name='C01IndependentReader';Verdict=$verdict;Reason=('Uncached='+$reader.Unbuffered+'; expected='+$(if($Released){'whole A'}else{'Win32:2'})+'; native='+$reader.NativeCode+'; '+$reader.Reason);Sequence=$Sample.Sequence}
    }
    if(@($Sample.C01Readers).Count -ne 2 -or @($Sample.C01Readers | Where-Object Unbuffered).Count -ne 1){$assertions+=@{Name='C01ReaderCoverage';Verdict='INCONCLUSIVE';Reason='Exactly one fresh and one uncached receipt required.'}}
    return ,$assertions
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
function Get-CachedHandBack($Actor,$OwnerFiles,[string]$Digest,[int]$Length) {
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
            $artifact=Join-Path $evidenceDirectory ('handback-'+$objects.Count+'.bin')
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
    return [pscustomobject]@{Root=$root;Files=$objects;Assertions=$assertions;SecondUserAccess='NotChecked: harness owns one standard user only';SafeRelativeCreation='NotChecked: product creation receipt unavailable';WindowClosureAndRestart='Deferred: interactive app/session required'}
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
function Invoke-CachedObservation {
    $context=$null;$baseline=$null;$disposal=$null;$samples=@();$predicateSamples=@();$checkpoints=@();$writer=$null;$agent=$null;$readyEvent=$null;$actor=$null;$agentStartLocal=$null
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
        $trial.ServiceBefore=Get-ServiceSnapshot 'before';$trial.LastAccessBefore=Get-LastAccessEvidence
        $context=Open-InvariantObserver $ready.VolumeGuid $protectedDirectory (Join-Path $evidenceDirectory 'raw') $CaseId
        if($context.Status -cne 'OK'){throw ($context.Error | Out-String)}
        $expected=@{'marker.bin'=[Convert]::FromBase64String($state.BaselineBase64);'cached.txt'=$null}
        $baseline=Capture-InvariantBaseline $context @('marker.bin','cached.txt') $expected
        $baseline | Add-Member NoteProperty CaptureStartedFileTime ([DateTime]::UtcNow.ToFileTimeUtc())
        if($baseline.Status -cne 'OK'){throw ($baseline.Error | Out-String)}
        $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID);$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
        if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $context.ObserverSid){throw 'C01 observer OS SID mismatch'}
        $trial.Platform=@{Build=$context.Build;BootId=$context.BootId;ObserverPid=$context.ObserverPid;ObserverSid=$context.ObserverSid;
            ObserverProcess=@{Pid=$process.ProcessId;OwnerSid=$owner.Sid;SessionId=$process.SessionId;CommandLine=$process.CommandLine}}
        $trial.Geometry=$context.Geometry;$trial.DecoderVersion=$context.DecoderVersion;$trial.ObserverModuleSha256=$context.ModuleSha256
        $imageA=[Convert]::FromBase64String($state.CachedImageBase64);$digest=[StagedInvariant.Native]::Hash($imageA);$trial.ImageA=@{Sha256=$digest;Length=$imageA.Length;Fixture=$state.CachedFixture}
        $sequence=1;$sample=Capture-CachedSample $context $baseline 'BeforeOperation' $sequence;$samples+= $sample;$predicateSamples+= $sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence
        $trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA
        Start-ScheduledTask -TaskName $writerTask
        $actor=Wait-WriterIdentity (Join-Path $actorDirectory 'identity.clixml');$trial.Actor=$actor
        if($actor.Sid -cne $state.ActorSid -or $actor.Elevated -or $actor.IsAdministrator -or $actor.Pid -eq $PID -or $actor.BootId -cne $context.BootId){throw 'C01 actor token/boot provenance invalid'}
        $trial.ActorProvenance=Assert-ActorProcess $actor
        $profiles=@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $actor.Sid)
        if($profiles.Count -ne 1 -or $profiles[0].LocalPath -ine $actor.Profile){throw 'C01 actor profile does not match OS SID profile binding'}
        if(@($trial.ServiceBefore.Journal | Where-Object {try{(ConvertFrom-ServiceJournalRecord $_).DestinationPaths -icontains (Join-Path $protectedDirectory 'cached.txt')}catch{$false}}).Count){throw 'C01 final already claimed in service journal'}
        Write-DurableFile (Join-Path $actorDirectory 'go') $RunName -New
        $held=Wait-WriterIdentity (Join-Path $actorDirectory 'held.clixml') 60
        if($held.Pid -ne $actor.Pid -or $held.Sid -cne $actor.Sid -or $held.Token -cne $state.WriterToken -or $held.BootId -cne $context.BootId){throw 'C01 held receipt identity/token mismatch'}
        $trial.HeldReceipt=$held;$trial.Operations=@($held.Calls)
        $trial.Assertions+=@{Name='C01PrivateRead';Verdict=$(if($held.PrivateSha256 -ceq $digest){'PASS'}else{'FAIL'});Reason='Whole private cached handle read must equal A after flush.'}
        for($n=0;$n -lt 3;$n++){
            $poll=Get-CachedJournalObservation ('held-'+$n) $actor;$trial.JournalSnapshots+= $poll.Snapshot
            if($poll.Status -cne 'OK' -or $poll.Entries.Count -ne 1){$trial.Assertions+=@{Name='C01HeldJournal';Verdict='INCONCLUSIVE';Reason=('Expected one authenticated Allocated transfer while held; '+($poll.Errors | Out-String))}}
            foreach($entry in $poll.Entries){
                if(-not $trial.JournalTransitions.Count -or $trial.JournalTransitions[-1].State -ne $entry.State){$trial.JournalTransitions+= $entry}
                $trial.Assertions+=@{Name='C01SealAfterClose';Verdict=$(if($entry.State -eq 0 -and -not $entry.SealedOnce){'PASS'}else{'FAIL'});Reason=('Held writer must remain Allocated/unsealed; observed '+$entry.StateName)}
            }
            $sequence++;$sample=Capture-CachedSample $context $baseline 'FlushedHandleHeld' $sequence;$samples+= $sample;$predicateSamples+= $sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence
            $trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA
            Start-Sleep -Milliseconds 10
        }
        $trial.CloseBarrierQpc=[Diagnostics.Stopwatch]::GetTimestamp();Write-DurableFile (Join-Path $actorDirectory 'close') $RunName -New
        $closed=Wait-WriterIdentity (Join-Path $actorDirectory 'closed.clixml') 60
        if($closed.Pid -ne $actor.Pid -or $closed.Token -cne $state.WriterToken -or $closed.Sid -cne $actor.Sid -or $closed.BootId -cne $context.BootId){throw 'C01 close receipt identity/token mismatch'}
        $trial.ClosedReceipt=$closed;$trial.Operations=@($closed.Calls)
        $good=($trial.Operations.Class -join ',') -ceq 'writer-open,cached-write,flush,close' -and @($trial.Operations | Where-Object NativeCode -ne 0).Count -eq 0
        $trial.Assertions+=@{Name='ExactNativeStatus';Verdict=$(if($good){'PASS'}else{'FAIL'});Reason=($row.StatusClasses -join ';')}
        if(-not $good){throw 'C01 actor native write/flush/close failed'}
        if($trial.Operations[0].StartQpc -lt $ready.Qpc -or $trial.Operations[-1].StartQpc -lt $trial.CloseBarrierQpc){throw 'C01 operation/readiness/close QPC order invalid'}
        $wanted=if($row.Outcome -ceq 'APPROVE'){'Released'}else{'Blocked'};$deadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((120)*[Diagnostics.Stopwatch]::Frequency));$pollNumber=0;$terminal=$null
        do {
            $poll=Get-CachedJournalObservation ('outcome-'+$pollNumber) $actor;$trial.JournalSnapshots+= $poll.Snapshot;$pollNumber++
            if($poll.Status -cne 'OK'){$trial.Assertions+=@{Name='C01JournalPoll';Verdict='INCONCLUSIVE';Reason=($poll.Errors | Out-String)}}
            if($poll.Entries.Count -gt 1){throw 'C01 destination has multiple transfer manifests'}
            foreach($entry in $poll.Entries){
                if($trial.JournalTransitions.Count -and $trial.JournalTransitions[0].TransferId -ine $entry.TransferId){throw 'C01 transfer identity changed while waiting'}
                if(-not $trial.JournalTransitions.Count -or $trial.JournalTransitions[-1].State -ne $entry.State){$trial.JournalTransitions+= $entry}
                if($entry.StateName -ceq $wanted){$terminal=$entry}
            }
            $sequence++;$sample=Capture-CachedSample $context $baseline 'OutcomeWait' $sequence;$samples+= $sample
            if($row.Outcome -ceq 'BLOCK'){$predicateSamples+= $sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence;$trial.Assertions+=Test-CachedSample $sample $baseline $false $imageA}
            if($null -ne $terminal){break};Start-Sleep -Milliseconds 10
        }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        $trial.Assertions+=Test-CachedJournalSequence $trial.JournalTransitions $row.Outcome $digest
        if($null -eq $terminal){throw ('C01 journal timeout after 120 seconds: expected '+$wanted+'; last observed='+($trial.JournalTransitions.StateName -join ' -> '))}
        $trial.TransferId=$terminal.TransferId
        # Allow asynchronous post-Blocked hand-back work a bounded grace period.
        # No service copy is fabricated by the harness.
        if($row.Outcome -ceq 'BLOCK'){
            $blockedEntry=ConvertFrom-ServiceJournalRecord $terminal.Record
            $stage=$null
            try{
                $stage=[SUProofFile]::Open($blockedEntry.Entry.Transfer.StagePath,$false,$true,$false,$true)
                $blockedBytes=[SUProofFile]::Read($stage,20971520)
                $trial.Assertions+=@{Name='C01BlockedStageRetained';Verdict=$(if($blockedBytes.Length -eq $imageA.Length -and [StagedInvariant.Native]::Hash($blockedBytes) -ceq $digest){'PASS'}else{'FAIL'});Reason='Blocked sealed snapshot remains private and equals exact A during the available window.'}
            }catch{$trial.Assertions+=@{Name='C01BlockedStageRetained';Verdict='INCONCLUSIVE';Reason=$_.Exception.ToString()}}
            finally{if($null -ne $stage){$stage.Dispose()}}
            $handBackDeadline=([Diagnostics.Stopwatch]::GetTimestamp()+[long]((10)*[Diagnostics.Stopwatch]::Frequency));$handBackRoot=Join-Path $actor.Profile 'SafeUpload\_bloqueados'
            do{if(Test-Path -LiteralPath $handBackRoot){if(@(Get-ChildItem -LiteralPath $handBackRoot -File -Force).Count){break}};Start-Sleep -Milliseconds 100}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $handBackDeadline)
        }
        Write-DurableFile (Join-Path $actorDirectory 'inspect-handback') $RunName -New
        $writer=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken 60
        $trial.HandBack=Get-CachedHandBack $actor $writer.Value.HandBackAfter $digest $imageA.Length;$trial.Assertions+=@($trial.HandBack.Assertions)
        $sequence++;$sample=Capture-CachedSample $context $baseline 'FinalQuiescence' $sequence;$samples+= $sample
        $trial.Assertions+=Test-CachedSample $sample $baseline ($row.Outcome -ceq 'APPROVE') $imageA
        if($row.Outcome -ceq 'BLOCK'){$predicateSamples+= $sample;$checkpoints+=Get-ExpectedCheckpoint $baseline $sample.Phase $sequence}
        $trial.Latency=Get-LatencyVerdict $trial.Operations $row.LatencyClasses $writer.Value.QpcFrequency
        $trial.Repetitions=$row.Repetitions;$trial.OperationClassTimeline=$row.StatusClasses
        $trial.Assertions+=@{Name='C01UnheldLatency';Verdict='INCONCLUSIVE';Reason='One coordinated functional write only; 100 unheld latency repetitions deferred.'}
        $trial.LastAccessAfter=Get-LastAccessEvidence
        $fence=[pscustomobject]@{Complete=$true;BootId=$context.BootId;QpcFrequency=$writer.Value.QpcFrequency;ReleasedQpc=$writer.Value.ReleasedQpc;CompletedQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
        $trial.ServiceAfter=Get-ServiceSnapshot 'after'
        $delta=Test-ServiceJournalDelta $trial.ServiceBefore $trial.ServiceAfter $true
        $proof=Test-NotificationWindow $trial.ServiceBefore.Notifications $trial.ServiceAfter.Notifications $fence $true
        $trial.ServiceEvidence=@{JournalDelta=$delta;NotificationProof=$proof;OperationFence=$fence;TrustBoundary='Existing SYSTEM/Administrators same-handle proof adapters'}
        $trial.Journal=$trial.ServiceAfter.Journal;$trial.Notifications=$proof.Emissions
        $trial.Assertions+=@{Name='JournalDelta';Verdict=$(if($delta.Findings.Count){'FAIL'}elseif($delta.Complete){'PASS'}else{'INCONCLUSIVE'});Reason=(@($delta.Failures)+@($delta.Findings) -join '; ')}
        $trial.Assertions+=Test-CachedNotifications $proof $terminal.TransferId $actor.SessionId $row.Outcome $digest
        $trial.VerifierAfter=Get-VerifierEvidence 'after' -RequireMode
    }catch{'ScriptError='+$_.Exception.ToString();$trial.Errors+=Get-ErrorChain $_.Exception;$trial.Assertions+=@{Name='C01Execution';Verdict='INCONCLUSIVE';Reason=($_.Exception.Message+'; '+$_.ScriptStackTrace)}}
    finally {
        if($null -ne $agentStartLocal){
            try{Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$agentStartLocal} -ErrorAction Stop | Where-Object ProviderName -match 'SafeUpload' |
                Sort-Object TimeCreated | ForEach-Object {$_.TimeCreated.ToString('o')+' '+$_.ProviderName+' '+$_.LevelDisplayName+' '+($_.Message -replace '\s+',' ')} |
                Set-Content -LiteralPath (Join-Path $evidenceDirectory 'agent-events-final.txt') -Encoding UTF8}catch{}
        }
        if($null -ne $actor){
            foreach($leaf in @('close','inspect-handback')){try{if(-not(Test-Path -LiteralPath (Join-Path $actorDirectory $leaf))){Write-DurableFile (Join-Path $actorDirectory $leaf) $RunName -New}}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
            try{
                if(Test-Path -LiteralPath (Join-Path $actorDirectory 'closed.clixml')){
                    $receipt=Wait-WriterIdentity (Join-Path $actorDirectory 'closed.clixml') 1
                    if($receipt.Pid -eq $actor.Pid -and $receipt.Token -ceq $state.WriterToken -and $receipt.BootId -ceq $actor.BootId){
                        $trial.Operations=@($receipt.Calls)
                        if(@($receipt.Calls | Where-Object NativeCode -ne 0).Count){$trial.Assertions+=@{Name='ExactNativeStatus';Verdict='FAIL';Reason=('Unexpected native failure: '+(@($receipt.Calls | ForEach-Object {$_.Class+'=Win32:'+$_.NativeCode}) -join '; '))}}
                    }
                }
            }catch{$trial.Errors+=Get-ErrorChain $_.Exception}
        }
        if($null -ne $context -and $context.Status -ceq 'OK'){$disposal=Close-InvariantObserver $context}
        if($null -ne $readyEvent){$readyEvent.Dispose()}
        try{Restore-CachedAgent}catch{$trial.Errors+=Get-ErrorChain $_.Exception;$trial.Assertions+=@{Name='C01AgentRestoration';Verdict='INCONCLUSIVE';Reason=$_.Exception.ToString()}}
        $trial.Baseline=$baseline;$trial.Samples=$samples;$trial.PredicateSamples=$predicateSamples;$trial.Disposal=$disposal
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
                if($assertion -is [Collections.IDictionary] -and $assertion['Name'] -ceq 'C01ReleasedRawExtent' -and $assertion.Contains('ForbiddenByteCount')){
                    $trial.ForbiddenByteCount+= [long]$assertion['ForbiddenByteCount']
                }
            }
        }
        $trial.Assertions+=@{Name='LiveTaintFlags';Verdict='INCONCLUSIVE';Reason='Live TEST_DISABLE_TAINT readback unavailable; BootPolicy.Flags is not a live proof.'}
        $trial.Assertions+=@{Name='C01PublicationAndTemporalCoverage';Verdict='INCONCLUSIVE';Reason='Lower mutation ledger, authenticated permit/snapshot grant and continuous coverage unavailable. APPROVE post-close samples are retained but cannot establish pre-permit absence from latest-state polling.'}
        if($null -eq $trial.ServiceEvidence){$trial.Assertions+=@{Name='ActualServiceTimelines';Verdict='INCONCLUSIVE';Reason='C01 authenticated service window incomplete; see exact execution error and partial journal artifacts.'}}
        if($null -eq $disposal -or $disposal.Status -cne 'OK'){$trial.Assertions+=@{Name='Disposal';Verdict='INCONCLUSIVE';Reason='Checked observer disposal missing/failed.'}}
        $trial.Verdict=if(@($trial.Assertions | Where-Object Verdict -ceq 'FAIL').Count -or @($trial.Latency | Where-Object Verdict -ceq 'FAIL').Count){'FAIL'}else{'INCONCLUSIVE'}
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
function Invoke-ActivationObservation {
    $context=$null;$agent=$null;$baseline=$null;$samples=@();$actorStarted=$false;$traceEnabled=$false
    $trial=[ordered]@{Errors=@();Assertions=@();Samples=@();Operations=@();Verdict='INCONCLUSIVE';ForbiddenByteCount=$null;Reasons=@()}
    $target=Join-Path $protectedDirectory 'marker.txt';$relativeName='marker.txt';$actor=$null
    try {
        Assert-Hash $installedDriver $ExpectedFeatureSha256
        if((Get-BootId) -ceq $state.PrepareBootId){throw 'Activating reboot not observed before A case.'}
        if((Get-ItemProperty "HKLM:\$registryService").Start -ne 0){throw 'A case requires the boot-start driver.'}
        if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0){throw 'Agent must be absent until the pre-scope holder is live.'}
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
        $null=Invoke-CapturedProcess $inspectorPath '--admission-trace-clear' $clearPrefix 45000
        $enablePrefix=Join-Path $evidenceDirectory ('activation-trace-enable-'+[guid]::NewGuid().ToString('N'))
        $null=Invoke-CapturedProcess $inspectorPath '--admission-trace-enable-sections-lifetime' $enablePrefix 45000
        $traceEnabled=$true

        Start-ScheduledTask -TaskName $writerTask
        $actor=Get-ActivationActorIdentity
        $actorStarted=$true
        $trial.Actor=$actor
        $trial.ActorProvenance=@{Pid=$actor.Pid;SessionId=$actor.SessionId;OwnerSid=$actor.OwnerSid;CommandLine=$actor.CommandLine;Task=$actor.Task}
        $state.ActivationActorPid=[int]$actor.Pid;Save-State $state $statePath
        $holder=Publish-ActivationActorCommand $state 'create-holder' $null
        if(-not $holder.HolderCreated -or $holder.NativeCode -ne 0){throw ('Pre-scope holder creation failed: Win32 '+$holder.NativeCode)}
        $expectClosed=($CaseId -ne 'A01')
        if([bool]$holder.SourceHandleClosed -ne $expectClosed){throw ('Holder source-handle state mismatch for '+$CaseId)}
        $trial.HolderSetup=@{CaseId=$CaseId;Pid=$actor.Pid;Sid=$actor.Sid;SessionId=$actor.SessionId;HolderKind=$row.Variant;
            SourceHandleClosed=$holder.SourceHandleClosed;CreateQpc=$holder.StartQpc;CompleteQpc=$holder.EndQpc;NativeCode=$holder.NativeCode}

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

        $epochBefore=Get-ActivationEpochStatus 'before-policy-update'
        if($null -eq $epochBefore.policyGeneration -or $null -eq $epochBefore.epochGeneration){throw 'Pre-update policy/epoch generation missing.'}
        $runtimePolicy=Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -ErrorAction Stop
        if(@($runtimePolicy.monitoredScopes.destinationPaths).Count -ne 0){throw 'A case runtime policy did not start empty.'}
        $runtimePolicy.version=[int]$runtimePolicy.version+1
        $runtimePolicy.monitoredScopes.destinationPaths=@($protectedDirectory)
        Write-DurableFile $policyPath ($runtimePolicy | ConvertTo-Json -Depth 8)
        $agent=Start-StagedTestAgent $serviceDirectory (Join-Path $evidenceDirectory 'activation-agent')
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
        $candidatePolicyGeneration=[uint32]$epochAfter.policyGeneration
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
            $current=Get-ActivationProductStatus 'pending-timeout-current' 3000
            $knownReady=($current.Status -eq 'OK' -and $current.Value.admissionCoverage -eq 'Ready')
            Add-ActivationAssertion $trial 'ServiceReadinessPendingWhileHolderLives' $(if($knownReady){'FAIL'}else{'INCONCLUSIVE'})`
                $(if($knownReady){'Service reported Ready while a pre-scope writable holder was still live.'}else{'Pending status was not observed within 45s: '+$pendingFailure}) $current
        }

        $activating=Get-ActivationPendingEntry $ntPath $fileId 'live-holder'
        if($activating.Entries.Count -ne 1){
            Add-ActivationAssertion $trial 'ExactActivatingWriterEvidence' 'FAIL'`
                ('Complete paged activating-status had '+$activating.Entries.Count+' exact path/file-ID matches; expected one Activating entry.') $activating.Snapshot.Record
            throw 'Target did not have one exact activating-status entry while its pre-scope holder lived.'
        }
        $entry=$activating.Entries[0]
        $holderStateGood=($activating.Snapshot.Record.policyGeneration -eq $candidatePolicyGeneration -and
            $activating.Snapshot.Record.totalEntries -eq $activating.Entries.Count -and
            $entry.state -ceq 'Activating' -and $entry.fileId -ieq $fileId -and $entry.path -ieq $ntPath -and
            [uint32]$entry.generation -gt 0 -and [uint32]$entry.W -eq 0 -and $entry.unknownReasons -ceq '0x00000000')
        if($CaseId -eq 'A01'){$holderStateGood=$holderStateGood -and [uint32]$entry.H -gt 0 -and $entry.openerPids -contains [int]$actor.Pid}
        else{$holderStateGood=$holderStateGood -and $entry.S -ceq 'YES'}
        $holderEvidenceReason=if($CaseId -eq 'A01'){'Complete paged Inspector snapshot identifies the exact NT path, stable file ID, policy generation, Activating state, H>0, and the standard-user actor opener PID.'}else{'Complete paged Inspector snapshot identifies the exact NT path, stable file ID, policy generation, Activating state and S=YES; the actor process independently created and retains the view/section after closing its source handle.'}
        Add-ActivationAssertion $trial 'ExactActivatingWriterEvidence' $(if($holderStateGood){'PASS'}else{'FAIL'})`
            $holderEvidenceReason`
            @{Entry=$entry;Snapshot=$activating.Snapshot.Record;ExpectedNtPath=$ntPath;ExpectedFileId=$fileId;ActorPid=$actor.Pid}
        if(-not $holderStateGood){throw 'Exact Activating holder evidence did not match the case contract.'}

        $writerBefore=Get-ActivationWriterState 'before-new-writer-probes'
        $probe=Publish-ActivationActorCommand $state 'probe-new-writers' $null
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
        for($sampleIndex=0;$sampleIndex -lt 3;$sampleIndex++){$holderReadinessSamples+=Get-ActivationProductStatus ('holder-readiness-'+$sampleIndex) 3000;Start-Sleep -Milliseconds 200}
        $trial.ReadinessSamplesWhileHolder=@()
        if($null -ne $pendingStatus){$trial.ReadinessSamplesWhileHolder+=@($pendingStatus)}
        $trial.ReadinessSamplesWhileHolder+=@($holderReadinessSamples | Where-Object {$null -ne $_})

        if($CaseId -eq 'A03'){
            $lateMap=Publish-ActivationActorCommand $state 'map-late' $null
            Add-ActivationAssertion $trial 'FirstWritableViewCreatedAfterEpoch' $(if($lateMap.NativeCode -eq 0 -and $lateMap.Mapped){'PASS'}else{'FAIL'})`
                ('First MapViewOfFile after admission epoch returned Win32 '+$lateMap.NativeCode+'.') $lateMap
        }

        $clearOldPrefix=Join-Path $evidenceDirectory ('activation-old-write-trace-clear-'+[guid]::NewGuid().ToString('N'))
        $null=Invoke-CapturedProcess $inspectorPath '--admission-trace-clear' $clearOldPrefix 45000
        $changes=@();$changeOffsets=@(64,[int]($pBytes.Length/2),($pBytes.Length-160));$changeIndex=0
        foreach($offset in $changeOffsets){$tag=('ACT-'+$CaseId+'-'+$RunName+'-'+$changeIndex);$payload=[Text.Encoding]::ASCII.GetBytes($tag.PadRight(96,'U'))
            $changes+=@{Offset=[long]$offset;BytesBase64=[Convert]::ToBase64String($payload);PayloadSha256=(Get-ActivationSha256 $payload);Length=$payload.Length};$changeIndex++}
        $oldWrite=Publish-ActivationActorCommand $state 'write-old' @{Changes=$changes}
        $trial.Operations+=@($oldWrite.Calls);$trial.OldHolderMutation=$oldWrite
        $oldApiGood=($oldWrite.NativeCode -eq 0 -and $oldWrite.FlushCode -eq 0 -and @($oldWrite.Calls | Where-Object NativeCode -ne 0).Count -eq 0)
        Add-ActivationAssertion $trial 'OldHolderMutationAllowedAndRecorded' $(if($oldApiGood){'PASS'}else{'FAIL'})`
            'Old pre-scope handle/view write calls and their required handle/view flush completed successfully while the exact file remained Activating.' $oldWrite
        $preProtectionSample=Capture-InvariantSample $context $baseline 'OldHolderMutationBeforeRelease' 2;$samples+=$preProtectionSample
        if($preProtectionSample.Status -ne 'OK'){Add-ActivationAssertion $trial 'PreProtectionRawMutation' 'INCONCLUSIVE' ('Raw sample after the old-holder write failed: '+($preProtectionSample.Error | Out-String)) $preProtectionSample}
        else{
            $preDifference=Get-ActivationRawDifference $baseline $preProtectionSample $target
            $trial.PreProtectionRawDifference=$preDifference
            $preVerdict=if($preDifference.Status -ne 'OK'){'INCONCLUSIVE'}elseif([long]$preDifference.DifferingBytes -gt 0){'PASS'}else{'INCONCLUSIVE'}
            $preReason=if($preDifference.Status -ne 'OK'){$preDifference.Reason}elseif([long]$preDifference.DifferingBytes -gt 0){'Raw allocated DATA extents changed before promotion; those allowed pre-protection bytes are recorded here and excluded from ForbiddenByteCount.'}else{'Old-holder API and lower write evidence exist, but this raw capture shows no persisted DATA-byte delta before release.'}
            Add-ActivationAssertion $trial 'PreProtectionRawMutation' $preVerdict $preReason $preDifference
        }
        $traceText=Invoke-CapturedProcess $inspectorPath '--admission-trace' (Join-Path $evidenceDirectory 'activation-old-holder-admission-trace') 45000
        $trace=ConvertFrom-ActivationTrace $traceText $fileId
        $trial.OldHolderAdmissionTrace=$trace
        $lowerCorrelations=@()
        foreach($change in $changes){
            $matchingPairs=@()
            foreach($pair in $trace.CompletedWritePairs){
                $lowerStart=[uint64]$pair.Begin.writeOffset;$lowerEnd=$lowerStart+[uint64]$pair.Begin.writeLength
                $expectedStart=[uint64]$change.Offset;$expectedEnd=$expectedStart+[uint64]$change.Length
                $actorMatches=($CaseId -ne 'A01' -or [uint32]$pair.Begin.processId -eq [uint32]$actor.Pid)
                if($actorMatches -and [uint64]$pair.Begin.writeLength -gt 0 -and $lowerEnd -gt $expectedStart -and $lowerStart -lt $expectedEnd){$matchingPairs+=@($pair)}
            }
            $lowerCorrelations+=@{Offset=$change.Offset;Length=$change.Length;PayloadSha256=$change.PayloadSha256;SuccessfulLowerPairs=$matchingPairs}
        }
        $lowerWriteEvidence=(@($lowerCorrelations | Where-Object {$_.SuccessfulLowerPairs.Count -gt 0}).Count -eq $changes.Count)
        Add-ActivationAssertion $trial 'OldHolderLowerCompletion' $(if($lowerWriteEvidence){'PASS'}else{'INCONCLUSIVE'})`
            $(if($lowerWriteEvidence){'Loss-free admission trace contains paired successful lower W_BEGIN/W_END records for the exact target file ID whose byte ranges overlap every known user-mode mutation; A01 also matches the actor PID. A02/A03 accept paging-system PID for the retained section writes.'}else{'The loss-free trace did not correlate a successful lower W_BEGIN/W_END range to every known old-holder mutation on the exact target file ID; user-mode success does not replace lower completion evidence.'})`
            @{Trace=$trace;RangeCorrelations=$lowerCorrelations;PayloadSha256Available=$trace.PayloadSha256Available;ActorOperations=$oldWrite.Calls}
        $traceDisablePrefix=Join-Path $evidenceDirectory ('activation-trace-disable-before-release-'+[guid]::NewGuid().ToString('N'))
        $null=Invoke-CapturedProcess $inspectorPath '--admission-trace-disable' $traceDisablePrefix 45000
        $traceEnabled=$false

        $activatingAfterWrite=Get-ActivationPendingEntry $ntPath $fileId 'after-old-holder-mutation'
        $afterWriteEntries=@($activatingAfterWrite.Entries)
        $stillActivating=($afterWriteEntries.Count -eq 1 -and $activatingAfterWrite.Snapshot.Record.policyGeneration -eq $candidatePolicyGeneration -and
            $afterWriteEntries[0].state -ceq 'Activating' -and $afterWriteEntries[0].fileId -ieq $fileId -and
            [uint32]$afterWriteEntries[0].W -eq 0 -and $afterWriteEntries[0].unknownReasons -ceq '0x00000000')
        if($CaseId -eq 'A01'){$stillActivating=$stillActivating -and [uint32]$afterWriteEntries[0].H -gt 0 -and $afterWriteEntries[0].openerPids -contains [int]$actor.Pid}
        else{$stillActivating=$stillActivating -and $afterWriteEntries[0].S -ceq 'YES'}
        Add-ActivationAssertion $trial 'OldHolderStillActivatingAfterMutation' $(if($stillActivating){'PASS'}else{'FAIL'}) 'After the tagged old-holder writes and flush completed, the exact same target remained Activating with its holder evidence and W drained to zero.' @{Entries=$afterWriteEntries;Snapshot=$activatingAfterWrite.Snapshot.Record;FileId=$fileId;ActorPid=$actor.Pid;Mutation=$oldWrite}
        if(-not $stillActivating){throw 'Target left Activating or lost exact holder evidence before the old holder was released.'}

        $holderStatusAfterWrite=Get-ActivationProductStatus 'holder-after-old-write' 3000
        if($holderStatusAfterWrite.Status -eq 'OK' -and $holderStatusAfterWrite.Value.admissionCoverage -eq 'Ready'){
            Add-ActivationAssertion $trial 'ServiceNeverReadyAtSampleAfterMutation' 'FAIL' 'Service reported Ready while the old-holder mutation completed and the old holder still lived.' $holderStatusAfterWrite
        }
        $trial.ReadinessSamplesWhileHolder+=@($holderStatusAfterWrite)
        $readyWhileHeld=@($trial.ReadinessSamplesWhileHolder | Where-Object {$_.Status -eq 'OK' -and $_.Value.admissionCoverage -eq 'Ready'})
        $unverifiedReadiness=@($trial.ReadinessSamplesWhileHolder | Where-Object {$_.Status -ne 'OK' -or [uint32]$_.Value.nativePolicyGeneration -ne $candidatePolicyGeneration -or -not $_.Value.protectionActive})
        $readinessSampleVerdict=if($readyWhileHeld.Count -gt 0){'FAIL'}elseif($pendingStatus -and $unverifiedReadiness.Count -eq 0){'PASS'}else{'INCONCLUSIVE'}
        $readinessSampleReason=if($readyWhileHeld.Count -gt 0){'At least one authenticated current service status reported Ready before last-holder release.'}elseif($readinessSampleVerdict -eq 'PASS'){'Every current status sample at the policy-acceptance, pre-mutation, and post-mutation checkpoints was authenticated, active, at the accepted generation, and non-Ready.'}else{'One or more holder-interval service status samples were missing, unauthenticated, inactive, or at another generation; sampled never-Ready evidence is incomplete.'}
        Add-ActivationAssertion $trial 'NoObservedReadyWhileHolderLives' $readinessSampleVerdict $readinessSampleReason @($trial.ReadinessSamplesWhileHolder | ForEach-Object {if($_.Status -eq 'OK'){@{Tag=$_.Tag;Coverage=$_.Value.admissionCoverage;Generation=$_.Value.nativePolicyGeneration;Qpc=$_.EndQpc}}else{@{Tag=$_.Tag;Status=$_.Status;Reason=$_.Reason}}})
        $release=Publish-ActivationActorCommand $state 'release-holder' $null
        if(-not $release.HolderReleased -or $release.NativeCode -ne 0){throw ('Last pre-scope holder release failed: Win32 '+$release.NativeCode)}
        $trial.LastHolderRelease=$release

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

        $promotionText=Invoke-CapturedProcess $inspectorPath '--promotion-trace' (Join-Path $evidenceDirectory 'activation-promotion-trace') 45000
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
            $current=Get-ActivationProductStatus 'ready-timeout-current' 3000
            $knownDegraded=($current.Status -eq 'OK' -and $current.Value.admissionCoverage -eq 'Degraded')
            Add-ActivationAssertion $trial 'ServiceReadinessReadyAfterPromotion' $(if($knownDegraded){'FAIL'}else{'INCONCLUSIVE'})`
                $(if($knownDegraded){'Service remained Degraded after exact Protected/Free promotion: '+$current.Value.admissionCoverageReason}else{'Ready status was not observed within 60s after promotion: '+$readyFailure}) $current
        }

        $promotionSample=Capture-InvariantSample $context $baseline 'RawImageAtPromotion' 3;$samples+=$promotionSample
        if($promotionSample.Status -ne 'OK'){throw ('Raw image capture after promotion failed: '+($promotionSample.Error | Out-String))}
        $trial.RawPromotionImage=@{FileId=$fileId;Images=$promotionSample.Images;Capture=$promotionSample;AfterProtectedEntry=$promoted.Record;AfterServiceReady=$readyStatus}
        $serviceBefore=Get-ServiceSnapshot 'activation-before-unapproved-write'
        $trial.ServiceBefore=$serviceBefore
        if($serviceBefore.Status -ne 'OK'){Add-ActivationAssertion $trial 'PostPromotionOwnedStreamJournal' 'INCONCLUSIVE' ('Before-write product journal snapshot failed: '+(@($serviceBefore.Errors | ForEach-Object {$_.Message}) -join ' / ')) $serviceBefore.Errors}

        $stagePayload=[Text.Encoding]::ASCII.GetBytes(('POSTPROTECT-'+$CaseId+'-'+$RunName+' CPF: 529.982.247-25').PadRight(96,'Z'))
        $stageOffset=[long]([int]($pBytes.Length/2)+256)
        if($stageOffset+$stagePayload.Length -gt $pBytes.Length){$stageOffset=64}
        $stageStartStatus=Get-ActivationProductStatus 'ready-before-staged-write' 3000
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
        if($stageStartStatus.Status -eq 'OK' -and $stageStartStatus.Value.admissionCoverage -eq 'Ready' -and $stageStartStatus.Value.nativePolicyGeneration -eq $candidatePolicyGeneration){
            Add-ActivationAssertion $trial 'ServiceStillReadyDuringOwnedWrite' 'PASS' 'Product readiness remained Ready at the accepted generation before the unapproved staged write.' $stageStartStatus
        }else{Add-ActivationAssertion $trial 'ServiceStillReadyDuringOwnedWrite' 'INCONCLUSIVE' 'Current service status immediately before the staged write was not a verified Ready status at the accepted generation.' $stageStartStatus}
        if($stageSample.Status -ne 'OK'){Add-ActivationAssertion $trial 'PostPromotionRawDestinationUnchanged' 'INCONCLUSIVE' ('Post-write raw observer sample failed: '+($stageSample.Error | Out-String)) $stageSample}

        Add-ActivationAssertion $trial 'NeverReadyWholeHolderInterval' 'INCONCLUSIVE'`
            'Sampled current service pipe statuses were Pending, but StatusNotification has no file identity or holder counters and the durable notification record retains only notification kind; there is no loss-detecting per-file readiness event sequence for the full holder interval.'`
            @{Samples=@($trial.ReadinessSamplesWhileHolder | ForEach-Object {if($_.Status -eq 'OK'){@{Coverage=$_.Value.admissionCoverage;Generation=$_.Value.nativePolicyGeneration;Qpc=$_.EndQpc}}else{@{Status=$_.Status;Reason=$_.Reason}}});Source='MinifilterInterceptor.cs PublishAdmissionCoverageLoopAsync; AgentNotification.cs StatusNotification; NotificationRecord.cs'}
        $trial.ExpectedTimeline=@{CaseId=$CaseId;Points=@('Unscoped P flushed and raw captured','Runtime agent policy apply adds the one destination scope','Exact target remains Activating with actor holder evidence','New writable opens and section acquisition denied','Old holder mutation logged before release','Free/Protected after last holder release','Service Ready at accepted generation','Unapproved post-promotion write routed to an owned stream','Raw destination DATA extents unchanged after promotion');
            WriterIdentities=@($actor);ExternalEvidence=@{Build=$trial.Platform.Build;PrepareBootId=$state.PrepareBootId;ActiveBootId=$context.BootId;
                ObserverPid=$trial.Platform.ObserverPid;ObserverSid=$trial.Platform.ObserverSid;ObserverProcess=$trial.Platform.ObserverProcess;ActorProvenance=$trial.ActorProvenance};
            AllowedPreProtectionMutationBytes=$(if($null -ne $trial.PreProtectionRawDifference){$trial.PreProtectionRawDifference.DifferingBytes}else{$null});
            ForbiddenByteAccounting='PostPromotionRawDifference only; pre-protection bytes are excluded';TargetFileId=$fileId;TargetDosPath=$target;TargetNtPath=$ntPath}
        $trial.Reasons=@('StatusNotification and durable notification evidence do not provide a per-file H/S/C/T/W holder event sequence; whole-interval never-Ready proof is INCONCLUSIVE.','The admission trace binds successful lower write ranges to the exact file ID, and raw extents prove pre-protection mutation, but it carries no lower payload digest; exact U payload-content correlation is deferred.','Inspector promotion evidence reports TEST_DISABLE_TAINT unavailable (0xffffffff); required live-policy Flags readback remains INCONCLUSIVE.')
        $trial.Actor=$actor;$trial.ReadinessAfter=Get-ActivationProductStatus 'final-current-status' 3000
        $trial.VerifierAfter=Get-VerifierEvidence 'activation-after' -RequireMode
    }catch{
        $trial.Errors+=Get-ErrorChain $_.Exception
        if(@($trial.Assertions | Where-Object Name -eq 'ActivationObservationCompleted').Count -eq 0){Add-ActivationAssertion $trial 'ActivationObservationCompleted' 'INCONCLUSIVE' ('A case stopped at the first missing/invalid bounded observation: '+$_.Exception.Message) $null}
    }finally{
        if($actorStarted){
            try{$exitReply=Publish-ActivationActorCommand $state 'exit-worker' $null;$actorStarted=$false
                if(-not $exitReply.HolderReleased -or $exitReply.NativeCode -ne 0){throw ('Activation actor holder cleanup failed: Win32 '+$exitReply.NativeCode)}
                $completion=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken 45
                $trial.ActorTaskCompletion=@{ExitCode=$completion.ExitCode;BootId=$completion.BootId;HolderReleased=$exitReply.HolderReleased}}
            catch{$trial.Errors+=Get-ErrorChain $_.Exception;Add-ActivationAssertion $trial 'ActorCleanup' 'INCONCLUSIVE' ('Could not prove the activation actor exited and released all handles: '+$_.Exception.Message) $null}
        }
        if($null -ne $agent){
            try{Stop-StagedTestAgent $agent;$state.AgentServiceStarted=$false;Save-State $state $statePath;$agent=$null}
            catch{$trial.Errors+=Get-ErrorChain $_.Exception;Add-ActivationAssertion $trial 'AgentServiceCleanup' 'INCONCLUSIVE' ('Could not stop/restore the test SafeUploadAgent service: '+$_.Exception.Message) $null}
        }
        if($traceEnabled){try{$disablePrefix=Join-Path $evidenceDirectory ('activation-trace-final-disable-'+[guid]::NewGuid().ToString('N'));$null=Invoke-CapturedProcess $inspectorPath '--admission-trace-disable' $disablePrefix 45000;$traceEnabled=$false}catch{$trial.Errors+=Get-ErrorChain $_.Exception}}
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
function Restore-Suite([switch]$Rollback) {
    $errors=[Collections.Generic.List[string]]::new()
    foreach($task in @($bootTask,$writerTask)){
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
        @{Name='fixture';Action={if(Test-Path -LiteralPath $protectedDirectory){Remove-Item -LiteralPath $protectedDirectory -Recurse -Force};if(Test-Path -LiteralPath $protectedDirectory){throw 'Fixture residue'}}},
        @{Name='service-package';Action={if(Test-Path -LiteralPath $serviceDirectory){Remove-Item -LiteralPath $serviceDirectory -Recurse -Force};if(Test-Path -LiteralPath $serviceDirectory){throw 'Service package residue'}}},
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
$cachedCase=$CaseId -in @('C01-approve-absent','C01-block-absent')
$activationCaseIds=@('A01','A02','A03')
$isActivationCase=$CaseId -cin $activationCaseIds
if($row.Status -ne 'Ready' -or ($CaseId -notin @('S00-observer-control','S01-denied-write-after-boot','S02-agent-down-open-refused','C01-approve-absent','C01-block-absent') -and -not $isActivationCase)){'CaseStatus=NOT_READY';throw "Case $CaseId is not implemented"}
if($StartupProbe -and $Phase -ne 'AfterBoot'){throw 'StartupProbe requires AfterBoot'}

if($Phase -eq 'Prepare'){
    if($StartupProbe){throw 'Invalid phase'}
    foreach($path in @($stateDirectory,$evidenceDirectory,$protectedDirectory,$parametersKey)){
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
    $state=@{CaseId=$CaseId;Mode=$Mode;RunName=$RunName;TableRevision=$table.TableRevision;PrepareBootId=(Get-BootId);
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
        $password='Su!'+[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N')
        $user=New-LocalUser -Name $actorUser -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires
        $state.ActorSid=$user.SID.Value
        # Logon requires Users membership; explicitly prove absence of Administrators membership.
        Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $actorUser
        Set-ActorBatchLogon $state.ActorSid $true
        if(@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object SID -eq $user.SID).Count -ne 0){throw 'Actor administrator membership'}
        if($cachedCase){
            # A batch-logon task gets no loaded profile (run c01h: empty UserProfile folder), but hand-back
            # contract H needs the profile a real user has after first logon. Create it explicitly; the
            # actor-profile restoration step removes it.
            if(-not ('SUProfile' -as [type])){Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;using System.Text;public static class SUProfile{[DllImport("userenv.dll",CharSet=CharSet.Unicode)]public static extern int CreateProfile(string sid,string user,StringBuilder path,uint cch);}'}
            $profilePath=[Text.StringBuilder]::new(260)
            $hr=[SUProfile]::CreateProfile($state.ActorSid,$actorUser,$profilePath,260)
            if($hr -ne 0){throw ('Actor profile creation failed: 0x'+$hr.ToString('X8'))}
            $state.ActorProfile=$profilePath.ToString()
        }
        & icacls.exe $stateDirectory /grant ('*'+$state.ActorSid+':RX') | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Actor traversal ACL failed'}
        & icacls.exe $actorDirectory /grant ('*'+$state.ActorSid+':(OI)(CI)M') | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Actor coordination ACL failed'}
        & icacls.exe $protectedDirectory /grant ('*'+$state.ActorSid+':(OI)(CI)M') | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Fixture ACL failed'}
        if(-not $isActivationCase){
            $stream=[IO.FileStream]::new((Join-Path $protectedDirectory 'marker.bin'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
            try{$stream.Write($baseline,0,$baseline.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        }
        $state.FixtureSddl=Get-SecuritySddl $protectedDirectory $true
        $scopes=if($isActivationCase){@()}elseif($CaseId -eq 'S00-observer-control'){@()}else{@($protectedDirectory)}
        if($cachedCase){$state.CachedProductBackup=Save-CachedProductState;Save-State $state $statePath}
        Set-ProtectedPolicyAcl
        $extensions=@(if($cachedCase -or $isActivationCase){'.txt'}else{'.bin'})
        $policy=@{version=1;activeCategories=@('Cpf');monitoredScopes=@{extensions=$extensions;destinationPaths=@($scopes);removableDrives=$false;networkPaths=$false};
            maxFileSizeMb=20;inspectionTimeoutSeconds=5;failOpen=$false;excludedProcesses=@('System','SafeUpload.Agent.App');auditOnly=$false;overrideAllowed=($cachedCase -and $row.Outcome -ceq 'BLOCK')}
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
            $prefix=$nt+$protectedDirectory.Substring(2)
            $pb=[Text.Encoding]::Unicode.GetBytes($prefix);if($pb.Length -gt 518){throw 'Scope prefix too long'}
            [Array]::Copy($pb,0,$expected,16,$pb.Length)
        }
        $state.ExpectedBootRecord=[Convert]::ToBase64String($expected)
        if(-not $readback.AclValid -or $readback.PendingPresent -or $readback.RecordBase64 -cne $state.ExpectedBootRecord -or $readback.DriverStart -ne 3 -or
            @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0 -or (& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s'){throw 'Product seed exact bytes/ACL/Start/no-load readback failed'}
        'BootPolicyPrebootVerified=ParametersAcl:True;BootPolicyAcl:True;RecordBytes:16656;ExactRecord:True;PendingScopes:Absent;Start:3;PASS'
        $configPath=Join-Path $stateDirectory 'writer-config.clixml'
        if($isActivationCase){
            $state.ActorNextSequence=1
            $holderKind=switch($CaseId){'A01'{'handle'}'A02'{'view'}default{'section'}}
            Save-State @{ActorSid=$state.ActorSid;ActorDirectory=$actorDirectory;Target=(Join-Path $protectedDirectory 'marker.txt');
                HolderKind=$holderKind;PBase64=$state.BaselineBase64;ImageLength=$size} $configPath
            $writerBody=Get-ActivatingWriterBody
            $writerBody=$writerBody.Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $configPath))
            $writerBody=$writerBody.Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'identity.clixml')))
            $writerBody=$writerBody.Replace('__SCRIPT_ERROR__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'script-error.txt')))
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
                $bytes=[Text.Encoding]::ASCII.GetBytes(('C01 patterned benign image '+$RunName+"`n").PadRight($size,'P'))
                $state.ForbiddenBlocks=@()
                foreach($offset in @(0,[int]($size/2),($size-128))){
                    $block=[Text.Encoding]::ASCII.GetBytes(('C01-'+$RunName+'-offset-'+$offset+"`n").PadRight(128,'A'))
                    if($block.Length -ne 128){throw 'C01 patterned block exceeds 128 bytes'}
                    [Array]::Copy($block,0,$bytes,$offset,128);$state.ForbiddenBlocks+= [Convert]::ToBase64String($block)
                }
                if($row.Outcome -ceq 'BLOCK'){$sensitive=[Text.Encoding]::ASCII.GetBytes("`nCPF 529.982.247-25`n");[Array]::Copy($sensitive,0,$bytes,256,$sensitive.Length)}
                $state.CachedImageBase64=[Convert]::ToBase64String($bytes)
                $state.CachedFixture=if($row.Outcome -ceq 'BLOCK'){'PlainTextExtractor/Cpf; synthetic valid-checkdigit 529.982.247-25'}else{'PlainTextExtractor/Cpf; no CPF candidate'}
                $payloads=@($state.CachedImageBase64)
            }
            Save-State @{ActorSid=$state.ActorSid;Payloads=$payloads;CachedCase=$cachedCase;Token=$state.WriterToken;CoordinationDirectory=$actorDirectory;
                CreateNew=($CaseId -eq 'S02-agent-down-open-refused');Target=(Join-Path $protectedDirectory $(if($cachedCase){'cached.txt'}elseif($CaseId -eq 'S02-agent-down-open-refused'){'new.bin'}else{'marker.bin'}))} $configPath
            $writerBody=(Get-WriterBody).Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $configPath)).Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'identity.clixml'))).Replace('__GO__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'go'))).Replace('__TEMP__',(ConvertTo-PowerShellLiteral $actorDirectory))
        }
        $writerLauncher=Join-Path $stateDirectory 'writer.ps1'
        Write-DurableFile $writerLauncher (New-TaskLauncher $writerBody $state.WriterToken (Join-Path $actorDirectory 'completion.clixml')) -New
        foreach($path in @($configPath,$writerLauncher)){
            & icacls.exe $path /grant ('*'+$state.ActorSid+':R') | Out-Host
            if($LASTEXITCODE -ne 0){throw 'Read-only writer input ACL failed'}
        }
        $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$writerLauncher+'"')
        Register-ScheduledTask -TaskName $writerTask -Action $action -User ($env:COMPUTERNAME+'\'+$actorUser) -Password $password -RunLevel Limited -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(5))) | Out-Null
        $password=$null
        # Trusted coordinator launches this SAME pinned suite in a fresh process.
        $invoke="& '"+(ConvertTo-PowerShellLiteral $PSCommandPath)+"' -Phase AfterBoot -StartupProbe"
        foreach($key in @($PSBoundParameters.Keys | Sort-Object)){if($key -notin @('Phase','StartupProbe')){$invoke+=' -'+$key+" '"+(ConvertTo-PowerShellLiteral ([string]$PSBoundParameters[$key]))+"'"}}
        $launcher=Join-Path $stateDirectory 'startup.ps1'
        Write-DurableFile $launcher (New-TaskLauncher $invoke $state.CoordinatorToken (Join-Path $evidenceDirectory 'startup-completion.clixml')) -New
        Register-SystemTask $bootTask $launcher -AtStartup
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
    if($state.CaseId -cne $CaseId -or $state.Mode -cne $Mode -or $state.RunName -cne $RunName){throw 'State identity mismatch'}
    if($StartupProbe){if($isActivationCase){Invoke-ActivationObservation}elseif($cachedCase){Invoke-CachedObservation}else{Invoke-SeedObservation};return}
    $observationError=$null
    try {
        $null=Wait-TaskCompletion $bootTask (Join-Path $evidenceDirectory 'startup-completion.clixml') $state.CoordinatorToken 900
        if(-not(Test-Path -LiteralPath $trialPath)){throw 'Completed startup task omitted trial'}
    }catch{$observationError=Get-ErrorChain $_.Exception;Save-State $observationError (Join-Path $evidenceDirectory 'startup-error.clixml')}
    finally {
        # StartupProbe updates actor/service recovery fields in its own process.
        # Re-read after its completion before restoration or those fields are lost.
        if($isActivationCase){$state=Load-State $statePath}
        $state.AfterBootId=Get-BootId
        Save-State $state $statePath
        Restore-Suite
    }
    # Completion means evidence was collected or its absence recorded. Verdict is
    # solely case.json + independent baseline. Never emit the Phase 2 sentinel.
    'INVARIANT_CASE_COMPLETED=True';'INVARIANT_RESTORED=True'
}else{
    $state=Load-State $statePath
    if((Get-BootId) -ceq $state.AfterBootId -or [string]::IsNullOrWhiteSpace($state.AfterBootId)){throw 'Restoration reboot identity unavailable'}
    Assert-Hash $installedDriver $originalDriverHash;Assert-Hash $policyPath $ExpectedOriginalPolicySha256
    $finalAudit=Get-ProcessCreationAudit
    if($null -eq $state.OriginalProcessCreationAudit -or
        $finalAudit.CreationFlags -ne $state.OriginalProcessCreationAudit.CreationFlags -or
        $finalAudit.PerUserPolicyCount -ne $state.OriginalProcessCreationAudit.PerUserPolicyCount){throw 'Final process-creation audit policy residue'}
    if(-not [string]::IsNullOrWhiteSpace($state.ActorSid)){
        foreach($profile in @(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $state.ActorSid)){
            if($profile.Loaded){throw 'Actor profile loaded after the restoration reboot'}
            Remove-CimInstance -InputObject $profile
        }
        if(@(Get-CimInstance Win32_UserProfile | Where-Object SID -ceq $state.ActorSid).Count -ne 0){throw 'Actor profile residue'}
    }
    if((Get-ItemProperty "HKLM:\$registryService").Start -ne 3 -or (& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s' -or
        (Test-Path -LiteralPath $parametersKey) -or (Test-Path -LiteralPath $protectedDirectory) -or (Test-Path -LiteralPath $serviceDirectory) -or
        @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0 -or
        @(Get-ScheduledTask | Where-Object {$_.TaskName -eq $bootTask -or $_.TaskName -eq $writerTask}).Count -ne 0 -or
        (Get-LocalUser -Name $state.ActorUser -ErrorAction SilentlyContinue)){throw 'Final restoration residue'}
    $active=(& verifier.exe /query 2>&1 | Out-String);$settings=(& verifier.exe /querysettings 2>&1 | Out-String)
    if($active -notmatch 'No drivers are currently verified' -or $settings -notmatch 'Verifier Flags:\s+0x00000000'){throw 'Verifier not off after restoration reboot'}
    Set-AgentServiceStart $state.OriginalAgentStart
    if((Get-SecuritySddl $policyPath $false) -cne $state.OriginalPolicyFileSddl -or
        (Get-SecuritySddl (Split-Path -Parent $policyPath) $true) -cne $state.OriginalPolicyDirectorySddl){throw 'Restored policy ACL mismatch'}
    $trial=if(Test-Path -LiteralPath $trialPath){Load-State $trialPath}else{@{Verdict='INCONCLUSIVE';ForbiddenByteCount=$null;Reasons=@('Startup task did not export observations')}}
    if(-not $cachedCase -and -not $isActivationCase -and $null -ne $trial.Baseline -and @($trial.Samples).Count -gt 0){
        $trial.Assertions=@($trial.Assertions | Where-Object {$trial.Predicate.Assertions.Name -notcontains $_.Name})
        $trial.Predicate=Test-NoUnapprovedByte $trial.Baseline @() $trial.Samples $trial.MutationLedger $trial.ExpectedTimeline
        $trial.Assertions+=@($trial.Predicate.Assertions)
        if($trial.Predicate.Verdict -eq 'FAIL'){$trial.Verdict='FAIL'}
        $trial.ForbiddenByteCount=$trial.Predicate.ForbiddenByteCount
    }
    $finalReasons=if($isActivationCase -and $trial.Reasons.Count -gt 0){@($trial.Reasons)}else{@('Seed rows do not qualify Phase4; driver lower mutation ledger and live taint readback unavailable; notification absence requires authenticated durable coverage or whole-window agent absence plus an unchanged authenticated record location')}
    $result=[ordered]@{Schema='StagedInvariantSuite/2';TableRevision=$table.TableRevision;CaseRevision=$row.Revision;CaseId=$CaseId;Mode=$Mode;RunName=$RunName;
        CaseStatus='READY';QualificationScope=$row.QualificationScope;Verdict=$trial.Verdict;ForbiddenByteCount=$trial.ForbiddenByteCount;Trials=@($trial);
        InputHashes=@{Table=$ExpectedTableSha256;Observer=$ExpectedObserverSha256;Suite=$ExpectedSuiteSha256;Helper=$ExpectedHelperSha256;
            Feature=$ExpectedFeatureSha256;Inspector=$ExpectedInspectorSha256;ServicePackage=$ExpectedServicePackageSha256;ServiceTree=$ExpectedServiceTreeSha256};
        BootIds=@{Prepare=$state.PrepareBootId;Active=$state.AfterBootId;Final=(Get-BootId)};Restoration=@{GuestChecks=$true;IndependentBaseline=$null;Known=$false;
            ProcessCreationAudit=@{Original=$state.OriginalProcessCreationAudit;Final=$finalAudit;Restored=$true}};
        AuthoritativeCaseExport=$false;Reasons=$(if($cachedCase){@('Functional/seed rows do not qualify full Phase4: lower mutation ledger, live taint and full temporal/permit evidence unavailable; C01 is one coordinated absent-final write, no approved B or interactive JUSTIFY/restart/window-closure qualification')}else{$finalReasons});
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
