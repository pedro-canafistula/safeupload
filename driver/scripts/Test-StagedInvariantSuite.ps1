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
    $deadline=[DateTime]::UtcNow.AddSeconds($Seconds);$reason='File not published.'
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
    }while([DateTime]::UtcNow -lt $deadline)
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
    $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $t=Get-ScheduledTask -TaskName $Task -ErrorAction Stop
        if((Test-Path -LiteralPath $Done) -and $t.State -ne 'Running'){break}
        Start-Sleep -Milliseconds 200
    }while([DateTime]::UtcNow -lt $deadline)
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
    try {Register-SystemTask $name $launcher;Start-ScheduledTask -TaskName $name;return (Wait-TaskCompletion $name $done $token 90).Value}
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
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr h,int c,out int v,int n,out int r);
 public static bool Elevated(IntPtr token) { int v,r; if(!GetTokenInformation(token,20,out v,4,out r))throw new Win32Exception(Marshal.GetLastWin32Error());return v!=0; }
 static SUCall Call(string c,int code,long start,long end,int trial) {return new SUCall{Class=c,NativeCode=code,StartQpc=start,EndQpc=end,Trial=trial,Cold=trial==0};}
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
    if($actor.Elevated -or $actor.IsAdministrator -or $actor.Sid -cne $config.ActorSid){throw 'Writer token is not the expected standard user'}
    Write-DurableFile '__IDENTITY__' ([Management.Automation.PSSerializer]::Serialize($actor,32)) -New
    $deadline=[DateTime]::UtcNow.AddSeconds(180)
    while(-not(Test-Path -LiteralPath '__GO__')){if([DateTime]::UtcNow -gt $deadline){throw 'Writer barrier timed out'};Start-Sleep -Milliseconds 10}
    $releasedQpc=[Diagnostics.Stopwatch]::GetTimestamp()
    $calls=@()
    # One cold attempt followed by 100 calls without per-call test holds. Payload
    # generation, serialization, observer waits and process startup are not timed.
    for($trial=0;$trial -le 100;$trial++) {
        $bytes=[Convert]::FromBase64String($config.Payloads[$trial])
        $calls+= [SUWriter]::Attempt($config.Target,$bytes,$config.CreateNew,$trial)
    }
    $value=@{Actor=$actor;Calls=$calls;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;ReleasedQpc=$releasedQpc;Held=$false}
}finally{$identity.Dispose()}
'@
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
    $deadline=[DateTime]::UtcNow.AddSeconds(180)
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
    }while([DateTime]::UtcNow -lt $deadline)
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
    $deadline=[DateTime]::UtcNow.AddSeconds(4);$reason='Notification record unavailable.'
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
    }while([DateTime]::UtcNow -lt $deadline)
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
function Get-AgentLogAnchor([string]$Name) {
    $start=[Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $log=Get-WinEvent -ListLog $Name -ErrorAction Stop
        if(-not $log.IsEnabled){throw 'Log disabled.'}
        $old=Get-WinEvent -LogName $Name -Oldest -MaxEvents 1 -ErrorAction Stop
        $last=Get-WinEvent -LogName $Name -MaxEvents 1 -ErrorAction Stop
        return [pscustomobject]@{Status='OK';Name=$Name;StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();
            OldestRecordId=$old.RecordId;NewestRecordId=$last.RecordId;NewestXml=$last.ToXml();SecurityDescriptor=$log.SecurityDescriptor}
    }catch{return [pscustomobject]@{Status='INCONCLUSIVE';Name=$Name;Reason=$_.Exception.Message;StartQpc=$start;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp()}}
}
function Get-AgentExecutionSnapshot {
    $result=[ordered]@{Status='INCONCLUSIVE';BootId=(Get-BootId);QpcFrequency=[Diagnostics.Stopwatch]::Frequency;
        StartQpc=[Diagnostics.Stopwatch]::GetTimestamp();Errors=@();Processes=@();CollectedByPid=$PID;Service=$null;Audit=$null;ServiceSid=$null;ImagePaths=@()}
    try {
        Initialize-AgentExecutionReader
        # Begin anchors precede inventory; end anchors follow it. Record-ID
        # ordering, rather than UTC filtering, overcovers the QPC case window.
        $result.SystemBegin=Get-AgentLogAnchor 'System';$result.SecurityBegin=Get-AgentLogAnchor 'Security'
        $result.InventoryStartQpc=[Diagnostics.Stopwatch]::GetTimestamp()
        $audit=[SUAgentExecution]::Audit();$result.Audit=@{CreationFlags=$audit[0];PerUserPolicyCount=$audit[1]}
        $services=@(Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction Stop)
        if($services.Count -ne 1){throw 'SCM SafeUploadAgent service missing/ambiguous.'}
        $service=$services[0]
        $result.Service=@{Name=$service.Name;DisplayName=$service.DisplayName;State=$service.State;ProcessId=$service.ProcessId;PathName=$service.PathName;StartMode=$service.StartMode}
        # Reject unresolved/ambiguous unquoted executable paths, not guesses.
        $match=[regex]::Match($service.PathName,'^\s*(?:"(?<image>[A-Za-z]:\\[^"\r\n]+\.exe)"|(?<image>[A-Za-z]:\\[^\s"]+\.exe))(?:\s|$)','IgnoreCase')
        if(-not $match.Success){throw 'SCM agent image path unresolved/ambiguous.'}
        $result.ImagePaths=@([IO.Path]::GetFullPath($match.Groups['image'].Value),[IO.Path]::GetFullPath((Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe')))
        $result.ServiceSid=[SUAgentExecution]::ServiceSid('SafeUploadAgent')
        # PID 0/4 are kernel pseudo/system processes, not user-mode emitters.
        # Any other vanished, protected or inaccessible process defeats proof.
        foreach($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)){
            if($process.ProcessId -in @(0,4)){continue}
            try{$result.Processes+=[SUAgentExecution]::Process([int]$process.ProcessId)}
            catch{$result.Errors+=('Process inventory PID '+$process.ProcessId+': '+$_.Exception.Message)}
        }
        $result.InventoryEndQpc=[Diagnostics.Stopwatch]::GetTimestamp()
        if(@($result.Processes | Where-Object Pid -eq $PID).Count -ne 1){$result.Errors+='Collector process missing/duplicated in inventory.'}
        $result.SystemEnd=Get-AgentLogAnchor 'System';$result.SecurityEnd=Get-AgentLogAnchor 'Security'
        if($result.Errors.Count -eq 0){$result.Status='OK'}
    }catch{$result.Errors+=$_.Exception.Message}
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
        if($Before.Status -cne 'OK' -or $After.Status -cne 'OK'){throw ('Log anchors unavailable: before='+$Before.Reason+'; after='+$After.Reason)}
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
    $failures=@();$scm=@();$creations=@()
    if(-not $WindowKnown){$failures+='QPC operation window is not bound to service snapshots.'}
    $b=$Before.AgentExecution;$a=$After.AgentExecution
    foreach($pair in @(@{Tag='before';Snapshot=$b},@{Tag='after';Snapshot=$a})){
        $s=$pair.Snapshot
        if($null -eq $s){$failures+=('Agent '+$pair.Tag+' execution snapshot missing.');continue}
        if($s.Status -cne 'OK'){$failures+=('Agent '+$pair.Tag+' inventory incomplete: '+($s.Errors -join '; '))}
        if($s.BootId -cne $Fence.BootId -or $s.EndBootId -cne $Fence.BootId -or $s.QpcFrequency -ne $Fence.QpcFrequency -or
            $null -eq $s.StartQpc -or $null -eq $s.EndQpc -or $s.StartQpc -gt $s.EndQpc){$failures+=('Agent '+$pair.Tag+' boot/QPC receipts missing/mismatched.')}
        if($null -eq $s.InventoryStartQpc -or $null -eq $s.InventoryEndQpc -or
            $s.InventoryStartQpc -lt $s.StartQpc -or $s.InventoryStartQpc -gt $s.InventoryEndQpc -or $s.InventoryEndQpc -gt $s.EndQpc){
            $failures+=('Agent '+$pair.Tag+' inventory QPC receipts missing/out of order.')
        }
        if($null -eq $s.Service -or $s.Service.Name -cne 'SafeUploadAgent' -or $s.Service.State -cne 'Stopped' -or
            $null -eq $s.Service.ProcessId -or $s.Service.ProcessId -ne 0){$failures+=('SCM SafeUploadAgent '+$pair.Tag+' state is not authenticated Stopped/PID 0.')}
        if($null -eq $s.Audit.CreationFlags -or ($s.Audit.CreationFlags -band 1) -eq 0 -or
            $null -eq $s.Audit.PerUserPolicyCount -or $s.Audit.PerUserPolicyCount -ne 0){$failures+=('Agent '+$pair.Tag+' process-creation success auditing missing/disabled or per-user overrides present.')}
        if([string]::IsNullOrWhiteSpace($s.ServiceSid) -or @($s.ImagePaths).Count -lt 2 -or $null -eq $s.Processes){$failures+=('Agent '+$pair.Tag+' image/SID/inventory identity missing.')}
        if($null -eq $s.CollectedByPid -or @($s.Processes | Where-Object Pid -eq $s.CollectedByPid).Count -ne 1){$failures+=('Agent '+$pair.Tag+' inventory lacks its collector process.')}
        foreach($process in $s.Processes){
            if([string]::IsNullOrWhiteSpace($process.Image) -or @($process.TokenSids).Count -eq 0){$failures+=('Agent '+$pair.Tag+' PID '+$process.Pid+' image/token SIDs unavailable.')}
            if($s.ImagePaths -icontains $process.Image -or $process.TokenSids -contains $s.ServiceSid){$failures+=('Agent image or service SID exists at '+$pair.Tag+' edge: PID '+$process.Pid+'.')}
        }
    }
    if($null -ne $b -and $null -ne $a){
        if($b.EndQpc -gt $Fence.ReleasedQpc -or $a.StartQpc -lt $Fence.CompletedQpc){$failures+='Agent inventory edges do not bracket whole operation window.'}
        if($b.ServiceSid -cne $a.ServiceSid -or ($b.ImagePaths -join '|') -ine ($a.ImagePaths -join '|') -or
            $b.Service.DisplayName -cne $a.Service.DisplayName -or $b.Service.PathName -cne $a.Service.PathName){$failures+='Agent SCM/image/SID identity changed between edges.'}
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
                            $failures+=('SCM SafeUploadAgent activity '+$event.Id+' at record '+$event.RecordId+'.')
                        }
                    }
                }else{
                    if(($event.Provider -ceq 'Microsoft-Windows-Eventlog' -and $event.Id -in @(1100,1101,1102,1104,1108)) -or
                        ($event.Provider -ceq 'Microsoft-Windows-Security-Auditing' -and $event.Id -in @(4719,4902,4906,4912,4696))){throw ('Security audit clear/loss/policy/token-change event '+$event.Id+' at record '+$event.RecordId+'.')}
                    if($event.Provider -ceq 'Microsoft-Windows-Security-Auditing' -and $event.Id -eq 4688){
                        $creations+=$event
                        if($b.ImagePaths -icontains $event.Data.NewProcessName -or $a.ImagePaths -icontains $event.Data.NewProcessName -or
                            $event.Data.SubjectUserSid -ceq $b.ServiceSid -or $event.Data.TargetUserSid -ceq $b.ServiceSid){$failures+=('Agent image/service SID process creation at Security record '+$event.RecordId+'.')}
                        # 4688 authenticates image/user, not group/restricted SIDs.
                        # No exemption for a benign-looking path or exited PID.
                        $failures+=('Process created between inventories at Security record '+$event.RecordId+'; 4688 lacks token group/restricted service-SID evidence.')
                    }
                }
            }
        }catch{$failures+=$_.Exception.Message}
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
    return [pscustomobject]@{Complete=($failures.Count -eq 0);Reason=$(if($failures.Count){$failures -join ' '}else{'agent did not run in window'});
        Failures=$failures;ScmEvents=$scm;ProcessCreations=$creations;SystemLog=$SystemLog;SecurityLog=$SecurityLog;
        Limitations='Trusted kernel, SCM, audit transport and privileged actors; inventories inspect primary user/group/restricted SIDs, not thread impersonation. 4688 does not expose group SIDs, so any creation defeats this proof. No claim about renamed/injected emitters, off-window activity or intermediate create/delete of notification files.'}
}

function Get-ServiceSnapshot([string]$Tag) {
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
                $obj=[SUProofFile]::Open($file.FullName,$false,$true,$false,$true)
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
        $deadline=[DateTime]::UtcNow.AddSeconds(60)
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
            if([DateTime]::UtcNow -gt $deadline.AddSeconds(120)){throw 'Writer completion unavailable'}
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
            PreCutoffImages=@();Checkpoints=$checkpoints;AllowedMutations=@();ExpectedDenials=@();WriterIdentities=@($trial.Actor | Where-Object {$null -ne $_});
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
function Restore-Suite([switch]$Rollback) {
    $errors=[Collections.Generic.List[string]]::new()
    foreach($task in @($bootTask,$writerTask)){
        try {if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){Stop-ScheduledTask -TaskName $task;Unregister-ScheduledTask -TaskName $task -Confirm:$false}
            if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Task residue'}}catch{$errors.Add($_.Exception.ToString())}
    }
    # Each restoration step is independent, but failed steps retain recovery state.
    $steps=@(
        @{Name='driver';Action={Set-DemandStartAndRestoreDriver}},
        @{Name='policy';Action={Restore-PolicyFile}},
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
                $profileDeadline=[DateTime]::UtcNow.AddSeconds(90)
                while(@(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -ceq $state.ActorSid -and $_.Loaded }).Count -ne 0 -and
                      [DateTime]::UtcNow -lt $profileDeadline){Start-Sleep -Milliseconds 500}
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
if($row.Status -ne 'Ready' -or $CaseId -notin @('S00-observer-control','S01-denied-write-after-boot','S02-agent-down-open-refused')){'CaseStatus=NOT_READY';throw "Case $CaseId is not implemented"}
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
    if($signature.Status.ToString() -cne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne '220DD82C37FCF36048D59E4F10113185D81D5DC7'){throw 'Feature signature gate failed'}
    Assert-Hash (Join-Path $documents 'stage-service-publish.zip') $ExpectedServicePackageSha256
    if((Get-ItemProperty "HKLM:\$registryService").Start -ne 3 -or (& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s' -or
        @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0){throw 'Expected unloaded demand-start driver and stopped agent'}
    $originalAgentStart=$null
    $agentKey='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
    if(Test-Path -LiteralPath $agentKey){
        if((Get-Service SafeUploadAgent).Status -ne 'Stopped'){throw 'Agent service must be stopped'}
        $originalAgentStart=[int](Get-ItemProperty $agentKey).Start
    }
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
        OriginalAgentStart=$originalAgentStart;OriginalPolicyBase64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($policyPath));
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
        & icacls.exe $stateDirectory /grant ('*'+$state.ActorSid+':RX') | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Actor traversal ACL failed'}
        & icacls.exe $actorDirectory /grant ('*'+$state.ActorSid+':(OI)(CI)M') | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Actor coordination ACL failed'}
        & icacls.exe $protectedDirectory /grant ('*'+$state.ActorSid+':(OI)(CI)M') | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Fixture ACL failed'}
        $stream=[IO.FileStream]::new((Join-Path $protectedDirectory 'marker.bin'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
        try{$stream.Write($baseline,0,$baseline.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        $state.FixtureSddl=Get-SecuritySddl $protectedDirectory $true
        $scopes=if($CaseId -eq 'S00-observer-control'){@()}else{@($protectedDirectory)}
        Set-ProtectedPolicyAcl
        $policy=@{version=1;activeCategories=@('Cpf');monitoredScopes=@{extensions=@('.bin');destinationPaths=@($scopes);removableDrives=$false;networkPaths=$false};
            maxFileSizeMb=20;inspectionTimeoutSeconds=5;failOpen=$false;excludedProcesses=@('System','SafeUpload.Agent.App');auditOnly=$false;overrideAllowed=$false}
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
        $configPath=Join-Path $stateDirectory 'writer-config.clixml'
        Save-State @{ActorSid=$state.ActorSid;Payloads=$payloads;CreateNew=($CaseId -eq 'S02-agent-down-open-refused');Target=(Join-Path $protectedDirectory $(if($CaseId -eq 'S02-agent-down-open-refused'){'new.bin'}else{'marker.bin'}))} $configPath
        $writerBody=(Get-WriterBody).Replace('__CONFIG__',(ConvertTo-PowerShellLiteral $configPath)).Replace('__IDENTITY__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'identity.clixml'))).Replace('__GO__',(ConvertTo-PowerShellLiteral (Join-Path $actorDirectory 'go')))
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
    if($StartupProbe){Invoke-SeedObservation;return}
    $observationError=$null
    try {
        $null=Wait-TaskCompletion $bootTask (Join-Path $evidenceDirectory 'startup-completion.clixml') $state.CoordinatorToken 600
        if(-not(Test-Path -LiteralPath $trialPath)){throw 'Completed startup task omitted trial'}
    }catch{$observationError=Get-ErrorChain $_.Exception;Save-State $observationError (Join-Path $evidenceDirectory 'startup-error.clixml')}
    finally {
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
    if($null -ne $trial.Baseline -and @($trial.Samples).Count -gt 0){
        $trial.Assertions=@($trial.Assertions | Where-Object {$trial.Predicate.Assertions.Name -notcontains $_.Name})
        $trial.Predicate=Test-NoUnapprovedByte $trial.Baseline @() $trial.Samples $trial.MutationLedger $trial.ExpectedTimeline
        $trial.Assertions+=@($trial.Predicate.Assertions)
        if($trial.Predicate.Verdict -eq 'FAIL'){$trial.Verdict='FAIL'}
        $trial.ForbiddenByteCount=$trial.Predicate.ForbiddenByteCount
    }
    $result=[ordered]@{Schema='StagedInvariantSuite/2';TableRevision=$table.TableRevision;CaseRevision=$row.Revision;CaseId=$CaseId;Mode=$Mode;RunName=$RunName;
        CaseStatus='READY';QualificationScope=$row.QualificationScope;Verdict=$trial.Verdict;ForbiddenByteCount=$trial.ForbiddenByteCount;Trials=@($trial);
        InputHashes=@{Table=$ExpectedTableSha256;Observer=$ExpectedObserverSha256;Suite=$ExpectedSuiteSha256;Helper=$ExpectedHelperSha256;
            Feature=$ExpectedFeatureSha256;Inspector=$ExpectedInspectorSha256;ServicePackage=$ExpectedServicePackageSha256;ServiceTree=$ExpectedServiceTreeSha256};
        BootIds=@{Prepare=$state.PrepareBootId;Active=$state.AfterBootId;Final=(Get-BootId)};Restoration=@{GuestChecks=$true;IndependentBaseline=$null;Known=$false};
        AuthoritativeCaseExport=$false;Reasons=@('Seed rows do not qualify Phase4; driver lower mutation ledger and live taint readback unavailable; notification absence requires authenticated durable coverage or whole-window agent absence plus an unchanged authenticated record location');
        Load=@{ComputerSystem=(Get-CimInstance Win32_ComputerSystem | Select-Object NumberOfLogicalProcessors,TotalPhysicalMemory);Cpu=(Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores);Disk=(Get-Disk | Select-Object Number,FriendlyName,BusType);ObserverPriority=[string][Diagnostics.Process]::GetCurrentProcess().PriorityClass}}
    Copy-Item -LiteralPath $statePath -Destination (Join-Path $evidenceDirectory 'lifecycle.clixml')
    Copy-Item -LiteralPath $actorDirectory -Destination (Join-Path $evidenceDirectory 'actor') -Recurse
    Remove-Item -LiteralPath $stateDirectory -Recurse -Force
    if(Test-Path -LiteralPath $stateDirectory){throw 'State directory residue'}
    Write-DurableFile (Join-Path $evidenceDirectory 'case.json') ($result | ConvertTo-Json -Depth 32) -New
    'InvariantVerdict='+$result.Verdict
    'INVARIANT_FINAL_STATE=True'
}
