#requires -Version 5.1
#requires -RunAsAdministrator
<# WP3 seed lifecycle. Completion sentinels describe transport/restoration, NOT
   protection. Finalize exports one provisional case.json; the host makes the
   single authoritative export after the wrapper's independent remote baseline.
   Missing lower-ledger/live-taint/service adapters deliberately cannot PASS. #>
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
    $calls=@()
    # One cold attempt followed by 100 calls without per-call test holds. Payload
    # generation, serialization, observer waits and process startup are not timed.
    for($trial=0;$trial -le 100;$trial++) {
        $bytes=[Convert]::FromBase64String($config.Payloads[$trial])
        $calls+= [SUWriter]::Attempt($config.Target,$bytes,$config.CreateNew,$trial)
    }
    $value=@{Actor=$actor;Calls=$calls;QpcFrequency=[Diagnostics.Stopwatch]::Frequency;Held=$false}
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
            else{$storage+=@{Path=$image.Path;Kind='Final';Version='Baseline';FileId=$image.Identity.FileId;Generation=0;ZeroPadding=$false}}
        }
    }
    return [pscustomobject]@{Phase=$PhaseName;OperationSequence=$Sequence;State=$row.ExpectedTimeline[2];Storage=$storage;Directories=$dirs;ReadDenials=@()}
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
        if($CaseId -eq 'S00-observer-control'){
            Start-ScheduledTask -TaskName $writerTask
            $identityPath=Join-Path $actorDirectory 'identity.clixml'
            $deadline=[DateTime]::UtcNow.AddSeconds(60)
            while(-not(Test-Path -LiteralPath $identityPath)){if([DateTime]::UtcNow -gt $deadline){throw 'Writer identity unavailable'};Start-Sleep -Milliseconds 100}
            $trial.ActorProvenance=Assert-ActorProcess (Load-State $identityPath)
            Write-DurableFile (Join-Path $actorDirectory 'go') $RunName -New
            $writer=Wait-TaskCompletion $writerTask (Join-Path $actorDirectory 'completion.clixml') $state.WriterToken
            $trial.Actor=$writer.Value.Actor
            # Known control writes are legitimate setup and are flushed before
            # independently expected baseline capture. Every later sample equals B.
        }
        $context=Open-InvariantObserver $ready.VolumeGuid $protectedDirectory (Join-Path $evidenceDirectory 'raw') $CaseId
        if($context.Status -ne 'OK'){throw ($context.Error | Out-String)}
        $expected=@{'marker.bin'=[Convert]::FromBase64String($state.BaselineBase64);'new.bin'=$null}
        $baseline=Capture-InvariantBaseline $context @('marker.bin','new.bin') $expected
        $trial.DecoderVersion=$context.DecoderVersion;$trial.ObserverModuleSha256=$context.ModuleSha256
        $trial.Geometry=$context.Geometry;$trial.Platform=@{Build=$context.Build;BootId=$context.BootId;ObserverPid=$context.ObserverPid;ObserverSid=$context.ObserverSid}
        if($baseline.Status -ne 'OK'){throw ($baseline.Error | Out-String)}
        $seq=1;$checkpoints+=Get-ExpectedCheckpoint $baseline 'BeforeOperation' $seq
        $samples+=Capture-InvariantSample $context $baseline 'BeforeOperation' $seq
        if($CaseId -ne 'S00-observer-control'){Start-ScheduledTask -TaskName $writerTask}
        $identityPath=Join-Path $actorDirectory 'identity.clixml'
        $deadline=[DateTime]::UtcNow.AddSeconds(60)
        while(-not(Test-Path -LiteralPath $identityPath)){if([DateTime]::UtcNow -gt $deadline){throw 'Writer identity unavailable'};Start-Sleep -Milliseconds 100}
        $actor=Load-State $identityPath
        if($actor.Sid -cne $state.ActorSid -or $actor.Elevated -or $actor.IsAdministrator -or $actor.Pid -eq $PID -or $actor.BootId -cne $context.BootId){throw 'Actor provenance invalid'}
        $trial.Actor=$actor
        if($CaseId -ne 'S00-observer-control'){$trial.ActorProvenance=Assert-ActorProcess $actor;Write-DurableFile (Join-Path $actorDirectory 'go') $RunName -New}
        do {
            $seq++;$checkpoints+=Get-ExpectedCheckpoint $baseline 'Continuous' $seq
            $samples+=Capture-InvariantSample $context $baseline 'Continuous' $seq
            # Target cadence only; durations/gaps survive, never mark gaps accounted without ledger.
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
        # No fabricated lower entries, actor-free bypass, live Flags or event proof.
        $trial.MutationLedger=@{Complete=$false;Overflow=$false;FirstSequence=0;LastSequence=0;Entries=@();Source='Unavailable: Phase3 lower-ledger adapter'}
        $trial.ExpectedTimeline=@{ForbiddenBlocks=@($state.ForbiddenBlocks | ForEach-Object {,[Convert]::FromBase64String($_)});
            PreCutoffImages=@();Checkpoints=$checkpoints;AllowedMutations=@();ExpectedDenials=@();WriterIdentities=@($trial.Actor | Where-Object {$null -ne $_});
            AccountedGapSequences=@();PlatformValidated=($null -ne $trial.Readiness);ObserverIndependent=($null -ne $trial.Actor);
            StandardUserWriters=($null -ne $trial.Actor);ContinuousObservationComplete=$false;RestorationKnown=$false}
        if($null -ne $baseline -and $samples.Count -gt 0){
            $trial.Predicate=Test-NoUnapprovedByte $baseline @() $samples $trial.MutationLedger $trial.ExpectedTimeline
            $trial.ForbiddenByteCount=$trial.Predicate.ForbiddenByteCount
            $trial.Assertions+=@($trial.Predicate.Assertions)
        }
        $trial.Assertions+=@{Name='LiveTaintFlags';Verdict='INCONCLUSIVE';Reason='TEST_DISABLE_TAINT setter/readback unavailable; BootPolicy.Flags is not live Flags'}
        $trial.Assertions+=@{Name='ActualServiceTimelines';Verdict='INCONCLUSIVE';Reason='Journal/notification negative assertions lack authenticated product adapter'}
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
    $size=[int](Get-Volume -DriveLetter C).AllocationUnitSize*3
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
                foreach($offset in @(0,[int]($size/2),$size-128)){
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
            Write-DurableFile (Join-Path $evidenceDirectory 'case.json') (@{Schema='StagedInvariantSuite/1';CaseId=$CaseId;Mode=$Mode;RunName=$RunName;
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
        $trial.Predicate=Test-NoUnapprovedByte $trial.Baseline @() $trial.Samples $trial.MutationLedger $trial.ExpectedTimeline
        if($trial.Predicate.Verdict -eq 'FAIL'){$trial.Verdict='FAIL'}
        $trial.ForbiddenByteCount=$trial.Predicate.ForbiddenByteCount
    }
    $result=[ordered]@{Schema='StagedInvariantSuite/1';TableRevision=$table.TableRevision;CaseRevision=$row.Revision;CaseId=$CaseId;Mode=$Mode;RunName=$RunName;
        CaseStatus='READY';QualificationScope=$row.QualificationScope;Verdict=$trial.Verdict;ForbiddenByteCount=$trial.ForbiddenByteCount;Trials=@($trial);
        InputHashes=@{Table=$ExpectedTableSha256;Observer=$ExpectedObserverSha256;Suite=$ExpectedSuiteSha256;Helper=$ExpectedHelperSha256;
            Feature=$ExpectedFeatureSha256;Inspector=$ExpectedInspectorSha256;ServicePackage=$ExpectedServicePackageSha256;ServiceTree=$ExpectedServiceTreeSha256};
        BootIds=@{Prepare=$state.PrepareBootId;Active=$state.AfterBootId;Final=(Get-BootId)};Restoration=@{GuestChecks=$true;IndependentBaseline=$null;Known=$false};
        AuthoritativeCaseExport=$false;Reasons=@('WP3 seeds do not qualify Phase4; lower ledger, live taint, exact service and cadence evidence unavailable');
        Load=@{ComputerSystem=(Get-CimInstance Win32_ComputerSystem | Select-Object NumberOfLogicalProcessors,TotalPhysicalMemory);Cpu=(Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores);Disk=(Get-Disk | Select-Object Number,FriendlyName,BusType);ObserverPriority=[string][Diagnostics.Process]::GetCurrentProcess().PriorityClass}}
    Copy-Item -LiteralPath $statePath -Destination (Join-Path $evidenceDirectory 'lifecycle.clixml')
    Copy-Item -LiteralPath $actorDirectory -Destination (Join-Path $evidenceDirectory 'actor') -Recurse
    Remove-Item -LiteralPath $stateDirectory -Recurse -Force
    if(Test-Path -LiteralPath $stateDirectory){throw 'State directory residue'}
    Write-DurableFile (Join-Path $evidenceDirectory 'case.json') ($result | ConvertTo-Json -Depth 32) -New
    'InvariantVerdict='+$result.Verdict
    'INVARIANT_FINAL_STATE=True'
}
