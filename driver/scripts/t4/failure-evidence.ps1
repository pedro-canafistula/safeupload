# T4 diagnostic helpers. Dot-sourcing defines functions only. These receipts
# never authorize publication, recovery, or cleanup of a product stage.
function Get-T4FailureDecision([hashtable]$Counts, $Outcome) {
    if ($Outcome.Ok) { return $null }
    if ($Outcome.Why -ceq 'BLOCKED BYTES PUBLISHED') {
        return [pscustomobject]@{ Reason = 'blocked-bytes-published'; FirstCycle = $Outcome.I; Count = 1; Key = $Outcome.Why }
    }
    if ($Outcome.Why -ceq 'actor: timeout') {
        return [pscustomobject]@{ Reason = 'actor-command-timeout'; FirstCycle = $Outcome.I; Count = 1; Key = $Outcome.Why }
    }
    # Ignore only this command's exact destination spelling. Do not erase
    # native error codes, operation names, or other diagnostic differences.
    $why = [string]$Outcome.Why
    if ($Outcome.Target) { $why = $why.Replace([string]$Outcome.Target, '<destination>') }
    $key = [string]$Outcome.Pattern + '|' + ($why -replace '\s+', ' ').Trim()
    if (-not $Counts.ContainsKey($key)) { $Counts[$key] = @{ FirstCycle = $Outcome.I; Count = 0 } }
    $Counts[$key].Count++
    if ($Counts[$key].Count -ge 2) {
        return [pscustomobject]@{ Reason = 'repeated-identical-failure'; FirstCycle = $Counts[$key].FirstCycle; Count = $Counts[$key].Count; Key = $key }
    }
    return $null
}

function Initialize-T4EvidenceIdentity {
    if ('T4EvidenceIdentity' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class T4EvidenceMetadata {
 public string VolumeSerial, FileId128;
 public long CreationTime, LastWriteTime, ChangeTime;
 public uint Attributes;
}
public static class T4EvidenceIdentity {
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int kind, byte[] data, uint size);
 public static T4EvidenceMetadata Read(SafeFileHandle handle) {
  var id=new byte[24]; var basic=new byte[40];
  if(!GetFileInformationByHandleEx(handle,18,id,(uint)id.Length) ||
     !GetFileInformationByHandleEx(handle,0,basic,(uint)basic.Length))
   throw new Win32Exception(Marshal.GetLastWin32Error());
  return new T4EvidenceMetadata {
   VolumeSerial=BitConverter.ToUInt64(id,0).ToString("X16"),
   FileId128=BitConverter.ToString(id,8,16).Replace("-",""),
   CreationTime=BitConverter.ToInt64(basic,0), LastWriteTime=BitConverter.ToInt64(basic,16),
   ChangeTime=BitConverter.ToInt64(basic,24), Attributes=BitConverter.ToUInt32(basic,32)
  };
 }
}
'@
}

function Save-T4FailureEvidence([string]$OutputRoot, [string]$JournalDirectory,
    [string]$StageDirectory, [int]$Cycle, [string]$Target) {
    Initialize-T4EvidenceIdentity
    $directory = Join-Path $OutputRoot ('cycle-' + $Cycle.ToString('D6'))
    if (Test-Path -LiteralPath $directory) { throw 'Failure evidence already exists; refuse overwrite.' }
    # Journal contents remain private in the guest. Only the test coordinator,
    # SYSTEM and administrators can read these diagnostic copies.
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($sid in @($owner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    [void][IO.Directory]::CreateDirectory($directory, $security)
    [void][IO.Directory]::CreateDirectory((Join-Path $directory 'journal'))
    $receipt = [ordered]@{ Cycle = $Cycle; Target = $Target; Qpc = [Diagnostics.Stopwatch]::GetTimestamp();
        PointInTimeOnly = $true; AtomicSnapshot = $false; ProductAuthority = $false;
        JournalCopied = 0; StageObserved = 0; Errors = @() }
    foreach ($source in @(
        @{ Kind = 'journal'; Path = $JournalDirectory },
        @{ Kind = 'stage'; Path = $StageDirectory }
    )) {
        try { $files = @(Get-ChildItem -LiteralPath $source.Path -File -Force) }
        catch { $receipt.Errors += $_.Exception.Message; continue }
        foreach ($file in $files) {
            $row = [ordered]@{ Kind = $source.Kind; Path = $file.FullName; Qpc = [Diagnostics.Stopwatch]::GetTimestamp() }
            if ($source.Kind -eq 'journal' -and $file.Extension -notin '.json', '.tmp') { continue }
            $stream = $null
            try {
                if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refuse a reparse-point diagnostic source.' }
                $stream = [IO.FileStream]::new($file.FullName, [IO.FileMode]::Open,
                    [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
                $row.Before = [T4EvidenceIdentity]::Read($stream.SafeFileHandle)
                if (($row.Before.Attributes -band 0x410) -ne 0) { throw 'Diagnostic source is not a regular non-reparse file.' }
                $row.LengthBefore = $stream.Length
                $row.Sddl = $stream.GetAccessControl().GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
                if ($source.Kind -eq 'journal') {
                    # Match the product manifest bound and include partial
                    # temporary metadata; never copy private user stage bytes.
                    $buffer = New-Object byte[] (128 * 1024 + 1)
                    $read = 0
                    while ($read -lt $buffer.Length) {
                        $n = $stream.Read($buffer, $read, $buffer.Length - $read)
                        if ($n -eq 0) { break }
                        $read += $n
                    }
                    if ($read -gt 128 * 1024) { throw 'Journal diagnostic source exceeds the 128-KiB bound.' }
                    $bytes = New-Object byte[] $read
                    [Array]::Copy($buffer, $bytes, $read)
                    [IO.File]::WriteAllBytes((Join-Path (Join-Path $directory 'journal') $file.Name), $bytes)
                    $row.CopiedBytes = $read
                    $receipt.JournalCopied++
                } else { $receipt.StageObserved++ }
                $row.After = [T4EvidenceIdentity]::Read($stream.SafeFileHandle)
                $row.LengthAfter = $stream.Length
                $row.UnchangedDuringRead = ($row.Before.VolumeSerial -ceq $row.After.VolumeSerial -and
                    $row.Before.FileId128 -ceq $row.After.FileId128 -and
                    $row.Before.LastWriteTime -eq $row.After.LastWriteTime -and
                    $row.Before.ChangeTime -eq $row.After.ChangeTime -and $row.LengthBefore -eq $row.LengthAfter)
            } catch { $row.Error = $_.Exception.Message; $receipt.Errors += ($file.FullName + ': ' + $_.Exception.Message) }
            finally { if ($stream) { $stream.Dispose() } }
            Write-T4ResultLine (Join-Path $directory 'inventory.jsonl') ($row | ConvertTo-Json -Depth 5 -Compress)
        }
    }
    [IO.File]::WriteAllText((Join-Path $directory 'receipt.json'),
        ($receipt | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    return $directory
}

function Stop-T4Actor([string]$Control) {
    $part = Join-Path $Control 'stop.part'
    $command = Join-Path $Control 'cmd-stop.txt'
    if (-not (Test-Path -LiteralPath $command)) {
        [IO.File]::WriteAllText($part, 'stop')
        [IO.File]::Move($part, $command)
    }
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 60 * [Diagnostics.Stopwatch]::Frequency
    while (-not (Test-Path -LiteralPath (Join-Path $Control 'actor-stopped.txt'))) {
        if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { return $false }
        Start-Sleep -Milliseconds 200
    }
    return $true
}
