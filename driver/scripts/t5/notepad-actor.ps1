<#
T5 actor: a standard user in its own interactive session (autologon, task with an interactive token) that saves into the protected
folder the way Notepad's Save As does. Commands arrive as C:\T5\control\cmd-<n>.json ({"N":..,"Op":..,"Path":..,"Text":..}); the
actor answers ack-<n>.json with every native step's Win32 code, or the UI's observations.

Ops:
  probe-delete   the common file dialog's test create, then the application's save: CreateFile(CREATE_NEW) + close, DeleteFile,
                 CreateFile(CREATE_ALWAYS) + write Text + close
  probe-doc      the same with the test file opened FILE_FLAG_DELETE_ON_CLOSE instead of an explicit delete
  notepad        real notepad.exe: type Text, Save As (Ctrl+Shift+S) to Path, then collect the text of any window Notepad shows
#>
param([string]$Control = 'C:\T5\control')
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class T5Native {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(IntPtr h, byte[] buffer, int count, out int written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool DeleteFileW(string name);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    static int Err() { return Marshal.GetLastWin32Error(); }
    // Returns "step=code" pairs; 0 is success.
    public static string Probe(string path, byte[] bytes, bool deleteOnClose) {
        var log = new System.Text.StringBuilder();
        uint flags = deleteOnClose ? 0x04000000u /* FILE_FLAG_DELETE_ON_CLOSE */ : 0x80u;
        IntPtr h = CreateFileW(path, 0x40000000 | (deleteOnClose ? 0x00010000u : 0u), 0, IntPtr.Zero, 1 /* CREATE_NEW */, flags, IntPtr.Zero);
        log.Append("test-create=" + (h == new IntPtr(-1) ? Err() : 0));
        if (h != new IntPtr(-1)) log.Append(" test-close=" + (CloseHandle(h) ? 0 : Err()));
        if (!deleteOnClose) log.Append(" test-delete=" + (DeleteFileW(path) ? 0 : Err()));
        h = CreateFileW(path, 0x40000000, 1 /* FILE_SHARE_READ */, IntPtr.Zero, 2 /* CREATE_ALWAYS */, 0x80, IntPtr.Zero);
        log.Append(" save-create=" + (h == new IntPtr(-1) ? Err() : 0));
        if (h != new IntPtr(-1)) {
            int written;
            log.Append(" save-write=" + (WriteFile(h, bytes, bytes.Length, out written, IntPtr.Zero) && written == bytes.Length ? 0 : Err()));
            log.Append(" save-close=" + (CloseHandle(h) ? 0 : Err()));
        }
        return log.ToString();
    }
}
'@
function Get-WindowTexts([int]$ProcessId) {
    # Every top-level window of the process with the names of its text elements (an error box's message is a Text element).
    $root = [Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId)
    $texts = @()
    foreach ($w in $root.FindAll([Windows.Automation.TreeScope]::Children, $cond)) {
        $parts = @($w.Current.Name)
        foreach ($e in $w.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)) {
            if ($e.Current.ControlType -eq [Windows.Automation.ControlType]::Text -and $e.Current.Name) { $parts += $e.Current.Name }
        }
        $texts += ($parts -join ' | ')
    }
    $texts
}
function Wait-Element([scriptblock]$Find, [int]$Seconds = 20) {
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + $Seconds * [Diagnostics.Stopwatch]::Frequency
    do { $e = & $Find; if ($null -ne $e) { return $e }; Start-Sleep -Milliseconds 200 } while ([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    $null
}
function Invoke-NotepadSaveAs([string]$Path, [string]$Text) {
    $obs = [ordered]@{}
    $p = Start-Process notepad.exe -PassThru
    try {
        $root = [Windows.Automation.AutomationElement]::RootElement
        $byPid = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
        $main = Wait-Element { $root.FindFirst([Windows.Automation.TreeScope]::Children, $byPid) }
        if ($null -eq $main) { throw 'Notepad window did not appear' }
        $edit = $main.FindFirst([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ClassNameProperty, 'Edit')))
        # Notepad's multi-line edit control has no ValuePattern: type the text as a user would. SendKeys metacharacters are escaped.
        [void][T5Native]::SetForegroundWindow([IntPtr]$main.Current.NativeWindowHandle)
        if ($null -ne $edit) { $edit.SetFocus() }
        Start-Sleep -Milliseconds 300
        [Windows.Forms.SendKeys]::SendWait(($Text -replace '([+^%~(){}\[\]])', '{$1}'))
        Start-Sleep -Milliseconds 300
        [Windows.Forms.SendKeys]::SendWait('^+s')
        $dialog = Wait-Element {
            foreach ($w in $root.FindAll([Windows.Automation.TreeScope]::Children, $byPid)) { if ($w.Current.Name -eq 'Save As') { return $w } }
            foreach ($w in $main.FindAll([Windows.Automation.TreeScope]::Children, [Windows.Automation.Condition]::TrueCondition)) { if ($w.Current.Name -eq 'Save As') { return $w } }
            $null
        }
        if ($null -eq $dialog) { throw 'Save As dialog did not appear' }
        $nameBox = Wait-Element { $dialog.FindFirst([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.AndCondition(
            (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty, '1001')),
            (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Edit))))) }
        if ($null -eq $nameBox) { throw 'file name box not found' }
        $nameBox.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue($Path)
        $save = $dialog.FindFirst([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty, '1')))
        $save.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
        Start-Sleep -Seconds 4
        $obs.WindowsAfterSave = @(Get-WindowTexts $p.Id)
        $obs.Title = (Get-Process -Id $p.Id).MainWindowTitle
    } finally {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    $obs
}
try {
'ACTOR_STARTED pid=' + $PID + ' user=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name + ' session=' + [Diagnostics.Process]::GetCurrentProcess().SessionId |
    Set-Content -LiteralPath (Join-Path $Control 'actor-started.txt')
for (;;) {
    $command = Get-ChildItem -LiteralPath $Control -Filter 'cmd-*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { Start-Sleep -Milliseconds 20; continue }
    $c = [IO.File]::ReadAllText($command.FullName) | ConvertFrom-Json
    if ($c.Op -eq 'stop') { Remove-Item -LiteralPath $command.FullName -Force; break }
    $result = [ordered]@{ N = $c.N; Op = $c.Op }
    try {
        $bytes = [Text.Encoding]::ASCII.GetBytes([string]$c.Text)
        switch ($c.Op) {
            'probe-delete' { $result.Steps = [T5Native]::Probe($c.Path, $bytes, $false) }
            'probe-doc' { $result.Steps = [T5Native]::Probe($c.Path, $bytes, $true) }
            'notepad' { $result.Ui = Invoke-NotepadSaveAs $c.Path ([string]$c.Text) }
            default { throw ('unknown op ' + $c.Op) }
        }
    } catch { $result.Error = $_.Exception.Message }
    $ack = Join-Path $Control ('ack-' + $c.N + '.json')
    [IO.File]::WriteAllText(($ack + '.tmp'), ($result | ConvertTo-Json -Depth 6 -Compress))
    [IO.File]::Move(($ack + '.tmp'), $ack)
    Remove-Item -LiteralPath $command.FullName -Force
}
'ACTOR_STOPPED' | Set-Content -LiteralPath (Join-Path $Control 'actor-stopped.txt')
} catch {
    ($_ | Format-List * -Force | Out-String) + "`n" + $_.ScriptStackTrace | Set-Content -LiteralPath (Join-Path $Control 'actor-error.txt')
    throw
}
