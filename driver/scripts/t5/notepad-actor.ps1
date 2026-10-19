<#
T5 actor: a standard user in its own interactive session (autologon, task with an interactive token) that saves into the protected
folder the way Notepad's Save As does. Commands arrive as C:\T5\control\cmd-<n>.json ({"N":..,"Op":..,"Path":..,"Text":..}); the
actor answers ack-<n>.json with every native step's Win32 code, or the UI's observations.

Ops:
  probe-delete-before-seal  keep the writable test-create handle open through the observer gate and DeleteFileW; close it before saving
  probe-delete-after-publication  close the test-create handle; the coordinator must observe public empty-file publication before releasing the gate
  probe-delete   native control replay of the common file dialog's test create, then the application's save: CreateFile(CREATE_NEW)
                 + close, an observer-gated control pause, DeleteFile, CreateFile(CREATE_ALWAYS) + write Text + close
  probe-doc      the same native control replay with FILE_FLAG_DELETE_ON_CLOSE; its gated pause is not part of the real UI sequence
  probe-onclose  two share-compatible handles set FILE_DISPOSITION_ON_CLOSE; clearing one must not clear the other's
                 delete-pending state, and clearing both must admit a new writer before clean bytes are written
  notepad        real notepad.exe: type Text, Save As (Ctrl+Shift+S) to Path, then collect the text of any window Notepad shows
#>
param([string]$Control = 'C:\T5\control')
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public sealed class T5ProbeCreateResult {
    public bool Created;
    public string Steps;
    public IntPtr HeldHandle;
}
public static class T5Native {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(IntPtr h, byte[] buffer, int count, out int written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool DeleteFileW(string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(IntPtr h, int informationClass, byte[] information, uint size);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr SendMessageW(IntPtr hwnd, uint msg, IntPtr w, string l);
    [DllImport("user32.dll")] static extern bool PostMessageW(IntPtr hwnd, uint msg, IntPtr w, IntPtr l);
    // .NET Framework SendKeys uses a journal hook that Windows refuses without UI access: set the text and post the command.
    public static void SetText(IntPtr hwnd, string text) { SendMessageW(hwnd, 0x000C /* WM_SETTEXT */, IntPtr.Zero, text); }
    public static bool PostCommand(IntPtr hwnd, int id) { return PostMessageW(hwnd, 0x0111 /* WM_COMMAND */, new IntPtr(id), IntPtr.Zero); }
    public static bool PostButtonClick(IntPtr hwnd) { return PostMessageW(hwnd, 0x00F5 /* BM_CLICK */, IntPtr.Zero, IntPtr.Zero); }
    static int Err() { return Marshal.GetLastWin32Error(); }
    static bool Valid(IntPtr h) { return h != IntPtr.Zero && h != new IntPtr(-1); }
    static int CloseCode(IntPtr h) { return CloseHandle(h) ? 0 : Err(); }
    static int SetDispositionCode(IntPtr h, uint flags) {
        byte[] value = BitConverter.GetBytes(flags);
        return SetFileInformationByHandle(h, 21 /* FileDispositionInfoEx */, value, 4) ? 0 : Err();
    }
    static IntPtr OpenProbe(string path, uint access, uint share, uint disposition, uint flags) {
        return CreateFileW(path, access, share, IntPtr.Zero, disposition, flags, IntPtr.Zero);
    }
    static int WriteCode(IntPtr h, byte[] bytes) {
        int written;
        if (!WriteFile(h, bytes, bytes.Length, out written, IntPtr.Zero)) return Err();
        return written == bytes.Length ? 0 : 29 /* ERROR_WRITE_FAULT */;
    }
    // Split this native control replay's test-create from the later delete/save so the SYSTEM observer can sample in between.
    // The real Notepad UI sequence below is run separately and has no artificial pause.
    // Returns "step=code" pairs; 0 is success.
    public static T5ProbeCreateResult ProbeCreate(string path, bool deleteOnClose) {
        var log = new System.Text.StringBuilder();
        uint flags = deleteOnClose ? 0x04000000u /* FILE_FLAG_DELETE_ON_CLOSE */ : 0x80u;
        uint access = 0x40000000u | (deleteOnClose ? 0x00010000u /* DELETE */ : 0u);
        const uint shareAll = 0x00000001u | 0x00000002u | 0x00000004u;
        IntPtr h = OpenProbe(path, access, deleteOnClose ? shareAll : 0, 1 /* CREATE_NEW */, flags);
        log.Append("test-create=" + (h == new IntPtr(-1) ? Err() : 0));
        if (Valid(h) && deleteOnClose) {
            IntPtr probe = OpenProbe(path, 0x40000000u, shareAll, 3 /* OPEN_EXISTING */, 0x80);
            int pending = Valid(probe) ? 0 : Err();
            log.Append(" open-after-doc-flag=" + pending);
            if (Valid(probe)) log.Append(" unexpected-close=" + CloseCode(probe));
        }
        bool created = Valid(h);
        if (created) {
            int close = CloseCode(h);
            log.Append(" test-close=" + close);
            created = close == 0;
        }
        return new T5ProbeCreateResult { Created = created, Steps = log.ToString() };
    }
    public static string ProbeFinish(string path, byte[] bytes, bool explicitDelete, bool probeCreated) {
        var log = new System.Text.StringBuilder();
        // A failed CREATE_NEW did not create a dialog test file. Deleting here
        // would remove the user's existing public version before the actual save.
        if (explicitDelete) log.Append(probeCreated
            ? "test-delete=" + (DeleteFileW(path) ? 0 : Err())
            : "test-delete=skipped-create-failed");
        IntPtr h = OpenProbe(path, 0x40000000, 1 /* FILE_SHARE_READ */, 2 /* CREATE_ALWAYS */, 0x80);
        log.Append(" save-create=" + (h == new IntPtr(-1) ? Err() : 0));
        if (Valid(h)) {
            log.Append(" save-write=" + WriteCode(h, bytes));
            log.Append(" save-close=" + CloseCode(h));
        }
        return log.ToString();
    }
    // A live writable handle prevents SafeUpload from sealing the empty probe.
    // Sharing DELETE lets DeleteFileW run while that exact handle is still open.
    public static T5ProbeCreateResult ProbeHoldUntilDelete(string path) {
        const uint shareAll = 0x00000001u | 0x00000002u | 0x00000004u;
        IntPtr h = OpenProbe(path, 0x40000000u, shareAll, 1 /* CREATE_NEW */, 0x80u);
        bool created = Valid(h);
        return new T5ProbeCreateResult { Created = created, HeldHandle = h,
            Steps = "test-create=" + (created ? 0 : Err()) };
    }
    public static string ProbeCloseHeld(T5ProbeCreateResult probe) {
        if (probe == null || !Valid(probe.HeldHandle)) return "";
        IntPtr h = probe.HeldHandle;
        probe.HeldHandle = IntPtr.Zero;
        return "test-close=" + CloseCode(h);
    }
    public static string ProbeDeleteWhileHeldThenSave(string path, byte[] bytes, T5ProbeCreateResult probe) {
        if (probe == null) throw new ArgumentNullException("probe");
        var log = new System.Text.StringBuilder();
        bool held = probe.Created && Valid(probe.HeldHandle);
        log.Append(held ? "test-delete=" + (DeleteFileW(path) ? 0 : Err())
            : "test-delete=skipped-create-failed");
        string close = ProbeCloseHeld(probe);
        if (close.Length != 0) log.Append(" " + close);
        log.Append(" " + ProbeFinish(path, bytes, false, false).TrimStart());
        return log.ToString();
    }
    // Exercises the driver's per-handle ON_CLOSE bit, including the aggregate pending state across two handles.
    public static string ProbeOnCloseCancellation(string path, byte[] bytes) {
        const uint writeDelete = 0x40000000u | 0x00010000u;
        const uint shareAll = 0x00000001u | 0x00000002u | 0x00000004u;
        var log = new System.Text.StringBuilder();
        IntPtr first = OpenProbe(path, writeDelete, shareAll, 1 /* CREATE_NEW */, 0x80);
        log.Append("first-create=" + (Valid(first) ? 0 : Err()));
        if (!Valid(first)) return log.ToString();
        IntPtr second = IntPtr.Zero, unexpected = IntPtr.Zero, afterClear = IntPtr.Zero;
        try {
            second = OpenProbe(path, writeDelete, shareAll, 3 /* OPEN_EXISTING */, 0x80);
            log.Append(" second-open=" + (Valid(second) ? 0 : Err()));
            if (!Valid(second)) return log.ToString();
            log.Append(" first-on-close-delete=" + SetDispositionCode(first, 0x00000009u /* DELETE|ON_CLOSE */));
            unexpected = OpenProbe(path, 0x40000000u, shareAll, 3 /* OPEN_EXISTING */, 0x80);
            int firstPending = Valid(unexpected) ? 0 : Err();
            log.Append(" open-after-first-flag=" + firstPending);
            if (Valid(unexpected)) { log.Append(" unexpected-close=" + CloseCode(unexpected)); unexpected = IntPtr.Zero; }
            log.Append(" second-on-close-delete=" + SetDispositionCode(second, 0x00000009u));
            log.Append(" first-on-close-clear=" + SetDispositionCode(first, 0x00000008u /* ON_CLOSE, clear DELETE */));
            unexpected = OpenProbe(path, 0x40000000u, shareAll, 3 /* OPEN_EXISTING */, 0x80);
            int secondPending = Valid(unexpected) ? 0 : Err();
            log.Append(" open-after-first-clear=" + secondPending);
            if (Valid(unexpected)) { log.Append(" unexpected-close=" + CloseCode(unexpected)); unexpected = IntPtr.Zero; }
            log.Append(" second-on-close-clear=" + SetDispositionCode(second, 0x00000008u));
            afterClear = OpenProbe(path, 0x40000000u, shareAll, 3 /* OPEN_EXISTING */, 0x80);
            log.Append(" open-after-both-clear=" + (Valid(afterClear) ? 0 : Err()));
            if (Valid(afterClear)) {
                log.Append(" save-write=" + WriteCode(afterClear, bytes));
                log.Append(" save-close=" + CloseCode(afterClear)); afterClear = IntPtr.Zero;
            }
        } finally {
            if (Valid(unexpected)) log.Append(" unexpected-close=" + CloseCode(unexpected));
            if (Valid(afterClear)) log.Append(" save-close=" + CloseCode(afterClear));
            log.Append(" first-close=" + CloseCode(first));
            if (Valid(second)) log.Append(" second-close=" + CloseCode(second));
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
        # Notepad's multi-line edit control has no ValuePattern, and SendKeys needs UI access: set the edit control's text, then post
        # Notepad's Save As command (WM_COMMAND 4, which does not block on the modal dialog); the File menu through UI Automation is
        # the fallback when no dialog appears.
        if ($null -eq $edit) { throw 'Notepad edit control not found' }
        [T5Native]::SetText([IntPtr]$edit.Current.NativeWindowHandle, $Text)
        $findDialog = {
            foreach ($w in $root.FindAll([Windows.Automation.TreeScope]::Children, $byPid)) { if ($w.Current.Name -eq 'Save As') { return $w } }
            foreach ($w in $main.FindAll([Windows.Automation.TreeScope]::Children, [Windows.Automation.Condition]::TrueCondition)) { if ($w.Current.Name -eq 'Save As') { return $w } }
            $null
        }
        $obs.MenuPath = 'command'
        [void][T5Native]::PostCommand([IntPtr]$main.Current.NativeWindowHandle, 4)
        if ($null -eq (Wait-Element $findDialog 5)) {
            $obs.MenuPath = 'uia'
            $menuBar = $main.FindFirst([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::MenuBar)))
            $fileMenu = $menuBar.FindFirst([Windows.Automation.TreeScope]::Children, (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::NameProperty, 'File')))
            $fileMenu.GetCurrentPattern([Windows.Automation.ExpandCollapsePattern]::Pattern).Expand()
            $saveAs = Wait-Element { $root.FindFirst([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.AndCondition(
                (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)),
                (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::NameProperty, 'Save As...'))))) } 5
            if ($null -eq $saveAs) { throw 'Save As could not be opened' }
            $saveAs.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
        }
        $dialog = Wait-Element $findDialog
        if ($null -eq $dialog) { throw 'Save As dialog did not appear' }
        $nameBox = Wait-Element { $dialog.FindFirst([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.AndCondition(
            (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty, '1001')),
            (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Edit))))) }
        if ($null -eq $nameBox) { throw 'file name box not found' }
        $nameBox.SetFocus()
        $nameBox.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue($Path)
        $save = $dialog.FindFirst([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty, '1')))
        # Commit the filename edit's focus transition before invoking the dialog.
        # UIA ValuePattern alone can leave the common dialog's cached name stale.
        $save.SetFocus()
        $obs.FileNameBeforeSave = $nameBox.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).Current.Value
        $obs.SaveButtonName = $save.Current.Name
        $saveHandle = [IntPtr]$save.Current.NativeWindowHandle
        $dialogHandle = [IntPtr]$dialog.Current.NativeWindowHandle
        $obs.SaveButtonHandle = $saveHandle.ToInt64()
        $obs.SaveDialogHandle = $dialogHandle.ToInt64()
        if ($saveHandle -ne [IntPtr]::Zero) {
            $obs.SaveMethod = 'native-button'
            if (-not [T5Native]::PostButtonClick($saveHandle)) { throw ('Save button click could not be posted: ' + ($obs | ConvertTo-Json -Compress)) }
        } else {
            # DirectUI buttons need not own an HWND. Send this one IDOK command
            # to the exact Notepad dialog; no button action was posted above.
            $obs.SaveMethod = 'dialog-command'
            if ($dialogHandle -eq [IntPtr]::Zero -or -not [T5Native]::PostCommand($dialogHandle, 1)) { throw ('Save dialog command could not be posted: ' + ($obs | ConvertTo-Json -Compress)) }
        }
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
            'probe-delete-before-seal' {
                $created = [T5Native]::ProbeHoldUntilDelete($c.Path)
                $result.Steps = $created.Steps
                $result.ForcedOrder = 'DeleteBeforeSeal'
                try {
                    $ready = Join-Path $Control ('probe-ready-' + $c.N + '.json')
                    $go = Join-Path $Control ('probe-go-' + $c.N + '.json')
                    [IO.File]::WriteAllText(($ready + '.tmp'), (@{ N = $c.N; Op = $c.Op; ProbeCreated = $created.Created;
                        WritableProbeHandleHeld = $created.Created; ForcedOrder = $result.ForcedOrder } | ConvertTo-Json -Compress))
                    [IO.File]::Move(($ready + '.tmp'), $ready)
                    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 45 * [Diagnostics.Stopwatch]::Frequency
                    while (-not (Test-Path -LiteralPath $go)) { if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'probe observation gate timed out' }; Start-Sleep -Milliseconds 20 }
                    Remove-Item -LiteralPath $go -Force
                    $result.Steps = $created.Steps + ' ' + [T5Native]::ProbeDeleteWhileHeldThenSave($c.Path, $bytes, $created)
                } finally {
                    $close = [T5Native]::ProbeCloseHeld($created)
                    if ($close) { $result.Steps += ' ' + $close }
                }
            }
            'probe-delete-after-publication' {
                $created = [T5Native]::ProbeCreate($c.Path, $false)
                $result.Steps = $created.Steps
                $result.ForcedOrder = 'DeleteAfterObservedPublication'
                $ready = Join-Path $Control ('probe-ready-' + $c.N + '.json')
                $go = Join-Path $Control ('probe-go-' + $c.N + '.json')
                [IO.File]::WriteAllText(($ready + '.tmp'), (@{ N = $c.N; Op = $c.Op; ProbeCreated = $created.Created;
                    WritableProbeHandleHeld = $false; RequiredObservation = 'PublicEmptyFile'; ForcedOrder = $result.ForcedOrder } | ConvertTo-Json -Compress))
                [IO.File]::Move(($ready + '.tmp'), $ready)
                $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 45 * [Diagnostics.Stopwatch]::Frequency
                while (-not (Test-Path -LiteralPath $go)) { if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'published-probe observation gate timed out' }; Start-Sleep -Milliseconds 20 }
                Remove-Item -LiteralPath $go -Force
                $result.Steps = $created.Steps + ' ' + [T5Native]::ProbeFinish($c.Path, $bytes, $true, $created.Created)
            }
            'probe-delete' {
                $created = [T5Native]::ProbeCreate($c.Path, $false)
                $result.Steps = $created.Steps
                $ready = Join-Path $Control ('probe-ready-' + $c.N + '.json')
                $go = Join-Path $Control ('probe-go-' + $c.N + '.json')
                [IO.File]::WriteAllText(($ready + '.tmp'), (@{ N = $c.N; Op = $c.Op; ProbeCreated = $created.Created } | ConvertTo-Json -Compress))
                [IO.File]::Move(($ready + '.tmp'), $ready)
                $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 45 * [Diagnostics.Stopwatch]::Frequency
                while (-not (Test-Path -LiteralPath $go)) { if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'probe observation gate timed out' }; Start-Sleep -Milliseconds 20 }
                Remove-Item -LiteralPath $go -Force
                $result.Steps = $created.Steps + ' ' + [T5Native]::ProbeFinish($c.Path, $bytes, $true, $created.Created)
            }
            'probe-doc' {
                $created = [T5Native]::ProbeCreate($c.Path, $true)
                $result.Steps = $created.Steps
                $ready = Join-Path $Control ('probe-ready-' + $c.N + '.json')
                $go = Join-Path $Control ('probe-go-' + $c.N + '.json')
                [IO.File]::WriteAllText(($ready + '.tmp'), (@{ N = $c.N; Op = $c.Op; ProbeCreated = $created.Created } | ConvertTo-Json -Compress))
                [IO.File]::Move(($ready + '.tmp'), $ready)
                $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 45 * [Diagnostics.Stopwatch]::Frequency
                while (-not (Test-Path -LiteralPath $go)) { if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'probe observation gate timed out' }; Start-Sleep -Milliseconds 20 }
                Remove-Item -LiteralPath $go -Force
                $result.Steps = $created.Steps + ' ' + [T5Native]::ProbeFinish($c.Path, $bytes, $false, $created.Created)
            }
            'probe-onclose' { $result.Steps = [T5Native]::ProbeOnCloseCancellation($c.Path, $bytes) }
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
