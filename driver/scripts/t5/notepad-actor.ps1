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
param([string]$Control = 'C:\T5\control', [string]$ChildOperation, [string]$ChildPath, [string]$ChildResult)
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
    static int Err() { return Marshal.GetLastWin32Error(); }
    // A refused open's NTSTATUS: Win32 reports STATUS_DELETE_PENDING as 5, like any access denial (2026-10-11 native control).
    [DllImport("ntdll.dll")] static extern int RtlGetLastNtStatus();
    static T5Native() { RtlGetLastNtStatus(); } // bind the stub before any probe so the first read is not a loader status
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
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool MoveFileExW(string source, string target, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFilePointerEx(IntPtr h, long distance, out long position, uint method);
    public static string Save(string path, byte[] bytes, uint disposition, bool append) {
        IntPtr h = OpenProbe(path, 0xC0000000u, 7, disposition, 0x80);
        string log = "open=" + (Valid(h) ? 0 : Err());
        if (!Valid(h)) return log;
        try {
            if (append) { long pos; bool ok = SetFilePointerEx(h, 0, out pos, 2); log += " seek=" + (ok ? 0 : Err()); if (!ok) return log; }
            log += " write=" + WriteCode(h, bytes);
        } finally { log += " close=" + CloseCode(h); }
        return log;
    }
    public static int Delete(string path) { return DeleteFileW(path) ? 0 : Err(); }
    public static int Move(string source, string target) { return MoveFileExW(source, target, 2) ? 0 : Err(); }
    public static T5ProbeCreateResult Hold(string path, bool writer, byte[] bytes) {
        IntPtr h = OpenProbe(path, writer ? 0xC0000000u : 0x80000000u, writer ? 7u : 3u, writer ? 2u : 3u, 0x80);
        var r = new T5ProbeCreateResult {Created=Valid(h), HeldHandle=h, Steps="hold-open="+(Valid(h)?0:Err())};
        if (writer && Valid(h)) r.Steps += " hold-write=" + WriteCode(h, bytes);
        return r;
    }
    public static string CloseHeld(T5ProbeCreateResult r) {
        if (!Valid(r.HeldHandle)) return "hold-close=-1";
        int code = CloseCode(r.HeldHandle); r.HeldHandle=IntPtr.Zero; return "hold-close="+code;
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
            int pendingNt = Valid(probe) ? 0 : RtlGetLastNtStatus();
            int pending = Valid(probe) ? 0 : Err();
            log.Append(" open-after-doc-flag=" + pending + " open-after-doc-flag-nt=" + pendingNt);
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
            int firstPendingNt = Valid(unexpected) ? 0 : RtlGetLastNtStatus();
            int firstPending = Valid(unexpected) ? 0 : Err();
            log.Append(" open-after-first-flag=" + firstPending + " open-after-first-flag-nt=" + firstPendingNt);
            if (Valid(unexpected)) { log.Append(" unexpected-close=" + CloseCode(unexpected)); unexpected = IntPtr.Zero; }
            log.Append(" second-on-close-delete=" + SetDispositionCode(second, 0x00000009u));
            log.Append(" first-on-close-clear=" + SetDispositionCode(first, 0x00000008u /* ON_CLOSE, clear DELETE */));
            unexpected = OpenProbe(path, 0x40000000u, shareAll, 3 /* OPEN_EXISTING */, 0x80);
            int secondPendingNt = Valid(unexpected) ? 0 : RtlGetLastNtStatus();
            int secondPending = Valid(unexpected) ? 0 : Err();
            log.Append(" open-after-first-clear=" + secondPending + " open-after-first-clear-nt=" + secondPendingNt);
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
[ComImport, Guid("947AAB5F-0A5C-4C13-B4D6-4BF7836FC9F8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IT5FileOperation {
    [PreserveSig] int Advise(IntPtr sink, out uint cookie);
    [PreserveSig] int Unadvise(uint cookie);
    [PreserveSig] int SetOperationFlags(uint flags);
    [PreserveSig] int SetProgressMessage([MarshalAs(UnmanagedType.LPWStr)] string message);
    [PreserveSig] int SetProgressDialog(IntPtr dialog);
    [PreserveSig] int SetProperties(IntPtr properties);
    [PreserveSig] int SetOwnerWindow(IntPtr owner);
    [PreserveSig] int ApplyPropertiesToItem(IntPtr item);
    [PreserveSig] int ApplyPropertiesToItems(IntPtr items);
    [PreserveSig] int RenameItem(IntPtr item, [MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr sink);
    [PreserveSig] int RenameItems(IntPtr items, [MarshalAs(UnmanagedType.LPWStr)] string name);
    [PreserveSig] int MoveItem(IntPtr item, IntPtr folder, [MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr sink);
    [PreserveSig] int MoveItems(IntPtr items, IntPtr folder);
    [PreserveSig] int CopyItem(IntPtr item, IntPtr folder, [MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr sink);
    [PreserveSig] int CopyItems(IntPtr items, IntPtr folder);
    [PreserveSig] int DeleteItem(IntPtr item, IntPtr sink);
    [PreserveSig] int DeleteItems(IntPtr items);
    [PreserveSig] int NewItem(IntPtr folder, uint attributes, [MarshalAs(UnmanagedType.LPWStr)] string name, [MarshalAs(UnmanagedType.LPWStr)] string template, IntPtr sink);
    [PreserveSig] int PerformOperations();
    [PreserveSig] int GetAnyOperationsAborted([MarshalAs(UnmanagedType.Bool)] out bool aborted);
}
public static class T5Shell {
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, PreserveSig=true)]
    static extern int SHCreateItemFromParsingName(string path, IntPtr bindContext, ref Guid iid, out IntPtr item);
    public static string Delete(string path) {
        object com=null; IntPtr item=IntPtr.Zero;
        try {
            Guid iid=new Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE");
            int hr=SHCreateItemFromParsingName(path,IntPtr.Zero,ref iid,out item);
            string log="shell-item-hr="+hr;
            if(hr<0)return log;
            com=Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("3AD05575-8857-4850-9277-11B85BDB8E09")));
            IT5FileOperation op=(IT5FileOperation)com;
            hr=op.SetOperationFlags(0x0014u | 0x0400u); // FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI; no recycle flag.
            log+=" shell-flags-hr="+hr;if(hr<0)return log;
            hr=op.DeleteItem(item,IntPtr.Zero);log+=" shell-delete-item-hr="+hr;if(hr<0)return log;
            hr=op.PerformOperations();log+=" shell-perform-hr="+hr;
            bool aborted=true;int end=op.GetAnyOperationsAborted(out aborted);
            return log+" shell-abort-hr="+end+" shell-aborted="+(aborted?1:0);
        } finally {if(item!=IntPtr.Zero)Marshal.Release(item);if(com!=null)Marshal.FinalReleaseComObject(com);}
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
function Invoke-NotepadSaveAs([string]$Path, [string]$Text, $obs) {
    if($null -eq $obs){$obs = [ordered]@{}}
    $p = Start-Process notepad.exe -PassThru
    try {
        $root = [Windows.Automation.AutomationElement]::RootElement
        $byPid = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
        $main = Wait-Element { $root.FindFirst([Windows.Automation.TreeScope]::Children, $byPid) }
        $obs.WindowsAtOpen=@(Get-WindowTexts $p.Id)
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
        $obs.DialogBeforeName=@(Get-WindowTexts $p.Id)
        $nameBox = Wait-Element { $dialog.FindFirst([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.AndCondition(
            (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty, '1001')),
            (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Edit))))) }
        if ($null -eq $nameBox) { throw 'file name box not found' }
        $nameBox.SetFocus()
        $nameBox.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue($Path)
        # Folder items reuse AutomationId=1. Require the actual dialog button;
        # invoking a matching folder merely navigates and never saves anything.
        $saveButtons = $dialog.FindAll([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.AndCondition(
            (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty, '1')),
            (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Button)))))
        if ($saveButtons.Count -ne 1) { throw 'Expected exactly one Save button' }
        $save = $saveButtons[0]
        # Commit the filename edit's focus transition before invoking the dialog.
        # UIA ValuePattern alone can leave the common dialog's cached name stale.
        $save.SetFocus()
        $obs.FileNameBeforeSave = $nameBox.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).Current.Value
        $obs.SaveButtonName = $save.Current.Name
        $save.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
        Start-Sleep -Seconds 4
        $obs.WindowsAfterSave = @(Get-WindowTexts $p.Id)
        $obs.Title = (Get-Process -Id $p.Id).MainWindowTitle
    } finally {
        $obs.WindowsAtExit=@(Get-WindowTexts $p.Id)
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    $obs
}
function Invoke-T5Child([string]$Operation,[string]$Path) {
    $receipt=Join-Path $Control ('child-'+[guid]::NewGuid().ToString('N')+'.json')
    $args='-NoProfile -STA -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -ChildOperation '+$Operation+' -ChildPath "'+$Path+'" -ChildResult "'+$receipt+'"'
    $child=Start-Process powershell.exe -ArgumentList $args -PassThru
    try {
        if(-not $child.WaitForExit(30000)){throw 'Second-process native operation timed out'}
        if($child.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $receipt)){throw ('Second process failed; pid='+$child.Id+' exit='+$child.ExitCode)}
        return ([IO.File]::ReadAllText($receipt) | ConvertFrom-Json)
    } finally {if(-not $child.HasExited){Stop-Process -Id $child.Id -Force}}
}
function Invoke-T5ShellRename([string]$Path,[string]$OldPath,$Observation) {
    $shell=$null;$folder=$null;$item=$null
    try {
        $shell=New-Object -ComObject Shell.Application
        $folder=$shell.NameSpace((Split-Path -Parent $OldPath))
        if($null -eq $folder){throw 'Shell rename: namespace missing'}
        $item=$folder.ParseName((Split-Path -Leaf $OldPath))
        $Observation.Method='Shell.Application FolderItem.Name setter'
        $Observation.OldPath=$OldPath;$Observation.NewPath=$Path
        $Observation.WindowsBefore=@(Get-T5DesktopWindows)
        $Observation.ExplorerWindows=@($shell.Windows() | ForEach-Object {try{$_.LocationName}catch{'unavailable'}})
        if($null -eq $item){throw 'Shell rename: old item missing'}
        $Observation.ItemBefore=[string]$item.Name;$Observation.ItemPathBefore=[string]$item.Path
        # Type what a user types in Explorer's rename box: with known extensions hidden (the default) the box shows and
        # takes the base name, and a full name there becomes '<name>.txt.txt' (m2t5ord8).
        $hidden=([string]$item.Name -ceq [IO.Path]::GetFileNameWithoutExtension($OldPath))
        $Observation.ExtensionHidden=$hidden
        $item.Name=$(if($hidden){[IO.Path]::GetFileNameWithoutExtension($Path)}else{Split-Path -Leaf $Path})
        $Observation.ItemAfter=[string]$item.Name;$Observation.ItemPathAfter=[string]$item.Path
        $Observation.WindowsAfter=@(Get-T5DesktopWindows)
        # The setter reports no status; the rename succeeded only if exactly the new name now exists and the old one is gone.
        return $(if((Test-Path -LiteralPath $Path) -and -not (Test-Path -LiteralPath $OldPath)){0}else{2})
    } finally {foreach($com in @($item,$folder,$shell)){if($null -ne $com){[void][Runtime.InteropServices.Marshal]::ReleaseComObject($com)}}}
}
function Invoke-T5ShellDelete([string]$Path,$Observation) {
    $Observation.Method='IFileOperation::DeleteItem; FOF_SILENT|FOF_NOCONFIRMATION|FOF_NOERRORUI (0x414)'
    $Observation.Path=$Path
    $Observation.WindowsBefore=@(Get-T5DesktopWindows)
    try {return [T5Shell]::Delete($Path)}finally{$Observation.WindowsAfter=@(Get-T5DesktopWindows)}
}
function Get-T5DesktopWindows {
    $root=[Windows.Automation.AutomationElement]::RootElement
    foreach($window in $root.FindAll([Windows.Automation.TreeScope]::Children,[Windows.Automation.Condition]::TrueCondition)){
        try{
            [pscustomobject]@{Title=$window.Current.Name;Pid=$window.Current.ProcessId;Class=$window.Current.ClassName;Text=@($window.FindAll([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty,[Windows.Automation.ControlType]::Text))) | ForEach-Object {$_.Current.Name})}
        }catch{[pscustomobject]@{Error=$_.Exception.Message}}
    }
}
if($ChildOperation) {
    $receipt=[ordered]@{Pid=$PID;Sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Operation=$ChildOperation;Path=$ChildPath;Error=$null}
    try {
        if($ChildOperation -eq 'delete'){$receipt.Code=[T5Native]::Delete($ChildPath)}
        elseif($ChildOperation -eq 'read-empty'){
            $stream=[IO.File]::Open($ChildPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]'ReadWrite, Delete')
            try {$receipt.Length=$stream.Length;$receipt.FirstByte=$stream.ReadByte();$receipt.Code=0;$receipt.ReadWrite=$true}finally{$stream.Dispose()}
        }else{throw ('Unknown child operation '+$ChildOperation)}
    }catch{
        # PowerShell wraps .NET call failures; report the underlying Win32 code (m2t5ord8 showed 0x1501 for a missing file).
        $failure=$_.Exception; while($failure -is [Management.Automation.MethodInvocationException] -and $null -ne $failure.InnerException){$failure=$failure.InnerException}
        $receipt.Error=$_.Exception.ToString();$receipt.Code=$failure.HResult -band 0xffff
    }
    [IO.File]::WriteAllText($ChildResult,($receipt | ConvertTo-Json -Depth 8));exit 0
}
$script:workflowHeld=$null
try {
'ACTOR_STARTED pid=' + $PID + ' user=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name + ' session=' + [Diagnostics.Process]::GetCurrentProcess().SessionId |
    Set-Content -LiteralPath (Join-Path $Control 'actor-started.txt')
for (;;) {
    $command = Get-ChildItem -LiteralPath $Control -Filter 'cmd-*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { Start-Sleep -Milliseconds 20; continue }
    $c = [IO.File]::ReadAllText($command.FullName) | ConvertFrom-Json
    if ($c.Op -eq 'stop') { Remove-Item -LiteralPath $command.FullName -Force; break }
    $result = [ordered]@{ N = $c.N; Op = $c.Op; Path=$c.Path; ActorPid=$PID; ActorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; SessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId }
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
            {$_ -cin @('inflight-before','inflight-after')} {
                # D2 refuses public delete while the newer private writer is open;
                # after a Released/raw observation D6 has already committed: delete wins.
                $created=[T5Native]::Hold($c.Path,$true,$bytes);$result.Steps=$created.Steps
                try {
                    if($c.Op -eq 'inflight-after'){$result.Steps+=' '+[T5Native]::CloseHeld($created)}
                    $ready=Join-Path $Control ('probe-ready-'+$c.N+'.json');$go=Join-Path $Control ('probe-go-'+$c.N+'.json')
                    [IO.File]::WriteAllText(($ready+'.tmp'),(@{N=$c.N;Op=$c.Op;ProbeCreated=$created.Created;WritableProbeHandleHeld=($c.Op -eq 'inflight-before');ActorPid=$PID} | ConvertTo-Json -Compress))
                    [IO.File]::Move(($ready+'.tmp'),$ready)
                    $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+45*[Diagnostics.Stopwatch]::Frequency
                    while(-not (Test-Path -LiteralPath $go)){if([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline){throw 'In-flight public-delete observation gate timed out'};Start-Sleep -Milliseconds 20}
                    Remove-Item -LiteralPath $go -Force
                    $result.Child=Invoke-T5Child 'delete' $c.Path;$result.Steps+=' delete='+$result.Child.Code
                } finally {if($created.HeldHandle -ne [IntPtr]::Zero -and $created.Created){$result.Steps+=' '+[T5Native]::CloseHeld($created)}}
            }
            'native-create' { $result.Steps=[T5Native]::Save($c.Path,$bytes,1,$false) }
            'native-save' { $result.Steps=[T5Native]::Save($c.Path,$bytes,2,$false) }
            'native-clear' { $result.Method='Native TRUNCATE_EXISTING + close (UI-independent equivalent)'; $result.Steps=[T5Native]::Save($c.Path,$bytes,5,$false) }
            'native-append' { $result.Method='Native OPEN_EXISTING + append (existing readable seeded edit)'; $result.Steps=[T5Native]::Save($c.Path,$bytes,3,$true) }
            'native-delete' { $result.Child=Invoke-T5Child 'delete' $c.Path;$result.Steps='delete='+$result.Child.Code }
            'second-open-empty' { $result.Child=Invoke-T5Child 'read-empty' $c.Path;$result.Steps='second-open='+$result.Child.Code }
            'hold-no-share-delete' { if($script:workflowHeld){throw 'A workflow handle is already held'};$script:workflowHeld=[T5Native]::Hold($c.Path,$false,$bytes);$result.Steps=$script:workflowHeld.Steps }
            'close-held' { if(-not $script:workflowHeld){throw 'No workflow handle held'};$result.Steps=[T5Native]::CloseHeld($script:workflowHeld);$script:workflowHeld=$null }
            'empty-copy' {
                $source=Join-Path $env:TEMP ('t5-copy-'+$c.N+'.txt');[IO.File]::WriteAllBytes($source,(New-Object byte[] 0))
                try {Copy-Item -LiteralPath $source -Destination $c.Path -ErrorAction Stop;$result.Steps='copy=0';$result.SourceLength=(Get-Item -LiteralPath $source).Length} finally {Remove-Item -LiteralPath $source -Force}
            }
            'empty-move' {
                $source=Join-Path $env:TEMP ('t5-move-'+$c.N+'.txt');[IO.File]::WriteAllBytes($source,(New-Object byte[] 0))
                $result.Method='MoveFileExW(MOVEFILE_COPY_ALLOWED)';$result.Steps='move='+[T5Native]::Move($source,$c.Path)
                $result.Source=$source;$result.SourceGone=-not (Test-Path -LiteralPath $source)
            }
            'shell-rename-empty' { $result.Ui=[ordered]@{};$renameCode=Invoke-T5ShellRename $c.Path ([string]$c.Text) $result.Ui;$result.Steps='shell-rename='+$renameCode }
            'remove-item' {Remove-Item -LiteralPath $c.Path -ErrorAction Stop;$result.Steps='remove=0'}
            'shell-delete' {$result.Ui=[ordered]@{};$result.Steps=Invoke-T5ShellDelete $c.Path $result.Ui}
            'probe-onclose'  { $result.Steps = [T5Native]::ProbeOnCloseCancellation($c.Path, $bytes) }
            'notepad' { $result.Ui=[ordered]@{};Invoke-NotepadSaveAs $c.Path ([string]$c.Text) $result.Ui | Out-Null }
            default { throw ('unknown op ' + $c.Op) }
        }
    } catch { $result.Error = $_.Exception.ToString(); $result.FailureWindows = @(Get-T5DesktopWindows) }
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
finally {if($script:workflowHeld){[void][T5Native]::CloseHeld($script:workflowHeld)}}
