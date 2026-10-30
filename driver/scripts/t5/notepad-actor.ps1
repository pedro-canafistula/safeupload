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
public sealed class T5ReadResult {
    public int Code;
    public string Steps;
    public long Length;
    public string Sha256;
}
public static class T5Native {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(IntPtr h, byte[] buffer, int count, out int written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr h, byte[] buffer, int count, out int read, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool DeleteFileW(string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(IntPtr h, int informationClass, byte[] information, uint size);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr SendMessageW(IntPtr hwnd, uint msg, IntPtr w, string l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr SendMessageW(IntPtr hwnd, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] static extern bool PostMessageW(IntPtr hwnd, uint msg, IntPtr w, IntPtr l);
    // .NET Framework SendKeys uses a journal hook that Windows refuses without UI access: set the text and post the command.
    public static void SetText(IntPtr hwnd, string text) { SendMessageW(hwnd, 0x000C /* WM_SETTEXT */, IntPtr.Zero, text); }
    public static void ReplaceText(IntPtr hwnd, string text) {
        // Unlike WM_SETTEXT on a multiline Edit, EM_REPLACESEL sends edit-change
        // notifications so Notepad marks this existing document modified.
        SendMessageW(hwnd, 0x00B1 /* EM_SETSEL */, IntPtr.Zero, new IntPtr(-1));
        SendMessageW(hwnd, 0x00C2 /* EM_REPLACESEL */, new IntPtr(1), text);
    }
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
    public static T5ReadResult Read(string path) {
        var r = new T5ReadResult();
        IntPtr h = OpenProbe(path, 0x80000000u /* GENERIC_READ */, 7 /* share R/W/D */, 3, 0x80);
        r.Code = Valid(h) ? 0 : Err(); r.Steps = "read-open=" + r.Code;
        if (!Valid(h)) return r; // denied control exports no bytes or digest
        try {
            using (var hash = System.Security.Cryptography.SHA256.Create()) {
                byte[] buffer = new byte[65536]; int count;
                for (;;) {
                    if (!ReadFile(h, buffer, buffer.Length, out count, IntPtr.Zero)) {
                        r.Code = Err(); r.Steps += " read=" + r.Code; return r;
                    }
                    if (count == 0) break;
                    r.Length += count; hash.TransformBlock(buffer, 0, count, buffer, 0);
                }
                hash.TransformFinalBlock(new byte[0], 0, 0);
                r.Sha256 = BitConverter.ToString(hash.Hash).Replace("-", ""); r.Steps += " read=0";
            }
        } finally {
            int close = CloseCode(h); r.Steps += " read-close=" + close;
            if (close != 0) r.Code = close;
        }
        return r;
    }
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
    public static string Transfer(string source, string target, bool move) {
        object com=null; IntPtr item=IntPtr.Zero, folder=IntPtr.Zero;
        try {
            Guid iid=new Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE");
            int hr=SHCreateItemFromParsingName(source,IntPtr.Zero,ref iid,out item);
            string log="shell-item-hr="+hr;if(hr<0)return log;
            hr=SHCreateItemFromParsingName(System.IO.Path.GetDirectoryName(target),IntPtr.Zero,ref iid,out folder);
            log+=" shell-folder-hr="+hr;if(hr<0)return log;
            com=Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("3AD05575-8857-4850-9277-11B85BDB8E09")));
            IT5FileOperation op=(IT5FileOperation)com;
            hr=op.SetOperationFlags(0x0014u | 0x0400u); // same flags as Delete
            log+=" shell-flags-hr="+hr;if(hr<0)return log;
            string name=System.IO.Path.GetFileName(target);
            hr=move ? op.MoveItem(item,folder,name,IntPtr.Zero) : op.CopyItem(item,folder,name,IntPtr.Zero);
            log+=" shell-transfer-item-hr="+hr;if(hr<0)return log;
            hr=op.PerformOperations();log+=" shell-perform-hr="+hr;
            bool aborted=true;int end=op.GetAnyOperationsAborted(out aborted);
            return log+" shell-abort-hr="+end+" shell-aborted="+(aborted?1:0);
        } finally {
            if(folder!=IntPtr.Zero)Marshal.Release(folder);
            if(item!=IntPtr.Zero)Marshal.Release(item);
            if(com!=null)Marshal.FinalReleaseComObject(com);
        }
    }
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
    # m2t5ord16: a window that closes while it is being read (Notepad's Save As dialog right after the save) raises
    # ElementNotAvailableException; that window is simply gone, so it is skipped, and the enumeration of the rest goes on.
    foreach ($w in $root.FindAll([Windows.Automation.TreeScope]::Children, $cond)) {
        try {
            $parts = @($w.Current.Name)
            foreach ($e in $w.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)) {
                try { if ($e.Current.ControlType -eq [Windows.Automation.ControlType]::Text -and $e.Current.Name) { $parts += $e.Current.Name } }
                catch [Windows.Automation.ElementNotAvailableException] { }
            }
            $texts += ($parts -join ' | ')
        } catch [Windows.Automation.ElementNotAvailableException] { }
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
# m2t5ord14: another process briefly held the coordinator's freshly moved cmd-3.json open and a plain ReadAllText died with a
# sharing violation, which ended the actor and hung the row. Retry only sharing/lock violations, for a bounded time.
function Invoke-NotepadEdit([string]$Path,[string]$Text,$obs) {
    $p=Start-Process notepad.exe -ArgumentList ('"'+$Path+'"') -PassThru
    try {
        $root=[Windows.Automation.AutomationElement]::RootElement
        $byPid=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty,$p.Id)
        $main=Wait-Element {$root.FindFirst([Windows.Automation.TreeScope]::Children,$byPid)}
        $obs.WindowsAtOpen=@(Get-WindowTexts $p.Id)
        if($null -eq $main){throw 'Notepad existing-file window did not appear'}
        # Notepad titles the window with the shell display name, which hides known extensions ("notepad-edit - Notepad").
        $titles=@(([IO.Path]::GetFileName($Path)+' - Notepad'),([IO.Path]::GetFileNameWithoutExtension($Path)+' - Notepad'))
        $opened=Wait-Element {$t=(Get-Process -Id $p.Id).MainWindowTitle;if(@($titles | Where-Object {$_ -ieq $t}).Count -gt 0){return $true};$null}
        $obs.OpenedExistingTitle=(Get-Process -Id $p.Id).MainWindowTitle
        if($opened -ne $true){throw 'Notepad did not open the requested existing file'}
        $edit=$main.FindFirst([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ClassNameProperty,'Edit')))
        if($null -eq $edit){throw 'Notepad existing-file edit control not found'}
        [T5Native]::ReplaceText([IntPtr]$edit.Current.NativeWindowHandle,$Text)
        $dirty=Wait-Element {if((Get-Process -Id $p.Id).MainWindowTitle.StartsWith('*')){return $true};$null} 5
        $obs.DirtyObserved=($dirty -eq $true)
        if(-not $obs.DirtyObserved){throw 'Notepad never displayed the modified title'}
        $obs.MenuPath='command-save'
        [void][T5Native]::PostCommand([IntPtr]$main.Current.NativeWindowHandle,3)
        $saved=Wait-Element {if(-not (Get-Process -Id $p.Id).MainWindowTitle.StartsWith('*')){return $true};$null} 5
        if($saved -ne $true){
            $file=$main.FindFirst([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::NameProperty,'File')))
            if($null -eq $file){throw 'Notepad File menu unavailable for Save fallback'}
            $file.GetCurrentPattern([Windows.Automation.ExpandCollapsePattern]::Pattern).Expand()
            $save=Wait-Element {$root.FindFirst([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.AndCondition(
                (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty,$p.Id)),
                (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::NameProperty,'Save')))))}
            if($null -eq $save){throw 'Notepad File > Save unavailable'}
            $obs.MenuPath='File > Save'
            $save.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
            $saved=Wait-Element {if(-not (Get-Process -Id $p.Id).MainWindowTitle.StartsWith('*')){return $true};$null}
        }
        $obs.WindowsAfterSave=@(Get-WindowTexts $p.Id)
        $obs.Title=(Get-Process -Id $p.Id).MainWindowTitle
        $obs.SaveCompleted=($saved -eq $true -and -not $obs.Title.StartsWith('*') -and $obs.WindowsAfterSave.Count -eq 1)
        if(-not $obs.SaveCompleted){throw ('Notepad Save failed: '+($obs.WindowsAfterSave -join ' | '))}
        [void]$p.CloseMainWindow()
        $obs.NoPromptClosed=$p.WaitForExit(10000)
        if(-not $obs.NoPromptClosed){throw ('Notepad close showed a prompt: '+((Get-WindowTexts $p.Id) -join ' | '))}
    } finally {
        $obs.WindowsAtExit=@(Get-WindowTexts $p.Id)
        if(-not $p.HasExited){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}
    }
}
function Set-T5ExcelCell($Range,$Value) {
    # mvpBWdiag7: assigning an Int32 to Value2 fails in the COM binder (InvalidCastException to String). A numeric
    # formula stores the same number; Value2 reads it back as 1/2.
    if($Value -is [int]){$Range.Formula=[string]$Value}else{$Range.Value2=$Value}
}
function Invoke-T5Excel([string]$Op,[string]$Path,[string]$Kind,$obs) {
    $x=$null;$wb=$null;$excelProcess=$null
    # Join-Path returns a PSObject that can spin inside COM SaveAs. Pass a CLR string.
    [string]$target=[IO.Path]::Combine([IO.Path]::GetDirectoryName($Path),[IO.Path]::GetFileName($Path))
    $inplace=$Kind -ceq 'ExcelInPlaceApprove';$cpf=$Kind -ceq 'ExcelCpfHandBack'
    $priorA=if($inplace){1}else{'T5 '+$Kind}
    $finalA=if($inplace){2}elseif($cpf){'529.982.247-25'}else{$priorA}
    try {
        $x=New-Object -ComObject Excel.Application
        $x.Visible=$true;$x.DisplayAlerts=$false
        [uint32]$excelPid=0
        [void][T5Native]::GetWindowThreadProcessId([IntPtr]$x.Hwnd,[ref]$excelPid)
        if($excelPid -le 0){throw 'Excel process identity missing'}
        $excelProcess=Get-Process -Id $excelPid -ErrorAction Stop
        $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$excelPid) -ErrorAction Stop
        $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
        $obs.ExcelPid=$excelPid;$obs.ExcelSid=$owner.Sid;$obs.SessionId=$excelProcess.SessionId
        $obs.ExcelCreationTime=$excelProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
        $obs.Version=[string]$x.Version;$obs.Build=[string]$x.Build;$obs.Action=$Op
        if($owner.ReturnValue -ne 0 -or $owner.Sid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
            $excelProcess.SessionId -ne (Get-Process -Id $PID).SessionId -or $excelProcess.SessionId -le 0){throw 'Excel is not the interactive standard actor'}
        if($Op -cin @('excel-saveas','excel-seed','excel-cpf')) {
            $wb=$x.Workbooks.Add()
            Set-T5ExcelCell $wb.Worksheets.Item(1).Range('A1') $(if($cpf){$finalA}else{$priorA})
            $wb.Worksheets.Item(1).Range('B1').Formula='=1+2'
            $wb.Worksheets.Item(1).Range('C1').Value2=$(if($cpf){'blocked'}else{'prior'})
            $x.Calculate()
            $wb.SaveAs($target,51)
        } else {
            $wb=$x.Workbooks.Open($target)
            if($Op -ceq 'excel-edit') {
                if($wb.Worksheets.Item(1).Range('A1').Value2 -ne $priorA -or $wb.Worksheets.Item(1).Range('B1').Value2 -ne 3 -or
                    $wb.Worksheets.Item(1).Range('C1').Value2 -cne 'prior'){throw 'Excel reopen did not show the published prior cells'}
                $obs.PriorCellsVerified=$true
                Set-T5ExcelCell $wb.Worksheets.Item(1).Range('A1') $finalA
                $wb.Worksheets.Item(1).Range('C1').Value2='edit'
                $wb.Save()
            }
        }
        $obs.A1=$wb.Worksheets.Item(1).Range('A1').Value2
        $obs.B1=$wb.Worksheets.Item(1).Range('B1').Value2
        $obs.C1=$wb.Worksheets.Item(1).Range('C1').Value2
        $obs.Saved=[bool]$wb.Saved;$obs.ReadOnly=[bool]$wb.ReadOnly
        $obs.ProtectedViewCount=$x.ProtectedViewWindows.Count;$obs.Ready=[bool]$x.Ready
        $obs.Windows=@(Get-WindowTexts $excelPid)
        # The CPF hand-back copy grants the user read only (StagedHandbackCopier), so its reopen is read-only; after the
        # blocked save itself the workbook may be either. Every clean save, edit and reopen stays writable.
        $readOnlyOk=if($cpf -and $Op -ceq 'excel-read'){$obs.ReadOnly}elseif($cpf){$true}else{-not $obs.ReadOnly}
        if(-not $obs.Saved -or -not $readOnlyOk -or -not $obs.Ready -or $obs.ProtectedViewCount -ne 0 -or $obs.Windows.Count -gt 1){throw 'Excel reported unsaved, read-only, not Ready, Protected View or a dialog'}
        if($Op -ceq 'excel-read' -and ($obs.A1 -ne $finalA -or $obs.B1 -ne 3 -or $obs.C1 -cne $(if($cpf){'blocked'}else{'edit'}))){throw 'Excel final reopen cell values differ'}
        $wb.Close($false);$obs.Closed=$true
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($wb);$wb=$null
        $x.Quit();$obs.Quit=$true
    } finally {
        if($wb){try{$wb.Close($false)}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($wb)}}
        if($x){
            if(-not $obs.Quit){try{$x.Quit()}catch{$obs.QuitError=$_.Exception.Message}}
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($x)
        }
        [GC]::Collect();[GC]::WaitForPendingFinalizers()
        $obs.ExcelExited=($null -ne $excelProcess -and $excelProcess.WaitForExit(10000))
        if($excelProcess){$obs.WindowsAtExit=@(Get-WindowTexts $excelProcess.Id)}
    }
    if(-not $obs.ExcelExited){throw 'Excel process remained after Close/Quit'}
}
function Start-T5WordAlertMonitor([int]$WordPid,[string]$Directory) {
    [void][IO.Directory]::CreateDirectory($Directory)
    $stem=[guid]::NewGuid().ToString('N')
    $file=[IO.Path]::Combine($Directory,$stem+'.json');$stop=[IO.Path]::Combine($Directory,$stem+'.stop')
    $textFunction=(Get-Item Function:\Get-WindowTexts).ScriptBlock.ToString()
    $job=Start-Job -ArgumentList $WordPid,$file,$stop,$textFunction -ScriptBlock {
        param($WordPid,$File,$Stop,$TextFunction)
        $ErrorActionPreference='Stop'
        $record=[ordered]@{WordPid=$WordPid;MonitorPid=$PID;MonitorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
            SessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId;WordCreationTime=$null;SawWordWindow=$false;
            Ready=$false;Stopped=$false;TimedOut=$false;PollCount=0;AlertTexts=@();Error=$null}
        function Write-Monitor {
            # The actor reads this file while the monitor runs; a replace that meets its open handle fails with a
            # sharing violation (mvpBWdiag8). Retry briefly instead of ending the monitor.
            [IO.File]::WriteAllText(($File+'.tmp'),($record | ConvertTo-Json -Depth 6 -Compress))
            for($try=0;;$try++){
                try{
                    if([IO.File]::Exists($File)){[IO.File]::Replace(($File+'.tmp'),$File,$null)}else{[IO.File]::Move(($File+'.tmp'),$File)}
                    break
                }catch [IO.IOException]{if($try -ge 100){throw};Start-Sleep -Milliseconds 10}
            }
        }
        try {
            Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
            $record.WordCreationTime=(Get-Process -Id $WordPid -ErrorAction Stop).StartTime.ToUniversalTime().ToFileTimeUtc()
            Set-Item Function:\Get-WindowTexts -Value ([scriptblock]::Create($TextFunction))
            $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+210*[Diagnostics.Stopwatch]::Frequency
            $lastAlerts=0
            do {
                $byPid=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty,([int]$WordPid))
                $root=[Windows.Automation.AutomationElement]::RootElement
                $top=@($root.FindAll([Windows.Automation.TreeScope]::Children,$byPid))
                if($top.Count -gt 0){$record.SawWordWindow=$true}
                $condition=New-Object Windows.Automation.AndCondition($byPid,(New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty,[Windows.Automation.ControlType]::Window)))
                $windows=@($root.FindAll([Windows.Automation.TreeScope]::Descendants,$condition))
                $alert=$false # only dialog-class or modal windows; Word's border/splash windows are not alerts
                foreach($window in $windows){
                    try {
                        $pattern=$null
                        if($window.Current.ClassName -match '#32770|bosa_sdm|NUIDialog' -or
                            ($window.TryGetCurrentPattern([Windows.Automation.WindowPattern]::Pattern,[ref]$pattern) -and $pattern.Current.IsModal)){$alert=$true}
                    }catch [Windows.Automation.ElementNotAvailableException]{}
                }
                if($alert){$record.AlertTexts=@(@($record.AlertTexts)+@(Get-WindowTexts ([int]$WordPid)) | Sort-Object -Unique)}
                if($record.AlertTexts.Count -gt 32){throw 'Word alert evidence exceeded 32 distinct windows'}
                $record.PollCount++
                $changed=(-not $record.Ready) -or ($record.AlertTexts.Count -ne $lastAlerts)
                $record.Ready=$true;$lastAlerts=$record.AlertTexts.Count
                if($changed){Write-Monitor} # the final state is written once more in finally
                if([IO.File]::Exists($Stop)){$record.Stopped=$true;break}
                Start-Sleep -Milliseconds 100
            }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
            if(-not $record.Stopped){$record.TimedOut=$true}
        }catch{$record.Error=$_.Exception.ToString()}
        finally{Write-Monitor}
    }
    return [pscustomobject]@{Job=$job;File=$file;Stop=$stop}
}
function Invoke-T5Word([string]$Op,[string]$Path,[string]$Kind,$obs) {
    $w=$null;$doc=$null;$wordProcess=$null;$monitor=$null
    [string]$target=[IO.Path]::Combine([IO.Path]::GetDirectoryName($Path),[IO.Path]::GetFileName($Path))
    $prior='T5 '+$Kind+' published clean prior'
    $newer='T5 '+$Kind+' inspected newer save'
    $cpf=$Kind -ceq 'WordCpfHandBack'
    $expected=if($cpf){'T5 Word CPF: 529.982.247-25'}elseif($Op -cin @('word-edit','word-overwrite','word-read')){$newer}else{$prior}
    $obs.AlertTexts=@()
    try {
        $w=New-Object -ComObject Word.Application
        $w.Visible=$true;$w.DisplayAlerts=0
        # Word exposes HWND on Window, unlike Excel's Application.Hwnd.
        # An unsaved blank document binds the actual COM instance before any protected open/save.
        $doc=$w.Documents.Add()
        [uint32]$wordPid=0
        [void][T5Native]::GetWindowThreadProcessId([IntPtr]$w.ActiveWindow.Hwnd,[ref]$wordPid)
        if($wordPid -le 0){throw 'Word process identity missing'}
        $wordProcess=Get-Process -Id $wordPid -ErrorAction Stop
        $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$wordPid) -ErrorAction Stop
        $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
        $obs.WordPid=$wordPid;$obs.WordSid=$owner.Sid;$obs.SessionId=$wordProcess.SessionId
        $obs.WordCreationTime=$wordProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
        $obs.Version=[string]$w.Version;$obs.Build=[string]$w.Build;$obs.Action=$Op
        if($owner.ReturnValue -ne 0 -or $owner.Sid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
            $wordProcess.SessionId -ne (Get-Process -Id $PID).SessionId -or $wordProcess.SessionId -le 0){throw 'Word is not the interactive standard actor'}
        $monitor=Start-T5WordAlertMonitor $wordPid ([IO.Path]::Combine($Control,'word-alerts'))
        $ready=Wait-Element {
            if([IO.File]::Exists($monitor.File)){
                $state=(Read-ActorControlText $monitor.File) | ConvertFrom-Json
                if($state.Error -or $state.TimedOut){throw 'Word alert monitor failed to start'}
                if($state.Ready -eq $true){return $state}
            };$null
        } 15
        if($null -eq $ready -or $ready.MonitorSid -cne $obs.WordSid -or $ready.SessionId -ne $obs.SessionId){throw 'Word alert monitor is not in the interactive actor session'}
        if($Op -ceq 'word-overwrite'){
            $obs.OverwritePriorRead=[T5Native]::Read($target)
            if($obs.OverwritePriorRead.Code -ne 0 -or $obs.OverwritePriorRead.Length -le 0){throw 'Word overwrite lacks the published prior'}
            $obs.OverwriteRequested=$true
        }
        if($Op -cin @('word-saveas','word-seed','word-cpf','word-overwrite')){
            $doc.Content.Text=$expected
            $doc.SaveAs2($target,16) # wdFormatDocumentDefault: .docx, including replacement of the published prior.
        }else{
            $doc.Close(0);[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($doc);$doc=$null
            $doc=$w.Documents.Open($target,$false,$false)
            if($doc.ReadOnly -and -not $cpf){throw 'Word reopened the document read-only'}
            if($Op -ceq 'word-edit'){
                if(([string]$doc.Content.Text).TrimEnd([char[]]@(13,10)) -cne $prior){throw 'Word reopen did not show the published prior text'}
                $obs.PriorTextVerified=$true
                $doc.Content.Text=$newer;$doc.Save()
            }
        }
        # Observe completion without another mutation or changes to Word's save options.
        $ready=Wait-Element {if($w.BackgroundSavingStatus -eq 0){return $true};$null} 30
        $obs.Ready=($ready -eq $true)
        $obs.Text=([string]$doc.Content.Text).TrimEnd([char[]]@(13,10))
        $obs.Saved=[bool]$doc.Saved;$obs.ReadOnly=[bool]$doc.ReadOnly;$obs.ProtectedViewCount=$w.ProtectedViewWindows.Count
        $obs.Windows=@(Get-WindowTexts $wordPid)
        # Same read-only rule as Excel: the CPF hand-back copy is read-only by design; the blocked save may be either.
        $readOnlyOk=if($cpf -and $Op -ceq 'word-read'){$obs.ReadOnly}elseif($cpf){$true}else{-not $obs.ReadOnly}
        if($obs.Text -cne $expected -or -not $obs.Ready -or -not $obs.Saved -or -not $readOnlyOk -or
            $obs.ProtectedViewCount -ne 0 -or $obs.Windows.Count -gt 1){throw ('Word save/reopen failed: '+($obs.Windows -join ' | '))}
        $doc.Close(0);$obs.Closed=$true
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($doc);$doc=$null
        $w.Quit();$obs.Quit=$true # Quit's optional arguments are by-reference; none needed with the document closed
    }catch{
        $obs.ErrorText=$_.Exception.ToString()
        if($wordProcess){$obs.WindowsOnFailure=@(Get-WindowTexts $wordProcess.Id)}
        throw
    }finally{
        if($doc){try{$doc.Close(0)}catch{$obs.QuitError=$_.Exception.Message}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($doc)}}
        if($w){
            if(-not $obs.Quit){try{$w.Quit()}catch{$obs.QuitError=$_.Exception.Message}}
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($w)
        }
        [GC]::Collect();[GC]::WaitForPendingFinalizers()
        $obs.WordExited=($null -ne $wordProcess -and $wordProcess.WaitForExit(10000))
        if($wordProcess){$obs.WindowsAtExit=@(Get-WindowTexts $wordProcess.Id)}
        if($monitor){
            [IO.File]::WriteAllText($monitor.Stop,'stop')
            try{
                [void]($monitor.Job | Wait-Job -Timeout 5)
                if($monitor.Job.State -cne 'Completed'){throw 'Word alert monitor did not finish'}
                $monitor.Job | Receive-Job -ErrorAction Stop | Out-Null
                $obs.AlertMonitor=(Read-ActorControlText $monitor.File) | ConvertFrom-Json
                $obs.AlertMonitor | Add-Member -NotePropertyName Artifact -NotePropertyValue $monitor.File
                $obs.AlertTexts=@($obs.AlertMonitor.AlertTexts)
            }catch{$obs.MonitorError=$_.Exception.ToString()}
            finally{$monitor.Job | Stop-Job -ErrorAction SilentlyContinue;$monitor.Job | Remove-Job -Force -ErrorAction SilentlyContinue}
        }
    }
    if(-not $obs.WordExited -or $obs.MonitorError -or $null -eq $obs.AlertMonitor -or $obs.AlertMonitor.Error -or
        $obs.AlertMonitor.Stopped -ne $true -or $obs.AlertMonitor.TimedOut -ne $false -or $obs.AlertTexts.Count -gt 0){throw 'Word error/alert/cleanup evidence did not pass'}
}
function Read-ActorControlText([string]$Path) {
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 5 * [Diagnostics.Stopwatch]::Frequency
    for (;;) {
        try {
            $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite, 4096, [IO.FileOptions]::None)
            try { $reader = [IO.StreamReader]::new($stream); try { return $reader.ReadToEnd() } finally { $reader.Dispose() } }
            finally { $stream.Dispose() }
        } catch [IO.IOException] {
            $ioFailure = $_.Exception
            while ($ioFailure.InnerException) { $ioFailure = $ioFailure.InnerException }
            if (($ioFailure.HResult -band 0xffff) -notin @(32,33) -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw }
            Start-Sleep -Milliseconds 5
        }
    }
}
function Invoke-T5Child([string]$Operation,[string]$Path) {
    $receipt=Join-Path $Control ('child-'+[guid]::NewGuid().ToString('N')+'.json')
    $args='-NoProfile -STA -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -ChildOperation '+$Operation+' -ChildPath "'+$Path+'" -ChildResult "'+$receipt+'"'
    $child=Start-Process powershell.exe -ArgumentList $args -PassThru
    try {
        if(-not $child.WaitForExit(30000)){throw 'Second-process native operation timed out'}
        if($child.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $receipt)){throw ('Second process failed; pid='+$child.Id+' exit='+$child.ExitCode)}
        return ((Read-ActorControlText $receipt) | ConvertFrom-Json)
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
    $c = (Read-ActorControlText $command.FullName) | ConvertFrom-Json
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
            'native-read' {$result.Read=[T5Native]::Read($c.Path);$result.Steps=$result.Read.Steps}
            {$_ -cin @('excel-saveas','excel-seed','excel-cpf','excel-edit','excel-read')} {
                $result.Ui=[ordered]@{}
                Invoke-T5Excel ([string]$c.Op) ([string]$c.Path) ([string]$c.Text) $result.Ui
                $result.Steps='excel=0'
                if($c.Op -ceq 'excel-read'){$result.Read=[T5Native]::Read($c.Path);$result.Steps+=' '+$result.Read.Steps}
            }
            {$_ -cin @('word-saveas','word-seed','word-cpf','word-edit','word-overwrite','word-read')} {
                $result.Ui=[ordered]@{}
                Invoke-T5Word ([string]$c.Op) ([string]$c.Path) ([string]$c.Text) $result.Ui
                $result.Steps='word=0'
                if($c.Op -ceq 'word-read'){$result.Read=[T5Native]::Read($c.Path);$result.Steps+=' '+$result.Read.Steps}
            }
            'notepad-edit' {$result.Ui=[ordered]@{};Invoke-NotepadEdit $c.Path ([string]$c.Text) $result.Ui;$result.Steps='notepad-edit=0'}
            {$_ -cin @('shell-copy-in','shell-move-in','shell-move-within')} {
                $move=$c.Op -ne 'shell-copy-in'
                $source=if($c.Op -eq 'shell-move-within'){[string]$c.Text}else{Join-Path $env:TEMP ('t5-shell-'+[guid]::NewGuid().ToString('N')+'.txt')}
                if($c.Op -ne 'shell-move-within'){[IO.File]::WriteAllBytes($source,$bytes)}
                $result.Source=$source;$result.SourceInActorTemp=($source.StartsWith($env:TEMP.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase))
                $result.SourceRead=[T5Native]::Read($source)
                if($result.SourceRead.Code -ne 0 -or $result.SourceRead.Length -le 0){throw 'Shell source was not readable and nonempty'}
                $result.Ui=[ordered]@{WindowsBefore=@(Get-T5DesktopWindows)}
                try {$result.Steps=[T5Shell]::Transfer($source,$c.Path,$move)}finally{$result.Ui.WindowsAfter=@(Get-T5DesktopWindows)}
                $result.SourceGone=-not (Test-Path -LiteralPath $source)
                # Keep move failures' sources as evidence; copy cleanup happens only after recording its observation.
                if(-not $move){Remove-Item -LiteralPath $source -Force}
            }
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
