#requires -Version 5.1
<#
  Interactive t5actor, unprotected dev fixtures. Real Win+E / Ctrl+C / Ctrl+V.
  Use with a separately owned FileIO WPR session; no completion-authority claim.
  -SelfCheck compiles and checks native input signatures without input or I/O.
#>
[CmdletBinding()]
param([string]$Label, [string]$RootParent = 'C:\T8', [switch]$SelfCheck)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) {
    throw 'Windows PowerShell 5.1 Desktop x64 required'
}
Add-Type -Path (Join-Path $PSScriptRoot 'motw-completion-native-control.cs') -ReferencedAssemblies @(
    'System.dll', 'System.Core.dll', 'System.Net.Http.dll', 'System.Web.Extensions.dll')
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class T8ExplorerInput {
    [StructLayout(LayoutKind.Explicit, Size=40)]
    public struct Input {
        [FieldOffset(0)] public uint Type;
        [FieldOffset(8)] public ushort Key;
        [FieldOffset(10)] public ushort Scan;
        [FieldOffset(12)] public uint Flags;
        [FieldOffset(16)] public uint Time;
        [FieldOffset(24)] public UIntPtr Extra;
    }
    [DllImport("user32.dll", SetLastError=true)] static extern uint SendInput(uint count, Input[] values, int bytes);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    static Input Key(ushort key, bool up) { return new Input { Type=1, Key=key, Flags=up ? 2u : 0u }; }
    static void Send(Input[] values) {
        if (SendInput((uint)values.Length, values, 40) != values.Length) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public static void Chord(ushort modifier, ushort key) { Send(new[] { Key(modifier,false),Key(key,false),Key(key,true),Key(modifier,true) }); }
    public static void Enter() { Send(new[] {Key(13,false),Key(13,true)}); }
    public static void Text(string text) {
        Input[] values=new Input[text.Length*2];
        for(int i=0;i<text.Length;++i) {
            values[i*2]=new Input {Type=1,Scan=text[i],Flags=4};
            values[i*2+1]=new Input {Type=1,Scan=text[i],Flags=6};
        }
        Send(values);
    }
    public static void SelfCheck() {
        if(Marshal.SizeOf(typeof(Input))!=40 || Marshal.OffsetOf(typeof(Input),"Key").ToInt32()!=8 ||
           Marshal.OffsetOf(typeof(Input),"Extra").ToInt32()!=24) throw new Exception("INPUT layout mismatch");
        var method=typeof(T8ExplorerInput).GetMethod("SendInput",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static);
        if(method.ReturnType!=typeof(uint) || method.GetParameters().Length!=3 ||
           method.GetParameters()[0].ParameterType!=typeof(uint) || method.GetParameters()[1].ParameterType!=typeof(Input[]) ||
           method.GetParameters()[2].ParameterType!=typeof(int)) throw new Exception("SendInput signature mismatch");
        if(typeof(T8ExplorerInput).GetMethod("GetForegroundWindow").ReturnType!=typeof(IntPtr) ||
           typeof(T8ExplorerInput).GetMethod("GetWindowThreadProcessId").GetParameters()[1].ParameterType!=typeof(uint).MakeByRefType())
           throw new Exception("Window signature mismatch");
    }
}
'@
[T8ExplorerInput]::SelfCheck()
[SafeUpload.T8.MotwObserver]::SelfCheck()
if ($SelfCheck) { 'T8ExplorerInputSignatureSelfCheck=PASS InputInjected=False NativeFiles=False'; return }
if ($Label -notmatch '^[A-Za-z0-9_-]{3,40}$') { throw 'Fresh label required' }
$who = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($who)
if ($who.IsSystem -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Standard user required' }
$root = Join-Path $RootParent ('explorer-' + $Label)
if (Test-Path -LiteralPath $root) { throw 'Fixture already exists' }
[void](New-Item -ItemType Directory -Path $root)
$files = Join-Path $root 'files'; [void](New-Item -ItemType Directory -Path $files)
$src = Join-Path $files 'source'; $dst = Join-Path $files 'destination'
[void](New-Item -ItemType Directory -Path $src); [void](New-Item -ItemType Directory -Path $dst)
$source = Join-Path $src 'tagged.txt'; $target = Join-Path $dst 'tagged.txt'
$output = [IO.File]::Open($source, 'CreateNew', 'Write', 'None')
try {
    $chunk = New-Object byte[] 65536
    for ($i = 0; $i -lt $chunk.Length; ++$i) { $chunk[$i] = 97 }
    for ($i = 0; $i -lt 1024; ++$i) { $output.Write($chunk, 0, $chunk.Length) }
    $output.Flush($true)
} finally { $output.Dispose() }
$zone = "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.invalid/explorer-fixture`r`n"
[SafeUpload.T8.MotwObserver]::SetZone($source, $zone, $false)
$result = [ordered]@{ Label=$Label; Qualification=$false; WholeVersionWitnessEstablished=$false;
    Identity=$who.Name; Sid=$who.User.Value; Root=$root; SourceState=[SafeUpload.T8.MotwObserver]::State($source);
    SourceSha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash; Failures=@() }
$shell = New-Object -ComObject Shell.Application
$baseline = @($shell.Windows() | ForEach-Object { [long]$_.HWND })
$observer = [SafeUpload.T8.MotwObserver]::new($files)
$window = $null
function Wait-ExplorerFolder([string]$path) {
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($deadline.Elapsed.TotalSeconds -lt 20) {
        foreach ($candidate in @($shell.Windows())) {
            try {
                if ($candidate.FullName -like '*\explorer.exe' -and $candidate.Document.Folder.Self.Path -ieq $path -and
                    $baseline -notcontains [long]$candidate.HWND) { return $candidate }
            } catch { }
        }
        Start-Sleep -Milliseconds 100
    }
    throw ('New Explorer window did not reach ' + $path)
}
function Assert-Foreground($view) {
    if ([T8ExplorerInput]::GetForegroundWindow().ToInt64() -ne [long]$view.HWND) { throw 'Explorer lost foreground; no keyboard input sent' }
}
try {
    $observer.Mark('BeforeWinE', $null)
    [T8ExplorerInput]::Chord(91, 69) # Windows+E: open a new actual Explorer window.
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($null -eq $window -and $deadline.Elapsed.TotalSeconds -lt 20) {
        foreach ($candidate in @($shell.Windows())) {
            try {
                if ($candidate.FullName -like '*\explorer.exe' -and $baseline -notcontains [long]$candidate.HWND -and
                    [T8ExplorerInput]::GetForegroundWindow().ToInt64() -eq [long]$candidate.HWND) { $window = $candidate; break }
            } catch { }
        }
        if ($null -eq $window) { Start-Sleep -Milliseconds 100 }
    }
    if ($null -eq $window) { throw 'Win+E did not open a new foreground Explorer window; navigation input refused' }
    Assert-Foreground $window
    [T8ExplorerInput]::Chord(17, 76); [T8ExplorerInput]::Text($src); [T8ExplorerInput]::Enter()
    $window = Wait-ExplorerFolder $src
    Assert-Foreground $window
    [uint32]$explorerProcess = 0
    [void][T8ExplorerInput]::GetWindowThreadProcessId([IntPtr]([long]$window.HWND), [ref]$explorerProcess)
    $result.ExplorerPid = $explorerProcess; $result.ExplorerWindow = [long]$window.HWND
    $item = $window.Document.Folder.ParseName('tagged.txt')
    $window.Document.SelectItem($item, 29)
    $observer.Mark('BeforeExplorerCopy', $source)
    [T8ExplorerInput]::Chord(17, 67)
    Start-Sleep -Milliseconds 300
    Assert-Foreground $window
    [T8ExplorerInput]::Chord(17, 76); [T8ExplorerInput]::Text($dst); [T8ExplorerInput]::Enter()
    $window = Wait-ExplorerFolder $dst
    Assert-Foreground $window
    $observer.Mark('BeforeExplorerPaste', $target)
    [T8ExplorerInput]::Chord(17, 86)
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $state = [SafeUpload.T8.MotwObserver]::State($target)
        $length = $state.PSObject.Properties['Length']; $tag = $state.PSObject.Properties['Zone']
        if ($null -ne $length -and $null -ne $tag -and $length.Value -eq 64 * 1024 * 1024 -and $tag.Value -ceq $zone) { break }
        if ($deadline.Elapsed.TotalSeconds -ge 60) { throw 'Explorer paste did not produce the expected complete tagged file' }
        Start-Sleep -Milliseconds 10
    }
    $result.DestinationState = $state
    $result.DestinationSha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    if ($result.SourceSha256 -ne $result.DestinationSha256) { throw 'Explorer bytes differ' }
    $observer.Mark('ExplorerCompleteStateObserved', $state)
    $result.NativeProbeCompleted = $true
} catch { $result.NativeProbeCompleted = $false; $result.Failures += $_.ToString() }
finally {
    if ($null -ne $window) { try { $window.Quit() } catch { $result.Failures += ('WindowClose: ' + $_) } }
    $observer.Dispose()
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    [IO.File]::WriteAllText((Join-Path $root 'observations.json'), $observer.Results(), [Text.Encoding]::UTF8)
    [IO.File]::WriteAllText((Join-Path $root 'result.json'), ($result | ConvertTo-Json -Depth 12), [Text.Encoding]::UTF8)
}
$result | ConvertTo-Json -Compress -Depth 12
if (-not $result.NativeProbeCompleted -or $result.Failures.Count) { throw ('Explorer native probe incomplete: ' + $root) }
'T8ExplorerPasteProbe=COMPLETE WholeVersionWitnessEstablished=False Qualification=False'
