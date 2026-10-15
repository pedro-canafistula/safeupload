<# Build-only validation of Git-commit agent sources. Never installs or starts the service. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{3,60}$')][string] $Label,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ArchiveSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string] $SourceCommit,
    [string] $BuilderName = $env:SAFEUPLOAD_BUILDER,
    [string] $BuilderSupportPath = (Join-Path $PSScriptRoot 'ApprovedBuilders.ps1'),
    [string] $BuilderConfigPath = (Join-Path $PSScriptRoot 'approved-builders.json'),
    [switch] $DiagnosticContinue,
    [switch] $DiagnosticCompileOnly,
    [switch] $CleanupSelfTestOnly
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# VSTest's public /ListTests output contains Unicode theory arguments. Set both
# the native console decoder and pipeline encoder before any dotnet process.
$script:Utf8ConsoleEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $script:Utf8ConsoleEncoding
$OutputEncoding = $script:Utf8ConsoleEncoding
. $BuilderSupportPath
$builder = Get-ApprovedBuilder -Role 'matrix' -Label $Label -BuilderName $BuilderName -ConfigPath $BuilderConfigPath
Assert-ApprovedBuilderIdentity $builder
if ($DiagnosticContinue -and $DiagnosticCompileOnly) { throw 'Choose only one diagnostic mode.' }
function Get-MatrixProfiles {
    foreach ($mode in @('feature')) {
        foreach ($configuration in @('Debug', 'Release')) {
            [pscustomobject]@{ Mode = $mode; Configuration = $configuration }
        }
    }
}
function Get-MatrixCompletionRows {
    param([bool] $Passed, [bool] $ContinueMode, [bool] $CompileOnly, [bool] $Parity)
    if ($CompileOnly) { "DiagnosticCompileGate=$Passed"; 'TestsExecuted=False' }
    if ($ContinueMode) { 'DiagnosticContinue=True'; 'DiagnosticContinue: not a gate' }
    if ($Parity) { 'ParityCheck: not a gate' }
    if ($ContinueMode -or $CompileOnly -or $Parity) { 'AgentMatrixGate=False' }
    else { "AgentMatrixGate=$Passed" }
}
function Invoke-MatrixDiagnosticStep {
    param([string] $StepName, [scriptblock] $Action)
    try { & $Action }
    catch {
        # Never proceed into another SYSTEM job without its lifetime proof.
        if ($_.Exception.Message -like 'SYSTEM task cleanup could not be confirmed:*') { throw }
        $script:diagnosticFailed = $true
        $script:summary += ($StepName + ': DiagnosticFailure=' + $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' '))
    }
}
function Get-MatrixUserIdentity { return [Security.Principal.WindowsIdentity]::GetCurrent() }
function Invoke-DiagnosticProfile {
    param([string] $Name, [string] $Configuration, [string[]] $Common,
        [string] $ServiceProject, [string] $AppProject, [string] $TestProject, [string] $ProfileSource)
    # Each independent action is attempted even after another action fails. A
    # missing assembly is recorded separately for BOTH user and SYSTEM legs.
    Invoke-MatrixDiagnosticStep ($Name + '-build') { Invoke-DotnetGate ($Name + '-build') (@('build', $ServiceProject) + $Common) }
    Invoke-MatrixDiagnosticStep ($Name + '-app-build') { Invoke-DotnetGate ($Name + '-app-build') (@('build', $AppProject) + $Common) }
    Invoke-MatrixDiagnosticStep ($Name + '-test-build') { Invoke-DotnetGate ($Name + '-test-build') (@('build', $TestProject) + $Common) }
    $results = Join-Path $out ($Name + '-results')
    [void][IO.Directory]::CreateDirectory($results)
    $testDlls = @(Get-ChildItem (Join-Path $ProfileSource ('agente/SafeUpload.Agent.Tests/bin/' + $Configuration)) `
        -Recurse -Filter 'SafeUpload.Agent.Tests.dll' -ErrorAction SilentlyContinue)
    $testDll = if ($testDlls.Count -eq 1) { $testDlls[0] } else { $null }
    $discoveryFqns = Join-Path $results 'agent-tests-discovered-fq.txt'
    $discoverySettings = Join-Path $results 'discovery.runsettings'
    [IO.File]::WriteAllText($discoverySettings,
        '<RunSettings><RunConfiguration><BatchSize>100000</BatchSize></RunConfiguration></RunSettings>', $script:Utf8ConsoleEncoding)
    $oldMachineSetting = $env:SAFEUPLOAD_MACHINE_TESTS
    try {
        $env:SAFEUPLOAD_MACHINE_TESTS = '1'
        Invoke-MatrixDiagnosticStep ($Name + '-tests-discovery-list') {
            if ($null -eq $testDll) { throw 'Expected exactly one built test assembly.' }
            Invoke-DotnetGate ($Name + '-tests-discovery-list') @('vstest', $testDll.FullName, '/ListTests', ("/Settings:$discoverySettings"))
        }
        Invoke-MatrixDiagnosticStep ($Name + '-tests-discovery-fqns') {
            if ($null -eq $testDll) { throw 'Expected exactly one built test assembly.' }
            Invoke-DotnetGate ($Name + '-tests-discovery-fqns') @('vstest', $testDll.FullName, '/ListFullyQualifiedTests',
                ("/Settings:$discoverySettings"), ("/ListTestsTargetPath:$discoveryFqns"))
        }
        ++$script:diagnosticTestLegsAttempted
        Invoke-MatrixDiagnosticStep ($Name + '-tests-user') {
            if ($null -eq $testDll) { throw 'Expected exactly one built test assembly.' }
            $identity = Get-MatrixUserIdentity
            if ($identity.User.Value -eq 'S-1-5-18' -or $identity.Name -notmatch ('(?i)\\' + [regex]::Escape($builder.ssh_user) + '$')) {
                throw 'Unprivileged test leg has the wrong identity.'
            }
            $script:summary += "${Name}-tests-user-identity: name=$($identity.Name) sid=$($identity.User.Value)"
            Remove-Item Env:SAFEUPLOAD_MACHINE_TESTS -ErrorAction SilentlyContinue
            Invoke-DotnetGate ($Name + '-tests-user') @('vstest', $testDll.FullName,
                '/TestCaseFilter:FullyQualifiedName!~CertificateAuthorityTests&FullyQualifiedName!~TlsInspectionProxyTests&FullyQualifiedName!~TrafficDiversionTests',
                '/Logger:trx;LogFileName=agent-tests-user.trx', ("/ResultsDirectory:$results"))
            [void](Assert-TrxLeg (Join-Path $results 'agent-tests-user.trx') ($Name + '/user'))
        }
        ++$script:diagnosticTestLegsAttempted
        Invoke-MatrixDiagnosticStep ($Name + '-tests-system') {
            if ($null -eq $testDll) { throw 'Expected exactly one built test assembly.' }
            $systemLog = Join-Path $out ($Name + '-tests-system.txt')
            $code = Invoke-SystemProcess -FilePath $script:dotnetExe `
                -ArgumentLine ('vstest "' + $testDll.FullName + '" /TestCaseFilter:"FullyQualifiedName~CertificateAuthorityTests|FullyQualifiedName~TlsInspectionProxyTests|FullyQualifiedName~TrafficDiversionTests" /Logger:"trx;LogFileName=agent-tests-system.trx" /ResultsDirectory:"' + $results + '"') `
                -WorkingDirectory $testDll.DirectoryName -StdoutPath $systemLog -Environment @{ SAFEUPLOAD_MACHINE_TESTS = '1' }
            $text = [IO.File]::ReadAllText($systemLog)
            $warnings = [regex]::Matches($text, '(?im)\bwarning\s+[A-Z]+\d+\b').Count
            $errors = [regex]::Matches($text, '(?im)\berror\s+[A-Z]+\d+\b').Count
            $script:summary += "${Name}-tests-system: exit=$code warnings=$warnings errors=$errors"
            if ([regex]::Matches($text, '(?m)^SYSTEM_TEST_TASK_SID=S-1-5-18\r?$').Count -ne 1) { throw 'SYSTEM identity evidence missing or duplicated.' }
            $script:summary += "${Name}-tests-system-identity: S-1-5-18"
            if ($code -ne 0 -or $warnings -ne 0 -or $errors -ne 0) { throw 'SYSTEM tests failed.' }
            [void](Assert-TrxLeg (Join-Path $results 'agent-tests-system.trx') ($Name + '/SYSTEM'))
        }
    } finally {
        if ($null -eq $oldMachineSetting) { Remove-Item Env:SAFEUPLOAD_MACHINE_TESTS -ErrorAction SilentlyContinue }
        else { $env:SAFEUPLOAD_MACHINE_TESTS = $oldMachineSetting }
    }
    if ($Configuration -eq 'Release') {
        Invoke-MatrixDiagnosticStep ($Name + '-publish') {
            $publish = Join-Path $out ($Name + '-publish')
            Invoke-DotnetGate ($Name + '-publish') (@('publish', $ServiceProject,
                '-r', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=true',
                '-p:IncludeNativeLibrariesForSelfExtract=true', '-o', $publish) + $Common)
        }
    }
}
$nativeJobSource = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public sealed class SafeUploadNativeJobProcess : IDisposable
{
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;
    private const int JobObjectBasicAccountingInformation = 1;
    private const uint WAIT_OBJECT_0 = 0;
    private const uint WAIT_TIMEOUT = 258;
    private const uint WAIT_FAILED = 0xFFFFFFFF;
    private const uint FILE_SHARE_READ = 1;
    private const uint FILE_SHARE_WRITE = 2;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint CREATE_ALWAYS = 2;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint TERMINATION_EXIT_CODE = 0xE0000001;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint infoLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint infoLength, IntPtr returnLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
        IntPtr environment, string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        ref SECURITY_ATTRIBUTES securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private IntPtr job;
    private IntPtr process;
    private bool disposed;
    public int ProcessId { get; private set; }

    private SafeUploadNativeJobProcess(IntPtr jobHandle, IntPtr processHandle, uint processId)
    {
        job = jobHandle;
        process = processHandle;
        ProcessId = checked((int)processId);
    }

    private static Exception LastError(string action)
    {
        return new InvalidOperationException(action + " failed with Win32 error " + Marshal.GetLastWin32Error() + ".");
    }

    private static IntPtr OpenInheritedFile(string path, bool output)
    {
        SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
        security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        security.bInheritHandle = true;
        IntPtr handle = CreateFileW(path, output ? GENERIC_WRITE : GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, ref security,
            output ? CREATE_ALWAYS : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (handle == new IntPtr(-1)) throw LastError("Opening redirected process stream");
        return handle;
    }

    public static SafeUploadNativeJobProcess Start(string filePath, string argumentLine,
        string workingDirectory, string stdoutPath, string stderrPath)
    {
        IntPtr jobHandle = CreateJobObjectW(IntPtr.Zero, null);
        if (jobHandle == IntPtr.Zero) throw LastError("Creating process job");
        IntPtr stdin = IntPtr.Zero;
        IntPtr stdout = IntPtr.Zero;
        IntPtr stderr = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        bool assigned = false;
        try
        {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int limitsSize = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr limitsMemory = Marshal.AllocHGlobal(limitsSize);
            try
            {
                Marshal.StructureToPtr(limits, limitsMemory, false);
                if (!SetInformationJobObject(jobHandle, JobObjectExtendedLimitInformation, limitsMemory, (uint)limitsSize))
                    throw LastError("Setting kill-on-close job policy");
            }
            finally { Marshal.FreeHGlobal(limitsMemory); }

            stdin = OpenInheritedFile("NUL", false);
            stdout = OpenInheritedFile(stdoutPath, true);
            stderr = OpenInheritedFile(stderrPath, true);
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = stdin;
            startup.hStdOutput = stdout;
            startup.hStdError = stderr;
            string command = "\"" + filePath.Replace("\"", "\\\"") + "\" " + argumentLine;
            if (!CreateProcessW(filePath, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, true,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, workingDirectory, ref startup, out pi))
                throw LastError("Creating suspended process");
            if (!AssignProcessToJobObject(jobHandle, pi.hProcess)) throw LastError("Assigning suspended process to job");
            assigned = true;
            if (ResumeThread(pi.hThread) == 0xFFFFFFFF) throw LastError("Resuming process in job");
            CloseHandle(pi.hThread);
            pi.hThread = IntPtr.Zero;
            return new SafeUploadNativeJobProcess(jobHandle, pi.hProcess, pi.dwProcessId);
        }
        catch
        {
            bool stopped = true;
            if (pi.hProcess != IntPtr.Zero)
            {
                if (assigned) TerminateJobObject(jobHandle, TERMINATION_EXIT_CODE);
                else TerminateProcess(pi.hProcess, TERMINATION_EXIT_CODE);
                stopped = WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0;
            }
            bool empty = WaitForJobEmptyHandle(jobHandle, 30000);
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            CloseHandle(jobHandle);
            if (!stopped || !empty)
                throw new InvalidOperationException("A failed process launch could not prove its process handle and job tree stopped.");
            throw;
        }
        finally
        {
            if (stdin != IntPtr.Zero) CloseHandle(stdin);
            if (stdout != IntPtr.Zero) CloseHandle(stdout);
            if (stderr != IntPtr.Zero) CloseHandle(stderr);
        }
    }

    private static uint ActiveProcessCount(IntPtr jobHandle)
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = new JOBOBJECT_BASIC_ACCOUNTING_INFORMATION();
        int size = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
        IntPtr memory = Marshal.AllocHGlobal(size);
        try
        {
            if (!QueryInformationJobObject(jobHandle, JobObjectBasicAccountingInformation, memory, (uint)size, IntPtr.Zero))
                throw LastError("Querying process job accounting");
            accounting = (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(
                memory, typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            return accounting.ActiveProcesses;
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    private static bool WaitForJobEmptyHandle(IntPtr jobHandle, int timeoutMilliseconds)
    {
        Stopwatch elapsed = Stopwatch.StartNew();
        while (true)
        {
            if (ActiveProcessCount(jobHandle) == 0) return true;
            if (elapsed.ElapsedMilliseconds >= timeoutMilliseconds) return false;
            Thread.Sleep(50);
        }
    }

    public bool WaitForExit(int timeoutMilliseconds)
    {
        uint result = WaitForSingleObject(process, checked((uint)timeoutMilliseconds));
        if (result == WAIT_OBJECT_0) return true;
        if (result == WAIT_TIMEOUT) return false;
        if (result == WAIT_FAILED) throw LastError("Waiting for process handle");
        throw new InvalidOperationException("Unexpected process wait result " + result + ".");
    }

    public int ExitCode
    {
        get
        {
            uint result;
            if (!GetExitCodeProcess(process, out result)) throw LastError("Reading process exit code");
            return unchecked((int)result);
        }
    }

    public bool WaitForJobEmpty(int timeoutMilliseconds)
    {
        return WaitForJobEmptyHandle(job, timeoutMilliseconds);
    }

    public void TerminateJobAndWait(int timeoutMilliseconds)
    {
        if (ActiveProcessCount(job) != 0 && !TerminateJobObject(job, TERMINATION_EXIT_CODE)
            && ActiveProcessCount(job) != 0)
            throw LastError("Terminating process job");
        if (!WaitForJobEmptyHandle(job, timeoutMilliseconds))
            throw new InvalidOperationException("Process job still contains descendants after termination.");
    }

    public void Dispose()
    {
        if (disposed) return;
        Exception failure = null;
        try
        {
            if (job != IntPtr.Zero && !WaitForJobEmptyHandle(job, 0))
                TerminateJobAndWait(30000);
        }
        catch (Exception error) { failure = error; }
        finally
        {
            if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; }
            if (process != IntPtr.Zero) { CloseHandle(process); process = IntPtr.Zero; }
            disposed = true;
        }
        if (failure != null)
            throw new InvalidOperationException("Process job did not reach a verified empty state before its kill-on-close handle was closed.", failure);
    }
}
'@
# Two groups of agent unit tests need different accounts. The certificate-authority and TLS-inspection tests create
# current-user CNG keys, which fails with "Access denied" in the builder's SSH logon (an S4U logon has no DPAPI user
# secret) and works as SYSTEM. The hand-back tests model an unprivileged host and the product refuses to route a
# hand-back to SYSTEM, so they must run as the normal user. Every test runs exactly once, in the account it needs; the two
# trx files are merged into the single agent-tests.trx that the pair qualification reads.
function Merge-TrxFiles {
    param([Parameter(Mandatory)][string[]] $Paths, [Parameter(Mandatory)][string] $Destination)
    $ns = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'
    $documents = @()
    foreach ($path in $Paths) { $document = New-Object System.Xml.XmlDocument; $document.Load($path); $documents += $document }
    $first = $documents[0]
    $firstManager = New-Object System.Xml.XmlNamespaceManager($first.NameTable); $firstManager.AddNamespace('t', $ns)
    foreach ($section in 'Results', 'TestDefinitions', 'TestEntries') {
        $target = $first.SelectSingleNode('//t:' + $section, $firstManager)
        if ($null -eq $target) { throw ('TRX has no ' + $section + ' section.') }
        for ($index = 1; $index -lt $documents.Count; $index++) {
            $manager = New-Object System.Xml.XmlNamespaceManager($documents[$index].NameTable); $manager.AddNamespace('t', $ns)
            $source = $documents[$index].SelectSingleNode('//t:' + $section, $manager)
            if ($null -eq $source) { continue }
            foreach ($node in @($source.ChildNodes)) { [void]$target.AppendChild($first.ImportNode($node, $true)) }
        }
    }
    $summary = $first.SelectSingleNode('//t:ResultSummary', $firstManager)
    $counters = $first.SelectSingleNode('//t:ResultSummary/t:Counters', $firstManager)
    foreach ($name in 'total', 'executed', 'passed', 'failed', 'error', 'timeout', 'aborted', 'inconclusive', 'passedButRunAborted',
        'notRunnable', 'notExecuted', 'disconnected', 'warning', 'completed', 'inProgress', 'pending') {
        $sum = 0
        foreach ($document in $documents) {
            $manager = New-Object System.Xml.XmlNamespaceManager($document.NameTable); $manager.AddNamespace('t', $ns)
            $counter = $document.SelectSingleNode('//t:ResultSummary/t:Counters', $manager)
            if ($counter.HasAttribute($name)) { $sum += [int]$counter.GetAttribute($name) }
        }
        $counters.SetAttribute($name, [string]$sum)
    }
    if ([int]$counters.GetAttribute('failed') -gt 0 -or [int]$counters.GetAttribute('error') -gt 0) { $summary.SetAttribute('outcome', 'Failed') }
    $first.Save($Destination)
}
function Get-RecordedProcess {
    param([Parameter(Mandatory)][string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $line = [IO.File]::ReadAllText($Path).Trim()
    if ($line -notmatch '^([1-9][0-9]*)\|([1-9][0-9]*)$') { throw ('Malformed process record: ' + $Path) }
    return [pscustomobject]@{ Id = [int]$Matches[1]; StartTicks = [long]$Matches[2] }
}
function Test-RecordedProcessAlive {
    param([Parameter(Mandatory)][string] $Path)
    $record = Get-RecordedProcess $Path
    if ($null -eq $record) { return $false }
    $process = Get-Process -Id $record.Id -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $false }
    try { $actualTicks = $process.StartTime.ToUniversalTime().Ticks }
    catch { throw ('Cannot verify recorded process identity: ' + $record.Id) }
    # Exact creation-time matching avoids treating a fast PID reuse as the privileged child.
    return ($actualTicks -eq $record.StartTicks)
}
function Assert-TrxLeg {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $Name)
    [xml]$document = [IO.File]::ReadAllText($Path)
    $counters = $document.TestRun.ResultSummary.Counters
    if ($null -eq $counters) { throw ('Missing TRX counters: ' + $Name) }
    $total = [int]$counters.total
    $passed = [int]$counters.passed
    $executed = [int]$counters.executed
    if ($total -le 0 -or $passed -ne $total -or $executed -ne $total) { throw ('Empty or incomplete test leg: ' + $Name) }
    foreach ($field in @('failed', 'error', 'timeout', 'aborted', 'inconclusive', 'passedButRunAborted',
        'notRunnable', 'notExecuted', 'disconnected', 'warning', 'inProgress', 'pending')) {
        if ([int]$counters.$field -ne 0) { throw ('Unsuccessful test leg: ' + $Name + '/' + $field) }
    }
    $rows = @($document.TestRun.Results.UnitTestResult)
    if ($rows.Count -ne $total) { throw ('TRX result count does not equal total: ' + $Name) }
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($row in $rows) {
        # executionId identifies a single result row. testId can be shared by parameterized cases.
        if ([string]::IsNullOrWhiteSpace($row.testId) -or [string]::IsNullOrWhiteSpace($row.executionId) -or
            [string]::IsNullOrWhiteSpace($row.testName) -or $row.outcome -ne 'Passed' -or
            -not $ids.Add([string]$row.executionId)) {
            throw ('Missing, duplicate, or unpassed TRX result: ' + $Name)
        }
    }
    return $total
}
function Remove-CompletedProfileOutputs {
    param([Parameter(Mandatory)][string] $ProfileSource, [Parameter(Mandatory)][string] $EvidenceDirectory,
        [Parameter(Mandatory)][System.Collections.IDictionary] $ExpectedInputs)
    $profilePath = [IO.Path]::GetFullPath($ProfileSource).TrimEnd('\')
    $evidencePath = [IO.Path]::GetFullPath($EvidenceDirectory).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($profilePath) -ne $evidencePath -or
        [IO.Path]::GetFileName($profilePath) -notmatch '^profile-src-feature-(debug|release)$') {
        throw 'Generated-output cleanup is outside a completed matrix profile.'
    }
    $agentPath = Join-Path $profilePath 'agente'
    foreach ($parent in @($evidencePath, $profilePath, $agentPath)) {
        if (((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Generated-output cleanup parent is a reparse point.'
        }
    }
    $generatedPaths = @()
    foreach ($project in @(Get-ChildItem -LiteralPath $agentPath -Directory)) {
        if (((Get-Item -LiteralPath $project.FullName).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Generated-output cleanup project is a reparse point.'
        }
        if (@(Get-ChildItem -LiteralPath $project.FullName -Filter '*.csproj' -File).Count -eq 0) { continue }
        foreach ($leaf in @('bin', 'obj')) {
            $relative = 'agente/' + $project.Name + '/' + $leaf + '/'
            foreach ($inputPath in $ExpectedInputs.Keys) {
                if ($inputPath.StartsWith($relative, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Generated-output cleanup would remove a source input.'
                }
            }
            $generated = Join-Path $project.FullName $leaf
            if (-not (Test-Path -LiteralPath $generated)) { continue }
            if (((Get-Item -LiteralPath $generated).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                @(Get-ChildItem -LiteralPath $generated -Recurse -Force | Where-Object {
                    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
                }).Count -ne 0) {
                throw 'Generated-output cleanup contains a reparse point.'
            }
            $generatedPaths += ,$generated
        }
    }
    foreach ($generated in $generatedPaths) {
        # Scanner/image-handle release may lag the already-drained build job.
        # Retry only these validated generated paths; a persistent denial fails.
        for ($attempt = 0; ; $attempt++) {
            try {
                if (Test-Path -LiteralPath $generated) { Remove-Item -LiteralPath $generated -Recurse -Force -ErrorAction Stop }
                break
            } catch {
                if ($attempt -ge 4) { throw }
                Start-Sleep -Milliseconds (250 * [Math]::Pow(2, $attempt))
            }
        }
    }
    Write-Output ('PROFILE_OUTPUT_CLEANUP=' + [IO.Path]::GetFileName($profilePath) +
        '; directories=' + $generatedPaths.Count + '; source_and_evidence_retained=True')
}

function Invoke-CleanupSelfTest {
    Add-Type -TypeDefinition $nativeJobSource
    $testRoot = Join-Path 'C:\Users\vika\Documents' ('exact-agent-matrix-cleanup-selftest-' + $Label + '-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($testRoot)
    $powershellExe = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellExe -PathType Leaf)) { throw 'PowerShell self-test executable is missing.' }
    $sleeperScript = Join-Path $testRoot 'sleep.ps1'
    $descendantScript = Join-Path $testRoot 'descendant.ps1'
    [IO.File]::WriteAllText($sleeperScript, 'Start-Sleep -Seconds 120', [Text.Encoding]::UTF8)
    $quotedPowerShell = "'" + $powershellExe.Replace("'", "''") + "'"
    $grandchildArguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $sleeperScript + '"'
    $descendantBody = '$null = Start-Process -FilePath ' + $quotedPowerShell + ' -ArgumentList ' +
        "'" + $grandchildArguments.Replace("'", "''") + "'" + ' -PassThru; Start-Sleep -Seconds 2'
    [IO.File]::WriteAllText($descendantScript, $descendantBody, [Text.Encoding]::UTF8)
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $sleeperScript + '"'
    $stdout = Join-Path $testRoot 'selftest.stdout.txt'
    $stderr = Join-Path $testRoot 'selftest.stderr.txt'
    $completed = $false
    try {
        # Simulate the failure window immediately after process creation but before a caller can persist a PID record.
        $recordFailureProcess = [SafeUploadNativeJobProcess]::Start($powershellExe, $arguments, $testRoot, $stdout, $stderr)
        try {
            throw 'injected child-record write failure'
        } catch {
            if ($_.Exception.Message -ne 'injected child-record write failure') { throw }
        } finally {
            $recordFailureProcess.TerminateJobAndWait(15000)
            if (-not $recordFailureProcess.WaitForJobEmpty(0)) { throw 'Spawn-record failure self-test left a job member.' }
            $recordFailureProcess.Dispose()
        }

        $timeoutProcess = [SafeUploadNativeJobProcess]::Start($powershellExe, $arguments, $testRoot, $stdout, $stderr)
        try {
            if ($timeoutProcess.WaitForExit(1000)) { throw 'Timeout self-test child exited before its timeout.' }
            $timeoutProcess.TerminateJobAndWait(15000)
            if (-not $timeoutProcess.WaitForJobEmpty(0)) { throw 'Timeout self-test left a job member.' }
        } finally { $timeoutProcess.Dispose() }

        $treeProcess = [SafeUploadNativeJobProcess]::Start($powershellExe,
            ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $descendantScript + '"'),
            $testRoot, $stdout, $stderr)
        try {
            if (-not $treeProcess.WaitForExit(15000)) { throw 'Descendant self-test parent did not exit.' }
            if ($treeProcess.ExitCode -ne 0) { throw 'Descendant self-test parent returned a failure exit code.' }
            if ($treeProcess.WaitForJobEmpty(1000)) { throw 'Descendant self-test did not leave a live child to clean up.' }
            $treeProcess.TerminateJobAndWait(15000)
            if (-not $treeProcess.WaitForJobEmpty(0)) { throw 'Descendant self-test left a job member.' }
        } finally { $treeProcess.Dispose() }
        # Completed profiles need their source and raw evidence, not four
        # simultaneous bin/obj trees. Check the deletion boundary independently
        # of the native-process job controls above.
        $fakeOut = Join-Path $testRoot 'out'
        $fakeProfile = Join-Path $fakeOut 'profile-src-feature-debug'
        $fakeProject = Join-Path $fakeProfile 'agente\Project'
        [void][IO.Directory]::CreateDirectory((Join-Path $fakeProject 'bin'))
        [void][IO.Directory]::CreateDirectory((Join-Path $fakeProject 'obj'))
        [IO.File]::WriteAllText((Join-Path $fakeProject 'Project.csproj'), '<Project />')
        [IO.File]::WriteAllText((Join-Path $fakeProject 'source.cs'), 'retained source')
        [IO.File]::WriteAllText((Join-Path $fakeProject 'bin\generated.dll'), 'generated')
        [IO.File]::WriteAllText((Join-Path $fakeProject 'obj\generated.cache'), 'generated')
        [IO.File]::WriteAllText((Join-Path $fakeOut 'raw.trx'), 'retained evidence')
        $rejected = $false
        try {
            Remove-CompletedProfileOutputs $fakeProfile $fakeOut @{'agente/Project/bin/generated.dll' = 'input'}
        } catch {
            if ($_.Exception.Message -ne 'Generated-output cleanup would remove a source input.') { throw }
            $rejected = $true
        }
        if (-not $rejected -or -not (Test-Path -LiteralPath (Join-Path $fakeProject 'bin\generated.dll'))) {
            throw 'Generated-output self-test failed to preserve a protected source input.'
        }
        Remove-CompletedProfileOutputs $fakeProfile $fakeOut @{'agente/Project/source.cs' = 'input'}
        if ((Test-Path -LiteralPath (Join-Path $fakeProject 'bin')) -or
            (Test-Path -LiteralPath (Join-Path $fakeProject 'obj')) -or
            -not (Test-Path -LiteralPath (Join-Path $fakeProject 'source.cs')) -or
            -not (Test-Path -LiteralPath (Join-Path $fakeOut 'raw.trx'))) {
            throw 'Generated-output self-test did not retain source and evidence.'
        }
        Write-Output 'PROFILE_OUTPUT_CLEANUP_SELFTEST=PASS source_input_refused,source_and_evidence_retained'
        $completed = $true
        Write-Output 'SYSTEM_JOB_CLEANUP_SELFTEST=PASS spawn_record_failure,timeout,descendant_cleanup'
    } finally {
        if ($completed) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
    }
}
if ($CleanupSelfTestOnly) {
    if ($DiagnosticCompileOnly) { throw 'Cleanup self-test and diagnostic compile-only modes cannot be combined.' }
    Invoke-CleanupSelfTest
    return
}
function Invoke-SystemProcess {
    param([Parameter(Mandatory)][string] $FilePath, [Parameter(Mandatory)][string] $ArgumentLine,
        [Parameter(Mandatory)][string] $WorkingDirectory, [Parameter(Mandatory)][string] $StdoutPath,
        [hashtable] $Environment = @{}, [int] $TimeoutMinutes = 30)
    $directory = [IO.Path]::GetDirectoryName($StdoutPath)
    $stamp = [guid]::NewGuid().ToString('N')
    $wrapper = Join-Path $directory ('system-run-' + $stamp + '.ps1')
    $exitFile = $wrapper + '.exit'
    $wrapperPidFile = $wrapper + '.pid'
    $jobEmptyFile = $wrapper + '.jobempty'
    $identityFile = $wrapper + '.identity'
    $stderrPath = $StdoutPath + '.stderr'
    [IO.File]::WriteAllText($stderrPath, '')
    $environmentLines = @($Environment.GetEnumerator() | ForEach-Object { '$env:' + $_.Key + ' = ' + ("'" + ([string]$_.Value).Replace("'", "''") + "'") })
    $wrapperPidLine = '[IO.File]::WriteAllText(''' + $wrapperPidFile + ''', [string]$PID + ''|'' + [string]([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks), [Text.Encoding]::ASCII)'
    $psFilePath = "'" + $FilePath.Replace("'", "''") + "'"
    $psArgumentLine = "'" + $ArgumentLine.Replace("'", "''") + "'"
    $psWorkingDirectory = "'" + $WorkingDirectory.Replace("'", "''") + "'"
    $psStdoutPath = "'" + $StdoutPath.Replace("'", "''") + "'"
    $psStderrPath = "'" + $stderrPath.Replace("'", "''") + "'"
    $startLine = '$jobProcess = [SafeUploadNativeJobProcess]::Start(' + $psFilePath + ', ' + $psArgumentLine + ', ' +
        $psWorkingDirectory + ', ' + $psStdoutPath + ', ' + $psStderrPath + ')'
    $body = @("Add-Type -TypeDefinition @'", $nativeJobSource, "'@",
        '$env:DOTNET_NOLOGO = ''1''; $env:DOTNET_CLI_TELEMETRY_OPTOUT = ''1''')
    $body += $environmentLines
    $body += '$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; if ($sid -ne ''S-1-5-18'') { throw ''SYSTEM test task has the wrong identity.'' }'
    $body += '[IO.File]::WriteAllText(''' + $identityFile + ''', $sid, [Text.Encoding]::ASCII)'
    $body += $wrapperPidLine
    $body += '$jobProcess = $null; $startAttempted = $false; $cleanupConfirmed = $false; $exitValue = $null'
    $body += 'try {'
    $body += '$startAttempted = $true'
    $body += $startLine
    $body += 'if ($jobProcess.WaitForExit(' + [string]($TimeoutMinutes * 60000) + ')) {'
    $body += 'if (-not $jobProcess.WaitForJobEmpty(30000)) { $jobProcess.TerminateJobAndWait(30000); throw ''SYSTEM test left descendant processes after dotnet exit.'' }'
    $body += '$exitValue = [string]$jobProcess.ExitCode'
    $body += '} else { $jobProcess.TerminateJobAndWait(30000); $exitValue = ''TIMEOUT'' }'
    $body += '} finally {'
    $body += 'if ($null -ne $jobProcess) {'
    $body += '$jobProcess.TerminateJobAndWait(30000)'
    $body += 'if (-not $jobProcess.WaitForJobEmpty(0)) { throw ''SYSTEM process job is not empty after cleanup.'' }'
    $body += '$jobProcess.Dispose(); $jobProcess = $null; $cleanupConfirmed = $true'
    $body += '} elseif (-not $startAttempted) { $cleanupConfirmed = $true }'
    $body += 'if ($cleanupConfirmed) { [IO.File]::WriteAllText(''' + $jobEmptyFile + ''', ''active_processes=0'', [Text.Encoding]::ASCII) }'
    $body += 'if ($null -ne $exitValue) { [IO.File]::WriteAllText(''' + $exitFile + ''', $exitValue, [Text.Encoding]::ASCII) }'
    $body += '}'
    Set-Content -LiteralPath $wrapper -Value $body -Encoding UTF8
    $wrapperAcl = Get-Acl -LiteralPath $wrapper
    $wrapperAcl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($wrapperAcl.Access)) { [void]$wrapperAcl.RemoveAccessRuleAll($rule) }
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
        $wrapperAcl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $wrapper -AclObject $wrapperAcl
    $taskName = 'SafeUpload-ExactAgentSystem-' + $stamp
    $powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $powershellExe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $wrapper + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes($TimeoutMinutes + 5))
    $registered = $false
    $timedOut = $false
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName
        $elapsed = [Diagnostics.Stopwatch]::StartNew()
        # The child has its own QPC timeout at TimeoutMinutes; allow time to terminate and verify the whole job.
        $cleanupDeadlineMinutes = $TimeoutMinutes + 2
        do {
            Start-Sleep -Seconds 2
            $ended = $elapsed.Elapsed.TotalSeconds -gt 15 -and (Get-ScheduledTask -TaskName $taskName).State -eq 'Ready'
        } while (-not (Test-Path -LiteralPath $exitFile) -and -not $ended -and $elapsed.Elapsed.TotalMinutes -lt $cleanupDeadlineMinutes)
        $timedOut = -not (Test-Path -LiteralPath $exitFile) -and $elapsed.Elapsed.TotalMinutes -ge $cleanupDeadlineMinutes
    }
    finally {
        $cleanupErrors = @()
        $taskBeforeCleanup = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -ne $taskBeforeCleanup -and ($timedOut -or -not (Test-Path -LiteralPath $exitFile) -or $taskBeforeCleanup.State -ne 'Ready')) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        }
        try {
            $wrapperWait = [Diagnostics.Stopwatch]::StartNew()
            while ($wrapperWait.Elapsed.TotalSeconds -lt 30) {
                $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                $wrapperAlive = Test-RecordedProcessAlive $wrapperPidFile
                if (($null -eq $task -or $task.State -eq 'Ready') -and -not $wrapperAlive) { break }
                Start-Sleep -Milliseconds 250
            }
        } catch { $cleanupErrors += $_.Exception.Message }
        if (Test-RecordedProcessAlive $wrapperPidFile) { $cleanupErrors += 'SYSTEM wrapper remains alive after task stop.' }
        if (-not (Test-Path -LiteralPath $jobEmptyFile -PathType Leaf) -or
            [IO.File]::ReadAllText($jobEmptyFile).Trim() -ne 'active_processes=0') {
            $cleanupErrors += 'SYSTEM process job did not provide an active_processes=0 cleanup proof.'
        }
        # Attempt task removal even when process verification has already failed.
        $taskBeforeCleanup = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($registered -or $null -ne $taskBeforeCleanup) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            $taskGone = $false
            $taskWait = [Diagnostics.Stopwatch]::StartNew()
            while (-not $taskGone -and $taskWait.Elapsed.TotalSeconds -lt 15) {
                $taskGone = $null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
                if (-not $taskGone) { Start-Sleep -Milliseconds 250 }
            }
            if (-not $taskGone) { $cleanupErrors += 'Scheduled task remains registered: ' + $taskName }
        }
        try {
            if (Test-RecordedProcessAlive $wrapperPidFile) { $cleanupErrors += 'SYSTEM wrapper process remains alive.' }
        } catch { $cleanupErrors += $_.Exception.Message }
        if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
            try {
                Get-Content -LiteralPath $stderrPath | Add-Content -LiteralPath $StdoutPath
            } catch { $cleanupErrors += 'Cannot retain SYSTEM test stderr: ' + $_.Exception.Message }
        }
        if ($cleanupErrors.Count -eq 0) {
            Remove-Item -LiteralPath $wrapper, $wrapperPidFile -ErrorAction SilentlyContinue
        }
        if ($cleanupErrors.Count -gt 0) { throw ('SYSTEM task cleanup could not be confirmed: ' + ($cleanupErrors -join '; ')) }
    }
    if ($timedOut) { throw 'The SYSTEM test run exceeded its QPC timeout; the scheduled task was stopped and the process job owns all descendants.' }
    if (-not (Test-Path -LiteralPath $exitFile)) { throw 'The SYSTEM test run ended without an exit code or did not finish in time.' }
    $exitText = [IO.File]::ReadAllText($exitFile).Trim()
    if ($exitText -eq 'TIMEOUT') { throw 'The SYSTEM test run exceeded its QPC timeout; the process job was emptied.' }
    if ($exitText -notmatch '^-?[0-9]+$') { throw 'The SYSTEM test run wrote an invalid exit code.' }
    $code = [int]$exitText
    if (-not (Test-Path -LiteralPath $identityFile -PathType Leaf) -or
        [IO.File]::ReadAllText($identityFile).Trim() -ne 'S-1-5-18') {
        throw 'The SYSTEM test task did not prove its SYSTEM identity.'
    }
    Add-Content -LiteralPath $StdoutPath -Value 'SYSTEM_TEST_TASK_SID=S-1-5-18'
    Add-Content -LiteralPath $StdoutPath -Value 'SYSTEM_TEST_JOB_CLEANUP=active_processes=0'
    Add-Content -LiteralPath $StdoutPath -Value 'SYSTEM_TEST_TASK_CLEANUP=task_absent,job_empty,wrapper_absent'
    Remove-Item -LiteralPath $wrapper, $wrapperPidFile, $identityFile, $exitFile, $jobEmptyFile -ErrorAction SilentlyContinue
    return $code
}
$documents = 'C:\Users\vika\Documents'
$run = Join-Path $documents ('exact-agent-matrix-' + $Label)
$archive = $run + '.zip'
if (Test-Path -LiteralPath $run) { throw 'Build directory already exists.' }
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $ArchiveSha256.ToUpperInvariant()) {
    throw 'Source archive delivery hash mismatch.'
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $fileCount = 0
    foreach ($entry in $zip.Entries) {
        $relative = $entry.FullName.TrimEnd('/')
        if (-not $relative.StartsWith('agente', [StringComparison]::Ordinal) -or
            ($relative -ne 'agente' -and -not $relative.StartsWith('agente/', [StringComparison]::Ordinal)) -or
            -not $seen.Add($relative)) { throw 'Archive path is duplicated or outside the agent tree.' }
        foreach ($part in $relative.Split('/')) {
            if ($part -in @('', '.', '..') -or $part -match '[\x00-\x1f\\:*?<>|"]' -or
                $part -match '[ .]$' -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
                throw 'Unsafe source archive path.'
            }
        }
        $kind = $entry.ExternalAttributes -shr 16 -band 0xf000
        if ($entry.FullName.EndsWith('/')) {
            # git archive ZIPs use DOS attributes (directory bit, no Unix mode).
            if ($kind -ne 0x4000 -and -not ($kind -eq 0 -and ($entry.ExternalAttributes -band 0x10))) {
                throw 'Archive directory has the wrong type.'
            }
        } else {
            if ($kind -notin @(0, 0x8000) -or ($entry.ExternalAttributes -band 0x10)) {
                throw 'Archive input is not a regular file.'
            }
            ++$fileCount
        }
    }
    if ($fileCount -le 0) { throw 'Source archive is empty.' }
} finally { $zip.Dispose() }
$out = Join-Path $run 'out'
$src = Join-Path $run 'src'
[void][IO.Directory]::CreateDirectory($out)
[IO.Compression.ZipFile]::ExtractToDirectory($archive, $src)
# Keep copy/mutation checks in memory. The Git commit is the source identifier;
# no per-file source manifest or worktree freeze is produced.
$expected = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$seenFiles = @(Get-ChildItem -LiteralPath $src -Recurse -File)
if ($seenFiles.Count -ne $fileCount) { throw 'Extracted input count mismatch.' }
foreach ($file in $seenFiles) {
    $relative = $file.FullName.Substring($src.Length + 1).Replace('\', '/')
    $expected.Add($relative, (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash)
}
$summary = @("LABEL=$Label", "BUILDER=$env:COMPUTERNAME", "SourceCommit=$($SourceCommit.ToLowerInvariant())",
    "ARCHIVE_SHA256=$($ArchiveSha256.ToUpperInvariant())",
    'AgentMatrixProfiles=feature-debug,feature-release', 'AgentMatrixTestLegs=4') + @(Get-BuilderReceipt $builder)
if ($DiagnosticContinue) { $summary += @('LabelKind=diagnostic') }
$gatePassed = $false
$diagnosticFailed = $false
$script:diagnosticProfilesCompleted = 0
$script:diagnosticTestLegsAttempted = 0
$dotnetCommand = Get-Command dotnet.exe -ErrorAction Stop
$trustedDotnet = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'dotnet\dotnet.exe'
if ([IO.Path]::GetFullPath($dotnetCommand.Source) -ine [IO.Path]::GetFullPath($trustedDotnet) -or
    -not (Test-Path -LiteralPath $trustedDotnet -PathType Leaf) -or
    ((Get-Item -LiteralPath $trustedDotnet).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'dotnet.exe must be the non-reparse Program Files installation before any SYSTEM test is launched.'
}
$script:dotnetExe = [IO.Path]::GetFullPath($trustedDotnet)
function Invoke-DotnetGate([string] $Name, [string[]] $Arguments) {
    $log = Join-Path $out ($Name + '.txt')
    # PS 5.1 turns redirected native stderr into ErrorRecords. Let the native
    # process finish so a failed test still writes its complete log and TRX.
    $previousErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $script:dotnetExe @Arguments > $log 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousErrorPreference }
    $text = [IO.File]::ReadAllText($log)
    $warnings = [regex]::Matches($text, '(?im)\bwarning\s+[A-Z]+\d+\b').Count
    $errors = [regex]::Matches($text, '(?im)\berror\s+[A-Z]+\d+\b').Count
    $script:summary += "$Name`: exit=$code warnings=$warnings errors=$errors"
    if ($code -ne 0 -or $warnings -ne 0 -or $errors -ne 0) {
        if ($DiagnosticCompileOnly) { $script:diagnosticFailed = $true }
        else { throw ('Build gate failed: ' + $Name) }
    }
}
Push-Location $src
try {
    & $script:dotnetExe --info > (Join-Path $out 'dotnet-info.txt') 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'SDK identity query failed.' }
    foreach ($profile in @(Get-MatrixProfiles)) {
        $mode = $profile.Mode
        $configuration = $profile.Configuration
        $feature = 'true'
            $name = $mode + '-' + $configuration.ToLowerInvariant()
            $summary += "$name`: admission_evidence=$feature"
            # Existing source-contract tests locate agente/scripts by walking
            # upward from their assembly. Keep that layout in a fresh verified
            # full source copy per profile, never mixing Debug/Release outputs.
            $profileSource = Join-Path $out ('profile-src-' + $name)
            if (Test-Path -LiteralPath $profileSource) { throw 'Profile source already exists.' }
            [void][IO.Directory]::CreateDirectory($profileSource)
            Copy-Item -LiteralPath (Join-Path $src 'agente') -Destination $profileSource -Recurse
            foreach ($relative in $expected.Keys) {
                if ((Get-FileHash -LiteralPath (Join-Path $profileSource $relative) -Algorithm SHA256).Hash -ne $expected[$relative]) {
                    throw 'Profile source copy hash mismatch.'
                }
            }
            $common = @('-c', $configuration, '-warnaserror',
                ('-p:SafeUploadAdmissionEvidence=' + $feature))
            $serviceProject = Join-Path $profileSource 'agente\SafeUpload.Agent.Service\SafeUpload.Agent.Service.csproj'
            $appProject = Join-Path $profileSource 'agente\SafeUpload.Agent.App\SafeUpload.Agent.App.csproj'
            $testProject = Join-Path $profileSource 'agente\SafeUpload.Agent.Tests\SafeUpload.Agent.Tests.csproj'
            if ($DiagnosticContinue) {
                Invoke-DiagnosticProfile $name $configuration $common $serviceProject $appProject $testProject $profileSource
                foreach ($relative in $expected.Keys) {
                    if ((Get-FileHash -LiteralPath (Join-Path $profileSource $relative) -Algorithm SHA256).Hash -ne $expected[$relative]) {
                        throw 'Diagnostic profile source changed during execution.'
                    }
                }
                ++$script:diagnosticProfilesCompleted
                # Retain failed-profile outputs for diagnosis. Successful ones
                # can be reclaimed with the existing guarded cleanup.
                if (-not $diagnosticFailed) { Remove-CompletedProfileOutputs $profileSource $out $expected }
                continue
            }
            Invoke-DotnetGate ($name + '-build') (@('build', $serviceProject) + $common)
            Invoke-DotnetGate ($name + '-app-build') (@('build', $appProject) + $common)
            if ($DiagnosticCompileOnly) {
                Invoke-DotnetGate ($name + '-test-build') (@('build', $testProject) + $common)
                foreach ($relative in $expected.Keys) {
                    if ((Get-FileHash -LiteralPath (Join-Path $profileSource $relative) -Algorithm SHA256).Hash -ne $expected[$relative]) {
                        throw 'Diagnostic profile source changed during compilation.'
                    }
                }
                continue
            }
            $results = Join-Path $out ($name + '-results')
            Invoke-DotnetGate ($name + '-test-build') (@('build', $testProject) + $common)
            $testDlls = @(Get-ChildItem (Join-Path $profileSource ('agente\SafeUpload.Agent.Tests\bin\' + $configuration)) `
                -Recurse -Filter 'SafeUpload.Agent.Tests.dll')
            if ($testDlls.Count -ne 1) { throw 'Expected exactly one built test assembly.' }
            $testDll = $testDlls[0]
            [void][IO.Directory]::CreateDirectory($results)
            $systemGroup = 'FullyQualifiedName~CertificateAuthorityTests|FullyQualifiedName~TlsInspectionProxyTests|FullyQualifiedName~TrafficDiversionTests'
            $userGroup = 'FullyQualifiedName!~CertificateAuthorityTests&FullyQualifiedName!~TlsInspectionProxyTests&FullyQualifiedName!~TrafficDiversionTests'
            # VSTest's discovery-only fully-qualified-name listing is the reference inventory for the two filtered runs.
            # SAFEUPLOAD_MACHINE_TESTS only affects the MachineFact skip marker; discovery does not execute test bodies.
            $discoveryFqns = Join-Path $results 'agent-tests-discovered-fq.txt'
            if (Test-Path -LiteralPath $discoveryFqns) { throw 'Test discovery output already exists.' }
            $discoverySettings = Join-Path $results 'discovery.runsettings'
            [IO.File]::WriteAllText($discoverySettings,
                '<RunSettings><RunConfiguration><BatchSize>100000</BatchSize></RunConfiguration></RunSettings>',
                $script:Utf8ConsoleEncoding)
            $oldMachineTestSetting = $env:SAFEUPLOAD_MACHINE_TESTS
            try {
                $env:SAFEUPLOAD_MACHINE_TESTS = '1'
                # VSTest deduplicates FQNs only within a discovery batch. A
                # theory spanning its default 1,000-case boundary repeats its
                # method name. Keep the inventory-uniqueness gate and collect
                # this bounded matrix in one batch instead of normalizing it.
                Invoke-DotnetGate ($name + '-tests-discovery-list') @('vstest', $testDll.FullName,
                    '/ListTests', ("/Settings:$discoverySettings"))
                Invoke-DotnetGate ($name + '-tests-discovery-fqns') @('vstest', $testDll.FullName,
                    '/ListFullyQualifiedTests', ("/Settings:$discoverySettings"), ("/ListTestsTargetPath:$discoveryFqns"))
            } finally {
                if ($null -eq $oldMachineTestSetting) { Remove-Item Env:SAFEUPLOAD_MACHINE_TESTS -ErrorAction SilentlyContinue }
                else { $env:SAFEUPLOAD_MACHINE_TESTS = $oldMachineTestSetting }
            }
            if (-not (Test-Path -LiteralPath $discoveryFqns -PathType Leaf) -or (Get-Item -LiteralPath $discoveryFqns).Length -le 0 -or
                -not (Test-Path -LiteralPath (Join-Path $out ($name + '-tests-discovery-list.txt')) -PathType Leaf) -or
                (Get-Item -LiteralPath (Join-Path $out ($name + '-tests-discovery-list.txt'))).Length -le 0) {
                throw ('VSTest full discovery produced no test names: ' + $name)
            }
            $userIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $userSid = $userIdentity.User.Value
            if ($userSid -eq 'S-1-5-18' -or $userIdentity.Name -notmatch '(?i)\\vika$') {
                throw ('The unprivileged test leg is not running as the expected builder SSH account: ' + $userIdentity.Name)
            }
            $summary += "${name}-tests-user-identity: name=$($userIdentity.Name) sid=$userSid"
            $oldUserMachineSetting = $env:SAFEUPLOAD_MACHINE_TESTS
            try {
                Remove-Item Env:SAFEUPLOAD_MACHINE_TESTS -ErrorAction SilentlyContinue
                Invoke-DotnetGate ($name + '-tests-user') @('vstest', $testDll.FullName,
                    ("/TestCaseFilter:$userGroup"), '/Logger:trx;LogFileName=agent-tests-user.trx', ("/ResultsDirectory:$results"))
            } finally {
                if ($null -eq $oldUserMachineSetting) { Remove-Item Env:SAFEUPLOAD_MACHINE_TESTS -ErrorAction SilentlyContinue }
                else { $env:SAFEUPLOAD_MACHINE_TESTS = $oldUserMachineSetting }
            }
            $systemLog = Join-Path $out ($name + '-tests-system.txt')
            $systemExit = Invoke-SystemProcess -FilePath $script:dotnetExe `
                -ArgumentLine ('vstest "' + $testDll.FullName + '" /TestCaseFilter:"' + $systemGroup + '" /Logger:"trx;LogFileName=agent-tests-system.trx" /ResultsDirectory:"' + $results + '"') `
                -WorkingDirectory $testDll.DirectoryName -StdoutPath $systemLog `
                -Environment @{ SAFEUPLOAD_MACHINE_TESTS = '1' }
            $systemText = [IO.File]::ReadAllText($systemLog)
            $systemWarnings = [regex]::Matches($systemText, '(?im)\bwarning\s+[A-Z]+\d+\b').Count
            $systemErrors = [regex]::Matches($systemText, '(?im)\berror\s+[A-Z]+\d+\b').Count
            if ([regex]::Matches($systemText, '(?m)^SYSTEM_TEST_TASK_SID=S-1-5-18\r?$').Count -ne 1) { throw ('SYSTEM identity evidence missing or duplicated: ' + $name) }
            $summary += "${name}-tests-system-identity: S-1-5-18"
            $summary += "${name}-tests-system: exit=$systemExit warnings=$systemWarnings errors=$systemErrors"
            if ($systemExit -ne 0 -or $systemWarnings -ne 0 -or $systemErrors -ne 0) { throw ('SYSTEM tests failed: ' + $name) }
            [void](Assert-TrxLeg (Join-Path $results 'agent-tests-user.trx') ($name + '/user'))
            [void](Assert-TrxLeg (Join-Path $results 'agent-tests-system.trx') ($name + '/SYSTEM'))
            Merge-TrxFiles -Paths @((Join-Path $results 'agent-tests-user.trx'), (Join-Path $results 'agent-tests-system.trx')) `
                -Destination (Join-Path $results 'agent-tests.trx')
            Get-Content -LiteralPath (Join-Path $out ($name + '-tests-user.txt')), $systemLog | `
                Set-Content -LiteralPath (Join-Path $out ($name + '-tests.txt')) -Encoding UTF8
            $summary += "${name}-tests: exit=0 warnings=0 errors=0"
            [xml] $trx = [IO.File]::ReadAllText((Join-Path $results 'agent-tests.trx'))
            $counters = $trx.TestRun.ResultSummary.Counters
            if ([int]$counters.total -le 0 -or $counters.passed -ne $counters.total -or
                $counters.executed -ne $counters.total) { throw ('Incomplete test run: ' + $name) }
            foreach ($field in @('failed', 'error', 'timeout', 'aborted', 'notExecuted', 'inconclusive')) {
                if ([int]$counters.$field -ne 0) { throw ('Unsuccessful test run: ' + $name + '/' + $field) }
            }
            $summary += "$name`: tests_passed=$($counters.passed)"
            if ($configuration -eq 'Release') {
                $publish = Join-Path $out ($name + '-publish')
                Invoke-DotnetGate ($name + '-publish') (@('publish', $serviceProject,
                    '-r', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=true',
                    '-p:IncludeNativeLibrariesForSelfExtract=true', '-o', $publish) + $common)
                $publishFiles = @(Get-ChildItem -LiteralPath $publish -Recurse -File)
                $serviceExecutable = Join-Path $publish 'SafeUpload.Agent.Service.exe'
                if ($publishFiles.Count -eq 0 -or -not (Test-Path -LiteralPath $serviceExecutable -PathType Leaf) -or
                    (Get-Item -LiteralPath $serviceExecutable).Length -le 0) {
                    throw ('Publish output is empty or missing a nonempty service executable: ' + $name)
                }
                $publishFiles | Sort-Object FullName | ForEach-Object {
                    (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash + '  ' + $_.FullName.Substring($publish.Length + 1).Replace('\', '/')
                } | Set-Content (Join-Path $out ($name + '-package-manifest.txt')) -Encoding UTF8
                $summary += "$name`: package_manifest_sha256=$((Get-FileHash -LiteralPath (Join-Path $out ($name + '-package-manifest.txt')) -Algorithm SHA256).Hash)"
                $package = Join-Path $out ($name + '-service-publish.zip')
                [IO.Compression.ZipFile]::CreateFromDirectory($publish, $package)
                if ((Get-Item -LiteralPath $package).Length -le 0) { throw ('Publish package is empty: ' + $name) }
                $summary += "$name`: package_sha256=$((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash)"
                $summary += "$name`: exe_sha256=$((Get-FileHash -LiteralPath $serviceExecutable -Algorithm SHA256).Hash)"
            }
            foreach ($relative in $expected.Keys) {
                if ((Get-FileHash -LiteralPath (Join-Path $profileSource $relative) -Algorithm SHA256).Hash -ne $expected[$relative]) {
                    throw 'Profile source changed during build.'
                }
            }
            # All test processes have ended, Release packages are retained and
            # source inputs are rechecked. Bound disk use to the current profile.
            Remove-CompletedProfileOutputs $profileSource $out $expected
    }
    # The build outputs live outside src; recheck all captured inputs after execution.
    foreach ($file in $seenFiles) {
        $relative = $file.FullName.Substring($src.Length + 1).Replace('\', '/')
        if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $expected[$relative]) {
            throw 'Source changed during build.'
        }
    }
    $gatePassed = -not $diagnosticFailed
} finally {
    Pop-Location
    if ($DiagnosticContinue) {
        $summary += "DiagnosticProfilesCompleted=$script:diagnosticProfilesCompleted"
        $summary += "DiagnosticTestLegsAttempted=$script:diagnosticTestLegsAttempted"
    }
    $summary += @(Get-MatrixCompletionRows $gatePassed $DiagnosticContinue.IsPresent $DiagnosticCompileOnly.IsPresent $builder.ParityCheck)
    $summary += 'BUILD_END_UTC=' + [DateTime]::UtcNow.ToString('o')
    $summary | Set-Content (Join-Path $out 'summary.txt') -Encoding UTF8
    $summary | Write-Output
}
if (-not $gatePassed) { throw 'Agent matrix gate incomplete.' }
