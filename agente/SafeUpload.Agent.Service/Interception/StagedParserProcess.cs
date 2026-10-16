using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// A parser resource container, not a security sandbox. It receives a read-only duplicated
/// snapshot handle; policy/publication/hand-back authority remains in the parent service.
/// </summary>
internal sealed class StagedParserProcess(long memoryBytes) : IStagedParser
{
    private const int MaximumMessageBytes = 8 * 1024 * 1024;
    private sealed record Request(Guid Nonce, long Handle, string Extension, int MaximumMiB, Category[] Categories);
    private sealed record Response(Guid Nonce, StagedParserResult Result);

    public async Task<IReadOnlyList<Finding>> InspectAsync(string extension, Stream input, Policy policy, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows() || memoryBytes < 64 * 1024 * 1024 || memoryBytes > 2L * 1024 * 1024 * 1024)
            throw new StagedParserFailureException("inspection_limit");
        SafeFileHandle source = input switch
        {
            StagedInspectionSnapshot.ReadLease lease => lease.Handle,
            FileStream file => file.SafeFileHandle,
            _ => throw new IOException("The parser requires an exact held file lease.")
        };
        var start = new ProcessStartInfo
        {
            FileName = Environment.ProcessPath!, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true
        };
        if (Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            // Framework-dependent development host only; the shipped single-file service runs itself (IL3000-safe).
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, typeof(Program).Assembly.GetName().Name + ".dll"));
        start.ArgumentList.Add("--staged-parser");
        start.Environment["DOTNET_GCHeapHardLimit"] = (memoryBytes / 2).ToString("X");
        using var job = ParserJob.Create(memoryBytes);
        using var process = Process.Start(start) ?? throw new IOException("Could not start the bounded parser.");
        try
        {
            // The child reads only a small fixed-size request until assignment. No parser or
            // source handle is supplied before the job limits have been successfully installed.
            job.Assign(process);
            if (!DuplicateHandle(GetCurrentProcess(), source, process.Handle, out IntPtr remote,
                0x00120089, false, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
            Guid nonce = Guid.NewGuid();
            await WriteFrameAsync(process.StandardInput.BaseStream,
                new Request(nonce, remote.ToInt64(), extension, policy.MaxFileSizeMb, policy.ActiveCategories.ToArray()), token)
                .ConfigureAwait(false);
            process.StandardInput.Close();
            Response response = await ReadFrameAsync<Response>(process.StandardOutput.BaseStream, token).ConfigureAwait(false);
            // No truncated result, nonzero exit, nonce mismatch or trailing output can approve.
            byte[] trailing = new byte[1];
            if (await process.StandardOutput.BaseStream.ReadAsync(trailing, token).ConfigureAwait(false) != 0)
                throw new IOException("The parser returned trailing data.");
            await process.WaitForExitAsync(token).ConfigureAwait(false);
            if (process.ExitCode != 0 || response.Nonce != nonce || response.Result.Findings.Count > 16_384)
                throw new IOException("The parser result is incomplete.");
            if (response.Result.Failure is { } failure)
                throw new StagedParserFailureException(AllowedFailure(failure) ? failure : "parse_error:worker");
            if (response.Result.Findings.Any(f => !policy.ActiveCategories.Contains(f.Category) ||
                f.MaskedSnippet.Length > 4096 || f.MemberName?.Length > 1024 * 1024))
                throw new IOException("The parser returned invalid findings.");
            return response.Result.Findings;
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            // Keep the exact input and the Core worker slot alive until termination is proven.
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    internal static async Task<int> RunWorkerAsync()
    {
        try
        {
            Request request = await ReadFrameAsync<Request>(Console.OpenStandardInput(), CancellationToken.None).ConfigureAwait(false);
            if (request.Nonce == Guid.Empty || request.Handle == 0 || request.Extension.Length > 16 ||
                request.Categories.Length is < 1 or > 32 || request.MaximumMiB <= 0) return 2;
            using var handle = new SafeFileHandle(new IntPtr(request.Handle), ownsHandle: true);
            await using var source = new FileStream(handle, FileAccess.Read, 64 * 1024, isAsync: false);
            var result = await StagedParserExecution.InspectAsync(source, request.Extension,
                request.MaximumMiB, request.Categories.ToHashSet(), CancellationToken.None).ConfigureAwait(false);
            await WriteFrameAsync(Console.OpenStandardOutput(), new Response(request.Nonce, result), CancellationToken.None)
                .ConfigureAwait(false);
            return 0;
        }
        catch { return 2; }
    }

    private static bool AllowedFailure(string failure) => failure is "file_too_large" or "unsupported_format" or
        "archive_encrypted" or "archive_unsupported_member" or "archive_unsupported_structure" or
        "archive_7z_unavailable" or "inspection_limit" or "parse_error:worker";
    private static async Task WriteFrameAsync<T>(Stream output, T value, CancellationToken token)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        if (bytes.Length > MaximumMessageBytes) throw new IOException("The parser message exceeds its output budget.");
        byte[] header = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
        await output.WriteAsync(header, token).ConfigureAwait(false);
        await output.WriteAsync(bytes, token).ConfigureAwait(false);
        await output.FlushAsync(token).ConfigureAwait(false);
    }
    private static async Task<T> ReadFrameAsync<T>(Stream input, CancellationToken token)
    {
        byte[] header = new byte[4]; await input.ReadExactlyAsync(header, token).ConfigureAwait(false);
        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is < 1 or > MaximumMessageBytes) throw new IOException("Invalid parser message length.");
        byte[] bytes = new byte[length]; await input.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(bytes) ?? throw new IOException("Missing parser message.");
    }

    private sealed class ParserJob : IDisposable
    {
        private readonly SafeFileHandle _handle;
        private ParserJob(SafeFileHandle handle) => _handle = handle;
        internal static ParserJob Create(long bytes)
        {
            var handle = CreateJobObjectW(IntPtr.Zero, null);
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var limits = new ExtendedLimits();
                limits.Basic.LimitFlags = 0x2000 | 0x100 | 0x8; // KILL_ON_JOB_CLOSE, PROCESS_MEMORY, ACTIVE_PROCESS.
                limits.Basic.ActiveProcessLimit = 1;
                limits.ProcessMemoryLimit = (UIntPtr)(ulong)bytes;
                if (!SetInformationJobObject(handle, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return new(handle);
            }
            catch { handle.Dispose(); throw; }
        }
        internal void Assign(Process process)
        {
            if (!AssignProcessToJobObject(_handle, process.Handle)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public void Dispose() => _handle.Dispose();
    }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters
    { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits
    {
        public BasicLimits Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, SafeFileHandle source, IntPtr targetProcess,
        out IntPtr target, uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int informationClass, ref ExtendedLimits limits, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
}
