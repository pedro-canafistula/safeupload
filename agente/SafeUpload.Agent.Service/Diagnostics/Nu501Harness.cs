#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Diagnostics;

// One shot, original service subject, empty installed product roots only.
// No policy setter, public destination, actor, fabricated sender or port exists here.
internal sealed class Nu501Harness(FilterPort port, Action requireIdle)
{
    private readonly List<Nu501Step> _steps = new();
    private readonly Stopwatch _elapsed = Stopwatch.StartNew();
    private readonly string _run = Guid.NewGuid().ToString("N");
    private ulong _request;
    private (ulong Cookie, Guid DriverInstance) _pair;
    private volatile bool _held;
    private readonly Nu501NativeSender _native = new();
    private readonly List<SafeFileHandle> _roots = new();
    private readonly HashSet<ulong> _childIds = new();
    private readonly List<StagedMetadataStore.Transaction> _transactions = new();
    private StagedMetadataStore? _store;
    private Nu501Latch? _legacyLatch;

    private void Check(string name, bool passed, string detail = "", ulong id = 0, int hr = 0, string status = "Assert")
    {
        _steps.Add(new(name, id, status, hr, _elapsed.Elapsed.TotalMilliseconds, _held, passed, detail));
        if (!passed) throw new InvalidDataException(name + ": " + detail);
    }
    private static byte[] Bytes<T>(T value) where T : unmanaged
    { byte[] bytes = new byte[Marshal.SizeOf<T>()]; MemoryMarshal.Write(bytes, in value); return bytes; }
    private byte[] Request<T>(ResourceControlOpcodeV32 opcode, T body, out ulong id) where T : unmanaged
    {
        id = ++_request;
        var header = new ResourceControlHeaderV32 { Version = 18, StructSize = (uint)(64 + Marshal.SizeOf<T>()),
            Command = 36, ResourceVersion = 32, Opcode = opcode, ControlRequestId = id,
            ConnectionCookie = _pair.Cookie, DriverInstance = _pair.DriverInstance, PayloadBytes = (uint)Marshal.SizeOf<T>() };
        return [.. Bytes(header), .. Bytes(body)];
    }
    private T Reply<T>(string name, ResourceSendResult result, ResourceControlOpcodeV32 opcode, ulong id) where T : unmanaged
    {
        int length = 64 + Marshal.SizeOf<T>();
        bool valid = result is { Status: ResourceSendStatus.Completed, HResult: 0 } && result.BytesReturned == length && result.Output?.Length == length;
        if (valid)
        {
            var h = MemoryMarshal.Read<ResourceControlHeaderV32>(result.Output);
            valid = ResourceControlWireV32.HeaderValid(h, length, opcode, length - 64) && h.ControlRequestId == id &&
                h.ConnectionCookie == _pair.Cookie && h.DriverInstance == _pair.DriverInstance;
        }
        Check(name + "Wire", valid, "Exact header/cookie/driver/request/length", id, result.HResult, result.Status.ToString());
        return MemoryMarshal.Read<T>(result.Output.AsSpan(64));
    }
    private Task<ResourceSendResult> Send<T>(ResourceControlOpcodeV32 opcode, T body, int output, CancellationToken token, out ulong id) where T : unmanaged
    {
        byte[] bytes = Request(opcode, body, out id);
        return port.TrySendResourceAsync(ResourceSendClass.MetadataProgress, () => bytes, output, token);
    }
    private static Guid Transaction(bool growth)
    { byte[] bytes = Guid.NewGuid().ToByteArray(); bytes[15] = (byte)((bytes[15] & 0x7f) | (growth ? 0x80 : 0)); return new(bytes); }
    private static unsafe ResourceRegisterChildV32 Child(ulong root, Guid tx, MetadataRoleV32 role, string leaf) 
    {
        var child = new ResourceRegisterChildV32 { RootId = root, TransactionId = tx, Role = role,
            AccessMask = MetadataStoreRoles.Access(role), MaximumLogicalBytes = (ulong)MetadataStoreRoles.Maximum(role),
            LeafBytes = (uint)(leaf.Length * 2), CreateDisposition = 2 };
        for (int i = 0; i < leaf.Length; i++) child.Leaf[i] = leaf[i];
        return child;
    }
    private async Task<ulong> Register(string name, ResourceRegisterChildV32 child, CancellationToken token)
    {
        var result = await Send(ResourceControlOpcodeV32.RegisterChildIntent, child, 80, token, out ulong id).ConfigureAwait(false);
        var body = Reply<ResourceRegisterChildReplyV32>(name, result, ResourceControlOpcodeV32.RegisterChildIntent, id);
        Check(name, body.Result == 1 && body.Reserved == 0 && body.ChildIntentId != 0 && _childIds.Add(body.ChildIntentId),
            $"Unique successful child ID={body.ChildIntentId}", id, result.HResult);
        return body.ChildIntentId;
    }
    private async Task Busy(string name, ResourceRegisterChildV32 child, CancellationToken token)
    {
        var result = await Send(ResourceControlOpcodeV32.RegisterChildIntent, child, 80, token, out ulong id).ConfigureAwait(false);
        // FltLib maps STATUS_DEVICE_BUSY through RtlNtStatusToDosError.
        int expected = HResultFromNtStatus(unchecked((int)0x80000011));
        Check(name, result.Status == ResourceSendStatus.Completed && result.HResult == expected &&
            result.BytesReturned == 0, "Kernel Busy; managed admission completed", id, result.HResult, result.Status.ToString());
    }
    private static int HResultFromNtStatus(int status) => unchecked((int)(0x80070000u | RtlNtStatusToDosError(status)));
    [DllImport("ntdll.dll")] private static extern uint RtlNtStatusToDosError(int status);

    internal async Task<Nu501Receipt> RunAsync(CancellationToken stoppingToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(90));
        CancellationToken token = deadline.Token;
        Task? lease = null, legacy = null;
        Exception? failure = null;
        try
        {
            requireIdle(); Check("Idle", true, "Empty fixed roots and accepted zero-destination policy; component mode has no workers");
            ResourceControlWireV32.Verify();
            var agent = Guid.NewGuid();
            var negotiate = new ResourceNegotiateV32 { AgentInstance = agent, OfferedCapabilities = 255, RequiredCapabilities = 255,
                AllocationLimit = 8, SidLimit = 4, GrowthWorkers = 8, GrowthQueue = 32, LifecycleWorkers = 2, LifecycleQueue = 32, Phase = 1 };
            byte[] probe = Request(ResourceControlOpcodeV32.Negotiate, negotiate, out ulong probeId);
            var probed = port.Nu501Bootstrap(probe, 176);
            bool probeValid = probed.Status == ResourceSendStatus.Completed && probed.HResult == 0 && probed.BytesReturned == 176 &&
                ResourceControlWireV32.TryReadProbe(probed.Output!, probeId, agent, out _);
            Check("Probe", probeValid, "Real main bootstrap; zero grants", probeId, probed.HResult);
            ResourceControlWireV32.TryReadProbe(probed.Output!, probeId, agent, out _pair);
            int pairHr = port.Nu501Pair(new() { ConnectionCookie = _pair.Cookie, DriverInstance = _pair.DriverInstance }, _native);
            Check("Pair", pairHr == 0, "Real original service main/resource pair", probeId, pairHr);
            negotiate.Phase = 2; negotiate.ReadinessEpoch = Guid.NewGuid();
            var commit = Request(ResourceControlOpcodeV32.Negotiate, negotiate, out ulong commitId);
            var committed = port.Nu501Bootstrap(commit, 176);
            var grant = Reply<ResourceNegotiateReplyV32>("Commit", committed, ResourceControlOpcodeV32.Negotiate, commitId);
            Check("CommitNotReady", grant.Result == 2 && grant.AgentInstance == agent && grant.ReadinessEpoch == negotiate.ReadinessEpoch &&
                grant.Mode == 0 && grant.AcceptedCapabilities == 0 && grant.BootDomain == Guid.Empty && grant.GrowthWaitTicks == 0 &&
                committed.Output!.AsSpan(136).IndexOfAnyExcept((byte)0) < 0, "NotReady, all authority fields zero", commitId);

            await ReleaseControls(token).ConfigureAwait(false);
            using var latch = new Nu501Latch(TimeSpan.FromSeconds(60), token);
            _legacyLatch = latch;
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            lease = port.HoldLegacySendForTesting(() => { _held = true; entered.SetResult(); latch.Wait(); _held = false; });
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
            Check("LeaseHeld", _held && !latch.Released, "Latch signaled strictly inside EnterSend lease");
            var attempted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            legacy = Task.Run(() => { attempted.SetResult(); return port.SendAdmissionEvidence(AdmissionEvidenceCommand.EpochStatus); });
            await attempted.Task.WaitAsync(token).ConfigureAwait(false);
            await WaitUntil(() => port.Nu501Lifetime.Active >= 2, token).ConfigureAwait(false);
            await Task.Delay(100, token).ConfigureAwait(false);
            Check("LegacyBlocked", !legacy.IsCompleted && _held && !latch.Released, "Independent real legacy send accepted and blocked on main gate");
            ulong[] roots = new ulong[4];
            string[] paths = [@"C:\ProgramData\SafeUpload\staging", @"C:\ProgramData\SafeUpload\staging\.space-reservations",
                @"C:\ProgramData\SafeUpload\staging-journal", @"C:\ProgramData\SafeUpload\staging-journal\completed"];
            StagedMetadataStoreNative? storeNative = null;
            for (int i = 0; i < 4; i++)
            {
                token.ThrowIfCancellationRequested();
                var handle = StagedMetadataStoreNative.OpenAnchor(paths[i]); _roots.Add(handle);
                var identity = StagedMetadataStoreNative.Identity(handle);
                // Capture geometry/security BEFORE registering this FILE_OBJECT;
                // root routing deliberately permits fewer query classes.
                if (i == 2) storeNative = new StagedMetadataStoreNative(handle, identity);
                var root = new ResourceRegisterRootV32 { Role = (uint)i + 1, Handle = (ulong)handle.DangerousGetHandle().ToInt64(),
                    Identity = new() { VolumeSerialNumber = identity.VolumeSerialNumber, FileIdHigh = identity.FileIdHigh, FileIdLow = identity.FileIdLow },
                    ParentRootId = i is 1 or 3 ? roots[i - 1] : 0, SecurityContractVersion = 1 };
                var sent = await Send(ResourceControlOpcodeV32.RegisterRoot, root, 104, token, out ulong id).ConfigureAwait(false);
                var reply = Reply<ResourceRegisterRootReplyV32>($"Root{i + 1}", sent, ResourceControlOpcodeV32.RegisterRoot, id);
                roots[i] = reply.RootId;
                Check($"Root{i + 1}", reply.Result == 1 && reply.Reserved == 0 && reply.RootId != 0 &&
                    reply.Identity.Equals(root.Identity) && !roots.Take(i).Contains(reply.RootId) && _held && !latch.Released, "Fixed installed root and exact object identity", id);
            }
            // Use the exact registered FILE_OBJECT as RootDirectory. A new
            // path open with the same identity would miss metadata routing.
            var native = storeNative ?? throw new InvalidOperationException("No captured native store anchor.");
            _store = new(native, new(64 * 1024 * 1024, 64 * 1024 * 1024, 128 * 1024 * 1024, 128));
            Guid transaction = Transaction(false);
            for (int i = 0; i < 4; i++)
            {
                string leaf = Guid.NewGuid().ToString("N") + ".json.new";
                byte[] bytes = Encoding.UTF8.GetBytes("N-U5-01 opaque component bytes " + _run + i);
                var intent = Child(roots[2], transaction, MetadataRoleV32.ManifestNew, leaf);
                intent.MaximumLogicalBytes = (ulong)bytes.Length;
                ulong childId = await Register($"Child{i}", intent, token).ConfigureAwait(false);
                var plan = Plan(native, transaction, (ulong)i + 1, MetadataRoleV32.ManifestNew, bytes.Length);
                var tx = _store.TryClaim(plan, leaf, leaf, bytes, MetadataPhysicalClass.HotJournal) ?? throw new IOException("Unexpected local Busy");
                _transactions.Add(tx);
                var result = _store.Execute(tx, step =>
                {
                    token.ThrowIfCancellationRequested();
                    var receipt = tx.Receipts.Last(r => r.Step == step);
                    Check($"Store{i}.{step}", receipt.Native.Success && _held && !latch.Released,
                        $"child={childId}; native={receipt.Native.Status}; information={receipt.Native.Information}", childId, receipt.Native.Status, "Native");
                });
                var observed = native.Query(tx.Output!);
                Check($"Store{i}", result.Disposition == MetadataStoreDisposition.Committed && observed.EndOfFile == bytes.Length &&
                    observed.Links == 1 && !observed.DeletePending && (observed.Identity.FileIdLow | observed.Identity.FileIdHigh) != 0 && _held && !latch.Released,
                    $"child={childId}; identity={observed.Identity}; EOF={observed.EndOfFile}; allocation={observed.AllocationSize}", childId);
            }
            await Busy("ChildCreditsBusy", Child(roots[2], transaction, MetadataRoleV32.ManifestNew, Guid.NewGuid().ToString("N") + ".json.new"), token).ConfigureAwait(false);
            for (int i = 0; i < 7; i++) await Register($"OtherPool{i}", Child(roots[2], Transaction(false), MetadataRoleV32.ManifestNew,
                Guid.NewGuid().ToString("N") + ".json.new"), token).ConfigureAwait(false);
            await Busy("OtherPoolBusy", Child(roots[2], Transaction(false), MetadataRoleV32.ManifestNew, Guid.NewGuid().ToString("N") + ".json.new"), token).ConfigureAwait(false);
            for (int i = 0; i < 8; i++) await Register($"GrowthPool{i}", Child(roots[0], Transaction(true), MetadataRoleV32.CompanionNew,
                Guid.NewGuid().ToString("N") + ".1.space.new"), token).ConfigureAwait(false);
            await Busy("GrowthPoolBusy", Child(roots[0], Transaction(true), MetadataRoleV32.CompanionNew, Guid.NewGuid().ToString("N") + ".1.space.new"), token).ConfigureAwait(false);
            var malformed = Child(roots[2], Transaction(false), MetadataRoleV32.ManifestNew, "../bad");
            var bad = await Send(ResourceControlOpcodeV32.RegisterChildIntent, malformed, 80, token, out ulong badId).ConfigureAwait(false);
            Check("Malformed", bad.Status == ResourceSendStatus.Completed && bad.HResult == HResultFromNtStatus(unchecked((int)0xC000000D)) && bad.BytesReturned == 0,
                "Malformed tuple is native INVALID_PARAMETER", badId, bad.HResult);
            var refused = Child(ulong.MaxValue, Transaction(false), MetadataRoleV32.ManifestNew, Guid.NewGuid().ToString("N") + ".json.new");
            var refusal = await Send(ResourceControlOpcodeV32.RegisterChildIntent, refused, 80, token, out ulong refusedId).ConfigureAwait(false);
            var refusedReply = Reply<ResourceRegisterChildReplyV32>("Refused", refusal, ResourceControlOpcodeV32.RegisterChildIntent, refusedId);
            Check("Refused", refusedReply.Result == 2 && refusedReply.Reserved == 0 && refusedReply.ChildIntentId == 0, "Well-formed invalid root refuses with no authority", refusedId);
            LocalStoreAdmission(native);
            await LocalSendAdmission(roots[2], token).ConfigureAwait(false);
            Check("HeldProgressComplete", _held && !latch.Released && !legacy.IsCompleted, "All resource/native work completed before release");
            latch.Release(); await lease.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
            await legacy.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
            var legacyReply = await ((Task<AdmissionEvidenceReply>)legacy).ConfigureAwait(false);
            Check("LegacyReleased", !_held && !latch.Expired && legacyReply.IsWirePayloadValid, "Real main send returned after explicit release", 0, legacyReply.HResult);
            // Close all metadata child handles before disconnect; pending intents
            // are kernel custody until the real group disconnect retires them.
            foreach (var tx in _transactions) tx.Dispose(); _transactions.Clear();
            Check("ChildrenClosed", true, "Four store transaction handles closed after their native calls returned");
            await Disconnect(token).ConfigureAwait(false);
        }
        catch (Exception error) { failure = error; }
        finally
        {
            _legacyLatch?.Release();
            // Native synchronous calls are joined, never abandoned on timeout.
            // The external host stops the row on a hang; no timeout frees memory.
            if (lease is not null) try { await lease.ConfigureAwait(false); } catch (Exception error) { failure ??= error; }
            if (legacy is not null) try { await legacy.ConfigureAwait(false); } catch (Exception error) { failure ??= error; }
            _native.BeforeNative = null;
            foreach (var tx in _transactions) tx.Dispose();
            _store?.Dispose();
            foreach (var root in _roots) root.Dispose();
        }
        var receipt = new Nu501Receipt("SafeUpload.N-U5-01.v1", _run, failure is null ? "PASS" : "FAIL",
            "Native component only; no protected boot, epoch drain, actor/growth or qualification", _steps,
            failure is null ? null : failure.GetType().Name + ": " + failure.Message);
        return receipt.ValidPass ? receipt : receipt with { Verdict = "FAIL", Failure = receipt.Failure ?? "Incomplete receipt" };
    }

    private static BoundedOutputPlan Plan(StagedMetadataStoreNative native, Guid tx, ulong incarnation, MetadataRoleV32 role, int length) =>
        new(role, new(tx, incarnation), length, native.Alignment, native.AllocationUnit,
            BoundedOutputPlan.Round(length, native.Alignment), BoundedOutputPlan.Round(BoundedOutputPlan.Round(length, native.Alignment), native.AllocationUnit), null, MetadataStoreRoles.Maximum(role));

    private void LocalStoreAdmission(StagedMetadataStoreNative native)
    {
        // Uses the same actual store and native geometry. Claims issue no I/O.
        var claims = new List<StagedMetadataStore.Transaction>();
        try
        {
            for (int i = 0; i < 4; i++) claims.Add(Claim(false)); // four already active
            for (int i = 0; i < 8; i++) claims.Add(Claim(true));
            var plan = Plan(native, Transaction(false), 1, MetadataRoleV32.ManifestNew, 1);
            string leaf = Guid.NewGuid().ToString("N") + ".json.new";
            Check("LocalStoreBusy", _store!.TryClaim(plan, leaf, leaf, new byte[1], MetadataPhysicalClass.HotJournal) is null,
                "8 other + 8 growth local transactions; refusal before child/open/native work");
        }
        finally { foreach (var claim in claims) claim.Dispose(); }
        StagedMetadataStore.Transaction Claim(bool growth)
        {
            var role = growth ? MetadataRoleV32.CompanionNew : MetadataRoleV32.ManifestNew;
            string leaf = Guid.NewGuid().ToString("N") + (growth ? ".1.space.new" : ".json.new");
            return _store!.TryClaim(Plan(native, Transaction(growth), 1, role, 1), leaf, leaf, new byte[1], MetadataPhysicalClass.HotJournal, growth)
                ?? throw new IOException("Local claim refused before the documented capacity");
        }
    }

    private async Task LocalSendAdmission(ulong root, CancellationToken token)
    {
        using var release = new Nu501Latch(TimeSpan.FromSeconds(15), token);
        int entered = 0;
        _native.BeforeNative = () => { Interlocked.Increment(ref entered); release.Wait(); };
        var sends = new List<Task<ResourceSendResult>>();
        try
        {
            for (int i = 0; i < 8; i++) sends.Add(Send(ResourceControlOpcodeV32.RegisterChildIntent,
                Child(root, Transaction(false), MetadataRoleV32.ManifestNew, "bad"), 80, token, out _));
            await WaitUntil(() => Volatile.Read(ref entered) == 8, token).ConfigureAwait(false);
            bool constructed = false;
            var busy = await port.TrySendResourceAsync(ResourceSendClass.MetadataProgress, () => { constructed = true; return []; }, 80, token).ConfigureAwait(false);
            Check("LocalSendBusy", busy.Status == ResourceSendStatus.Busy && busy.HResult == 0 && !constructed &&
                port.ResourceSendPopulation(ResourceSendClass.MetadataProgress) == (8, 0), "Local Busy; no input construction or ninth native call");
        }
        finally { release.Release(); await Task.WhenAll(sends).ConfigureAwait(false); _native.BeforeNative = null; }
        Check("LocalSendsReturned", !release.Expired && sends.All(t => t.Result.Status == ResourceSendStatus.Completed &&
            t.Result.HResult == HResultFromNtStatus(unchecked((int)0xC000000D)) && t.Result.BytesReturned == 0), "Eight real adapter calls returned native malformed-tuple refusals");
    }

    private async Task ReleaseControls(CancellationToken token)
    {
        foreach (string cause in new[] { "Timeout", "Failure", "Cancellation" })
        {
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(token);
            using var release = new Nu501Latch(TimeSpan.FromSeconds(5), cancel.Token);
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Task held = port.HoldLegacySendForTesting(() => { _held = true; entered.SetResult(); release.Wait(); _held = false; });
            Task<AdmissionEvidenceReply>? pending = null;
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
                pending = Task.Run(() => port.SendAdmissionEvidence(AdmissionEvidenceCommand.EpochStatus));
                await WaitUntil(() => port.Nu501Lifetime.Active == 2, token).ConfigureAwait(false);
                Check($"Release{cause}Held", _held && !release.Released && !pending.IsCompleted,
                    "Real main lease plus an independently admitted legacy send");
                if (cause == "Cancellation") cancel.Cancel();
                if (cause == "Failure")
                {
                    try { throw new IOException("Expected managed harness fault; no native success is substituted"); }
                    catch (IOException) { }
                    finally { release.Release(); }
                }
                // Timeout has no explicit release: the dedicated watchdog must
                // unblock the real EnterSend lease without any native progress.
                await held.WaitAsync(TimeSpan.FromSeconds(7), token).ConfigureAwait(false);
                AdmissionEvidenceReply reply = await pending.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
                Check($"Release{cause}Returned", !_held && release.Released && release.Expired == (cause == "Timeout") && reply.IsWirePayloadValid,
                    "Observed real legacy native return after " + cause + " release", 0, reply.HResult);
            }
            finally
            {
                release.Release();
                await held.ConfigureAwait(false);
                if (pending is not null) await pending.ConfigureAwait(false);
            }
        }
    }

    private async Task Disconnect(CancellationToken token)
    {
        using var revoke = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var mainRelease = new Nu501Latch(TimeSpan.FromSeconds(5), revoke.Token);
        var mainEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task main = port.HoldLegacySendForTesting(() => { _held = true; mainEntered.SetResult(); mainRelease.Wait(); _held = false; });
        using var release = new Nu501Latch(TimeSpan.FromSeconds(5), token);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _native.BeforeNative = () => { entered.SetResult(); release.Wait(); };
        long returned = Volatile.Read(ref _native.Returned);
        Task<ResourceSendResult>? call = null;
        Task? disconnect = null;
        ulong id = 0;
        var elapsed = Stopwatch.StartNew();
        try
        {
            await mainEntered.Task.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
            call = Send(ResourceControlOpcodeV32.RegisterChildIntent,
                Child(ulong.MaxValue, Transaction(false), MetadataRoleV32.ManifestNew, "bad"), 80, token, out id);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
            disconnect = Task.Run(port.Dispose);
            await WaitUntil(() => !port.Nu501Lifetime.Accepting, token).ConfigureAwait(false);
            var state = port.Nu501Lifetime;
            Check("DisconnectRetains", !disconnect.IsCompleted && !call.IsCompleted && state.HandlesOpen && state.Active == 2 &&
                _held && Volatile.Read(ref _native.Returned) == returned,
                "Disconnect during admitted real-adapter call with real main lease held; handles/buffers retained", id);
            revoke.Cancel();
            await main.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
            Check("RevokeLatchReleased", !_held && !mainRelease.Expired && !call.IsCompleted && port.Nu501Lifetime.HandlesOpen,
                "Revoke cancellation released main lease while measured native progress was still paused", id);
        }
        finally
        {
            mainRelease.Release(); release.Release();
            await main.ConfigureAwait(false);
            if (call is not null) await call.ConfigureAwait(false);
            if (disconnect is not null) await disconnect.ConfigureAwait(false);
            _native.BeforeNative = null;
        }
        Check("DisconnectDrain", !release.Expired && !mainRelease.Expired && elapsed.Elapsed < TimeSpan.FromSeconds(5) &&
            Volatile.Read(ref _native.Returned) == returned + 1 && port.Nu501Lifetime is { Disposed: true, Active: 0, HandlesOpen: false } &&
            call?.Result.Status == ResourceSendStatus.Revoked &&
            _native.LastHResult == HResultFromNtStatus(unchecked((int)0xC000000D)) && _native.LastBytesReturned == 0,
            "Finite disconnect join; exact native malformed refusal returned before handle release; no adoption after revoke", id,
            _native.LastHResult, "RevokedAfterNativeReturn");
    }
    private static async Task WaitUntil(Func<bool> predicate, CancellationToken token)
    {
        var elapsed = Stopwatch.StartNew();
        while (!predicate())
        { if (elapsed.Elapsed > TimeSpan.FromSeconds(5)) throw new TimeoutException("Admission observation timed out"); await Task.Delay(5, token).ConfigureAwait(false); }
    }
}
#endif
