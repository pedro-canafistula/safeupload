#if SAFEUPLOAD_ADMISSION_EVIDENCE
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

// Managed sequencing and receipt controls ONLY. No N-U5-01 native execution.
public sealed class Nu501ControlTests
{
    [Fact]
    public async Task Latch_is_signaled_inside_main_lease_and_second_lease_waits_for_release()
    {
        using var port = FilterPort.CreateResourceForTesting(new SafeFileHandle((IntPtr)101, false),
            new SafeFileHandle((IntPtr)102, false), new UnusedSender());
        using var latch = new Nu501Latch(TimeSpan.FromSeconds(5), default);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task held = port.HoldLegacySendForTesting(() => { entered.SetResult(); latch.Wait(); });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        bool secondEntered = false;
        Task second = port.HoldLegacySendForTesting(() => secondEntered = true);
        try
        {
            await Task.Delay(30);
            Assert.False(secondEntered); Assert.False(second.IsCompleted); Assert.False(latch.Released);
        }
        finally { latch.Release(); await Task.WhenAll(held, second).WaitAsync(TimeSpan.FromSeconds(2)); }
        Assert.True(secondEntered); Assert.False(latch.Expired);
    }

    [Theory]
    [InlineData("timeout")]
    [InlineData("failure")]
    [InlineData("cancellation")]
    [InlineData("revoke")]
    [InlineData("disposal")]
    public async Task Independent_release_does_not_need_progress_being_measured(string cause)
    {
        using var cancel = new CancellationTokenSource();
        var latch = new Nu501Latch(cause == "timeout" ? TimeSpan.FromMilliseconds(30) : TimeSpan.FromSeconds(5), cancel.Token);
        Task blocked = Task.Run(latch.Wait);
        try
        {
            switch (cause)
            {
                case "failure": try { throw new IOException(); } catch (IOException) { } finally { latch.Release(); } break;
                case "cancellation": cancel.Cancel(); break;
                case "revoke": latch.Release(); break;
                case "disposal": latch.Dispose(); break;
            }
            await blocked.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.True(latch.Released);
            Assert.Equal(cause == "timeout", latch.Expired);
        }
        finally { latch.Dispose(); }
    }

    [Fact]
    public void Complete_logic_receipt_is_accepted_without_claiming_native_execution() => Assert.True(Receipt().ValidPass);

    [Theory]
    [MemberData(nameof(MissingSteps))]
    public void Every_missing_or_duplicate_required_step_refuses_pass(string name, bool duplicate)
    {
        var receipt = Receipt();
        var steps = duplicate ? receipt.Steps.Append(receipt.Steps.Single(s => s.Name == name)).ToArray() :
            receipt.Steps.Where(s => s.Name != name).ToArray();
        Assert.False((receipt with { Steps = steps }).ValidPass);
    }
    public static IEnumerable<object[]> MissingSteps() => Nu501Receipt.Required.SelectMany(n =>
        new[] { new object[] { n, false }, new object[] { n, true } });

    [Theory]
    [InlineData("failure")]
    [InlineData("failed-step")]
    [InlineData("duplicate")]
    [InlineData("wrong-schema")]
    [InlineData("wrong-run")]
    [InlineData("bad-elapsed")]
    [InlineData("unheld-root")]
    [InlineData("zero-root-request")]
    [InlineData("unheld-store")]
    [InlineData("unheld-blocked")]
    [InlineData("held-released")]
    [InlineData("fail-verdict")]
    public void Receipt_mutants_never_turn_incomplete_or_failed_evidence_green(string mutation)
    {
        var receipt = Receipt(); var steps = receipt.Steps.ToList();
        switch (mutation)
        {
            case "failure": receipt = receipt with { Failure = "failure" }; break;
            case "failed-step": steps[0] = steps[0] with { Passed = false }; break;
            case "duplicate": steps.Add(steps[0]); break;
            case "wrong-schema": receipt = receipt with { Schema = "unknown" }; break;
            case "wrong-run": receipt = receipt with { RunId = "invalid" }; break;
            case "bad-elapsed": steps[0] = steps[0] with { ElapsedMs = double.NaN }; break;
            case "unheld-root": Mutate("Root1", s => s with { LegacyHeld = false }); break;
            case "zero-root-request": Mutate("Root1", s => s with { RequestId = 0 }); break;
            case "unheld-store": Mutate("Store0", s => s with { LegacyHeld = false }); break;
            case "unheld-blocked": Mutate("LegacyBlocked", s => s with { LegacyHeld = false }); break;
            case "held-released": Mutate("LegacyReleased", s => s with { LegacyHeld = true }); break;
            case "fail-verdict": receipt = receipt with { Verdict = "FAIL" }; break;
        }
        Assert.False((receipt with { Steps = steps }).ValidPass);
        void Mutate(string name, Func<Nu501Step, Nu501Step> mutate)
        { int index = steps.FindIndex(s => s.Name == name); steps[index] = mutate(steps[index]); }
    }
    private static Nu501Receipt Receipt()
    {
        var names = new List<string> { "Idle", "Probe", "Pair", "CommitWire", "CommitNotReady" };
        names.AddRange(new[] { "Timeout", "Failure", "Cancellation" }.SelectMany(c => new[] { $"Release{c}Held", $"Release{c}Returned" }));
        names.AddRange(["LeaseHeld", "LegacyBlocked"]);
        names.AddRange(Nu501Receipt.Required.Except(names).Except(new[] { "HeldProgressComplete", "LegacyReleased", "ChildrenClosed", "DisconnectRetains", "RevokeLatchReleased", "DisconnectDrain" }));
        names.AddRange(["HeldProgressComplete", "LegacyReleased", "ChildrenClosed", "DisconnectRetains", "RevokeLatchReleased", "DisconnectDrain"]);
        int held = names.IndexOf("LeaseHeld"), released = names.IndexOf("LegacyReleased");
        return new("SafeUpload.N-U5-01.v1", Guid.NewGuid().ToString("N"), "PASS", "Managed logic control only",
            names.Select((n, i) => new Nu501Step(n, (ulong)i + 1,
                n.Contains('.') ? "Native" : n is "ChildCreditsBusy" or "OtherPoolBusy" or "GrowthPoolBusy" ? "Completed" : "Assert",
                n is "ChildCreditsBusy" or "OtherPoolBusy" or "GrowthPoolBusy" or "Malformed" ? -1 : 0,
                i, i >= held && i < released || n.StartsWith("Release", StringComparison.Ordinal) && n.EndsWith("Held", StringComparison.Ordinal) ||
                    n == "DisconnectRetains", true, "local logic")).ToArray(), null);
    }
    private sealed class UnusedSender : IResourceNativeSender
    {
        public int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint returned)
        { returned = 0; throw new InvalidOperationException("No native call belongs in these logic controls"); }
    }
}
#endif
