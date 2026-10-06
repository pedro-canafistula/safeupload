using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Minifilter;

public sealed record AdmissionCoverageScopeReceipt(
    uint ScopeKind,
    uint ScopeIndex,
    uint Resolution,
    uint State,
    uint Reason,
    uint MatchingInstances,
    uint UniqueVolumes,
    uint ReadyInstances,
    string Prefix);

public sealed record AdmissionCoverageReceipt(
    uint ProtocolVersion,
    uint State,
    uint Flags,
    uint PolicyGeneration,
    uint PolicyFlags,
    uint BootPolicyState,
    uint ScopeCount,
    uint ExpectedScopeCount,
    uint PolicyGenerationEnd,
    uint PolicyFlagsEnd,
    uint BootPolicyStateEnd,
    uint EpochGeneration,
    uint EpochFlags,
    uint EpochActiveCallbacks,
    uint EpochGenerationEnd,
    uint EpochFlagsEnd,
    uint EpochActiveCallbacksEnd,
    uint EnumeratedInstances,
    uint SetupInFlight,
    uint TeardownInFlight,
    uint CoverageChangesInFlight,
    uint WriterGlobalUnknown,
    uint WriterEntries,
    uint WriterEntriesNotReady,
    uint WriterEntriesUnknown,
    uint FutureMountGateReady,
    uint Reason,
    ulong PolicyScopeSequenceStart,
    ulong PolicyScopeSequenceEnd,
    ulong TopologySequenceStart,
    ulong TopologySequenceEnd,
    ulong CoverageSequenceStart,
    ulong CoverageSequenceEnd,
    ulong RegistrySequenceStart,
    ulong RegistrySequenceEnd,
    IReadOnlyList<AdmissionCoverageScopeReceipt> Scopes);

public enum AdmissionCoverageReadiness
{
    Pending,
    Ready,
    Degraded
}

public sealed record AdmissionCoverageDecision(
    AdmissionCoverageReadiness Readiness,
    string Reason,
    uint NativePolicyGeneration);

public static class AdmissionCoverageEvaluator
{
    private const uint BootPolicyValid = 1;
    private const uint EpochPending = 0x00000001;
    private const uint EpochFailedClosed = 0x00000002;
    private const uint EpochFinalizing = 0x00000004;
    private const uint KnownEpochFlags = EpochPending | EpochFailedClosed | EpochFinalizing;
    private const uint RemovablePolicyFlag = 0x00000001;
    private const uint NetworkPolicyFlag = 0x00000002;
    private const uint AuditOnlyPolicyFlag = 0x00000004;
    private const uint KnownPolicyFlags = 0x0000001f;

    public static unsafe string[] GetExpectedPrefixes(SafeUploadPolicyMessage policy)
    {
        if (policy.PrefixCount > Contract.MaxPrefixes)
            throw new InvalidDataException("Policy prefix count exceeds its protocol capacity.");

        var prefixes = new string[checked((int)policy.PrefixCount)];
        // The by-value policy is a stack local; its fixed buffer is already fixed.
        char* data = policy.Prefixes;
        {
            for (int index = 0; index < prefixes.Length; ++index)
            {
                char* slot = data + index * Contract.MaxPrefixChars;
                int length = 0;
                while (length < Contract.MaxPrefixChars && slot[length] != '\0') ++length;
                if (length == 0)
                    throw new InvalidDataException("Accepted policy contains an empty destination prefix.");
                for (int charIndex = 0; charIndex < length; ++charIndex)
                {
                    if (char.IsControl(slot[charIndex]))
                        throw new InvalidDataException("Accepted policy contains an invalid destination prefix.");
                }
                prefixes[index] = new string(slot, 0, length);
            }
        }
        return prefixes;
    }

    public static AdmissionCoverageDecision Evaluate(
        AdmissionCoverageReceipt receipt,
        IReadOnlyList<string> expectedPrefixes,
        uint expectedPolicyFlags,
        uint boundNativePolicyGeneration)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(expectedPrefixes);

        if (receipt.ProtocolVersion != Contract.Version ||
            receipt.ScopeCount > Contract.AdmissionCoverageMaxScopes ||
            receipt.ExpectedScopeCount > Contract.AdmissionCoverageMaxScopes ||
            receipt.Scopes.Count != receipt.ScopeCount)
            return Degraded("MalformedReceipt", 0);

        if ((receipt.Flags & AdmissionCoverageContract.PolicyPendingFlag) != 0 ||
            receipt.PolicyGeneration != receipt.PolicyGenerationEnd ||
            receipt.PolicyFlags != receipt.PolicyFlagsEnd ||
            receipt.BootPolicyState != receipt.BootPolicyStateEnd ||
            receipt.PolicyScopeSequenceStart != receipt.PolicyScopeSequenceEnd ||
            receipt.EpochGeneration != receipt.EpochGenerationEnd ||
            receipt.EpochFlags != receipt.EpochFlagsEnd ||
            receipt.TopologySequenceStart != receipt.TopologySequenceEnd ||
            receipt.CoverageSequenceStart != receipt.CoverageSequenceEnd ||
            receipt.RegistrySequenceStart != receipt.RegistrySequenceEnd ||
            receipt.SetupInFlight != 0 || receipt.TeardownInFlight != 0 ||
            receipt.CoverageChangesInFlight != 0)
            return Pending("PolicyOrTopologyChanging", 0);

        if (receipt.ExpectedScopeCount != receipt.ScopeCount)
            return Degraded("MalformedReceipt", 0);

        uint currentGeneration = receipt.PolicyGeneration;
        if (boundNativePolicyGeneration != 0 && currentGeneration != boundNativePolicyGeneration)
            return Degraded("NativePolicyGenerationChanged", currentGeneration);

        if ((receipt.Flags & ~0x0000003fu) != 0)
            return Degraded("UnknownReceiptFlags", 0);
        if ((receipt.Flags & AdmissionCoverageContract.PolicyScopeOverflowFlag) != 0)
            return Degraded("PolicyScopeOverflow", 0);
        if ((receipt.PolicyFlags & ~KnownPolicyFlags) != 0)
            return Degraded("UnknownPolicyFlags", 0);
        if (receipt.PolicyFlags != expectedPolicyFlags)
            return Degraded("AcceptedPolicyMismatch", 0);
        if (expectedPrefixes.Count == 0 &&
            (expectedPolicyFlags & (RemovablePolicyFlag | NetworkPolicyFlag)) == 0)
            return Degraded("NoDestinationScope", 0);

        uint expectedScopeCount = checked((uint)expectedPrefixes.Count +
            (((expectedPolicyFlags & RemovablePolicyFlag) != 0) ? 1u : 0u) +
            (((expectedPolicyFlags & NetworkPolicyFlag) != 0) ? 1u : 0u));
        if (receipt.ScopeCount != expectedScopeCount || receipt.ExpectedScopeCount != expectedScopeCount)
            return Degraded("AcceptedScopeSetMismatch", 0);

        int cursor = 0;
        string? degradedScopeReason = null;
        string? pendingScopeReason = null;
        for (int index = 0; index < expectedPrefixes.Count; ++index)
        {
            AdmissionCoverageScopeReceipt scope = receipt.Scopes[cursor++];
            if (scope.ScopeKind != AdmissionCoverageContract.PrefixScope ||
                scope.ScopeIndex != (uint)index ||
                !string.Equals(scope.Prefix, expectedPrefixes[index], StringComparison.Ordinal))
                return Degraded("AcceptedScopeSetMismatch", 0);
            AdmissionCoverageDecision? result = EvaluateScope(scope, prefixScope: true, currentGeneration);
            if (result?.Readiness == AdmissionCoverageReadiness.Degraded)
                degradedScopeReason ??= result.Reason;
            else if (result?.Readiness == AdmissionCoverageReadiness.Pending)
                pendingScopeReason ??= result.Reason;
        }
        if ((expectedPolicyFlags & RemovablePolicyFlag) != 0)
        {
            AdmissionCoverageScopeReceipt scope = receipt.Scopes[cursor++];
            if (scope.ScopeKind != AdmissionCoverageContract.RemovableScope || scope.Prefix.Length != 0)
                return Degraded("AcceptedScopeSetMismatch", 0);
            AdmissionCoverageDecision? result = EvaluateScope(scope, prefixScope: false, currentGeneration);
            if (result?.Readiness == AdmissionCoverageReadiness.Degraded)
                degradedScopeReason ??= result.Reason;
            else if (result?.Readiness == AdmissionCoverageReadiness.Pending)
                pendingScopeReason ??= result.Reason;
        }
        if ((expectedPolicyFlags & NetworkPolicyFlag) != 0)
        {
            AdmissionCoverageScopeReceipt scope = receipt.Scopes[cursor++];
            if (scope.ScopeKind != AdmissionCoverageContract.NetworkScope || scope.Prefix.Length != 0)
                return Degraded("AcceptedScopeSetMismatch", 0);
            AdmissionCoverageDecision? result = EvaluateScope(scope, prefixScope: false, currentGeneration);
            if (result?.Readiness == AdmissionCoverageReadiness.Degraded)
                degradedScopeReason ??= result.Reason;
            else if (result?.Readiness == AdmissionCoverageReadiness.Pending)
                pendingScopeReason ??= result.Reason;
        }

        if (currentGeneration == 0)
            return Pending("PolicyGenerationUnavailable", 0);
        if ((receipt.Flags & AdmissionCoverageContract.CompleteFlag) == 0 ||
            (receipt.Flags & AdmissionCoverageContract.StableFlag) == 0 ||
            (receipt.Flags & AdmissionCoverageContract.FutureGateFlag) == 0 ||
            (receipt.Flags & AdmissionCoverageContract.RegistryCompleteFlag) == 0 ||
            receipt.FutureMountGateReady == 0)
            return Pending("CoverageIncomplete", boundNativePolicyGeneration);

        if (receipt.BootPolicyState != BootPolicyValid)
            return Degraded("BootPolicyInvalid", currentGeneration);
        if ((receipt.EpochFlags & ~KnownEpochFlags) != 0)
            return Degraded("UnknownEpochFlags", currentGeneration);
        if ((receipt.EpochFlags & EpochFailedClosed) != 0)
            return Degraded("PolicyFailedClosed", currentGeneration);
        if ((receipt.EpochFlags & (EpochPending | EpochFinalizing)) != 0)
            return Pending("PolicyTransition", 0);
        if ((receipt.PolicyFlags & AuditOnlyPolicyFlag) != 0)
            return Degraded("AuditOnly", currentGeneration);

        if (receipt.WriterGlobalUnknown != 0 || receipt.WriterEntriesUnknown != 0)
            return Degraded("WriterStateUnknown", currentGeneration);
        if (receipt.State == AdmissionCoverageContract.Degraded)
            return Degraded(ReasonName(receipt.Reason), currentGeneration);
        if (receipt.State != AdmissionCoverageContract.Ready)
        {
            if (receipt.State == AdmissionCoverageContract.Pending)
                pendingScopeReason ??= ReasonName(receipt.Reason);
            else return Degraded("UnknownCoverageState", currentGeneration);
        }
        if (degradedScopeReason is not null)
            return Degraded(degradedScopeReason, currentGeneration);
        if (receipt.WriterEntriesNotReady != 0)
            pendingScopeReason ??= "WriterPromotionPending";
        if (pendingScopeReason is not null)
            return Pending(pendingScopeReason, currentGeneration);

        return new AdmissionCoverageDecision(AdmissionCoverageReadiness.Ready, "Ready", currentGeneration);
    }

    private static AdmissionCoverageDecision? EvaluateScope(
        AdmissionCoverageScopeReceipt scope, bool prefixScope, uint generation)
    {
        if (scope.Reason > 16)
            return Degraded("UnknownScopeReason", generation);
        if (scope.State == AdmissionCoverageContract.Degraded)
            return Degraded(ReasonName(scope.Reason), generation);
        if (scope.State == AdmissionCoverageContract.Pending)
            return Pending(ReasonName(scope.Reason), generation);
        if (scope.State != AdmissionCoverageContract.Ready)
            return Degraded("UnknownScopeState", generation);

        if (prefixScope)
        {
            if (scope.Resolution != AdmissionCoverageContract.UniqueResolution ||
                scope.UniqueVolumes != 1 || scope.MatchingInstances == 0 ||
                scope.ReadyInstances != scope.MatchingInstances || scope.Reason != 0)
                return Degraded("PrefixNotUniquelyReady", generation);
        }
        else if (scope.Resolution != AdmissionCoverageContract.NotApplicableResolution ||
                 scope.ReadyInstances != scope.MatchingInstances || scope.Reason != 0 ||
                 scope.UniqueVolumes > scope.MatchingInstances)
        {
            return Degraded("FlagScopeNotReady", generation);
        }
        return null;
    }

    private static AdmissionCoverageDecision Pending(string reason, uint generation) =>
        new(AdmissionCoverageReadiness.Pending, reason, generation);

    private static AdmissionCoverageDecision Degraded(string reason, uint generation) =>
        new(AdmissionCoverageReadiness.Degraded, reason, generation);

    private static string ReasonName(uint reason) => reason switch
    {
        0 => "Pending",
        1 => "NoDestinationScope",
        2 => "PolicyChange",
        3 => "TopologyChanging",
        4 => "DestinationAbsent",
        5 => "DestinationAmbiguous",
        6 => "CoverageUnknown",
        7 => "UnsupportedDestination",
        8 => "CanaryPending",
        9 => "CanaryFailed",
        10 => "WriterStateUnknown",
        11 => "WriterPromotionPending",
        12 => "BootPolicyInvalid",
        13 => "FutureMountGateUnavailable",
        14 => "PolicyFailedClosed",
        15 => "VolumeIdentityUnknown",
        16 => "AuditOnly",
        _ => "Unknown"
    };
}

public sealed partial class FilterPort
{
    public unsafe AdmissionCoverageReceipt GetAdmissionCoverageStatus()
    {
        using var send = EnterSend();
        SafeUploadControl control = new()
        {
            Version = Contract.Version,
            StructSize = (uint) sizeof(SafeUploadControl),
            Command = ControlCommand.AdmissionCoverage,
            Reserved = 0
        };
        IntPtr output = Marshal.AllocHGlobal(Contract.AdmissionCoverageStatusSize);
        try
        {
            new Span<byte>((void*)output, Contract.AdmissionCoverageStatusSize).Clear();
            int hr = FilterSendMessage(send.Handle, (IntPtr)(&control),
                (uint)sizeof(SafeUploadControl), output,
                (uint)Contract.AdmissionCoverageStatusSize, out uint returned);
            if (hr != 0) throw new Win32Exception(hr, $"Admission coverage query failed: 0x{hr:X8}");
            if (returned != Contract.AdmissionCoverageStatusSize)
                throw new InvalidDataException("Admission coverage response length does not match Protocol.h.");

            SafeUploadAdmissionCoverageStatus* status = (SafeUploadAdmissionCoverageStatus*)output;
            if (status->StructSize != Contract.AdmissionCoverageStatusSize ||
                status->ProtocolVersion != Contract.Version ||
                status->ScopeCount > Contract.AdmissionCoverageMaxScopes ||
                status->ExpectedScopeCount > Contract.AdmissionCoverageMaxScopes)
                throw new InvalidDataException("Admission coverage receipt has an invalid version or bound.");

            var scopes = new List<AdmissionCoverageScopeReceipt>((int)status->ScopeCount);
            byte* scopeBytes = (byte*)output + 176;
            SafeUploadAdmissionCoverageScope* nativeScopes = (SafeUploadAdmissionCoverageScope*)scopeBytes;
            for (int index = 0; index < status->ScopeCount; ++index)
            {
                SafeUploadAdmissionCoverageScope* scope = &nativeScopes[index];
                uint chars = Math.Min(scope->PrefixChars, (uint)Contract.MaxPrefixChars);
                string prefix = new(scope->Prefix, 0, (int)chars);
                if (scope->PrefixChars != chars || prefix.IndexOf('\0') >= 0)
                    throw new InvalidDataException("Admission coverage scope contains an invalid prefix length.");
                scopes.Add(new AdmissionCoverageScopeReceipt(scope->ScopeKind, scope->ScopeIndex,
                    scope->Resolution, scope->State, scope->Reason,
                    scope->MatchingInstances, scope->UniqueVolumes, scope->ReadyInstances, prefix));
            }

            return new AdmissionCoverageReceipt(status->ProtocolVersion, status->State, status->Flags,
                status->PolicyGeneration, status->PolicyFlags, status->BootPolicyState,
                status->ScopeCount, status->ExpectedScopeCount,
                status->PolicyGenerationEnd, status->PolicyFlagsEnd, status->BootPolicyStateEnd,
                status->EpochGeneration, status->EpochFlags, status->EpochActiveCallbacks,
                status->EpochGenerationEnd, status->EpochFlagsEnd, status->EpochActiveCallbacksEnd,
                status->EnumeratedInstances, status->SetupInFlight, status->TeardownInFlight,
                status->CoverageChangesInFlight, status->WriterGlobalUnknown, status->WriterEntries,
                status->WriterEntriesNotReady, status->WriterEntriesUnknown, status->FutureMountGateReady,
                status->Reason, status->PolicyScopeSequenceStart, status->PolicyScopeSequenceEnd,
                status->TopologySequenceStart, status->TopologySequenceEnd,
                status->CoverageSequenceStart, status->CoverageSequenceEnd,
                status->RegistrySequenceStart, status->RegistrySequenceEnd, scopes.AsReadOnly());
        }
        finally
        {
            Marshal.FreeHGlobal(output);
        }
    }
}
