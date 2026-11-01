namespace SafeUpload.Agent.Service.Gate;

public sealed record GateScopeReceipt(string MessageKey, int PathCount, bool Removable, bool Network,
    DateTimeOffset AcceptedUtc);
/// <summary>Transport receipt only; does not prove enforcement, mounted drives or completed file publication.</summary>
public sealed record GatePolicyStatus(string LastApplyOutcome = "not_attempted",
    bool ConnectionHasAcceptedScope = false, GateScopeReceipt? LastAcceptedScope = null);
