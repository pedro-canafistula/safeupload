using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Drive;
using SafeUpload.Agent.Service.Gate;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Service.Drive;

/// <summary>
/// Mounts one SafeUpload drive per protected folder of the policy (S:, T:, ...) and turns each decision into an audit
/// event and, for blocks, a notification with the justification option. The real folders become read-only for users;
/// the gate driver, when loaded, also refuses other processes' writes there and on removable/network volumes.
/// </summary>
public sealed class DriveService : BackgroundService
{
    private static readonly TimeSpan PolicyCheckInterval = TimeSpan.FromSeconds(30);

    private readonly IPolicyStore _policyStore;
    private readonly InspectionService _inspection;
    private readonly NotificationHub _hub;
    private readonly DriveJustifications _justifications;
    private readonly GateClient _gate;
    private readonly ILogger<DriveService> _logger;
    private readonly string[] _letters;
    private readonly string _privateRoot;
    private readonly Dictionary<string, DriveMount> _mounts = new(StringComparer.OrdinalIgnoreCase);
    private string? _lastStatus;

    public DriveService(IPolicyStore policyStore, InspectionService inspection, NotificationHub hub,
        DriveJustifications justifications, GateClient gate, IConfiguration configuration, ILogger<DriveService> logger)
    {
        _policyStore = policyStore;
        _inspection = inspection;
        _hub = hub;
        _justifications = justifications;
        _gate = gate;
        _logger = logger;
        _letters = (configuration["Drive:Letters"] ?? "S,T,U,V,W,X,Y,Z")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        _privateRoot = configuration["Drive:PrivateRoot"] ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SafeUpload", "drive");
    }

    /// <summary>Drive letter for each mounted destination folder.</summary>
    public IReadOnlyDictionary<string, string> Mounts
    {
        get { lock (_mounts) return _mounts.ToDictionary(p => p.Key, p => p.Value.MountPoint, StringComparer.OrdinalIgnoreCase); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        DriveLog.Sink = line => _logger.LogInformation("drive: {Line}", line);
        Directory.CreateDirectory(_privateRoot);
        Protect(_privateRoot, usersMayRead: false);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try { await SyncAsync(stoppingToken).ConfigureAwait(false); }
                catch (Exception error) when (error is not OperationCanceledException)
                {
                    _logger.LogError(error, "Could not apply the protected folders of the policy");
                }
                try { await Task.Delay(PolicyCheckInterval, stoppingToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
        finally
        {
            lock (_mounts)
            {
                foreach (var mount in _mounts.Values) mount.Dispose();
                _mounts.Clear();
            }
        }
    }

    private async Task SyncAsync(CancellationToken token)
    {
        var policy = await _policyStore.LoadAsync(token).ConfigureAwait(false);
        var folders = policy.MonitoredScopes.DestinationPaths
            .Select(path => Path.GetFullPath(path).TrimEnd('\\'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();
        // USB sticks get a SafeUpload drive too; the gate refuses direct writes to them.
        var sticks = policy.MonitoredScopes.RemovableDrives ? RemovableRoots() : [];
        var wanted = folders.Concat(sticks).ToList();
        // Close the real places before the drives appear.
        _gate.Apply(folders, policy.MonitoredScopes.RemovableDrives, policy.MonitoredScopes.NetworkPaths);
        lock (_mounts)
        {
            foreach (var gone in _mounts.Keys.Where(k => !wanted.Contains(k, StringComparer.OrdinalIgnoreCase)).ToList())
            {
                _mounts[gone].Dispose();
                _mounts.Remove(gone);
            }
            foreach (var destination in wanted.Where(d => !_mounts.ContainsKey(d)))
            {
                var letter = FreeLetter();
                if (letter is null)
                {
                    _logger.LogError("No free drive letter for {Destination}", destination);
                    continue;
                }
                try
                {
                    bool stick = sticks.Contains(destination, StringComparer.OrdinalIgnoreCase);
                    bool share = destination.StartsWith(@"\\", StringComparison.Ordinal);
                    if (!stick) Directory.CreateDirectory(destination);
                    // Local folders become read-only for users; shares and sticks are protected by the gate driver.
                    if (!stick && !share) Protect(destination, usersMayRead: true);
                    var privateRoot = Path.Combine(_privateRoot, ShortHash(destination));
                    var mount = DriveMount.Mount(destination, privateRoot, letter, new ContentInspector(_inspection, _policyStore),
                        new Observer(this, destination), stick ? DestinationKind.RemovableDrive : DestinationKind.Cloud,
                        Label(destination, stick));
                    _mounts[destination] = mount;
                    _logger.LogInformation("Protected folder {Destination} is available as {Letter}", destination, letter);
                }
                catch (Exception error)
                {
                    _logger.LogError(error, "Could not mount the SafeUpload drive for {Destination}", destination);
                }
            }
        }
        bool active = wanted.Count > 0 && _mounts.Count == wanted.Count;
        PublishStatus(policy, active);
    }

    private void PublishStatus(Policy policy, bool active)
    {
        var key = $"{policy.Version}|{policy.ActiveCategories.Count}|{active}|{policy.AuditOnly}";
        if (key == _lastStatus) return;
        _lastStatus = key;
        _hub.Publish(new StatusNotification(policy.Version, policy.ActiveCategories.Count, active, policy.AuditOnly));
    }

    /// <summary>Roots of ready removable volumes ("E:\\"), excluding our own drives.</summary>
    private List<string> RemovableRoots()
    {
        var ours = _mounts.Values.Select(m => m.MountPoint.TrimEnd(':').ToUpperInvariant()).ToHashSet();
        return DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Removable && d.IsReady && !ours.Contains(d.Name[..1].ToUpperInvariant()))
            .Select(d => d.RootDirectory.FullName)
            .ToList();
    }

    private string? FreeLetter()
    {
        var used = DriveInfo.GetDrives().Select(d => d.Name[..1].ToUpperInvariant()).ToHashSet();
        foreach (var mount in _mounts.Values) used.Add(mount.MountPoint[..1].ToUpperInvariant());
        return _letters.Select(l => l.TrimEnd(':').ToUpperInvariant()).FirstOrDefault(l => !used.Contains(l)) is { } free
            ? free + ":" : null;
    }

    private DriveWriter? IdentifyWriter(int processId)
    {
        string name = "unknown";
        try { name = Process.GetProcessById(processId).ProcessName; } catch (Exception) { }
        try
        {
            var identity = SessionResolver.GetRequiredProcessIdentity(processId);
            string? user = null;
            try { user = identity.UserSid.Translate(typeof(NTAccount)).Value; } catch (IdentityNotMappedException) { }
            return new DriveWriter(processId, name, identity.SessionId, identity.UserSid.Value, user);
        }
        catch (Exception)
        {
            return new DriveWriter(processId, name, null, null, null);
        }
    }

    private void OnDecision(string destination, DriveDecision decision)
    {
        _ = Task.Run(async () =>
        {
            try { await HandleDecisionAsync(destination, decision).ConfigureAwait(false); }
            catch (Exception error) { _logger.LogError(error, "Could not report the decision for {File}", decision.DrivePath); }
        });
    }

    private async Task HandleDecisionAsync(string destination, DriveDecision decision)
    {
        if (decision.Approved) return;
        Policy? policy = null;
        try { policy = await _policyStore.LoadCurrentAsync(CancellationToken.None).ConfigureAwait(false); }
        catch (Exception error) { _logger.LogSafeWarning(error, "Current drive policy unavailable; release stays disabled."); }
        DriveMount? mount;
        lock (_mounts) _mounts.TryGetValue(destination, out mount);
        await HandleDecisionAsync(decision, policy,
            mount is null ? null : kind => mount.FileSystem.Approve(decision.VersionId, kind)).ConfigureAwait(false);
    }

    internal async Task HandleDecisionAsync(DriveDecision decision, Policy? policy, Func<DriveApprovalKind, bool>? approve)
    {
        // Approval is not a transfer outcome. The reconciler reports it after the destination write.
        if (decision.Approved) return;
        var writer = decision.Writer;
        bool samePolicy = policy is not null && decision.Result?.PolicyContentFingerprint is { } binding &&
            string.Equals(binding, PolicyContentFingerprint.Compute(policy), StringComparison.Ordinal);
        // Audit mode (the console's "alertar"): a version whose inspection completed with findings goes through and
        // is audited as an approval with its categories. A failed inspection still blocks (fail closed).
        bool alert = samePolicy && policy?.AuditOnly == true &&
            decision.Result is { Reason: null } inspected && inspected.Categories.Count > 0;
        if (alert && approve?.Invoke(DriveApprovalKind.Audit) == true) return;

        if (decision.Operation is { } operation && decision.Result is { } result)
        {
            await _inspection.RecordTransferOutcomeAsync(operation,
                result, Verdict.Blocked, result.Reason, CancellationToken.None, eventId: decision.VersionId,
                auditUserName: writer?.UserName).ConfigureAwait(false);
        }
        bool overrideAllowed = samePolicy && policy?.OverrideAllowed == true && approve is not null &&
            decision.Result is { InScope: true, IsBlocked: true } &&
            decision.Result.FailureKind != InspectionFailureKind.NotEnoughStagingSpace &&
            writer?.SessionId is not null && writer.UserSid is not null;
        if (overrideAllowed)
            _justifications.Remember(decision.VersionId, writer!.SessionId!.Value, writer.UserSid!,
                decision.Result!.PolicyContentFingerprint!, () => approve!(DriveApprovalKind.Justification));
        // The blocked version stays visible to the user on the drive, at DrivePath.
        var notification = new TransferNotification(decision.VersionId, decision.DrivePath, TransferPhase.Blocked,
            decision.Result?.Findings ?? [], overrideAllowed, HandbackPath: decision.DrivePath, HandbackVerified: true,
            SnapshotSha256Hex: Sha256(decision.Snapshot), InspectionFailure: decision.Result?.FailureKind);
        if (writer?.SessionId is null || writer.UserSid is null)
            _logger.LogWarning("Blocked {File}; no user session to notify", decision.DrivePath);
        _hub.Publish(notification, writer?.SessionId, writer?.UserSid);
    }

    private void OnPublication(DrivePublication publication)
    {
        _ = Task.Run(async () =>
        {
            try { await HandlePublicationAsync(publication).ConfigureAwait(false); }
            catch (Exception error) { _logger.LogSafeWarning(error, "Could not report the drive publication outcome."); }
        });
    }

    internal Task HandlePublicationAsync(DrivePublication publication)
    {
        var decision = publication.Decision;
        if (decision.Operation is not { } operation || decision.Result is not { } result ||
            (publication.Succeeded && decision.FileName.StartsWith("~$", StringComparison.Ordinal)))
            return Task.CompletedTask;
        // Alertar and justified findings become Approved only after the copy. Preserve the initial blocked event,
        // which remains the justification's reference: a later outcome gets a separate immutable event id.
        var verdict = publication.Succeeded
            ? result.IsBlocked ? Verdict.Approved : result.Verdict
            : Verdict.Blocked;
        var reason = publication.Succeeded ? result.Reason : "publication_failed";
        return _inspection.RecordTransferOutcomeAsync(
            operation with { DestinationPath = publication.DestinationPath, FileName = decision.FileName },
            result, verdict, reason, CancellationToken.None, eventId: publication.EventId,
            auditUserName: decision.Writer?.UserName);
    }

    /// <summary>SYSTEM and administrators control the folder; users may only read it (or nothing).</summary>
    private static void Protect(string folder, bool usersMayRead)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (usersMayRead)
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(folder).SetAccessControl(security);
    }

    /// <summary>Volume label users see in Explorer, e.g. "SafeUpload-Envios" or "SafeUpload-USB-F".</summary>
    private static string Label(string destination, bool stick)
    {
        var trimmed = destination.TrimEnd('\\');
        var leaf = stick ? "USB-" + destination[..1] : trimmed[(trimmed.LastIndexOf('\\') + 1)..];   // works for \\server\share too
        return "SafeUpload-" + (string.IsNullOrEmpty(leaf) ? "Destino" : leaf);
    }

    private static string Sha256(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return Convert.ToHexString(SHA256.HashData(Array.Empty<byte>()));
        }
    }

    private static string ShortHash(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToUpperInvariant())))[..16];

    private sealed class Observer(DriveService owner, string destination) : IDriveObserver
    {
        public DriveWriter? IdentifyWriter(int processId) => owner.IdentifyWriter(processId);
        public void OnDecision(DriveDecision decision) => owner.OnDecision(destination, decision);
        public void OnPublication(DrivePublication publication) => owner.OnPublication(publication);
    }
}
