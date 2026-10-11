using System.Diagnostics;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Core.Infrastructure;
using PortVerdict = SafeUpload.Agent.Minifilter.Verdict;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// O gatilho real: o minifiltro em modo kernel.
///
/// Faz o mesmo papel do <see cref="FileSystemInterceptor"/> e é a razão de ele
/// existir como mock. A diferença não é de implementação, é de natureza: o
/// watcher reage depois que o arquivo já chegou ao destino e "bloqueia"
/// apagando, enquanto aqui a operação é interceptada **antes** de acontecer e
/// a negação impede que ela aconteça. Nenhum byte chega ao destino.
///
/// O <see cref="InspectionService"/> continua sendo quem decide. Este tipo
/// traduz — do que o kernel manda para <see cref="FileOperation"/>, e do
/// veredito de dominio de volta para o veredito do protocolo — e nada mais.
/// Regra de negócio aqui dentro seria regra em dois lugares.
///
/// <para><b>O prazo.</b> Havia uma ordem de grandeza entre o que o driver
/// esperava (500 ms fixos) e o que a RN-012 dá ao motor (5 s), e enquanto ela
/// existiu todo arquivo que precisasse de extração real estouraria o prazo e
/// passaria sem inspeção. O prazo do kernel passou a vir da política: o
/// serviço empurra <c>InspectionTimeout</c> mais uma margem, o motor desiste
/// antes do driver, e o número existe num lugar só.
///
/// O que isso <b>não</b> resolve é o custo: enquanto o veredito não volta, a
/// abertura do arquivo está parada. Um prazo maior protege mais e trava mais,
/// e o ponto certo dessa troca só se conhece medindo com arquivo de verdade.
/// Cada estouro continua contado e registrado.</para>
/// </summary>
public sealed class MinifilterInterceptor : BackgroundService
{
    /// <summary>
    /// O que o motor recebe, derivado da RN-012 quando a política carrega.
    /// Antes disso não há inspeção acontecendo, então o valor não importa.
    /// </summary>
    private TimeSpan _budget = TimeSpan.FromMilliseconds(400);

    private readonly InspectionService _inspection;
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly NotificationHub _hub;
    private readonly PendingOverrides _pending;
    private readonly OverrideGrantDispatcher _grants;
    private readonly DriverDiagnosticsSource _diagnostics;
    private readonly StagedJustifications _stagedJustifications;
    private readonly ILogger<MinifilterInterceptor> _logger;
    private readonly bool _stagingEnabled;
    private readonly SemaphoreSlim _bootPolicyGate = new(1, 1);
    private StagedTransferAllocator? _stageAllocator;
    private StagedTransferJournal? _stageJournal;
    private StagedTransferPublisher? _stagePublisher;
    // Readiness is scoped to this authenticated FilterPort connection. The
    // exact driver epoch is installed only after a v20 capability receipt is
    // successfully delivered, and staging recovery completes before the
    // dispatcher accepts any stage mutation.
    private Guid? _activeDriverInstanceId;
    // On a fresh authenticated channel, this is the sole authority retained
    // for replaying a previously committed op17 after its reply was lost. It
    // never makes ordinary stage operations ready.
    private Guid? _drainReplayDriverInstanceId;
    private volatile bool _stageV20Ready;
    private volatile bool _stagingRecoveryReady;
    private bool _stagingRecovered;
    private TaskCompletionSource<bool> _stagingReadySignal =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private long _overBudget;
    private long _answered;
    private int _discardCleanupCursor;
    private bool _overrideAllowed;
    private bool _auditOnly;
    private int _policyVersion;
    private int _activeCategories;
    private string[] _acceptedCoveragePrefixes = Array.Empty<string>();
    private uint _acceptedCoveragePolicyFlags;
#if SAFEUPLOAD_ADMISSION_EVIDENCE
    private readonly AdmissionEvidenceEndpoint _admissionEvidence;
    private byte[]? _acceptedPolicyFingerprint;
#endif

    /// <summary>Compõe o interceptador.</summary>
    public MinifilterInterceptor(
        InspectionService inspection,
        IPolicyStore policyStore,
        IAuditSink auditSink,
        NotificationHub hub,
        PendingOverrides pending,
        OverrideGrantDispatcher grants,
        DriverDiagnosticsSource diagnostics,
        StagedJustifications stagedJustifications,
        IConfiguration configuration,
        ILogger<MinifilterInterceptor> logger
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        , AdmissionEvidenceEndpoint admissionEvidence
#endif
        )
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _hub = hub ?? throw new ArgumentNullException(nameof(hub));
        _pending = pending ?? throw new ArgumentNullException(nameof(pending));
        _grants = grants ?? throw new ArgumentNullException(nameof(grants));
        _diagnostics = diagnostics ?? throw new ArgumentNullException(nameof(diagnostics));
        _stagedJustifications = stagedJustifications ?? throw new ArgumentNullException(nameof(stagedJustifications));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _stagingEnabled = configuration.GetValue<bool>("Interception:StagingPrototype");
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        _admissionEvidence = admissionEvidence ?? throw new ArgumentNullException(nameof(admissionEvidence));
#endif
    }

    /// <inheritdoc />
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // FilterGetMessage bloqueia a thread que o chama, e não há sobreposto
        // aqui. Numa thread do pool isso prenderia um worker pelo tempo todo
        // de vida do serviço, então o laço vive numa thread própria.
        //
        // Uma thread, portanto uma operação por vez: toda abertura monitorada
        // da máquina enfileira atrás do veredito mais lento. É a limitação 3
        // do DEPLOY.md e continua verdadeira; resolvê-la é um pool sobre a
        // mesma porta, e não cabe junto da troca de gatilho.
        var thread = new Thread(() => Run(stoppingToken))
        {
            IsBackground = true,
            Name = "SafeUpload.Minifilter",
        };

        thread.Start();

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _bootPolicyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await BootPolicySeeder.SeedAsync(_policyStore,
                    new BootPolicyRegistryWriter(new WindowsBootPolicyRegistryBackend()),
                    cancellationToken).ConfigureAwait(false);
                _logger.LogInformation("BootPolicy reseeded for the next boot during service shutdown.");
            }
            finally
            {
                _bootPolicyGate.Release();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning("Shutdown BootPolicy reseed was cancelled; the last durable policy remains in place.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Shutdown BootPolicy reseed failed; the last durable policy remains in place.");
        }

        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private void Run(CancellationToken stoppingToken)
    {
        // A UI must never infer protection merely from a live service pipe.
        // It becomes active only after the driver accepts the policy.
        _hub.Publish(new StatusNotification(0, 0, ProtectionActive: false));

        try
        {
            Contract.Verify();
        }
        catch (InvalidOperationException ex)
        {
            // Descompasso de layout entre Protocol.cs e Protocol.h. Seguir
            // daqui produziria vereditos respondidos para a requisição
            // errada, sem nada no sistema reportando erro.
            _logger.LogCritical(ex, "Contrato incompativel com o driver. O gatilho de kernel nao vai subir.");
            return;
        }

        FilterPort port;

        try
        {
            port = FilterPort.Connect();
        }
        catch (Exception ex)
        {
            // Driver não carregado, ou processo sem privilégio. Nenhum dos
            // dois se resolve com nova tentativa imediata, e o serviço não
            // deve morrer por causa disso: o agente segue no ar sem o
            // gatilho de kernel, o que o log precisa deixar explícito.
            _logger.LogError(ex, "Nao foi possivel conectar na porta do minifiltro. Sem intercepcao de kernel.");
            return;
        }

        using (port)
        {
            _activeDriverInstanceId = null;
            _drainReplayDriverInstanceId = null;
            _stageV20Ready = false;
            _stagingRecoveryReady = false;
            _stagingRecovered = false;
            _stagingReadySignal = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            // The driver authenticates the SYSTEM client only after its
            // durable policy is flushed and accepted. Do that first so
            // recovery can use the private stage namespace without opening
            // a pre-policy access window in the public protected scopes.
            if (!TryPushPolicy(port))
            {
                return;
            }

            if (_stagingEnabled && _stageAllocator is null)
            {
                if (!InitializeStagingSubsystem(port, stoppingToken)) return;
            }

            _grants.Bind(port);
            _diagnostics.Bind(port);
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            IAdmissionEvidenceSender? evidenceSender = port as IAdmissionEvidenceSender;
            bool evidenceBound = false;
#endif
            using var publishCancellation =
                CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            Task? publishTask = null;
            Task? coverageTask = null;
            Task? discardCleanupTask = null;
            try
            {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
                evidenceBound = _stagingEnabled && evidenceSender is not null &&
                    _acceptedPolicyFingerprint is { Length: 32 } &&
                    _admissionEvidence.TryBind(evidenceSender, _policyVersion, _acceptedPolicyFingerprint);
#endif
                publishTask = _stagePublisher is null ? null :
                    Task.Run(() => PublishSealedLoopAsync(publishCancellation.Token),
                        publishCancellation.Token);
                discardCleanupTask = _stageJournal is null ? null :
                    Task.Run(() => ProcessExactDiscardCleanupLoopAsync(publishCancellation.Token),
                        publishCancellation.Token);

                _logger.LogInformation("Minifiltro conectado. Interceptando em modo kernel.");

                _hub.Publish(new StatusNotification(
                    _policyVersion, _activeCategories, ProtectionActive: true, AuditOnly: _auditOnly,
                    AdmissionCoverage: _stagingEnabled ? AdmissionCoverageStatus.Pending :
                        AdmissionCoverageStatus.NotAvailable,
                    AdmissionCoverageReason: _stagingEnabled ? "CoveragePending" : null));

                if (_stagingEnabled)
                {
                    string[] expectedPrefixes = _acceptedCoveragePrefixes;
                    uint expectedFlags = _acceptedCoveragePolicyFlags;
                    int acceptedPolicyVersion = _policyVersion;
                    int acceptedCategories = _activeCategories;
                    bool acceptedAuditOnly = _auditOnly;
                    coverageTask = Task.Run(() => PublishAdmissionCoverageLoopAsync(port,
                        expectedPrefixes, expectedFlags, acceptedPolicyVersion,
                        acceptedCategories, acceptedAuditOnly, publishCancellation.Token),
                        publishCancellation.Token);
                }
                else
                {
                    ReadySignal.Announce(ReadySignal.ServiceEvent);
                }

                while (!stoppingToken.IsCancellationRequested &&
                       port.TryGetMessage(out SafeUploadRequest request, out ulong messageId, stoppingToken))
                {
                    uint verdict;
                    string? stageName = null;
                    StagedAllocationReply? typedCreateReply = null;
                    uint? typedStatusReply = null;
                    SafeUploadStageLifecycleV20? typedLifecycleReply = null;
                    SafeUploadStageReconcileReplyV20? typedReconcileReply = null;
                    SafeUploadStageEpochDrainReplyV20? typedEpochDrainReply = null;
                    bool reconcileDrainReplayOnly = false;
                    if (request.Version != Contract.Version || request.StructSize != Contract.RequestSize ||
                        (request.Operation != Operation.StageDiagnostic && !request.HasKnownFlags))
                    {
                        verdict = PortVerdict.Deny;
                    }
                    else if (request.Operation == Operation.StageAllocate)
                    {
                        // A typed v20 marker is opaque binary input even when its
                        // operation-specific flags are malformed. Route every
                        // such request through the strict typed parser so it
                        // can be denied without interpreting ImageName as text.
                        if (request.Reserved == Contract.StageExtensionVersion ||
                            (request.Flags & Contract.StageV20ReplyFlag) != 0)
                            (verdict, typedCreateReply) = AllocateStageV19(request);
                        else if (_stagingEnabled)
                            verdict = PortVerdict.Deny;
                        else
                            (verdict, stageName) = AllocateStage(request, out typedCreateReply);
                    }
                    else if (request.Operation == Operation.StageSeal)
                    {
                        if (request.Reserved == Contract.StageExtensionVersion)
                            (verdict, typedStatusReply) = SealStageV19(request);
                        else if (_stagingEnabled) verdict = PortVerdict.Deny;
                        else verdict = SealStage(request);
                    }
                    else if (request.Operation == Operation.StageDiscard)
                    {
                        if (request.Reserved == Contract.StageExtensionVersion)
                            (verdict, typedStatusReply) = DiscardStageV19(request);
                        else if (_stagingEnabled) verdict = PortVerdict.Deny;
                        else verdict = DiscardStage(request);
                    }
                    else if (request.Operation == Operation.StageCreateAfterDiscard)
                    {
                        (verdict, typedCreateReply) = CreateAfterPrivateDiscardStage(request);
                    }
                    else if (request.Operation == Operation.StageReconcile)
                    {
                        (verdict, typedReconcileReply, reconcileDrainReplayOnly) =
                            RegisterDriverInstanceV20(request);
                    }
                    else if (request.Operation == Operation.StageEpochDrain)
                    {
                        (verdict, typedEpochDrainReply) = DrainDriverInstanceV20(request);
                    }
                    else if (request.Operation is Operation.StageAttachPrepare or
                             Operation.StageAttachCommit or Operation.StageAttachAbort or
                             Operation.StageCompletionPermit or Operation.StageRetireUnexposed or
                             Operation.StageRetireAttachedPrivate or Operation.StageHandleObserved)
                    {
                        (verdict, typedLifecycleReply) = ApplyStageLifecycleV20(request);
                    }
                    else if (request.Operation is Operation.StageRename or
                             Operation.StageRenameCommit or Operation.StageRenameAbort)
                    {
                        verdict = RetargetStage(request);
                    }
                    else if (request.Operation == Operation.StageDiagnostic)
                    {
                        _logger.LogWarning("Staged kernel diagnostic: phase {Phase}, status 0x{Status:X8}, path {Path}",
                            request.Flags, request.Reserved, request.GetPath());
                        verdict = PortVerdict.Deny;
                    }
                    else
                    {
                        verdict = request.Operation is Operation.Create or Operation.Read
                            ? Judge(request) : PortVerdict.Deny;
                    }

                    try
                    {
                        if (typedReconcileReply is { } reconcileReply)
                        {
                            bool drainReplayOnly = reconcileReply.Result == StageV20Result.EpochBusy &&
                                reconcileDrainReplayOnly;
                            if (drainReplayOnly)
                            {
                                // Reconciliation may report a durably drained
                                // epoch after this channel was established. Fence
                                // ordinary work before attempting the reply; a
                                // lost response must not leave an old in-memory
                                // Ready bit authorizing mutations.
                                _activeDriverInstanceId = null;
                                _drainReplayDriverInstanceId = reconcileReply.DriverInstanceId;
                                _stageV20Ready = false;
                                _stagingRecoveryReady = false;
                            }
                            bool delivered = port.ReplyStageReconcileV20(messageId, reconcileReply);
                            if (delivered && reconcileReply.Result == StageV20Result.CapabilitiesAccepted)
                            {
                                _activeDriverInstanceId = reconcileReply.DriverInstanceId;
                                _drainReplayDriverInstanceId = null;
                                _stageV20Ready = true;
                                if (!_stagingRecovered)
                                {
                                    try
                                    {
                                        RecoverStagingSubsystem(stoppingToken);
                                        _stagingRecovered = true;
                                    }
                                    catch (Exception recoveryError)
                                    {
                                        _logger.LogCritical(recoveryError,
                                            "Stage-v20 recovery failed after capability negotiation; staged requests remain refused.");
                                        _stageV20Ready = false;
                                        _activeDriverInstanceId = null;
                                    }
                                }
                                _stagingRecoveryReady = _stagingRecovered;
                                if (_stagingRecoveryReady) _stagingReadySignal.TrySetResult(true);
                            }
                        }
                        else if (typedEpochDrainReply is { } drainReply)
                        {
                            bool delivered = port.ReplyStageEpochDrainV20(messageId, drainReply);
                            if (delivered && drainReply.Result == StageV20Result.EpochDrained)
                            {
                                _stageV20Ready = false;
                                _stagingRecoveryReady = false;
                                _activeDriverInstanceId = null;
                                _drainReplayDriverInstanceId = null;
                            }
                        }
                        else if (typedLifecycleReply is { } lifecycleReply)
                        {
                            _ = port.ReplyStageLifecycleV20(messageId, lifecycleReply);
                        }
                        else if (verdict == PortVerdict.Allow && typedCreateReply is { } typedCreate)
                        {
                            SafeUploadStageIdentityV19 wireIdentity = ToWireStageIdentity(typedCreate.StageIdentity);
                            port.ReplyStageCreateV19(messageId, request.RequestId,
                                Path.GetFileName(typedCreate.Transfer.StagePath),
                                checked((ulong)typedCreate.DestinationGeneration), in wireIdentity);
                        }
                        else if (verdict == PortVerdict.Allow && typedStatusReply is { } typedStatus)
                            port.ReplyStageStatusV19(messageId, request.RequestId, typedStatus);
                        else
                            port.Reply(messageId, request.RequestId, verdict, stageName);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Falha ao responder o veredito {RequestId}.", request.RequestId);
                    }
                }
            }
            finally
            {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
                if (evidenceBound && evidenceSender is not null)
                {
                    try
                    {
                        _admissionEvidence.UnbindAsync(evidenceSender).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Admission evidence endpoint failed to drain before FilterPort close.");
                    }
                }
#endif
                publishCancellation.Cancel();
                if (publishTask is not null)
                {
                    try { publishTask.GetAwaiter().GetResult(); }
                    catch (OperationCanceledException) { }
                    catch (Exception ex)
                    {
                        _logger.LogCritical(ex,
                            "Processamento de transferencias seladas interrompido.");
                    }
                }
                if (coverageTask is not null)
                {
                    try { coverageTask.GetAwaiter().GetResult(); }
                    catch (OperationCanceledException) { }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Admission coverage monitor stopped before FilterPort close.");
                    }
                }
                if (discardCleanupTask is not null)
                {
                    try { discardCleanupTask.GetAwaiter().GetResult(); }
                    catch (OperationCanceledException) { }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Exact private-stage cleanup worker stopped before FilterPort close.");
                    }
                }
                _grants.Unbind(port);
                _diagnostics.Unbind(port);
                _stagedJustifications.Clear();
                _stageV20Ready = false;
                _stagingRecoveryReady = false;
                _activeDriverInstanceId = null;
                _drainReplayDriverInstanceId = null;
                _stagingReadySignal.TrySetCanceled();
                _hub.Publish(new StatusNotification(
                    _policyVersion, _activeCategories, ProtectionActive: false,
                    AdmissionCoverage: AdmissionCoverageStatus.NotAvailable));
            }
        }

        _logger.LogInformation(
            "Laco do minifiltro encerrado. {Answered} vereditos, {OverBudget} fora do prazo.",
            Interlocked.Read(ref _answered),
            Interlocked.Read(ref _overBudget));
    }

    private uint RetargetStage(SafeUploadRequest request)
    {
        if (_stageJournal is null || !_stagingEnabled || !_stageV20Ready || !_stagingRecoveryReady ||
            _activeDriverInstanceId is not { } activeDriver || request.Version != Contract.Version ||
            request.RequestId == 0 || request.RequestorProcessId == 0 || request.Reserved > 1 ||
            request.ImageNameLength != 32 * sizeof(char) ||
            request.TypedFlags.HasFlag(RequestFlags.PathTruncated) ||
            request.TypedFlags.HasFlag(RequestFlags.PathNotNormalized)) return PortVerdict.Deny;
        try
        {
            if (!Guid.TryParseExact(request.GetImageName(), "N", out Guid id)) return PortVerdict.Deny;
            string? destination = NtPathTranslator.ToDosPath(request.GetPath());
            if (destination is null) return PortVerdict.Deny;
            var entry = _stageJournal.ReadAsync(id, CancellationToken.None).GetAwaiter().GetResult();
            if (entry.DriverInstanceId != activeDriver ||
                entry.Transfer.ProcessId != checked((int)request.RequestorProcessId) ||
                !IsExactLiveOwner(entry.Transfer))
                return PortVerdict.Deny;
            if (request.Operation != Operation.StageRename)
            {
                _stageJournal.CompleteRenameAsync(id, request.RequestId,
                    checked((int)request.RequestorProcessId), destination,
                    request.Operation == Operation.StageRenameCommit, CancellationToken.None)
                    .GetAwaiter().GetResult();
                return PortVerdict.Allow;
            }
            var policy = _policyStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
            var operation = new FileOperation(destination, Path.GetFileName(destination),
                Path.GetExtension(destination), 0, DateTime.MinValue, entry.Transfer.ProcessName,
                entry.Transfer.ProcessId, destination, entry.Transfer.Destination);
            if (!policy.IsMonitoredDestination(operation)) return PortVerdict.Deny;
            _stageJournal.PrepareRenameAsync(id, request.RequestId, checked((int)request.RequestorProcessId),
                destination, request.Reserved != 0, CancellationToken.None).GetAwaiter().GetResult();
            return PortVerdict.Allow;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao renomear transferencia privada {RequestId}.", request.RequestId);
            return PortVerdict.Deny;
        }
    }

    internal static DestinationKind ClassifyStagedDestination(RequestFlags flags) =>
        flags.HasFlag(RequestFlags.StageNetwork) ? DestinationKind.NetworkShare :
        flags.HasFlag(RequestFlags.StageRemovable) ? DestinationKind.RemovableDrive : DestinationKind.Cloud;

    private static bool HasValidStageAllocateFlags(SafeUploadRequest request)
    {
        const uint volumeFlags = (uint)(RequestFlags.StageRemovable | RequestFlags.StageNetwork);
        const uint referenceFlags = (uint)(RequestFlags.StageFollowup | RequestFlags.StageTombstoneCreate);
        const uint allowedFlags = volumeFlags | referenceFlags | Contract.StageV19ReplyFlag;
        uint flags = request.Flags;
        if ((flags & ~allowedFlags) != 0 || (flags & volumeFlags) == volumeFlags ||
            (flags & referenceFlags) == referenceFlags ||
            request.TypedFlags.HasFlag(RequestFlags.PathTruncated) ||
            request.TypedFlags.HasFlag(RequestFlags.ImageNameTruncated) ||
            request.TypedFlags.HasFlag(RequestFlags.PathNotNormalized))
            return false;
        return !request.TypedFlags.HasFlag(RequestFlags.StageTombstoneCreate) || request.Reserved == 2;
    }

    private (uint Verdict, StagedAllocationReply? Reply) AllocateStageV19(SafeUploadRequest request)
    {
        if (_stageAllocator is null || _stageJournal is null || !_stagingEnabled ||
            !_stageV20Ready || !_stagingRecoveryReady ||
            !request.TryReadStagePayload<SafeUploadStageAllocateV19>(Operation.StageAllocate, out var payload) ||
            payload.AllocationReservationId == Guid.Empty || payload.DriverInstanceId == Guid.Empty ||
            payload.Disposition > 5 || payload.ReferenceKind > StageV19AllocationReferenceKind.Tombstone ||
            (payload.ReferenceKind == StageV19AllocationReferenceKind.None) !=
                (payload.ParentTransferId == Guid.Empty) || request.RequestorProcessId == 0)
            return (PortVerdict.Deny, null);

        try
        {
            if (_activeDriverInstanceId != payload.DriverInstanceId)
                throw new IOException("The v19 allocation did not match the registered driver instance.");
            string? destination = NtPathTranslator.ToDosPath(request.GetPath());
            if (destination is null) return (PortVerdict.Deny, null);
            int processId = checked((int)request.RequestorProcessId);
            DestinationKind kind = ClassifyStagedDestination(request.TypedFlags);
            var intent = new StagedAllocationIntentV19(payload.AllocationReservationId,
                payload.ParentTransferId, payload.Disposition, payload.ReferenceKind,
                payload.DriverInstanceId);

            // A retry may arrive after the original process exited. Resolve an
            // already durable reservation first; it is private and immutable,
            // and the driver's post-RPC owner check will exact-discard it when
            // the original owner no longer exists.
            TransferJournalEntry? existing = TryReadStageEntry(_stageJournal,
                payload.AllocationReservationId);
            if (existing is not null)
            {
                if (!MatchesV19AllocationReplay(existing, destination, kind, processId, payload))
                    throw new IOException("The v19 reservation is already committed to a different request.");
                StagedTransfer? savedPrevious = null;
                Guid? savedTombstoneOwner = null;
                if (payload.ReferenceKind == StageV19AllocationReferenceKind.Followup)
                {
                    if (existing.ParentVersionIdentity is not { } parentIdentity ||
                        parentIdentity.TransferId != payload.ParentTransferId)
                        throw new IOException("The allocation replay lost its exact predecessor.");
                    savedPrevious = _stageJournal.ReadAsync(parentIdentity.TransferId,
                        CancellationToken.None).GetAwaiter().GetResult().Transfer;
                }
                else if (payload.ReferenceKind == StageV19AllocationReferenceKind.Tombstone)
                {
                    savedTombstoneOwner = payload.ParentTransferId;
                }
                StagedTransfer saved = existing.Transfer;
                StagedAllocationReply replay = _stageAllocator.AllocateV19Async(destination, kind,
                    saved.ProcessName, processId, saved.SessionId ??
                        throw new IOException("The v19 allocation replay has no saved session."), intent,
                    savedPrevious, savedTombstoneOwner,
                    saved.RequestorSid ?? throw new IOException("The v19 allocation replay has no saved SID."),
                    saved.RequestorProcessCreationTime ??
                        throw new IOException("The v19 allocation replay has no saved process identity."),
                    CancellationToken.None).GetAwaiter().GetResult();
                return (PortVerdict.Allow, replay);
            }

            SessionResolver.ProcessIdentity requestor = SessionResolver.GetRequiredProcessIdentity(processId);
            string processName = Process.GetProcessById(processId).ProcessName;
            Policy policy = _policyStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
            var operation = new FileOperation(destination, Path.GetFileName(destination),
                Path.GetExtension(destination), 0, DateTime.MinValue, processName,
                processId, destination, kind);
            if (!policy.IsMonitoredDestination(operation)) return (PortVerdict.Deny, null);

            StagedTransfer? previous = null;
            Guid? tombstoneOwner = null;
            if (payload.ReferenceKind == StageV19AllocationReferenceKind.Followup)
            {
                TransferJournalEntry prior = _stageJournal.ReadAsync(payload.ParentTransferId,
                    CancellationToken.None).GetAwaiter().GetResult();
                if (!prior.SealedOnce || prior.State is not (TransferJournalState.Sealed or
                        TransferJournalState.Retained or TransferJournalState.EmptyHeld) ||
                    prior.DriverInstanceId != payload.DriverInstanceId ||
                    !string.Equals(prior.Transfer.DestinationPath, destination,
                        StringComparison.OrdinalIgnoreCase) ||
                    prior.Transfer.Destination != kind || prior.Transfer.ProcessId != processId ||
                    prior.Transfer.SessionId != requestor.SessionId ||
                    !string.Equals(prior.Transfer.RequestorSid, requestor.UserSid.Value,
                        StringComparison.OrdinalIgnoreCase) ||
                    prior.Transfer.RequestorProcessCreationTime != requestor.CreationTimeFileTime)
                    return (PortVerdict.Deny, null);
                previous = prior.Transfer;
            }
            else if (payload.ReferenceKind == StageV19AllocationReferenceKind.Tombstone)
            {
                if (payload.Disposition != 2) return (PortVerdict.Deny, null);
                TransferJournalEntry owner = _stageJournal.ReadAsync(payload.ParentTransferId,
                    CancellationToken.None).GetAwaiter().GetResult();
                if (owner.Transfer.ProcessId != processId || owner.Transfer.SessionId != requestor.SessionId ||
                    !string.Equals(owner.Transfer.RequestorSid, requestor.UserSid.Value,
                        StringComparison.OrdinalIgnoreCase) ||
                    owner.Transfer.RequestorProcessCreationTime != requestor.CreationTimeFileTime)
                    return (PortVerdict.Deny, null);
                tombstoneOwner = payload.ParentTransferId;
                processName = owner.Transfer.ProcessName;
            }

            StagedAllocationReply reply = _stageAllocator.AllocateV19Async(destination, kind,
                processName, processId, requestor.SessionId, intent, previous, tombstoneOwner,
                requestor.UserSid.Value, requestor.CreationTimeFileTime,
                CancellationToken.None).GetAwaiter().GetResult();

            SessionResolver.ProcessIdentity after = SessionResolver.GetRequiredProcessIdentity(processId);
            if (after.SessionId != requestor.SessionId || after.CreationTimeFileTime != requestor.CreationTimeFileTime ||
                !after.UserSid.Equals(requestor.UserSid))
                throw new IOException("The allocation owner changed while the v19 request was being handled.");
            return (PortVerdict.Allow, reply);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Exact v19 allocation refused for request {RequestId}.", request.RequestId);
            return (PortVerdict.Deny, null);
        }
    }

    private static TransferJournalEntry? TryReadStageEntry(StagedTransferJournal journal, Guid transferId)
    {
        try { return journal.ReadAsync(transferId, CancellationToken.None).GetAwaiter().GetResult(); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    private static bool MatchesV19AllocationReplay(TransferJournalEntry entry, string destination,
        DestinationKind kind, int processId, SafeUploadStageAllocateV19 payload) =>
        entry.Transfer.TransferId == payload.AllocationReservationId &&
        string.Equals(entry.Transfer.DestinationPath, Path.GetFullPath(destination),
            StringComparison.OrdinalIgnoreCase) && entry.Transfer.Destination == kind &&
        entry.Transfer.ProcessId == processId && entry.CreateReservationId == payload.AllocationReservationId &&
        entry.AllocationDisposition == payload.Disposition &&
        entry.AllocationReferenceKind == payload.ReferenceKind &&
        entry.AllocationReferenceId == (payload.ReferenceKind == 0 ? (Guid?)null : payload.ParentTransferId) &&
        entry.DriverInstanceId == payload.DriverInstanceId && entry.StageIdentity is not null &&
        entry.DestinationGeneration > 0 && !entry.SealedOnce && entry.SealedLength is null &&
        entry.State is (TransferJournalState.Allocated or TransferJournalState.Unsealed) &&
        entry.PendingRename is null;

    private (uint Verdict, SafeUploadStageReconcileReplyV20? Reply, bool DrainReplayOnly)
        RegisterDriverInstanceV20(
        SafeUploadRequest request)
    {
        if (_stageJournal is null ||
            !_stagingEnabled || request.RequestId == 0 || request.RequestorProcessId != 0 ||
            request.Flags != 0 || request.PathLength != 0 ||
            !request.TryReadStagePayload<SafeUploadStageReconcileV20>(Operation.StageReconcile, out var payload) ||
            payload.DriverInstanceId == Guid.Empty ||
            payload.RequiredCapabilityMask != (uint)StageV20Capability.Required || payload.ReservedZero != 0)
            return (PortVerdict.Deny, null, false);

        try
        {
            StagedDriverEpochReconcileV20 reconcile = _stageJournal.ReconcileDriverInstanceV20Async(payload.DriverInstanceId,
                payload.RequiredCapabilityMask, CancellationToken.None).GetAwaiter().GetResult();
            bool accepted = reconcile == StagedDriverEpochReconcileV20.Active;
            bool drainReplayOnly = reconcile == StagedDriverEpochReconcileV20.DrainReplayOnly;
            var reply = new SafeUploadStageReconcileReplyV20
            {
                Version = Contract.StageExtensionVersion,
                StructSize = Contract.StageReconcileReplyV20Size,
                Operation = Operation.StageReconcile,
                Result = accepted ? StageV20Result.CapabilitiesAccepted : StageV20Result.EpochBusy,
                RequestId = request.RequestId,
                DriverInstanceId = payload.DriverInstanceId,
                AcceptedCapabilityMask = accepted ? (uint)StageV20Capability.Required : 0,
                ReservedZero = 0
            };
            return (PortVerdict.Allow, reply, drainReplayOnly);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Stage-v20 epoch reconciliation refused for request {RequestId}.",
                request.RequestId);
            return (PortVerdict.Deny, null, false);
        }
    }

    private (uint Verdict, SafeUploadStageEpochDrainReplyV20? Reply) DrainDriverInstanceV20(
        SafeUploadRequest request)
    {
        if (_stageJournal is null || !_stagingEnabled ||
            (_activeDriverInstanceId ?? _drainReplayDriverInstanceId) is not { } activeDriver ||
            request.RequestId == 0 ||
            request.RequestorProcessId != 0 || request.Flags != 0 || request.PathLength != 0 ||
            !request.TryReadStagePayload<SafeUploadStageEpochDrainV20>(Operation.StageEpochDrain, out var payload) ||
            payload.DriverInstanceId != activeDriver || payload.DrainNonce == 0)
            return (PortVerdict.Deny, null);

        try
        {
            bool drained = _stageJournal.DrainDriverInstanceV20Async(payload.DriverInstanceId,
                request.RequestId, payload.DrainNonce, CancellationToken.None).GetAwaiter().GetResult();
            if (drained)
            {
                _stageV20Ready = false;
                _stagingRecoveryReady = false;
                _drainReplayDriverInstanceId = payload.DriverInstanceId;
            }
            return (PortVerdict.Allow, new SafeUploadStageEpochDrainReplyV20
            {
                Version = Contract.StageExtensionVersion,
                StructSize = Contract.StageEpochDrainReplyV20Size,
                Operation = Operation.StageEpochDrain,
                Result = drained ? StageV20Result.EpochDrained : StageV20Result.EpochBusy,
                RequestId = request.RequestId,
                DriverInstanceId = payload.DriverInstanceId,
                DrainNonce = payload.DrainNonce
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Stage-v20 epoch drain refused for request {RequestId}.", request.RequestId);
            return (PortVerdict.Deny, null);
        }
    }

    private (uint Verdict, SafeUploadStageLifecycleV20? Reply) ApplyStageLifecycleV20(
        SafeUploadRequest request)
    {
        if (_stageJournal is null || !_stagingEnabled || !_stageV20Ready || !_stagingRecoveryReady ||
            _activeDriverInstanceId is not { } activeDriver || request.RequestId == 0 ||
            request.RequestorProcessId == 0 ||
            !request.TryReadStagePayload<SafeUploadStageLifecycleV20>(request.Operation, out var payload) ||
            payload.Operation != request.Operation || payload.Result != 0 || payload.RequestId != request.RequestId ||
            payload.TransferId == Guid.Empty || payload.DestinationGeneration == 0 ||
            !payload.StageIdentity.HasNonzeroFileId || payload.DriverInstanceId != activeDriver ||
            !payload.ParentDirectoryIdentity.HasNonzeroFileId)
            return (PortVerdict.Deny, null);

        try
        {
            string? destination = NtPathTranslator.ToDosPath(request.GetPath());
            if (destination is null) return (PortVerdict.Deny, null);
            int processId = checked((int)request.RequestorProcessId);
            StagedVersionIdentity version = new(payload.TransferId,
                checked((long)payload.DestinationGeneration), FromWireStageIdentity(payload.StageIdentity));
            TransferJournalEntry entry = _stageJournal.ReadAsync(payload.TransferId,
                CancellationToken.None).GetAwaiter().GetResult();
            if (entry.Transfer.Destination != ClassifyStagedDestination(request.TypedFlags))
                throw new IOException("The v20 attachment volume flags do not match the exact allocation.");

            bool ownerIsLive = IsExactLiveOwner(entry.Transfer);
            bool commitPolicyAllowed = false;
            if (request.Operation == Operation.StageAttachCommit)
            {
                Policy policy = _policyStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
                var operation = new FileOperation(destination, Path.GetFileName(destination),
                    Path.GetExtension(destination), 0, DateTime.MinValue, entry.Transfer.ProcessName,
                    entry.Transfer.ProcessId, destination, entry.Transfer.Destination);
                commitPolicyAllowed = policy.IsMonitoredDestination(operation);
            }

            uint? result = _stageJournal.ApplyAttachmentV20Async(new StagedAttachmentRequestV20(
                request.Operation, payload.RequestId, version, payload.DriverInstanceId,
                FromWireStageIdentity(payload.ParentDirectoryIdentity), destination,
                processId), ownerIsLive, commitPolicyAllowed, CancellationToken.None)
                .GetAwaiter().GetResult();
            if (result is null) return (PortVerdict.Deny, null);
            SafeUploadStageLifecycleV20 response = payload;
            response.Result = result.Value;
            return (PortVerdict.Allow, response);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Stage-v20 lifecycle operation {Operation} refused for request {RequestId}.",
                request.Operation, request.RequestId);
            return (PortVerdict.Deny, null);
        }
    }

    private static bool IsExactLiveOwner(StagedTransfer transfer)
    {
        if (transfer.RequestorSid is null || transfer.RequestorProcessCreationTime is not { } creationTime ||
            creationTime <= 0 || transfer.ProcessId <= 0)
            return false;
        try
        {
            SessionResolver.ProcessIdentity current = SessionResolver.GetRequiredProcessIdentity(transfer.ProcessId);
            return current.SessionId == transfer.SessionId &&
                current.CreationTimeFileTime == creationTime &&
                string.Equals(current.UserSid.Value, transfer.RequestorSid, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private (uint Verdict, string? StageName) AllocateStage(SafeUploadRequest request,
        out StagedAllocationReply? typedReply)
    {
        typedReply = null;
        if (_stageAllocator is null || request.Version != Contract.Version ||
            !request.HasKnownFlags || !HasValidStageAllocateFlags(request) ||
            request.RequestorProcessId == 0 || request.Reserved > 5 ||
            request.ImageNameLength == 0 ||
            request.ImageNameLength > Contract.MaxImageNameChars * sizeof(char) ||
            (request.ImageNameLength % sizeof(char)) != 0)
        {
            return (PortVerdict.Deny, null);
        }

        try
        {
            string? destination = NtPathTranslator.ToDosPath(request.GetPath());
            if (destination is null)
            {
                return (PortVerdict.Deny, null);
            }

            int requestorProcessId = checked((int)request.RequestorProcessId);
            SessionResolver.ProcessIdentity requestor =
                SessionResolver.GetRequiredProcessIdentity(requestorProcessId);

            var kind = ClassifyStagedDestination(request.TypedFlags);
            Policy policy = _policyStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
            var destinationOperation = new FileOperation(destination, Path.GetFileName(destination),
                Path.GetExtension(destination), 0, DateTime.MinValue, request.GetImageName(),
                checked((int)request.RequestorProcessId), destination, kind);
            if (!policy.IsMonitoredDestination(destinationOperation)) return (PortVerdict.Deny, null);
            StagedTransfer? previous = null;
            Guid? tombstoneOwner = null;
            string processName = request.GetImageName();
            if (request.TypedFlags.HasFlag(RequestFlags.StageTombstoneCreate))
            {
                if (_stageJournal is null || request.Reserved != 2 ||
                    request.TypedFlags.HasFlag(RequestFlags.StageFollowup) ||
                    !Guid.TryParseExact(processName, "N", out Guid ownerId))
                    return (PortVerdict.Deny, null);
                var ownerEntry = _stageJournal.ReadAsync(ownerId, CancellationToken.None)
                    .GetAwaiter().GetResult();
                if (ownerEntry.Transfer.ProcessId != requestorProcessId ||
                    !string.Equals(ownerEntry.Transfer.RequestorSid, requestor.UserSid.Value,
                        StringComparison.OrdinalIgnoreCase) ||
                    ownerEntry.Transfer.RequestorProcessCreationTime != requestor.CreationTimeFileTime)
                    return (PortVerdict.Deny, null);
                tombstoneOwner = ownerId;
                processName = ownerEntry.Transfer.ProcessName;
                // CreateAsync rechecks the committed, current tombstone and
                // writer/session under the SAME lock as generation allocation.
            }
            if (request.TypedFlags.HasFlag(RequestFlags.StageFollowup))
            {
                if (_stageJournal is null ||
                    !Guid.TryParseExact(processName, "N", out Guid previousId))
                {
                    return (PortVerdict.Deny, null);
                }
                var prior = _stageJournal.ReadAsync(previousId, CancellationToken.None)
                    .GetAwaiter().GetResult();
                if (!prior.SealedOnce ||
                    !string.Equals(prior.Transfer.DestinationPath, destination,
                        StringComparison.OrdinalIgnoreCase) ||
                    prior.Transfer.ProcessId != requestorProcessId ||
                    !string.Equals(prior.Transfer.RequestorSid, requestor.UserSid.Value,
                        StringComparison.OrdinalIgnoreCase) ||
                    prior.Transfer.RequestorProcessCreationTime != requestor.CreationTimeFileTime)
                {
                    return (PortVerdict.Deny, null);
                }
                previous = prior.Transfer;
                processName = previous.ProcessName;
            }
            if (request.TypedFlags.HasFlag(RequestFlags.StageV19Reply))
            {
                typedReply = _stageAllocator.AllocateV19Async(destination, kind, processName,
                    requestorProcessId, requestor.SessionId, request.Reserved, previous,
                    CancellationToken.None, tombstoneOwner, requestor.UserSid.Value,
                    requestor.CreationTimeFileTime).GetAwaiter().GetResult();
                return (PortVerdict.Allow, null);
            }
            var transfer = _stageAllocator.AllocateAsync(
                destination, kind, processName,
                requestorProcessId,
                requestor.SessionId,
                request.Reserved, previous,
                CancellationToken.None, tombstoneOwner, requestor.UserSid.Value,
                requestor.CreationTimeFileTime).GetAwaiter().GetResult();
            return (PortVerdict.Allow, Path.GetFileName(transfer.StagePath));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao reservar estagio para a requisicao {RequestId}.",
                request.RequestId);
            return (PortVerdict.Deny, null);
        }
    }

    private uint SealStage(SafeUploadRequest request)
    {
        if (_stageJournal is null || request.Version != Contract.Version ||
            request.TypedFlags.HasFlag(RequestFlags.PathTruncated) ||
            request.TypedFlags.HasFlag(RequestFlags.PathNotNormalized))
        {
            return PortVerdict.Deny;
        }

        try
        {
            string? stage = NtPathTranslator.ToDosPath(request.GetPath());
            if (stage is null ||
                !string.Equals(Path.GetDirectoryName(stage),
                    Path.Combine(AgentPaths.RootDirectory, "staging"),
                    StringComparison.OrdinalIgnoreCase))
            {
                return PortVerdict.Deny;
            }

            string basename = Path.GetFileName(stage);
            if (basename.Length < 32 ||
                !Guid.TryParseExact(basename[..32], "N", out Guid id))
            {
                return PortVerdict.Deny;
            }

            _stageJournal.SealAsync(id, checked((int)request.RequestorProcessId),
                stage, CancellationToken.None)
                .GetAwaiter().GetResult();
            return PortVerdict.Allow;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao selar estagio para a requisicao {RequestId}.",
                request.RequestId);
            return PortVerdict.Deny;
        }
    }

    private (uint Verdict, uint? Result) SealStageV19(SafeUploadRequest request)
    {
        if (_stageJournal is null || !_stagingEnabled || !_stageV20Ready || !_stagingRecoveryReady ||
            _activeDriverInstanceId is not { } activeDriver || request.RequestorProcessId == 0 || request.Flags != 0 ||
            !request.TryReadStagePayload<SafeUploadStageSealV19>(Operation.StageSeal, out var payload))
            return (PortVerdict.Deny, null);
        try
        {
            string? stage = NtPathTranslator.ToDosPath(request.GetPath());
            if (stage is null || !IsOwnedStagePath(stage) ||
                !Guid.TryParseExact(Path.GetFileName(stage)[..32], "N", out Guid id) ||
                payload.DestinationGeneration == 0 || !payload.StageIdentity.HasNonzeroFileId)
                return (PortVerdict.Deny, null);
            var expected = new StagedVersionIdentity(id, checked((long)payload.DestinationGeneration),
                FromWireStageIdentity(payload.StageIdentity));
            TransferJournalEntry before = _stageJournal.ReadAsync(id, CancellationToken.None).GetAwaiter().GetResult();
            if (before.DriverInstanceId != activeDriver || before.StageIdentity != expected.StageIdentity ||
                before.DestinationGeneration != expected.DestinationGeneration ||
                before.AttachmentStateV20 != StagedAttachmentStateV20.HandleObserved)
                return (PortVerdict.Deny, null);
            TransferJournalEntry sealedEntry = _stageJournal.SealAsync(id,
                checked((int)request.RequestorProcessId), stage, CancellationToken.None, expected)
                .GetAwaiter().GetResult();
            uint result = sealedEntry.SealedLength switch
            {
                0 => StageV19Result.EmptyHeld,
                > 0 => StageV19Result.SealedNonempty,
                _ => throw new IOException("The v19 seal result has no stable measured length.")
            };
            return (PortVerdict.Allow, result);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Exact v19 seal refused for request {RequestId}.", request.RequestId);
            return (PortVerdict.Deny, null);
        }
    }

    /// <summary>
    /// T5: the owner deleted its private version before it was sealed. The driver has closed its backing; the journal marks the
    /// version Discarded (never inspected or published, generation kept), then the stage is removed before acknowledgement. If
    /// removal fails, deny the request so the driver keeps the version pending and retries while the service remains connected.
    /// </summary>
    private uint DiscardStage(SafeUploadRequest request)
    {
        if (_stageJournal is null || request.Version != Contract.Version ||
            request.TypedFlags.HasFlag(RequestFlags.PathTruncated) ||
            request.TypedFlags.HasFlag(RequestFlags.PathNotNormalized))
        {
            return PortVerdict.Deny;
        }

        try
        {
            string? stage = NtPathTranslator.ToDosPath(request.GetPath());
            if (stage is null ||
                !string.Equals(Path.GetDirectoryName(stage),
                    Path.Combine(AgentPaths.RootDirectory, "staging"),
                    StringComparison.OrdinalIgnoreCase))
            {
                return PortVerdict.Deny;
            }

            string basename = Path.GetFileName(stage);
            if (basename.Length < 32 ||
                !Guid.TryParseExact(basename[..32], "N", out Guid id))
            {
                return PortVerdict.Deny;
            }

            TransferJournalEntry discarded = _stageJournal.DiscardAsync(id, checked((int)request.RequestorProcessId),
                stage, CancellationToken.None)
                .GetAwaiter().GetResult();
            if (!StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(stage, discarded.StageIdentity,
                    out Exception? deletionFailure))
            {
                if (deletionFailure is null)
                    _logger.LogWarning("Estagio descartado {TransferId} continua presente; o driver tentara novamente.", id);
                else
                    _logger.LogWarning(deletionFailure, "Estagio descartado {TransferId} continua presente; o driver tentara novamente.", id);
                return PortVerdict.Deny;
            }
            return PortVerdict.Allow;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao descartar estagio para a requisicao {RequestId}.",
                request.RequestId);
            return PortVerdict.Deny;
        }
    }

    private (uint Verdict, uint? Result) DiscardStageV19(SafeUploadRequest request)
    {
        if (_stageJournal is null || !_stagingEnabled || !_stageV20Ready || !_stagingRecoveryReady ||
            request.Flags != 0 ||
            !request.TryReadStagePayload<SafeUploadStageVersionV19>(Operation.StageDiscard, out var payload) ||
            payload.Kind < StageV19DiscardKind.PrivateVersion ||
            payload.Kind > (uint)StagedDiscardKind.UnattachedAllocation ||
            payload.DestinationGeneration == 0 || !payload.StageIdentity.HasNonzeroFileId ||
            payload.ReservationId == Guid.Empty || _activeDriverInstanceId is not { } activeDriverInstanceId ||
            (request.RequestorProcessId == 0 && payload.Kind is not
                (StageV19DiscardKind.OwnerExitEmpty or StageV19DiscardKind.DriverUnloadEmpty)))
            return (PortVerdict.Deny, null);
        try
        {
            string? stage = NtPathTranslator.ToDosPath(request.GetPath());
            if (stage is null || !IsOwnedStagePath(stage) ||
                !Guid.TryParseExact(Path.GetFileName(stage)[..32], "N", out Guid id))
                return (PortVerdict.Deny, null);
            var version = new StagedVersionIdentity(id, checked((long)payload.DestinationGeneration),
                FromWireStageIdentity(payload.StageIdentity));
            var discard = new StagedDiscardRequest(payload.ReservationId, version,
                (StagedDiscardKind)payload.Kind);
            StagedDiscardStatus status = _stageJournal.BeginOrConfirmDiscardAsync(discard,
                CancellationToken.None, request.RequestorProcessId == 0 ? null :
                    checked((int)request.RequestorProcessId),
                activeDriverInstanceId).GetAwaiter().GetResult();
            return (PortVerdict.Allow, status == StagedDiscardStatus.Acknowledged
                ? StageV19Result.DiscardAcknowledged : StageV19Result.DiscardPending);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Exact v19 discard refused for request {RequestId}.", request.RequestId);
            return (PortVerdict.Deny, null);
        }
    }

    private (uint Verdict, StagedAllocationReply? Reply) CreateAfterPrivateDiscardStage(
        SafeUploadRequest request)
    {
        const uint volumeFlags = (uint)(RequestFlags.StageRemovable | RequestFlags.StageNetwork);
        if (_stageJournal is null || _stageAllocator is null || request.RequestorProcessId == 0 ||
            !_stagingEnabled || !_stageV20Ready || !_stagingRecoveryReady ||
            (request.Flags & ~volumeFlags) != 0 ||
            (request.Flags & volumeFlags) == volumeFlags ||
            !request.TryReadStagePayload<SafeUploadStageCreateAfterDiscardV19>(
                Operation.StageCreateAfterDiscard, out var payload) ||
            payload.ReservationId == Guid.Empty || payload.DeleteTransferId == Guid.Empty ||
            payload.DeleteGeneration == 0 || !payload.DeleteStageIdentity.HasNonzeroFileId ||
            !payload.ParentDirectoryIdentity.HasNonzeroFileId)
            return (PortVerdict.Deny, null);
        try
        {
            string? destination = NtPathTranslator.ToDosPath(request.GetPath());
            if (destination is null || _activeDriverInstanceId is not { } activeDriverInstanceId)
                return (PortVerdict.Deny, null);
            int processId = checked((int)request.RequestorProcessId);
            TransferJournalEntry delete = _stageJournal.ReadAsync(payload.DeleteTransferId,
                CancellationToken.None).GetAwaiter().GetResult();
            DestinationKind kind = ClassifyStagedDestination(request.TypedFlags);
            var deleteIdentity = new StagedVersionIdentity(payload.DeleteTransferId,
                checked((long)payload.DeleteGeneration), FromWireStageIdentity(payload.DeleteStageIdentity));
            StagedStageIdentity parentDirectoryIdentity = FromWireStageIdentity(payload.ParentDirectoryIdentity);
            if (delete.DestinationGeneration != deleteIdentity.DestinationGeneration ||
                delete.StageIdentity != deleteIdentity.StageIdentity || delete.PendingRename is not null ||
                !string.Equals(delete.Transfer.DestinationPath, Path.GetFullPath(destination),
                    StringComparison.OrdinalIgnoreCase) || delete.Transfer.Destination != kind ||
                delete.Transfer.ProcessId != processId || delete.DriverInstanceId != activeDriverInstanceId)
                throw new IOException("The create-after request does not identify the exact V2 owner and destination.");
            if (delete.ParentVersionIdentity is not { } exactParentIdentity)
                throw new IOException("The create-after V2 has no exact V1 ancestry.");
            TransferJournalEntry exactParent = _stageJournal.ReadAsync(exactParentIdentity.TransferId,
                CancellationToken.None).GetAwaiter().GetResult();
            if (exactParent.StageIdentity is null || exactParent.DestinationGeneration <= 0 ||
                new StagedVersionIdentity(exactParent.Transfer.TransferId,
                    exactParent.DestinationGeneration, exactParent.StageIdentity) != exactParentIdentity ||
                exactParent.State != TransferJournalState.EmptyHeld || exactParent.SealedLength != 0 ||
                exactParent.DriverInstanceId != activeDriverInstanceId ||
                !string.Equals(exactParent.Transfer.DestinationPath, Path.GetFullPath(destination),
                    StringComparison.OrdinalIgnoreCase) || exactParent.Transfer.Destination != kind ||
                exactParent.Transfer.ProcessId != processId ||
                exactParent.Transfer.SessionId != delete.Transfer.SessionId ||
                !string.Equals(exactParent.Transfer.RequestorSid, delete.Transfer.RequestorSid,
                    StringComparison.OrdinalIgnoreCase) ||
                exactParent.Transfer.RequestorProcessCreationTime != delete.Transfer.RequestorProcessCreationTime)
                throw new IOException("The create-after V1 predecessor is not bound to this driver epoch and owner.");

            TransferJournalEntry? existingChild = TryReadStageEntry(_stageJournal, payload.ReservationId);
            bool resumeDurableIntent = existingChild is not null ||
                (delete.State == TransferJournalState.DiscardPending &&
                 delete.DiscardKind == StagedDiscardKind.PrivateVersion &&
                 delete.DiscardReservationId == delete.Transfer.TransferId &&
                 delete.CreateAfterReservationId == payload.ReservationId);
            uint sessionId;
            string requestorSid;
            long creationTime;
            bool liveOwnerRequired = !resumeDurableIntent;
            if (existingChild is not null)
            {
                if (existingChild.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed) ||
                    existingChild.CreateReservationId != payload.ReservationId ||
                    existingChild.DeleteVersionIdentity != deleteIdentity ||
                    existingChild.ParentDirectoryIdentity != parentDirectoryIdentity ||
                    existingChild.AllocationDisposition != payload.Disposition ||
                    existingChild.AllocationReferenceId != payload.DeleteTransferId ||
                    existingChild.AllocationReferenceKind != 1u ||
                    existingChild.DriverInstanceId != activeDriverInstanceId ||
                    !string.Equals(existingChild.Transfer.DestinationPath, Path.GetFullPath(destination),
                        StringComparison.OrdinalIgnoreCase) || existingChild.Transfer.Destination != kind ||
                    existingChild.Transfer.ProcessId != processId ||
                    delete.State != TransferJournalState.DiscardPending ||
                    delete.CreateAfterReservationId != payload.ReservationId)
                    throw new IOException("The create-after reservation is already committed to a different request.");
                sessionId = existingChild.Transfer.SessionId ??
                    throw new IOException("The create-after replay has no saved session.");
                requestorSid = existingChild.Transfer.RequestorSid ??
                    throw new IOException("The create-after replay has no saved SID.");
                creationTime = existingChild.Transfer.RequestorProcessCreationTime ??
                    throw new IOException("The create-after replay has no saved process identity.");
            }
            else if (resumeDurableIntent)
            {
                // Crash after V2 became nonsealable but before V3's manifest
                // was written. The exact V2 reservation binds owner metadata;
                // finish that same transaction even if the app has exited.
                if (delete.CreateAfterReservationId != payload.ReservationId)
                    throw new IOException("The pending V2 delete belongs to another create-after reservation.");
                sessionId = delete.Transfer.SessionId ??
                    throw new IOException("The pending V2 delete has no saved session.");
                requestorSid = delete.Transfer.RequestorSid ??
                    throw new IOException("The pending V2 delete has no saved SID.");
                creationTime = delete.Transfer.RequestorProcessCreationTime ??
                    throw new IOException("The pending V2 delete has no saved process identity.");
            }
            else
            {
                SessionResolver.ProcessIdentity requestor = SessionResolver.GetRequiredProcessIdentity(processId);
                if (delete.Transfer.SessionId != requestor.SessionId ||
                    !string.Equals(delete.Transfer.RequestorSid, requestor.UserSid.Value,
                        StringComparison.OrdinalIgnoreCase) ||
                    delete.Transfer.RequestorProcessCreationTime != requestor.CreationTimeFileTime)
                    throw new IOException("The create-after owner does not match its exact V2 predecessor.");
                sessionId = requestor.SessionId;
                requestorSid = requestor.UserSid.Value;
                creationTime = requestor.CreationTimeFileTime;
            }

            if (liveOwnerRequired)
            {
                string processName = Process.GetProcessById(processId).ProcessName;
                Policy policy = _policyStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
                var operation = new FileOperation(destination, Path.GetFileName(destination),
                    Path.GetExtension(destination), 0, DateTime.MinValue, processName,
                    processId, destination, kind);
                if (!policy.IsMonitoredDestination(operation)) return (PortVerdict.Deny, null);
            }

            var createRequest = new StagedCreateAfterDiscardRequest(payload.ReservationId,
                deleteIdentity, parentDirectoryIdentity, payload.Disposition,
                destination, kind, processId, sessionId, requestorSid,
                creationTime, activeDriverInstanceId);
            StagedAllocationReply reply = _stageAllocator.CreateAfterPrivateDiscardAsync(createRequest,
                CancellationToken.None).GetAwaiter().GetResult();

            if (liveOwnerRequired)
            {
                SessionResolver.ProcessIdentity after = SessionResolver.GetRequiredProcessIdentity(processId);
                if (after.SessionId != sessionId || !string.Equals(after.UserSid.Value, requestorSid,
                        StringComparison.OrdinalIgnoreCase) || after.CreationTimeFileTime != creationTime)
                    throw new IOException("The requesting process identity changed before stage attachment.");
            }
            return (PortVerdict.Allow, reply);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CREATE_AFTER_DISCARD refused for request {RequestId}.", request.RequestId);
            return (PortVerdict.Deny, null);
        }
    }

    private static StagedStageIdentity FromWireStageIdentity(SafeUploadStageIdentityV19 identity) =>
        new(identity.VolumeSerialNumber, identity.FileIdHigh, identity.FileIdLow);

    private static SafeUploadStageIdentityV19 ToWireStageIdentity(StagedStageIdentity identity) =>
        new() { VolumeSerialNumber = identity.VolumeSerialNumber,
            FileIdLow = identity.FileIdLow, FileIdHigh = identity.FileIdHigh };

    private static bool IsOwnedStagePath(string path) =>
        string.Equals(Path.GetDirectoryName(path),
            Path.Combine(AgentPaths.RootDirectory, "staging"), StringComparison.OrdinalIgnoreCase) &&
        Path.GetFileName(path).Length >= 32;

    private async Task PublishSealedLoopAsync(CancellationToken cancellationToken)
    {
        if (_stageJournal is null || _stagePublisher is null) return;

        await _stagingReadySignal.Task.WaitAsync(cancellationToken).ConfigureAwait(false);

        while (!cancellationToken.IsCancellationRequested && _stageV20Ready && _stagingRecoveryReady)
        {
            foreach (var entry in await _stageJournal.ReadPendingAsync(cancellationToken)
                         .ConfigureAwait(false))
            {
                if (entry.PendingRename is not null) continue;
                if (entry.State == TransferJournalState.EmptyHeld)
                {
                    try
                    {
                        await _stagePublisher.ReportEmptyHeldAsync(entry.Transfer.TransferId, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Falha ao notificar que o salvamento vazio permanece privado {TransferId}.",
                            entry.Transfer.TransferId);
                    }
                    continue;
                }
                if (entry.State == TransferJournalState.Blocked)
                {
                    try
                    {
                        await _stagePublisher.ProcessBlockedCleanupAsync(entry, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Falha ao limpar estagio bloqueado {TransferId}.",
                            entry.Transfer.TransferId);
                    }
                    continue;
                }
                if (entry.State == TransferJournalState.Released &&
                    entry.HandbackState == StagedHandbackState.Verified &&
                    entry.JustificationWindowClosed && !entry.StageDeleted)
                {
                    try
                    {
                        await _stagePublisher.ProcessBlockedCleanupAsync(entry, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Falha ao limpar estagio publicado {TransferId}.",
                            entry.Transfer.TransferId);
                    }
                    continue;
                }
                if (entry.State != TransferJournalState.Sealed) continue;

                try
                {
                    await _stagePublisher.PublishAsync(entry.Transfer, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Falha ao inspecionar transferencia selada {TransferId}.",
                        entry.Transfer.TransferId);
                    var current = await _stageJournal.ReadAsync(
                        entry.Transfer.TransferId, cancellationToken).ConfigureAwait(false);
                    if (current.State is (TransferJournalState.Sealed or TransferJournalState.Inspecting or TransferJournalState.Approved) &&
                        current.PendingRename is null &&
                        current.Transfer == entry.Transfer)
                    {
                        try
                        {
                            await _stageJournal.TransitionAsync(entry.Transfer.TransferId,
                                current.State, TransferJournalState.Retained,
                                null, cancellationToken, entry.Transfer).ConfigureAwait(false);
                        }
                        catch (Exception changed) when (changed is IOException or InvalidOperationException)
                        {
                            // A rename can prepare after the read above. Its
                            // durable hold wins; keep the publisher loop alive.
                            _logger.LogDebug(changed, "Transferencia mudou antes da retencao {TransferId}.",
                                entry.Transfer.TransferId);
                        }
                    }
                }
            }
            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ProcessExactDiscardCleanupLoopAsync(CancellationToken cancellationToken)
    {
        if (_stageJournal is null) return;
        const int MaximumItemsPerPass = 16;
        await _stagingReadySignal.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        while (!cancellationToken.IsCancellationRequested && _stageV20Ready && _stagingRecoveryReady)
        {
            IReadOnlyList<StagedDiscardRequest> pending = await _stageJournal
                .ReadDiscardPendingAsync(cancellationToken).ConfigureAwait(false);
            if (pending.Count > 0)
            {
                int start = _discardCleanupCursor % pending.Count;
                int count = Math.Min(MaximumItemsPerPass, pending.Count);
                for (int offset = 0; offset < count; offset++)
                {
                    StagedDiscardRequest request = pending[(start + offset) % pending.Count];
                    try
                    {
                        if (request.Kind == StagedDiscardKind.EmptyHeldPredecessor && _stagePublisher is not null)
                        {
                            TransferJournalEntry child = await _stageJournal.ReadAsync(request.ReservationId,
                                cancellationToken).ConfigureAwait(false);
                            if (child.ParentVersionIdentity == request.Version &&
                                child.DeleteVersionIdentity is null && child.CreateAfterReservationId is null &&
                                child.State == TransferJournalState.Released && !child.StageDeleted)
                            {
                                // Released children may be removed only through
                                // the same driver-held gate as ordinary
                                // publication disposal. A true/held response
                                // leaves both the child and V1 cleanup pending.
                                await _stagePublisher.DisposeReleasedStageAsync(child.Transfer.TransferId,
                                    cancellationToken).ConfigureAwait(false);
                                child = await _stageJournal.ReadAsync(request.ReservationId,
                                    cancellationToken).ConfigureAwait(false);
                                if (!child.StageDeleted) continue;
                            }
                        }
                        await _stageJournal.CompleteDiscardAsync(request, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        // A locked/replaced stage remains private and pending.
                        // Another pass retries the exact durable tuple.
                        _logger.LogDebug(ex, "Exact private-stage cleanup remains pending for {TransferId}.",
                            request.Version.TransferId);
                    }
                }
                _discardCleanupCursor = (start + count) % Math.Max(1, pending.Count);
            }
            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Traduz a política do agente para a do driver e empurra.
    ///
    /// A política durável já protege os escopos do boot enquanto o agente
    /// está desconectado. A atualização só fica ativa depois da gravação
    /// durável e da aceitação pela porta autenticada.
    /// </summary>

    private bool InitializeStagingSubsystem(FilterPort port, CancellationToken stoppingToken)
    {
        try
        {
            string root = Path.Combine(AgentPaths.RootDirectory, "staging");
            string journal = Path.Combine(AgentPaths.RootDirectory, "staging-journal");
            _stageJournal = new StagedTransferJournal(journal, requireProtectedParent: true);
            _stageAllocator = new StagedTransferAllocator(root, _stageJournal,
                requireProtectedParent: true, requireSystemIdentity: true);
            _stagePublisher = new StagedTransferPublisher(
                _inspection, _hub, _stageJournal, root,
                new StagedPublicationGate(port), _stagedJustifications, _logger,
                _policyStore);
            // The v20 reconcile request is the first stage mutation-capable
            // message on a new authenticated port. Journal recovery and the
            // publication/discard workers wait until that exact receipt has
            // been delivered to the kernel.
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Falha ao inicializar o diario de transferencias.");
            return false;
        }
    }

    private void RecoverStagingSubsystem(CancellationToken stoppingToken)
    {
        if (_stageJournal is null || _stagePublisher is null)
            throw new InvalidOperationException("The staging subsystem is not initialized.");

            _stageJournal.RetainInterruptedAsync(stoppingToken).GetAwaiter().GetResult();
            _stageJournal.ReconcilePublishingAsync(stoppingToken).GetAwaiter().GetResult();
            foreach (TransferJournalEntry entry in _stageJournal.ReadPendingAsync(stoppingToken)
                         .GetAwaiter().GetResult())
            {
                if (entry.State == TransferJournalState.EmptyHeld)
                    _stagePublisher.ReportEmptyHeldAsync(entry.Transfer.TransferId, stoppingToken)
                        .GetAwaiter().GetResult();
                else if (entry.State == TransferJournalState.Blocked)
                    _stagePublisher.RecoverBlockedAsync(entry, stoppingToken).GetAwaiter().GetResult();
                else if (entry.State == TransferJournalState.Released &&
                         entry.HandbackState == StagedHandbackState.Verified &&
                         entry.JustificationWindowClosed && !entry.StageDeleted)
                    _stagePublisher.ProcessBlockedCleanupAsync(entry, stoppingToken).GetAwaiter().GetResult();
            }
            // Approved stages a previous run could not dispose of (or that the driver dropped at unload).
            _stagePublisher.DisposeReleasedStagesAsync(stoppingToken).GetAwaiter().GetResult();
            // T5: stages of discarded versions that could not be removed when they were discarded.
            foreach (TransferJournalEntry discarded in _stageJournal.ReadDiscardedWithStageAsync(stoppingToken)
                         .GetAwaiter().GetResult())
            {
                if (!StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(discarded.Transfer.StagePath,
                        discarded.StageIdentity, out Exception? deletionFailure))
                    _logger.LogWarning(deletionFailure, "Estagio descartado {TransferId} nao pode ser removido.",
                        discarded.Transfer.TransferId);
            }
            // T11: finished transfers from earlier boots leave the journal, so it stops growing with every save. The cutoff is a day
            // before this boot: no per-boot driver state can name those transfers, and the guest clock's step after boot is covered.
            try
            {
                DateTimeOffset bootUtc = DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
                int compacted = _stageJournal.CompactAsync(bootUtc - TimeSpan.FromDays(1), stoppingToken).GetAwaiter().GetResult();
                if (compacted > 0)
                    _logger.LogInformation("Diario de transferencias compactado: {Count} entradas concluidas removidas.", compacted);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Falha ao compactar o diario de transferencias; ele sera compactado no proximo inicio.");
            }
    }

    private bool TryPushPolicy(FilterPort port
        )
    {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        // Never let a later failed push reuse fingerprint metadata from an
        // earlier accepted candidate when considering endpoint binding.
        _acceptedPolicyFingerprint = null;
#endif
        try
        {
            Policy policy = _policyStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
            MonitoredScopes scopes = policy.MonitoredScopes;
            _budget = policy.InspectionTimeout;

            SafeUploadPolicyMessage driverPolicy = MinifilterPolicyFactory.Build(policy);
            string[] candidateCoveragePrefixes = AdmissionCoverageEvaluator.GetExpectedPrefixes(driverPolicy);
            uint candidateCoveragePolicyFlags = driverPolicy.Flags;
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            byte[] candidatePolicyFingerprint =
                AdmissionEvidencePolicyFingerprint.ComputeCanonicalCandidateFingerprint(driverPolicy);
#endif
            var bootPolicyWriter = new BootPolicyRegistryWriter(new WindowsBootPolicyRegistryBackend());
            _bootPolicyGate.Wait();
            try
            {
                bootPolicyWriter.Apply(driverPolicy,
                    () => port.SetPolicy(driverPolicy),
                    () => port.SetPolicy(driverPolicy, finalizeDurableBootScopes: true));
            }
            finally
            {
                _bootPolicyGate.Release();
            }
            _overrideAllowed = policy.OverrideAllowed;
            _auditOnly = policy.AuditOnly;
            _policyVersion = policy.Version;
            _activeCategories = policy.ActiveCategories.Count;
            _acceptedCoveragePrefixes = candidateCoveragePrefixes;
            _acceptedCoveragePolicyFlags = candidateCoveragePolicyFlags;
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            _acceptedPolicyFingerprint = candidatePolicyFingerprint;
#endif

            _logger.LogInformation(
                "Politica v{Version} empurrada ao driver: {Extensions} extensoes, " +
                "{Paths} destinos, classificacao de fontes em todos os volumes.",
                policy.Version,
                scopes.Extensions.Count,
                scopes.DestinationPaths.Count);

            if (policy.AuditOnly)
            {
                // Em letras garrafais de proposito: uma maquina que alguem
                // acha protegida e nao esta e pior que uma sem agente.
                _logger.LogWarning(
                    "MODO AUDITORIA: nada sera negado. As operacoes sao avaliadas e contadas " +
                    "em WouldHaveDenied, que mede quanto o bloqueio custaria se fosse ligado.");
            }

            _logger.LogInformation(
                "Prazo: motor {Budget} ms (RN-012), kernel espera {Kernel} ms.",
                _budget.TotalMilliseconds,
                (policy.InspectionTimeout + MinifilterPolicyFactory.Margin).TotalMilliseconds);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao empurrar a politica. O driver ficaria carregado sem inspecionar nada.");
            return false;
        }
    }

    private async Task PublishAdmissionCoverageLoopAsync(
        FilterPort port,
        IReadOnlyList<string> expectedPrefixes,
        uint expectedPolicyFlags,
        int policyVersion,
        int activeCategories,
        bool auditOnly,
        CancellationToken cancellationToken)
    {
        uint boundNativeGeneration = 0;
        AdmissionCoverageStatus? lastStatus = AdmissionCoverageStatus.Pending;
        string? lastReason = "CoveragePending";
        uint lastPublishedGeneration = 0;
        bool announcedReady = false;
        string? lastQueryFailure = null;

        while (!cancellationToken.IsCancellationRequested)
        {
            AdmissionCoverageDecision decision;
            try
            {
                AdmissionCoverageReceipt receipt = port.GetAdmissionCoverageStatus();
                decision = AdmissionCoverageEvaluator.Evaluate(receipt, expectedPrefixes,
                    expectedPolicyFlags, boundNativeGeneration);
                if (boundNativeGeneration == 0 && decision.NativePolicyGeneration != 0)
                    boundNativeGeneration = decision.NativePolicyGeneration;
                lastQueryFailure = null;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                if (lastQueryFailure != ex.GetType().Name)
                {
                    _logger.LogWarning(ex, "Admission coverage receipt is unavailable; status remains degraded.");
                    lastQueryFailure = ex.GetType().Name;
                }
                decision = new AdmissionCoverageDecision(
                    AdmissionCoverageReadiness.Degraded, "CoverageQueryFailed", boundNativeGeneration);
            }

            AdmissionCoverageStatus status = decision.Readiness switch
            {
                AdmissionCoverageReadiness.Ready => AdmissionCoverageStatus.Ready,
                AdmissionCoverageReadiness.Pending => AdmissionCoverageStatus.Pending,
                _ => AdmissionCoverageStatus.Degraded
            };
            if (status == AdmissionCoverageStatus.Ready && !announcedReady)
            {
                ReadySignal.Announce(ReadySignal.ServiceEvent);
                announcedReady = true;
            }

            if (status != lastStatus || !string.Equals(decision.Reason, lastReason, StringComparison.Ordinal) ||
                decision.NativePolicyGeneration != lastPublishedGeneration)
            {
                // Protection that cannot be confirmed is an operator-visible event; the default
                // service event-log filter keeps warnings, so Pending/Degraded carry their reason.
                if (status == AdmissionCoverageStatus.Ready)
                    _logger.LogInformation("Admission coverage Ready (native generation {Generation}).",
                        decision.NativePolicyGeneration);
                else
                    _logger.LogWarning("Admission coverage {Status}: {Reason} (native generation {Generation}).",
                        status, decision.Reason, decision.NativePolicyGeneration);
                _hub.Publish(new StatusNotification(policyVersion, activeCategories,
                    ProtectionActive: true, AuditOnly: auditOnly,
                    AdmissionCoverage: status, AdmissionCoverageReason: decision.Reason,
                    NativePolicyGeneration: decision.NativePolicyGeneration == 0 ? null :
                        decision.NativePolicyGeneration));
                lastStatus = status;
                lastReason = decision.Reason;
                lastPublishedGeneration = decision.NativePolicyGeneration;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Decide uma requisição dentro do orçamento, ou libera sem inspeção.
    /// </summary>
    private uint Judge(SafeUploadRequest request)
    {
        Interlocked.Increment(ref _answered);

        if (request.Version != Contract.Version)
        {
            // Regra 5 do contrato: o que não se entende, permite-se.
            return PortVerdict.Allow;
        }

        FileOperation? operation = Translate(request);

        if (operation is null)
        {
            return PortVerdict.Allow;
        }

        // Numa requisição de ORIGEM, negar não impede nada: o driver permite
        // a leitura e apenas marca o processo. É por isso que "não consegui
        // inspecionar" pode virar negação aqui sem custo para quem abre o
        // arquivo - e não pode do lado do destino, onde negar impede mesmo.
        bool sourceScope = request.TypedFlags.HasFlag(RequestFlags.ScopeSource);

        var stopwatch = Stopwatch.StartNew();

        try
        {
            using var budget = new CancellationTokenSource(_budget);

            // GetAwaiter().GetResult() e não .Result: preserva a exceção
            // original em vez de embrulhá-la em AggregateException. O laço é
            // síncrono por natureza — o kernel está bloqueado esperando.
            InspectionResult result = _inspection
                .InspectAsync(operation, budget.Token)
                .GetAwaiter()
                .GetResult();

            Announce(operation, result);

            if (result.IsBlocked)
            {
                return PortVerdict.Deny;
            }

            // Nao consegui inspecionar: marque, nao libere em silencio.
            //
            // Ha tres caminhos que chegam aqui - file_too_large,
            // unsupported_format e inspection_timeout - e nos tres o
            // conteudo nunca foi olhado. Liberar sem marcar significa que
            // um arquivo grande demais, ou de formato sem extrator, sai
            // livre para qualquer destino vigiado. O limite de 20 MB e
            // deliberado e previsivel, o que o torna trivial de explorar:
            // basta encher o arquivo ate passar do corte.
            //
            // O custo e um falso positivo: um arquivo legitimo que nao
            // coube na inspecao marca o processo pelo TTL da tabela. E
            // aceitavel porque a marca nao impede trabalho nenhum - so
            // escrita em destino vigiado - e porque a alternativa e um
            // buraco que a propria politica documenta como aberto.
            if (sourceScope && result.Verdict == Core.Domain.Verdict.AllowedWithoutInspection)
            {
                _logger.LogInformation(
                    "{Arquivo} nao pode ser inspecionado ({Motivo}): processo {Pid} marcado por precaucao.",
                    operation.FileName,
                    result.Reason ?? "sem motivo registrado",
                    operation.ProcessId);

                return PortVerdict.Deny;
            }

            return PortVerdict.Allow;
        }
        catch (OperationCanceledException)
        {
            Interlocked.Increment(ref _overBudget);

            _logger.LogWarning(
                "Inspecao de {Path} passou de {Budget} ms.{Consequencia}",
                operation.FileName,
                _budget.TotalMilliseconds,
                sourceScope ? " Processo marcado por precaucao." : " A operacao passou SEM INSPECAO.");

            // Mesma regra do caminho acima: na origem, marca; no destino,
            // libera, porque negar ali impede o trabalho de verdade.
            return sourceScope ? PortVerdict.Deny : PortVerdict.Allow;
        }
        catch (Exception ex)
        {
            // Fail-open, como o resto do agente: um DLP que bloqueia quando
            // quebra impede o usuário de trabalhar e é desligado na primeira
            // semana.
            _logger.LogError(
                ex,
                "Erro ao inspecionar {Path}.{Consequencia}",
                operation.FileName,
                sourceScope ? " Processo marcado por precaucao." : " Liberado sem inspecao.");

            return sourceScope ? PortVerdict.Deny : PortVerdict.Allow;
        }
        finally
        {
            stopwatch.Stop();
        }
    }

    /// <summary>
    /// Publica o evento para o painel, quando houver o que publicar.
    ///
    /// A sessão de origem vem do PID, e aqui ela finalmente resolve: com o
    /// <see cref="FileSystemInterceptor"/> o PID chega zero e toda notificação
    /// vira difusão. O minifiltro informa quem pediu a operação, então a
    /// entrega passa a ser dirigida a quem de fato a fez - o caminho que já
    /// existia no serviço esperando por esta informação.
    /// </summary>
    private void Announce(FileOperation operation, InspectionResult result)
    {
        if (!result.InScope)
        {
            // Fora de escopo não gera evento, e portanto não há o que anunciar.
            return;
        }

        try
        {
            IReadOnlyList<AuditEvent> recent =
                _auditSink.ReadRecentAsync(5, CancellationToken.None).GetAwaiter().GetResult();

            AuditEvent? auditEvent = recent.FirstOrDefault(e =>
                string.Equals(e.FileName, operation.FileName, StringComparison.OrdinalIgnoreCase));

            if (auditEvent is not null)
            {
                uint? sessionId = SessionResolver.TryGetSessionId(operation.ProcessId);

                // Um bloqueio fica elegivel a justificativa, e so ele. Isto e
                // o que impede a interface de liberar o que quiser: uma
                // justificativa so vale contra um identificador que o servico
                // registrou aqui, para a sessao que recebeu a notificacao.
                if (result.IsBlocked)
                {
                    _pending.Remember(auditEvent.EventId.ToString("D"), new PendingOverrides.Entry(
                        ProcessId: (uint) operation.ProcessId,
                        NtPath: PolicyBuilder.ToNtPath(operation.DestinationPath),
                        FileName: operation.FileName,
                        SessionId: sessionId,
                        ExpiresAt: DateTimeOffset.UtcNow + PendingOverrides.Window));
                }

                _hub.Publish(new EventNotification(
                    auditEvent, result.Findings,
                    OverrideAllowed: result.IsBlocked && _overrideAllowed), sessionId);
            }
        }
        catch (Exception ex)
        {
            // Falhar em avisar o painel não pode mudar o veredito nem derrubar
            // o laço: a proteção continua, o usuário é que não vê o aviso.
            _logger.LogWarning(ex, "Falha ao publicar a notificacao de {Arquivo}.", operation.FileName);
        }
    }

    /// <summary>
    /// Monta a <see cref="FileOperation"/> a partir do que o kernel mandou.
    ///
    /// Devolve null quando a operação não dá para inspecionar — caminho sem
    /// letra de unidade, arquivo que sumiu entre o pedido e a leitura. Nunca
    /// é motivo para bloquear.
    /// </summary>
    private FileOperation? Translate(SafeUploadRequest request)
    {
        string? path = NtPathTranslator.ToDosPath(request.GetPath());

        if (path is null)
        {
            return null;
        }

        // Tamanho e data não vêm na requisição, então saem do sistema de
        // arquivos — I/O dentro do caminho do veredito, que é justamente o
        // que o orçamento não comporta com folga. O driver já conhece os
        // dois (ele os usa como carimbo do cache de fluxo) e o campo
        // Reserved da requisição existe: mandá-los junto tiraria este acesso
        // do caminho quente. Fica anotado, não feito.
        FileInfo info;

        try
        {
            info = new FileInfo(path);

            if (!info.Exists)
            {
                return null;
            }
        }
        catch (Exception)
        {
            return null;
        }

        // Os dois lados do escopo, e a distinção não é cosmética: o motor
        // julga origem pela lista de origens e destino pela de destinos.
        //
        // Tratar origem como Cloud - que foi a primeira versão disto - faz a
        // leitura ser julgada contra os caminhos de destino, não casar
        // nenhum e sair como fora de escopo. O arquivo nunca é aberto, o CPF
        // nunca é encontrado, nada é marcado, e a bateria vê apenas uma
        // escrita que passou.
        //
        // Origem vem primeiro porque uma requisição pode trazer as duas
        // flags, e nesse caso o que interessa é o conteúdo sendo lido.
        //
        // Sobra que o driver sabe mais do que consegue contar: ele conhece a
        // natureza do volume (removível, rede, fixo) e o protocolo não tem
        // campo para isso. O Reserved da requisição existe e resolveria.
        DestinationKind destination =
            request.TypedFlags.HasFlag(RequestFlags.ScopeSource) ? DestinationKind.SensitiveSource
            : request.TypedFlags.HasFlag(RequestFlags.ScopeDestination) ? DestinationKind.Cloud
            : DestinationKind.OutOfScope;

        return new FileOperation(
            FilePath: path,
            FileName: info.Name,
            Extension: info.Extension.ToLowerInvariant(),
            SizeBytes: info.Length,
            LastWriteUtc: info.LastWriteTimeUtc,
            ProcessName: request.GetImageName(),
            ProcessId: (int) request.RequestorProcessId,
            DestinationPath: path,
            Destination: destination);
    }
}
