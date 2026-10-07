# Immutable data only. Revision changes whenever a contract changes; variants must get
# distinct CaseIds before becoming Ready. NotReady family IDs reserve the entire
# design section 4 corpus, NOT a claim that one row covers every future variant.
@{
    Schema = 'StagedInvariantCases/1'
    TableRevision = 4
    Modes = @('ordinary', 'runtime-verifier', 'boot-verifier')
    RowSchema = @{
        Required = @('CaseId', 'Revision', 'Status', 'Variant', 'Outcome',
            'ActorSid', 'ActorSession', 'InitialPolicy', 'Scopes', 'Setup', 'Actions',
            'Barriers', 'ExpectedTimeline', 'StatusClasses', 'JournalExpectations',
            'NotificationExpectations', 'AllowedDirectoryTransitions', 'LatencyClasses',
            'Cleanup', 'Repetitions', 'QualificationScope')
        Status = @('Ready', 'NotReady')
        ActorSid = 'ResolveStandardUserTokenAtRuntime; persist exact SID and PID'
        ActorSession = 'ResolveActualTokenSessionAtRuntime; no interactive UI in seeds'
        InitialPolicy = 'Product-seeded record plus live Flags evidence; never infer live Flags from registry'
        LatencyClasses = 'Each class: >=100 unheld samples; cold included in max; nearest-rank p95'
        Variant = 'One immutable expanded storage/action/outcome variant per CaseId'
    }
    CommonAssertions = @{
        TargetBuild = '19045.2965'
        Protocol = 18
        TestDisableTaint = 'SetAndReadLiveFlagsRequired; unavailable adapter is INCONCLUSIVE'
        ObserverSelfChecks = 'Exact module hash and this VM/build/representation evidence required'
        MutationLedger = 'Loss-detecting lower admission/completion required; never synthesize from user results'
        ContinuousCadenceMs = 10
        P95BudgetMs = 250
        MaxBudgetMs = 1000
        ForbiddenByteCount = 0
        Restoration = 'Changed restoration boot plus independent remote BaselineClean=True'
    }
    Cases = @(
        @{
            CaseId = 'S00-observer-control'; Revision = 2; Status = 'Ready'
            Variant = 'fixed-NTFS-nonresident-known-rewrite'; Outcome = 'CONTROL'
            QualificationScope = 'WP3SeedOnly; cannot satisfy Phase4Suite'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @()
            Setup = @('DriverUnloaded', 'IndependentExpectedImage', 'DurableFixture', 'ProductBootPolicy', 'StandardUserTask')
            Actions = @('WriteBaselineImageUnscoped')
            Barriers = @('BootIdentityChanged', 'FilterReady', 'ValidPolicy', 'NewlyMounted', 'CanaryPassed', 'Trusted', 'ReadinessDurable', 'BeforeOperation', 'AfterOperation', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Unscoped', 'BaselineEqualsEverySample')
            StatusClasses = @('Open=Win32:0', 'Write=Win32:0', 'Flush=Win32:0', 'Close=Win32:0')
            MetadataExpectations = @{
                Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl')
                Accessed = 'NtfsReadWindow'
                AccessReason = 'NTFS reads update in-memory LastAccess; disk updates are lazy (at most one hour when enabled). Disabled updates require exact baseline raw Accessed; API Accessed may advance only between baseline and sample-end FILETIME. No other field is tolerated.'
                Source = 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior'
            }
            ServiceEvidence = @{ Journal = '%ProgramData%\SafeUpload\staging-journal'; OwnerSid = 'S-1-5-18'; ProtectedAcl = 'Exact SYSTEM and Administrators full control'; EventLog = 'Application'; Provider = 'SafeUpload.Agent.Service'; NotificationContract = 'v1 notifications/emissions.jsonl + previous.jsonl + head.json; complete boot/QPC/instance coverage required'; Scope = 'Fixture destination paths; retained journal manifests' }
            JournalExpectations = @('NoNewTransfer', 'NoApproved', 'NoReleased')
            NotificationExpectations = @('NoApproval', 'NoRelease', 'NoHandBack')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurity')
            LatencyClasses = @('writer-open', 'cached-write', 'flush', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('CloseObserver', 'StopOwnedTasks', 'RemoveOwnedUser', 'RestoreDriver', 'RestorePolicyBytesAndAcls', 'RemoveOwnedBootPolicy', 'RestoreAgentConfig', 'ResetVerifier', 'RemoveFixtureAndState', 'RestorationReboot', 'IndependentBaseline')
        }
        @{
            CaseId = 'S01-denied-write-after-boot'; Revision = 2; Status = 'Ready'
            Variant = 'fixed-NTFS-nonresident-first-write'; Outcome = 'DENY'
            QualificationScope = 'WP3SeedOnly; cannot satisfy Phase4Suite'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'IndependentExpectedImage', 'DurableFixture', 'ProductBootPolicy', 'StandardUserTask')
            Actions = @('FirstWriteAfterDurableBootReadiness', 'RepeatDeniedWriteOpen')
            Barriers = @('BootIdentityChanged', 'FilterReady', 'ValidPolicy', 'NewlyMounted', 'CanaryPassed', 'Trusted', 'ReadinessDurable', 'BeforeOperation', 'AfterOperation', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'ProtectedAgentAbsent', 'BaselineEqualsEverySample')
            StatusClasses = @('Open=Win32:5', 'Write=NotCalled', 'Flush=NotCalled', 'Close=NotCalled')
            MetadataExpectations = @{
                Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl')
                Accessed = 'NtfsReadWindow'
                AccessReason = 'NTFS reads update in-memory LastAccess; disk updates are lazy (at most one hour when enabled). Disabled updates require exact baseline raw Accessed; API Accessed may advance only between baseline and sample-end FILETIME. No other field is tolerated.'
                Source = 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior'
            }
            ServiceEvidence = @{ Journal = '%ProgramData%\SafeUpload\staging-journal'; OwnerSid = 'S-1-5-18'; ProtectedAcl = 'Exact SYSTEM and Administrators full control'; EventLog = 'Application'; Provider = 'SafeUpload.Agent.Service'; NotificationContract = 'v1 notifications/emissions.jsonl + previous.jsonl + head.json; complete boot/QPC/instance coverage required'; Scope = 'Fixture destination paths; retained journal manifests' }
            JournalExpectations = @('NoNewTransfer', 'NoApproved', 'NoReleased')
            NotificationExpectations = @('NoApproval', 'NoRelease', 'NoHandBack')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurity')
            LatencyClasses = @('writer-open-deny')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('CloseObserver', 'StopOwnedTasks', 'RemoveOwnedUser', 'RestoreDriver', 'RestorePolicyBytesAndAcls', 'RemoveOwnedBootPolicy', 'RestoreAgentConfig', 'ResetVerifier', 'RemoveFixtureAndState', 'RestorationReboot', 'IndependentBaseline')
        }
        @{
            CaseId = 'S02-agent-down-open-refused'; Revision = 2; Status = 'Ready'
            Variant = 'fixed-NTFS-absent-new-name'; Outcome = 'DENY'
            QualificationScope = 'WP3SeedOnly; cannot satisfy Phase4Suite'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'IndependentExpectedImage', 'DurableFixture', 'ProductBootPolicy', 'StandardUserTask')
            Actions = @('AssertAgentAbsent', 'CreateNewWriteOpenDenied')
            Barriers = @('BootIdentityChanged', 'FilterReady', 'ValidPolicy', 'NewlyMounted', 'CanaryPassed', 'Trusted', 'ReadinessDurable', 'BeforeOperation', 'AfterOperation', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'ProtectedAgentAbsent', 'BaselineEqualsEverySample')
            StatusClasses = @('Open=Win32:5', 'Write=NotCalled', 'Flush=NotCalled', 'Close=NotCalled')
            MetadataExpectations = @{
                Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl')
                Accessed = 'NtfsReadWindow'
                AccessReason = 'NTFS reads update in-memory LastAccess; disk updates are lazy (at most one hour when enabled). Disabled updates require exact baseline raw Accessed; API Accessed may advance only between baseline and sample-end FILETIME. No other field is tolerated.'
                Source = 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior'
            }
            ServiceEvidence = @{ Journal = '%ProgramData%\SafeUpload\staging-journal'; OwnerSid = 'S-1-5-18'; ProtectedAcl = 'Exact SYSTEM and Administrators full control'; EventLog = 'Application'; Provider = 'SafeUpload.Agent.Service'; NotificationContract = 'v1 notifications/emissions.jsonl + previous.jsonl + head.json; complete boot/QPC/instance coverage required'; Scope = 'Fixture destination paths; retained journal manifests' }
            JournalExpectations = @('NoNewTransfer', 'NoApproved', 'NoReleased')
            NotificationExpectations = @('NoApproval', 'NoRelease', 'NoHandBack')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurity')
            LatencyClasses = @('writer-open-deny')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('CloseObserver', 'StopOwnedTasks', 'RemoveOwnedUser', 'RestoreDriver', 'RestorePolicyBytesAndAcls', 'RemoveOwnedBootPolicy', 'RestoreAgentConfig', 'ResetVerifier', 'RemoveFixtureAndState', 'RestorationReboot', 'IndependentBaseline')
        }
        @{
            CaseId = 'A01'; Revision = 2; Status = 'Ready'
            Variant = 'fixed-NTFS-pre-scope-write-handle-runtime-scope-add-supported-text-target'
            Outcome = 'ACTIVATING_THEN_STAGED; pre-protection old-handle mutation is permitted and captured; post-promotion write remains private before approval'
            QualificationScope = 'Phase4A01SingleHandleVariant; noncached/EOF/allocation/disposition/rename/link variants deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; InitialDestinationPaths = @(); RuntimeDestinationPath = 'FixtureScope'; RuntimeUpdate = 'Real MinifilterInterceptor startup plus BootPolicyRegistryWriter pending-union/SET_POLICY/finalize'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('BootAttachedTrustedFixedNtfs', 'StandardUserCreatesMarkerTxtPAndKeepsWriteHandleWhileUnscoped', 'IndependentRawCapturePBeforeRuntimePolicyUpdate')
            Actions = @('AddScopeThroughRealServicePolicyPath', 'RequireExactActivatingStatusAndPendingReadiness', 'DenyNewWritableOpen', 'DenyNewWritableSectionAcquire', 'CachedWriteTaggedUThroughOldHandleWhileActivating', 'ReleaseLastOldHandle', 'RequireFreeAndProtectedPromotion', 'CaptureRawPromotionImage', 'StandardUserWritesSyntheticCpfToSupportedTxtThroughOwnedStream', 'RequireBlockedJournalAndProductStagingPath', 'RequireRawDestinationUnchangedUntilApproval')
            Barriers = @('BootIdentityChanged', 'FilterReady', 'ValidEmptyBootPolicy', 'NewlyMounted', 'CanaryPassed', 'Trusted', 'PFlushedAndRawCapturedBeforeEpoch', 'PendingUnionAndAdmissionEpochAdvanced', 'ActivatingStatusAndServicePending', 'OldHandleWriteAndLowerCompletion', 'LastHandleClosed', 'FreePredicate-H-S-C-T-W-Zero-And-SameFileId-SOP', 'PromotionTraceAndProtectedStatus', 'ServiceCoverageReady', 'RawPromotionCapture', 'StagedWriteClosed', 'PostPromotionRawExtentComparison', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'PAndOpenHandleWhileUnscoped', 'RawPBeforeEpochSwap', 'RuntimePolicyPendingUnion', 'AdmissionEpochSwap', 'Activating:H>0:HolderPidKnown', 'ServiceReadiness:Pending', 'NewWritableOpen:AccessDenied', 'NewWritableSection:AccessDenied', 'OldHandleU:PreProtectionMutationAllowed', 'LastHandleRelease', 'Free(F):H=0:S=NO:C=0:T=0:W=0', 'Promotion:Protected', 'ServiceReadiness:Ready', 'RawImageAtPromotion', 'PostPromotionUnapprovedWrite:RoutedToOwnedStream', 'RawDestinationUnchangedBeforeApproval')
            StatusClasses = @('NewWriteOpen=Win32:5', 'NewWritableSection=Win32:5+SectionInFlightInsertedDelta:1+RemovedOnFailureDelta:1', 'OldHolderWrite=Win32:0', 'OldHolderFlush=Win32:0', 'HolderClose=Win32:0', 'Promotion=RegistryState:Protected;Free:True;H:0;S:NO;C:0;T:0;W:0', 'Readiness=PendingThenReady', 'PostPromotionStageOpenWriteFlushClose=Win32:0', 'PostPromotionJournal=Blocked;StagePath=ProductStagingRoot', 'RawDestinationDeltaAfterProtected=0')
            JournalExpectations = @('NewOwnedStreamForExactDestination', 'NoApproved', 'NoReleased')
            NotificationExpectations = @('CurrentPipeStatusPending', 'CurrentPipeStatusReady')
            AllowedDirectoryTransitions = @('SameDestinationFileIdAndActiveNameAtPromotionAndAfterUnapprovedStagedWrite')
            LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4011 }
            Cleanup = @('CloseObserver', 'ReleaseActorHolder', 'StopTestServiceAndRestoreServiceConfig', 'StopOwnedTasks', 'RestoreDriver', 'RestorePolicyBytesAndAcls', 'RemoveOwnedBootPolicy', 'RestoreAgentConfig', 'ResetVerifier', 'RemoveFixtureAndState', 'RestorationReboot', 'IndependentBaseline')
        }
        @{
            CaseId = 'A02'; Revision = 2; Status = 'Ready'
            Variant = 'fixed-NTFS-pre-scope-writable-view-source-handle-closed-runtime-scope-add-supported-text-target'
            Outcome = 'ACTIVATING_THEN_STAGED; retained-view paging mutation is permitted and captured before promotion; post-promotion write remains private before approval'
            QualificationScope = 'Phase4A02SingleLateStoreVariant; no-store and additional reconnect repetitions deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; InitialDestinationPaths = @(); RuntimeDestinationPath = 'FixtureScope'; RuntimeUpdate = 'Real MinifilterInterceptor startup plus BootPolicyRegistryWriter pending-union/SET_POLICY/finalize'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('BootAttachedTrustedFixedNtfs', 'StandardUserCreatesAndFlushesMarkerTxtPWhileUnscoped', 'CreatesPAGE_READWRITEView', 'ClosesSourceFileHandleAndRetainsMappedView', 'IndependentRawCapturePBeforeRuntimePolicyUpdate')
            Actions = @('AddScopeThroughRealServicePolicyPathWhileViewLives', 'RequireSYesAndExactActivatingStatusAndPendingReadiness', 'DenyNewWritableOpen', 'DenyNewWritableSectionAcquire', 'StoreTaggedUThroughOldViewAndFlushViewWhileActivating', 'ReleaseViewAndSection', 'RequireFreeAndProtectedPromotion', 'CaptureRawPromotionImage', 'StandardUserWritesSyntheticCpfToSupportedTxtThroughOwnedStream', 'RequireBlockedJournalAndProductStagingPath', 'RequireRawDestinationUnchangedUntilApproval')
            Barriers = @('BootIdentityChanged', 'FilterReady', 'ValidEmptyBootPolicy', 'NewlyMounted', 'CanaryPassed', 'Trusted', 'SourceHandleClosedAndPFlushed', 'RawPBeforeEpochSwap', 'PendingUnionAndAdmissionEpochAdvanced', 'SYesAndActivatingStatusAndServicePending', 'ViewStoreFlushAndPagingLowerCompletion', 'LastViewAndSectionRelease', 'FreePredicate-H-S-C-T-W-Zero-And-SameFileId-SOP', 'PromotionTraceAndProtectedStatus', 'ServiceCoverageReady', 'RawPromotionCapture', 'StagedWriteClosed', 'PostPromotionRawExtentComparison', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'PAndWritableViewWhileUnscoped', 'SourceHandleClosed', 'RawPBeforeEpochSwap', 'RuntimePolicyPendingUnion', 'AdmissionEpochSwap', 'Activating:S=YES:ActorOwnsRetainedView', 'ServiceReadiness:Pending', 'NewWritableOpen:AccessDenied', 'NewWritableSection:AccessDenied', 'OldViewUAndPagingWrite:PreProtectionMutationAllowed', 'LastViewAndSectionRelease', 'Free(F):H=0:S=NO:C=0:T=0:W=0', 'Promotion:Protected', 'ServiceReadiness:Ready', 'RawImageAtPromotion', 'PostPromotionUnapprovedWrite:RoutedToOwnedStream', 'RawDestinationUnchangedBeforeApproval')
            StatusClasses = @('NewWriteOpen=Win32:5', 'NewWritableSection=Win32:5+SectionInFlightInsertedDelta:1+RemovedOnFailureDelta:1', 'ViewStore=Win32:0', 'FlushViewOfFile=Win32:0', 'HolderRelease=Win32:0', 'Promotion=RegistryState:Protected;Free:True;H:0;S:NO;C:0;T:0;W:0', 'Readiness=PendingThenReady', 'PostPromotionStageOpenWriteFlushClose=Win32:0', 'PostPromotionJournal=Blocked;StagePath=ProductStagingRoot', 'RawDestinationDeltaAfterProtected=0')
            JournalExpectations = @('NewOwnedStreamForExactDestination', 'NoApproved', 'NoReleased')
            NotificationExpectations = @('CurrentPipeStatusPending', 'CurrentPipeStatusReady')
            AllowedDirectoryTransitions = @('SameDestinationFileIdAndActiveNameAtPromotionAndAfterUnapprovedStagedWrite')
            LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4012 }
            Cleanup = @('CloseObserver', 'ReleaseActorHolder', 'StopTestServiceAndRestoreServiceConfig', 'StopOwnedTasks', 'RestoreDriver', 'RestorePolicyBytesAndAcls', 'RemoveOwnedBootPolicy', 'RestoreAgentConfig', 'ResetVerifier', 'RemoveFixtureAndState', 'RestorationReboot', 'IndependentBaseline')
        }
        @{
            CaseId = 'A03'; Revision = 2; Status = 'Ready'
            Variant = 'fixed-NTFS-retained-PAGE_READWRITE-section-no-view-runtime-scope-add-supported-text-target'
            Outcome = 'ACTIVATING_THEN_STAGED; first late view store is permitted and captured before promotion; post-promotion write remains private before approval'
            QualificationScope = 'Phase4A03SingleLateStoreVariant; no-store and additional reconnect repetitions deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; InitialDestinationPaths = @(); RuntimeDestinationPath = 'FixtureScope'; RuntimeUpdate = 'Real MinifilterInterceptor startup plus BootPolicyRegistryWriter pending-union/SET_POLICY/finalize'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('BootAttachedTrustedFixedNtfs', 'StandardUserCreatesAndFlushesMarkerTxtPWhileUnscoped', 'CreatesPAGE_READWRITESectionWithoutView', 'ClosesSourceFileHandleAndRetainsSection', 'IndependentRawCapturePBeforeRuntimePolicyUpdate')
            Actions = @('AddScopeThroughRealServicePolicyPathWhileSectionLives', 'RequireSYesAndExactActivatingStatusAndPendingReadiness', 'CreateFirstViewAfterEpochSwap', 'DenyNewWritableOpen', 'DenyNewWritableSectionAcquire', 'StoreTaggedUThroughLateViewAndFlushViewWhileActivating', 'ReleaseViewAndSection', 'RequireFreeAndProtectedPromotion', 'CaptureRawPromotionImage', 'StandardUserWritesSyntheticCpfToSupportedTxtThroughOwnedStream', 'RequireBlockedJournalAndProductStagingPath', 'RequireRawDestinationUnchangedUntilApproval')
            Barriers = @('BootIdentityChanged', 'FilterReady', 'ValidEmptyBootPolicy', 'NewlyMounted', 'CanaryPassed', 'Trusted', 'SectionRetainedWithoutViewAndPFlushed', 'RawPBeforeEpochSwap', 'PendingUnionAndAdmissionEpochAdvanced', 'SYesAndActivatingStatusAndServicePending', 'FirstViewMappedAfterEpoch', 'LateViewStoreFlushAndPagingLowerCompletion', 'LastViewAndSectionRelease', 'FreePredicate-H-S-C-T-W-Zero-And-SameFileId-SOP', 'PromotionTraceAndProtectedStatus', 'ServiceCoverageReady', 'RawPromotionCapture', 'StagedWriteClosed', 'PostPromotionRawExtentComparison', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'PAndWritableSectionWithoutViewWhileUnscoped', 'SourceHandleClosed', 'RawPBeforeEpochSwap', 'RuntimePolicyPendingUnion', 'AdmissionEpochSwap', 'Activating:S=YES:ActorOwnsRetainedSection', 'ServiceReadiness:Pending', 'FirstViewMappedAfterEpochWithoutNewAcquire', 'NewWritableOpen:AccessDenied', 'NewWritableSection:AccessDenied', 'LateViewUAndPagingWrite:PreProtectionMutationAllowed', 'LastViewAndSectionRelease', 'Free(F):H=0:S=NO:C=0:T=0:W=0', 'Promotion:Protected', 'ServiceReadiness:Ready', 'RawImageAtPromotion', 'PostPromotionUnapprovedWrite:RoutedToOwnedStream', 'RawDestinationUnchangedBeforeApproval')
            StatusClasses = @('NewWriteOpen=Win32:5', 'NewWritableSection=Win32:5+SectionInFlightInsertedDelta:1+RemovedOnFailureDelta:1', 'LateMap=Win32:0', 'LateViewStore=Win32:0', 'FlushViewOfFile=Win32:0', 'HolderRelease=Win32:0', 'Promotion=RegistryState:Protected;Free:True;H:0;S:NO;C:0;T:0;W:0', 'Readiness=PendingThenReady', 'PostPromotionStageOpenWriteFlushClose=Win32:0', 'PostPromotionJournal=Blocked;StagePath=ProductStagingRoot', 'RawDestinationDeltaAfterProtected=0')
            JournalExpectations = @('NewOwnedStreamForExactDestination', 'NoApproved', 'NoReleased')
            NotificationExpectations = @('CurrentPipeStatusPending', 'CurrentPipeStatusReady')
            AllowedDirectoryTransitions = @('SameDestinationFileIdAndActiveNameAtPromotionAndAfterUnapprovedStagedWrite')
            LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4013 }
            Cleanup = @('CloseObserver', 'ReleaseActorHolder', 'StopTestServiceAndRestoreServiceConfig', 'StopOwnedTasks', 'RestoreDriver', 'RestorePolicyBytesAndAcls', 'RemoveOwnedBootPolicy', 'RestoreAgentConfig', 'ResetVerifier', 'RemoveFixtureAndState', 'RestorationReboot', 'IndependentBaseline')
        }
        @{
            CaseId = 'A04'; Revision = 3; Status = 'Ready'
            Variant = 'fixed-NTFS-real-cross-process-duplicated-physical-file-object-runtime-scope-add'
            Outcome = 'ACTIVATING_THEN_STAGED_APPROVED; child P+U captured before Free/Protected, subsequent benign owned save Released'
            QualificationScope = 'Phase4A04Functional; exact duplicate/cleanup/raw U/actual Approved evidence, complete lower permit and temporal coverage still required'
            ActorSid = 'ResolveTwoSameSidStandardUserProcessesAtRuntime'; ActorSession = 'ResolveAndBindBothTokenSessionIds'
            InitialPolicy = @{ Seed = 'Product'; InitialDestinationPaths = @(); RuntimeDestinationPath = 'FixtureScope'; RuntimeUpdate = 'Real MinifilterInterceptor startup plus BootPolicyRegistryWriter pending-union/SET_POLICY/finalize'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('BootAttachedTrustedFixedNtfs', 'PrimaryCreatesFlushesPhysicalPWhileUnscoped', 'DistinctStandardUserChild', 'NativeDuplicateHandleIntoChild', 'TwoWaySharedFilePositionProvesSameFO', 'IndependentRawPBeforeEpoch')
            Actions = @('AddScopeThroughRealServicePolicyPathWhileBothReferencesLive', 'ExactActivatingH1AndOriginalOpenerPid', 'ParentCloseHasNoTargetCleanupAndKeepsH1', 'ChildNewWritableOpenAndSectionDenied', 'ChildTaggedOldObjectWriteFlushAndLowerCompletion', 'ExactRawPPlusUAndNoJournalOrHandBack', 'ChildLastCloseOneCleanupSameFO', 'RequireFreeProtectedAndStableExactU', 'PostPromotionBenignOwnedWriteFlushHeldPrivateImageA', 'RawUUnchangedBeforeApproval', 'OwnedLastCloseThenActualApprovedReleasedAndFinalWholeA')
            Barriers = @('BootIdentityChanged', 'StandardUserBothPidSidSessionBootBound', 'DuplicateSameFOTwoWayPosition', 'RawPBeforeEpochSwap', 'PendingUnionAndAdmissionEpochAdvanced', 'ExactH1AndActivatingPending', 'ParentCloseNoCleanup', 'ChildMutationComplete', 'ExactRawU', 'LastChildCleanup', 'Free-H-S-C-T-W-Zero', 'PromotionStableU', 'ServiceReady', 'OwnedHeldBeforeApproval', 'OwnedFinalClose', 'ActualReleasedWholeA', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedP', 'SamePhysicalFOTwoProcesses', 'RuntimeScopeAdded', 'ActivatingH1WithOriginalOpenerPid', 'ParentClose:H1NoCleanup', 'ChildNewWriteAndSection:Denied', 'ChildOldWriteU:AllowedPreProtection', 'NoJournalReleaseOrHandBack', 'ChildLastClose:ExactlyOneCleanup', 'WDrainThenFree', 'ProtectedSameFileIdWithStableU', 'ServiceReady', 'HeldOwnedSaveA:AllocatedAndPrivate', 'BeforeApproval:RawUUnchanged', 'CloseThenSealedInspectingApprovedPublishingReleased', 'FinalRawA')
            StatusClasses = @('DuplicateHandle=Win32:0', 'AdoptRemoteHandle=Win32:0', 'SharedPosition=317Then619BothWays', 'ParentClose=Win32:0;TargetCleanup:0;H:1;State:Activating', 'NewWriteOpen=Win32:5', 'NewWritableSection=Win32:5+SectionAcquireAndFailedRetireDelta:1', 'ChildWriteAndFlush=Win32:0', 'ChildRawImage=ExactPPlusU', 'ChildLastClose=Win32:0;TargetCleanup:1;SameFO', 'Promotion=Protected;Free:True;H:0;S:NO;C:0;T:0;W:0', 'PostPromotionHeldSave=Win32:0;PrivateWholeA;Allocated', 'PreApprovalRawDelta=0', 'Journal=AllocatedSealedInspectingApprovedPublishingReleased;ExactA', 'FinalRawWholeA')
            JournalExpectations = @('NoNewExactTransferWhileOldDuplicateLives', 'OnePostPromotionOwnedTransferForPrimaryAndExactTarget', 'ActualApprovedReleasedWholeA')
            NotificationExpectations = @('CurrentPipeStatusPending', 'NoObservedReadyWhileChildLives', 'CurrentPipeStatusReadyAfterPromotion')
            AllowedDirectoryTransitions = @('SameDestinationFileIdAndNameThroughOldChildMutationAndPromotion', 'ApprovedOwnedPublicationOnly')
            LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4014 }
            Cleanup = @('ReleaseBothActorsAndProveTaskCompletion', 'CloseObserverAndNotificationCapture', 'StopRestoreTestService', 'StopBothOwnedTasks', 'RestoreDriverPolicyAclsBootPolicyAuditProductState', 'ResetVerifier', 'RemoveActorAccountProfileFixturesAndBothRoutes', 'RestorationReboot', 'IndependentBaseline')
        }
        @{
            CaseId = 'A05'; Revision = 2; Status = 'Ready'
            Variant = 'core-a-after-new-writer-gate-before-final-FreeF'; Outcome = 'Protected; agent-down unpermitted write refused'
            QualificationScope = 'MVP coordinated core (a); sampled raw/fresh/uncached bytes and existing lower/promotion diagnostics'
            DeferredVariants = @('(b) pending lower WRITE versus CLEANUP', '(c) mutating SET_INFORMATION/FSCTL draining', '(d) final identity/barrier race', 'Seeded unheld races', 'Repetition beyond one coordinated core (post-MVP hardening)')
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'ProductEmptyScopes'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('EmptyAtBoot', 'RuntimeAddsFixtureScope')
            Setup = @('PrebootMarkerTxt', 'StandardUserPhysicalHandleP', 'IndependentRawObserver', 'RealAgentPolicyApply', 'ExistingProofProxyAndControl26')
            Actions = @('CaptureExactRawP', 'ExpandScope', 'VerifyNewWritableOpenAndSectionDenied', 'HoldPhysicalHBeforeFreeF', 'WriteThreeDisjointUAndFlush', 'RecordPairedLowerCompletions', 'CaptureExactRawPUWhileActivating', 'LastHolderClose', 'RequireFreeFAndSinglePromotionEdge', 'CaptureExactStablePUBaseline', 'StopRealAgent', 'StandardUserNativeWriteAttemptMustReturn5AndZeroBytes', 'CompareThreeRawFreshUncachedSamplesToPU')
            Barriers = @('NewBoot', 'PreScopePFlush', 'ExpandedAdmissionEpoch', 'Control26ExactActivatingH', 'CompletedUAndFlush', 'LastHolderRelease', 'FreeProtectedPromotion', 'AuthenticatedReady', 'StablePU', 'AgentStopped', 'RefusedWrite', 'FinalQuiescence')
            ExpectedTimeline = @('Unscoped:P', 'ExpandedGate:Activating:H>0', 'NewWriterDenied', 'OldFileObject:P->PUAllowed', 'Activating:H>0:W=0', 'LastClose', 'FreeF:Protected', 'Ready', 'ExactStablePU', 'AgentDown:Win32:5:ZeroWritten', 'RawDestinationStillPU')
            StatusClasses = @('OldWritesAndFlush=Win32:0', 'NewWriterGate=Win32:5', 'LastClose=Win32:0', 'ProtectedAgentDownMutation=Win32:5;BytesWritten=0')
            JournalExpectations = @('OldPhysicalPUNoTransferOrPublication', 'RefusedWriteNoJournalDelta')
            NotificationExpectations = @('AuthenticatedPendingWhileHLive', 'AuthenticatedReadyAfterFreeF')
            AllowedDirectoryTransitions = @('marker.txtSameIdentityAndNames;P->PUOnlyBeforeProtection')
            LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('CooperativeActorRelease', 'StopRestoreRealAgent', 'CloseRawObserver', 'RestoreProductState', 'CommonSeedRestoration', 'IndependentBaseline')
        }
        @{
            CaseId = 'C01-approve-absent'; Revision = 1; Status = 'Ready'
            Variant = 'fixed-NTFS-cached-create-absent'; Outcome = 'APPROVE'
            QualificationScope = 'Phase4FunctionalOnly; sampled bytes, not full temporal/permit/latency qualification'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'AbsentFinal', 'IndependentPatternedTextA', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent')
            Actions = @('CachedCreateNew', 'WholeImageWrite', 'FlushFileBuffers', 'PrivateHandleReadEqualsA', 'HoldWriterDuringThreeRawSamples', 'Close', 'BoundedJournalReleasedWait')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'BeforeOperation', 'FlushedHandleHeld', 'LastUpperClose', 'Released', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'Allocated', 'HeldFinalAbsent', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released', 'FinalEqualsA')
            StatusClasses = @('Open=Win32:0', 'Write=Win32:0;WholeImage', 'Flush=Win32:0', 'PrivateRead=Win32:0;EqualsA', 'Close=Win32:0', 'FreshAbsent=Win32:2', 'UncachedAbsent=Win32:2')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released', 'ImmutableSealedDigestA')
            NotificationExpectations = @('ReleasedDigestA', 'NoBlocked', 'NoHandBack')
            AllowedDirectoryTransitions = @('BaselineWhileHeld', 'OneApprovedFinalAfterRelease', 'NoLingeringTemp')
            LatencyClasses = @('writer-open', 'cached-write', 'flush', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
        }
        @{
            CaseId = 'C01-block-absent'; Revision = 3; Status = 'Ready'
            Variant = 'fixed-NTFS-cached-create-absent'; Outcome = 'BLOCK'
            QualificationScope = 'Phase4FunctionalOnly; H checked, restart/window closure and unheld latency deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'AbsentFinal', 'IndependentPatternedTextAWithValidCpf', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent', 'SecondStandardUserTaskAndRegisteredProfile')
            Actions = @('CachedCreateNew', 'WholeImageWrite', 'FlushFileBuffers', 'PrivateHandleReadEqualsA', 'HoldWriterDuringThreeRawSamples', 'Close', 'BoundedJournalBlockedWait', 'VerifyActorHandBackH', 'RequireSecondUserReadWriteAndFolderListWin32AccessDenied')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'BeforeOperation', 'FlushedHandleHeld', 'LastUpperClose', 'Blocked', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'Allocated', 'HeldFinalAbsent', 'Sealed', 'Inspecting', 'Blocked', 'FinalAbsent', 'HandBackEqualsA')
            StatusClasses = @('Open=Win32:0', 'Write=Win32:0;WholeImage', 'Flush=Win32:0', 'PrivateRead=Win32:0;EqualsA', 'Close=Win32:0', 'FreshAbsent=Win32:2', 'UncachedAbsent=Win32:2', 'OwnerHandBackRead=Success', 'SecondUserReadWriteFolderList=Win32:5Each')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Blocked', 'ImmutableSealedDigestA', 'NoApprovedPublishingReleased')
            NotificationExpectations = @('BlockedDigestA', 'BlockedWithVerifiedHandBackPath', 'NoReleased')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurity')
            LatencyClasses = @('writer-open', 'cached-write', 'flush', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline', 'RemoveSecondUserTaskBatchRightAccountAndProfileIncludingAfterRestorationReboot')
        }
        @{
            CaseId = 'C01'; Revision = 2; Status = 'NotReady'
            Variant = 'fixed-NTFS-cached-create-absent-justify'; Outcome = 'JUSTIFY'
            QualificationScope = 'Deferred: requires the owning standard-user interactive app session and actual justification UI; batch actor cannot submit it. C01 approved-base variants remain deferred; C03/C04 now seed inspected and approved B through the product.'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP4: design section 4.1 C01')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'C02-approve-absent'; Revision = 1; Status = 'Ready'
            Variant = 'fixed-NTFS-owned-mapped-create-absent-source-closed-view-held'; Outcome = 'APPROVE'
            QualificationScope = 'Phase4FunctionalOnly; sampled bytes, not full temporal/permit/latency qualification'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'AbsentFinal', 'IndependentPatternedTextA', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent')
            Actions = @('OwnedCreateNew', 'CreateFileMappingPAGE_READWRITE', 'MapViewOfFileFILE_MAP_WRITE', 'CloseSourceHandleBeforeStore', 'WholeImageMappedStoreA', 'FlushViewOfFile', 'PrivateMappedReadEqualsA', 'HoldSectionAndViewDuringThreeRawSamples', 'UnmapView', 'CloseSection', 'BoundedJournalReleasedWait')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'BeforeOperation', 'SourceClosedViewHeld', 'LastViewAndSectionRelease', 'Released', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'Allocated', 'PAGE_READWRITE:OwnedStream', 'MappedViewLive', 'SourceHandleClosed', 'MappedStoreA', 'FlushViewOfFile', 'HeldFinalAbsent:AllocatedUnsealed', 'LastViewAndSectionRelease', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released', 'FinalEqualsA')
            StatusClasses = @('Open=Win32:0;CREATE_NEW', 'CreateFileMapping=Win32:0;PAGE_READWRITE', 'MapViewOfFile=Win32:0;FILE_MAP_WRITE', 'SourceClose=Win32:0;BeforeMappedStore', 'MappedStore=Success;WholeImageA', 'FlushViewOfFile=Win32:0', 'PrivateMappedRead=Success;EqualsA', 'UnmapViewOfFile=Win32:0', 'SectionClose=Win32:0', 'HeldFreshAbsent=Win32:2', 'HeldUncachedAbsent=Win32:2', 'FinalRawFreshUncached=WholeA')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released', 'ImmutableSealedDigestA')
            NotificationExpectations = @('ReleasedDigestA', 'NoBlocked', 'NoHandBack')
            AllowedDirectoryTransitions = @('BaselineWhileHeld', 'OneApprovedFinalAfterRelease', 'NoLingeringTemp')
            LatencyClasses = @('writer-open', 'create-mapping', 'map-view', 'close-source', 'mapped-store', 'flush-view', 'unmap-view', 'close-section')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestorePolicyBeforeProductStateInPlace', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
        }
        @{
            CaseId = 'C02-block-absent'; Revision = 1; Status = 'Ready'
            Variant = 'fixed-NTFS-owned-mapped-create-absent-source-closed-view-held'; Outcome = 'BLOCK'
            QualificationScope = 'Phase4FunctionalOnly; H checked, restart/window closure and unheld latency deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'AbsentFinal', 'IndependentPatternedTextAWithValidCpf', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent')
            Actions = @('OwnedCreateNew', 'CreateFileMappingPAGE_READWRITE', 'MapViewOfFileFILE_MAP_WRITE', 'CloseSourceHandleBeforeStore', 'WholeImageMappedStoreA', 'FlushViewOfFile', 'PrivateMappedReadEqualsA', 'HoldSectionAndViewDuringThreeRawSamples', 'UnmapView', 'CloseSection', 'BoundedJournalBlockedWait', 'VerifyActorHandBackH')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'BeforeOperation', 'SourceClosedViewHeld', 'LastViewAndSectionRelease', 'Blocked', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'Allocated', 'PAGE_READWRITE:OwnedStream', 'MappedViewLive', 'SourceHandleClosed', 'MappedStoreA', 'FlushViewOfFile', 'HeldFinalAbsent:AllocatedUnsealed', 'LastViewAndSectionRelease', 'Sealed', 'Inspecting', 'Blocked', 'FinalAbsent', 'HandBackEqualsA:H')
            StatusClasses = @('Open=Win32:0;CREATE_NEW', 'CreateFileMapping=Win32:0;PAGE_READWRITE', 'MapViewOfFile=Win32:0;FILE_MAP_WRITE', 'SourceClose=Win32:0;BeforeMappedStore', 'MappedStore=Success;WholeImageA', 'FlushViewOfFile=Win32:0', 'PrivateMappedRead=Success;EqualsA', 'UnmapViewOfFile=Win32:0', 'SectionClose=Win32:0', 'HeldFreshAbsent=Win32:2', 'HeldUncachedAbsent=Win32:2', 'OwnerHandBackRead=Success;EqualsA')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Blocked', 'ImmutableSealedDigestA', 'NoApprovedPublishingReleased')
            NotificationExpectations = @('BlockedDigestA', 'BlockedWithVerifiedHandBackPath', 'NoReleased')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurity')
            LatencyClasses = @('writer-open', 'create-mapping', 'map-view', 'close-source', 'mapped-store', 'flush-view', 'unmap-view', 'close-section')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestorePolicyBeforeProductStateInPlace', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
        }
        @{
            CaseId = 'C03-approve-existing'; Revision = 1; Status = 'Ready'
            Variant = 'fixed-NTFS-truncate-overwrite-approved-B'; Outcome = 'APPROVE'
            QualificationScope = 'Phase4FunctionalOnly; approved B and retained physical B checked; full temporal/permit/latency qualification deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'SeedBenignBThroughStandardUserOwnedStreamAndRequireApprovedPublishingReleasedDigestB', 'IndependentPatternedTextA', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent', 'HoldIndependentPhysicalBReaderSharingDELETE', 'BIsFourClusters:AIsThreeClusters')
            Actions = @('SeedAndProveApprovedB', 'OpenTRUNCATE_EXISTING', 'WholeImageWriteA', 'FlushFileBuffers', 'PrivateHandleReadEqualsA', 'HoldWriterDuringThreeRawFreshUncachedBSamples', 'Close', 'BoundedJournalReleasedWait', 'VerifyRetainedPhysicalB')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'ApprovedBaseB', 'BeforeOperation', 'FlushedHandleHeld', 'LastUpperClose', 'Released', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'SeedB:AllocatedSealedInspectingApprovedPublishingReleased', 'RawFreshUncachedB', 'RetainPhysicalB:ShareDELETE', 'TruncateOpen:OwnedStream', 'Allocated', 'WriteFlushPrivateA', 'HeldRawFreshUncachedB:SameEOFAllocationNamesIds', 'LastUpperClose', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released', 'FinalEqualsA:NewFileId', 'RetainedReaderAndRawB')
            StatusClasses = @('SeedBOpenWriteFlushClose=Win32:0', 'SeedBJournal=Released;DigestB;DurableFullHistory', 'Open=Win32:0;TRUNCATE_EXISTING', 'Write=Win32:0;WholeImageA', 'Flush=Win32:0', 'PrivateRead=Win32:0;EqualsA', 'Close=Win32:0', 'HeldRawFreshUncached=WholeB', 'RetainedPhysicalReaderAndRaw=WholeB', 'FinalRawFreshUncached=WholeA')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released', 'ImmutableSealedDigestA')
            NotificationExpectations = @('ReleasedDigestA', 'NoBlocked', 'NoHandBack')
            AllowedDirectoryTransitions = @('BaselineBWhileHeld', 'OnlyTargetIdentityBToAAfterRelease', 'NoUserOrServiceTemp', 'RetainedBUnchanged')
            LatencyClasses = @('writer-open', 'cached-write', 'flush', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestorePolicyBeforeProductStateInPlace', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
        }
        @{
            CaseId = 'C03-block-existing'; Revision = 2; Status = 'Ready'
            Variant = 'fixed-NTFS-truncate-overwrite-approved-B'; Outcome = 'BLOCK'
            QualificationScope = 'Phase4FunctionalOnly; H checked, restart/window closure and unheld latency deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'SeedBenignBThroughStandardUserOwnedStreamAndRequireApprovedPublishingReleasedDigestB', 'IndependentPatternedTextAWithValidCpf', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent', 'HoldIndependentPhysicalBReaderSharingDELETE', 'BIsFourClusters:AIsThreeClusters', 'SecondStandardUserTaskAndRegisteredProfile')
            Actions = @('SeedAndProveApprovedB', 'OpenTRUNCATE_EXISTING', 'WholeImageWriteA', 'FlushFileBuffers', 'PrivateHandleReadEqualsA', 'HoldWriterDuringThreeRawFreshUncachedBSamples', 'Close', 'BoundedJournalBlockedWait', 'VerifyRetainedPhysicalB', 'VerifyActorHandBackH', 'RequireSecondUserReadWriteAndFolderListWin32AccessDenied')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'ApprovedBaseB', 'BeforeOperation', 'FlushedHandleHeld', 'LastUpperClose', 'Blocked', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'SeedB:AllocatedSealedInspectingApprovedPublishingReleased', 'RawFreshUncachedB', 'RetainPhysicalB:ShareDELETE', 'TruncateOpen:OwnedStream', 'Allocated', 'WriteFlushPrivateA', 'HeldRawFreshUncachedB:SameEOFAllocationNamesIds', 'LastUpperClose', 'Sealed', 'Inspecting', 'Blocked', 'FinalRemainsB:SameFileId', 'HandBackEqualsA:H')
            StatusClasses = @('SeedBOpenWriteFlushClose=Win32:0', 'SeedBJournal=Released;DigestB;DurableFullHistory', 'Open=Win32:0;TRUNCATE_EXISTING', 'Write=Win32:0;WholeImageA', 'Flush=Win32:0', 'PrivateRead=Win32:0;EqualsA', 'Close=Win32:0', 'HeldRawFreshUncached=WholeB', 'RetainedPhysicalReaderAndRaw=WholeB', 'OwnerHandBackRead=Success;EqualsA', 'SecondUserReadWriteFolderList=Win32:5Each')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Blocked', 'ImmutableSealedDigestA', 'NoApprovedPublishingReleased')
            NotificationExpectations = @('BlockedDigestA', 'BlockedWithVerifiedHandBackPath', 'NoReleased')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurity', 'NoUserOrServiceTemp')
            LatencyClasses = @('writer-open', 'cached-write', 'flush', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestorePolicyBeforeProductStateInPlace', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline', 'RemoveSecondUserTaskBatchRightAccountAndProfileIncludingAfterRestorationReboot')
        }
        @{
            CaseId = 'C04-approve'; Revision = 1; Status = 'Ready'
            Variant = 'fixed-NTFS-private-sibling-replacement-approved-B'; Outcome = 'APPROVE'
            QualificationScope = 'Phase4FunctionalOnly; approved B and retained physical B checked; full temporal/permit/latency qualification deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'SeedBenignBThroughStandardUserOwnedStreamAndRequireApprovedPublishingReleasedDigestB', 'IndependentPatternedTextA', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent', 'HoldIndependentPhysicalBReaderSharingDELETE', 'BIsFourClusters:AIsThreeClusters')
            Actions = @('SeedAndProveApprovedB', 'OwnedCreateNewSiblingSaveTmpTxt', 'WholeImageWriteA', 'FlushFileBuffers', 'PrivateHandleReadEqualsA', 'HoldWriterDuringThreeRawFreshUncachedBSamples', 'SetFileInformationByHandleFileRenameInfoExReplacePosixOntoTarget', 'RequireSameTransferCommittedTargetAndSourceTombstone', 'HoldRenamedWriterDuringThreeRawFreshUncachedBSamples', 'Close', 'BoundedJournalReleasedWait', 'VerifyRetainedPhysicalB')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'ApprovedBaseB', 'BeforeOperation', 'BeforeRenameHandleHeld', 'NativeRename', 'AfterRenameHandleHeld', 'LastUpperClose', 'Released', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'SeedB:AllocatedSealedInspectingApprovedPublishingReleased', 'RawFreshUncachedB', 'RetainPhysicalB:ShareDELETE', 'PrivateSiblingTemp:Allocated', 'WriteFlushPrivateA', 'BeforeRename:PublicB:NoTemp', 'RenameExReplacePosix:Win32:0', 'CommittedTarget:SameTransfer:SourceTombstone', 'AfterRenameHeld:PublicB:NoTemp:AllocatedUnsealed', 'LastUpperClose', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released', 'FinalEqualsA:NewFileId', 'RetainedReaderAndRawB')
            StatusClasses = @('SeedBOpenWriteFlushClose=Win32:0', 'SeedBJournal=Released;DigestB;DurableFullHistory', 'TempOpen=Win32:0;CREATE_NEW;DELETE', 'Write=Win32:0;WholeImageA', 'Flush=Win32:0', 'PrivateRead=Win32:0;EqualsA', 'RenameEx=Win32:0;REPLACE_IF_EXISTS|POSIX', 'PrivateReadAfterRename=Win32:0;EqualsA', 'Close=Win32:0', 'HeldRawFreshUncached=WholeB', 'RetainedPhysicalReaderAndRaw=WholeB', 'PublicSiblingTemp=Absent', 'FinalRawFreshUncached=WholeA')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released', 'ImmutableSealedDigestA')
            NotificationExpectations = @('ReleasedDigestA', 'NoBlocked', 'NoHandBack')
            AllowedDirectoryTransitions = @('BaselineBWhileHeld', 'OnlyTargetIdentityBToAAfterRelease', 'NoUserOrServiceTemp', 'RetainedBUnchanged')
            LatencyClasses = @('writer-open', 'cached-write', 'flush', 'rename-ex', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestorePolicyBeforeProductStateInPlace', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
        }
        @{
            CaseId = 'C04-block'; Revision = 2; Status = 'Ready'
            Variant = 'fixed-NTFS-private-sibling-replacement-approved-B'; Outcome = 'BLOCK'
            QualificationScope = 'Phase4FunctionalOnly; H checked, restart/window closure and unheld latency deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'SeedBenignBThroughStandardUserOwnedStreamAndRequireApprovedPublishingReleasedDigestB', 'IndependentPatternedTextAWithValidCpf', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent', 'HoldIndependentPhysicalBReaderSharingDELETE', 'BIsFourClusters:AIsThreeClusters', 'SecondStandardUserTaskAndRegisteredProfile')
            Actions = @('SeedAndProveApprovedB', 'OwnedCreateNewSiblingSaveTmpTxt', 'WholeImageWriteA', 'FlushFileBuffers', 'PrivateHandleReadEqualsA', 'HoldWriterDuringThreeRawFreshUncachedBSamples', 'SetFileInformationByHandleFileRenameInfoExReplacePosixOntoTarget', 'RequireSameTransferCommittedTargetAndSourceTombstone', 'HoldRenamedWriterDuringThreeRawFreshUncachedBSamples', 'Close', 'BoundedJournalBlockedWait', 'VerifyRetainedPhysicalB', 'VerifyActorHandBackH', 'RequireSecondUserReadWriteAndFolderListWin32AccessDenied')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'ApprovedBaseB', 'BeforeOperation', 'BeforeRenameHandleHeld', 'NativeRename', 'AfterRenameHandleHeld', 'LastUpperClose', 'Blocked', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'SeedB:AllocatedSealedInspectingApprovedPublishingReleased', 'RawFreshUncachedB', 'RetainPhysicalB:ShareDELETE', 'PrivateSiblingTemp:Allocated', 'WriteFlushPrivateA', 'BeforeRename:PublicB:NoTemp', 'RenameExReplacePosix:Win32:0', 'CommittedTarget:SameTransfer:SourceTombstone', 'AfterRenameHeld:PublicB:NoTemp:AllocatedUnsealed', 'LastUpperClose', 'Sealed', 'Inspecting', 'Blocked', 'FinalRemainsB:SameFileId', 'HandBackEqualsA:H')
            StatusClasses = @('SeedBOpenWriteFlushClose=Win32:0', 'SeedBJournal=Released;DigestB;DurableFullHistory', 'TempOpen=Win32:0;CREATE_NEW;DELETE', 'Write=Win32:0;WholeImageA', 'Flush=Win32:0', 'PrivateRead=Win32:0;EqualsA', 'RenameEx=Win32:0;REPLACE_IF_EXISTS|POSIX', 'PrivateReadAfterRename=Win32:0;EqualsA', 'Close=Win32:0', 'HeldRawFreshUncached=WholeB', 'RetainedPhysicalReaderAndRaw=WholeB', 'PublicSiblingTemp=Absent', 'OwnerHandBackRead=Success;EqualsA', 'SecondUserReadWriteFolderList=Win32:5Each')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Blocked', 'ImmutableSealedDigestA', 'NoApprovedPublishingReleased')
            NotificationExpectations = @('BlockedDigestA', 'BlockedWithVerifiedHandBackPath', 'NoReleased')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurity', 'NoUserOrServiceTemp')
            LatencyClasses = @('writer-open', 'cached-write', 'flush', 'rename-ex', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestorePolicyBeforeProductStateInPlace', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline', 'RemoveSecondUserTaskBatchRightAccountAndProfileIncludingAfterRestorationReboot')
        }
        @{
            CaseId = 'C02'; Revision = 2; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Mapped write'
            QualificationScope = 'JUSTIFY and retained section without view / late view variants deferred; APPROVE/BLOCK absent variants have distinct Ready IDs'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP4: design section 4.1 C02')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'C03'; Revision = 2; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Overwrite'
            QualificationScope = 'JUSTIFY and supersede variants deferred; APPROVE/BLOCK truncate-existing variants have distinct Ready IDs'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP4: design section 4.1 C03')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'C04'; Revision = 2; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Replacement save'
            QualificationScope = 'JUSTIFY, open private target refusal and reconnect tombstone variants deferred; APPROVE/BLOCK replacement variants have distinct Ready IDs'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP4: design section 4.1 C04')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'C05-denied-external-rename'; Revision = 1; Status = 'Ready'
            Variant = 'fixed-NTFS-old-physical-external-source-rename-into-protected-absent-target'; Outcome = 'DENY'
            QualificationScope = 'Phase4FunctionalDOnly; exact denial ledger/reason and unheld latency unavailable; positive owned-source variant deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'AbsentFinal', 'DurablePhysicalSourceAOutsidePolicyOnSameVolume', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent', 'IndependentExternalRawObserver')
            Actions = @('OpenPhysicalExternalSourceDELETEAndKeepOldHandle', 'SourceHandleReadEqualsA', 'ThreeBeforeRenameRawSamplesOfTargetAndSource', 'SetFileInformationByHandleFileRenameInfoExReplacePosixOntoTarget', 'RequireExactAccessDeniedOnRename', 'SourceHandleReadStillEqualsA', 'ThreeAfterDeniedRenameRawSamplesOfTargetAndSource', 'ClosePhysicalSource', 'NoTransferOrOutcomeNotificationOrHandBack')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'BeforeOperation', 'BeforeRenameHandleHeld', 'NativeRename', 'AfterRenameHandleHeld', 'SourceClose', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSourceSetup', 'BootTrusted', 'Protected', 'TargetAbsent', 'PhysicalExternalSourceOpen:Win32:0', 'HeldSourceA:SameIdAllocationNames', 'RenameIntoProtected:Win32:5', 'SourceStillA:SameIdAllocationNames', 'TargetStillAbsent:NoPublicTemp', 'SourceClose:Win32:0', 'NoNewTransfer', 'NoApprovalReleaseHandBack', 'FinalTargetAbsentAndSourceA')
            StatusClasses = @('SourceOpen=Win32:0;OPEN_EXISTING;DELETE', 'SourceRead=Win32:0;WholeA', 'RenameEx=Win32:5;REPLACE_IF_EXISTS|POSIX', 'SourceReadAfterDenial=Win32:0;WholeA', 'SourceClose=Win32:0', 'TargetFreshAbsent=Win32:2', 'TargetUncachedAbsent=Win32:2', 'SourceRawFreshUncached=WholeA;SameIdAllocation')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('NoNewTransfer', 'NoApproved', 'NoReleased')
            NotificationExpectations = @('NoApproval', 'NoRelease', 'NoHandBack')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurityInProtectedAndExternalFolders')
            LatencyClasses = @('writer-open', 'rename-ex', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('CloseBothObservers', 'StopAndRestoreAgent', 'RestorePolicyBeforeProductStateInPlace', 'RestoreProductStateBytesAndAcls', 'RemoveExternalFixture', 'CommonSeedRestoration', 'IndependentBaseline')
        }
        @{
            CaseId = 'C05'; Revision = 2; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Rename into folder'
            QualificationScope = 'Positive owned source rename and existing-target denial variants deferred; external old physical handle / absent target denial has a distinct Ready ID'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP4: design section 4.1 C05')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'B01'; Revision = 2; Status = 'Ready'
            CoreVariant = 'One coordinated C01 BLOCK absent save; standard actor replaces empty hand-back folder with sentinel junction before last close; fail closed'
            DeferredVariants = @('PreExistingValidHandBackTarget', 'JunctionAtOtherAncestorComponents', 'AncestorSwapBetweenProductCheckAndCreate', 'SymlinkAncestor', 'HardLinkTarget', 'ProtectedTarget', 'SyncedTarget', 'CopyFailure', 'DigestFailure', 'SeededUnheldAncestorRace', 'AdditionalRepetitions', 'UnheldLatencyCorpus', 'SafeRetryProductGap: agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs RecoverBlockedAsync only cleans temporaries for HandbackState=Failed; no external retry API for this exact blocked version')
            Variant = 'fixed-NTFS-cached-block-absent-handback-sentinel-junction'; Outcome = 'BLOCK'
            QualificationScope = 'Phase4MvpCoreVariant; fail-closed terminal Blocked/Failed retained; safe retry is a deferred product feature gap'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'AbsentFinalN', 'IndependentWholeAWithValidCpf', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent', 'ActorSeedsReadableSentinelMarkerAndPreExistingExactTransferLeafOutsideProtection')
            Actions = @('CachedCreateNewWholeAWriteFlushPrivateReadAndHold', 'ActorReplacesEmptyHandBackFolderWithJunction', 'VerifyActorAndOsJunctionTargetBeforeClose', 'RawSentinelBaselineBeforeHandBack', 'CloseLastWriter', 'RealCpfBlockAndHandBackFailure', 'RequireBlockedSnapshotAAndFailedJournal', 'VerifySentinelRawBytesIdsListingFreshAndUncachedUnchanged', 'RequireNoReleasedAndNoDestinationDeltaOrTemp')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'HeldMutableAllocated', 'ActorJunctionReceiptAndOsReadback', 'IndependentSentinelRawBaseline', 'LastUpperClose', 'BlockedHandbackFailed', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'AllocatedMutableA', 'ActorJunctionWhileHeld', 'RawSentinelBaseline', 'LastUpperClose', 'SealedA', 'InspectingA', 'BlockedA', 'HandbackStateFailed:handback_failed', 'StageRetainedA', 'RawNAbsentAndProtectedListingUnchanged', 'SentinelUnchangedNoNewNameTempOrOverwrite', 'NoReleased')
            StatusClasses = @('OpenWriteFlushClose=Win32:0', 'PrivateRead=WholeA', 'ActorMklinkJunction=Exit:0;Reparse;ExactSentinelTarget', 'FreshUncachedAbsent=Win32:2', 'SentinelRawFreshUncached=ExactOriginalWholeImages', 'HandbackState=Failed:3;PathNull;StageRetained')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Blocked', 'SealedDigestA', 'HandbackStateFailed', 'HandbackFailureReason:handback_failed', 'NoApprovedPublishingReleased', 'NoStageCleanupOrDeletion')
            NotificationExpectations = @('BlockedExactTransferSessionDigestAWithNullHandBackPath', 'ExactTransferApplicationFailureWarning', 'NoReleased')
            AllowedDirectoryTransitions = @('ProtectedDestinationAndSentinelExactRawNamesIdsSizesAttributes', 'NoPublicDestinationOrSentinelTemporary', 'NoSentinelOverwrite')
            LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4051 }
            Cleanup = @('CooperativeWriterCancellationAndClose', 'CloseBothObservers', 'StopAndRestoreAgent', 'RemoveOnlyJunctionEntryBeforeSentinelAndProfileRemoval', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
        }
        @{
            CaseId = 'B02'; Revision = 1; Status = 'NotReady'
            Variant = 'core-existing-T-block-v1-block-v2-stale-v1-justify-latest-v2'; Outcome = 'Blocked: no owning standard-user interactive session in suite'
            QualificationScope = 'MVP core blocked; real pipe is scriptable but session binding cannot be met by the existing disposable batch actor'
            Blocker = 'agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs: TryGetBoundSession/PublishCoreAsync require SessionResolver.TryGetSessionUserSid to match the requesting SID before Remember opens justification. SessionResolver.cs uses WTSQueryUserToken. Test-StagedInvariantSuite.ps1 Prepare creates a new disposable user and password/batch limited task in session 0, with no logged-on WTS session for that SID. Need an owning logged-on standard-user session and InteractiveToken actor/restoration support; sending the real pipe protocol from the current batch actor can only be rejected and cannot qualify latest-v2 release. No product hook or UI bypass added.'
            DeferredVariants = @('C04 replacement-save JUSTIFY/stale-JUSTIFY companion', 'Wrong principal or session', 'Duplicate/replayed submission', 'V1 justification after restart', 'Repetition beyond coordinated core')
            ActorSid = 'OwningLoggedOnStandardUserRequired'; ActorSession = 'WTSBoundInteractiveSessionRequired'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required'; OverrideAllowed = $true }
            Scopes = @('FixtureScope'); Setup = @('CoreRequiresPrebootB', 'C03StyleOverwrite', 'RealJustificationPipe', 'OwningInteractiveSessionUnavailable')
            Actions = @('BlockedPendingSessionPrerequisite; do not fabricate a justification window')
            Barriers = @('V1Blocked', 'V2BlockedAtNewDigest', 'RealV1SubmissionRejected', 'RealV2SubmissionAccepted')
            ExpectedTimeline = @('BRemainsPublicThroughBothBlocksAndStaleSubmission', 'LatestV2OnlyReleasedOnce')
            StatusClasses = @('RealPipeRejectedStale', 'RealPipeAcceptedLatest')
            JournalExpectations = @('V1NeverPublished', 'V2ReleasedOnce'); NotificationExpectations = @('RealBlockedAndReleased')
            AllowedDirectoryTransitions = @('T:B->V2Only'); LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('CoreNotStarted; common restoration mandatory when session prerequisite is implemented')
        }
        @{
            CaseId = 'R01'; Revision = 2; Status = 'Ready'
            CoreVariant = 'One coordinated cached new-name save; restart at mutable Allocated with the private writer held'
            DeferredVariants = @('ExistingFinalB', 'MutableAllocatedOwnedViewWriter', 'SealRequestBeforeReply', 'Inspecting', 'ApprovedBeforePermit', 'PublishingAfterPermittedRenameBeforeReleasedCommit', 'DisconnectAfterPermitBeforeTemporaryCreate', 'FailedRename', 'BlockedCompanion', 'SeededUnheldStopRace', 'AdditionalRepetitions', 'UnheldLatencyCorpus')
            Variant = 'fixed-NTFS-cached-create-absent-restart-mutable-Allocated'; Outcome = 'APPROVE'
            QualificationScope = 'Phase4MvpCoreVariant; sampled raw/fresh/uncached evidence; other section 4.1 variants are post-MVP hardening'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'AbsentFinalN', 'IndependentDistinctInitialAndFinalBenignWholeImages', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent')
            Actions = @('CachedCreateNewWriteFlushAndHoldPrivateHandle', 'StopAgentAtAllocated', 'SecondOpenOfSameActorDeniedWhileDown', 'RewriteFinalWholeAThroughHeldPrivateHandleWhileDown', 'RestartSameServiceWithFreshSystemProcess', 'RequireExactTransferUnsealedWhileHolderLives', 'CloseLastWriter', 'FreshRealInspection', 'RequireReleasedExactWholeAExactlyOnce')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'HeldMutableAllocated', 'SCMStoppedAndNoServiceProcess', 'OfflineNativeReceipt', 'RestartedAuthenticatedReady', 'UnsealedHolderLive', 'LastUpperClose', 'Released', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'AllocatedMutable:InitialPrivateImage', 'AgentStopped:RawNAbsent', 'NewProtectedOpenDenied', 'HeldRewriteA:RawNAbsent', 'Restart:UnsealedNoImplicitApproval', 'LastUpperClose', 'SealedA', 'InspectingA', 'ApprovedA', 'PublishingA', 'ReleasedOnceA', 'FinalRawFreshUncachedA')
            StatusClasses = @('InitialOpenWriteFlush=Win32:0', 'OfflineSecondOpen=Win32:5;NoWriteFlushClose', 'HeldOfflineWriteFlush=Win32:0;PrivateWholeA', 'Close=Win32:0', 'HeldFreshUncachedAbsent=Win32:2', 'OutcomeRawFreshUncached=AbsentOrWholeA', 'FinalRawFreshUncached=WholeA')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('OneTransferAndGeneration', 'Allocated', 'UnsealedWhileHeld', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'ReleasedExactlyOnce', 'SealedDigestFinalA')
            NotificationExpectations = @('NoHeldInspectionApprovalReleaseAtCheckpoints', 'SeparateAuthenticatedBeforeStopAndAfterRestartWindows', 'ExactlyOneReleasedExactTransferSessionDigestA', 'NoBlockedOrHandBack')
            AllowedDirectoryTransitions = @('BaselineWhileHeldAndOfflineAndUnsealed', 'ApprovedPublicationOnlyAfterClose', 'OneFinalNEqualsAAtQuiescence', 'NoLingeringTemp')
            LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4061 }
            Cleanup = @('CooperativeWriterCancellationAndClose', 'StopAndRestoreAgent', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
        }
        @{
            CaseId = 'R02'; Revision = 1; Status = 'NotReady'
            Variant = 'core-stop-after-durable-PendingScopes-before-authenticated-apply'; Outcome = 'Blocked: no coordinated pre-apply service barrier'
            QualificationScope = 'MVP core blocked; registry polling plus Stop-Service is an unheld race and cannot guarantee the selected stop point'
            Blocker = 'agente/SafeUpload.Agent.Service/Interception/BootPolicyRegistryWriter.cs: Apply calls _backend.WritePending (WindowsBootPolicyRegistryBackend.WriteValue flushes and verifies PendingScopes), then immediately applyAuthenticatedPolicy, WriteCommitted, ClearPending and finalizeAuthenticatedPolicy. MinifilterInterceptor.TryPushPolicy provides no service pause/stop hook between WritePending and the first port update. An A01 H holder blocks file promotion, not this policy update. Control 26 and StagedProofProxy observe/forward diagnostics only. Need an existing coordinated barrier at Apply after WritePending returns and before applyAuthenticatedPolicy; none exists. No product edit, registry injection, or polling race substituted.'
            DeferredVariants = @('Other three stop points', 'Dirty-holder status variants', 'FailedClosed variants', 'Seeded unheld stop races', 'Repetition beyond coordinated core')
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'ProductOldScopeX'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('ProtectedX', 'CandidateY'); Setup = @('ProtectedBaselineX', 'StandardUserA01PhysicalHolderY', 'MissingDurablePendingPreApplyBarrier')
            Actions = @('CoreNotStarted: cannot stop at required coordinated boundary')
            Barriers = @('PendingScopesDurableBeforePortUpdate', 'AgentStopped', 'RestartCandidateRetryFinalize', 'Control26ExactHeldY', 'LastHolderRelease', 'FreeFStableRawBaseline', 'ProtectedReady')
            ExpectedTimeline = @('XProtectedUnchanged', 'NoAppliedSuccessBeforeStop', 'YNotReady', 'RestartRetryCandidate', 'YActivatingWhileHLive', 'ReleaseDrainFreeF', 'YProtectedReadyWithStableBaseline')
            StatusClasses = @('NoPrematurePolicyAppliedOrReady'); JournalExpectations = @('NoHolderPublication')
            NotificationExpectations = @('NoPrematureAppliedSuccess', 'ReadyOnlyAfterFreeF')
            AllowedDirectoryTransitions = @('XBaselineExact', 'YPreProtectionHolderMutationsAllowed'); LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('CoreNotStarted; common restoration mandatory when barrier prerequisite exists')
        }
        @{
            CaseId = 'R03'; Revision = 2; Status = 'Ready'
            Variant = 'fixed-NTFS-boot-agent-disabled-cached-overwrite-and-create-then-fresh-approve'; Outcome = 'APPROVE'
            QualificationScope = 'Phase4MvpCoordinatedCore; sampled raw/fresh/uncached evidence; unheld latency remains a separate hardening workload'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; AgentStart = 4; LiveFlags = 'TEST_DISABLE_TAINT-required; actual taint counter window retained' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'PrebootMarkerB', 'AbsentCachedTxtN', 'ProductBootPolicy', 'DisabledAgentService', 'AtStartupStandardUserTask')
            Actions = @('ActorDurablyRecordsReadiness', 'CachedOverwriteBRefused', 'CachedCreateNRefused', 'VerifyWholeDirectoryAndJournalUnchanged', 'StartRealAgent', 'RequirePolicyAcceptedAndCoverageReady', 'FreshExplicitCachedCreateN', 'WholeImageWriteFlushPrivateRead', 'CloseAndRequireReleasedA')
            Barriers = @('BootIdentityChanged', 'StartupActorIdentity', 'DurableBootReadiness', 'OfflineRawBaseline', 'OfflineGo', 'OfflineReceipt', 'AgentAbsenceWindowComplete', 'CoverageReady', 'FreshSaveGo', 'FlushedHandleHeld', 'LastUpperClose', 'Released', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'ProtectedAgentAbsent', 'BUnchangedNAbsent', 'OfflineOpensDenied', 'NoTransferNotificationOrHandBack', 'PolicyAcceptedCoverageReady', 'FreshSaveAllocated', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released', 'BUnchangedNEqualsA')
            StatusClasses = @('OfflineOverwriteOpen=Win32:5;WriteFlushNotCalled', 'OfflineCreateOpen=Win32:5;WriteFlushNotCalled', 'OnlineOpenWriteFlushClose=Win32:0', 'PrivateRead=WholeA', 'OfflineFreshUncachedN=Win32:2', 'FinalFreshUncachedN=WholeA')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('NoNewTransfer', 'NoApproved', 'NoReleased')
            NotificationExpectations = @('NoNotification', 'NoApproval', 'NoRelease', 'NoHandBack')
            OnlineJournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released', 'ImmutableSealedDigestA', 'ExactlyOneFreshActorTransfer')
            OnlineNotificationExpectations = @('ReleasedDigestA', 'NoBlocked', 'NoHandBack')
            AllowedDirectoryTransitions = @('BaselineWhileAgentDownAndWriterHeld', 'OneApprovedNAfterRelease', 'BUnchanged', 'NoLingeringTemp')
            LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4033 }
            DeferredVariants = @('WritableSectionWhileDown', 'ReplacementWhileDown', 'RenameInWhileDown', 'SeededUnheldStartupRace', 'AdditionalRepetitions', 'UnheldLatency')
            Cleanup = @('StopAndRestoreAgentIncludingDisabledBootConfiguration', 'StopOwnedStartupActor', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
        }
        @{
            CaseId = 'P01'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Expansion/shrink epoch corpus'
            QualificationScope = 'Phase4; WP5 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP5: design section 4.1 P01')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'P02'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: TxF'
            QualificationScope = 'Phase4; WP5 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP5: design section 4.1 P02')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'P03'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Cache barrier/representation'
            QualificationScope = 'Phase4; WP5 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP5: design section 4.1 P03')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'P04'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Capacity/loss'
            QualificationScope = 'Phase4; WP6 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP6: design section 4.1 P04')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'P05'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Boot/trust/install'
            QualificationScope = 'Phase4; WP6 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP6: design section 4.1 P05')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'P06'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Authorization/refusal regression'
            QualificationScope = 'Phase4; WP6 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP6: design section 4.1 P06')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'X01'; Revision = 2; Status = 'Ready'
            Variant = 'core-two-live-processes-cached-overwrite-block-v1-approve-latest-v2'; Outcome = 'v1 Blocked; v2 Released'
            QualificationScope = 'MVP coordinated core; v1 BLOCK completes before v2 allocation, with both writer processes live; sampled whole-byte publication invariant'
            DeferredVariants = @('Four writers', 'Mapped/replacement mixes', 'Held old reader as a separately exercised variant', 'Stale justification', 'Cross-process private-capability negative probes', 'New allocation versus Publishing reservation', 'Seeded unheld races', 'Repetition beyond one coordinated core (post-MVP hardening)')
            ActorSid = 'TwoDistinctStandardUserProcessesSameResolvedSid'; ActorSession = 'ResolveBothActualTokenSessions'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DurablePrebootTEqualsB', 'V1SyntheticValidCpf', 'V2BenignDistinctWholeImage', 'TwoLimitedTasks', 'RealStagingAgent', 'IndependentRawObserverAndFreshUncachedReaders')
            Actions = @('StartBothProcessesAtGoBarriers', 'Writer1CachedTruncateOverwriteV1AndPrivateRead', 'ObserveAllocatedV1WithHandleHeld', 'CloseV1WaitForDurableBlocked', 'KeepWriter1AliveAtHandBackBarrier', 'ReleaseWriter2AllocationBarrier', 'Writer2CachedTruncateOverwriteV2AndPrivateRead', 'ObserveAllocatedV2NewerGeneration', 'CloseV2', 'SampleRawFreshUncachedBOrV2ThroughoutOutcomeWait', 'RejectV1PublicationAfterSupersession', 'RequireV2ReleasedOnce', 'VerifyExactV1HandBackThroughOwnerReadAndTrustedAclByteChecks', 'RequireExactlyOneTAndNoTempOrDuplicates')
            Barriers = @('NewBoot', 'AgentReady', 'BothProcessIdentities', 'RawPrebootB', 'V1AllocatedHeld', 'V1Blocked', 'V2AllocationGo', 'V2AllocatedHeld', 'V2Close', 'V2Released', 'HandBackOwnerRead', 'FinalQuiescence')
            ExpectedTimeline = @('Protected:T=B', 'v1:Allocated->Sealed->Inspecting->Blocked', 'v2:AllocatedAtGreaterDestinationGeneration', 'v1RemainsBlockedAfterSupersession', 'v2:Sealed->Inspecting->Approved->Publishing->ReleasedExactlyOnce', 'T:B->V2Only', 'V1ExactHandBack', 'OneFinalTNoTemporaryOrDuplicateNames')
            StatusClasses = @('BothCachedOverwriteWriteFlushClose=Win32:0', 'PrivateWholeDigests=ExactV1AndV2', 'RawFreshUncachedWholeDigests=BThenV2')
            JournalExpectations = @('V1CompleteBlockedHistoryNoApprovePublishRelease', 'V2CompleteReleasedHistoryExactlyOnce', 'V2DestinationGenerationGreaterThanV1')
            NotificationExpectations = @('V1BlockedWithExactDigestAndVerifiedHandBackPath', 'V2ReleasedWithExactDigestAndActorSession')
            AllowedDirectoryTransitions = @('TIdentityReplacedOnlyByApprovedV2', 'FinalRawNameMultisetExactlyPrebootNamesWithOneT')
            LatencyClasses = @()
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('CancelAndCloseBothActors', 'WaitBothTaskEnvelopes', 'CloseRawObserver', 'StopRestoreRealAgent', 'RestoreProductStateBytesAndAcls', 'RemoveBothTasksAndOwnedProfile', 'CommonSeedRestoration', 'IndependentBaseline')
        }
    )
}
