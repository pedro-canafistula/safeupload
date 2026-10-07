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
            CaseId = 'A04'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Duplicated handle'
            QualificationScope = 'Phase4; WP5 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP5: design section 4.1 A04')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'A05'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Activation-gate race'
            QualificationScope = 'Phase4; WP5 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP5: design section 4.1 A05')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
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
            CaseId = 'C01-block-absent'; Revision = 2; Status = 'Ready'
            Variant = 'fixed-NTFS-cached-create-absent'; Outcome = 'BLOCK'
            QualificationScope = 'Phase4FunctionalOnly; H checked, restart/window closure and unheld latency deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'AbsentFinal', 'IndependentPatternedTextAWithValidCpf', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent')
            Actions = @('CachedCreateNew', 'WholeImageWrite', 'FlushFileBuffers', 'PrivateHandleReadEqualsA', 'HoldWriterDuringThreeRawSamples', 'Close', 'BoundedJournalBlockedWait', 'VerifyActorHandBackH')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'BeforeOperation', 'FlushedHandleHeld', 'LastUpperClose', 'Blocked', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'Allocated', 'HeldFinalAbsent', 'Sealed', 'Inspecting', 'Blocked', 'FinalAbsent', 'HandBackEqualsA')
            StatusClasses = @('Open=Win32:0', 'Write=Win32:0;WholeImage', 'Flush=Win32:0', 'PrivateRead=Win32:0;EqualsA', 'Close=Win32:0', 'FreshAbsent=Win32:2', 'UncachedAbsent=Win32:2', 'OwnerHandBackRead=Success')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Blocked', 'ImmutableSealedDigestA', 'NoApprovedPublishingReleased')
            NotificationExpectations = @('BlockedDigestA', 'BlockedWithVerifiedHandBackPath', 'NoReleased')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurity')
            LatencyClasses = @('writer-open', 'cached-write', 'flush', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
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
            CaseId = 'C03-block-existing'; Revision = 1; Status = 'Ready'
            Variant = 'fixed-NTFS-truncate-overwrite-approved-B'; Outcome = 'BLOCK'
            QualificationScope = 'Phase4FunctionalOnly; H checked, restart/window closure and unheld latency deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'SeedBenignBThroughStandardUserOwnedStreamAndRequireApprovedPublishingReleasedDigestB', 'IndependentPatternedTextAWithValidCpf', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent', 'HoldIndependentPhysicalBReaderSharingDELETE', 'BIsFourClusters:AIsThreeClusters')
            Actions = @('SeedAndProveApprovedB', 'OpenTRUNCATE_EXISTING', 'WholeImageWriteA', 'FlushFileBuffers', 'PrivateHandleReadEqualsA', 'HoldWriterDuringThreeRawFreshUncachedBSamples', 'Close', 'BoundedJournalBlockedWait', 'VerifyRetainedPhysicalB', 'VerifyActorHandBackH')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'ApprovedBaseB', 'BeforeOperation', 'FlushedHandleHeld', 'LastUpperClose', 'Blocked', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'SeedB:AllocatedSealedInspectingApprovedPublishingReleased', 'RawFreshUncachedB', 'RetainPhysicalB:ShareDELETE', 'TruncateOpen:OwnedStream', 'Allocated', 'WriteFlushPrivateA', 'HeldRawFreshUncachedB:SameEOFAllocationNamesIds', 'LastUpperClose', 'Sealed', 'Inspecting', 'Blocked', 'FinalRemainsB:SameFileId', 'HandBackEqualsA:H')
            StatusClasses = @('SeedBOpenWriteFlushClose=Win32:0', 'SeedBJournal=Released;DigestB;DurableFullHistory', 'Open=Win32:0;TRUNCATE_EXISTING', 'Write=Win32:0;WholeImageA', 'Flush=Win32:0', 'PrivateRead=Win32:0;EqualsA', 'Close=Win32:0', 'HeldRawFreshUncached=WholeB', 'RetainedPhysicalReaderAndRaw=WholeB', 'OwnerHandBackRead=Success;EqualsA')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Blocked', 'ImmutableSealedDigestA', 'NoApprovedPublishingReleased')
            NotificationExpectations = @('BlockedDigestA', 'BlockedWithVerifiedHandBackPath', 'NoReleased')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurity', 'NoUserOrServiceTemp')
            LatencyClasses = @('writer-open', 'cached-write', 'flush', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestorePolicyBeforeProductStateInPlace', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
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
            CaseId = 'C04-block'; Revision = 1; Status = 'Ready'
            Variant = 'fixed-NTFS-private-sibling-replacement-approved-B'; Outcome = 'BLOCK'
            QualificationScope = 'Phase4FunctionalOnly; H checked, restart/window closure and unheld latency deferred'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; StartDuringSeed = 3; StartAfterSeed = 0; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('FixtureScope')
            Setup = @('DriverUnloaded', 'SeedBenignBThroughStandardUserOwnedStreamAndRequireApprovedPublishingReleasedDigestB', 'IndependentPatternedTextAWithValidCpf', 'ProductBootPolicy', 'StandardUserTask', 'RealStagingAgent', 'HoldIndependentPhysicalBReaderSharingDELETE', 'BIsFourClusters:AIsThreeClusters')
            Actions = @('SeedAndProveApprovedB', 'OwnedCreateNewSiblingSaveTmpTxt', 'WholeImageWriteA', 'FlushFileBuffers', 'PrivateHandleReadEqualsA', 'HoldWriterDuringThreeRawFreshUncachedBSamples', 'SetFileInformationByHandleFileRenameInfoExReplacePosixOntoTarget', 'RequireSameTransferCommittedTargetAndSourceTombstone', 'HoldRenamedWriterDuringThreeRawFreshUncachedBSamples', 'Close', 'BoundedJournalBlockedWait', 'VerifyRetainedPhysicalB', 'VerifyActorHandBackH')
            Barriers = @('BootIdentityChanged', 'DurableReadiness', 'AgentPolicyAccepted', 'ApprovedBaseB', 'BeforeOperation', 'BeforeRenameHandleHeld', 'NativeRename', 'AfterRenameHandleHeld', 'LastUpperClose', 'Blocked', 'FinalQuiescence')
            ExpectedTimeline = @('UnscopedSetup', 'BootTrusted', 'Protected', 'SeedB:AllocatedSealedInspectingApprovedPublishingReleased', 'RawFreshUncachedB', 'RetainPhysicalB:ShareDELETE', 'PrivateSiblingTemp:Allocated', 'WriteFlushPrivateA', 'BeforeRename:PublicB:NoTemp', 'RenameExReplacePosix:Win32:0', 'CommittedTarget:SameTransfer:SourceTombstone', 'AfterRenameHeld:PublicB:NoTemp:AllocatedUnsealed', 'LastUpperClose', 'Sealed', 'Inspecting', 'Blocked', 'FinalRemainsB:SameFileId', 'HandBackEqualsA:H')
            StatusClasses = @('SeedBOpenWriteFlushClose=Win32:0', 'SeedBJournal=Released;DigestB;DurableFullHistory', 'TempOpen=Win32:0;CREATE_NEW;DELETE', 'Write=Win32:0;WholeImageA', 'Flush=Win32:0', 'PrivateRead=Win32:0;EqualsA', 'RenameEx=Win32:0;REPLACE_IF_EXISTS|POSIX', 'PrivateReadAfterRename=Win32:0;EqualsA', 'Close=Win32:0', 'HeldRawFreshUncached=WholeB', 'RetainedPhysicalReaderAndRaw=WholeB', 'PublicSiblingTemp=Absent', 'OwnerHandBackRead=Success;EqualsA')
            MetadataExpectations = @{ Exact = @('Attributes','Creation','Modified','Changed','Links','SecurityId','Sddl'); Accessed = 'NtfsReadWindow'; AccessReason = 'Same bounded NTFS read-side LastAccess rule as S00-S02; all other baseline metadata exact.' }
            JournalExpectations = @('Allocated', 'Sealed', 'Inspecting', 'Blocked', 'ImmutableSealedDigestA', 'NoApprovedPublishingReleased')
            NotificationExpectations = @('BlockedDigestA', 'BlockedWithVerifiedHandBackPath', 'NoReleased')
            AllowedDirectoryTransitions = @('SameActiveNamesIdsSizesAttributesSecurity', 'NoUserOrServiceTemp')
            LatencyClasses = @('writer-open', 'cached-write', 'flush', 'rename-ex', 'close')
            Repetitions = @{ Coordinated = 1; Unheld = 0; DeterministicSeed = 4003 }
            Cleanup = @('StopAndRestoreAgent', 'RestorePolicyBeforeProductStateInPlace', 'RestoreProductStateBytesAndAcls', 'CommonSeedRestoration', 'IndependentBaseline')
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
            CaseId = 'B01'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Block hand-back failures'
            QualificationScope = 'Phase4; WP4 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP4: design section 4.1 B01')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'B02'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Exact-version justification'
            QualificationScope = 'Phase4; WP4 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP4: design section 4.1 B02')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'R01'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Service restart mid-save'
            QualificationScope = 'Phase4; WP6 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP6: design section 4.1 R01')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'R02'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Service restart mid-policy'
            QualificationScope = 'Phase4; WP6 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP6: design section 4.1 R02')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'R03'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Agent down at boot'
            QualificationScope = 'Phase4; WP6 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP6: design section 4.1 R03')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
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
            CaseId = 'X01'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Concurrent writers/readers'
            QualificationScope = 'Phase4; WP4 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP4: design section 4.1 X01')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
    )
}
