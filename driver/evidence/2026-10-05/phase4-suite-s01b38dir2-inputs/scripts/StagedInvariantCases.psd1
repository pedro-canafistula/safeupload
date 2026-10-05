# Immutable data only. Revision changes whenever a contract changes; variants must get
# distinct CaseIds before becoming Ready. NotReady family IDs reserve the entire
# design section 4 corpus, NOT a claim that one row covers every future variant.
@{
    Schema = 'StagedInvariantCases/1'
    TableRevision = 2
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
            CaseId = 'A01'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Pre-scope handle'
            QualificationScope = 'Phase4; WP5 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP5: design section 4.1 A01')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'A02'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Pre-scope mapped view'
            QualificationScope = 'Phase4; WP5 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP5: design section 4.1 A02')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
        }
        @{
            CaseId = 'A03'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Retained section'
            QualificationScope = 'Phase4; WP5 must expand all design variants'
            ActorSid = 'ResolveStandardUserTokenAtRuntime'; ActorSession = 'ResolveTokenSessionId'
            InitialPolicy = @{ Seed = 'Product'; LiveFlags = 'TEST_DISABLE_TAINT-required' }
            Scopes = @('Unimplemented'); Setup = @('WP5: design section 4.1 A03')
            Actions = @('Unimplemented'); Barriers = @('Unimplemented')
            ExpectedTimeline = @('Unimplemented'); StatusClasses = @('Unimplemented')
            JournalExpectations = @('Unimplemented'); NotificationExpectations = @('Unimplemented')
            AllowedDirectoryTransitions = @('Unimplemented'); LatencyClasses = @('Unimplemented')
            Repetitions = @{ Coordinated = 1; Unheld = 100; DeterministicSeed = 4003 }
            Cleanup = @('Unimplemented; common restoration still mandatory')
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
            CaseId = 'C01'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Cached write'
            QualificationScope = 'Phase4; WP4 must expand all design variants'
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
            CaseId = 'C02'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Mapped write'
            QualificationScope = 'Phase4; WP4 must expand all design variants'
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
            CaseId = 'C03'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Overwrite'
            QualificationScope = 'Phase4; WP4 must expand all design variants'
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
            CaseId = 'C04'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Replacement save'
            QualificationScope = 'Phase4; WP4 must expand all design variants'
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
            CaseId = 'C05'; Revision = 1; Status = 'NotReady'
            Variant = 'UnexpandedFamily'; Outcome = 'Unimplemented: Rename into folder'
            QualificationScope = 'Phase4; WP4 must expand all design variants'
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
