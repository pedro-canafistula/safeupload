**REVISE.** Both original findings are resolved in the code, but the revision introduces two maintenance problems, and the tests will not all pass as written.

1. **The two previous findings are resolved.**

   Startup and live maintenance now reconsider unmarked Retained predecessors. Child discovery follows the exact parent link across hot and archived records, including archived children hidden by newer destination claims. Empty histories are explicitly excluded, and cancellation explicitly refuses an already-retired version. See [StagedUnboundNamespaceJournal.cs:108](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedUnboundNamespaceJournal.cs:108).

   The archive index appears consistent: load clears and rebuilds it; successful append updates it through `AddArchivedClaims`; compaction invalidates the index and reloads it before returning. I found no stale-ID or duplicate-index defect in those paths. See [StagedTerminalArchive.cs:166](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedTerminalArchive.cs:166), [load:274](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedTerminalArchive.cs:274), and [compaction:578](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedTerminalArchive.cs:578).

   The startup loop preserves the previous dispatch branches and immediately dispatches a newly retired entry. No new startup state-selection defect found.

2. **New defect: throttle entries survive completed transfers.**

   `_supersededChecks` removes an ID only when retirement succeeds through `ReconcileSupersededAsync`. If reconciliation first records an unsuccessful check and the later publication callback successfully retires that predecessor, the dictionary entry remains. Subsequent disposal/archive bypasses reconciliation, and the early ineligible return also performs no removal. Repeated saves therefore accumulate historical IDs for the publisher’s lifetime. See [StagedTransferRecovery.cs:59](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedTransferRecovery.cs:59).

   **Minimal change:** remove the ID on every successful `RetireSupersededAsync`, including prompt triggers; prune throttle IDs against eligible candidates from each pending snapshot so cancelled, retargeted or otherwise completed entries also disappear.

3. **New defect: reconciliation repeats a full hot scan for every predecessor.**

   Each eligible Retained entry enumerates and reads the entire hot journal while holding the global journal gate. With `R` retained candidates and `H` hot entries, a reconciliation round performs **O(R × H)** work. Five-second per-entry throttling does not bound aggregate work or individual gate occupancy; startup performs these scans consecutively before readiness. Cached reads still require enumeration, stamp checks and cache operations. See [StagedUnboundNamespaceJournal.cs:103](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedUnboundNamespaceJournal.cs:103) and [startup:1806](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1806).

   **Minimal change:** derive hot parent-to-child candidates once from the maintenance scan, then reread only candidate records under `_gate` and apply the existing exact eligibility checks. Avoid a fresh directory-wide scan per predecessor. This is a source-level scaling finding; no runtime latency measurement was performed.

4. **The tests fail because their publication fixtures are outside policy scope.**

   `UnboundSealedAsync()` uses `CreateFixtureAsync`’s default `DestinationKind.Cloud`. The fixtures write beneath the temporary workspace, while the default policy monitors `C:\SafeUpload\Escopo Monitorado`. These tests never configure their destination as monitored. See [fixture:874](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Tests/StagedAttachmentV20Tests.cs:874) and [default policy:217](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Core/Infrastructure/PolicyDocument.cs:217).

   Consequently, clean-child assertions expecting Released receive Retained; the CPF case also receives Retained because inspection exits as out-of-scope before detecting CPF. See [InspectionService.cs:170](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Core/Application/InspectionService.cs:170).

   **Minimal change:** explicitly configure the temporary destination directory in `PolicyDocument.Default.MonitoredScopes.DestinationPaths` before publication in these tests, preserving the active CPF category and expected outcomes.

   The other questioned details look correct: the “newer” fixture shares the journal/destination and creates an unrelated allocation; advancing the injected clock by 60 seconds clears recovery backoff; replacing `StateHistory` with `[]` remains valid legacy input and reaches the new refusal check.

Read-only, offline review of `084b9bdb`; no files written or tests executed.