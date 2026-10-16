**ACCEPT WITH CONDITIONS** — scoped re-review of `92f2b159..a086b3dd`. All three previous findings are resolved; no new delta defect confirmed.

1. **High — disconnect disables disposal proof: resolved.** Proof is now a permanent profile requirement, rechecked during final unlink; legacy Released disposal is refused regardless of connection readiness. Feature teardown has no legacy-delete fallback. Evidence: [StageStream.c:6376](driver/SafeUpload.Minifilter/StageStream.c:6376), lines 6425, 7589 and 6343.

2. **High — circular failed-attachment cleanup: resolved.** CleanupOnly is selected before backing closure. The helper holds one explicit pin, drops namespace ownership before flush/rundown/close, then rechecks name withdrawal. Abort also withdraws the candidate claim. Evidence: [StageStream.c:4524](driver/SafeUpload.Minifilter/StageStream.c:4524), lines 4537–4572 and 6529; [StagedTransferJournal.cs:1008](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:1008).

3. **Medium — unbounded positive history: resolved.** Cumulative count/bytes are reconstructed across epochs, retain cleaned positives, and fail closed on exhaustion or uncertain inventory. Reservation precedes manifest creation; existing exact replay bypasses fresh admission. Evidence: [StagedPositiveRecoveryAccountingV29.cs:24](agente/SafeUpload.Agent.Service/Interception/StagedPositiveRecoveryAccountingV29.cs:24), line 64; [StagedTransferJournal.cs:319](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:319); [StagedCustodyV29.cs:262](agente/SafeUpload.Agent.Service/Interception/StagedCustodyV29.cs:262).

**New findings: none confirmed** across the requested lifetime, locking, IRQL/residency, reference, authority, mutation and accounting checks.

The controls address the reported regressions. Native flush/rundown/close are stubs; these controls do not prove Windows concurrency or lifetime behavior.

Before boot, retain the required current-source WDK/PREfast/ApiValidator/import, complete Windows agent matrix and harness gates. The 1,024-record/448-MiB limits remain evaluation defaults pending owner sizing approval before cutover.

Verified statically; runtime safety remains unqualified. Diff whitespace and changed Python syntax checks passed. No builds, product tests, VM actions or file changes.