**REVISE — b75625eb is not ready for its first Verifier boot.**

Read-only review of the requested diff and contracts; no edits, builds, tests or VM actions. Findings are source-derived interleavings, not reproduced failures.

1. **High — Early history retirement races an admitted CREATE’s instance lookup.**  
   [StageWriters.c:6130](driver/SafeUpload.Minifilter/StageWriters.c:6130) retires all instances before unregister, without joining ordinary CREATE completions. Retirement clears `Entry->Instance` under RegistryLock at [3957](driver/SafeUpload.Minifilter/StageWriters.c:3957), but alias-proof processing checks and rereads that pointer **before acquiring the lock** at [2567](driver/SafeUpload.Minifilter/StageWriters.c:2567). A pre-gate CREATE can pass section association, pause, then race retirement and supply NULL to `FltGetInstanceContext`. Channel, worker and staged-object drains do not join this callback.  
   **Required:** use a stable callback-owned instance, or capture/reference the instance under RegistryLock while rejecting retired entries; release outside the lock. Add a paused-CREATE teardown control.

2. **Medium — Bound-publication reconciliation suppresses unfinished justified-stage cleanup.**  
   The live loop now routes Released/Verified cleanup through recovery at [MinifilterInterceptor.cs:1438](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1438). Recovery’s bound-attempt branch returns unconditionally at [StagedTransferRecovery.cs:121](agente/SafeUpload.Agent.Service/Interception/StagedTransferRecovery.cs:121), before reaching cleanup. Thus an already-Released justified version with an unresolved publication ACK cannot retry its independent private-stage cleanup until that attempt retires. Previously the live loop invoked cleanup directly. The new hand-back tests do not exercise this bound justified-release case.  
   **Required:** retain publication-receipt recovery and stage cleanup as separate obligations; run eligible cleanup with bounded backoff while the publication attempt remains. Test pending ACK plus last-close cleanup without repeating publication.

3. **Medium — Veto capture fails when the service was already running.**  
   At [Test-StagedInvariantSuite.ps1:6633](driver/scripts/Test-StagedInvariantSuite.ps1:6633), an existing Running service leaves `$agent` NULL. It therefore remains connected when [6652](driver/scripts/Test-StagedInvariantSuite.ps1:6652) forces direct inspection. The driver permits only one connection ([Communication.c:418](driver/SafeUpload.Minifilter/Communication.c:418)), so this branch records a connection error instead of LastUnloadVeto.  
   **Required:** query through the live service proxy, or stop that service and establish disconnect before direct capture. Cover both initially-running and restarted-service cases; preserve restoration assertions.

Verified in source: ACK-before-commit, unchanged quarantine/post-ACK retry branches, mandatory bypass of PrepareUnload/op17, idempotent fence recommit, crossed section-owner deferrals, timer/DPC shutdown, exact completed-BLOCK receipt matching, and lexical validation confined to historical names.

H/UnknownWriterCount exclusion permits quiet **live legacy handles** through; it supplies no writer-free evidence. Sticky Unknown remains enforced while attached. Residual-reference safety depends on callback withdrawal and unregister—the documented I/O boundary supports that ordering, while runtime completion/pool-return behavior remains unverified. [Microsoft’s unregister contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunregisterfilter).

After revision, the required WDK gates, complete Windows agent matrix and PowerShell 5.1 gate still precede boot.