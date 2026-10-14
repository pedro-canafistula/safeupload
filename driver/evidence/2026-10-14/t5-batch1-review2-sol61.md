**ACCEPT WITH CONDITIONS for the first Verifier boot of b97d263e.** No new defects found in `b75625eb..b97d263e`; no further source revision required by this review.

Previous findings:

1. **High kernel instance race — resolved.** [StageWriters.c:2583](driver/SafeUpload.Minifilter/StageWriters.c:2583) captures/references the instance under RegistryLock, rejects retired entries, rechecks after lookup, and releases the context and instance outside locks at line 2616. Capture-before-retirement and retirement-before-capture are safe under the documented [rundown-reference contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltobjectreference).

2. **Medium publication receipt suppressing cleanup — resolved.** [StagedTransferRecovery.cs:121](agente/SafeUpload.Agent.Service/Interception/StagedTransferRecovery.cs:121) lets Released/Verified cleanup bypass receipt reconciliation. Receipt and cleanup retries have separate dictionaries and monotonic deadlines, capped at eight seconds. Cleanup completion preserves receipt obligations. The two-case regression at [StagedBoundPublicationDispatcherTests.cs:212](agente/SafeUpload.Agent.Tests/StagedBoundPublicationDispatcherTests.cs:212) covers lost ACK replies and retained acknowledged rows.

3. **Medium already-running service blocking veto capture — resolved.** [Test-StagedInvariantSuite.ps1:6655](driver/scripts/Test-StagedInvariantSuite.ps1:6655) stops the running service, waits for Stopped/PID zero, and skips direct capture on timeout. Existing restoration steps and assertions remain unchanged.

**New findings: none.**

Verified in the delta: RegistryLock → SectionLock ordering; no added filter-object reference, lookup or wait under spin locks; balanced new instance/context references on all exits; resident spin-lock code and nonpaged registry objects; the paged transient classifier bypasses diagnostic spin locking; no Unknown reset or synthetic Ended. Agent recovery continues through bookkeeping/private-cleanup paths without replaying publication or a public mutation.

The matrix regression is addressed in source: full recovery restores Verified hand-back notification/justification progress at [StagedTransferRecovery.cs:151](agente/SafeUpload.Agent.Service/Interception/StagedTransferRecovery.cs:151), while live cleanup avoids repeating it. The existing journal-failure assertions remain intact; the two erroneous fixture setups were corrected with added absence assertions.

I ran the source-only teardown self-check: **23 tests passed**, including paused-CREATE models and mutation controls. `git diff --check` passed; the worktree remains clean. Runtime safety is inferred from source/API contracts, not reproduced here.

**Before boot:** require the exact-commit four WDK/PREfast/ApiValidator builds at 0/0, complete four-profile Windows agent matrix without skips, and PowerShell 5.1/native-signature gate. Those receipts were not verified here. Review acceptance does not establish pair qualification or restoration success.