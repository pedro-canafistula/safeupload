# t5-batch1a matrix failure fixes

Base: `b75625eb`, `wt/t5-unload-batch1`. Changes are uncommitted. This is a worker
implementation report, not an independent review or Windows test receipt.

The supplied TRX reports 1,590 executed user cases, 1,583 passed and seven failed.
Its unchanged copy is [failed-normal-debug.trx](failed-normal-debug.trx), SHA-256
`a47a013fff7307e135825ba90528049d8c891f20295ec9e4cd5c6a8f90913082`.

## Failure 1: product regression

`Journal_failure_resumes_handback_without_terminal_failure_or_duplicate_copy`,
both `completingCopy=true / afterReplacement=true` cases, failed because the
dispatcher excluded `Verified` from `RecoverBlockedAsync`. The injected
AfterReplacement failure means the durable record already says Verified, but
execution has not reached the Blocked notification and justification registration.
`ProcessBlockedCleanupAsync` performs neither obligation. It also leaves the
stage held while the existing justification window is open, explaining the sole
Analyzing notification without a terminal copy failure.

Full recovery now calls the existing `RecoverBlockedAsync` for Blocked records,
including Verified. That method rereads durable state, verifies the hand-back's
exact evidence, checks current policy and restores the existing notification and
justification callback. Its copy branch remains restricted to NotAttempted/Copying,
so a committed Verified hand-back is not copied again. No public mutation is replayed.

The live pending scan explicitly selects `cleanupOnly` for Verified records.
It therefore retains bounded cleanup retries without repeating the already-completed
notification or justification registration. The original two-argument recovery
entry point still serves startup, queued progress, and the feature reconciliation
delegate. Explicit bound-receipt recovery retains its separate obligation and idle
shortcut bypass.

After full hand-back recovery succeeds, the dispatcher removes only the queued
progress record it captured before the call, using reference equality. A newer
record queued during cleanup remains pending. Remaining durable cleanup keeps the
existing monotonic backoff. This also makes the existing test's second
`RecoverJournalProgressAsync` pass idle regardless of elapsed execution time.

The existing eight-case test, including every expectation, is unchanged; its body
was compared against HEAD. The two reported failures are expected to obtain exactly
one Blocked notification, a usable justification, and one copy. Windows execution
is still required to establish that result.

## Failure 2: new test setup error

`TestPublicationGate.DisposeStage` always returned true. For Released disposal,
true means the driver retains the version; `DisposeReleasedStageAsync` correctly
returns without deleting the stage or recording StageDeleted. An approved record
already leaves pending publication dispatch in this state. Requiring StageDeleted
while simulating a held stage was inconsistent setup, not a product failure.

The gate now has `HoldReleasedStages`, defaulting to true to preserve all existing
tests. Only the new eight-pattern completion control sets it false, allowing the
existing service-owned exact deletion and journal completion path to run. CleanedUp
responses retain their old behavior. The StageDeleted assertion is retained and a
stage-absence assertion is added. The publisher already closes its measured stage
handle before this disposal, and mapped test handles close before seal.

All eight cases still assert final public bytes, idle repeated publisher passes,
no additional manifest reads/copies/disposals/authorizations, and retained generation,
rename tombstones and deletion receipt across restart. This does not implement the
deferred batch-2 recovery of a driver-deleted Released stage.

## Failure 3: new test setup error

The first save is a blocked new name, so publication never creates the destination.
The subsequent allocation used disposition 1 (FILE_OPEN). The allocator intentionally
refuses FILE_OPEN/FILE_OVERWRITE when there are no previous public bytes; its
FileNotFoundException is the correct precondition enforcement.

The new name-reuse allocation now uses disposition 2 (FILE_CREATE), with assertions
that the public destination is absent both before and after allocation. No public
file is seeded to evade the precondition and the allocator is unchanged. The new
private generation must still advance, while the old completed version remains
absent from dispatch, keeps its exact deletion receipt, and performs no repeated
entry work after requester exit and reconnect.

## Files changed by this task

| File | Change |
|---|---|
| `agente/SafeUpload.Agent.Service/Interception/StagedTransferRecovery.cs` | Full versus cleanup-only recovery; restore Verified hand-back progress; remove only the completed queued snapshot. |
| `agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs` | Live Verified pending records select cleanup-only recovery through the same bounded dispatcher. |
| `agente/SafeUpload.Agent.Tests/StagedHandbackTests.cs` | Correct the two new setups, preserve original assertions, add absence assertions and assert bounded cleanup does not repeat Blocked notifications. |
| `driver/scripts/t5/teardown-participation-selfcheck.py` | Seven added lines in the existing agent dispatch control require Verified restoration, guarded queued-progress removal and the live cleanup-only route. No existing control is renamed or removed. |

Concurrent changes appeared during this session in `StageWriters.c`,
`Test-StagedInvariantSuite.ps1`, and other hunks of the shared teardown self-check.
They were preserved and are not this task's implementation. The final worktree has
six modified tracked files. The local evidence directory is also new and ignored.
No status plan, memory file, shared Git metadata or original evidence was modified.

## Local outputs

- Offline `Invoke-LocalAgentCompile.sh`: **PASS**, all 12 Service/App/Tests builds,
  normal/feature x Debug/Release, SDK 10.0.400, warnings-as-errors. TMPDIR was inside
  this worktree's ignored evidence directory. [Output](local-compile.log).
- Every `driver/scripts/t5/*.py`: **PASS**, exit 0. Initial individual logs are
  retained here; final checks against the concurrent current tree are in
  [current-tree-t5](current-tree-t5/summary.json): allocation retry 7, attach pin 9,
  attachment replay 16, reconciliation retry 15, rename receipt 8, stream listing 3,
  teardown participation 23, Unknown origin 7. The teardown count includes two
  concurrent additions. Notepad verdict reports 14 assertions and
  `ProductQualified=False`.
- Required-test preflight against `t5-block4` using
  `/home/victor/Work/safeupload-staging/driver/evidence`: **PASS**, required=26,
  source_methods=957, baseline_methods=948, removed=0. Its nine listed additions
  include six batch-1 methods and three existing normal-only methods absent from
  feature discovery. [Output](preflight.log).
- The strengthened existing dispatch source control rejects the b75625eb dispatcher
  and three in-memory mutations: removed Verified restoration, removed protection
  for newer queued progress, and removed live cleanup-only selection. Current code
  passes. These are structural diagnostics, not executed Windows regression tests.
  [Output](recovery-source-controls.log).
- `git diff --check`: **PASS**. Service InternalsVisibleTo and the normal/feature
  SAFEUPLOAD_ADMISSION_EVIDENCE symbols were checked; all new overload calls compiled
  in every profile. Existing constructor signatures are unchanged. No wire layout
  or wire test was changed and no Marshal round-trip was introduced.

## Expected Windows counts

No method or theory case is added, removed or renamed in this follow-up. The six
batch-1 methods still add 23 cases per profile to t5-block4. Baseline raw account-leg
TRX counters confirm the user/SYSTEM split:

| Profile | User cases | SYSTEM cases | Total |
|---|---:|---:|---:|
| normal Debug | 1,590 | 25 | 1,615 |
| normal Release | 1,590 | 25 | 1,615 |
| feature Debug | 2,170 | 25 | 2,195 |
| feature Release | 2,170 | 25 | 2,195 |

These remain expected counts. No Windows tests ran here. WDK/PREfast/ApiValidator,
PowerShell 5.1 parsing, Windows runtime and the next full agent matrix remain
unverified. No VM or builder action was taken and no independent review is claimed.
