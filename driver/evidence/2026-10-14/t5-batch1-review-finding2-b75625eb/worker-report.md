# Batch-1 review finding 2 and veto-capture control

Base: `b75625eb` on `wt/t5-unload-batch1`, with the prior matrix-failure fixes and
the other workers' finding-1/finding-3 edits already present. All changes remain
uncommitted. No builder, VM, commit or push action was taken. This worker report
does not constitute an independent review or review acceptance.

## Finding 2: independent publication receipt and private cleanup

The reviewed bound-attempt branch returned before Released/Verified cleanup, and
its retry used the same dictionary as private cleanup. A pending ACK could thus
suppress the first exact disposition or prevent last-close bookkeeping from
finishing. A retained receipt without a diagnostic also escaped bounded retry.

The worker now has two separately owned retry dictionaries under the existing
serialized recovery gate:

| Dispatch | Work and retry owner |
|---|---|
| Explicit bound receipt recovery | Exact Facts/ACK/replay reconciliation; bound receipt retry. |
| Bound Publishing recovery | Existing receipt reconciliation; bound receipt retry. |
| Ordinary Released/Verified recovery | Existing exact private cleanup; local cleanup retry, bypassing bound reconciliation even while its attempt exists. |
| Blocked full recovery versus live cleanup-only recovery | Prior matrix fix retained: restore Verified notification/justification progress when needed; live cleanup does not repeat it. |

Both deadlines remain monotonic, per transfer, 250/500 ms then 1/2/4/8 seconds,
capped at eight seconds. Any unfinished publication receipt arms its retry,
including a retained ACK row with no diagnostic. Bound reconciliation exceptions
also arm the bound retry. Completing private cleanup clears only local retry;
publication receipt retirement still requires the existing later exact replay.
Neither recovery route invokes publication. No wire contract or retirement mode
was introduced. The existing two-argument reconciliation delegate remains intact.

The timing/state note is added to `driver/T5-VOLUNTARY-UNLOAD.md`; status plans
were not edited.

## New agent regression theory

`StagedPublicationNativeJournalTests.Pending_publication_ACK_does_not_suppress_justified_stage_last_close_cleanup`
adds two feature-only cases: lost ACK reply, and acknowledged-but-retained native
row without a diagnostic. It uses the existing real manifest/head fixture and
bound dispatcher, fake native publication calls, and actual private files/read holds.

It constructs the justified version through Blocked, verified hand-back, closed
justification, Approved, Publishing and exact bound Released journal transitions.
It then grows only receipt backoff to eight seconds before attempting cleanup.
The assertions require:

- An exact blocked-deletion receipt and cleanup-start state while a real read hold
  prevents last close; StageDeleted must still be false.
- No manifest reads or disposal calls during skipped local retries before 250 ms.
- Closing the read hold permits StageDeleted/absence while the publication attempt
  and its durable native receipt are still retained, before receipt retry is due.
- Local completion does not clear the receipt deadline. Completed cleanup visits
  perform no per-entry manifest reads, but explicit receipt dispatch remains eligible.
- ACK alone keeps durable publication obligations; a later exact replay retires them.
- Native CREATE and rename each occur once, publication cleanup is never invoked,
  public identity stays unchanged, and cleanup never authorizes legacy publication
  or recopies the verified hand-back. The cleanup hand-back stub checks actual bytes.

Before this fix, the lost-reply case is blocked by the shared eight-second retry;
the retained-row case enters reconciliation and returns without private cleanup.
Neither can produce the deletion receipt, so the first receipt assertion fails.
This fail-before conclusion is source-derived, not a Windows execution receipt.
The strengthened source control also rejects an in-memory restoration of the old
bound-return route. [Mutation results](source-mutations.json).

The existing publication fake defaults retain their behavior; the two new switches
are enabled only by this theory. The existing hand-back regression test and the
previous matrix-failure fixes were preserved. Constructor signatures, service
InternalsVisibleTo, and feature symbols were checked; all overload/test calls compile
in every profile. No wire test gained a Marshal round-trip.

## Harness control

The existing `test_veto_diagnostic_preserves_restoration_and_direct_inspector_route`
is extended, without renaming it or changing the harness. It now pins:

- No-success unload branch, restarted-agent stop, and capture before later unload.
- For a still-running SafeUploadAgent: service stop, monotonic disconnect wait,
  Stopped plus ProcessId zero, and a timeout throw before direct inspection.
- Direct `--writer-state-status` capture and CapturePath in both success and failure
  receipts, including the initially-running and restarted-agent paths.
- Timeout goes to the diagnostic catch instead of invoking the inspector.

Its three in-memory mutations must fail: removed disconnect wait, removed PID-zero
proof, and removed timeout throw. All are caught. Existing ASCII/no-BOM, inspector
helper/proxy routing, and restoration controls remain. The kernel paused-CREATE
controls and the orchestrator's harness implementation were preserved.

## Files changed in this turn

1. `agente/SafeUpload.Agent.Service/Interception/StagedTransferRecovery.cs` — separate
   receipt retry and cleanup dispatch; retain the prior hand-back recovery fix.
2. `agente/SafeUpload.Agent.Tests/StagedBoundPublicationDispatcherTests.cs` — two-case
   regression theory and isolated fake/stub support.
3. `driver/scripts/t5/teardown-participation-selfcheck.py` — independent cleanup/receipt
   routing guards and the disconnect/capture control with three mutations.
4. `driver/T5-VOLUNTARY-UNLOAD.md` — retry ownership and interleaving note.

The complete worktree has eight modified tracked files. The earlier changes to
MinifilterInterceptor.cs, StagedHandbackTests.cs, StageWriters.c and
Test-StagedInvariantSuite.ps1 remain untouched in this turn. Earlier hunks in the
two shared modified files were retained. This new ignored evidence directory
contains the report and logs; existing evidence and memory were preserved.

## Local verification

- **PASS** offline four-profile compile: all 12 Service/App/Tests builds,
  normal/feature x Debug/Release, SDK 10.0.400, warnings-as-errors. TMPDIR was inside
  this worktree's ignored evidence directory. [Output](local-compile.log).
- **PASS** every `driver/scripts/t5/*.py` check. Final [summary](final-t5/summary.json):
  allocation retry 7 tests, attach pin 9, attachment replay 16, reconciliation retry
  15, rename receipt 8, stream listing 3, teardown participation 23, Unknown origin
  7. Notepad verdict reports 14 assertions and ProductQualified=False.
- The first self-check run caught a new matcher incorrectly requiring a semicolon
  after PowerShell `throw`. The matcher now accepts valid syntax with or without
  that semicolon; the timeout guard remains mandatory. The [failed output](teardown-participation-selfcheck.log)
  and all initial logs were retained separately from final outputs.
- **PASS** requested preflight against t5-block4 with
  `/home/victor/Work/safeupload-staging/driver/evidence`: required=26,
  source_methods=958, baseline_methods=948, added=10, removed=0. The additions include
  three existing normal-only methods absent from feature discovery. [Output](preflight.log).
- **PASS** `git diff --check`. No existing agent method/control was renamed or removed.

## Expected matrix counts

The prior batch-1 six methods add 23 cases per profile. This turn adds one theory
with two cases under SAFEUPLOAD_ADMISSION_EVIDENCE, both in the user leg:

| Profile | User | SYSTEM | Total |
|---|---:|---:|---:|
| normal Debug | 1,590 | 25 | 1,615 |
| normal Release | 1,590 | 25 | 1,615 |
| feature Debug | 2,172 | 25 | 2,197 |
| feature Release | 2,172 | 25 | 2,197 |

These are expected counts, not discovery/execution receipts. Windows agent tests,
PowerShell 5.1 parsing/native signatures, WDK/PREfast/ApiValidator, Verifier and
protected runtime behavior remain unverified. Fake publication calls and structural
source mutations are component diagnostics, not product qualification.
