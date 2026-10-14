# T5 batch 1 worker handoff

Implemented in `/home/victor/Work/safeupload-t5unload`, branch `wt/t5-unload-batch1`, based on
`27f570b78df33e01bc00d45225a40f6a5c6f5c00`. All source changes are uncommitted. No build server,
product VM, commit or push was used. POST-MVP-PLAN.md, other status plans and .ai-memory.toml
were not edited. This is implementation and local diagnostic evidence, not independent review
or protected-pair qualification.

Kernel preparation now excludes disposable history from both existing writer snapshots.
Genuine owning leases/backends, reservations, W/rename users, active transaction users/enlistment,
directory completions, tagged section callback owners and live SOP spill users still veto.
Ordinary H/UnknownWriterCount records contain non-owning FILE_OBJECT identities; counting
quiet handle history would recreate the volume-wide veto, so those counts are excluded.
All other staged/native/public/bound/fence/receipt/policy vetoes remain. Successful exact
EPOCH_DRAINED plus the second snapshot and fence commit enters the existing permanent local
teardown machinery for both callers. Mandatory teardown still bypasses preparation and op17.
Post-ACK veto/quarantine/replay behavior is unchanged.

Retirement detaches and releases registry pins outside RegistryLock, retires association table
references, joins/purges directory rename work and preserves callback-owned reservations,
section slots and spill references. Anchors close before dependent waits. Section callback
ownership is separate from idle pairing history; crossed acquire/release completions defer
slot removal until both owners end. No teardown path publishes synthetic Ended or resets
Unknown for admission. Residual section/SOP references drop only after unregister; the compact
pool's complete-return condition is asserted and its defensive live-pool retention remains.

The agent excludes only exact completed BLOCK cleanup from pending dispatch, retains its
manifests/receipts/tombstones, uses lexical historical-name validation and routes unfinished
cleanup through bounded monotonic recovery backoff. Explicit bound-publication receipt
recovery remains separate from the terminal cleanup shortcut. RCA defect (2), durable R/E
retirement, refusal reclamation and late-load/reload hardening remain deferred.

## Changed source files (14)

| File | Change |
|---|---|
| `driver/SafeUpload.Minifilter/Filter.c` | Common committed local teardown after successful voluntary preparation; pre-unregister retirement and post-source-barrier final cleanup. |
| `driver/SafeUpload.Minifilter/Stage.h` | PASSIVE retirement/finalization declarations and resident section acquire completion declaration; historical common API semantics documented. |
| `driver/SafeUpload.Minifilter/StageStream.c` | Common permanent-state semantics and successful section acquire postoperation ownership release. |
| `driver/SafeUpload.Minifilter/StageWriters.c` | Obligation predicate, permanent producer fences, all-instance retirement, pin/table reference release, directory completion join, source-barrier slot cleanup, tagged slot ownership and compact-pool assertion. |
| `agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs` | Exact completed-cleanup projection, terminal-only pending-scan cache eligibility, lexical historical paths and manifest-read observability. Fresh live/authority reads retained. |
| `agente/SafeUpload.Agent.Service/Interception/StagedTransferRecovery.cs` | Cleanup dispatch/backoff and terminal shortcut; explicit bound receipt recovery; two-argument delegate preserved; deterministic monotonic timestamp seam. |
| `agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs` | Completed cleanup snapshot returns before journal/file work. |
| `agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs` | Live BLOCK/justified cleanup uses the bounded recovery dispatcher. |
| `agente/SafeUpload.Agent.Tests/StagedHandbackTests.cs` | Eight actor patterns, seven receipt mismatch cases, last-close backoff and requester-exit/reconnect/name-reuse controls. |
| `agente/SafeUpload.Agent.Tests/StagedTransferJournalTests.cs` | Five lexical historical-path cases. |
| `agente/SafeUpload.Agent.Tests/StagedAttachmentV20Tests.cs` | Exact tilde rename receipt/tombstone replay after name reuse and same-epoch reconnect. |
| `driver/scripts/Test-StagedInvariantSuite.ps1` | Veto status after stopping restarted agent, before later unload; direct inspector-helper switch avoids stopped proxy. ASCII/no BOM. Restoration assertions unchanged. |
| `driver/scripts/t5/teardown-participation-selfcheck.py` | Existing names retained; corrected history expectation, added retirement/ownership mutations and agent/harness structural controls. |
| `driver/T5-VOLUNTARY-UNLOAD.md` | Batch-1 P/Q/T contract, lifetime/lock/retry interleavings, implementation and explicitly deferred work. |

This ignored local evidence directory is also new. It contains selected raw outputs and this
handoff; no existing evidence was overwritten or removed.

## Agent controls and expected counts

| New method | Cases per profile | What its assertions establish when run on Windows |
|---|---:|---|
| Completed_harness_patterns_leave_dispatch_and_do_no_entry_io | 8 | resave/new/replace/mapped x approve/block; actual mapped write; occupied public targets; exact cleanup; repeated pending projections and completed BLOCK visits perform no manifest read, copy, disposal or authorization; restart preserves generation/tombstones/receipts. |
| Completed_BLOCK_projection_requires_the_matching_deletion_receipt | 7 | Missing/wrong transfer, generation, full identity, rename count, length or digest cannot become terminal pending projection; incomplete flags still dispatch. |
| Unfinished_BLOCK_cleanup_uses_bounded_monotonic_backoff_and_last_close_finishes_once | 1 | Driver-like read hold keeps deletion unfinished; no entry work before 250/500 ms, 1/2/4/8 s deadlines; capped 8 s retry and real last close finish without recopy/public authorization. |
| Completed_BLOCK_after_requester_exit_remains_idle_across_reconnect_and_name_reuse | 1 | Historical owner binding survives actual requester exit; service restart preserves receipt, ordinary resave advances generation and the prior completed version stays idle. |
| Historical_names_are_validated_lexically_even_when_the_leaf_is_absent | 5 | Literal tilde/short-name spellings accepted without creating/opening the absent directory; dot/dotdot/repeated separators refused. |
| Historical_tilde_rename_receipt_and_tombstone_survive_name_reuse_and_same_epoch_reconnect | 1 | Original exact v20 source receipt and tombstone replay survive reuse of the old name; altered source generation refuses replay and the reused object is unchanged. |

Six methods add **23 cases in each profile**. Against t5-block4's 1,592 normal / 2,172 feature,
expected discovery/execution counts are **1,615 normal Debug, 1,615 normal Release,
2,195 feature Debug and 2,195 feature Release**. These are expected counts, not a Windows
matrix receipt. No existing test was renamed or removed. Service InternalsVisibleTo, test
constructors and SAFEUPLOAD_ADMISSION_EVIDENCE paths were checked by the four-profile compile.
No wire test gained a Marshal round-trip; existing MemoryMarshal wire construction is preserved.

The completed BLOCK idle assertions target the old ReadPendingAsync defect; approved patterns
are regression controls for the already-idle Released projection. Actual Windows fail-before /
pass-after execution remains unverified here. Five lexical cases were invoked directly on Linux
with their existing xUnit assertions, without VSTest discovery; that is a diagnostic subset only.

## Changed self-check expectations

- `test_sop_anchor_and_witness_participation` no longer requires an empty RegistryEntries or
  TransactionAssociations table, or zero global/SOP Unknown. It requires the actual reservation,
  W/rename, association-user/enlistment, active-directory and spill-owner guards.
  H and UnknownWriterCount remain admission evidence but are not owning unload obligations. Sticky
  lifetime Invalid and the permanent anchor/reclaim fences remain checked.
- `test_close_owned_handles_before_dependent_drains` now checks history retirement before
  unregister and residual slot/reference finalization after unregister/callback rundown. Its
  existing close-before-wait, worker, paging and context barriers remain.
- Both writer snapshots remain required in `test_voluntary_rollback_and_new_create_fence`;
  ordinary veto/reopen behavior remains required. New commit controls apply only after success,
  so they do not reject the approved post-ACK quarantined retry path.
- Section pairing history is not an active tagged callback owner. New controls require acquire /
  release ownership, both crossed-completion deferrals and source-barrier-only bulk slot cleanup.
  Natural failed acquire / successful release paths also refuse to free another callback's slot.
- The body reader accepts in-memory mutated sources without writing production files. All
  original test method names remain; four additional methods cover the batch contract,
  mutations, agent dispatch/lexical authority and veto diagnostic ordering.

**27 mutation controls are rejected:** unconditional ready; missing owner/write-callback/reservation guards;
missing second snapshot; teardown before ACK; post-commit reopen/rollback/veto; missing or double
instance and volume pin release; retained association table reference; anchor reinsertion;
active reservation or section free; missing acquire/release owner guards; freeing an acquire
owner on release or a release owner on failed acquire; forced Ended; Unknown reset; paged spin
body; surviving timer, directory completion or worker. The old HEAD fails the new obligation /
retirement source contract as expected. These structural controls do not prove WDK IRQL or
Windows completion behavior.

## Local outputs

- `TMPDIR=/tmp/safeupload-t5-batch1-tmp bash driver/scripts/Invoke-LocalAgentCompile.sh`: final
  **PASS for all 12 Service/App/Tests builds**, normal/feature x Debug/Release, offline SDK
  10.0.400, warnings-as-errors. [Final output](local-compile-delivery-pass.txt).
- An intermediate four-profile compile caught a feature-only CS1503 method-group mismatch
  from the recovery signature. The two-argument delegate was restored using a private
  three-argument overload and the entire compile passed afterward. The
  [failed output](local-compile-delegate-failure.txt) and individual feature logs are retained;
  initial compile output is retained separately.
- Required-test preflight with the requested external t5-block4 evidence path: **PASS**,
  required=26, removed=0, baseline feature methods=948, combined source methods=957. Its nine
  listed additions include six new methods and three already-existing normal-only methods
  excluded from feature discovery. [Output](agent-test-preflight.txt).
- Every `python3 driver/scripts/t5/*.py` check passed on final kernel/source. See
  [final summaries](selfchecks-delivery/summary.json) and each full output there: allocation retry
  7, attach pin 9, attachment replay 16, reconciliation retry 15, rename receipt 8, stream listing
  3, teardown participation 21 (including 27 mutation subcontrols), Unknown origin 7; Notepad
  host verdict reports 14 assertions and ProductQualified=False. Earlier all-pass outputs are
  separately retained in `selfchecks/` and `selfchecks-final/`.
- Focused lexical VSTest attempt: **ABORTED before execution**, sandbox socket permission
  denied (SocketException 13). [Output](lexical-vstest-aborted.txt) and
  [TRX](lexical-vstest-aborted.trx) retained. A socket-free direct diagnostic invoked the same
  five lexical test bodies on Linux: **5 PASS**, no skips. [Output](lexical-direct-run.txt).
- `git diff --check`: PASS. PowerShell source byte checks: ASCII, no BOM. No PowerShell 5.1
  interpreter/native Windows signature gate was available locally.

## Outstanding verification

No WDK build, PREfast, ApiValidator, Windows agent test execution, PowerShell 5.1 parsing,
real harness run, Verifier or product VM observation was performed. In particular, the
unregister completion-source barrier, slot deferrals, compact-pool return, idle/nonzero-history
voluntary unload, real vetoes and unchanged quarantine/post-ACK retry need builder/static and
Windows runtime evidence. Independent Sol 6.1 xhigh pre-boot review follows; none of the worker's
source checks is independent review. No matched driver/agent binaries or artifact hashes are
delivered by this source-only handoff.
