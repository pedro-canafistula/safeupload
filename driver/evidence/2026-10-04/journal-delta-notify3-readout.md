# notify3 journal rejection and delta adapter follow-up

Authoring/evidence analysis only. No guest rerun, qualification, or verification result is asserted. No commit was made.

## Branch and artifact location

`git merge --ff-only feat/staged-kernel-prototype` was attempted first, but the sandbox rejected creation of `ORIG_HEAD.lock` in the linked worktree's read-only Git metadata. `HEAD` and `feat/staged-kernel-prototype` already both resolve to `ba772859c866b929e6cfdb3cccbf4fa967e20302`; the starting worktree was clean.

The notify3 artifacts are untracked in the primary worktree at `/home/victor/Work/safeupload-staging/driver/evidence/2026-10-04/`, rather than this linked worktree. Analysis read the original `boot-start-invariant-{S00-observer-control,S01-denied-write-after-boot,S02-agent-down-open-refused}-ordinary-notify3-artifacts/` directories without changing them.

## Exact rejection

Every case's before and after collection rejects:

`C:\ProgramData\SafeUpload\staging-journal\1807552b5e024c438a012a6a580b4de5.json`

The retained copies are `service-before-1807552b5e024c438a012a6a580b4de5.json` and `service-after-1807552b5e024c438a012a6a580b4de5.json` in each of the three artifact directories. All six copies are byte-identical, with SHA-256:

`A9D51B0A2436705E0112E1666C359F5C4A662120612CDC3146EE1D8AD812A193`

The rejecting clause in the former `Get-ServiceSnapshot` identity/state check is **`$null -eq $entry.DestinationGeneration`**. That property is absent. The filename and `Transfer.TransferId` agree; `ProcessId=10472`, `ProcessName=powershell.exe`, `Destination=0`, `State=6` (Blocked), and the non-default `UpdatedAtUtc` satisfy the other identity/state clauses. `SealedOnce=true` and the 64-character digest are also present.

This is stricter than `StagedTransferJournal.ValidateEntry` for legacy input: its `long DestinationGeneration` defaults to zero when absent and the validator rejects negative values. The observer incorrectly demanded that the property be explicitly present in every historical entry.

The old collector wrote the first JSON copy, then threw before adding its journal record or reading later files. Thus the retained snapshots do **not** contain a complete inventory of the roughly 13 guest manifests. This one rejection is established in all six collections; the other guest files cannot be assessed from these truncated artifacts. Existing notify3 verdicts must remain INCONCLUSIVE.

## Fix

`Test-StagedInvariantSuite.ps1` now collects authenticated, bounded manifest bytes and artifact receipts without parsing current state. It no longer aborts inventory collection because a legacy schema is present.

`Test-ServiceJournalDelta` compares every pre-existing entry by exact retained bytes across snapshots, including entries outside the fixture namespace. Unchanged entries are explicitly listed as **pre-existing, unchanged**, with no current-schema parsing. Changed entries, deletion from a complete inventory, and duplicate paths are findings and produce FAIL, including in the journal expectation results. Missing bytes, incomplete collection, or an unbound operation fence remain INCONCLUSIVE.

Only entries absent from a complete before inventory are interpreted as new. They must satisfy the current writer's serialized fields, identity, numeric/boolean types, timestamp, seal/digest/publication constraints, paths, rename evidence, namespace history, and a reachable state/seal pair under `StagedTransferJournal.IsTransitionAllowed`. Invalid new entries fail regardless of their fixture path. An incomplete before inventory cannot establish that a previously uncollected legacy file is new.

Journal expectations use the new fixture entries and the byte delta. A pre-existing Released fixture manifest no longer contradicts a case-window expectation when its bytes are unchanged. Latest-state snapshots still cannot prove the actual intermediate transitions of a new nonterminal entry; the applicable absence expectations remain INCONCLUSIVE.

## Authoring checks

Linux PowerShell 7.4.2: `StagedInvariantProofAdapters.SelfCheck.ps1` reports `ProofAdapterEvaluationChecks=82;PASS (host-safe synthetic evaluation and identity publication only)`. Added checks cover the actual retained legacy JSON, opaque unchanged bytes, an unchanged Released fixture entry, modified/deleted pre-existing entries, new invalid JSON/schema/state, missing retained bytes, incomplete before inventory, canonical UNC paths, and the absence of intermediate transition history. Existing positive-evidence and notification checks still pass.

PowerShell parsing and compilation of the unchanged native evidence helper completed without invoking Windows functions. `git diff --check` passed. These checks are authoring QA; Windows PowerShell 5.1 and new guest collections have not been exercised here.

## Remaining INCONCLUSIVE reasons in retained notify3 trials

- Journal inventory is truncated by the original rejection; the identical first file alone cannot establish the whole delta.
- `C:\ProgramData\SafeUpload\notifications` is absent in both snapshots. The agent-down seed does not run a durable notification writer; Application events cannot supply emission-absence proof.
- The driver lower admission/completion mutation ledger is unavailable, leaving `PredicateCoverage` and `NoUnapprovedByte` unresolved.
- S01 has an unaccounted capture interval; S02 has an unaccounted cadence gap. Actor attempts overlap those intervals and no lower ledger bridges them.
- Retained `ExternalCoverage` assertions await the host independent baseline and restoration reboot; S01/S02 also cite incomplete cadence.
- The Inspector lacks live `TEST_DISABLE_TAINT` flag readback. Registry `BootPolicy.Flags` does not establish live flags.

The code change does not retroactively replace any retained verdict. Fresh, complete authenticated journal snapshots are needed to establish the requested delta on the guest.
