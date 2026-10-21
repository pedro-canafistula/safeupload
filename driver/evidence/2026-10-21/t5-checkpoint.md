# T5 checkpoint — 2026-10-21

Owner decisions D1–D3 for closing T5 for now are in `driver/POST-MVP-PLAN.md` ("2026-10-21 (T5 plan)"). T5 rows run on the T4 kernel
(`d1068cc3`, signed driver sha 3547377A…) with product defaults (staging budget on). Nothing here is a qualification result.

## D1 source check (no VM): the shipped path lacks the owner's unreadable-seed policy

Owner decision 2026-10-13 (option 1, `T5-NATIVE-PUBLIC-OPENS.md`): a blocked version that contains prior bytes whose read/export authority is denied or
unresolved stays service-private (Blocked + HandbackState.Failed, named reason, no readable hand-back). Only the bound profile implements it
(`StagedSeedExport.Failure` returns null for an entry with neither `SeedProvenance` nor `BoundAllocation`). The unbound allocator (`StagedTransferAllocator`,
`copyExisting`) seeds the old public bytes under SYSTEM, and a block hands the whole snapshot back with user read access. A subject that may write but not
read the file would receive its old bytes. Agent-only fix delegated (branch `t5/seed-export`); a regression case (blocked edit of an existing readable file keeps
its hand-back) is part of the row work.

## Diagnostic rows (T4 pair, ordinary mode, existing Notepad row)

| Row | Result |
|---|---|
| `m2t5ord1` | Stopped at install (exit 15, [host](m2t5ord1-host.txt), [install](m2t5ord1-install.txt)): PR #38's installer passes the agent configuration to `--seed-boot-policy`; the older `586ae7cb` agent rejects it (task result 2). The row launcher uploads the installer from the checkout, so T5 rows need an agent built from the merged tree. No T5 case ran. |
| `m2t5ord2`, `m2t5ord3` | Launched from a worktree at `99b00f38` (installer matches the package). Same result twice: case 1 `probe-delete-before-seal` native steps `test-create=0 test-delete=0 test-close=0 save-create=32`; `T5CasesCompleted` FAIL 1 of 8 ([ord2](m2t5ord2-verdict.txt), [ord3](m2t5ord3-verdict.txt)). Deterministic. |
| `m2t5ord4` | Same launcher plus a copy of the agent's journal and staging root ([verdict](m2t5ord4-verdict.txt), [journal](m2t5ord4-agent-journal), [list](m2t5ord4-agent-state-list.txt)). |

### Root cause of `save-create=32`

The agent's journal in `m2t5ord4` (`completed/00000001.pack`, frame for `probe-delete.txt`): `DiscardPending` requested 09:31:47.669, acknowledged 09:31:49.213 — **1.54 s**
(the budget refund followed at 09:31:50.245). The staging-budget refund grace is 1.5 s (`StagedSpaceBudget.RefundGrace`), so the next allocation
(`StageAllocate` 1530 ms, no transfer) was refused and the kernel mapped "allocation not committed" to STATUS_SHARING_VIOLATION (Win32 32).
Why 1.5 s: the discard is requested when the delete disposition is set, while the application's writer handle still holds the stage open; the exact delete
(`StagedStageFile.TryDeleteExactAndConfirmAbsent`, share mode 0) fails, and `ProcessExactDiscardCleanupLoopAsync` retried on a flat 1 s interval with no wake-up
when a discard arrived. The harness expectation (`save-create=0`) is right and unchanged.

Fix (agent only): `StagedDiscardCleanupSchedule` — wake the loop when a discard is recorded and retry on a bounded 25→800 ms backoff while discards stay pending,
then the 1 s idle interval. Compiled in feature Debug/Release; the new tests (`StagedDiscardCleanupScheduleTests`) and the full matrix have not run yet.

### Harness findings

- The T5 coordinator's `Get-JournalFor` reads only flat `*.json` manifests; the staged agent archives terminal receipts into `completed\*.pack`, so the case's
  journal evidence is empty and the forced-order gate cannot complete. Worker `t5/rows` ports the Phase 4 reader contract (`e7a6990a`).
- The coordinator throws on the first failed case, so the remaining 7 cases never ran. Per-case recording is part of the same work.

## Agent matrices

| Label | Source | Result |
|---|---|---|
| `m2t5a1` | `47121503` (merged PR #38 + discard pacing) | **FAIL**, first leg (feature-debug user) 3,103/3,104, zero skipped; remaining legs did not run. Failed: `StagedTerminalArchiveTests.Ten_thousand_terminal_records_leave_constant_hot_work_and_bounded_allocate_seal_cost(sameDestination: True)`, 11,595 ms against the unchanged 1,000 ms bound. The whole leg ran 1,229 s vs 653 s in the last green matrix (`m2t4refund2`) and the same test family 3.4-4.2x slower, while a second matrix (`m2t5a2`) ran on builder2 on the same host. Hypothesis: host contention, not code; not yet shown. Receipt: [summary](exact-agent-matrix-m2t5a1-summary.txt), [durations](exact-agent-matrix-m2t5a1-durations.txt). |
| `m2t5a2` | `dc16ae12` (+ seed-export guard) | **FAIL**, first leg 3,146/3,148: the same timing bound again (it ran beside `m2t5a1`) and `StagedHandbackTests.Blocked_same_name_resave_after_retirement_is_ordinary_and_inspected(blockAgain: True)` (see `m2t5a3`). |
| `m2t5a3` | `d157ba3f` (final agent tree, owner option A) | **FAIL**, first leg 3,148/3,149 in 827 s (no concurrent matrix): the timing bound passed alone, which supports contention as the cause of the two earlier timing failures. The one failure is `Blocked_same_name_resave_after_retirement_is_ordinary_and_inspected(blockAgain: True)`: the seed-export guard evaluates read authority of a fixture requestor (fixed PID/creation time, not a live process) as Unproven, so the second save's hand-back is withheld. A test fixture issue, not a product regression: the test now injects an `Allowed` evaluator like the other seed tests; the Denied/Unproven outcomes stay covered in `StagedUnboundSeedExportTests`. |
| `m2t5a4` | the commit with that test fix | pending: must run alone, all four legs. |

## Next

- [ ] Seed-export guard (worker `t5/seed-export`) and the row harness (worker `t5/rows`) land; merged tree builds the four-leg agent matrix.
- [ ] Ordinary, runtime-Verifier and boot-Verifier T5 rows on that agent; restoration after each.
