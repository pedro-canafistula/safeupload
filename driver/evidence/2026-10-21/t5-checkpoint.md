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
| `m2t5a4` | `a85ae8d4` (that test fix) | **PASS**, all four legs alone on builder1: 3,174/3,174 per profile, user and SYSTEM legs, 0 warnings / 0 errors; package `FF0C55D2…` (service exe `E3F871A8…`). [Summary](exact-agent-matrix-m2t5a4-summary.txt), [durations](exact-agent-matrix-m2t5a4-durations.txt). Component result, not row qualification. |

## Harness gates (Windows PowerShell 5.1)

| Label | Source | Result |
|---|---|---|
| `m2t5hg1` | `4a8f8c26` (row harness `53ddf152`) | **FAIL** ([receipt](harness-windows-gate-m2t5hg1.txt)): every file parses with 0 errors; 33 self-checks exit 0; `t5/notepad-actor.SelfCheck.ps1` and `t5/notepad-coordinator.SelfCheck.ps1` (both from 2026-10-11, first gated by `53ddf152`) exit 1 at line 2 — in an advanced script run with `-File`, 5.1 leaves `$PSScriptRoot` empty inside `param()` defaults. Fixed in `601cb311` (path resolved in the body; assertions unchanged). |
| `m2t5hg4` | `18723ea6` | **PASS** ([receipt](harness-windows-gate-m2t5hg4.txt)): 35/35; observer self-check 122/122 (adds the opt-in stale-metadata retry classification), coordinator 176. |
| `m2t5hg3` | `0ac25de0` | **PASS** ([receipt](harness-windows-gate-m2t5hg3.txt)): 35/35, coordinator self-check 176 assertions including the case-inventory load. |
| `m2t5hg2` | `601cb311` | **PASS** ([receipt](harness-windows-gate-m2t5hg2.txt)): all files parse with 0 errors, 35/35 self-checks exit 0 on 5.1.19041.6456 (coordinator schema 174 assertions; actor native control `NativeActorControl=PASS`, unprotected). |

## Rows on the merged agent (T4 kernel `3547377A…` + `m2t5a4` agent `FF0C55D2…`, win10-debug3)

| Row | Source / mode | Result |
|---|---|---|
| `m2t5ord5` | `601cb311`, ordinary | **FAIL**, harness ([verdict](m2t5ord5-verdict.txt), [result](m2t5ord5-result.json)): install, reboot, Ready, actor session and raw baseline all succeeded; the coordinator then ran **0 of 20** cases. Windows PowerShell 5.1 writes a top-level JSON array as one object, so `@(… \| ConvertFrom-Json)` gave a one-element case list and `Join-Path $root $case.Leaf` threw on `Object[]` (coordinator line 1856). PS 7 enumerates the array, so the offline replay never saw it. No product behaviour was exercised. Restoration: XML unchanged, run overlay deleted, base untouched. Fixed in `0ac25de0` (inventory loader plus a self-check assertion that fails on the old form). |
| `m2t5ord6` | `0ac25de0`, ordinary | **FAIL** ([verdict](m2t5ord6-verdict.txt), [result](m2t5ord6-result.json), [journal](m2t5ord6-agent-journal)): all 20 cases ran (374 s); restoration clean. Product outcomes seen: case 1 now publishes its exact 25 bytes after the private discard (the `47121503` pacing fix), Notepad clean Save As publishes exactly 28 bytes, Notepad CPF Save As is handed back with nothing leaked. Every case still fails, on four harness defects and three findings below. |
| `m2t5ord7` | `98964002`, ordinary | **FAIL** ([verdict](m2t5ord7-verdict.txt), [result](m2t5ord7-result.json)): 20/20 cases, 186 samples (470 s); restoration clean. The on-close case's native steps now match exactly (STATUS_DELETE_PENDING / Win32 5). Remaining failures below. |
| `m2t5ord8` | `eadb2a58`, ordinary, **budget off** (owner) | **FAIL** ([verdict](m2t5ord8-verdict.txt), [setting](m2t5ord8-stage-space.txt); the 26 MB result stays local): 20/20 cases, 171 samples (437 s); restoration clean. The first eight cases now have all or nearly all raw samples OK (ProbeDelete 8/8, CPF delete-before-seal 9/9 with hand-back and private discard, delete-on-close 9/9, on-close 6/6, Notepad clean 11/11 and CPF 10/10). With the budget off the save after the test-file delete succeeds, confirming the T9 diagnosis. |
| `m2t5ord9` | `b8cb3e49`, ordinary, budget off, **D7 driver** `26075F68…` | **FAIL, product regression** ([verdict](m2t5ord9-verdict.txt), [agent events](m2t5ord9-service-events.txt); 181 MB result kept local): after the first native D7 `DeleteFileW`, the agent logged "Admission coverage Degraded: WriterStateUnknown" and from then on the driver's legacy create gate refused every approved publication ("Could not create approved publication file … Access is denied"; deny ring: service process, reason `legacyCreateGate`), so most cases timed out (1,830 s). Root cause below. |

### `m2t5ord9` triage — D7 opens bypass the writer registry

The writer registry treats DELETE and FILE_WRITE_ATTRIBUTES opens as writers that need a reservation (`StageWriterCreateCanMutate`);
the generic CREATE path reserves them (`SafeUploadStageWritersReserveCreate` in `StageDispatchCore`), but the native namespace route
returns before that point. When such a handle closes, the registry's cleanup finds no stream context on a trusted instance and marks
`SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP` (`StageWriters.c` cleanup), which is sticky until reboot. Writer state Unknown degrades admission
coverage, the instance trust gate is no longer satisfied, and the legacy create gate refuses protected creates, including the agent's
publications. The pre-existing D1 non-mutation route and the native delete-on-close route have the same bypass for writer-classified
opens; D7 made it common (`DeleteFileW`, `MoveFileExW`). Not caught before boot: the host fixture does not compile the registry or the
cleanup path, and neither review traced registry ownership of native-route handles. Fail-closed held: no forbidden bytes; publications
were refused, not exposed. Next: D7 revision 4 — native-route writer-classified opens take the writer-registry reservation and its
post-create — then review, build and rows; the next row also captures the driver's registry Unknown reasons.

### `m2t5ord8` triage

- **Product (kernel, design gap): `DeleteFileW` of a published protected file is refused.** Both after-publication probes: a new
  private version is allocated 34–87 ms before the refusal (journal: allocation 02:42.333, deny 02:42.367; 02:56.839 / 02:56.926), and
  the disposition on that staged handle is refused `STATUS_ACCESS_DENIED` (deny ring 109–112). `DeleteFileW` opens with
  DELETE | READ_ATTRIBUTES and `FILE_OPEN_REPARSE_POINT`; `StageMvpNamespaceCreateEligible` excludes that flag, so the open keeps writer
  classification (DELETE is writer access) and takes staged admission, as `T5-UX-NAMESPACE-GAP.md` item 2 specifies
  ("OPEN|DELETE_ON_CLOSE|OPEN_REPARSE_POINT … must take ordinary staged admission or refuse"). Consequence: `del`, `Remove-Item` and
  Explorer's permanent delete of a published file fail "Access denied" on the shipped profile (recycling is a rename and is native).
  This contradicts T5's requirement that both `DeleteFileW` calls succeed. Fix needs a design delta and an independent review before
  kernel code. The earlier "own view lingers" hypothesis is superseded: the process's own view is not required.
- **Harness: Explorer rename produced `explorer-renamed.txt.txt`** (FolderItem.Name with hidden extensions takes the base name); the
  stray file failed every later raw sample's directory check (22 samples), and the second-process open reported 5377
  (`0x80131501`, a PowerShell wrapper) for a missing file. Fixed in `b5bbeb97`.
- **Harness: unsynchronised "actor running" samples can straddle a publication** (3 samples): the raw capture saw the name absent and
  the buffered read a moment later found the newly published file (0 or 45 bytes). Accepting such a transition would change a verdict
  rule, so it is for the owner; not changed.

### `m2t5ord7` triage

- **Harness: the observer's MFT map failed permanently (53 samples).** As the cases create files, Windows grows the MFT; the one allowed map refresh reads the MFT's own record 0 from disk, which also lags, so it stays truncated and the observer marks its map unusable for the rest of the run (by design). Fix: with the opt-in flush, flush before every capture, not only after a failure. "Bad signature" (5 samples) is the same lag.
- **Product (kernel): deleting a just-published file is refused.** `probe-delete-after-publication`: the empty probe version reached Released and the raw observer saw it at 16:44:39.998; the actor's `DeleteFileW` at 16:44:41.44 opened with DELETE successfully, then both disposition classes (0x40, 0xD) were refused `STATUS_ACCESS_DENIED` by the filter (deny ring 111–112, no reason/site, choke point only). T5 requires that delete to succeed natively. Hypothesis, not yet shown: the released version's private view still exists for the name, so the open takes the private route instead of the native one (`StageMvpNamespacePre`: `StageFindView` → private). Under investigation.
- **Product (agent, T9 class): a save right after deleting the dialog's test file is refused** (`probe-delete-before-seal` CPF variant: `save-create=32`). Each allocation reserves the user's whole remaining allowance, so the new save must wait for the deleted test file's refund; the agent's receive loop handles `StageAllocate` inline, so during the 1.5 s refund grace it does not read the discard message that would provide that refund. Evidence: allocation refused at 16:44:49.296 after 1,546 ms (service event), discard recorded at 16:44:49.297. Whether it occurs depends on message order (case 1 passed this time). This also explains `m2t5ord4` and `m2t5ord6`'s `open=32`. The approved T9 growing-reservation design removes the whole-allowance wait; T4 met the same class and ran budget-off isolation rows.
- **Product (kernel, minor): metadata-only opens refused with a sharing violation** while a new version's allocation receipt is pending (deny ring 109–110: read-attributes / read-control opens, reason 17 gate 3), as well as during a directory mutation (gate 1, `m2t5ord6`). Native NTFS never applies share modes to metadata-only opens. Transient; the observer retries it; noted for T6/T8.

### `m2t5ord6` triage (first T5 row with the raw observer to run all cases; no T5 row has passed `T5RawObserver` since the observer was added)

Harness defects, fixed together in the next commit (observer behaviours are opt-in for T5; Phase 4 is unchanged):

1. **Stale raw metadata (46 of the 60 failed samples; 65 taken).** "Wrong record number/sequence or not in use", "Raw/FSCTL identity mismatch" (raw sequence 9 vs cached 14) and "Raw parent index does not identify the requested name": NTFS writes MFT records and directory indexes lazily, as Phase 4 found in `b17r1` (its `Flush-InvariantFinalVolume`). Fix: with an opt-in flush scriptblock on the context, a sample flushes the volume and captures again within the same module sample (every attempt kept).
2. **`$observerReaderSummaries = @{}`** (a hashtable) took `+=` of objects: "A hash table can only be added to another hash table" on every sample with a present leaf (6 samples). Fix: `@()`.
3. **Delete-pending names.** The probe gates sample while the actor holds a handle with delete set; the observer's target `Test-Path` then fails "Access is denied" (8 samples) (the filter returns STATUS_DELETE_PENDING, which Win32 reports as 5). Fix (opt-in): the name is recorded absent with `NamedLookup=DELETE_PENDING` only when the lookup's NTSTATUS is exactly 0xC0000056 **and** the raw parent index has no entry; the buffered reader must then also report DELETE_PENDING. An indexed (native) delete-pending name still fails.
4. **Pre-case journal errors were thrown without being recorded** (3 cases). The end-of-row journal replays clean offline, so they were transient; they are now recorded in the case (no retry, so they cannot be hidden).

Findings:

- **On-close expectation (harness/design text).** `probe-onclose`/`probe-doc` expected Win32 303 for opens refused as delete-pending; the row observed 5. The 2026-10-11 native control shows Windows reports STATUS_DELETE_PENDING as Win32 5, and no earlier row ever recorded these steps, so 303 was never observed. The actor now records the NTSTATUS and the assertion is the exact STATUS_DELETE_PENDING plus Win32 5 (stricter than a Win32 code alone); `T5-DELETES.md` text corrected.
- **`open=32` on a fresh create (`delete-remove.txt`).** The agent refused that `StageAllocate` after 1,528 ms with no transfer (service event 33400), the `m2t5ord4` signature. The previous case had aborted on harness defect 1 without waiting for its version to settle, so this is consistent with the known T9 same-user overlapping-save refusal; to be confirmed on the next row.
- **Filter refused the observer's read-attributes open of the protected folder** (deny ring seq 138: STATUS_SHARING_VIOLATION, reason 17 `STAGE_CREATE_CONFLICT`, gate 1 = directory mutation active) 57 µs before the actor's move into protection returned the expected NOT_SAME_DEVICE. Any open routed to stage creation is refused while a directory mutation is active, including an attributes-only open of the folder itself. Transient; noted for T6 (the observer now retries it like defect 1).

## D7: native DeleteFileW / MoveFileExW source opens (owner 2026-10-21)

Design delta D7 in `T5-UX-NAMESPACE-GAP.md`: Sol 6.1 high reviews [rev 0 REVISE](t5-d7-review-sol61.md),
[rev 1 REVISE](t5-d7-rereview-sol61.md), [rev 2 REVISE](t5-d7-rereview2-sol61.md), [rev 3 ACCEPT (design)](t5-d7-rereview3-sol61.md).
Implementation (`StageStream.c` + host controls in `namespace_ux_fixture.c`): [review of eb42b0fb REVISE](t5-d7-impl-review-sol61.md),
[e41913c4 REVISE](t5-d7-impl-rereview-sol61.md), [9eb46e87 ACCEPT](t5-d7-impl-rereview2-sol61.md). Host controls pass on cc and clang; 32/32
negative mutations killed by the intended assertions ([receipts](t5-d7-host-mutants.json)). Two host modules still fail on this host's
clang 23 (`-Wunused-but-set-global` in the untouched registry and context-retirement fixtures): failing checks, unrelated to D7.

| Build | Source | Result |
|---|---|---|
| `m2t5d7k1` | `eb42b0fb` | **FAIL**: PREfast C6388 (legacy completion context not NULL before `SafeUploadPreCreate`); fixed `35d2df1d`. [Summary](exact-m2t5d7k1-summary.txt) |
| `m2t5d7k2` | `35d2df1d` | Both profiles 0/0, PREfast, ApiValidator, imports PASS; **signing FAIL** (script default signer `220DD…` absent; the current test signer is `A6D6…`, LocalMachine). [Summary](exact-m2t5d7k2-summary.txt) |
| `m2t5d7k3` | `e41913c4` | **PASS**: both profiles 0/0, PREfast, ApiValidator, imports 248/247, A6D6 signature valid (`1D2F56FC…`). Superseded by `9eb46e87`. [Summary](exact-m2t5d7k3-summary.txt) |
| `m2t5d7k4` | `9eb46e87` (implementation accepted) | **PASS**: both profiles 0/0, PREfast, ApiValidator, imports 248/247, A6D6 signature valid; signed driver `26075F68…` (kept locally in `m2t5d7k4-candidate/`). [Summary](exact-m2t5d7k4-summary.txt). This is the driver for the T5 rows. |
| `m2t5d7k5` | `b3c87c70` (D7 rev 5: writer-registry reservation; review pending) | **PASS**: both profiles 0/0, PREfast, ApiValidator, imports 248/247, A6D6 signature valid; signed driver `AC998FD6…` (kept locally in `../2026-10-22/m2t5d7k5-candidate/`). [Summary](../2026-10-22/exact-m2t5d7k5-summary.txt). Build gates only; no Windows result. |
| `m2t5d7k6` | `3a16ec0f` (D7 rev 5 with the registry post last; second review pending) | **PASS**: both profiles 0/0, PREfast, ApiValidator, imports 248/247, A6D6 signature valid; signed driver `29D6130E…` (kept locally in `../2026-10-22/m2t5d7k6-candidate/`). [Summary](../2026-10-22/exact-m2t5d7k6-summary.txt). Supersedes `m2t5d7k5` (registry post before the legacy post; review REVISE). Build gates only; no Windows result. |

## Next

- [x] Seed-export guard (`dc16ae12`, `d157ba3f`) and the row harness (`53ddf152`) landed; the merged tree passes the four-leg agent matrix (`m2t5a4`).
- [ ] Ordinary, runtime-Verifier and boot-Verifier T5 rows on that agent; restoration after each.
