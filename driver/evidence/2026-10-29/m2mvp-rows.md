# M2 MVP task rows, 2026-10-29

Target win10-debug3 only; serial chain `~/Work/safeupload-tools/session-scratch/mvp-rows.sh`.

## Attempt 1 — mvpACDord1 (ordinary), FAILED (preserved)

- Pair: kernel `cb2407eb` (m2mvpk1029d, `SafeUpload-stage-prototype.sys` SHA-256 `FDA22EE7…E769673`), agent `2fc93f61` (m2mvpa1029d, `stage-service-publish.zip` `EB16E54B…5E06B37`). Pair hashes, mode readback and restoration PASS.
- Result: coordinator still running at the 1800 s bound, 0 of 25 cases recorded, 23 stage files and 25 hot journal entries left, all published (state 5) but never disposed.
- Cause: `SAFEUPLOAD_CONTROL_STAGE_STREAMS` (T8 increment 0, `366952de`, 2026-10-22 19:00) reused command 29 = `SAFEUPLOAD_CONTROL_STAGE_DISPOSE`. The diagnostics branch runs first, so every disposal was refused with `STATUS_INVALID_BUFFER_SIZE` (`0x800706F8`, ~12k warnings; driver `disposeHeld/NotHeld/Stale/Deferred` all 0, `stageDeletes` 0). Each case then waited out its 90 s settlement bound. The last passing rows (ord19/rtv19/bov19) predate the collision.
- Fix: `c3f3f5d1` moves STAGE_STREAMS to 37 in driver and agent, with a C_ASSERT and an agent test that rejects a shared command number.
- Raw: `mvpACDord1-verdict.txt`, `-mvp-verdict.txt`, `-after.txt`, `-service-events.txt`, `-agent-journal/` (local, ignored).

## Diagnostic mvpACDdiag2 (ordinary; kernel `c3f3f5d1` m2mvpk1029e `9924EFA5…`, previous agent package m2mvpa1029d) — not a final-pair row

- With disposal fixed: 25/25 cases completed, staging and hot journal empty, restoration PASS. MVP C and D PASS.
- MVP A failed only on NotepadEditApprove: the actor required the window title to start with `notepad-edit.txt`, but Notepad shows the shell display name (`notepad-edit - Notepad`). Harness fix `93cdebe1`.
- Carried full-row regressions (not MVP task outcomes; both passed in ord19/rtv19 on 2026-10-22): `T5ProbeDeleteAfterPublicationCpf` (`test-delete=32`, sharing violation on deleting the published empty probe before the CPF write) and `T5DeleteNewerPublished`/`ForcedOrder`. Cause not yet isolated among the kernel changes since 2026-10-22.

## Final pair candidate: kernel `c3f3f5d1` (m2mvpk1029e, `.sys` `9924EFA5…D66E8CA`… see summary) + agent `93cdebe1` (m2mvpa1029f, zip `9658168C…C7465E`)

- mvpACDord2 (ordinary): 25/25 cases, staging/journal empty, restoration PASS; MVP C and D PASS; the earlier non-MVP delete regressions passed this time (flaky, still carried). MVP A failed only on the host-side NotepadEditApprove title check (same display-name assumption as the actor; every other line of that case PASS). Verdict fix `1b4033c7`; rows rerun as mvpACDord3/mvpACDrv3.
- Office diagnostics (previous agent package): mvpBWdiag2 refused at preflight (glob matched the lifecycle lock and parked demo1; fixed `87d0b377`); mvpBWdiag3 stopped at the actor-profile check and reported a false T5OfficeBase FAIL from a ctime-only change (fixed `7ad2b444`; domain XML/vda restored exactly); mvpBWdiag4 reached Excel: Save As failed with "The rename destination is busy" and the temp versions stayed Retained. Regression since the 10-22 T8 sweep (Excel passed there). Diagnostic package `output/diag/m2mvpdiag1` (refusal names the blocking claim, `47a29cee`) for mvpBWdiag5.
- **mvpACDord3 (ordinary, final pair): MVP A, C and D PASS**; no FAIL line in the full row (exit 1 only from the historical INCONCLUSIVE proof lines, which are not MVP task outcomes).
- mvpACDrv3 (runtime Verifier) not started: the chain gated on the full-row exit code. mvpBWdiag5 (Office diagnostic) was stopped by the host's low-memory reaper during its wait, before evidence collection; its run disk was then torn down manually (`mvpBWdiag5-manual-restore.txt`: overlay deleted, base untouched, original vda and XML restored, both base size/mtime unchanged).
- **mvpACDrv3 (runtime Verifier, final pair): MVP A, C and D PASS**; no FAIL line (exit 1 only from the historical INCONCLUSIVE proof lines). With mvpACDord3, tasks A/C/D meet the owner's ordinary + runtime-Verifier bar on the final pair.
- mvpBWdiag6 (Office diagnostic, package m2mvpdiag1): restoration and T5OfficeBase PASS; Excel Save As still fails. The refusal now names the cause: `The rename destination is busy: <excel-saveas.xlsx version> Allocated at excel-saveas.xlsx renaming to F224D9D2.tmp (source <E6210000 version> Allocated at E6210000)`. Excel's swap renames the current workbook away to a `.tmp` backup and then the new temp onto the workbook name; the journal still counts the outgoing pending rename as reserving `excel-saveas.xlsx`, so the incoming rename is refused and both temps stay Retained. Fix direction (not started, paused by owner): an outgoing pending rename must not reserve its old name once the kernel has committed it, or the incoming rename waits (bounded) for that commit.

## Excel and Word (Office base) — diagnostic runs mvpBWdiag7–15, kernel `8d6e8737` (m2mvpk1029f, `.sys` `32344A39…E67B4`), diagnostic agent m2mvpdiag1

- Kernel `8d6e8737` sends a rename's commit RPC before the user's rename returns; all three Excel cases (Save As, in-place, CPF hand-back) then PASS in every run from mvpBWdiag8 on.
- Harness fixes found by these runs (all committed, PS 5.1 gate PASS m2mvph1029m): Word `Quit` by-reference args, Excel numeric cells, hand-back read-only rule, journal read race (`131843a5`); alert monitor sharing violations (`f0d49d75`), no UI search once Word has exited and a failing final write falls back to in-place (`c2eef887`, `22ba54a2`); Office's published `~$` owner lock file is an expected directory companion in the coordinator and the verdict.
- Word Save As, in-place save and CPF hand-back PASS together in mvpBWdiag13 (verdict re-run offline on that evidence). Not stable: in mvpBWdiag15 Save As ended with one Word version Retained (`~WRD0000.tmp` renamed to `word-saveas.docx`, commit receipt present, never re-inspected) while a second version published, leaving one stage file and one journal entry after the run.
- **Word overwrite (Save As over an existing published name) fails deterministically** (mvpBWdiag11–15): `0x800A156F file permission error`. Driver ring: Word's opens of `word-overwrite.docx` return `STATUS_DELETE_PENDING` (native-delete tombstone for Word's process, `StageNativeRecords.c`), then the rename of `~WRD0000.tmp` onto the name returns `STATUS_OBJECT_NAME_COLLISION`. An independent open loop (mvpBWdiag15) shows the physical file stays openable (13385 bytes) for the whole attempt, so the old file is not physically delete-pending; the tombstone is process-local. Needs a design decision for a rename into a name the same process just deleted.
- Because B and W share one Office run, MVP B stays FAIL in any run that includes the Word overwrite case and its leftovers (run-level raw observer and staging/journal-empty dependencies).

## FINAL PAIR (drop 1): kernel `8d6e8737` (m2mvpk1029f, `SafeUpload-stage-prototype.sys` `32344A39…E67B4`) + agent `8d6e8737` (m2mvpa1029g, `stage-service-publish.zip` `21028FA8…F100D`)

- Gates on this commit: kernel exact-source gate m2mvpk1029f PASS; agent matrix m2mvpa1029g PASS (feature-debug and feature-release 5895/5895 each, user + SYSTEM legs); PS 5.1 harness gate m2mvph1029m PASS (current harness commit).
- **mvpACDordF1 (ordinary): MVP A, C and D PASS** (25/25 cases, staging and hot journal empty, restoration PASS). Only FAIL lines are the carried non-MVP `T5DeleteNewerPublished*` probe cases (flaky; passed in other runs on the same pair family).
- **mvpACDrvF1 (runtime Verifier, flags 0x13B): MVP A, C and D PASS** (25/25, staging and journal empty, restoration PASS, no FAIL line).
- Raw: `mvpACDordF1-*`, `mvpACDrvF1-*` (local, ignored); logs `~/Work/safeupload-tools/session-scratch/mvp-rows-final.log`.
