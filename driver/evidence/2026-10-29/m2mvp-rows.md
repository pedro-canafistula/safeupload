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
