# M2 MVP task rows, 2026-10-29

Target win10-debug3 only; serial chain `~/Work/safeupload-tools/session-scratch/mvp-rows.sh`.

## Attempt 1 — mvpACDord1 (ordinary), FAILED (preserved)

- Pair: kernel `cb2407eb` (m2mvpk1029d, `SafeUpload-stage-prototype.sys` SHA-256 `FDA22EE7…E769673`), agent `2fc93f61` (m2mvpa1029d, `stage-service-publish.zip` `EB16E54B…5E06B37`). Pair hashes, mode readback and restoration PASS.
- Result: coordinator still running at the 1800 s bound, 0 of 25 cases recorded, 23 stage files and 25 hot journal entries left, all published (state 5) but never disposed.
- Cause: `SAFEUPLOAD_CONTROL_STAGE_STREAMS` (T8 increment 0, `366952de`, 2026-10-22 19:00) reused command 29 = `SAFEUPLOAD_CONTROL_STAGE_DISPOSE`. The diagnostics branch runs first, so every disposal was refused with `STATUS_INVALID_BUFFER_SIZE` (`0x800706F8`, ~12k warnings; driver `disposeHeld/NotHeld/Stale/Deferred` all 0, `stageDeletes` 0). Each case then waited out its 90 s settlement bound. The last passing rows (ord19/rtv19/bov19) predate the collision.
- Fix: `c3f3f5d1` moves STAGE_STREAMS to 37 in driver and agent, with a C_ASSERT and an agent test that rejects a shared command number.
- Raw: `mvpACDord1-verdict.txt`, `-mvp-verdict.txt`, `-after.txt`, `-service-events.txt`, `-agent-journal/` (local, ignored).
