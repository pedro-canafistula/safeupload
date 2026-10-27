# Independent review: T9 maintained reservation totals

2026-10-27. Reviewer: `gpt-6.1-sol`, reasoning effort **high**, no fast tier,
fresh read-only agent `/root/t9_totals_review`. Reviewed the scoped agent working
diff against `e555f186`; no edits, builds, remote contact or VM actions.

**ACCEPT WITH CONDITIONS. No blocking correctness finding.**

- Every reservation mutation routes through `AdoptReservation` or
  `RemoveReservation`, including constructor reconstruction, legacy import,
  snapshot changes, binding, content release and exact metadata retirement.
- Charges remain identical to the former scan: four capacity copies unless
  `ContentReleased`, plus metadata. SID comparison remains ordinal; replay adds
  no debit and retirement refunds the recorded user once.
- Persistence precedes adoption; exact durable deletion precedes removal.
  Checked arithmetic and faulted admission protect failed in-memory adoption.
  Aggregate startup overflow now refuses earlier, still failing closed.
- The regression covers global exhaustion, per-user isolation, replay,
  retirement, refill and restart.

Delivery conditions: complete local compile, relevant controls and the complete
feature Debug/Release × user/SYSTEM matrix, including allocation recovery,
large defaults/integration, snapshots and allocation-resolution persistence
faults. Preserve activation/qualification gates. This is **maintained reservation
totals only**: completed-save shared accounting, growing reservations and
history-sized metadata callback scans remain open.

The reviewer recommended explicit aggregate-overflow startup and retained-metadata
boundary controls. Root added both without changing the reviewed production diff;
the resulting focused diagnostic passes 36/36 with no skips. Local feature
Debug/Release service/app/tests compile passes; all 14 T5 offline controls and
required-test preflight pass. Windows matrix remains a separate result.
