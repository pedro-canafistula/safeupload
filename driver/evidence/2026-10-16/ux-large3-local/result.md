# T9 product-default and upgrade follow-up

2026-10-16. Branch `ux/large`, base `a2b67984ade69152716aef4d0edec1f2e4bcfeb6`.
Owner's current instruction accepts the previously proposed storage defaults and requests default enablement and upgrade compatibility.
Source delivery is `.scratch/ux-large3.bundle`, ref/head `ux/large`; the scratch delivery receipt records its commit and SHA-256.
Original repository Git refs/index and `.ai-memory.toml` are preserved. No builder or VM was contacted.

## Changes

- `StageSpace.Enabled` defaults true in code and settings. Runtime staging-volume defaults are total min(32 GiB, available/10),
  per SID min(8 GiB, total/4), floor max(1 GiB, volume/20). Explicit values override independently; an overridden total determines
  the default SID quarter. New versions retain the existing accounted grants without a fixed per-file staging cap.
- Parser memory defaults 256 MiB. Newly generated policies and omitted inspection fields use 4096 MiB/900 s. The existing
  [nine-input measurements](../ux-large-local/measurements.json) peaked around 54–74 MiB; 2 GiB DOCX took 246 s, text 97 s, ZIP 154 s.
  The 15-minute default adds work/queue margin. Explicit local/remote policy values, including persisted 20 MiB/5 s, remain authoritative;
  upgrade does not silently rewrite an administrator's policy. Timeouts/incomplete extraction still block staged publication.
- Pending legacy versions are durably charged as `LegacyGuard` under their existing 16 MiB guard, retaining recorded SID/exact identity.
  Missing SID is global unattributed debt; missing identity grants no cleanup/refund authority. Legacy records issue no companion,
  cannot acquire new capacity and cannot use the no-manifest retirement shortcut. Existing exact cleanup/snapshot rules control refunds.
- Trusted completed hot/packed receipts remain compatible and unchanged. Metadata is covered by a shared, charged recovery envelope;
  historical negative receipts and immutable security snapshots are validated/accounted without becoming transfer/grant authority.
  Valid existing debt above a smaller/zero budget permits recovery while new admission refuses with the staging-space alert.
- Missing modern ledgers/companions, oversized claimed legacy content, unknown objects and corrupt/partial evidence remain holds.
  Failed initialization clears all partial subsystem fields, so reconnect cannot bypass accounting with a pre-budget allocator.
  Disabled-mode and older-binary downgrade restrictions remain as documented.

## Verification and limits

Feature Debug and Release builds pass with **0 warnings / 0 errors**. **321/321 focused diagnostic rows pass**, including
18 default/upgrade rows, policy overrides/defaults, budget/restart/isolation, hot/packed archive controls and streaming/failure regressions.
Exact raw receipt/artifact hashes and the retained first failures are in [verification.json](verification.json).
These are Linux feature builds and in-process diagnostics, **not** the required Windows user/SYSTEM matrix or protected-pair qualification.
No kernel source changed from the base; no WDK/PREfast/ApiValidator/new binary import or Verifier result is claimed.
The unchanged production grant predicate still passes cc/clang strict-warning/UBSan controls; feature defaults (2), exact matrix runner (21),
manifest retry (3) and reconcile retry (15) offline self-checks pass.

All failed attempts remain under `.scratch/ux-large3`. The first new-test build found an ambiguous enum import, corrected in test code.
The first broad diagnostic retained five invalid-history fixture failures (fixed with valid transition histories) and three existing Windows-path
assumptions run on Linux. Product assertions were not removed/weakened: the final diagnostic selects portable controls explicitly, including the
updated exact default-policy test; all three Windows-path tests remain in the required Windows matrix. The only existing test assertion edits are
20->4096 MiB and 5->900 s in the default-policy contract, matching the authorized behavior change.

[Independent design REVISE](design-review-sol61.md) identified unsafe modern-grant reclassification and legacy negative-receipt startup limits.
Both are closed in the [implementation ACCEPT WITH CONDITIONS](implementation-review-sol61.md), including auxiliary security accounting and
failed-initialization retry review. Acceptance is source review, separate from component gates and native qualification.

See [current design](../../../docs/design/large-files/UX-LARGE.md) and [Windows handoff](../../../docs/design/large-files/UX-LARGE-VM.md) for defaults, migration, cold/hot history,
legacy writer guard, low-space, per-SID isolation, failure/reconnect, explicit overrides and three-mode byte-observation cases.
Windows actors remain standard user `t5actor`. Full-SID leases/concurrent-save refusals, synchronous seeding cost, retained metadata,
unsupported older-binary downgrade and final T9/pair qualification remain open. Runtime readiness and v31 capability gates remain in force.
