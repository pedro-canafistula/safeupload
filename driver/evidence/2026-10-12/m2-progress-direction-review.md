# M2 progress and direction review — 2026-10-12

Reviewed committed source `da20d23e` and the in-progress `Stage.h`, `StageProtocol.c` and
`T5-NATIVE-PUBLIC-OPENS.md` changes. Codex checked the source, raw run verdict/restoration,
build summary and current TRX results; Luna 6 at max effort independently audited direction
and status. This is a progress review, not the final M2 adversarial qualification.

**Verdict:** the architecture and milestone scope follow the owner's decisions. Delivery needs
more focus: tested components have accumulated without a revised protected T5 pair. Static
and component passes are real progress, but do not prove Save As, public deletes or recovery.
No materially false completed product claim was found in the current status plan.

## T4 — failed stress gate

- [x] All 10,000 cycles were attempted; Verifier remained active, pool slope was 1.501 B/cycle,
  the cap-refusal counter stayed zero and the worker became idle.
- [ ] The product gate failed: 8,740 passed, 1,260 failed, three versions/views remained at settle
  and four private stage files remained. Two blocked saves lacked hand-back.
  - [x] [Raw verdict](../2026-10-11/m2t4boot10k1011a2-verdict.txt) and
    [separate restoration](../2026-10-11/m2t4boot10k1011a2-independent-restoration.txt) retained;
    run disk deleted, base untouched and XML unchanged. Both start records show EFI reset.
  - [ ] Owner direction remains pending before product fixes/retry after repeated identical failures.

The [read-only diagnosis](../2026-10-11/t4-journal-failure-diagnosis.md) identifies four failed
private-journal replacements and the resulting reservation/hand-back failures. The underlying
native error 5 is unproven. Do not loosen permissions or sharing on that assumption.
The cycle row's sampled no-blocked-publication check does not replace raw-volume regression rows.

## T5 — substantial service progress, no live qualification

- [x] Service V23 allocation, anchored seeding, durable manifest/head claims, replay and receipt
  validation have [passing component gates](t5-bound-service-allocation-gates.md) at `be78b958`.
  Root independently recounted all four user TRX files: 863/863 per normal profile, 1112/1112
  per feature profile, zero failed/skipped results and unique execution IDs.
- [x] Four WDK profiles at `827b3f41` passed PREfast/ApiValidator with 0 warnings / 0 errors
  ([readout](t5-bound-allocation-static-gates.md)). These passes do not cover the dirty protocol changes.
- [ ] Live integration is incomplete. `MinifilterBoundAllocation.cs:14,45` keeps admission false;
  `StagedTransferPublisher.cs:81–82` refuses bound publication. `StageStream.c:2259` still calls
  the old allocator; the new V23 sender has no caller. No revised pair has booted.
- [ ] Correct kernel CREATE permission capture before implementation. Luna's design verdict is
  **REVISE**, covering disposition-specific implicit rights and collision results, case-aware
  identity anchors, native sharing during seed reads, full descriptor/mandatory-label handling,
  post-allocation authorization recheck and live writer identity on replay.
  - [ ] `StagedDestinationDirectory.cs:68` uses a read open with share mask 1. Establish how seeding
    preserves the original CREATE's native sharing behavior; merely closing the probe is insufficient.
  - [ ] `MinifilterBoundAllocation.cs:67–78` reuses saved writer ownership without a live identity
    check. Keep filesystem authority in the captured effective kernel subject, separate from
    service-side primary-token ownership used for hand-back.

These are pre-admission blockers; this review establishes no leak through the disabled new path.
The permission review made no new owner decision. If implementing native semantics forces a new
denial, grant or failure behavior, ask the owner with the user-visible effects before proceeding.

## T6–T11 — M2 still has work beyond T5

- [x] T6 and T7 have component/runtime evidence on earlier pairs; T10 has a source change.
- [ ] Final-pair reruns, T6 directory moves, T8 real applications/metadata, T9 complete bounded
  inspection/space/failure handling, T10's failed phase and T11 review conditions remain open.
  Earlier-pair passes cannot qualify the changed M2 pair.

## T12/T14, T21–T23, T15–T19 — scope remains correct

- [x] The plan retains M3, then USB/removable, SMB/UNC and cloud sync, then combined M4 qualification.
  T21 records automatic remount reconciliation; the fixed-NTFS Restart exception does not extend to USB.
- [ ] Both mapping repros, new destinations, combined stress/crash/recovery/latency and cutover remain unqualified.
  Taint stays; normal builds compile staging out and unsupported capabilities stay disabled.

## T5 — delivery correction

- [ ] Close the current permission-design revision and complete one connected kernel/service path:
  CREATE capture/allocation, head-bound publication/delete permits, native close/startup reconciliation,
  cleanup acknowledgement and teardown. Keep admission disabled throughout incomplete integration.
  - [ ] Gate the exact resulting committed source, perform the single integrated pre-boot lifetime/
    lock-order/retirement review, then run both forced-delete orders and real Notepad clean/CPF
    in all required modes, with independent byte observation and separate restoration.

Group implementation around that runtime checkpoint. Do not create another component milestone or
per-patch review unless integration exposes a new product-security design decision. Harness fixes
continue to need PS5.1 parsing, self-checks and real execution, not review manifests/dispositions.

At review time `feat/driver-m2` matched its remote. The only running VM was the `win10` builder;
`win10-debug3` and the shared-IP `win10-debug2` were off. This review made no VM or host-wide
configuration changes and launched no product retry.
