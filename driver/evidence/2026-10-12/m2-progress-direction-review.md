# M2 progress and direction review — 2026-10-12

Latest review covers committed source `fa687b61495f47c0bb9485ccf6547552a197254a`.
Codex checked source, plan, raw run verdict/restoration,
WDK summary and TRX execution files; Luna 6 at max effort independently audited direction
and status. This is the owner's progress review, not the final M2 adversarial qualification
or the integrated pre-boot lifetime review.

**Verdict:** the architecture and milestone scope follow the owner's decisions. Delivery needs
more focus: native CREATE/close is now a connected, statically tested lifecycle, resolving the
preceding review's no-production-caller finding. No revised protected T5 pair has run.
Static/component passes are real progress, but do not prove Save As,
public deletes or recovery. No materially false completed product claim was found.
M2 remains unfinished; the MVP is not ready.

## T4 — failed stress gate

- [x] All 10,000 cycles were attempted; Verifier remained active, pool slope was 1.501 B/cycle,
  the cap-refusal counter stayed zero and the worker became idle.
- [ ] The product gate failed: 8,740 passed, 1,260 failed, three versions/views remained at settle
  and four private stage files remained. Two blocked saves lacked hand-back.
  - [x] [Raw verdict](../2026-10-11/m2t4boot10k1011a2-verdict.txt) and
    [separate restoration](../2026-10-11/m2t4boot10k1011a2-independent-restoration.txt) retained;
    run disk deleted, base untouched and XML unchanged. Test and restoration start records
    each contain `RunDiskEfiReset=True`.
  - [ ] Owner direction remains pending before product fixes/retry after repeated identical failures.

The [read-only diagnosis](../2026-10-11/t4-journal-failure-diagnosis.md) identifies four failed
private-journal replacements and the resulting reservation/hand-back failures. The underlying
native error 5 is unproven. Do not loosen permissions or sharing on that assumption.
The cycle row's sampled no-blocked-publication check does not replace raw-volume regression rows.

## T5 — connected lifecycle progress, no protected qualification

- [x] Latest agent [gates](t5-bound-service-allocation-gates.md) cover **`fa687b61`**:
  **866/866 normal**, **1140/1140 feature**, in both Debug and Release. Root independently verified
  aggregate TRX equals the disjoint user + SYSTEM union: 841 + 25 normal, 1115 + 25 feature;
  all Passed, unique IDs, no skips. Every build/package leg is 0/0.
  - [x] Four WDK profiles at **0 warnings / 0 errors**, PREfast and ApiValidator, on `da66fef4`.
    Its kernel subtree is identical at `fa687b61`; raw summaries are linked in the gate record.
- [x] Native-name capture now has its producer in `StageStream.c:3528–3536`; the receive loop
  dispatches V24 (`MinifilterInterceptor.cs:303–310`). Prepare persists before forward; lifecycle
  facts feed exact-name/last-close reconciliation and retained terminal receipts
  (`StagedNativeLifecycleDispatcher.cs:38–140,154–179`). All 22 lifecycle controls pass per feature profile.
- [x] Ordinary and native delete allocation include retained bound-manifest high-water under the
  turn/journal gate (`StagedDestinationCommitJournal.cs:312–320`); both orders pass within 14 allocation controls.
- [ ] No protected FilterPort/Verifier run qualifies the revised pair. `_stageBoundHeadReady` remains
  false (`MinifilterBoundAllocation.cs:14,23–30,45–50`); native capability is unadvertised. The publisher
  refuses bound entries (`StagedTransferPublisher.cs:81–83`). Journal reopening is not service-restart qualification.
- [ ] Ordinary public disposition remains unimplemented: `StageSetDisposition` still handles private
  streams (`StageStream.c:4120–4175,4594–4599`). The separately checked backend factory remains unconnected.
  - [ ] Luna's bounded relay verdict is **REVISE**: require exact link/open and binding-time Published
    identity; one forward/no replay; strict successful typed permit; native FALSE no-op; preserve the
    combined DELETE+write backend and original caller context. Corrections are recorded in
    [the design](../../T5-NATIVE-PUBLIC-OPENS.md#ordinary-public-disposition-integration--proposal-for-review-2026-10-12).
    These preserve approved behavior and do not themselves force a new owner choice.
- [ ] Bound-writer permission/sharing/security-label capture, all physical publication/delete through
  the shared head, startup activation and resolving directory events remain open. Startup currently
  refuses unresolved heads (`StagedNativeStartupRecovery.cs:83–107`); diagnostics cannot release a hold.
  - [ ] The [unreadable-seeded-bytes hand-back choice](../../T5-NATIVE-PUBLIC-OPENS.md#owner-choice-pending--unreadable-seeded-bytes)
    awaits owner decision. Full-file hand-back must not disclose old bytes without read authority.

No new security leak or unsafe product-completion claim surfaced. The disabled path does not establish
live safety. The kernel EmptyHeld/successor chain is removed; reserved values, guarded migration and
legacy cleanup protections remain intentionally. Finish classified removal without deleting safeguards blindly.

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

- [ ] Close the finite ordinary-relay design corrections once, then connect ordinary disposition,
  bound-writer allocation, every physical commit and automatic close/startup recovery to the same head.
  Keep admission disabled throughout incomplete integration; do not extend an unused exported
  service-handle path in parallel or add routine component reviews.
  - [ ] Gate the exact resulting committed source, perform the single integrated pre-boot lifetime/
    lock-order/retirement review, then run both forced-delete orders and real Notepad clean/CPF
    in all required modes, with independent byte observation and separate restoration.

Group implementation around that runtime checkpoint. Do not create another component milestone or
per-patch review unless integration exposes a new product-security design decision. Harness fixes
continue to need PS5.1 parsing, self-checks and real execution, not review manifests/dispositions.

At latest audit start, committed `feat/driver-m2` matched its tracked remote through `fa687b61`.
The status plan remains close to the requested M1 size. This review updates status/design documentation,
changes no product code, test assertions, VM baseline or host-wide configuration and launches no product retry.
