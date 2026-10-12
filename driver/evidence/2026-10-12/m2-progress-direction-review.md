# M2 progress and direction review — 2026-10-12

Latest review covers committed source `c546a71b` and eight uncommitted code/design files
(381 insertions, nine deletions). Codex checked source, plan, raw run verdict/restoration,
WDK summary and TRX execution files; Luna 6 at max effort independently audited direction
and status. This is the owner's progress review, not the final M2 adversarial qualification
or the integrated pre-boot lifetime review.

**Verdict:** the architecture and milestone scope follow the owner's decisions. Delivery needs
more focus: the preceding review identified delivery fragmentation, and no revised protected
T5 pair has run since. Static/component passes are real progress, but do not prove Save As,
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

## T5 — substantial service progress, no live qualification

- [x] Latest matching driver/agent [gates](t5-bound-service-allocation-gates.md) cover **`dbe02d04`**:
  four WDK profiles at **0 warnings / 0 errors**, PREfast and ApiValidator
  ([raw summary](exact-t5-rpc-integration1-summary.txt)), and **863/863 normal**, **1113/1113 feature**.
  Root independently verified each aggregate TRX is the disjoint user + SYSTEM execution union:
  838 + 25 normal, 1088 + 25 feature; all Passed, unique IDs, no skipped cases.
- [x] Since the preceding review, `dbe02d04` adds the retained V23 request, concurrent-RPC
  authority fence and live allocation-replay ownership check. These are source changes.
- [ ] Live integration is incomplete. `MinifilterBoundAllocation.cs:12–15,45–50` keeps admission false;
  `StagedTransferPublisher.cs:81–83` refuses bound publication. `StageStream.c:2259` still calls
  the old allocator; the V23 sender and native-name capture have no production callers.
  No revised pair has booted. The eight dirty files are outside the passing gates.
- [ ] Correct kernel CREATE permission capture before implementation. Luna's design verdict is
  **REVISE**, covering disposition-specific implicit rights and collision results, case-aware
  identity anchors, native sharing during seed reads, full descriptor/mandatory-label handling,
  post-allocation authorization recheck and live writer identity on replay.
  - [ ] `StagedDestinationDirectory.cs:68` uses a read open with share mask 1. Establish how seeding
    preserves the original CREATE's native sharing behavior; merely closing the probe is insufficient.
  - [x] Allocation replay now checks live PID/session/SID/creation before and after replay
    (`dbe02d04`). Ownership is separate from the effective subject's filesystem authority.
  - [ ] The [unreadable-seeded-bytes hand-back choice](../../T5-NATIVE-PUBLIC-OPENS.md#owner-choice-pending--unreadable-seeded-bytes)
    awaits owner decision. Full-file hand-back must not disclose old bytes without read authority.
  - [ ] Native scheduled-CREATE transport is independently ready for implementation, not boot
    qualification. Startup must compare full CREATE-outcome/identity/generation facts;
    `StagedNativeStartupRecovery.cs:120` currently projects only part of that evidence.

These are pre-admission blockers; this review establishes no leak through the disabled new path.
The current transport review requires no new owner decision; the separate seeded-content
hand-back decision remains pending. Ask before a new denial, grant or failure behavior.
The kernel EmptyHeld/successor chain is removed, but reserved values, guarded migration and
some legacy service cleanup APIs/tests remain intentionally. Operation 10 is denied
(`MinifilterInterceptor.cs:357–359`); finish classified removal without deleting safeguards blindly.

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

- [ ] Complete one connected fixed-NTFS public-delete path: original subject/anchored identity,
  durable destination intent before forwarding unchanged native CREATE, exact close/startup
  reconciliation, and terminal receipt retention until confirmed kernel-record removal.
  Connect ordinary disposition/allocation and every physical publication/delete/recovery path
  to the shared head; keep admission disabled throughout incomplete integration.
  - [ ] Gate the exact resulting committed source, perform the single integrated pre-boot lifetime/
    lock-order/retirement review, then run both forced-delete orders and real Notepad clean/CPF
    in all required modes, with independent byte observation and separate restoration.

Group implementation around that runtime checkpoint. Do not create another component milestone or
per-patch review unless integration exposes a new product-security design decision. Harness fixes
continue to need PS5.1 parsing, self-checks and real execution, not review manifests/dispositions.

At latest audit start, committed `feat/driver-m2` matched its tracked remote through `c546a71b`.
This review changes no product code, test assertions, VM baseline or host-wide configuration
and launches no product retry. The in-progress files remain outside the static gate.
