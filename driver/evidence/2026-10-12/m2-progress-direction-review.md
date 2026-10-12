# M2 progress and direction review — 2026-10-12

Owner-requested refresh covers committed source **`ffd47a97c8ee8cc866800e0fad72d3e677175ce3`** and the unfinished working-tree
ordinary-disposition relay. Codex checked source, plan, raw build summaries, aggregate/user/SYSTEM TRX, the T4 verdict and separate
restoration. Luna 6 at max effort independently reviewed security and delivery direction. This is a progress review, not the final
M2 adversarial gate or the integrated pre-boot lifetime review.

**Verdict:** architecture, destination scope and owner constraints remain aligned. Delivery is still too fragmented: ordinary-open
binding is now connected and statically tested, but no revised protected T5 pair has run. The next checkpoint must integrate deletes,
publication and automatic recovery, then qualify actual protected behavior. M2 is unfinished and the MVP is not ready.

## T4 — failed stress gate, pending owner direction

- [x] All 10,000 cycles were attempted under boot Verifier; pool slope was 1.501 B/cycle, no cap refusal, and the worker became idle.
- [ ] The product gate failed: **8,740 passes / 1,260 failures**, comprising 845 same-name access denials, 413 rename sharing violations
  and two missing hand-backs. Three versions/views remained at settle and four private stage files remained.
  - [x] [Raw verdict](../2026-10-11/m2t4boot10k1011a2-verdict.txt) and
    [read-only journal diagnosis](../2026-10-11/t4-journal-failure-diagnosis.md) retained. Four private manifest replacements failed;
    the underlying native error 5 remains unproven. Do not loosen ACLs/sharing on that assumption.
  - [x] [Test restoration](../2026-10-11/m2t4boot10k1011a2-final-restored-state.txt) and
    [separate fresh-disk restoration](../2026-10-11/m2t4boot10k1011a2-independent-restoration.txt) passed: deleted overlays, untouched
    base, clean original baseline and unchanged XML. [Test start](../2026-10-11/m2t4boot10k1011a2-checkpoint.txt) and
    [verification start](../2026-10-11/m2t4boot10k1011a2restore-start.txt) each record `RunDiskEfiReset=True`.
  - [ ] Owner direction remains pending before product fixes/retry after repeated identical failures. No retry was launched by this review.

Flat pool and clean restoration do not make the failed product row pass. Sampled public checks do not replace raw-volume regressions.

## T5 — meaningful static progress, unfinished protected integration

- [x] [Latest committed gates](t5-bound-service-allocation-gates.md): four WDK profiles at **0 warnings / 0 errors**, PREfast/ApiValidator;
  **876/876 normal** and **1171/1171 feature** tests in both Debug and Release, with service/tray/package legs at 0/0.
  - [x] Root rechecked aggregate TRX equals the disjoint user + SYSTEM union: 851 + 25 normal, 1146 + 25 feature; every result Passed,
    unique executions, no skips. [Raw WDK](exact-t5-public-open2-summary.txt) and [raw agent](exact-agent-matrix-t5-public-open3-summary.txt)
    summaries name sources `450c8d74` and `8ef80fcc`. Their tested kernel/agent subtrees respectively match committed `ffd47a97`.
- [x] Native scheduled CREATE/close dispatch and ordinary FILE_OPEN binding are connected behind the disabled capability
  (`653ef223`–`8ef80fcc`; `StageStream.c:3501–3508,3538`; `StagedPublicOpenDispatcher.cs:39–84`). Ordinary binding allocates no delete
  generation and preserves the original NTFS open. Fourteen binding and 26 lifecycle controls pass per feature profile.
- [ ] No protected FilterPort/Verifier run qualifies this pair. Bound-head readiness remains false
  (`MinifilterBoundAllocation.cs:14,23,45`); the existing publisher refuses bound entries (`StagedTransferPublisher.cs:81–82`).
  - [ ] The kernel exchange still accepts only open-prepare/open-facts (`StageProtocol.c:1145–1147`); ordinary mutation forwarding is
    not connected. The approved [relay design](../../T5-NATIVE-PUBLIC-OPENS.md#ordinary-public-disposition-integration--proposal-for-review-2026-10-12)
    is **READY WITH CORRECTIONS**, superseding this review's earlier REVISE status.
  - [ ] Working-tree relay intent/result journaling and dispatcher changes are **uncommitted and outside those gates**. Receipt ACK,
    exact cleanup/recovery completion and retirement remain absent; an acknowledgement field alone is not that implementation.
    Preserve one-use forwarding and durable uncertainty; do not enable an incomplete path or accumulate a new per-boot ceiling.
- [ ] Bound-writer CREATE/security/sharing/seeding, combined DELETE+write backend use, every physical publication/delete through the
  shared head, startup activation, resolving directory events and complete teardown remain on the same integration critical path.
  - [ ] The [unreadable-seeded-bytes hand-back choice](../../T5-NATIVE-PUBLIC-OPENS.md#owner-choice-pending--unreadable-seeded-bytes)
    awaits the owner. Neither policy option is approved; full-file hand-back must not disclose prior bytes without read authority.

Journal reopening and injected replay tests are not qualified service restart or app-close recovery. The runtime rows must prove
the owner's automatic hold release, both deterministic DeleteFile orders and real clean/CPF Notepad Save As with independent bytes.

The audit corrected one proposed defect before acting: exact `STATUS_SUCCESS` governs the service prepare reply that permits
forwarding; recording the final lower NTFS status is separate. Luna withdrew its claim that the dirty journal's nonnegative native
result classification itself violates that permit rule. The independently confirmed integration/retirement gaps remain.

## T6–T11 — M2 has substantial work beyond T5

- [x] T6 and T7 retain earlier-pair runtime evidence; T10 has its permission-routing source change.
- [ ] Final-pair reruns, T6 directory moves, T8 real applications/metadata, T9 bounded complete inspection and space/failure handling,
  T10's failed phase, SOP/journal lifetime and the final M2 review conditions remain open in [the status plan](../../POST-MVP-PLAN.md).

Earlier-pair passes do not qualify the changed pair. Builds and test counts do not establish a percentage of MVP completion.

## T12/T14, T21–T23, T15–T19 — required scope remains intact

- [x] The plan retains M3, then USB/removable, SMB/UNC and real cloud sync, then combined M4 qualification. T21 requires automatic
  remount reconciliation; M2's fixed-NTFS Restart exception does not extend to removable media. T20/T24 remain Later.
- [ ] Both original mapping repros, new destination observers, combined stress/crash/recovery/latency and cutover remain unqualified.

Taint stays; normal builds compile staging out; unsupported destinations remain disabled. The writable-state detour remains parked
on `wip/t5-writable-state-20261011`. The plan is 475 lines, close to the owner's requested M1 size, with checklists at most two levels.

## T5 — next delivery checkpoint

- [ ] Finish one integrated, still-disabled T5 pair: original-operation delete relay including combined handles, shared allocation/
  publication/delete ordering, exact close/startup reconciliation, cleanup/receipt retirement and local teardown.
  - [ ] Gate the exact committed source; obtain the single integrated kernel lifetime/lock-order/retirement review before boot.
  - [ ] Qualify both forced-delete orders, real clean/CPF Notepad and automatic-recovery fault/compatibility rows in all three modes,
    retaining every byte assertion, runtime Verifier and separate restoration.

Group implementation around that checkpoint. No new component milestone or routine per-patch review is warranted. Resolve the
pending T4 hold before its focused reproduction/retry, and rerun T4 on the final M2 pair. Harness fixes retain PS5.1 parsing,
self-checks and real execution, with no review manifests/dispositions.

At audit start committed HEAD matched the tracked remote through `ffd47a97`. This refresh corrects stale test counts, relay review
status and exported-handle wording. It changes no product code, assertion, VM baseline or host configuration and starts no VM run.
