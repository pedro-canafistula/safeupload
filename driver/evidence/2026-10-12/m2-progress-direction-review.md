# M2 progress and direction review — 2026-10-12

Owner-requested refresh covers gated agent source **`a7e238ff`** and WDK source **`19d5f33c`**, whose kernel source is unchanged
through the agent commit and reviewed HEAD **`283fff88`**: kernel and agent subtree hashes remain identical, so its later native-control
and documentation changes introduce no new product-build result. Codex checked source, plan, raw build summaries, the T4 verdict and separate restoration. The earlier
Luna 6 max direction review found the architecture aligned but delivery fragmented; the corrected publication design subsequently
received READY WITH CORRECTIONS. This refresh is not the final M2 adversarial gate or the integrated pre-boot lifetime review.

**Verdict:** architecture, destination scope and owner constraints remain aligned. Ordinary native dispositions now have a connected
intent/result and known-cleanup ACK/retirement path. Delivery is still too fragmented: no revised protected T5 pair has run, and
bound publication remains unavailable. Finish the shared save/delete/recovery path and qualify actual protected behavior. Static
component passes and repeated status refreshes do not deliver that checkpoint. M2 is unfinished and the MVP is not ready.

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

- [x] [Latest passing gates](t5-bound-service-allocation-gates.md): four WDK profiles at **0 warnings / 0 errors**, PREfast/ApiValidator;
  **880/880 normal** and **1230/1230 feature** tests in both Debug and Release, with service/tray/package legs at 0/0.
  - [x] Root rechecked aggregate TRX equals the disjoint user + SYSTEM union: 855 + 25 normal, 1205 + 25 feature; every result Passed,
    unique executions, no skips. [Raw WDK](exact-t5-publication-journal1-summary.txt) identifies `19d5f33c`;
    [raw agent](exact-agent-matrix-t5-publication-journal4-summary.txt) identifies `a7e238ff`. Kernel subtree
    `15251c35099a789e4ca1556428c399c373aea64e` is unchanged through `a7e238ff`.
- [x] `19d5f33c` adds exact durable native publication receipts: unknown outcomes retain the pending commit; bound manifests reject
  Boolean-only completion; late cleanup cannot republish an older generation after manifest compaction. Its
  [four WDK builds](exact-t5-publication-journal1-summary.txt) pass 0/0 with PREfast/ApiValidator.
- [x] The final matrix passes all 13 native-result journal controls per feature profile. Earlier attempts stopped at a collection
  analyzer error, omitted fixture digest and wrong expected rejection type. Corrections `b2414dea`, `07a748a6`, `a7e238ff` preserve
  every rejection, unchanged-head and no-skip assertion. Failed attempts remain local.
- [x] Native scheduled CREATE/close and ordinary FILE_OPEN binding remain connected behind the disabled capability. The ordinary
  original SetInformation relay, durable result, known-cleanup ACK and authenticated receipt retirement are connected
  (`10a8ea4e`, `d5779d5a`; `StageProtocol.c:1133–1157`; `StagedPublicOpenDispatcher.cs:145–289`). There are 22 ordinary and 26
  native lifecycle controls per feature profile. Original NTFS operations are forwarded once; recorded results cannot authorize a retry.
- [ ] No protected FilterPort/Verifier run qualifies this pair. Bound-head readiness remains false
  (`MinifilterBoundAllocation.cs:14,23,45`); the existing publisher refuses bound entries (`StagedTransferPublisher.cs:81–82`).
  - [x] The [corrected bound-publication design](../../T5-BOUND-PUBLICATION.md) has Luna READY WITH CORRECTIONS: complete authenticated
    execution-facts replay, a one-way temporary-write fence with admitted-I/O drain and actual rename-time target identity checks.
    Feature-only wire/client code and 34 client controls pass on `a15fc758`; the kernel producer/fence/name gate remains unimplemented.
  - [x] [Unprotected native control](bound-publication-native-ab6dc0b9.txt) passes PowerShell 5.1 parsing/self-checks and actual
    parent-relative create/rename of 0-byte and 37-byte files with exact grants and stable full IDs. It proves neither driver permits
    nor protected replacement, privacy, recovery or Verifier behavior.
- [ ] Bound-writer CREATE/security/sharing/seeding, combined DELETE+write backend use, every physical publication/delete through the
  shared head, startup activation, resolving directory events and complete teardown remain on the same integration critical path.
  - [ ] The latest Luna writer-authority review is REVISE: every writer needs its original subject/inputs, exact disposition checks
    and share lifetime, fully assigned descriptor transport, and coherent seed/read provenance. Corrections are recorded in the
    [existing design](../../T5-NATIVE-PUBLIC-OPENS.md#kernel-permission-and-identity-capture--required-integration-corrections);
    they are prerequisites, not a READY or runtime claim, and introduce no new owner policy.
  - [ ] The [unreadable-seeded-bytes hand-back choice](../../T5-NATIVE-PUBLIC-OPENS.md#owner-choice-pending--unreadable-seeded-bytes)
    awaits the owner. Neither policy option is approved; full-file hand-back must not disclose prior bytes without read authority.

The subsequent native writer controls settle 980 tested rights/share/grant comparisons on builder **19045.6466**, not the
qualification VM. The later zero-access revalidation candidate failed; the separate nine supplied-descriptor cases completed.
The [existing writer design](../../T5-NATIVE-PUBLIC-OPENS.md#kernel-permission-and-identity-capture--required-integration-corrections)
records both outcomes and Luna's retained-object correction. Its verdict remains REVISE, and none of these controls is a protected
runtime pass. Further controls should resolve those finite implementation prerequisites, not become another component milestone.

Journal reopening and injected replay tests are not qualified service restart or app-close recovery. The runtime rows must prove
the owner's automatic hold release, both deterministic DeleteFile orders and real clean/CPF Notepad Save As with independent bytes.

An earlier review claim about nonnegative lower NTFS status was withdrawn: exact `STATUS_SUCCESS` governs the typed prepare reply;
the actual native completion is separate. Do not reopen that claim without new evidence. Known-cleanup retirement has since been
implemented; unknown-result, lost-coverage and startup recovery still need complete integration and protected fault qualification.

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
on `wip/t5-writable-state-20261011`. The plan remains roughly the owner's requested M1 size, with checklists at most two levels.

## T5 — next delivery checkpoint

- [ ] Connect the reviewed clean-save path from checked writer authority through temporary
  creation/write fencing and exact target-checked rename to durable Published state and recovery. Complete combined delete handles,
  owner tombstones, close/startup recovery, cleanup and teardown in the same still-disabled T5 pair.
  - [ ] Gate the exact committed source; obtain the single integrated kernel lifetime/lock-order/retirement review before boot.
  - [ ] Qualify both forced-delete orders, real clean/CPF Notepad and automatic-recovery fault/compatibility rows in all three modes,
    retaining every byte assertion, runtime Verifier and separate restoration.

Group implementation around that checkpoint. No new component milestone or routine per-patch review is warranted. Resolve the
pending T4 hold before its focused reproduction/retry, and rerun T4 on the final M2 pair. Harness fixes retain PS5.1 parsing,
self-checks and real execution, with no review manifests/dispositions.

At this refresh's start the tracked remote was `6bc77dd5`; `19d5f33c` awaited push. Native-result implementation and fixture
corrections were committed during the review. No product assertion, VM baseline or host configuration changed and no product VM run was started.
No completion percentage is inferred from commits or test counts. Architecture remains aligned; delivery needs one integrated
protected save/delete/recovery checkpoint before more component passes can count as user-visible progress.
