# SafeUpload MVP status plan

Updated 2026-10-12. **Goal:** replace process-taint enforcement with owned-stream staged writes for every supported protected
destination, keeping unapproved bytes private throughout. M2 is the current milestone, not the completion boundary.
Historical implementation narratives remain in Git history, [POST-MVP-LOG.md](POST-MVP-LOG.md), and the local WIP branch noted below.

## Milestone order

| Order | Scope | Status |
|---|---|---|
| M1 | T0–T3: safe to leave loaded | Complete on the recorded M1 pair |
| **M2** | **T4–T11: everyday file work** | **Active: T4 10,000 cycles first, then T5 deletes** |
| M3 | T12, T14: release configuration and lifecycle | After M2 |
| T21 | USB/removable | After M3; own design, owner decisions, Luna design review and destination qualification |
| T22 | SMB/UNC | After T21; own design, owner decisions, Luna design review and destination qualification |
| T23 | Cloud-sync folders | After T22; own design, owner decisions, Luna design review and real-client qualification |
| M4 | T15–T19: combined qualification | Qualify local NTFS and T21–T23 together |
| Later | T20 other Windows builds; T24 ReFS | Outside the current milestone sequence |
| Owner-deferred | T13 production signing/Secure Boot | Test mode remains in force |

USB, SMB/UNC and cloud-sync are required MVP work; they are no longer deferred until after M4. They remain disabled until their
respective support and qualification gates are met and the owner approves cutover.

## Owner decisions

**2026-10-11 — destinations and completion.** Follow the order above. M4 covers local NTFS, USB including surprise removal,
UNC/SMB, and a real sync client with independent destination-byte observers. Both mapping leaks need their repros rerun and closed.
T21 and T22 are required MVP milestones before M4, not Later work. Each needs its own design note, owner decisions and Luna 6
max-effort design review before implementation; adding them to the plan does not approve particular filesystems or network configurations.
After all required tracker items have run evidence, write a taint-removal plan and wait for owner sign-off. Taint stays, normal builds
compile staging out, and unsupported capabilities stay disabled until the owner approves cutover.

**2026-10-11 — empty files and deletes.** Empty files are ordinary content: seal, verify stable length, inspect trivially clean,
and publish normally. This reverses the 2026-10-10 EmptyHeld decision. Public deletes are in M2 and Windows decides the caller's
delete authority on the real public file. A newer save cancels a delete only if that save has already published. Allocated, unsealed,
sealed, inspecting or blocked successors do not cancel it; older versions cannot publish after deletion. See [T5-DELETES.md](T5-DELETES.md).
Only the old no-empty-publication assertion changes; every other product assertion remains required.

**2026-10-11 — accepted native-delete tracking failure.** The owner approves preserving NTFS's accepted result only with automatic
reconciliation at the app's last-handle close and again at service startup after a crash. Hold publication to that name meanwhile;
establish that it is gone or still the original pre-open file, then release the recovery hold automatically. Reuse the durable
pre-CREATE intent and existing startup recovery; add no protocol states beyond **accepted, unresolved**. If exact reconciliation
cannot decide, retain the hold, name the file and an actionable next step in the tray, and record diagnostics. Fault-injection rows
must prove automatic hold release after handle close and service restart. If that automatic guarantee cannot be met, ask the owner
before implementation. See [T5-NATIVE-PUBLIC-OPENS.md](T5-NATIVE-PUBLIC-OPENS.md). Ordinary mounted-instance recovery has a corrected
design; the approved fixed-NTFS exception below covers forced instance teardown. Protected fault-injection qualification remains open.

**2026-10-11 — forced-teardown recovery scope.** For **M2 local fixed NTFS only**, the owner approves holding the affected name
private after forced instance teardown until exact evidence or a qualified full Windows **Restart** permits automatic reconciliation.
The tray names the file and gives that remedy; app close, service restart and Fast Startup cannot substitute for lost cleanup evidence.
Keep the existing service-stop prohibition and veto voluntary unregister while coverage-lost native records remain unresolved.
For **T21 USB/removable**, surprise removal makes this routine: restarting Windows is **not** an acceptable remedy. Design automatic
reconciliation when the volume remounts, proving that the old removed-volume handle can no longer change the file before checking
the returning volume's state. Record this requirement now; implement it only in T21 after its dedicated design/review.

**2026-10-11 — VM restoration.** Independently verified restoration means all of:

- A throwaway qcow2 run disk is deleted afterwards.
- The base disk is verified untouched (`RunDiskBaseUntouched=True` and `Get-StagedBaseline.ps1`).
- Domain XML is unchanged by the run.
- EFI variables are reset at every start; if reset boot is unreliable, restore a saved known-good VARS copy before each run.
- Test VMs have no TPM; Windows 10 runs test-signed with Secure Boot off.

Use **win10-debug3 only**; win10-debug2 must remain off because the clones share a guest IP. Its TPM was removed with the original
XML backed up and the exact [XML diff](evidence/2026-10-11/t4-vm-setup-1011-xml.diff) retained. Libvirt supports `start --reset-nvram`.
The [setup boot](evidence/2026-10-11/t4setup1011a1-host.txt) passed the original baseline, disk deletion, untouched-base and unchanged-XML checks.
Run restoration separately from the product test. Writable-state proofs, file leases and libvirt request-drain work are not prerequisites.

The unfinished writable-state/recovery transaction, polkit/QEMU-hook tooling and remote-execution harness rework are preserved locally
on **`wip/t5-writable-state-20261011` (`61dedee1`)**, removed from the active M2 tooling. No polkit, QEMU hooks, sudoers, libvirt daemon,
systemd or other host-wide configuration may be changed without asking the owner.

**2026-10-11 — workflow.** Codex orchestrates and does ordinary work. Luna 6 at max effort reviews only product-security designs,
kernel lifetime/lock-order/retirement changes once before their first VM boot, and one adversarial review per milestone against the
working system. Harness/test scripts need Windows PowerShell 5.1 parsing, their self-checks and a real run; no per-revision Luna
review, freeze/pin manifests or disposition JSON. The Git commit hash identifies source. Keep raw evidence local under
[evidence/README.md](evidence/README.md); track only cited files. Commit and push coherent changes. Progress checklists start with their
T item and have at most two levels. Stop and ask on repeated identical failures, changed VM baselines, or product/taint/cutover/failure-policy
choices. Every option must explain what users will notice.

**2026-10-12 — T4 recovery.** The owner approves automatic recovery of interrupted bookkeeping: retry only the unfinished
recording step, never repeat an already-completed public save. Preserve pending hand-back work across journal failures and verify an
existing returned copy. An uncertain publication keeps its name held and gets a named tray explanation/diagnostic; historical
unbound Publishing records without an exact native receipt cannot be released from a digest match. Identity/content failures keep
their terminal handling. Prove deliberate failure cases before the short Verifier gate and another 10,000-cycle run.

**Earlier decisions still in force:**

- Protection starts before applications open protected files for editing; installation may need an initial restart (reconfirmed 2026-10-10).
- Sticky Unknown lasts until reboot; no scan/timer workaround for unresolved writer state. T1 is event-driven. T4's previously approved
  bounded retry applies only where Windows supplies no resolving event; it is not authority to clear Unknown.
- Windows 10 22H2 build 19045.2965 remains the qualification platform; production signing and other Windows builds remain deferred.
- Moves into protection are inspected like copies (T6); reads follow Windows permissions (T7).
- Permission/owner changes reach the real file or directory and use Windows access checks (T10).
- No fixed driver file-size cap: stage-space budgets, whole-file inspection, and Blocked/hand-back/allowed justification when inspection
  cannot complete (T9). Do not truncate inspection or infer approval from a failure.
- NTFS object-ID writes on potentially protected volumes remain refused until safely classified after open. The M1 TrkWks workload
  exception requires identifying that exact service; it is not a general bypass.

## Gates that stay required

Four WDK builds (normal/feature × Debug/Release), PREfast and ApiValidator at **0 warnings / 0 errors**, and passing agent tests.
Kernel runtime changes run under Verifier. Keep every product assertion, independent raw-volume observation and **ForbiddenByteCount=0**.
Any removed refusal needs a row proving unapproved bytes remain private. BLOCK-window tests run serially on the selected VM.
A milestone ends with its matched pair, three-mode gate, adversarial review and separate restoration checks.

## M1 — completed component baseline

M1 passed 69/69 cells on `m1-driver21` (`498f4ed7`) plus agent `4d02039a`, with U01 and installer workloads recorded in
[POST-MVP-LOG.md](POST-MVP-LOG.md). These results do not qualify later changed pairs.

### T0. Field diagnostics and installer fixes

**Problem:** refusals could not be diagnosed while the agent owned the filter port.
**Done when:** the bounded deny ring/counters are readable through the agent and installation reaches Ready without hand edits.

- [x] Deny ring, counters, agent pipe and installer fixes; real C05 refusal observed (M1 log above).

### T1. Event-driven reclaim

**Problem:** unresolved work repeatedly requeued the worker and consumed CPU.
**Done when:** idle passes approach zero, required activation/recovery rows pass, and all boot-Verifier cells finish.

- [x] Event-driven worker and identity anchor; final M1 69/69 and idle cell `m21c1` (M1 log).
- [ ] Keep wake-up attribution and unchanged idle assertions in the final combined gate.

### T2. New user profiles

**Problem:** protection refused unrelated profile/registry operations during first sign-in.
**Done when:** real first sign-in succeeds with no out-of-scope refusal and no weakened protected-file check.

- [x] U01 normal/boot-Verifier and registry/section fixes on the M1 pair (`u0121a`, `u0121b`; M1 log).

### T3. Installers and Windows Update

**Problem:** heavy installer workloads caused refusals or exhausted writer tracking.
**Done when:** MSI, Microsoft 365, cumulative update and Defender update finish, coverage stays Ready and overhead is measured.

- [x] All four workloads and controls on final M1; no Unknown/overflow, scoped TrkWks exception only (M1 log).
- [ ] Recheck coexistence and workload impact on the final combined product (T17).

## M2 — active

**Next delivery checkpoint:** Qualify the owner-approved T4 journal recovery repair, then retry the short/10,000-cycle gates. Complete the
integrated T5 pair: bound allocation/manifests/seeding, every physical publication/delete through the shared head and permits,
exact close/startup reconciliation, cleanup acknowledgements and teardown. Group implementation and static checks around that
integration. After the single pre-boot kernel lifetime review, qualify native deletes in both forced orders and real Notepad
clean/CPF Save As in all three modes, with independent bytes and separate restoration. Component passes do not complete T5.
Keep the broad application/metadata matrix in T8; all existing assertions and the full milestone sequence remain required.

The [latest progress/direction review](evidence/2026-10-12/m2-progress-direction-review.md), covering `a7e238ff` and the latest builder attempts,
confirms the architecture and scope but finds delivery still fragmented. Original ordinary dispositions and known-cleanup ACK/retirement
are connected; no revised protected T5 pair has run. Finish checked writer authority, shared publication/deletes and automatic recovery
as one delivery checkpoint. The [publication contract](T5-BOUND-PUBLICATION.md) now has its corrected Luna design review;
transport/client and durable native-result journal are implemented; kernel object integration and recovery remain unfinished.
The seeded-content hand-back owner choice remains open. The retained-object construction passed its direct native query gate and
is ready to implement; the failed zero-access reopen is discarded. Unprotected native controls do not qualify this pair.

### T4. Remove the 128-saves-per-boot ceiling

**Problem:** retired versions retained slots; later saves failed until reboot. Registry/context memory attribution remains unresolved.
**Done when:** 10,000 mixed approve/block saves in one boot pass with flat nonpaged pool, no Verifier hit, no cap refusal, zero residual
versions/views/tombstones/stages and an idle worker; C01–C04, B01, B02 and X01 pass in all three modes.

**Owner decision — 2026-10-12: smoke occupancy and loaded-context release.** The 256-cycle row is a smoke test; its module-pool
slope is informational and is never a stop reason. SafeUpload.sys Verifier bytes are almost entirely the writer registry: fixed pool
plus 2,400 bytes per live named entry, capped at 4,096. Live occupancy floats around 220–280; one entry at the last of four samples
moves the slope by 11.25 B/cycle. In `m2t4clean256b1`, module bytes rose 89,856 between cycles 64 and 256 while SwUr rose
39 × 2,400 = 93,600 bytes. Short slopes (−23, 192, 319, 462 B/cycle) are occupancy noise. The 10k slope of 1.501 B/cycle over
cycles 1,000–10,000 is the meaningful measurement. The short row retains the 64 KiB idle endpoint band (`T4PoolEndpoint`);
leak detection remains the 10,000-cycle row's unchanged slope < 4 B/cycle from cycle 1,000 and the 64 KiB endpoint band (`T4PoolFlat`).

Strengthen the 10k gate with `T4ContextsReleased`: after the existing idle sample, as SYSTEM enable privileges 13 and 5, then empty
working sets, flush the modified list and purge the standby list through `NtSetSystemInformation` class 80, commands 2/3/4 in order.
Record every NTSTATUS without throwing on failure, wait 30 seconds for NTFS delayed close, then sample `purged`. Require all purge
statuses to succeed and live SUfl allocations at `purged` ≤ `start` + 2,048; missing purge evidence fails the 10k assertion. Short rows
report this check as INFO. No handles, driver calls or file deletion are part of the purge. Every sampled registry entry count must
remain within capacity and idle capacity failures must be zero (`T4RegistryBounded`, all rows).

In `m2t4boot10k1011a2`, live SUfl grew from 343 to 14,898, tracking roughly 13,100 created/kept files (9,155 journal manifests,
2,075 hand-backs, approximately 1,875 new public files). `m2t4memdiag1` proves unload releases them; the new check establishes whether
memory pressure releases contexts while the driver stays loaded. This adds a gate and does not relax the long-row or functional
assertions. The repeated-failure stop rule applies to the 10k row and functional assertions, never a short slope.

Validate the actual purge Add-Type signature on Windows PowerShell 5.1 with the harness gate, and replay retained evidence with
`python3 driver/scripts/t4/verdict-selfcheck.py` before any run. Use win10-debug3 only, the existing disposable disk/reset-NVRAM and
separate-restoration workflow, unchanged k11 (`EBDFCE549EA1DC271498A5F6A38D151AC952ADE9105D476B073A313EB271C851`) and agent
`6198eee7` archive (`21F725DD4995603979CF173C43499477B45E2CC5085404AFC594C5B04CD5293F`), verifying both hashes before boot.
Run 256 boot-Verifier cycles sampled every 64 first. Stop if any required assertion fails, any purge status fails, purge evidence is
missing, or purge releases less than half of the SUfl growth since start; understand that measurement before a long run. Only after
smoke passes run 10,000 boot-Verifier cycles and require every assertion, including post-idle `T4AdmissionRecovered`. Only after both
pass run C01–C04, B01, B02 and X01 in all three modes. Stop and report any run failure other than the informational short slope.

- [x] Lifetime fix and pre-boot review, including `60fecdbc`; `m2-driver5-t11` has
  [all four WDK/PREfast/ApiValidator builds at 0/0](evidence/2026-10-10/exact-m2-driver5-t11-summary.txt).
- [x] Simplified VM setup, bounded readiness and repeated-failure capture/stop:
  [PowerShell 5.1 readiness controls](evidence/2026-10-11/harness-windows-gate-t4-readiness-1011-a2.txt) and
  [18 self-checks plus 27 failure controls](evidence/2026-10-11/harness-windows-gate-t4-stop-evidence-1011-a1.txt).
- [x] Journal recovery through `aea1ec16`; [main agent matrix at `8e0156c9`](evidence/2026-10-12/exact-agent-matrix-t4-journal-recovery6-summary.txt):
  normal Debug/Release 895 tests each, feature Debug/Release 1,245 each, no skips, 0 warnings/errors.
- [x] Reviewed allocation-reply cleanup/timing on isolated protocol-18 agent `6198eee7`;
  [four-profile matrix](evidence/2026-10-12/exact-agent-matrix-t4-rejected-allocation1-summary.txt): 558 normal / 625 feature tests each, no skips, 0/0.
- [ ] **Memory attribution:** [analysis and independent Luna lifetime review](evidence/2026-10-12/t4-memory-direction.md).
  - [x] Approved diagnostic `m2t4memdiag1`: 256/256, original short assertions pass, zero staged leftovers; unload returns SUfl/SwUr
    and Verifier allocations to zero; separate restoration passes ([result and raw evidence](evidence/2026-10-12/t4-memory-attribution-result.md)).
  - [ ] Establish bounded retention while loaded with the owner-approved purge gate above. The new
    [10k verdict](evidence/2026-10-12/m2t4purge10ka1-verdict.txt) fails `T4ContextsReleased`: start 335, idle 15,952, purged 2,712;
    limit 2,383, exceeded by 329. All five native statuses are zero; purge releases 13,240 allocations (84.8% of idle growth).
    This proves substantial release while loaded, but does not meet the chosen bound. No kernel reclamation or threshold change is authorized.
    The historical [clean short result](evidence/2026-10-12/t4-clean-short-result.md) is retained unchanged; its slope is now informational.
- [ ] Qualify the allocation-reply fault path under protection; the latest clean short run did not exercise NO_WAITER.
  The historical delay's cause remains open ([diagnosis](evidence/2026-10-12/t4-allocation-reply-diagnosis.md)).
- [ ] Pass the complete short and 10k rows with the revised harness. [New smoke](evidence/2026-10-12/m2t4purge256a1-verdict.txt):
  256/256, every required assertion PASS, 69.8% of idle SUfl growth released. New 10k: 10,000/10,000, functional/pool/registry/Ready
  assertions PASS, pool slope −1.293 B/cycle; contexts bound FAIL above. Both separate restorations PASS; further product VM runs stopped.
  The historical [journal-failure diagnosis](evidence/2026-10-11/t4-journal-failure-diagnosis.md) remains preserved.
- [x] Correct verdict exit classification found by the new long row: an explanatory `purge NTSTATUS PASS` incorrectly made its
  `T4ContextsReleased FAIL` line return success. Read the status token only; the
  [offline contexts-only failure control](evidence/2026-10-13/t4-purge-verdict-exit-selfcheck.txt) requires exit 1 with all other assertions PASS.
  Original run evidence, including the incorrect exit 0 receipt, is retained unchanged; no further VM row was run for this reporting fix.
- [ ] Run the required raw-volume regression cells above, then rerun T4 on the final M2 pair.
  The cycle row's sampled public-byte checks do not replace the raw-volume observer.

### T5. Empty saves, Notepad Save As and deletes

**Problem:** public probe deletion was refused and private-delete names stayed occupied until physical cleanup. EmptyHeld broke normal
zero-byte file operations and added a successor protocol. Empty is now ordinary content; public deletes are M2.
**Done when:** clean saves publish exactly their bytes; CPF saves hand back and leave new names absent or existing prior bytes intact;
no empty probe is left behind; no uninspected nonempty byte reaches the public name. All existing other assertions pass in three modes.

- [x] Owner reversal recorded 2026-10-11 in this plan and [MVP-PLAN.md](MVP-PLAN.md).
- [x] [Source classification](evidence/2026-10-11/t5-empty-public-delete-component-classification.md) distinguishes EmptyHeld-only
  removal from independent identity, callback drain and cleanup protections; [native NTFS controls](evidence/2026-10-11/t5-ntfs-disposition-control-1011.txt) verify ordinary clear, on-close timing and parent DELETE_CHILD authority.
- [x] [Delete design](T5-DELETES.md), source classification and [independent Luna design review](evidence/2026-10-11/t5-empty-public-delete-design-review-luna6.md)
  ready before code: private last-close name release, checked public deletes, durable ordering, reserved enum slots and guarded legacy migration.
- [x] Simpler unload design reviewed in the same note: voluntary veto for outstanding private work; mandatory teardown drains local
  references without waiting on the service. Startup retains private stages; adding a reaper or changing failure policy needs an owner decision.
- [x] Native actor skips DeleteFileW after a failed CREATE_NEW; [PowerShell 5.1/native controls](evidence/2026-10-11/t5-actor-probe-native-control-1011a2.txt)
  prove the existing object's full identity survives and successful new-name probes still delete/save. Protected rows remain unqualified.
- [x] Actor branches force a held-writer delete and an observer-gated after-publication delete;
  [PowerShell 5.1/native NTFS controls](evidence/2026-10-11/t5-actor-forced-delete-orders-native-control-1011a1.txt) pass both native
  orders and the failed-create identity guard. Protected coordinator/order receipts and runtime qualification remain open.
- [ ] Implement reviewed design; remove EmptyHeld/SupersededEmpty/AbandonedEmpty, EmptySavePrivate and CREATE_AFTER_PRIVATE_DISCARD /
  SuccessorReservation chains. Keep independent identity cleanup, local rundown and exact-ACK safeguards where applicable.
  - [x] Released-stage cleanup checks volume + full 128-bit ID and refuses reparse replacements (`a9c0fb59`); its four WDK builds pass
    at 0/0 with PREfast/ApiValidator ([summary](evidence/2026-10-11/exact-t5-exact-cleanup1-summary.txt)). Verifier qualification remains pending.
  - [x] Ordinary measured-zero publication, guarded legacy migration, removed empty notice, and last-cleanup private-name release
    implemented (`f305d607`, `d8fd93c6`); seal replay refuses changed identity/length. This is source/test completion, not VM qualification.
  - [x] EmptyHeld kernel flags, successor ancestry, rotation and create-after sends/replay removed (`028a1b66`); generic exact ACKs,
    failed-allocation receipts, paging rundown and RPC/worker pins remain. Public-delete backends and complete teardown rescope are still open.
  - [x] Identity-keyed destination head/commit queue and ordinary-delete journal layer (`b5c2d13f`, `fe529a2d`); 19 new cases pass in
    each agent profile. Durable accepted reservations release locks while waiting; only newer Published suppresses a delete.
  - [x] Caller CREATE-subject snapshot, separate NTFS-checked backend factory and exact authenticated service-process hold
    (`334f11af`–`3be0fe71`), original process-lifetime/effective-SID binding and reconciled service-epoch pin; normal builds omit
    the backend. The factory is not yet connected to public-delete handling.
  - [x] [Native public-open correction](T5-NATIVE-PUBLIC-OPENS.md) and automatic accepted/unresolved recovery have a
    [READY WITH CORRECTIONS Luna review](evidence/2026-10-11/t5-automatic-native-delete-recovery-review-luna6.md).
    [Builder parent-query control](evidence/2026-10-11/t5-native-pending-link-control-builder-1011a1.txt) identifies a pending original
    and exact absence after last reader close; protected runtime and automatic-recovery fault rows remain pending.
  - [x] Native accepted/unresolved journal component (`960ba2d7`, `e9458807`) with immutable on-close kind, current-session cleanup/cancellation/qualified-boot proof,
    automatic queue wake and retained generation floor; all 28 component cases pass in each agent profile. The
    [boot-lifetime review](evidence/2026-10-11/t5-native-boot-lifetime-design-review-luna6.md) rejects counter-only release;
    gated last-close dispatch is now connected; startup activation and protected automatic-recovery qualification remain pending.
  - [x] Anchored native parent observer (`3df7aa97`) without child opens, using complete repeated 128-bit directory enumeration;
    all 14 buffer/native-handle cases pass in each agent profile. The metadata RPC below replaces handle export; live recovery remains pending.
  - [x] Named-file recovery guidance, exact owner-session/SID delivery and structured diagnostics (`a3b3b81e`, `6ee1112e`);
    [18 cases pass in each agent profile](evidence/2026-10-11/t5-native-notice4-static-gates.md), including real emission-record reopening and qualified Restart advice.
    Startup preflight now emits owner-scoped diagnostics (`9e9dea9d`); [10 startup cases pass per feature profile](evidence/2026-10-11/t5-native-startup-notice-static-gates.md).
    Gated last-close dispatch now reuses this guidance (`da66fef4`); startup activation/runtime remain pending. Emission cannot clear a hold.
  - [x] Owner approves the [forced-instance exception](evidence/2026-10-11/t5-native-instance-teardown-feasibility-luna6.md) for M2 fixed NTFS:
    keep the named-file hold until qualified Restart recovery; T21 must reconcile at remount instead. Implementation/runtime remain open.
  - [x] Bounded native-object record map, exact CREATE/CLEANUP/cancellation ownership and unload veto (`5591afe8`, `e9458807`);
    [canceled-CREATE design review](evidence/2026-10-11/t5-native-cancelled-create-design-luna6.md) and
    [static gates](evidence/2026-10-11/t5-native-replay-static-gates.md). Authenticated read-only replay is built/tested (`aa1a2a46`);
    durable destination-head discovery exists (`e97585cb`). Gated original-CREATE producer/typed lifecycle and terminal receipt removal
    are connected (`b6e3d1b6`–`dcf4b276`); [26 lifecycle controls pass](evidence/2026-10-12/t5-bound-service-allocation-gates.md).
    Ordinary native disposition is connected at `d5779d5a`; combined backends, startup/directory-event activation and pre-boot review remain pending; capability stays off.
  - [x] [Startup epoch security design](evidence/2026-10-11/t5-native-startup-epoch-design-review-luna6.md) reviewed with corrections:
    authenticated boot metadata, asynchronous private preflight and visible readiness gate implemented (`9c1f9737`);
    [agent gates pass](evidence/2026-10-11/t5-native-startup-static-gates.md). Anchored native hold release/runtime remain open.
  - [x] [Observation transport review](evidence/2026-10-11/t5-native-observation-transport-review-luna6.md): return checked metadata directly;
    volume-GUID/legacy-hold and portable-device guards implemented (`1d3f47cc`, `e088cde4`) with [passing static gates](evidence/2026-10-11/t5-native-volume-static-gates.md).
    Authenticated metadata RPC and strict receiver implemented (`13a8fb8b`, `589e9034`), with [passing query static gates](evidence/2026-10-11/t5-native-query-static-gates.md)
    including 42 new query cases per feature profile. Live recovery and runtime portability/hold-release checks remain open.
  - [ ] Correct ordinary CREATE authority: disposition-specific rights, case/identity anchors, native sharing, complete security labels,
    post-allocation authorization and live replay identity; see the [current review](evidence/2026-10-12/m2-progress-direction-review.md).
    Replay identity is fixed (`dbe02d04`); [kernel seed/read-authority corrections and the owner hand-back choice](T5-NATIVE-PUBLIC-OPENS.md#owner-choice-pending--unreadable-seeded-bytes) remain open.
    [Native rights/grant controls](evidence/2026-10-12/writer-permission-native-control-a5.txt), `0a5add63`: 980 comparisons pass on the builder;
    existing supersede with NULL descriptor preserves queried security. Qualified-platform, assignment, seed and kernel integration remain open.
    Every queued CREATE now captures its original static subject and owned access/share/options/case/EA/supplied-security inputs;
    [direct native ID controls](evidence/2026-10-12/writer-permission-native-control-a8.txt) pass all eight retained share-0 cases.
    Capture source `f5cff550` passes [four revised WDK 0/0 gates](evidence/2026-10-12/exact-t5-writer-capture3-summary.txt).
    Original opened/relative/raw-ID lookup and root capture at `4b478e10` passes
    [four WDK/PREfast/ApiValidator 0/0 builds](evidence/2026-10-13/exact-t5-lookup-capture4-summary.txt), including nonpageable cancellation cleanup.
    [90 native sharing cases](evidence/2026-10-12/writer-split-share-lifetime-native-a9.txt) validate closing supplemental checks
    before retaining the original-grant lease. Checked backends, assigned security/seeding transport and runtime remain open.
    The [focused writer-authority report](<../reports/T5 native writer authority.md>) records seven finite control groups and
    unresolved low-token capture, native assignment/creator-grant, metadata and coherent-seed mechanisms. It is provisional
    design evidence; admission, the pending owner hand-back choice and the product-run stop are unchanged.
    The [durable allocation security record](T5-NATIVE-PUBLIC-OPENS.md#durable-allocation-security-record-implementation-checkpoint)
    is connected to manifest commit, exact replay/recovery and retention-aware cleanup (`4c235172`, `ac69dc00`);
    [Windows matrix passes](evidence/2026-10-13/exact-agent-matrix-t5-security-storage2-summary.txt) at 913 normal/1,269 feature
    tests per Debug/Release profile with no skips and 0 warnings/errors. Lost committed metadata refuses replay and retains backing.
    Complete native snapshot production, metadata RPC, rename rebinding and publication descriptor use remain open.
    [Seven native SYSTEM security cases](evidence/2026-10-13/t5-security-roundtrip-native4.txt) expose a publication-construction
    limitation: two inherited descriptors lose `SE_DACL_AUTO_INHERITED` on the original temporary CREATE. Exact control equality
    is unresolved; no masking, protection repair or privileged post-set is approved. Metadata share-zero queries pass with a
    private SYSTEM SeSecurityPrivilege copy, not extra original-writer or temporary-handle rights.
    The [14-row inheritance-request comparison](evidence/2026-10-13/t5-security-auto-request1.txt) adds only the documented
    `SE_DACL_AUTO_INHERIT_REQ` to candidate CREATE inputs; both constructions retain the same five matches/two inherited-control
    failures. The exact expected descriptor is unchanged, so this candidate is rejected. PowerShell 5.1 and strict independent
    fixture/task/worker restoration pass; publication remains NotReady, with no kernel/agent change or product boot.
  - [ ] Connect checked public proxy/backend capabilities, all namespace/physical commits, exact last-close reconciliation and
    sealed-private cancellation to that head; finish teardown and its kernel lifetime review before boot. The complete shared head is not live.
    [Ordinary disposition relay](T5-NATIVE-PUBLIC-OPENS.md#ordinary-public-disposition-integration--proposal-for-review-2026-10-12)
    design is READY WITH CORRECTIONS. Original native-open/disposition producer, typed permit/result and known-cleanup ACK/retirement
    are connected (`10a8ea4e`, `d5779d5a`); [all static gates pass](evidence/2026-10-12/t5-bound-service-allocation-gates.md), including 22 ordinary controls.
    The capability stays off; owner tombstones, combined backends, startup/events and protected qualification remain open. Pre-boot lifetime review is required.
    [Reviewed integration contract](evidence/2026-10-11/t5-bound-allocation-publication-design-review-luna6.md), V23 transport and
    Windows filename resolver are implemented (`827b3f41`, `5f294008`) with [passing static gates](evidence/2026-10-12/t5-bound-allocation-static-gates.md).
  - [x] Service V23 dispatch → anchored seeding → bound manifest/head claim and receipt validation connected (`ca5a9cfa`–`be78b958`);
    [agent gates pass](evidence/2026-10-12/t5-bound-service-allocation-gates.md), including 14 allocation/continuation and two native Windows controls per feature profile.
    Interrupted claims retain exact private cleanup obligations. Kernel producer/physical commits remain open; admission stays disabled.
- [ ] Qualify both deterministic native orders: DeleteFileW before seal and after independently observed publication; both succeed.
  - [x] Prepare clean/CPF forced-order coordinator gates and no-empty-leftover verdicts; Windows PowerShell 5.1 parsing,
    168 schema assertions and actual unprotected NTFS actor controls pass ([raw output](evidence/2026-10-11/t5-forced-order-harness-controls-1011a5.txt));
    14 host evidence-rejection controls pass ([output](evidence/2026-10-11/t5-host-forced-order-verdict-control-1011a1.txt)). Protected coordinator runs remain pending.
- [ ] Run real Notepad clean/CPF Save As in ordinary, runtime-Verifier and boot-Verifier modes, independently observing destination bytes.
- [ ] Add compatibility/ordering rows: Explorer New Text Document → rename → another process opens it in Notepad; empty copy/move;
  clear-and-save existing; authorized and denied public delete; delete during newer save; delete followed by blocked CPF.
- [ ] Four WDK 0/0 builds, agent matrix, Verifier and separate restoration on the revised pair.

Latest static gates: agent `a7e238ff`, WDK `f5cff550`; agent subtree is unchanged through the WDK commit.
four WDK builds at **0 warnings / 0 errors**, PREfast/ApiValidator; **880/880** per normal profile and **1230/1230** per feature profile,
every discovered case executed once without skips,
service/tray builds and Release packages at 0/0 ([readout](evidence/2026-10-12/t5-bound-service-allocation-gates.md)).
Raw build output, TRX and execution checks remain local under the readout's recorded prefixes. No revised pair has booted.
V23 allocation, native CREATE/close, ordinary disposition/known-cleanup, 34 v26 publication-client and 13 native-result journal controls pass;
kernel publication records/hooks remain open. Bound-writer capture,
combined backends, owner tombstones, shared physical commits, startup and directory events remain open; reopening is not service-restart qualification.
Both build runners use the Git commit as the source identifier, without source manifests or worktree freezes; archive hashes check
delivery. Agent-runner [PowerShell 5.1 controls](evidence/2026-10-11/t5-agent-commit-build-powershell51-gate2.txt) and
[matrix self-checks](evidence/2026-10-11/t5-agent-matrix-runner-selfcheck.txt) pass.

Ordinary CPF overwrite of an existing file preserves prior bytes. Explicit authorized deletion followed by a blocked new save leaves
that name absent. Do not delete a pre-existing file after a failed CREATE_NEW probe. Historical EmptyHeld source/build acceptance
(`e0de7e46`) is not runtime qualification of this revised behavior. Preserve exact file identity, callback/worker/owner lifetime and
cleanup obligations; removal must follow the source classification, not a text-wide deletion.

### T6. Moves inspected like copies

**Problem:** a same-volume rename can introduce bytes without a staged write.
**Done when:** Explorer, Move-Item, cmd move and MoveFileEx publish clean moves or hand back CPF, remove the source appropriately,
and never publish uninspected bytes; C05 reflects inspection rather than blanket refusal.

- [x] Copy fallback via STATUS_NOT_SAME_DEVICE (`baec933f`); runtime row `m2t6rv4` passed 28/28 on its component pair.
- [ ] Rerun ordinary, runtime and boot-Verifier on the final pair, including empty files and real Explorer drag.
- [ ] Resolve and qualify directory moves; current Explorer folder move leaves the source intact because protected directory creation is refused.

### T7. Reads follow Windows permissions

**Problem:** legacy read enforcement denied reads that Windows allowed.
**Done when:** authorized users read the exact justified bytes; unauthorized users receive Windows denial with no bytes.

- [x] `4a438b36`; B02 `m2t7o1`, `m2t7v1`, `m2t7b1` passed with ForbiddenByteCount=0 and restoration on that pair.
- [ ] Preserve these assertions in the final M2/combined gates.

### T8. Office/common apps and metadata

**Problem:** real application save/replace/delete sequences and publication metadata need qualification.
**Done when:** Word, Excel, PowerPoint, Paint, WordPad, Explorer replace, browser download, robocopy and 7-Zip rows pass all three modes;
the publishing application can reopen the file and agreed metadata is preserved.

- [ ] Trace/replay real save sequences, including temporary/backup deletes under T5; respect staged rename limits.
- [ ] Decide and test owner, DACL inheritance, timestamps, attributes, ADS including Zone.Identifier, EAs and kernel labels.
- [ ] Qualify application rows under the matched pair with independent byte observation and restoration.

### T9. Large files and complete inspection

**Problem:** 16 MiB driver/seeding limits and whole-memory extraction prevent ordinary large-file use.
**Done when:** no fixed driver size cap; per-user/total stage budgets fail closed without harming other users; full-content inspection
uses bounded memory; incomplete inspection is Blocked with hand-back and policy-authorized justification; runtime rows prove privacy.

- [x] Failure classification, bounded worker concurrency, notifications, single-handle snapshot input, parser-integrity controls and
  bounded numeric-scanner scratch space are implemented; [component gates](evidence/2026-10-10/m2-agent-component-gates.json).
- [ ] Finish whole-file streaming, format/encoding/extraction coverage, stage-space accounting/orphan cleanup and seeding cost.
- [ ] Handle policy-load/snapshot failures safely; qualify interactive failure UI, hand-back, digest and policy-bound justification.
- [ ] Measure cold/warm throughput and peak memory before choosing defaults; existing 256 MiB warm-input measurements are not staged qualification.
- [ ] Qualify large clean/CPF, corrupt/encrypted/password-protected, parser/extraction-limit, timeout and disk-full cases.
- [ ] Resolve the all-zero payment-card classification question with user-visible options before changing its current verdict.

### T10. Permission and owner changes

**Problem:** metadata-only security changes were redirected/refused instead of reaching the real public object.
**Done when:** Windows-authorized file/folder ACL and owner changes succeed; private backing ACLs remain private; permission changes
cannot publish unapproved bytes, proven by the observer.

- [x] Security-only opens use the public file/folder; staged backing remains inaccessible (`771a551b`).
- [ ] Fix/finish phase B: `m2t10rv5` stopped after 5/13 checks when its stage-file access was denied; do not count admin-only success as the row passing.
- [ ] Rerun all modes on the final pair. Carry publication ACL/owner fidelity into T8.

### T11. Review conditions

**Problem:** remaining locking, generation, section-lifetime and journal-scaling findings need closure.
**Done when:** every finding has a tested change or row and the M2 adversarial review closes the working system.

- [x] Nested sealed-stage query guard (`203d31e9`), 32-bit serial-generation arithmetic (`b8394357`), journal cache eviction (`cb1d0930`).
- [ ] Validate SOP lifetime at startup; retire changed-SOP registry entries with a lifetime review before first boot.
- [ ] Finish journal compaction without losing generation barriers or unresolved identity/cleanup obligations.
  - 2026-10-13 component checkpoint (`16c980a4`): compaction now groups bound generation claims by full
    volume-root/parent/mount/case/leaf identity, keeping legacy pathname claims separate. Its retained-reference closure
    includes allocation-reference owners as well as exact parent/delete versions. Journal-only controls cover distinct
    identities sharing a locator, case-sensitive tombstones, case-insensitive aliases, legacy separation, lost-head recovery
    and tombstone-owner replay after restart. The [exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t11-bound-compaction2-summary.txt)
    passes 913 normal/1,278 feature tests per Debug/Release profile, including all nine new compaction controls, with exact
    discovery/execution coverage, no skips and 0 warnings/errors. This does not close the full compaction/scaling or final-pair review gate.
    The destination hash deliberately omits the leaf to preserve Windows equality; many names under one parent share its
    bucket. The follow-up below replaces that lookup and repeated closure scans in the compactor; other destination-index
    users and full journal I/O remain outside this checkpoint.
    The [first matrix stopped on builder disk exhaustion](evidence/2026-10-13/exact-agent-matrix-t11-bound-compaction1-build.stderr.txt)
    after both normal test profiles passed. [Scoped recovery](evidence/2026-10-13/t11-builder-generated-cleanup2.stdout.txt)
    verified eight unpacked publication copies against host-retained ZIPs/manifests before removal (one inline bootstrap,
    then seven copies), preserving source, packages and evidence; the fresh matrix above passes without product VM boots.
  - Follow-up implementation (`23b7eed9`): the bound claim index uses an ordered tree with the same Windows ordinal
    filename comparator as destination equality, avoiding leaf-hash collision chains. A GUID-indexed queue walks retained
    parent/delete/allocation references once each, including shared references/cycles. Snapshot controls exercise 1k/10k/50k
    ancestor chains, up to 50k bound destinations/100k claims under one parent, maximum ties, cancellation and native Unicode
    equality under Turkish culture. Eligibility and durable file validation remain in the existing compactor. Index timings
    qualify only that in-memory decision phase; full journal I/O/scaling and final-pair review remain open.
    The [exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t11-compaction-scaling1-summary.txt) passes 919 normal/1,289
    feature tests per Debug/Release profile, exact discovery/execution coverage, no skips and 0 warnings/errors. All six normal
    and eleven feature index controls pass, alongside the nine disk-backed bound retention/restart controls. In feature Release,
    the [single index measurements](evidence/2026-10-13/t11-compaction-scaling1-index-timings.json) are 12.897/209.442/1,208.669 ms
    for 2k/20k/100k bound claims; the 50k-reference chain takes 58.403 ms. These are scoped measurements, not end-to-end latency
    assertions. [Preflight duplicate-output cleanup](evidence/2026-10-13/t11-scaling-preflight-cleanup.stdout.txt) preserves the
    previous source/packages/evidence and prevents another builder disk-full failure. No product pair was installed or booted.
- [ ] Close every M2 review condition against the final matched pair.

## M3 — after M2

### T12. Release configuration

**Problem:** staging remains feature-gated and test diagnostics must not ship as product interfaces.
**Done when:** an owner-approved release configuration passes the complete gate with test-only hooks absent.

- [ ] Separate product and test-only protocol/diagnostics; keep normal builds staging-free until cutover approval.
- [ ] Check service-SID port authorization, message validation, normal-build identity and four-build static-analysis gates.

### T14. Install, upgrade and uninstall

**Problem:** installation/reboot and mixed driver-agent versions must preserve protection and recoverability.
**Done when:** clean install, both upgrade directions and uninstall pass on a clean VM with verified restoration.

- [ ] Qualify INF/boot-policy seeding/reboot, protocol negotiation and old/new version combinations.
- [ ] Qualify uninstall and residue removal; apply the reviewed voluntary/mandatory teardown policy.

## New destinations — after M3, before M4

### T21. USB and removable media

**Problem:** removal, changing volume identity and filesystems without stable file IDs challenge private staging and publication.
**Done when:** the owner-approved USB/removable scope, including surprise removal, keeps unapproved bytes private, has independent
destination-byte run evidence, and is ready for combined M4 qualification.

**Owner requirement, 2026-10-11:** surprise removal must reconcile automatically at remount, where the old handle can no longer
change the file. Prove that lifetime boundary and validate the returning volume/file state in the T21 design. Windows Restart is
not an acceptable removable-media recovery remedy; the M2 fixed-NTFS exception does not extend here. Do not implement this in M2.

- [ ] Complete the dedicated USB/removable design before implementation.
  - [ ] Record owner decisions on supported filesystems/removal behavior, explaining what users notice under each option; obtain Luna 6 max-effort design review.
  - [ ] Design automatic remount reconciliation after surprise removal; retain the exact identity/generation hold until verified.
- [ ] Implement only the approved scope; keep unsupported combinations disabled.
- [ ] Qualify attach/detach, surprise removal during write/seal/inspection/publication, reconnect and recovery with an independent observer.
  - [ ] Cite matched-pair results, destination-byte observations, Verifier and separate VM restoration; include the approved scope in M4.

### T22. SMB / UNC

**Problem:** policy UNC strings and provider-normalized paths differ; redirector identity, remote permissions and disconnects need a supported design.
**Done when:** the owner-approved SMB/UNC scope preserves privacy through writes, mapping and reconnect on an actual SMB server,
has independent server-side destination-byte run evidence, and is ready for combined M4 qualification.

- [ ] Complete the dedicated SMB/UNC design before implementation.
  - [ ] Cover canonical names, redirector identity, remote authorization, commit ordering and disconnect/retry; record owner choices with user-visible effects and obtain Luna 6 max-effort design review.
- [ ] Implement only the approved scope; keep unsupported network capabilities disabled.
- [ ] Qualify an actual SMB server with independent server-side destination-byte observation.
  - [ ] Cite matched-pair results, mapping/reconnect/recovery evidence, Verifier and separate VM restoration; include the approved scope in M4.

### T23. Cloud-sync folders

**Problem:** sync-client writers, placeholders and upload timing can expose bytes before approval.
**Done when:** a real supported sync client uploads only approved content, with independent local and remote destination observation.

- [ ] Write a dedicated design note for client/Cloud Files behavior, hydration and uploads; obtain owner decisions and Luna design review.
- [ ] Implement the approved client/scope and qualify edits, empty files, delete/rename, conflicts, offline/reconnect and recovery.
- [ ] Observe the real remote destination independently; retain unsupported-client guards until approved.

## M4 — qualify local NTFS and T21–T23 together

### T15. Full functional matrix and mapping repros

**Problem:** component passes do not prove the combined product or all section/mapping variants.
**Done when:** full section-4.1 variants, P01–P06, RV4, T2/T3/T5–T10 rows and both mapping-leak repros pass on every supported destination.

- [ ] Close both mapping leaks and rerun their original repro scripts without weakening their observers/assertions.
- [ ] Run the combined ordinary/runtime-Verifier/boot-Verifier matrix, independent raw-volume/destination observation and separate restoration.
- [ ] Run dedicated latency measurements; keep BLOCK-window cells serial and report costs without masking failures.

### T16. Soak, stress and failure recovery

**Problem:** interruption and concurrency can violate privacy or lifetime despite ordinary passes.
**Done when:** the combined product survives the required stress/crash/recovery matrix with privacy and Verifier gates intact.

- [ ] Multi-day saves, concurrent writers, low-resource Verifier, full disk, service crash loops and power loss during seal/publication.
- [ ] Mapped dirty-write retirement races; lost/duplicate/short/stale replies; voluntary/mandatory unload and allocation failures during I/O.
- [ ] Bound protocol-parser fuzzing, reject malformed/cyclic/extreme inputs, and qualify recovery at each durable transition.

### T17. Coexistence

**Problem:** other filters, storage tools and clients alter the same objects and metadata.
**Done when:** supported coexistence workloads pass with independent privacy observation and no new lifetime/Verifier failures.

- [ ] Defender and at least one third-party AV/EDR, BitLocker, VSS/System Restore, indexer, backup, chkdsk and defrag.
- [ ] Real sync-client coexistence with T23, installers/updates and metadata-label preservation under the agreed T8 rules.

### T18. Degraded / Unknown behavior

**Problem:** sticky Unknown needs actionable status without suggesting protection is Ready.
**Done when:** administrators see the durable reason/remedy and Unknown never clears before reboot.

- [ ] Qualify status, notification, diagnostic reason and documented remedy across supported destinations.

### T19. Continuous evidence

**Problem:** sampled raw reads and final images do not by themselves prove all intermediate publication states.
**Done when:** required continuous mutation/denial evidence closes the observer gaps without weakening existing raw observations.

- [ ] Qualify the mutation ledger and deferred C05 denial ledger; preserve causal operation/inspection/publication ordering.
- [ ] Finish combined adversarial review, stress/latency and evidence audit; then write the taint-removal plan for owner sign-off.

## Later / owner-deferred

### T13. Production signing and Secure Boot

**Problem:** the current test-signed driver requires test mode and Secure Boot off.
**Done when:** after owner authorization, production signing/altitude/INF work passes the gate with Secure Boot on.

- [ ] Deferred by owner: remain test-signed; do not purchase certificates or change signing scope automatically.

### T20. Other Windows builds

**Problem:** section behavior and startup canaries are qualified only on the current platform.
**Done when:** an owner-approved additional Windows build passes its behavior experiments and full combined gate.

- [ ] Later; keep other builds explicitly unqualified until their own evidence exists.

### T24. ReFS

**Problem:** NTFS identity, staging and observer assumptions are not ReFS qualification.
**Done when:** a dedicated reviewed design and owner-approved scope pass the full destination gate.

- [ ] Later; retain unsupported guards.

## Product work outside the driver

- [ ] Package and qualify notifications and correctly named hand-back files, including real interactive blocked-save behavior.
- [ ] Qualify central policy distribution against kernel/boot-policy bounds; change the protocol explicitly if the product exceeds them.
- [ ] Pass agent TLS/certificate tests with their required machine-key permissions, alongside normal and feature agent profiles.
