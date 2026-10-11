# SafeUpload MVP status plan

Updated 2026-10-11. **Goal:** replace process-taint enforcement with owned-stream staged writes for every supported protected
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

### T4. Remove the 128-saves-per-boot ceiling

**Problem:** retired versions retained slots; later saves failed until reboot. Idle writer-context retention also affected pool accounting.
**Done when:** 10,000 mixed approve/block saves in one boot pass with flat nonpaged pool, no Verifier hit, no cap refusal, zero residual
versions/views/tombstones/stages and an idle worker; C01–C04, B01, B02 and X01 pass in all three modes.

- [x] Lifetime fix and pre-boot review, including `60fecdbc`; `m2-driver5-t11` has all four WDK/PREfast/ApiValidator builds at 0/0.
- [x] Simplified VM setup and harness gates (`04fc6bbb`); [PowerShell 5.1 gate](evidence/2026-10-11/harness-windows-gate-t4-resume-1011-a1.txt).
- [x] Bounded readiness reads; real ready/silent/absent pipe controls and all harness self-checks pass in
  [Windows PowerShell 5.1](evidence/2026-10-11/harness-windows-gate-t4-readiness-1011-a2.txt).
- [ ] **Failed:** `m2t4boot10k1011a2`, win10-debug3, `m2-driver5-t11` + `t4-af1`, Verifier from boot: 8,740/10,000 passed;
  845 same-name access denials, 413 rename sharing violations and two missing hand-backs. Four stage files remained.
  - [x] Retained [verdict](evidence/2026-10-11/m2t4boot10k1011a2-verdict.txt), [all cycle outcomes](evidence/2026-10-11/m2t4boot10k1011a2-cycles.jsonl),
    [pool/Verifier samples](evidence/2026-10-11/m2t4boot10k1011a2-samples.jsonl), [raw Verifier queries](evidence/2026-10-11/m2t4boot10k1011a2-verifier/),
    [final result/counters](evidence/2026-10-11/m2t4boot10k1011a2-after.txt)
    and [service errors](evidence/2026-10-11/m2t4boot10k1011a2-service-events.txt). Pool slope 1.501 B/cycle, no cap refusal, idle worker;
    settle versions/views failed, though they reached zero after actor exit. No assertion waived.
  - [x] [Stop reason](evidence/2026-10-11/m2t4boot10k1011a2-stop.txt), [test-disk restoration](evidence/2026-10-11/m2t4boot10k1011a2-final-restored-state.txt)
    and [separate fresh-disk baseline/restoration](evidence/2026-10-11/m2t4boot10k1011a2-independent-restoration.txt) passed;
    both [test start](evidence/2026-10-11/m2t4boot10k1011a2-checkpoint.txt) and [verification start](evidence/2026-10-11/m2t4boot10k1011a2restore-start.txt)
    record EFI reset.
  - [x] [Read-only diagnosis](evidence/2026-10-11/t4-journal-failure-diagnosis.md): four failed private-journal replacements;
    two leave Publishing reservations, two prevent hand-back. The underlying native error 5 remains unproven.
  - [x] Harness stops on the second identical failure, captures private journal records and full-ID stage metadata, and records
    the stop reason. [PowerShell 5.1 gate](evidence/2026-10-11/harness-windows-gate-t4-stop-evidence-1011-a1.txt): all 18 self-checks
    pass; 27 new controls include two real native actor failures and orderly stop. Revised protected runtime remains pending.
  - [ ] Owner reply before product fixes/retry after repeated identical failures. No retry launched.
- [ ] Run the listed raw-observer regression cells, then rerun T4 on the final M2 pair.

The preceding `m2t4boot10k9` stopped after 4,714/10,000 without a final result; it is not a pass. Its run disk was deleted and base
verified untouched. The cycle row's sampled public checks do not replace the raw-volume invariant regressions.
Attempt `m2t4boot10k1011a1` [stopped before any cycles](evidence/2026-10-11/m2t4boot10k1011a1-stop-request.txt): the selected agent lacked admission-evidence support (`UnknownReceiptFlags`).
The retry uses admission-evidence agent `t4-af1` (596 tests passed, protocol 18); this stopped attempt provides no T4 qualification.
Its [run-disk restoration](evidence/2026-10-11/m2t4boot10k1011a1-final-restored-state.txt) and
[separate fresh-disk baseline verification](evidence/2026-10-11/m2t4boot10k1011a1-independent-restoration.txt) passed.

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
    live dispatcher, startup recovery and notification emission remain pending.
  - [x] Anchored native parent observer (`3df7aa97`) without child opens, using complete repeated 128-bit directory enumeration;
    all 14 buffer/native-handle cases pass in each agent profile. Authenticated driver-anchor export and live recovery remain pending.
  - [x] Named-file recovery guidance, exact owner-session/SID delivery and structured diagnostics (`a3b3b81e`, `6ee1112e`);
    [18 cases pass in each agent profile](evidence/2026-10-11/t5-native-notice4-static-gates.md), including real emission-record reopening and qualified Restart advice.
    The notification helper is not connected to the live recovery dispatcher and cannot clear a hold.
  - [x] Owner approves the [forced-instance exception](evidence/2026-10-11/t5-native-instance-teardown-feasibility-luna6.md) for M2 fixed NTFS:
    keep the named-file hold until qualified Restart recovery; T21 must reconcile at remount instead. Implementation/runtime remain open.
  - [x] Bounded native-object record map, exact CREATE/CLEANUP/cancellation ownership and unload veto (`5591afe8`, `e9458807`);
    [canceled-CREATE design review](evidence/2026-10-11/t5-native-cancelled-create-design-luna6.md) and
    [static gates](evidence/2026-10-11/t5-native-replay-static-gates.md). Authenticated read-only replay is built/tested (`aa1a2a46`);
    durable destination-head discovery exists (`e97585cb`). CREATE producer and integrated pre-boot kernel review remain pending.
  - [x] [Startup epoch security design](evidence/2026-10-11/t5-native-startup-epoch-design-review-luna6.md) reviewed with corrections:
    authenticated boot metadata plus conservative private recovery before readiness; implementation/runtime remain open.
  - [ ] Connect checked public proxy/backend capabilities, all namespace/physical commits, exact last-close reconciliation and
    sealed-private cancellation to that head; finish teardown and its kernel lifetime review before boot. The new journal layer is not live.
- [ ] Qualify both deterministic native orders: DeleteFileW before seal and after independently observed publication; both succeed.
  - [x] Prepare clean/CPF forced-order coordinator gates and no-empty-leftover verdicts; Windows PowerShell 5.1 parsing,
    168 schema assertions and actual unprotected NTFS actor controls pass ([raw output](evidence/2026-10-11/t5-forced-order-harness-controls-1011a5.txt));
    14 host evidence-rejection controls pass ([output](evidence/2026-10-11/t5-host-forced-order-verdict-control-1011a1.txt)). Protected coordinator runs remain pending.
- [ ] Run real Notepad clean/CPF Save As in ordinary, runtime-Verifier and boot-Verifier modes, independently observing destination bytes.
- [ ] Add compatibility/ordering rows: Explorer New Text Document → rename → another process opens it in Notepad; empty copy/move;
  clear-and-save existing; authorized and denied public delete; delete during newer save; delete followed by blocked CPF.
- [ ] Four WDK 0/0 builds, agent matrix, Verifier and separate restoration on the revised pair.

Latest static gates: driver and agent `aa1a2a46`, four WDK builds at **0 warnings / 0 errors**, PREfast/ApiValidator;
**821/821** per normal agent profile and **936/936** per feature profile, every discovered case executed once without skips,
service/tray builds and Release packages at 0/0 ([readout](evidence/2026-10-11/t5-native-replay-static-gates.md)).
Raw build output, TRX and execution checks remain local under the readout's recorded prefixes. No revised pair has booted.
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
