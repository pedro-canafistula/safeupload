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
| New destinations | **T21 USB/removable → T22 SMB/UNC → T23 cloud-sync folders** | After M3; separate design, owner decisions and Luna design review for each |
| M4 | T15–T19: combined qualification | Qualify local NTFS and T21–T23 together |
| Later | T20 other Windows builds; T24 ReFS | Outside the current milestone sequence |
| Owner-deferred | T13 production signing/Secure Boot | Test mode remains in force |

USB, SMB/UNC and cloud-sync are required MVP work; they are no longer deferred until after M4. They remain disabled until their
respective support and qualification gates are met and the owner approves cutover.

## Owner decisions

**2026-10-11 — destinations and completion.** Follow the order above. M4 covers local NTFS, USB including surprise removal,
UNC/SMB, and a real sync client with independent destination-byte observers. Both mapping leaks need their repros rerun and closed.
After all required tracker items have run evidence, write a taint-removal plan and wait for owner sign-off. Taint stays, normal builds
compile staging out, and unsupported capabilities stay disabled until the owner approves cutover.

**2026-10-11 — empty files and deletes.** Empty files are ordinary content: seal, verify stable length, inspect trivially clean,
and publish normally. This reverses the 2026-10-10 EmptyHeld decision. Public deletes are in M2 and Windows decides the caller's
delete authority on the real public file. A newer save cancels a delete only if that save has already published. Allocated, unsealed,
sealed, inspecting or blocked successors do not cancel it; older versions cannot publish after deletion. See [T5-DELETES.md](T5-DELETES.md).
Only the old no-empty-publication assertion changes; every other product assertion remains required.

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
- [ ] Run 10,000 cycles on win10-debug3 with `m2-driver5-t11`, a matching admission-evidence agent, Verifier from boot and an eight-hour test deadline.
  - [ ] Final result, raw Verifier/pool samples, stop reason and separate fresh-disk restoration baseline.
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
- [ ] Finish [delete design](T5-DELETES.md), source classification and independent Luna design review before code.
  - [ ] Private name release at last cleanup; retired exact-ID cleanup outside namespace locks; ordinary max+1 creates.
  - [ ] Permission-checked public-delete generations, published-only cancellation, durable ordering and publication-collision waits.
  - [ ] Reserve old enum numbers; migrate old EmptyHeld journals only after retirement reconciliation and fresh stable-length checks.
- [ ] Review simpler unload semantics: voluntary veto for outstanding private work; mandatory teardown never waits on service.
  Retained private-stage behavior and any changed product/failure policy need an owner decision before code.
- [ ] Implement reviewed design; remove EmptyHeld/SupersededEmpty/AbandonedEmpty, EmptySavePrivate and CREATE_AFTER_PRIVATE_DISCARD /
  SuccessorReservation chains. Keep independent identity cleanup, local rundown and exact-ACK safeguards where applicable.
- [ ] Qualify both deterministic native orders: DeleteFileW before seal and after independently observed publication; both succeed.
- [ ] Run real Notepad clean/CPF Save As in ordinary, runtime-Verifier and boot-Verifier modes, independently observing destination bytes.
- [ ] Add compatibility/ordering rows: Explorer New Text Document → rename → another process opens it in Notepad; empty copy/move;
  clear-and-save existing; authorized and denied public delete; delete during newer save; delete followed by blocked CPF.
- [ ] Four WDK 0/0 builds, agent matrix, Verifier and separate restoration on the revised pair.

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
**Done when:** the approved USB scope, including surprise removal, keeps unapproved bytes private and passes independent destination-byte checks.

- [ ] Write a dedicated design note; present supported filesystems/removal behavior as user-visible owner choices; obtain Luna design review.
- [ ] Implement only the approved scope; keep unsupported combinations disabled.
- [ ] Qualify attach/detach, surprise removal during write/seal/inspection/publication, reconnect and recovery with an independent observer.

### T22. SMB / UNC

**Problem:** policy UNC strings and provider-normalized paths differ; redirector identity, remote permissions and disconnects need a supported design.
**Done when:** the approved SMB/UNC scope preserves privacy through writes, mapping and reconnect, observed independently at the destination.

- [ ] Write a dedicated design note covering canonical names, redirector identity, remote authorization, commit ordering and disconnect/retry.
- [ ] Resolve user-visible scope/failure decisions and obtain Luna design review before implementation.
- [ ] Qualify an actual SMB server with independent server-side destination-byte observation; keep unsupported network capabilities disabled.

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
