# SafeUpload MVP status plan

Updated 2026-10-13. **Goal:** replace process-taint enforcement with owned-stream staged writes for every supported protected
destination, keeping unapproved bytes private throughout. M2 is the current milestone, not the completion boundary.
Historical implementation narratives remain in Git history, [POST-MVP-LOG.md](POST-MVP-LOG.md), and the local WIP branch noted below.

## Milestone order

| Order | Scope | Status |
|---|---|---|
| M1 | T0–T3: safe to leave loaded | Complete on the recorded M1 pair |
| **M2** | **T4–T11: everyday file work** | **Active; product VM gates stopped at T4's contexts bound** |
| M3 | T12, T14: release configuration and lifecycle | After M2 |
| T21 | USB/removable | After M3; own design, owner decisions, Sol 6.1 xhigh design review and destination qualification |
| T22 | SMB/UNC | After T21; own design, owner decisions, Sol 6.1 xhigh design review and destination qualification |
| T23 | Cloud-sync folders | After T22; own design, owner decisions, Sol 6.1 xhigh design review and real-client qualification |
| M4 | T15–T19: combined qualification | Qualify local NTFS and T21–T23 together |
| Later | T20 other Windows builds; T24 ReFS | Outside the current milestone sequence |
| Owner-deferred | T13 production signing/Secure Boot | Test mode remains in force |

USB, SMB/UNC and cloud-sync are required MVP work; they are no longer deferred until after M4. They remain disabled until their
respective support and qualification gates are met and the owner approves cutover.

## Owner decisions

**2026-10-13 — review model.** Use **Sol 6.1 at xhigh** (`gpt-6.1-sol`) instead of Luna for future reviews. This supersedes the
reviewer-model choice in earlier decisions, without changing their scope or gates. Historical Luna reports remain valid records of
who reviewed that work. The review cadence remains product-security designs, one pre-boot review of kernel lifetime/lock-order/retirement
changes, and an adversarial review of the working milestone pair; no per-revision harness reviews.

The [M2 completion review and proposed sequence](M2-COMPLETION-PLAN.md) records the 2026-10-13 source/evidence audit, concrete remaining
coverage/integration gaps, and proportionate lab automation recommendations. [AGENTS.md](../AGENTS.md) records contributor instructions.
Those recommendations alone do not release T4's runtime stop, approve pending seed/metadata/budget choices, or authorize infrastructure
changes; the owner's direction below accepts the review with specific changes.

**2026-10-13 — M2 completion direction.** The owner accepts the completion review with these changes:
- **T4 attribution diagnostic authorized.** One harness-only, non-qualifying row on win10-debug3 with the unchanged k11/agent `6198eee7`
  pair. Hypothesis: the 2,377 SUfl allocations left above start after the 10k purge track the 2,500 kept hand-backs; the smoke row
  left 440 with 64 hand-backs, so a few hundred are a fixed part. Run a block-heavy mix (about 2,000 cycles), keep the existing idle and
  purge samples, then record which processes hold kept files open (hand-backs, journal manifests, new public files), delete only the
  hand-backs and sample again. A drop of about the hand-back count means those contexts followed the files' Windows lifetime; no drop
  points at a driver-held reference. The `T4ContextsReleased` bound (start + 2,048), every assertion and the stop on other product rows
  stay unchanged; this row neither passes nor fails the gate. Two retained points cannot distinguish a slow leak from a bounded cache.
- **T9 coverage first; read common payloads, refuse rare ones.** Read the text of DrawingML shapes/text boxes, charts (titles, axis and
  series names, labels, cached values), VML drawings/legacy comment boxes, and PDF annotation contents and form-field values. Return
  `unsupported_format` (staged Blocked) for embedded files, PDF attachments, XFA forms and any other payload the readers cannot consume.
  Office acceptance becomes an allowlist of part types the readers consume or that carry no user text; any other reachable part is
  refused, so an unknown part fails closed. Refusing every chart would block many ordinary spreadsheets. This is component work.
- **Unreadable seeded bytes: option 1** in [T5-NATIVE-PUBLIC-OPENS.md](T5-NATIVE-PUBLIC-OPENS.md#owner-choice--unreadable-seeded-bytes):
  preserve native write-only editing; a blocked version containing prior bytes without read/export authority stays service-private with
  a named reason, and no full-file hand-back or justification is offered until that authority exists.
- **Lab tooling now:** only make [Invoke-StagedSuiteBatch.sh](scripts/Invoke-StagedSuiteBatch.sh) fail on any failed or missing case and
  require an explicit approved target (done in `18849424`: 29 offline controls; a single-case runner exit 1 counts only when the
  incomplete table is its sole failure). Defer the readiness doctor, build-capacity preflight, CI, Ansible and Packer until after the T5
  integration checkpoint. Terraform is not adopted.
- **False Degraded notices (T18).** A coverage query answered `ERROR_RETRY` (writer registry changed during the snapshot) reports
  Degraded at once; T4 short rows log 12–21 per run. Retry that answer briefly before reporting Degraded, with admission authority
  unchanged. Write the small design and obtain the Sol review before implementation.
- **Workers.** Claude may delegate to Codex `gpt-6-astra`, `gpt-6.1-sol` and `gpt-6-luna` at any effort up to max, with the fast tier.
  Reviews required by the review policy remain Sol 6.1 xhigh.
- **Later the same day — design work in parallel.** While M2 jobs run, start the design notes for the improved lab/development workflow
  (Ansible, Packer and related tooling), T21 USB/removable and T22 SMB/UNC. Designs only: no implementation, no host-wide or
  qualified-baseline change, and USB/SMB stay disabled until their owner decisions, Sol 6.1 xhigh design reviews and gates.
  This replaces the earlier "defer the tooling" bullet for design work only; tooling implementation still waits for the T5 checkpoint.
  Drafts: [LAB-WORKFLOW-DESIGN.md](LAB-WORKFLOW-DESIGN.md), [T21](T21-USB-REMOVABLE-DESIGN.md), [T22](T22-SMB-UNC-DESIGN.md); all decisions pending.

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

**Next delivery checkpoint:** T4's revised smoke passed; its 10,000-cycle row failed the loaded-context bound. Further product VM rows
remain stopped except the owner-authorized hand-back attribution diagnostic, with no kernel reclamation or threshold change authorized.
Work order from the 2026-10-13 owner direction: T9 complete-or-refuse coverage (drawings/charts/VML, PDF annotations/forms, Office part
allowlist); the T4 hand-back diagnostic; batch-wrapper failure propagation; the T18 retry design; then the integrated T5 pair, following
the [completion sequence](M2-COMPLETION-PLAN.md). Complete the integrated T5 pair: checked allocation/manifests/coherent seeding, every physical publication/delete through the shared head and permits,
exact close/startup reconciliation, cleanup acknowledgements and service-independent mandatory teardown. Group implementation and static checks around that
integration. After the single pre-boot kernel lifetime review, qualify native deletes in both forced orders and real Notepad
clean/CPF Save As in all three modes, with independent bytes and separate restoration. Component passes do not complete T5.
Keep the broad application/metadata matrix in T8; all existing assertions and the full milestone sequence remain required.

The [latest progress/direction review](evidence/2026-10-12/m2-progress-direction-review.md), covering `a7e238ff` and the latest builder attempts,
confirms the architecture and scope but finds delivery still fragmented. Original ordinary dispositions and known-cleanup ACK/retirement
are connected; no revised protected T5 pair has run. Finish checked writer authority, shared publication/deletes and automatic recovery
as one delivery checkpoint. The [publication contract](T5-BOUND-PUBLICATION.md) now has its corrected Luna design review;
transport/client and durable native-result journal are implemented; kernel object integration and recovery remain unfinished.
The seeded-content hand-back choice is option 1 (owner, 2026-10-13). The retained-object construction passed its direct native query gate and
is ready to implement; the failed zero-access reopen is discarded. Unprotected native controls do not qualify this pair.

**Current M2 completion audit — 2026-10-13, source/evidence through `46ba2ae6`.** No T4–T11 completion claim is established by the
latest inspector matrix. The remaining delivery requirements and their current proof are:

| Item | Required proof still outstanding | Current authoritative state |
|---|---|---|
| T4 | Passing loaded-context 10k gate, allocation-reply fault row, raw C01–C04/B01/B02/X01 and final pair | [10k contexts FAIL](evidence/2026-10-12/m2t4purge10ka1-verdict.txt); product VM rows stopped; one non-qualifying hand-back attribution diagnostic authorized. |
| T5 | Checked writer/seed/security authority, shared physical commit/recovery pipeline, final WDK/agent gates and three-mode native/Notepad rows | `_stageBoundHeadReady` stays false; the legacy publisher rejects bound manifests. [Unreadable-seed choice](T5-NATIVE-PUBLIC-OPENS.md#owner-choice--unreadable-seeded-bytes) is option 1 (2026-10-13), not yet implemented; [native descriptor construction](T5-NATIVE-PUBLIC-OPENS.md#native-publication-security-control-2026-10-13) has two exact-control failures. |
| T6 | Directory moves, empty/Explorer moves and final-pair three-mode byte observation | Only the earlier 28/28 copy-fallback component pair is qualified; directory creation/moves remain unresolved. |
| T7 | Final-pair authorized/denied read rows | Earlier component B02 passes do not cover the revised pair. |
| T8 | Nine real application workflows in all three modes; agreed owner/DACL/timestamps/attributes/ADS/EAs/labels | Final application/metadata rows and metadata decisions remain missing. |
| T9 | Stage/seed caps removed under per-user/total budgets; complete format/encoding coverage, bounded parser memory, durable cleanup, interactive failure and protected large-file rows | `StageStream.c:STAGE_MAX_BYTES` and `StagedTransferAllocator.MaximumSeedBytes` remain 16 MiB. The [14-case inspector measurement](evidence/2026-10-13/t9-inspector-metrics3-result.json) covers neither those caps/budgets nor hostile parser memory, publisher costs or protected behavior. The [Sol source review](M2-COMPLETION-PLAN.md#findings-in-delivery-order) identifies unconsumed drawing text and PDF annotation payloads; the owner chose extraction for common payloads and refusal for rare ones (2026-10-13); independent fixtures remain required. |
| T10 | Repair stage access in phase B and pass the final pair in all modes | `m2t10rv5` stopped at 5/13; admin-only success is insufficient. |
| T11 | SOP lifetime/retirement, complete journal scaling/recovery and adversarial review of the working final system | Scoped index/compaction/head-read controls pass; O(N) fresh head I/O and final-system review remain open. |

T4's stop and the open T5 security questions remain prerequisites for the integrated delivery. Do not enable admission,
change the failed contexts bound, discard native security control bits, add an unapproved descriptor repair, or count an unprotected
component pass as that delivery. Storage-budget/default decisions require the measured scope and explicit user-visible failure
behavior; the unchanged inspector defaults and scoped measurements above do not decide them.

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
  - [ ] Hand-back attribution diagnostic (owner-authorized 2026-10-13, non-qualifying; see owner decisions): block-heavy mix, handle
    holders of kept files after purge, SUfl after deleting only the hand-backs. Decide the next step from the drop, not before.
    - [x] Harness `e642e212` (`T4_HANDBACK_DIAGNOSTIC=yes`); [PowerShell 5.1 gate](evidence/2026-10-13/harness-windows-gate-t4-handback-diag1.txt)
      PASS with a holder self-check; offline replay proves the diagnostic changes no gate line.
    - [ ] Row `m2t4hbdiag1`: 2,000 boot-Verifier cycles on the unchanged k11/`6198eee7` pair.
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
    Replay identity is fixed (`dbe02d04`); [kernel seed/read-authority corrections](T5-NATIVE-PUBLIC-OPENS.md#owner-choice--unreadable-seeded-bytes) remain open; the hand-back choice is option 1 (2026-10-13).
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
- [ ] **Integrated checkpoint (goal item 5, 2026-10-13).** [Gap inventory and ten-increment plan](evidence/2026-10-13/t5-integration-plan-astra.md)
  (Astra, read-only, at `a00e7e14`): option-1 provenance → original-authority writer lease → metadata transport → V23 allocation/kernel
  seeding → V26 permits → bound inspection/publication → unified deletes → startup/last-close recovery → T11 SOP → mandatory local
  teardown and readiness composition; one pre-boot Sol 6.1 xhigh lifetime review covers the kernel increments. Unresolved native
  mechanisms (descriptor `0x8C04 → 0x8804`, low-impersonation capture, coherent seed interval, export authority proof) stay
  fail-closed holds with named reasons; none is approved as a narrower contract. Readiness stays false until all increments land.
  - [ ] Increment 1: option-1 provenance and private/no-export enforcement (agent).
  - [ ] Service-independent mandatory teardown for current objects (kernel), extended by later increments.
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

- [ ] **Complete-or-refuse coverage first** (owner direction 2026-10-13; [review finding](M2-COMPLETION-PLAN.md#findings-in-delivery-order)).
  - [ ] Read DrawingML shape/text-box text, chart titles/axis and series names/labels/cached values, VML drawing text and PDF
    annotation contents/form-field values; refuse embedded files, PDF attachments, XFA and other unconsumed payloads.
  - [ ] Replace the Office part denylist with an allowlist; independent fixtures include a clean cell plus a CPF-only drawing text box,
    a CPF chart label, a clean PDF page plus a CPF annotation or form value, an attachment and an unknown part type.
  - [x] First increment (Astra worker, integrated here): 27-type read allowlist, unreferenced/unknown parts refused, drawings/charts/VML/
    threaded comments/properties read; PDF annotations/fields/outlines/Info/XMP read; attachments/XFA/JS/AP/RC refused; legacy uses the
    streaming readers. [Matrix `t9-coverage1`](evidence/2026-10-13/exact-agent-matrix-t9-coverage1-summary.txt): 1,210 normal / 1,580 feature
    tests per Debug/Release profile, no skips, 0/0. [Coverage table](../agente/docs/INSPECTION-COVERAGE.md).
  - [ ] Round 2 (fail-closed gaps that block ordinary files): read Excel tables, cell metadata, pivot caches, external links, Word people/
    comment extensions/glossary, custom properties and custom XML; scan External relationship targets; accept PDF appearance streams that
    draw no text. Filled-form text appearances, incremental PDF revisions and page-level metadata stay refused (recorded below) until read.
- [x] Failure classification, bounded worker concurrency, notifications, single-handle snapshot input, parser-integrity controls and
  bounded numeric-scanner scratch space are implemented; [component gates](evidence/2026-10-10/m2-agent-component-gates.json).
- [ ] Finish whole-file streaming, format/encoding/extraction coverage, stage-space accounting/orphan cleanup and seeding cost.
  - Office auxiliary-text implementation (`41ed0f66`): Word footnotes/endnotes/comments and classic Excel comment text/authors
    are included in extraction, with paragraph/note boundaries preserved. Present Word header/footer/note parts must have a root;
    malformed auxiliary XML cannot become a clean partial extraction. Independent package-XML controls exercise identifiers only
    in these parts, empty/clean notes, numeric fragments across adjacent notes, corruption, masked findings and unchanged bytes.
    Source mechanisms follow Microsoft's [Word part API](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.packaging.maindocumentpart?view=openxml-3.0.1)
    and [Spreadsheet comments model](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.spreadsheet.comments?view=openxml-3.0.1).
    This does not close streaming or complete Office coverage: modern/threaded comments, images/OCR, drawings/charts, embedded/external
    content, formula completeness and other metadata remain unqualified. The existing declarations of excluded content do not prove
    staged whole-content inspection; these remaining cases require inspection or explicit incomplete-inspection refusal.
    The [exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t9-office-notes1-summary.txt) passes 974 normal/1,344 feature tests
    per Debug/Release profile, exact discovery/execution coverage, no skips and 0 warnings/errors. All
    [12 independent package controls](evidence/2026-10-13/t9-office-notes1-controls.json) pass in every profile; sensitive/corrupt
    cases exercise both legacy and staged outcomes and preserve original package bytes. Valid empty note text remains accepted.
    [Preflight duplicate-output cleanup](evidence/2026-10-13/t9-office-notes1-preflight-cleanup.stdout.txt) preserves the previous
    verified source/packages/evidence. No product pair was installed or booted; T4's stop and T5 NotReady remain in force.
  - Known unsupported Office payload refusal (`449ddfaf`): before returning extracted text, both Office extractors walk the
    package's relationship graph with cancellation and a visited-part set. Reachable images, thumbnails, embedded objects/packages,
    ActiveX persistence parts and alternative-format imports receive `unsupported_format`: staged Blocked, legacy
    AllowedWithoutInspection, using the existing inspection-failure path. No OCR, embedded execution, file deletion or source rewrite.
    Traversal follows Microsoft's [part relationship API](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.packaging.openxmlpartcontainer.parts?view=openxml-3.0.1).
    Independent ZIP/relationship XML controls include Word body/header/footnote images, Excel drawing images, valid raster thumbnails,
    embedded Word packages, opaque objects/controls, HTML imports, clean text-only packages and unchanged source bytes.
    The [exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t9-office-payload1-summary.txt) passes 990 normal/1,360 feature tests
    per Debug/Release profile, exact discovery/execution coverage, no skips and 0 warnings/errors; all
    [16 payload controls](evidence/2026-10-13/t9-office-payload1-controls.json) pass in each profile. This closes the identified known-part
    partial-approval path, not complete Office coverage: drawings/charts without images, modern/threaded comments, external or
    unreferenced package content, formula completeness, other metadata and whole-file streaming remain open. No protected run occurred.
    [Scoped builder cleanup](evidence/2026-10-13/t9-office-payload1-preflight-host.json) removed only hash-verified unpacked duplicates
    from completed builds while preserving their source, package ZIPs/manifests and evidence; no host-wide configuration changed.
  - Staged plaintext streaming (`56e2e53f`): the strict BOM-aware extractor now opens disposable readers on the same held private
    snapshot. Complete numeric, bounded-regex, unbounded-token and password passes preserve existing category precedence, masks
    and ordering without capturing the source or full extracted text. Fixed buffers carry boundary context; only offsets, labels and
    masked findings persist between passes. A 16,384 candidate/finding budget produces explicit `inspection_limit` Blocked with
    empty findings rather than approving a partial scan. Existing policy size/deadline limits, worker concurrency, legacy capture/cache
    and Office/PDF paths are unchanged. The [exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t9-stream-text1-summary.txt)
    passes 1,013 normal/1,383 feature tests per Debug/Release profile, exact discovery/execution coverage, no skips and 0 warnings/errors.
    All [18 streaming controls](evidence/2026-10-13/t9-stream-text1-controls.json) pass in each profile: every category subset,
    fragmented input, all fixed-pattern overlap positions, deterministic mixed text, two-million-character unbounded values/whitespace,
    strict UTF-8/16/32 readers on real snapshots, explicit budget failure and cancellation/stream ownership. Boundary word categories
    follow [.NET's regex implementation](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Text.RegularExpressions/src/System/Text/RegularExpressions/RegexCharClass.cs).
    These component passes do not establish peak live memory, default-limit throughput, protected publication or complete format coverage.
    [Scoped preflight cleanup](evidence/2026-10-13/t9-stream-text1-preflight.host.json) preserves previous source/packages/evidence.
    No product pair was installed or booted; source/evidence remain local while the earlier push approval is pending.
  - Spreadsheet formula coverage (`6b13ce8f`): inspect each formula expression and its cached result on separate lines, including
    shared-formula masters. Cached clean display text cannot hide a credential literal in the formula. Missing cached results receive
    `unsupported_format` (staged Blocked, legacy AllowedWithoutInspection); a present empty result remains valid. No formula, link or
    external data is executed. Microsoft's [formula model](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.spreadsheet.cellformula?view=openxml-3.0.1)
    defines the expression and shared masters; [cell values](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.spreadsheet.cellvalue?view=openxml-3.0.1)
    carry cached results. Independent ZIP/XML controls cover formula-only secrets, cached CPF, both sources, shared formulas,
    clean/empty results, missing normal/shared caches and numeric boundaries, in both modes with masked findings, audit behavior and
    unchanged source bytes. This addresses a concrete partial-extraction gap; formula evaluation, external/unreferenced content,
    other Office content and DOM/output streaming remain open.
    The [complete exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t9-formula1-summary.txt) passes 1,044 normal/1,414 feature
    tests per Debug/Release profile, exact discovery/execution coverage, no skips and 0 warnings/errors, with both release packages
    independently verified. All [20 formula and 11 large-input controls](evidence/2026-10-13/t9-formula1-controls-measurements.json)
    pass in every profile. No protected pair was installed or booted; commits remain local pending the earlier push approval.
  - Staged Word text streaming (`6840afe3`, scalar/lookahead correction `6127e878`, tested source `99473988`): each pass opens
    package parts on the same held snapshot through a facade that cannot dispose the caller stream. Header/body/footer/notes/comments
    use XML pull readers with 8 KiB value chunks; part DOMs, complete text-node strings and a complete extracted-output string are
    absent from this staged path. Legacy extraction/cache stays unchanged. Roots and the main body are required, DTDs/external XML
    resolution are disabled, corrupt tails refuse the whole scan, and all part/package readers dispose on completion/failure.
    Paragraph/run/table boundaries are preserved. Nested text-box paragraphs are emitted once on separate lines, preserving surrounding
    text instead of duplicating descendants through the outer paragraph's InnerText. Selected-part/depth budgets (16,384/256) produce
    explicit `inspection_limit` Blocked, without partial findings/approval. Existing policy size/deadline, worker and unsupported-payload
    gates remain intact. This is text-node streaming, not proof of complete Word coverage or bounded hostile metadata: XML attributes,
    parser name tables, SDK/package relationship metadata and other Office content remain qualification findings.
    The [initial matrix](evidence/2026-10-13/exact-agent-matrix-t9-word-stream1-summary.txt) passes 1,055 normal/1,425 feature tests
    per Debug/Release profile and all [11 initial controls](evidence/2026-10-13/t9-word-stream1-controls.json). The
    [corrected complete matrix](evidence/2026-10-13/exact-agent-matrix-t9-word-stream3-summary.txt) passes 1,057 normal/1,427 feature
    tests per profile, exact discovery/execution coverage, no skips, 0 warnings/errors and both verified release packages. All
    [13 controls and live-state samples](evidence/2026-10-13/t9-word-stream3-controls-memory.json) pass: fragmented reads, nested
    paragraphs, 8 MiB single text nodes with clean/EOF CPF, malformed/missing roots/body/tails, DTD refusal, scalar/peek/EOF behavior,
    cancellation and source ownership/SHA-256. Isolated 8/32 MiB real-package controls collect live reader state at checkpoints; these
    are not process-peak, hostile-metadata or protected measurements. The [prior corrected-source matrix](evidence/2026-10-13/t9-word-stream2-retained-failure.json)
    failed the existing legacy queue/parsing deadline control at 8,162 ms against its unchanged 7,500 ms upper bound. One full identical-source
    retry passes above; no assertion, policy budget, timing bound or test filter changed. Failed raw evidence remains retained.
    Scoped duplicate-output cleanup preserves source/packages/manifests/evidence
    ([initial](evidence/2026-10-13/t9-word-stream1-preflight.host.json), [corrected](evidence/2026-10-13/t9-word-stream2-preflight.host.json),
    [retry](evidence/2026-10-13/t9-word-stream3-preflight.host.json)). No product pair was installed or booted; source/evidence remain local.
  - Staged spreadsheet streaming (`015354d4`): a pull reader consumes stored shared-string items once, including unused entries,
    then cell formulas/inline/cached values and classic comment authors/text on separate lines. Shared references are checked against
    the actual parsed table count; neither a complete shared-string array nor worksheet DOM/output string is required. Stored text is
    ordered by package-part traversal; repeated cell references do not duplicate findings. This deliberately differs from legacy
    cell-display order/counts and inspects stored credentials that unused shared entries previously hid. Legacy capture/extraction/cache
    remains unchanged. Workbook defined-name text is also consumed. Present roots are required, malformed tails/invalid references
    refuse the complete scan, missing formula caches retain unsupported-format refusal, and all part/package readers close without
    closing the held caller snapshot. Parts/depth/reference-field budgets (16,384/256/32 chars) prevent unbounded selected-part state,
    nesting and reference accumulation; policy size/deadline/worker limits are unchanged. Hostile XML attributes/name tables,
    SDK/package metadata and complete spreadsheet content still need separate qualification.
    The [complete Windows matrix](evidence/2026-10-13/exact-agent-matrix-t9-sheet-stream1-summary.txt) passes 1,073 normal/1,443
    feature tests per Debug/Release profile, exact discovery/execution coverage, no skips, 0 warnings/errors and both verified packages.
    All [16 new controls and live-state samples](evidence/2026-10-13/t9-sheet-stream1-controls-memory.json) pass in every profile:
    fragmented rich/shared/inline/formula text, unused/repeated shared references, invalid/oversized indices, corrupt table/sheet tails,
    large shared/inline/cached values, scalar/peek/cancellation/source lifetime and original SHA-256. Existing formula/comment/empty/
    malformed-content controls remain in the full matrix. Collected live reader state on real 8 MiB values is sampled in an isolated
    collection; it is not a process-peak or protected measurement. [Scoped preflight](evidence/2026-10-13/t9-sheet-stream1-preflight.host.json)
    removes only verified unpacked duplicates, retaining source/packages/manifests/evidence. No product pair was installed or booted;
    source/evidence remain local pending the earlier push approval. T9 overall and M2 final/runtime gates remain open.
  - Staged PDF extracted-text streaming (`33ca257e`): consume page letter values in content order, with existing platform page
    newlines and raster-image refusal, without Page.Text or a document-wide extracted-output string. A read-only stream facade
    preserves the caller's held snapshot across page/package disposal; cancellation is checked between letter/page operations.
    Legacy capture/extraction/cache and policy/worker budgets remain unchanged. The pinned PdfPig 0.1.16
    [Page.Text implementation](https://github.com/UglyToad/PdfPig/blob/v0.1.16/src/UglyToad.PdfPig/Content/Page.cs)
    concatenates these same letter values; [page construction](https://github.com/UglyToad/PdfPig/blob/v0.1.16/src/UglyToad.PdfPig/Content/Pages.cs)
    still parses a page's content and retains document structures/resources. This removes output copies, not a worst-case parser bound.
    Large individual pages, metadata/resource caches, annotations/forms/ActualText and other PDF content, encryption/corruption and
    parser behavior remain qualification findings; the existing lenient parser setting was not changed by this checkpoint.
    The [complete Windows matrix](evidence/2026-10-13/exact-agent-matrix-t9-pdf-stream1-summary.txt) passes 1,079 normal/1,449 feature
    tests per Debug/Release profile, exact discovery/execution coverage, no skips, 0 warnings/errors and both verified packages. All
    [six independent raw-PDF controls](evidence/2026-10-13/t9-pdf-stream1-controls.json) pass in every profile: independently authored
    object/xref structures, fragmented reads, page/numeric boundaries, last-page CPF, blank pages, scalar/peek/EOF/cancellation and
    source ownership/SHA-256. Existing image-content refusal and privacy controls remain in the full suite. This is not a PDF process-peak
    or protected measurement. [Scoped preflight](evidence/2026-10-13/t9-pdf-stream1-preflight.host.json) preserves completed source,
    packages/manifests and evidence. No product pair was installed or booted; commits remain local pending the earlier push approval.
  - Measured snapshot-copy bound (`9a46baf3`): copy at most the sealed length with fixed 64 KiB scratch space. Initial length
    mismatch, growth during capture, premature EOF and cancellation cannot yield a complete inspection snapshot. Existing digest,
    publication and failure handling remain intact. The [complete exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t9-snapshot-bound2-summary.txt)
    passes 1,086 normal/1,456 feature tests per Debug/Release profile, exact discovery/execution coverage, no skips, 0 warnings/errors
    and both independently verified Release packages. All [seven copy controls](evidence/2026-10-13/t9-snapshot-bound2-controls.json)
    pass in every profile, including source growth from 128 KiB to 8 MiB while copied/read bytes stay at 128 KiB.
    The [initial matrix](evidence/2026-10-13/t9-snapshot-bound1-retained-failure.json) passed every test but failed final feature ZIP
    creation on builder disk exhaustion; its empty summary/partial ZIP remain failure evidence. One identical-source retry passes,
    without changing assertions, policy budgets, timing bounds or filters. Scoped duplicate-output cleanup
    ([initial](evidence/2026-10-13/t9-snapshot-bound1-preflight.host.json), [retry](evidence/2026-10-13/t9-snapshot-bound2-preflight.host.json))
    preserves source/packages/manifests/raw evidence. No product pair was installed or booted; commits remain local pending push approval.
  - Owned-handle snapshot lifecycle (`245da04a`, completion-port correction `fa3019cc`): create the service-only temporary object
    with delete-on-close and no sharing, copy/hash the measured bytes, then drop its write handle. Publication/hand-back and scanner
    workers receive read-only duplicates of that held object, without reopening or deleting a pathname. A worker owns its lease
    until actual completion, including after timeout; the existing worker/deadline and late-result gates remain intact. The new
    inspection entry point rejects missing, writable, nonseekable or wrong-length leases without falling back to a pathname.
    The [first matrix](evidence/2026-10-13/t9-snapshot-handles1-retained-failure.json) compiled at 0/0 but failed 87/1,079 normal Debug
    user cases: duplicated asynchronous handles could not bind the same file object's completion port again. The correction uses
    synchronous native handles; .NET 10's [FileStream strategy](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Private.CoreLib/src/System/IO/Strategies/OSFileStreamStrategy.cs)
    and [Windows offset I/O](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Private.CoreLib/src/System/IO/RandomAccess.Windows.cs)
    retain independent logical read offsets and async call support. Nineteen controls cover all four formats, native read grants,
    independent concurrent offsets, empty/failing capture, noncooperative parser lifetime and independent Windows process termination.
    The [corrected-source matrix](evidence/2026-10-13/t9-snapshot-handles2-retained-failure.json) passes both normal profiles at
    1,105/1,105; feature Debug fails only the immediate process-exit cleanup observation (1/1,450 user cases). An
    [independent 20-trial native-signal diagnostic](evidence/2026-10-13/t9-snapshot-close-diag1-result.json) finds every file immediately
    absent after WaitForExit(int), without cleanup polling, path deletion or purge. The failure is consistent with .NET's
    [early exit-code HasExited path](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Diagnostics.Process/src/System/Diagnostics/ProcessManager.Windows.cs)
    allowing WaitForExitAsync to complete before the native process object is signaled. Test correction `e2854de5` waits for that
    actual signal, retaining the ten-second bound and immediate absence assertion. The
    [complete matrix at `0581833c`](evidence/2026-10-13/exact-agent-matrix-t9-office-stores1-summary.txt) passes 1,116 normal/1,486 feature
    tests per Debug/Release profile, exact discovery/execution coverage, no skips, 0 warnings/errors and both independently verified
    Release packages. All [19 snapshot lifecycle controls](evidence/2026-10-13/t9-office-stores1-controls.json) pass in each profile,
    including the unchanged immediate-absence assertion after native process completion. Both failures remain retained.
    No product assertion, policy budget, original backing/public-file cleanup or kernel code changed.
    [Scoped duplicate-output recovery](evidence/2026-10-13/t9-snapshot-handles1-preflight.host.json) preserved source/packages/evidence;
    subsequent [snapshot](evidence/2026-10-13/t9-snapshot-handles2-preflight.host.json) and
    [combined-matrix](evidence/2026-10-13/t9-office-stores1-preflight.host.json) headroom checks were read-only, with no further cleanup.
    Whole-machine interruption/orphan recovery and quotas remain open.
  - Office stored-payload/relationship safeguards (`0581833c`): custom XML stores, custom document properties and unknown SDK
    extension parts now use the existing unsupported-content refusal instead of approving only their visible body/cell text.
    Staged failures remain Blocked with empty findings; legacy failures retain AllowedWithoutInspection. No stored payload is
    executed, deleted or rewritten. Microsoft's [custom XML overview](https://learn.microsoft.com/en-us/visualstudio/vsto/custom-xml-parts-overview?view=visualstudio)
    confirms these stores persist data inside Office files. The relationship walk caps its unique visited parts at 16,384, matching
    the staged text-reader part budget, with explicit inspection_limit. This bounds the walk's own state/work, not SDK/ZIP/XML
    metadata allocation before enumeration. Ten independent Word/Excel payload cases and a 17,000-header package control cover
    refusal/classification in both modes and unchanged source bytes. The complete matrix above also passes all
    [26 payload and one relationship-budget controls](evidence/2026-10-13/t9-office-stores1-controls.json) in each profile, including
    the existing image/embedded-payload and clean-package controls. Complete format coverage, hostile parser metadata,
    storage budgets and the protected milestone gate remain open. No product pair was installed or booted; commits remain local.
  - Snapshot storage finding: the prior ordinary-publisher inspection lifecycle used random private `.inspection` names, with no durable
    snapshot-owner/cleanup obligation in the transfer journal. Process interruption could leave copies, and deletion failure could
    mask capture/cleanup errors or surface after an already-completed transfer. Source/inspection/publication authority must remain
    separate from cleanup success. Durable identity-bound cleanup and storage charging remain required; filename matching, an
    unverified pathname or digest alone must not authorize deletion. The exact-length copy safeguard does not solve these findings
    or introduce per-user/total quotas, and no startup deletion sweep is implemented by that change. Capture also precedes
    InspectionService's bounded worker/deadline admission; those parser slots alone do not bound concurrent snapshot storage.
- [ ] Handle policy-load/snapshot failures safely; qualify interactive failure UI, hand-back, digest and policy-bound justification.
  - Strict current-policy implementation (`bfffa535`): staged inspection, approval, justification, allocation/rename/attach
    admission and hand-back routing use an explicit current read. Local ACL rejection or loss of an already loaded file and
    HTTP failure/empty responses cannot substitute cached/default policy authority. Legacy fallback remains available to its
    existing consumers. Controls cover provider failures/recovery, all staged decision routes, retention during an ACL failure
    before publication, and refusal to export hand-back bytes. Whole-file streaming, failure UI and protected qualification remain open.
    The [exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t9-current-policy1-summary.txt) passes 936 normal/1,306 feature
    tests per Debug/Release profile, exact discovery/execution coverage, no skips and 0 warnings/errors. All
    [13 new authority/fallback controls](evidence/2026-10-13/t9-current-policy1-controls.json) pass in every profile. Initial local
    provisioning may still create/validate its live default file; disappearance after loading refuses a current read without
    recreating a default. That checkpoint identified same-version semantic edits as a separate publication/justification
    binding gap; the follow-up below addresses it.
    [Scoped preflight cleanup](evidence/2026-10-13/t9-current-policy-preflight-cleanup.stdout.txt) preserves the previous verified
    source/packages/evidence. No product pair was installed or booted; T4's stopped gate and T5 NotReady remain in force.
  - Complete-policy binding implementation (`f792d437`, corrected fixture `aa6ad3a8`): staged results carry a deterministic fingerprint of every policy
    field, with collection order normalized and exact strings/strict UTF-8 preserved. Approval and justification require both
    that fingerprint and the version. Blocked manifests persist the binding; recovery rechecks it before restoring a callback.
    Missing historical bindings or same-version edits retain the exact private version for a new inspection, without inventing
    prior authority or deleting backing. Controls cover every field, framing/order/encoding, same-version decision/publication
    races, durable restart/justification and malformed/missing metadata. Audit/UI payloads and driver ABI remain unchanged.
    The [exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t9-policy-binding3-summary.txt) passes 962 normal/1,332 feature
    tests per Debug/Release profile, exact discovery/execution coverage, no skips and 0 warnings/errors. All
    [27 targeted binding/recovery controls](evidence/2026-10-13/t9-policy-binding3-controls.json) pass in every profile. The
    [first matrix](evidence/2026-10-13/exact-agent-matrix-t9-policy-binding1-summary.txt) correctly distinguished the configured
    clipboard defaults from an omitted block; the equality fixture was corrected to represent omitted/explicit empty defaults.
    The [second matrix](evidence/2026-10-13/exact-agent-matrix-t9-policy-binding2-summary.txt) failed the existing queued-deadline
    control at 7,707 ms against its unchanged 7,500 ms bound. One complete retry of the identical source passes above; no timing
    threshold, test filter or assertion was changed. All failed raw receipts remain retained. Scoped duplicate-output cleanup
    preserves source/packages/evidence; no product pair was installed or booted. T9 streaming/runtime and M2 final gates remain open.
  - Ordinary-publisher preparation failures (`c6f1f435`, recovery call corrected in `3d2d5979`, tested source `e62b658a`): snapshot
    creation, durable-length validation and hashing finish together before inspection starts. I/O/access failure transitions the exact
    version to Retained, closes its exception window and sends only safe read/parse-failure metadata to its owner; initial current-policy
    read failures also carry that metadata. The tray explains that analysis did not finish and bytes were not sent. These holds neither
    publish nor register a justification callback; a trusted snapshot/current policy must be available before new inspection can proceed.
    Existing private bytes and prior public bytes survive. Without trusted preparation/authority, this path cannot claim a verified
    hand-back or inspected digest. Retained startup/retry UX, disk-full, snapshot orphan cleanup/storage budgets and protected UI/runtime
    qualification remain open; the controls invoke a fresh ordinary publisher inspection directly, not automatic service/UI retry.
    The [exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t9-preparation3-summary.txt) passes 992 normal/1,362 feature tests
    per Debug/Release profile, exact discovery/execution coverage, no skips and 0 warnings/errors. Both
    [new failure controls](evidence/2026-10-13/t9-preparation3-controls.json) pass in every profile: real directory CreateFiles denial,
    exact DACL restoration/access recovery, durable stage retention, owner-only notification, preserved public bytes, safe failure
    metadata, no callback/permit, and successful explicit reinspection after the failure clears. Source changes include application builds;
    no protected pair was installed or booted, and bound-publication integration is not qualified by these ordinary-publisher controls.
    [Retained failures](evidence/2026-10-13/t9-preparation-retained-failures.json) record the missed recovery caller's first build error
    and the second matrix's fixture restoration failure. The fixture now explicitly marks/restores the saved DACL and proves recovered
    creation access: [.NET persists changed security sections only](https://github.com/dotnet/runtime/blob/main/src/libraries/System.IO.FileSystem.AccessControl/src/System/Security/AccessControl/FileSystemSecurity.cs).
    No assertion or timing limit was relaxed. [Scoped preflight cleanup](evidence/2026-10-13/t9-preparation1-preflight-host.json)
    preserves completed source/packages/evidence. Commits remain local while the earlier source/evidence push approval is pending.
- [ ] Measure cold/warm throughput and peak memory before choosing defaults; existing 256 MiB warm-input measurements are not staged qualification.
  - Fresh-process inspector measurement tooling (`c25192a2`): a separate read-only Windows Release process per retained synthetic
    file measures first/repeat wall/CPU time and cumulative process peak working set. Source/corpus hashes and measured assembly
    hashes are checked; staged classification never audits/caches an outcome, and inputs remain unchanged. Policy stays at 20 MiB/
    five seconds. The [first measurement run](evidence/2026-10-13/t9-inspector-metrics2-retained-result.json) builds at 0 warnings/errors
    and passes 12 plaintext/Word/spreadsheet cases (1/20 MiB decoded text, clean/EOF CPF), with both scans per case. Twenty-MiB first
    scans take 1.265–1.964 seconds, repeats 0.776–1.004 seconds; observed cumulative process peaks are 41.5–49.9 MiB. Word/Excel
    fixtures are highly compressed 21–22 KiB packages containing 20 MiB text, not 20 MiB package files. The first 1 MiB/16-page PDF
    case is Blocked with inspection_timeout at 5.022 seconds and peaks at 148.5 MiB; the PDF CPF case was not run. No failure/limit
    was relaxed. These are inspector-only observations: filesystem cache is uncontrolled, no publisher copy/policy I/O is measured,
    and cold-filesystem, hostile-parser, protected and complete-format qualification remain open. No default has been chosen/changed.
  - Bounded per-worker PDF text replay (`a7aaabc6`, PDF-only correction `f4be7e09`): retain at most four MiB
    of extracted PDF characters inside one staged worker, usable only after complete extraction EOF. Later detector passes keep the same precedence/masks on those exact
    characters; overflow abandons/clears the replay and follows the existing full streaming passes. Disposal clears the character
    buffer, including failure/timeout worker completion. Plaintext/Office retain their fresh readers. There is no persistent text or cached approval, and legacy behavior,
    candidate limits, policy deadlines/size limits and worker ownership remain unchanged. Nine controls cover fragmented reads,
    full detector parity, capacity/overflow, abandoned/late-failing extraction, scalar/EOF/cancellation and owner disposal. This bounds
    the added replay storage; it does not bound the underlying PDF/ZIP/XML parser. The
    [first replay matrix](evidence/2026-10-13/t9-text-replay1-retained-failure.json) compiles at 0/0 but fails seven normal Debug user
    cases: six unchanged plaintext controls require multiple fresh readers, and the new late-failure fixture omitted its synchronous
    reader implementation. The correction preserves those assertions, restricts replay to PDF and fixes the fixture. Its
    [first corrected matrix](evidence/2026-10-13/t9-pdf-replay2-retained-failure.json) passes 1,125/1,125 normal Debug cases, then normal
    Release fails only the unchanged staged missing-cache spreadsheet formula control (UnsupportedFormat became Timeout).
    All nine replay controls pass in both executed profiles. The
    [complete identical-source retry](evidence/2026-10-13/exact-agent-matrix-t9-pdf-replay3-summary.txt) passes 1,125 normal/1,495 feature
    tests per Debug/Release profile, exact discovery/execution coverage, no skips, 0 warnings/errors and both verified Release packages.
    All [21 scoped controls](evidence/2026-10-13/t9-pdf-replay3-controls.json) pass per profile: nine replay, six unchanged strict
    plaintext-reader and six PDF streaming cases. No assertion, budget, timing limit or test filter changed; original failures remain retained.
    Corpus-reuse tooling (`c351236e`) verifies the retained archive, manifest
    and every fixture byte/hash before copying; its offline reuse control passed, so before/after inputs stay identical.
    [Headroom preflight](evidence/2026-10-13/t9-text-replay1-preflight.host.json) stopped before delivery;
    [scoped recovery](evidence/2026-10-13/t9-text-replay1-headroom.host.json) removed only two hash-verified unpacked duplicates,
    preserving source/packages/manifests/raw evidence. The
    [corrected preflight](evidence/2026-10-13/t9-pdf-replay2-preflight.host.json) passes without further cleanup/configuration changes.
    [Retry headroom recovery](evidence/2026-10-13/t9-pdf-replay3-headroom.host.json) removes only two verified old completed lifecycle
    unpacked duplicates; their source/packages/manifests/evidence remain retained.
    No product pair was installed or booted.
    The [isolated byte-identical measurement rerun](evidence/2026-10-13/t9-inspector-metrics3-result.json) passes all 14 cases and both
    scans per case, with input, corpus/archive, measured assembly and policy hashes verified. The same clean 1 MiB/16-page PDF that
    previously timed out now approves in 1.517 seconds, repeats in 0.868 seconds; the EOF-CPF counterpart blocks in 1.583/0.817 seconds.
    PDF cumulative process peaks remain 148.3–153.7 MiB. Twenty-MiB plaintext/Word/Excel first scans take 1.388–1.884 seconds,
    repeats 0.789–1.194 seconds, with 41.4–49.7 MiB observed peaks. These are single retained measurements with uncontrolled
    filesystem cache, not paired statistical latency gates, publisher costs, hostile-parser bounds or protected qualification.
    PDF runtime improved without policy/default changes; its parser-memory and complete-content findings remain open.
  - Large-plaintext component controls (`c2dd8033`, complete matrix at `6b13ce8f` above): real 1/20 MiB ASCII snapshots are read
    completely on first/repeat scans under the unchanged 20 MiB/five-second default. Clean and EOF-only CPF cases prove approval/block,
    complete reader disposal, no cache/audit shortcut and unchanged source SHA-256. Malformed UTF-8/16/32 tails refuse approval,
    including the no-detector extraction path. Isolated 8/64 MiB logical readers measure collected live scanner-state growth at read
    checkpoints, using no source-sized body; these are not process-peak, cold filesystem-cache, all-format or protected measurements.
    The [first large-input matrix](evidence/2026-10-13/t9-large-text1-retained-failure.json) failed the existing malformed Excel-comment
    control when ReadOrParse became Timeout. Its identical-source [retry](evidence/2026-10-13/t9-large-text2-controls-incomplete-matrix.json)
    passes every test in all four profiles, then fails feature Release packaging on builder disk exhaustion: neither is a complete
    matrix PASS. Failed raw receipts are preserved; no assertion, timing bound, policy default or test filter changed. Scoped recovery
    verifies/removes eight older unpacked duplicates while retaining source, ZIPs, manifests and evidence
    ([full-disk recovery](evidence/2026-10-13/t9-formula1-preflight.host.json), [headroom](evidence/2026-10-13/t9-formula1-headroom.host.json));
    the fresh complete matrix above passes both test and packaging gates. Protected large-file and memory qualification remains open.
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
    bucket. The follow-ups below replace that lookup, repeated closure scans, live queue lookup and startup duplicate
    indexing; per-destination head resolution and full journal I/O remain separate findings.
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
  - Destination-index follow-up (`5a825944`): live queue cells and startup head duplicate detection now share the
    compactor's ordered full-identity/Windows-leaf comparator. This removes same-parent leaf-hash collision chains from all
    three indexes while preserving alias serialization and duplicate-head refusal. Real private-journal controls exercise
    1k/10k simultaneously retained queue cells, canceled alias waits, distinct case/volume/parent identities, exact zero-cell
    teardown and 1k/10k on-disk head reads with unchanged generation tuples. The
    [exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t11-destination-index1-summary.txt) passes 923 normal/1,293 feature
    tests per Debug/Release profile, exact discovery/execution coverage, no skips and 0 warnings/errors, including all four new
    integration controls in each profile and existing alias/duplicate-head/publication controls. The
    [single feature Release measurements](evidence/2026-10-13/t11-destination-index1-timings.json) acquire/release 10k live queue
    cells in 370.063/38.711 ms and discover 10k real private head files in 6,078.922 ms, preserving every generation tuple.
    Timings include the production read/queue paths but exclude fixture-file construction; they are not a latency gate or
    protected-pair qualification. Per-destination durable-head resolution still scans every head on every request; that
    I/O scaling cost remains an explicit finding. Scoped cleanup of four verified unpacked package duplicates preserves
    prior source/packages/evidence ([preflight](evidence/2026-10-13/t11-destination-index-preflight-cleanup.stdout.txt),
    [extra headroom](evidence/2026-10-13/t11-destination-index-headroom-cleanup.stdout.txt)). No product pair was installed or booted.
  - Fresh head-read batching (`c911d5d0`): startup discovery and each destination resolution now read bounded batches of at most
    eight heads concurrently per journal. The journal gate remains held; every started reader finishes/disposes before batch failure
    returns. Single-file reads avoid worker scheduling. Complete fresh validation still covers every head, including unrelated files:
    owner/ACL, no-follow/single-link/size, JSON schema, full identity/storage filename and alias conflicts are not replaced by a cache.
    New real-file controls measure 1k/10k lookup paths, corrupt an unrelated head after a successful lookup to prove it still refuses,
    and prove parse failures drain readers with exclusive leases on every file before recovery; cancellation leaves the journal usable.
    The [exact Windows matrix](evidence/2026-10-13/exact-agent-matrix-t11-head-reads1-summary.txt) passes 995 normal/1,365 feature tests
    per Debug/Release profile, exact discovery/execution coverage, no skips and 0 warnings/errors. All seven destination integration
    cases (three new) pass in each profile. [Single full-read measurements and the retained sequential baseline](evidence/2026-10-13/t11-head-reads1-controls-timings.json)
    report feature Release discovery of 10k real heads at 3,360.008 ms (the preceding `t9-preparation3` run measured 5,536.233 ms),
    and a 10k-head lookup at 4,501.360 ms. The 1k observations vary between runs; these are suite measurements, not controlled paired
    benchmarks or latency assertions. This reduces observed long-scan elapsed time while preserving integrity, but every lookup still
    reads O(number of durable heads): the asymptotic I/O cost, full journal scaling and final-pair review remain open.
    [Scoped preflight cleanup](evidence/2026-10-13/t11-head-reads1-preflight-host.json) preserves completed source/packages/evidence.
    No protected pair was installed or booted; this change remains local while the earlier source/evidence push approval is pending.
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
  - [x] [Design draft](T21-USB-REMOVABLE-DESIGN.md) (2026-10-13, Astra): NTFS-first envelope, local private staging, two lifetime proofs
    for surprise removal, automatic remount reconciliation, decisions D1–D7 and native controls.
    [Independent Sol 6.1 xhigh review](evidence/2026-10-13/t21-design-review-sol61.md): REVISE — select a routing owner that survives
    removal for live upper streams; couple each external-copy exposure to current shared-head eligibility. Revised (StageFs routing
    owner, range admission coupled to head eligibility, device-resource ACK contract); independent re-review pending.
  - [ ] Record owner decisions on supported filesystems/removal behavior, explaining what users notice under each option; obtain Sol 6.1 xhigh design review.
  - [ ] Design automatic remount reconciliation after surprise removal; retain the exact identity/generation hold until verified.
- [ ] Implement only the approved scope; keep unsupported combinations disabled.
- [ ] Qualify attach/detach, surprise removal during write/seal/inspection/publication, reconnect and recovery with an independent observer.
  - [ ] Cite matched-pair results, destination-byte observations, Verifier and separate VM restoration; include the approved scope in M4.

### T22. SMB / UNC

**Problem:** policy UNC strings and provider-normalized paths differ; redirector identity, remote permissions and disconnects need a supported design.
**Done when:** the owner-approved SMB/UNC scope preserves privacy through writes, mapping and reconnect on an actual SMB server,
has independent server-side destination-byte run evidence, and is ready for combined M4 qualification.

- [ ] Complete the dedicated SMB/UNC design before implementation.
  - [x] [Design draft](T22-SMB-UNC-DESIGN.md) (2026-10-13, Astra): local fixed-NTFS stage, enrolled UNC identity, Kerberos caller
    authority, remote replacement gap and commit options, decisions D1–D13 and native controls.
    [Independent Sol 6.1 xhigh review](evidence/2026-10-13/t22-design-review-sol61.md): ACCEPT WITH CONDITIONS — forced-teardown
    coverage-loss gate, corrected cross-volume retargeting rationale, enumerated diagnostic candidates. Revised; re-review pending.
  - [ ] Cover canonical names, redirector identity, remote authorization, commit ordering and disconnect/retry; record owner choices with user-visible effects and obtain Sol 6.1 xhigh design review.
- [ ] Implement only the approved scope; keep unsupported network capabilities disabled.
- [ ] Qualify an actual SMB server with independent server-side destination-byte observation.
  - [ ] Cite matched-pair results, mapping/reconnect/recovery evidence, Verifier and separate VM restoration; include the approved scope in M4.

### T23. Cloud-sync folders

**Problem:** sync-client writers, placeholders and upload timing can expose bytes before approval.
**Done when:** a real supported sync client uploads only approved content, with independent local and remote destination observation.

- [ ] Write a dedicated design note for client/Cloud Files behavior, hydration and uploads; obtain owner decisions and Sol 6.1 xhigh design review.
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
- [ ] Stop false Degraded notices (owner direction 2026-10-13): retry an `ERROR_RETRY` coverage answer briefly before reporting
  Degraded; T4 short rows log 12–21 `CoverageQueryFailed` notices each ([analysis](evidence/2026-10-12/t4-coverage-retry-analysis.md)).
  Sol design review first; admission authority, Unknown and real query failures are unchanged.
  - [x] [Design](T18-COVERAGE-RETRY.md): up to three retries (10/20/40 ms) of exactly `0x800704D5` within one poll; nothing held or synthesized.
  - [x] [Sol 6.1 xhigh review](evidence/2026-10-13/t18-coverage-retry-review-sol61.md): ACCEPT WITH CONDITIONS; conditions folded into the design.
  - [ ] Implementation with the review's controls; agent matrix.

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
