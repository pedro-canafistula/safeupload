# SafeUpload MVP status plan

Updated 2026-10-28. **Goal:** replace process-taint enforcement with owned-stream staged writes for every supported protected
destination, keeping unapproved bytes private throughout. M2 is the current milestone, not the completion boundary.
Historical implementation narratives remain in Git history, [POST-MVP-LOG.md](docs/history/POST-MVP-LOG.md), and the local WIP branch noted below.

## Milestone order

| Order | Scope | Status |
|---|---|---|
| M1 | T0–T3: safe to leave loaded | Complete on the recorded M1 pair |
| **M2** | **T4–T11: everyday file work** | **Active; T4 and T5 closed for now (owner, 2026-10-21 plan D1–D3; T5 rows 2026-10-22) on isolation rows with carried items; T6–T11 next** |
| T21 | USB/removable | After M2, before M3 (owner, 2026-10-21); own design, owner decisions, Sol 6.1 high design review and destination qualification |
| T22 | SMB/UNC | After T21, before M3 (owner, 2026-10-21); own design, owner decisions, Sol 6.1 high design review and destination qualification |
| M3 | T12, T14: release configuration and lifecycle | After T22 |
| T23 | Cloud-sync folders | After M3; own design, owner decisions, Sol 6.1 high design review and real-client qualification |
| M4 | T15–T19: combined qualification | Qualify local NTFS and T21–T23 together |
| Later | T20 other Windows builds; T24 ReFS | Outside the current milestone sequence |
| Owner-deferred | T13 production signing/Secure Boot | Test mode remains in force |

USB, SMB/UNC and cloud-sync are required MVP work; they are no longer deferred until after M4. They remain disabled until their
respective support and qualification gates are met and the owner approves cutover.

## Owner decisions

**2026-10-28 (T9) — O3 decided (recommended option).** Owner, in the session: a successful publication, or a completed authorized hand-back, transfers staging accounting responsibility. Its charge leaves the staging budget once a persisted, identity-bound receipt binds it to the exact published/handed-back object. Failed, uncertain or unreceipted promotions stay charged (FullDebitHeld). This matches the existing completed-save retirement. No gate, threshold or assertion changes.

**2026-10-28 (T9) — O1 and O2 decided (recommended options).** Owner, in the session. **O2** (gates increment 4): M2 keeps the existing trusted-service/private-storage boundary. Local SYSTEM/administrators are trusted. Erasure or rollback of SafeUpload's private storage by them is outside the M2 guarantee, while surviving modern evidence with a missing or corrupt marker still holds. A stronger external anchor, if ever wanted, is a separately reviewed post-M2 architecture. **O1** (gates increment 6): the growth wait is bounded at **3 s per application I/O**, measured from the first crossing through sufficient adoption, reacquisition or recomputation (not per RPC). A joined extent or append race cannot renew it, and expiry permanently fails that save privately. The approved 120 s allocation/seed interval is unchanged. No gate, threshold or assertion changes.

**2026-10-28 (T9 increment 3) — N-U5-01 component host.** Owner, in the session, chose the recommended option: N-U5-01 runs on a fresh disposable `win10-debug3` overlay with the reviewed dormant driver and the feature agent, and **no protected folder, actor or protection policy**, under runtime Verifier `0x13B`. It runs serially with both builders idle, the overlay is discarded, and restoration is checked separately. This is the design's "separately authorized native component host" (8.7.4). It is not the protected first boot and qualifies nothing. The protected first boot follows on another fresh overlay, after N-U4-06 and N-U5-01 pass. Builders are not component hosts. No gate, threshold or assertion changes.

**2026-10-28 (M2 continuation) — focused timing diagnostic and persistent goal.** Owner: "Yes, and set a goal to finish M2 so that you don't stop."
This approves the prepared 14-case Debug/user timing diagnostic from `afd972ef` after the recorded repeated-failure stop, and continuing towards the agreed M2 completion scope.
The persistent goal is active. Keep the existing assertions, lab stop rules, scope deferrals, runtime gates and separate owner merge/cutover decisions; the goal does not waive them.

**2026-10-27 (M2 execution) — seed wait approved; test transparent MOTW completion first.** Owner, in the session: "1. Agreed / 2. Yes, test that first. Go, start following the plan."
The opener of a large existing file may wait up to **120 s** for allocation/seeding, using one monotonic issuance-to-adoption deadline; expiry fails closed with a diagnostic distinguishing
timeout from exhausted storage. Late or uncertain allocation stays charged until exact resolution; this changes no inspection deadline or recovery authority. For T8, first test whether
real Edge downloads and downloaded-file copies can supply transparent whole-version completion evidence. No broker, extension, new UI step or unsupported-client refusal is selected.
Execute T9 budgets → publication/reopen → metadata/MOTW → integrated app acceptance → final-pair qualification → review/PR, with metadata/MOTW feasibility work alongside T9.
The agreed deferrals, current gates and lab boundaries remain in force; owner merge and cutover remain separate.

**2026-10-22 (T8 discovery 1) — publication-window wait yes, folders not now.** Owner, in the session, on [discovery 1](evidence/2026-10-22/t8-discovery-1.md): (1) an operation on a name whose
publication is in flight waits (bounded, proposed 10 s) and then proceeds instead of failing; design [T8-PUBLICATION-WINDOW.md](docs/design/publication-and-namespace/T8-PUBLICATION-WINDOW.md),
independent review before its first boot; (2) folder rename/delete and the Recycle Bin move are not in M2 now (T6 stays postponed; the parity catalog records them as known limits). Work order:
T9 allocation/growing reservations first, then the wait rule, then the metadata contract. No gate or assertion changes.

**2026-10-22 (T8 closure plan) — native-parity bar, Office base image, order and budget.** Owner, in the session ("Agreed") on the recommendations of the
[T8 closure plan](docs/design/T8-CLOSURE-PLAN.md): (1) one new Office base image is derived from the current `win10-debug3` baseline (Microsoft 365 Apps,
7-Zip, Edge settings; the owner signs in to Office once; the existing base stays untouched; every row takes a fresh disposable overlay with the usual
restoration); (2) T8's "done when" adds the native-parity bar: the same standard user, operation and application-visible state as in an unprotected control
folder on the same volume, the agreed metadata, and zero unexplained deny-ring refusals, with every found bug kept as a permanent catalog case;
(3) order: everyday parity (harness, discovery sweep, fixes) first, metadata/Mark of the Web in parallel without blocking it, both required for M2;
(4) discovery runs with the product-default budget on and off, qualification waits for T9's growing reservations. Decision 5 of the plan (browser/Explorer
Mark of the Web user-visible behavior) stays open until the native spike shows whether a transparent completion witness exists.

**2026-10-22 (T5 raw samples) — a racing ERROR sample is superseded by the next valid sample.** Owner, in the session, on `m2t5ord10`–`m2t5bov18`
([T5 checkpoint](evidence/2026-10-21/t5-checkpoint.md)): about 5% of raw samples taken while the actor or the agent is mid-operation fail because a name
appeared or vanished between the independent reads or the raw metadata lagged, so no row could pass by chance. Chosen, in three steps: (1) an ERROR sample is
accepted when the very next sample of the same case is fully valid; (2) the successor may be in the next phase of the same case; (3) a deny-list: in `ActorRunning`,
`WorkflowSettlement` and `AfterActorAcknowledgementSettlement` any ERROR sample is accepted that way unless it carries forbidden bytes, a baseline or parent identity
mismatch, unexpected directory entries, incomplete artifacts or a module FAIL/VIOLATION verdict; the control gates and the final `AfterActorOutcomeSettlement`
bracket stay fatal. Every ERROR sample stays in the result and `T5RawErrorsSuperseded` counts them. No byte, privacy or identity assertion changed.

**2026-10-22 (process) — push each commit.** Owner: "Don't keep commits local, keep pushing." `feat/driver-m2` is pushed fast-forward after every commit; a pending
review gates the VM boot, not the push.

**2026-10-21 (T5 deletes and samples) — native DeleteFileW for regular files; bracket reads.** Owner, in the session, chose both
recommended options after `m2t5ord8` ([T5 checkpoint](evidence/2026-10-21/t5-checkpoint.md)). (1) `DeleteFileW` opens with
`FILE_OPEN_REPARSE_POINT`, which `T5-UX-NAMESPACE-GAP.md` item 2 keeps on staged admission, so `del`, `Remove-Item` and Explorer's
permanent delete of a published protected file fail "Access denied". Such an open takes the native NTFS route when the opened object is
not a reparse point; a real reparse point is closed and refused as today. Design delta and Sol 6.1 high review precede kernel code;
T5's "both DeleteFileW calls succeed" requirement stands. (2) Raw samples taken while the actor runs bracket the capture with public
reads before and after; the raw image must match one of them and any change between them must be known approved bytes. Gated samples
keep the strict rule; every read is retained; unapproved bytes in a raw image still fail.

**2026-10-21 (T5 rows) — budget-off isolation rows until the T9 fix.** Owner, in the session, chose the recommended option: T5 rows run with
the staging budget disabled as isolation rows, as T4 did, because a save right after the file dialog deletes its test file can be refused
by the known T9 whole-allowance reservation defect ([T5 checkpoint](evidence/2026-10-21/t5-checkpoint.md), `m2t5ord7`). The budget-on T5
rows are rerun after the T9 fix. No gate, threshold or assertion changes; this amends the "product defaults" clause of D2 above.

**2026-10-21 (M2 scope) — five items postponed out of M2.** Owner, in the session: "Ok, I agree with the suggested postponements."
(1) T6 directory moves into protection → after M2; meanwhile such a move is refused, while folder copies and single-file moves work (the
existing MVP limit). (2) `.7z` inspection → after M2; `.7z` files saved into protection stay blocked as uninspectable. (3) T9 cold/warm
throughput and latency measurement → M4; hostile-input peak-memory and capture/storage/parser bounds stay M2 requirements. (4) T11 journal
packing/compaction beyond what the protected 10k workload needs → after M2 (as the 2026-10-17 rule); crash recovery and its barriers stay.
(5) The T5 D1–D6 namespace edge-case matrix beyond the everyday cases (D3 above) → M4. Not postponed: raw-volume byte proof, the three
Verifier modes, the T9 budget fixes, the T8 metadata/MOTW contract and the final adversarial review. No gate or assertion changes.

**2026-10-21 (order) — T21 and T22 before M3.** Owner, in the session: "I want them done before M3." The order is now M2 → T21 (USB/removable)
→ T22 (SMB/UNC) → M3 → T23 → M4; T23 keeps its place after M3. Gates, scope and the "do not implement in M2" rule for T21 are unchanged.
Consequences: both accepted designs build on the T5 bound-head profile and on service-independent mandatory teardown, so the items the T5
plan (D1, D3) moved after M2 become T21/T22 prerequisites; T21 needs owner decisions D1–D8 and T22 needs D16 before implementation; the
release configuration and install/upgrade qualification (M3) come later.

**2026-10-21 (lab images) — reproducible lab VMs for colleagues; Terraform adopted for their hosts.** Owner, in the session: asked for images of the
lab VMs so colleagues can replicate the Windows build, preferably with Terraform and Ansible, with personal information and cached sessions removed, from a clean
Windows 10 ISO; then "Let's not wait for the T5 checkpoint, I downloaded an ISO and I want to have the same environment as my colleagues, so I must be the first
to set it up." This starts the Packer/Ansible work that the 2026-10-13 decision deferred until after the T5 checkpoint, and adopts Terraform for creating the
VMs on colleagues' libvirt hosts (the earlier "Terraform is not adopted" decision concerned the lab host). Rules kept: nothing is applied to `win10-debug3`, its
base disk, its XML or the `run-disk.sh` overlays; images are built from pinned, hash-checked media and carry no accounts, keys, certificates or caches; the image is a
development candidate, not the qualified target (the harness keeps checking the qualified machine's name and UUID). Media: `Win10_22H2_EnglishInternational_x64v1.iso`
(SHA-256 `edc53c5c...`, install image SP build 2965). Recipes in `lab/`; builder images and Office are later work. A first build runs only when no timing-sensitive
matrix or row is running on the host.

**2026-10-21 (lab portability) — Linux testing and local Hyper-V for Windows colleagues.** Owner selected local Hyper-V;
no Hyper-V test host is available. After the repeated Public-profile stop, owner approved the candidate-only fix and fresh
runs ("Yes I mean"). Build K passed the full Linux build and Terraform first-boot/acceptance/reboot/destroy lifecycle after
fixes to OOBE account handling, secret cleanup, seed certificate import and guest acceptance. Owner then postponed the
Hyper-V part; its VHDX is exported and byte-verified but never booted. `win10-debug3` remains off with unchanged inactive XML.
[Results and remaining checks](../lab/VALIDATION.md).

**2026-10-21 (T5 plan) — close T5 for now on the shipped (unbound) profile.** Owner, in the session ("I agree, go") on the T5 plan:
(D1) T5 closes on the unbound MVP profile the pair ships; the bound-head profile (`wt/t5-batch2`, runtime NotReady) and its caller-grant /
seed read-export / descriptor / generation-ordering item move to the post-M2 hardening list, after a no-VM source check that the shipped
profile keeps the caller's grants and never hands back unreadable seeded bytes. (D2) One extended T5 row (`Invoke-StageNotepad.sh`) in
ordinary, runtime-Verifier and boot-Verifier modes; Explorer cases drive the shell file operations, real Notepad stays UI-driven, and the
owner's hands-on Notepad/Word/Explorer test covers the UI gap. (D3) Carried to the final M2 pair: service-independent unload/teardown
qualification, the Word rows (with T8), and the `T5-UX-NAMESPACE-GAP.md` D1–D6 edge-case matrix beyond the everyday subset. The row runs on
the T4 pair (`d1068cc3` + `586ae7cb`) with product defaults (staging budget on); no gate, threshold or assertion changes.
(D1 follow-up, owner 2026-10-21, option A) The unreadable-seed check on the shipped path accepts read access Windows grants through a group: the verdict is the
process-primary token's AccessCheck on the held source plus the medium-integrity / unelevated / unrestricted / recipient checks; a writer without proved read access still
gets no hand-back of the old bytes. The stricter direct-account-ACE rule was dropped.

**2026-10-21 (later) — T4 pool endpoint band 128 KiB, future rows only.** Owner, in the session: "Ok I choose 2, but only to future
rows" (option 2 of the [endpoint analysis](evidence/2026-10-20/t4-checkpoint.md#endpoint-decision--2026-10-21)). The after-idle endpoint
band of `T4PoolFlat`/`T4PoolEndpoint` is 128 KiB for rows run from 2026-10-21 on; the slope limit (<4 B/cycle from cycle 1,000) and
every other gate are unchanged. Earlier receipts, including `m2t4bvoff1`/`m2t4bvoff2`, keep their 64 KiB FAIL verdicts and are not
re-judged. Not established: which files the ~24 extra writer-registry entries belong to and whether the step repeats per idle period.

**2026-10-21 — T4 closed for now.** Owner, in the session: "Record, push, and close T4 for now." Closed provisionally on the pair kernel
`d1068cc3` + agent `586ae7cb`: smoke `m2t4smoke1020j` 256/256; one-boot 10k rows with the staging budget disabled (isolation, approved
2026-10-20): ordinary PASS (`m2t4ordoff1`), runtime Verifier PASS (`m2t4rvoff3`), boot Verifier all functional gates PASS twice with
`T4PoolFlat` over the 64 KiB endpoint band (band for future rows decided above); raw-volume cells with zero forbidden bytes but not MVP-gate PASS.
No gate, threshold or assertion was changed or waived. Carried to the final M2 pair: a boot-Verifier 10k row under the 128 KiB band; raw-cell harness modernization
for C01–C04/B01/B02/X01 in three modes (BLOCK hand-back evidence, B01/B02 wrapper, X01 execution, dedicated latency, live-taint receipts);
the lost-reply fault row (harness held on `t4/fault-row`); the T9 budget-on defects (completed saves keep 1 MiB, allocation latency growth,
lost allocation reply does not self-heal) that block M2 with the default configuration; the sticky `WriterStateUnknown` family seen in
3 of about 15 boots; the T8 immediate-reopen control. [Checkpoint](evidence/2026-10-20/t4-checkpoint.md).

**2026-10-20 — complete T4 first.** Owner, in the session ("I agree. Now focus on completing T4 asap"), after the review of the
last days and the plan proposed in it: (1) the T4 smoke's immediate-reopen probes run in sequence: the saving process finishes and
closes both of its read and read/write opens, then the second process probes (`T4_REOPEN_ORDER=sequential`). No probe is retried
and no assertion or threshold changes; two programs write-opening one protected file in the same instant becomes a sharing-policy
question for T5/T8 and is not a T4 lifetime result. (2) Growing reservations stay in design review; their implementation follows
T4 and runs in parallel only while no T4 VM row is in progress. (3) The allocation/Prepare lost-reply fault row uses a one-shot
reply drop that exists only in a fault-test build of the same commit (no product hook); built during the 10k rows, reviewed
before it runs. (4) Workers: at most two Sol 6.1 high fast workers at a time. T4 rows run with both builder locks held.
Order: diagnostic smoke without reopens, harness gate, smoke with sequential reopens, unchanged 10k in ordinary, runtime-Verifier
and boot-Verifier modes, raw-volume cells, lost-reply row, separate restoration after each row.

**2026-10-20 (later) — T4 isolation rows.** The first 10k row (boot Verifier, budget on) failed at cycle 326 on T9 accounting: allocation latency
growth/tails, a lost allocation reply that does not self-heal, and completed saves that keep a 1 MiB charge forever (see the
[checkpoint](evidence/2026-10-20/t4-checkpoint.md)). Owner approved running the T4 kernel-lifetime rows with the staging budget disabled
(`T4_STAGE_SPACE=off`, the 2026-10-12 configuration): an isolation result recorded in every receipt, not a product-configuration
qualification. The accounting defects stay open under T9 and block M2 with the default configuration.

**2026-10-19 — T4/T9 growing reservations.** Owner approved replacing the single-active-file resource allocation rule with
reservations that grow as files grow, keeping the approved total/per-user budgets, free-space floor and large-file support.
Replace the obsolete single-concurrent-winner strategy test with concurrent no-overspend controls; preserve all privacy,
resource, sharing and qualification assertions. Users should be able to save Word temporary files and overlapping small files;
real budget exhaustion still refuses the affected save. [Design](docs/design/large-files/UX-LARGE-CONCURRENCY.md) and independent security/lifetime
review precede implementation. This approves no sharing-policy change or cutover.

**2026-10-17 — current goal is M2 everyday file work.** Owner supplied the M2 goal file: one matched pair, staging under runtime gates,
interactive standard user `t5actor` on win10-debug3; real Notepad/Word/Excel/PowerPoint/PDF/ZIP and Explorer file/folder/empty workflows,
clean exact publication and CPF/CNPJ/card block/tray/hand-back, no false Office alerts, packaged/autostart tray, corrupt-recorder recovery,
service restart and installer/updater resilience. All T4–T11 rows, existing 69 cells and new rows in ordinary/runtime-/boot-Verifier,
independent bytes, separate restoration, T3 workloads/U01, final adversarial review, and one PR to main with green CI are required.
Owner merges and approves cutover. Keep the Office-equipped dev disk; qualification uses fresh run disks. Dev builds may be unreviewed,
with one review per coherent kernel delta before qualification; focused feedback now, full gates at checkpoints. Keep ≥4 GiB host
memory available and shut idle VMs; first-free approved builder, one job each; branch pushes are fast-forward to feat/driver-m2 only.
Statuses include T-item checkbox trees, app results, commits/evidence and BRT times. Latest direct effort preference remains Sol high.
Batch 3/compaction/V30 outside a user-visible defect, 10k leak/cap refusal or crash are post-M2 hardening, never a prerequisite here.

**2026-10-17 — delegated work uses Sol high.** Owner: use only Sol high agents, with no fast tier for now. This supersedes the prior
xhigh default for new reviews; earlier reports retain their original model/effort provenance. Ordinary implementation stays with Codex.

**2026-10-16 (evening) — M2 user experience first.** Owner goal: M2 is done when real apps work as standard user `t5actor` on one
matched pair with staging enabled (Notepad, Word, Excel, PowerPoint, PDF, .zip, Explorer copy/move/rename/delete/folders), plus T4
and the T6–T11 rows; dev builds may be installed unreviewed on win10-debug3's dev run disk (one fresh Sol 6.1 xhigh review per
coherent kernel delta before the first qualification boot). Owner decisions: Office owner files (`~$*`) are inspected as plain
text instead of refused; an attribute holding exactly one 20-hex-digit PANOSE code is skipped. Batch 3, compaction and V30 continue
only where they fix a user-visible failure, a 10k leak/cap refusal or a crash; the rest (and the parked T6 census branch
`wt/t6-dirs` 5b9c868c) moves to a post-M2 hardening list. Dev line: `demo/apps` (MVP line + UX fixes, merged with
feat/driver-m2 at `d104d994`). Orchestrator design calls for the unbound profile (recorded for review): a no-content-write open
of a published file is native; deleting or renaming a published file is native NTFS, cancels unpublished versions waiting for
that name and refuses (sharing violation) while a writer holds one; a private rename retargets its pending publication; renaming
an unmonitored file to a monitored name is refused as not-same-device (copy, inspected); folders: create native, rename/delete
native when nothing under them is pending (else busy), moved in from outside = not-same-device. Owner decision (option A): PowerPoint's
package-root thumbnail (`docProps/thumbnail.jpeg`, rendered from slide 1) is accepted without OCR; images anywhere else stay refused.
T9 resource defaults (owner, 2026-10-16 16:10 BRT, recommended values accepted): no fixed per-file staging cap; total staging budget
min(32 GiB, 10% of available space), per user min(8 GiB, total/4), free-space floor max(1 GiB, 5% of the volume); a save beyond a budget
fails closed with a "not enough staging space" reason and alert, without affecting other users.
  Dev line state 2026-10-16 17:20 BRT (`demo/apps` b59ea08e; unreviewed dev builds, owner-approved): every listed app workflow passes as
  t5actor on driver `ux-k8` + agent of `2ed2b20b` (Notepad, Explorer copy/move/rename/delete/new file/folders, Word Save As + read-write
  open + edit/save, Excel, PowerPoint, PDF, ZIP; CPF blocked with the tray card; service restart survives) —
  [evidence](evidence/2026-10-16/demo1/) `test-ux-k8-*.txt`. Windows agent matrix `ux-m5-diag` 2,604/2,604 + 25/25 both. Merged branches:
  ux/kernel (native namespace ops), ux/dirs (folders), ux/outside (outside refusals), ux/activating (writer promotion liveness),
  ux/fix1, ux/allocfault (lost allocation replies), ux/journal (archive scaling, read-free terminal recovery), ux/meta + ux/meta2
  (metadata, partial), ux/large (opt-in), ux/t11 (SOP startup proof, compaction retention, [review checklist](docs/reviews/M2-REVIEW-CONDITIONS.md)
  once merged to this branch). T4 `uxk5t4ord2` stopped at cycle 548 (journal scan O(n) -> reply timeout -> stranded name; receipt kept);
  rerun `uxk8t4ord` in progress. Dev-disk shutdown freeze = OneDrive DebugBreak into the absent kernel debugger (not SafeUpload).

**2026-10-16 — T9 large-file product defaults and upgrade.** Owner accepted total staging budget min(32 GiB, 10% of
available space), per-user min(8 GiB, total/4), free-space floor max(1 GiB, 5% of volume); resource refusal is fail closed
with a staging-space alert, isolated per SID, with no fixed per-file staging cap. Follow-up authorizes `StageSpace.Enabled`
to default true, runtime formulas with explicit overrides, a measured parser memory default, suitable inspection defaults
and safe existing-install migration. `ux/large` implementation on base `a2b67984`: [design](docs/design/large-files/UX-LARGE.md),
[local receipt](evidence/2026-10-16/ux-large3-local/result.md). Pending legacy stages are charged under their original guard;
completed history stays compatible. Runtime readiness gates and Windows/pair qualification remain required.

**2026-10-16 — MVP pair now, batch 3 in parallel.** Owner, in the session, after the [critical-path plan](evidence/2026-10-16/t5-critical-path-plan-sol61.md)
(full T4/T5 to M2 standard: 180–310 worker-hours plus 30–50 lab hours): "MVP now + batch 3 in parallel". An MVP pair is cut from
the last booted line (`t5-pair14`, `b97d263e`; its 10k row reached 9,998/10,000 with no blocked bytes, no cap refusal and no
Verifier hit) plus the two 10k fixes (agent journal-replace retry and op13/op15 retry-not-refusal; kernel SOP witness detach after
one focused Sol review), then T4 smoke/10k/raw cells and the T5 Notepad/delete rows in three modes. Documented MVP limits: 16 MiB
stage cap, restart-time bookkeeping stays held (fail closed), the journal keeps one manifest per save, folder moves refused. Batch 3
continues on `wt/t5-batch2` along the critical-path plan and replaces the MVP pair when qualified; MVP VM rows have priority for
builder-free windows. Then M3 and the USB/SMB designs.
  MVP track (`wt/mvp-pair`): `0d0ae2a6` journal retry + SOP witness detach, focused review REVISE (declaration order) fixed in
  `47882864`, PREfast C6297 in `9e392df3`; WDK `mvp-k3` PASS; matrix `mvp-m1` all green except one Release case of the pre-existing
  rare publisher stall (receipt kept; `mvp-m2` rerun for the feature package). Demo VM (`demo1`, t5-pair14) findings
  ([evidence](evidence/2026-10-16/demo1/)): direct saves and Explorer copy/move of `.txt`/`.docx` publish clean and block CPF after a
  fresh boot; Word direct save is refused (FileBasicInformation/compression/object-ID/temp-file operations unsupported; T8); an
  installer pushed the driver into its fail-closed state until reboot. Kernel attach-key race ([RCA](evidence/2026-10-16/demo1/copy-rca-sol61.md))
  fixed in `6bda78ef`: review ACCEPT WITH CONDITIONS, WDK `mvp-k4` PASS. Next: MVP VM rows after the owner's demo.
  Demo build (owner-approved, local branch `demo/apps`, not reviewed; [evidence](evidence/2026-10-16/demo1/)): `dabb5478` waits
  (bounded 10 s, no lock held) for the op19 handle receipt before a private delete/rename; with it Notepad Save As (create, close,
  DeleteFile probe), Explorer copy/move/new file and Word direct save pass as a standard user (`demo-k1`, imports PASS). T5 input:
  a rename within ~0.1 s of create publishes under the old name; a public rename keeps the old name too; a public delete reports
  success but the file stays. T8 input: Word's default theme/font table PANOSE codes (20 hex digits) give PaymentCard false
  positives on every new `.docx` (demo VM policy v2 disables cards; product fix needs an owner decision on skipping exact PANOSE
  values). Agent: `Restart-Service` alone fails transfer-journal init (access denied; reboot works); a corrupt notification record
  (`tail differs from durable head`) suppressed all notifications until reset. Tray app installed from source for the demo.

**2026-10-16 — moves into protection get cross-drive metadata.** Owner, in the session (recommended option): a file or folder moved
into protection, which SafeUpload turns into a cross-drive-style copy, ends with what Windows gives a move to another drive: the
files inherit the protected folder's permissions (an explicit source permission is not carried over) and keep the dates Windows'
cross-drive move keeps. This is the metadata reference for T6 moves under the T8 contract; it closes T6 design review finding 1.

**2026-10-16 — T8 metadata contract, Mark of the Web, PowerPoint/archives in M2, images after M2.** Owner, in the session, chose
the recommended option of each question ([T8 memo](evidence/2026-10-16/t8-metadata-contract-sol61.md), [T9 gap plan](evidence/2026-10-16/t9-gap-plan-sol61.md)):
1. **Metadata:** a published file carries what Windows gives the same caller's operation without SafeUpload: owner/group, DACL
   (only the accepted moved-file `0x0400` marker differs), SACL, integrity label, creation/last-write/last-access times and
   attributes, revalidated at commit (no stale replay over a later authorized change; the `m2t10rv6` lost admin ACE is a defect).
   `ChangeTime` is the publication time. M2 refuses, with a clear reason, EFS-encrypted, offline, extended-attribute, reparse-point
   and hard-linked saves into protection; sparse/compressed keep semantic state with complete logical inspection or are held.
2. **Mark of the Web:** `Zone.Identifier` is inspected like content and published together with its file, never visible without
   it; every other alternate data stream stays refused. Browser downloads and copies of downloaded files keep Protected View.
3. **PowerPoint and archives in M2:** `.pptx` slide/notes/comment/chart text inspected like Word/Excel; `.zip`/`.7z` members inspected
   with the existing inspectors, an encrypted archive or an unsupported member blocks the whole archive with a reason.
4. **Images after M2:** images stay refused (blocked with an "images are not inspected yet" reason, handed back). **The Paint row
   leaves M2**: T8 qualifies eight workflows; Paint moves to a later OCR item (Windows built-in OCR, pt-BR language feature).

**2026-10-16 — folders follow the copy rule; idle folder renames; all-zero numbers are not cards.** Owner, in the session, chose the
recommended option of each question:
1. **All-zero card (T9):** `0000000000000000` no longer counts as a payment card (it passes Luhn; CPF/CNPJ already ignore repeated
   digits). Every other 16-digit Luhn-valid number still blocks.
2. **Folder moves into protection (T6), "like copies":** empty folders may be created inside protection; Explorer/PowerShell folder
   moves into protection behave like a move to another drive: every file is copied in and inspected, clean files publish, CPF files
   are blocked and handed back, and the caller removes the source as usual. `cmd move`/`MoveFileEx` of a whole folder fail as Windows
   does across drives. No strict tree transaction in M2. Directory streams/EAs carry no uninspected content (T8 contract).
3. **Folder rename/move inside protection (T6), "allow when idle":** allowed when nothing under the folder has a save, delete or
   recovery in progress; otherwise refused with a try-again message. Short design note and the pre-boot review first.

**2026-10-15 — one 10,000-update checkpoint endurance test.** Owner, in the session: "I accept merging them into one".
`StagedSemanticMembershipV30Tests.Ten_thousand_opt_in_updates_match_the_accepted_foreground_checkpoint_and_durability_arithmetic`
and `StagedCheckpointV30Tests.Ten_thousand_checkpoint_updates_have_fixed_files_bounded_actual_IO_and_one_reconstruction` drive the
same semantic WAL path with identical I/O totals after the default incremental-validation cutover. Keep one 10,000-update endurance
row that carries every assertion of both (exact durability arithmetic, fixed files, bounded actual I/O, one reconstruction) plus the
focused selected/multipart/read-set controls; the merged-away method is listed in `agent-test-removals.authorized`. Confirm the
identical work from the instrumented Windows counters first. Saves ~150–330 s per feature user leg; no threshold changes.

**2026-10-15 — Defender exclusions on the builders.** Builders were slow because Defender real-time scanning (`MsMpEng`) used about
1.6–1.9 of 4 cores on each builder while the test host used about 0.1 (no exclusions). Owner approved exclusions on both builders
only: folders `C:\Users\vika\Documents`, `C:\Users\vika\AppData\Local\Temp`, `C:\Users\vika\.nuget`, `C:\Windows\SystemTemp`,
`C:\Windows\Temp`; processes testhost(.x86), dotnet, MSBuild, VBCSCompiler. Real-time protection stays on; the qualified target
(win10-debug3) keeps Defender unchanged. Afterwards `MsMpEng` used 0–1.3 CPU-seconds per 10 s instead of 16–19.

**2026-10-15 — incremental store validation.** The semantic-store cutover showed every metadata update re-reading and checksumming
the whole store (about 4.1 MB read per update in the 10,000-update test; writes about 28 KB and 3 flushes), a per-save cost that
grows with store size. Owner approved replacing it: each operation verifies only the pages and log records it reads (per-page
checksums, failing closed on mismatch), and the whole store is validated at service start, after any I/O error or hold, and
periodically when idle. This changes an integrity rule of the accepted sizing design, so it gets a design delta and a Sol 6.1
xhigh delta review before the batch-3 implementation.
  Delta `T5-INCREMENTAL-VALIDATION.md` (`e9952b33` on `wt/t5-batch2`; planned test reads about 78 KB instead of 4.1 MB per update);
  [independent review](evidence/2026-10-15/t5-incremental-validation-review-sol61.md) **ACCEPT WITH CONDITIONS**: absence answers only
  from membership metadata of a fully validated recovery or a frontier-durable transaction; idle-sweep snapshots bound to the
  canonical control page plus owner mutation/lifecycle/hold state, with paused-sweep controls for checkpoint reset, failed apply,
  a latched hold and teardown; arithmetic assumptions labelled. The cold coherent-rollback limit stays documented. Joins batch 3.

**2026-10-15 — kernel builds on both builders; no queueing behind a busy builder.** Owner, in the session:
- Option B: the existing test-signing certificate (`A6D6…`) is installed on builder2 too. The owner ran the installation
  (`install-signer-builder2.sh`, outside the repository); builder2 reported HasPrivateKey=True and a Valid test signature, and the
  temporary copies were removed. builder2 now has the kernel-sign role as well as matrix and gate.
- "Never again queue something behind a busy builder when the other one is available": every builder job goes through
  `builder-run.sh` (one lock per builder; the first free builder with the role takes the job).

**2026-10-15 — staging is the product; the staging-out profile is retired.** Owner, in the session: the staging-free "normal"
build (`SAFEUPLOAD_STAGING_PROTOTYPE` / `SafeUploadAdmissionEvidence` off) is no longer a shipping target or delivery gate: without
taint it enforces almost nothing, and nothing ships before cutover. AGENTS.md now reads: "Staging is the product path. Runtime
activation/readiness gates (V30 enablement, NotReady holds, capability gates) stay until qualification and owner cutover
approval; compile-time staging-out builds are retired." This approves no activation or cutover of unqualified staging.
1. Inventory first and report before changing anything (staging-out-only driver/agent paths, normal-only tests per profile,
   normal kernel builds, matrix legs, required lists, scripts, installer/packaging T12/T14, docs; feature test-only hooks a product
   build must not ship, for T12; any dependency of the M1 baseline, a recorded gate or an approved decision on the normal profile,
   which stops the change until the owner decides).
2. Phase 1 now (gates/process only, no source refactor under the batch-3 worker): agent matrix = feature Debug/Release (4 legs);
   kernel = the two feature WDK builds with PREfast/ApiValidator and the import gate; update the AGENTS.md verification table, matrix
   runner, required lists and expected counts with offline self-checks; harness rules apply; no feature-profile test, gate,
   threshold or assertion changes.
3. Phase 2 after batch 3 lands (own branch, one change): staging always compiled in, staging-out paths and normal-only tests
   removed (each listed for the preflight), product-vs-test-hook split folded into T12 with a short design note; lifetime/lock-order/
   teardown kernel deltas join the next pre-boot Sol 6.1 xhigh review.
4. Report as a checkbox tree with commits, evidence paths and the matrix/build time saved.
   - **Phase 1 done (2026-10-15)**, merged into feat/driver-m2 with the approved-builder list and diagnostic continue mode
     (`wt/runner-builders`: `6d6b34c5` gates, `be3db991`/`65b34458` builder2 approval and signing, `bef3c269` self-check fix).
     Verified: PS 5.1 gate [hg-integ2](evidence/2026-10-15/harness-windows-gate-hg-integ2.txt) and
     [hg-merge1](evidence/2026-10-15/harness-windows-gate-hg-merge1.txt); two-profile signed kernel builds on both builders
     ([integ-k1](evidence/2026-10-15/exact-integ-k1-summary.txt) on builder2, [t5-merge1-k](evidence/2026-10-15/exact-t5-merge1-k-summary.txt)
     on builder1, about 2 min each); 4-leg matrix [integ-m1](evidence/2026-10-15/exact-agent-matrix-integ-m1-summary.txt); continue mode
     [t5-batch3q-diag](evidence/2026-10-15/exact-agent-matrix-t5-batch3q-diag-summary.txt) ran all 4 legs after failures with
     `DiagnosticContinue=True`/`AgentMatrixGate=False`. **Time saved:** 4 of 8 matrix legs and 2 of 4 kernel builds per delivery
     round; with the Defender exclusions a feature user leg fell from 3,426 s to 1,158 s (Debug) / 931 s (Release), SYSTEM legs ~7 s
     ([durations](evidence/2026-10-15/matrix-durations-t5-batch3q-diag.txt)); the remaining long test (10,000-update checkpoint,
     990 s) goes with the default incremental-validation cutover, so neither splitting test classes nor 6 cores is needed now.
     **Re-measured the same evening (corrected):** after the cutover three 10,000-iteration tests dominated the leg (Debug user
     1,418 s, [durations](evidence/2026-10-15/matrix-durations-t5-batch3s-diag.txt)); both builders were set to 6 vCPUs (owner's
     conditional OK) and `t5-batch3t-diag` ran 726 s / 581 s ([durations](evidence/2026-10-15/matrix-durations-t5-batch3t-diag.txt)).
     That halving was **not** the vCPUs: without a libvirt CPU topology QEMU presents one socket per vCPU and Windows 10 client uses
     at most 2 sockets, so both builders ran on 2 logical CPUs at 4 and at 6 vCPUs (test counters `cpuCount=2`). The slow run
     overlapped another flush-heavy matrix on the same host disk while the host was near memory exhaustion; per-update cost is
     ~85% flushes ([`t5-batch3u-diag`](evidence/2026-10-15/matrix-durations-t5-batch3u-diag.txt): 17.3 of 20.1 ms, ~5.7 ms per
     flush under load vs 1.3 ms idle). Contention is the working hypothesis, not a measured cause. Both domains now have 1 socket
     × 6 cores (builder2 verified 6 logical CPUs). `matrix-durations.py` now flags guest clock jumps (that run's Release TRX shows
     14,902 s; host elapsed for the whole matrix was 20 min 39 s).

**2026-10-15 — remove process-taint enforcement.** Owner, in the session: remove process-taint enforcement from the product; it
is superseded by staging, and keeping it in code, tests and harness rows wastes development and builder time. The AGENTS.md
invariant "Keep taint enforcement and staging feature gates" becomes "Keep the staging feature gates". Inventory first and report
it before deleting anything (driver, agent, tests per profile, harness/self-checks, VM rows/cases, scripts; what the normal build
will enforce afterwards; any dependency from staging, T7 reads or the qualified M1 baseline, which stops the removal until the
owner decides). Then remove it in one coherent change on its own branch, not under the running batch-3 worker, integrating after
its stage boundary. Removing taint tests is authorized and listed explicitly for the preflight; no non-taint test, gate,
threshold or assertion changes. Kernel: four WDK/PREfast/ApiValidator builds 0/0 and the import gate; lifetime, lock-order or
teardown deltas join the next pre-boot Sol 6.1 xhigh review. Agent: local compile, T5 checks, preflight, matrix. Harness: PS 5.1
gate and self-checks. If the normal build then enforces nothing until staging cutover, that is accepted: nothing ships before
cutover.
- **Inventory and follow-up (2026-10-15).** Taint lives in `Taint.c`, `Filter.c` (table, read marking, tainted CREATE/rename/link
  refusals, pre-taint handle check), `Filter.h`, `Policy.c` (test-disable switch), `Protocol.h` (policy bit `0x20`, coverage bit `0x40`,
  taint counters, promotion-trace field), small staging references, agent `Protocol.cs`/`PolicyBuilder.cs`/`MinifilterPolicyFactory.cs`
  (`ClassifyAllSources` exists only to feed taint)/`AdmissionCoverage.cs`/probe, two agent tests per profile, and the staged harness
  (all 34 cases require the disable flag; `Test-InvariantLiveTaintWindow`; LiveTaint self-check; gate scripts). Without taint the
  normal build no longer stops new sensitive content being copied into monitored destinations; it still refuses write-opens of
  existing sensitive destination files and protected-scope creates while the service is disconnected. No functional dependency in
  staging, T7 or the recorded M1 evidence. Owner: "If there's no taint mechanism, there's no need for a taint absent condition" —
  the cases' taint precondition and live-taint checks are deleted without replacement. Former counter/flag positions stay as
  unused zero slots only to keep the wire layout; nothing asserts them.

**2026-10-15 — second builder and parallel builder jobs.** Owner, in the session:
- **A. Second builder: approved, including the host/libvirt changes needed to create it.** Clone the current builder
  (192.168.122.210, DESKTOP-O1LP5DG) into a smaller VM holding only what an extra builder needs: the OS and the exact toolchain
  (WDK/EWDK, .NET SDK 10.0.400 / runtime 10.0.11, Windows PowerShell 5.1, the warmed NuGet cache, build/matrix prerequisites).
  Remove old `exact-*`/`exact-agent-*`/`harness-gate-*` folders, outputs and evidence copies, zero free space and produce a sparse
  qcow2. Copy only while the builder is idle (no queued/running builder job, no timing-sensitive T4 row); never modify the original
  builder disk or use it as a backing file. Own libvirt domain, MAC, IP and computer name; before both run together, verify no other
  domain shares its guest address; add its SSH host key to known_hosts with StrictHostKeyChecking=yes. Use it first for agent
  matrices and harness gates; signed kernel builds stay on the current builder unless a concrete reason to install the existing
  test-signing certificate is shown to the owner, and the private key is not copied otherwise. Parameterize builder identity/host
  checks (`Invoke-ExactAgentMatrixBuild.py`, `Build-ExactAgentMatrix.ps1`, `Invoke-HarnessWindowsGate.sh`, `remote_ps.py` users)
  to an approved builder list, record the builder identity in every receipt, keep defaults unchanged (harness rules apply). Prove
  parity first: toolchain inventory on both, then the same commit's matrix on both labelled as a parity check, comparing discovery
  counts and outcomes; no gate use until parity passes. Watch host disk with space-guard; keep the clone off the HDD path.
- **B. Workflow rule 6 revised:** "one job per builder" replaces "never two builder jobs at once". Two different builders may run
  jobs in parallel; never two jobs on the same builder or VM target, and no builder jobs on either builder during timing-sensitive
  T4 rows. AGENTS.md lab boundaries updated.
- **Speed-ups started now:** (1) batch 3's single-store/WAL removes the per-test 3,877-file domain bootstrap; after every matrix,
  report the first-leg duration and every test over 60 s, never weakening, skipping or shrinking assertions. (2) An explicit opt-in
  diagnostic "continue past failure" matrix mode that runs all eight legs, prints `AgentMatrixGate=False` plus a
  `DiagnosticContinue` marker, never counts as a gate or qualification, leaves the default exactly unchanged, with offline
  self-checks for both modes. (3) No idle gaps: every launched/resumed worker and builder/VM job gets an immediate background wait;
  a watchdog lists running workers/jobs and flags finished-but-unhandled workers.
- **Optional, propose first:** split a full gate matrix across the two builders (normal on one, feature on the other) only if the
  combined result stays equivalent to today's gate (same commit, identical toolchain inventory, complete discovery/execution
  coverage, no skips), with offline controls proving it.

**2026-10-15 — publication descriptor and receipt sizing.** Owner, in the session:
- **Descriptor: marker-only difference accepted for the moved shape.** "I accept decision 1, it's even better that that flag isn't
  set because it follows the permissions of its previous parent, so it would be a lie." Publication constructs security with
  native inheritance (NULL input in the destination parent) or stored replay, whichever reproduces the expected descriptor exactly.
  Only when neither does, and the sole difference is expected `SE_DACL_AUTO_INHERITED` (`0x0400`) set / stored clear with every
  other byte equal (owner, group, ACL bytes, ACE flags/order, label, SACL `0x0800`, protection and request bits), is the result
  equivalent. No other difference is accepted; no repair, privileged post-set or AccessState injection. Evidence:
  [controls](docs/design/publication-and-namespace/T5-NATIVE-PUBLIC-OPENS.md#descriptor-candidate-controls-2026-10-15) (equal access in all 30 rows; Windows re-marks it on
  the next inheritance operation). Note: the moved file's entries keep their old-folder `INHERITED_ACE` marks in both versions.
- **Receipt slots: commercial pattern approved, ceiling 256.** Owner proposed 256 per in-flight family, asked what a robust
  commercial DLP would choose, and on the answer: "The behaviour of this commercial pattern sound perfect". The pattern:
  - a guaranteed floor (proposed 32 slots per family, about 1.2 MB) reserved at load so recovery and cleanup always progress;
  - further slots allocated on demand at admission up to the 256 ceiling and reused; once admitted, an operation never needs new
    memory to finish;
  - at the ceiling, a save waits briefly (about two seconds, set by measurement) for a free slot, then fails closed with a notice;
  - an administrator-configurable ceiling, high-water telemetry and a warning near the limit;
  - only small state resident in nonpaged memory; bulky request records pageable or on disk;
  - one preallocated, checksummed store file per receipt domain instead of one file per slot, sized when the feature is enabled.
  Exact floor, wait and record sizes come from the design note and measurements; it needs a design note and Sol 6.1 xhigh review
  before implementation in batch 3. The physical byte budget for retained private copies is still to be proposed.
  Design `T5-RECEIPT-SIZING.md` (`ed72734c` on `wt/t5-batch2`): ~343 KB nonpaged at the floor, ~708 KB at the ceiling; 2,000 ms
  FIFO wait then `STATUS_DEVICE_BUSY` and a tray notice. [Independent review](evidence/2026-10-15/t5-sizing-review-sol61.md) **REVISE**:
  per-transaction full-image store writes (136.8 GB per 10,000 saves; the batch-3 metadata checkpoint has the same flaw) must become
  WAL or copy-on-write writes proportional to the change; cancellation handoff, concrete admission bundles and PASSIVE-validation
  lifetime protection must be specified. Revision 2 (`16ee6635`): a bounded redo WAL for both stores (about 0.8 MB per approved and
  1.1 MB per blocked save, upper bound for the planning traces), stable cancellation owners, per-origin admission bundles and
  critical-region rundown; nonpaged ~540 KB at the floor, ~904 KB at the 256 ceiling; receipt file 34 MiB.
  [Delta re-review](evidence/2026-10-15/t5-sizing-rereview-sol61.md) **ACCEPT WITH CONDITIONS**: implement the cancellation state
  machine, allocation-free admitted paths at H=32/256 and the race controls; the design implies about 72 (approve) / 96 (BLOCK)
  flushes per save, so flush counts and foreground and lifecycle save latency must be measured before M2 acceptance, with
  record-level logging or group commit required only if the latency misses the M2 criterion (none is set yet; to propose with
  the measurement). Implementation joins batch 3.
  Test contract (2026-10-15): existing tests that assert the replaced per-slot layout (18 directories, 3,877 files, full-image
  checkpoint I/O) are updated as a deliberate contract replacement under design section 8 and the owner-approved store, not as a
  weakening: each such assertion becomes an equally exact one on the new store (file count, names, sizes, WAL/checkpoint bytes and
  flushes, fault targets); authority/lifetime/closure assertions, test names, workloads and both compaction tests stay unchanged;
  every changed assertion is listed old → new in the batch-3 progress record and reviewed before it is taken.

**2026-10-14 (evening) — retained residue and the test base.** Owner, in the session:
- **Retained never-exposed residue: exception accepted.** Proved service-owned residue (exact custody, charged storage, ancestry and
  nonpublication obligations, as specified in [T5-RECOVERY-HOLDS.md](docs/design/publication-and-namespace/T5-RECOVERY-HOLDS.md)) does not veto voluntary unload; the
  bytes stay private and keep their storage charge. Residue without that proof still vetoes. This replaces the conservative default.
- **Edge self-update on the test base: approved to disable** to improve measurements. A new base layer on win10-debug3 disables
  the Edge Update services and scheduled tasks; the previous base stays untouched underneath as its backing file (rollback:
  point the domain back at it). Windows itself and every other component are unchanged.
  Done: win10-debug3 now boots `win10-debug3.base-20261014.qcow2` over the untouched `win10-debug3.base-20261009.qcow2`
  (mtime/size unchanged); `edgeupdate`/`edgeupdatem` Disabled, both `MicrosoftEdgeUpdateTask*` tasks Disabled, EdgeUpdate policy
  `UpdateDefault=0`; Edge stays 154.0.4258.62; Windows 10.0.19045.2965 unchanged; clean shutdown
  ([receipt](evidence/2026-10-14/win10-debug3-base-20261014-edge-update.txt); a first attempt rolled back safely on a CRLF check).
  Fresh-run-disk baseline [BaselineClean=True](evidence/2026-10-14/base20261014verify-baseline.txt), independent restoration PASS.
- **Refusal receipts: no durable receipts (owner agreed).** A repeated allocation request only happens after the application's
  CREATE already failed (`StageStream.c` `StageRetainAllocationReceipt`: the worker replays the request to learn whether a private
  allocation exists, then issues exact kind-5 cleanup), so the repeat asks "is there a leftover private file to delete?", never
  "may this save proceed?". A refusal creates nothing and is answered statelessly under the current policy; a later "yes" for that
  dead request is deleted by the existing exact cleanup; only answers that create something are durable. This removes the refusal
  files, the budget decision and the reboot/retirement question. Condition for the independent review: a "yes" for a dead request
  must claim nothing that outlives its cleanup (for example a destination generation that would reorder later saves); if it does,
  that claim gets the exact cleanup, not a receipt.

**2026-10-14 — workflow rules.** Scope, gates and the qualification plan are unchanged; these rules shorten defect loops for the rest
of M2. Classes they target: compile-blind matrix rounds (`t5-rename1`, `t5-block1`, `t5-diag1`), test mistakes found only by the matrix
(`t5-rename2`, `t5-rename3`, `t5-rename5`, `t5-block2`), kernel–agent contract defects found only by boots (`m2t5boot8`, `9`, `11`/`12`,
`13`, `14`), and process slips (three timer rejections without a design note, worker self-reviews reported as independent, a worker
editing this plan, a Codex resume switching Sol to Astra).

1. **Local compile before any builder run.** A user-local .NET SDK matching the builder's `dotnet-info` under
   `~/Work/safeupload-tools/dotnet` (no sudo, system packages or shell-profile edits), an offline NuGet cache, and a script compiling the
   product and test projects for normal/feature × Debug/Release with the builder's warnings-as-errors settings. Run after every worker
   hand-off; workers run it too (offline, in the Codex workspace-write sandbox). Diagnostic only; the matrix stays the gate.
2. **Required-test preflight** before queuing a matrix: every test named in `Invoke-ExactAgentMatrixBuild.py`'s required list exists as
   a method in source, and discovered test methods are diffed against the last passing matrix. A removed or renamed test is a stop.
3. **Contract first** for any change to the kernel–agent conversation: write down, per operation, the exact fields the driver sends and
   adopts (name, generation, identity, view, owner, epoch) and the agent's validation of each; add an agent test driving the harness
   pattern involved (resave/new/replace/mapped × approve/block, name reuse, rename onto occupied names, BLOCK then resave, requester
   exit, disconnect/reconnect, lost reply). For every new reply path, including denials, answer "what does the driver do with this?".
4. **Design note first** for timer, retry, lifetime or lock-order changes: states, who arms/clears, which waits are timer-eligible and
   the interleavings considered, sent with the code so one review round suffices.
5. **Batch.** Fix all defects an RCA finds in one change, then one build + matrix + review + boot. Re-reviews cover only the delta and
   the previous findings, never unchanged code.
6. **Overlap waiting.** While a matrix, build or boot runs, do the next independent item (RCA, next brief, local compile). One job
   per builder (revised 2026-10-15): two different approved builders may run jobs in parallel; never two jobs on the same builder or
   the same VM target, and no builder job on either builder during a timing-sensitive T4 row. Every launched worker or job gets an
   immediate background wait.
7. **Worker briefs** always require: the local compile and every `driver/scripts/t5` check; no renamed or removed tests; wire tests with
   `MemoryMarshal`, never `Marshal` round-trips; `InternalsVisibleTo`, constructor signatures and profile symbols checked in every
   touched test; no edits to status plans; no self-run review claimed as independent; expected test counts per profile. Codex resume
   pins the model and effort explicitly.
8. **Independent reviews** come only from a fresh Sol 6.1 xhigh session launched by Claude; a worker's internal review is advisory.

Tools: [Invoke-LocalAgentCompile.sh](scripts/Invoke-LocalAgentCompile.sh) (rule 1; SDK 10.0.400/runtime 10.0.11 user-local, offline cache,
works in the Codex sandbox) and [agent-test-preflight.py](scripts/agent-test-preflight.py) (rule 2). Kernel PREfast (e.g. C6262) still
needs the builder's WDK gate. The Codex launcher pins model and effort on resume and stops a session whose header differs.

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
- **Unreadable seeded bytes: option 1** in [T5-NATIVE-PUBLIC-OPENS.md](docs/design/publication-and-namespace/T5-NATIVE-PUBLIC-OPENS.md#owner-choice--unreadable-seeded-bytes):
  preserve native write-only editing; a blocked version containing prior bytes without read/export authority stays service-private with
  a named reason, and no full-file hand-back or justification is offered until that authority exists.
- **Lab tooling now:** only make [Invoke-StagedSuiteBatch.sh](scripts/Invoke-StagedSuiteBatch.sh) fail on any failed or missing case and
  require an explicit approved target (done in `18849424`: 29 offline controls; a single-case runner exit 1 counts only when the
  incomplete table is its sole failure). Defer the readiness doctor, build-capacity preflight, CI, Ansible and Packer until after the T5
  integration checkpoint. Terraform is not adopted.
- **False Degraded notices (T18).** A coverage query answered `ERROR_RETRY` (writer registry changed during the snapshot) reports
  Degraded at once; T4 short rows log 12–21 per run. Retry that answer briefly before reporting Degraded, with admission authority
  unchanged. Write the small design and obtain the Sol review before implementation.
- **Later the same day — T4 KD attribution authorized.** One identity-resolved local-KD attribution row (see T4), non-qualifying,
  on win10-debug3 with the unchanged pair; the stop on other product VM rows is unchanged.
- **Later the same day — product VM rows authorized.** Owner, in the session: "I give my ok for every row". Read as lifting the T4 stop
  for the planned product VM rows (KD attribution reruns, T4 short/10k gates, allocation-reply fault row, raw-volume cells, later M2
  rows) on win10-debug3 only, under the existing lab rules: serial runs, unchanged-pair hash checks, separate restoration, stop on
  repeated identical failures. No gate, threshold or assertion change is implied. AGENTS.md records the same authorization.
- **Workers.** Claude may delegate to Codex `gpt-6-astra`, `gpt-6.1-sol` and `gpt-6-luna` at any effort up to max, with the fast tier.
  **Superseded 2026-10-14 (owner):** use Astra only when necessary; use Sol (`gpt-6.1-sol`, any effort, fast tier) for everything
  else. Required reviews stay Sol 6.1 xhigh.
  Reviews required by the review policy remain Sol 6.1 xhigh.
- **Later the same day — design work in parallel.** While M2 jobs run, start the design notes for the improved lab/development workflow
  (Ansible, Packer and related tooling), T21 USB/removable and T22 SMB/UNC. Designs only: no implementation, no host-wide or
  qualified-baseline change, and USB/SMB stay disabled until their owner decisions, Sol 6.1 xhigh design reviews and gates.
  This replaces the earlier "defer the tooling" bullet for design work only; tooling implementation still waits for the T5 checkpoint.
  Drafts: [LAB-WORKFLOW-DESIGN.md](docs/operations/LAB-WORKFLOW-DESIGN.md), [T21](docs/design/destinations/T21-USB-REMOVABLE-DESIGN.md), [T22](docs/design/destinations/T22-SMB-UNC-DESIGN.md); all decisions pending.

**2026-10-11 — destinations and completion.** Follow the order above. M4 covers local NTFS, USB including surprise removal,
UNC/SMB, and a real sync client with independent destination-byte observers. Both mapping leaks need their repros rerun and closed.
T21 and T22 are required MVP milestones before M4, not Later work. Each needs its own design note, owner decisions and Luna 6
max-effort design review before implementation; adding them to the plan does not approve particular filesystems or network configurations.
After all required tracker items have run evidence, write a taint-removal plan and wait for owner sign-off. Taint stays, normal builds
compile staging out, and unsupported capabilities stay disabled until the owner approves cutover.

**2026-10-11 — empty files and deletes.** Empty files are ordinary content: seal, verify stable length, inspect trivially clean,
and publish normally. This reverses the 2026-10-10 EmptyHeld decision. Public deletes are in M2 and Windows decides the caller's
delete authority on the real public file. A newer save cancels a delete only if that save has already published. Allocated, unsealed,
sealed, inspecting or blocked successors do not cancel it; older versions cannot publish after deletion. See [T5-DELETES.md](docs/design/publication-and-namespace/T5-DELETES.md).
Only the old no-empty-publication assertion changes; every other product assertion remains required.

**2026-10-11 — accepted native-delete tracking failure.** The owner approves preserving NTFS's accepted result only with automatic
reconciliation at the app's last-handle close and again at service startup after a crash. Hold publication to that name meanwhile;
establish that it is gone or still the original pre-open file, then release the recovery hold automatically. Reuse the durable
pre-CREATE intent and existing startup recovery; add no protocol states beyond **accepted, unresolved**. If exact reconciliation
cannot decide, retain the hold, name the file and an actionable next step in the tray, and record diagnostics. Fault-injection rows
must prove automatic hold release after handle close and service restart. If that automatic guarantee cannot be met, ask the owner
before implementation. See [T5-NATIVE-PUBLIC-OPENS.md](docs/design/publication-and-namespace/T5-NATIVE-PUBLIC-OPENS.md). Ordinary mounted-instance recovery has a corrected
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

Two feature WDK builds (Debug/Release), PREfast and ApiValidator at **0 warnings / 0 errors**, binary-import availability PASS,
and the complete four-leg feature agent matrix (Debug/Release × user/SYSTEM). Compile-time staging-out profiles were retired by the owner on 2026-10-15.
Kernel runtime changes run under Verifier. Keep every product assertion, independent raw-volume observation and **ForbiddenByteCount=0**.
Any removed refusal needs a row proving unapproved bytes remain private. BLOCK-window tests run serially on the selected VM.
A milestone ends with its matched pair, three-mode gate, adversarial review and separate restoration checks.

## M1 — completed component baseline

M1 passed 69/69 cells on `m1-driver21` (`498f4ed7`) plus agent `4d02039a`, with U01 and installer workloads recorded in
[POST-MVP-LOG.md](docs/history/POST-MVP-LOG.md). These results do not qualify later changed pairs.

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

**Next delivery checkpoint:** qualify one matched local-NTFS pair, starting with T4. Planned M2 rows remain authorized on
win10-debug3 only (owner, 2026-10-13); no revised pair has qualified. Keep the unchanged raw-volume, Verifier, context/pool and
separate restoration gates. Current [integration evidence](evidence/2026-10-17/m2-integration-status.md) and
latest [development checkpoint](evidence/2026-10-19/m2-checkpoint.md) record retained artifacts and pending matrix/app results.

| T item | Current state | Next required result |
|---|---|---|
| T4 | **Closed for now (owner, 2026-10-21).** Pair `d1068cc3` + `586ae7cb`: smoke 256/256; 10k (budget disabled, isolation) ordinary and runtime Verifier PASS, boot Verifier functional PASS with the pool endpoint over the band; raw cells zero forbidden bytes. [Checkpoint](evidence/2026-10-20/t4-checkpoint.md). | Carried to the final M2 pair: boot-Verifier 10k under the 128 KiB endpoint band (owner, future rows), raw-cell MVP gate, lost-reply row, budget-on 10k after the T9 fixes. |
| T5 | **Closed for now** on reviewed `m2t5d7k6`/`m2t5a5`, three-mode budget-off native-delete and Notepad rows ([checkpoint](evidence/2026-10-21/t5-checkpoint.md)). | Final-pair budget-on reruns and applicable lifecycle/recovery conditions; Word follows T8. The full namespace edge-case matrix stays at M4. |
| T6 | File copy-fallback component evidence exists; directory moves, folder rename/delete and Recycle Bin remain postponed. | Final-pair supported single-file moves, copies and pending conflicts in all required modes, with native metadata. |
| T7 | Windows-authorized read design retained. | Final-pair authorized/denied reads and exact bytes. |
| T8 | Standard-user app dev evidence exists; final metadata implementation/qualification remains incomplete. | Eight required app workflows, matching owner/DACL/SACL/label/times/attributes/MOTW controls in all modes. |
| T9 | Whole-SID allocation causes overlapping-save refusals. Growing-reservation revision 5 is accepted with implementation conditions; the 120 s allocation/seed wait is approved (2026-10-27). | Concrete protocol/accounting implementation, then Windows budgets/upgrade, parser bounds, large-file and failure UX on the matched pair. |
| T10 | Earlier runtime-Verifier component pass exists. | Final-pair permissions/ownership rows in all modes with metadata preservation. |
| T11 | Epoch/archive and context retirement repairs integrated; component controls are distinct from qualification. | Final journal/recovery/lifetime gates and one adversarial review of the working M2 pair. |

- [x] T4: build/agent prerequisites closed on the pair above; failed attempts and root causes in the [2026-10-20 checkpoint](evidence/2026-10-20/t4-checkpoint.md).
- [x] T4: smoke `1020j` 256/256; 10k isolation rows (budget disabled, owner-approved): ordinary PASS; runtime Verifier PASS (`m2t4rvoff3`); boot Verifier
  functional PASS twice with the pool endpoint 7-10 KB over the 64 KiB band (the post-idle level is a constant ~6.68 MB independent of cycle count; those receipts
  stay FAIL; owner set 128 KiB for future rows, 2026-10-21).
- [x] T4: closed for now (owner, 2026-10-21); carried items are listed in the owner decision and the checkpoint.
- [ ] T4 (carried): raw-volume cells: journal reader and host validation fixed for the staged agent; C01-approve ordinary completes with zero forbidden bytes; the other
  ordinary cells are INCONCLUSIVE with per-family harness gaps (BLOCK hand-back evidence, B01/B02 wrapper, X01 execution, live-taint receipts).
- [ ] T5–T11: qualify the coherent pair against every existing assertion; component/dev passes do not complete these items.
- [ ] T11: perform final adversarial review only after the runtime evidence exists.

The superseded checkpoint narratives are in [POST-MVP-LOG.md](docs/history/POST-MVP-LOG.md#archived-m2-checkpoint-narrative--replaced-2026-10-17).

### T4. Remove the 128-saves-per-boot ceiling

**Problem:** retired versions retained slots and contexts; later saves failed until reboot.
**Done when:** 10,000 mixed approve/block saves in one boot pass with flat nonpaged pool, no Verifier hit, no cap refusal, zero residual
versions/views/tombstones/stages and an idle worker; C01–C04, B01, B02 and X01 pass in all three modes.

Design: [stage lifetime](docs/design/lifetime/T4-STAGE-LIFETIME.md), [lease/retirement correction and reopen controls](docs/design/lifetime/UX-LEAK2.md).
**Closed for now (owner, 2026-10-21)** on the evidence in the [checkpoint](evidence/2026-10-20/t4-checkpoint.md); the open items below are
carried to the final M2 pair, not waived. The 2026-10-19 smoke failure and its diagnosis are retained there.
The [prior 10k contexts failure](evidence/2026-10-12/m2t4purge10ka1-verdict.txt) and
[attribution rows](evidence/2026-10-13/t4-delete-kd-attribution-result.md) remain preserved.

**Owner gates (2026-10-12; endpoint band changed 2026-10-21):** 256-cycle slope is INFO only. The idle endpoint band is 128 KiB for rows
from 2026-10-21 (owner, future rows only; earlier receipts keep their 64 KiB verdicts). Long-row slope stays <4 B/cycle from cycle 1,000. Registry occupancy must remain within capacity with zero idle capacity
failures. After idle, SYSTEM enables privileges 13/5 and runs class-80 commands 2/3/4 (empty working sets, flush modified list,
purge standby), recording every NTSTATUS; wait 30 seconds and sample purged. Every status must succeed and 10k SUfl live allocations
must be ≤start+2,048. Missing evidence fails. Smoke must release at least half the SUfl growth before a long run; short contexts
check is INFO. No handles, driver calls or file deletion substitute for purge. Keep post-idle T4AdmissionRecovered and all functional
assertions. Use the current committed matched pair, fresh disposable disk/reset EFI and separate restoration. No builder jobs or
host maintenance during timing-sensitive rows. Stop/report required failed assertions; short slope alone is never a stop.

- [x] T4: integrate context leases/retirement and immediate same-owner/child reopen controls (`412f05ad`); independent kernel review
  [accepted with conditions](evidence/2026-10-17/kernel-namespace-integration-sol-high.md), corrected WDK/import gates PASS (`f8e99d25`).
- [x] T4: PS5.1 harness/native controls and verdict replay pass; latest [harness gate](evidence/2026-10-17/harness-windows-gate-m2-ux-harness-1017b.txt).
- [x] T4: pass the full four-leg agent matrix (5,570/5,570); [package retry/strict verification](evidence/2026-10-19/matrixpkg1019c/verification.txt)
  preserves the tested payload bytes. [Checkpoint](evidence/2026-10-19/m2-checkpoint.md) retains the original failed attempts.
- [ ] T4 (carried): qualify V20 allocation/Prepare lost-reply cleanup under protection; fault-test harness delivered on `t4/fault-row`, held and unrun.
- [x] T4: fix serial-save refusals (agent refund wait, `586ae7cb`) and the pageable-router double fault (`d1068cc3`).
- [x] T4: pass 256-cycle boot-Verifier smoke with 64-cycle sampling: [`m2t4smoke1020j`](evidence/2026-10-20/m2t4smoke1020j-verdict.txt) 256/256, every required line PASS.
- [ ] T8: immediate-reopen control (moved from T4, owner may veto): original owner's reopen passes, a second process's read/write open fails Win32 32.
- [x] T4: one-boot 10k with the budget disabled (isolation): ordinary [`m2t4ordoff1`](evidence/2026-10-20/m2t4ordoff1-verdict.txt) PASS and runtime Verifier
  [`m2t4rvoff3`](evidence/2026-10-21/m2t4rvoff3-verdict.txt) PASS (runtime mode now arms Verifier after Ready, `e329048f`).
- [ ] T4 (carried): boot-Verifier 10k on the final M2 pair under the 128 KiB endpoint band (owner, 2026-10-21). [`m2t4bvoff1`](evidence/2026-10-20/m2t4bvoff1-verdict.txt)/[`m2t4bvoff2`](evidence/2026-10-20/m2t4bvoff2-verdict.txt)
  stay FAIL under 64 KiB: all functional gates PASS, endpoint +72–75 KB (constant post-idle level, not growth).
- [ ] T4 (carried): rerun the 10k rows with the default staging budget once the T9 budget defects are fixed.
- [ ] T4 (carried): run C01–C04/B01/B02/X01 with the raw-volume observer in all modes to MVP-gate PASS, then repeat on the final M2 pair. Sampled bytes do not replace raw observation.


### T5. Empty saves, Notepad Save As and deletes

**Problem:** public probe deletion was refused and private-delete names stayed occupied until physical cleanup. EmptyHeld broke normal
zero-byte file operations and added a successor protocol. Empty is ordinary content; public deletes are M2.
**Done when:** clean saves publish exactly their bytes; CPF saves hand back and leave new names absent or existing prior bytes intact;
no empty probe is left behind; no uninspected nonempty byte reaches the public name. All existing other assertions pass in three modes.

Designs: [deletes/teardown](docs/design/publication-and-namespace/T5-DELETES.md), [native public opens](docs/design/publication-and-namespace/T5-NATIVE-PUBLIC-OPENS.md),
[bound publication/recovery](docs/design/publication-and-namespace/T5-BOUND-PUBLICATION.md), [current MVP namespace correction](docs/design/publication-and-namespace/T5-UX-NAMESPACE-GAP.md).
Latest [integration status](evidence/2026-10-17/m2-integration-status.md) and
[pre-boot review](evidence/2026-10-17/kernel-namespace-integration-sol-high.md) do not qualify the protected pair.
Detailed historical implementations, failed runs and prior component gates are retained in POST-MVP-LOG.md and Git history.

- [x] T5: record empty-file reversal, public-delete design and independent design review; [source classification](evidence/2026-10-11/t5-empty-public-delete-component-classification.md)
  separates empty-only machinery from identity/lifetime/cleanup safeguards. Persisted enum slots remain reserved.
- [x] T5: remove kernel EmptyHeld/successor sends and empty-only refusal/notice paths; implement ordinary measured-zero publication and guarded legacy migration
  (`f305d607`, `d8fd93c6`, `028a1b66`). Source completion is distinct from runtime qualification.
- [x] T5: prepare both deterministic native DeleteFileW orders and failed-CREATE_NEW identity protection; current PS5.1 harness gate passes.
- [ ] T5: finish/verify coherent caller grants, seed read/export policy, exact security/metadata, generation ordering and automatic accepted/unresolved recovery.
  - [ ] Preserve original checked authority, exact destination/object/generation/policy; only a newer **published** successor cancels a delete.
  - [ ] Keep uncertain publication/cleanup held with named-file owner-session diagnostics; retry bookkeeping, never a completed public mutation.
- [x] T5: four-leg feature agent matrix `m2t5a5` (`bd1cae84`) 3,179/3,179 per leg, and the matched driver `m2t5d7k6` (`29D6130E…`; both WDK profiles 0/0, PREfast, ApiValidator, imports 248/247). Reviewed
  as D7 rev 5 (`3a16ec0f`) and D8 (`13ea6fbf`), both Sol 6.1 high ACCEPT WITH CONDITIONS; no separate adversarial review of the pair as a milestone.
  See the [T5 checkpoint](evidence/2026-10-21/t5-checkpoint.md).
- [x] T5: native delete before seal and after independently observed publication; both DeleteFileW calls succeed, with failed-CREATE identity intact (rows `m2t5ord19`/`rtv19`/`bov19`, budget off).
- [x] T5: real Notepad clean/CPF Save As in ordinary/runtime-/boot-Verifier modes, independent destination bytes, separate restoration (run disk deleted, base untouched, XML unchanged, EFI reset each row).
  Isolation rows: StageSpace off until the T9 growing-reservation fix (owner, 2026-10-21); the budget-on T5 rows are carried.
- [ ] T5: Explorer New Text Document → rename → another-process Notepad open; empty copy/move; clear-and-save; DELETE-authorized/refused public deletion; delete during a newer in-flight save;
  delete then blocked CPF save: every case PASS in all three modes (70 PASS / 0 FAIL lines per row, registry Known, staging and hot journal empty after the run), but the public-delete cases'
  durable `DeleteBarrier` stays INCONCLUSIVE (the unbound route writes none) and `T5CanonicalNoUnapprovedByte` INCONCLUSIVE (no lower-mutation ledger in the T5 adapter): carried (D1).
- [ ] T5: fault rows prove holds end automatically at original-handle close and service restart. The approved fixed-NTFS forced-teardown exception may require Restart;
  unresolved identity stays held. T21 must reconcile at remount instead of requiring Windows restart.
- [ ] T5: qualify voluntary unload veto, exact cleanup ACKs and service-independent mandatory teardown/shutdown; startup recovery retains unresolved private objects.
- [ ] T5: qualify Word swap/public rename/delete, pending-writer conflicts, original/restricted caller grants, DOC identity faults, cancellation/restart and draining boundaries.

Ordinary blocked overwrite preserves prior bytes; explicit authorized delete followed by a blocked save leaves the name absent.
A failed CREATE_NEW probe never authorizes deleting its pre-existing target. Keep exact file identity, callback/worker/owner lifetime
and cleanup obligations; historical EmptyHeld acceptance `e0de7e46` is not qualification of this design.


### T6. Moves inspected like copies

**Problem:** a same-volume rename can introduce bytes without a staged write.
**Done when:** Explorer, Move-Item, cmd move and MoveFileEx publish clean moves or hand back CPF, remove the source appropriately,
and never publish uninspected bytes; C05 reflects inspection rather than blanket refusal.

- [x] Copy fallback via STATUS_NOT_SAME_DEVICE (`baec933f`); runtime row `m2t6rv4` passed 28/28 on its component pair.
- [ ] Rerun ordinary, runtime and boot-Verifier on the final pair, including empty files and real Explorer drag.
- [ ] Directory moves (owner 2026-10-16: like copies; idle renames inside protection; **postponed after M2**, owner 2026-10-21): design note (RCA `driver/evidence/2026-10-16/t6-dirmove-rca-sol61.md`),
  review, implementation, native caller traces, then D-rows in all three modes. The small unbound MVP [directory UX change](docs/design/publication-and-namespace/UX-DIRECTORIES.md) has local controls and Sol 6.1 xhigh acceptance with conditions; WDK/native three-mode qualification remains open.
  - [x] Design `driver/T6-DIRECTORY-MOVES.md` (`wt/t6-dirs` `82da3a06`): [review](evidence/2026-10-16/t6-design-review-sol61.md) REVISE, then
    [re-review](evidence/2026-10-16/t6-design-rereview-sol61.md) **ACCEPT WITH CONDITIONS** (idle census proof, lock/rundown rules, checked
    ancestry for every live T5 consumer, native traces first, separate gates).
  - [x] Native traces steps 1–2 ([`t6trace3`](evidence/2026-10-16/t6trace3-result.md), harness `c216ed1a`/`6dfe9c3d`): real cross-volume folder moves
    fall back to copy+delete in PS 5.1 and the Explorer engine; cmd/MoveFileEx fail with the source intact; cross-drive DACLs inherit
    the destination; timestamps are per caller.
  - [ ] Traces 3–5 after implementation (induced NOT_SAME_DEVICE incl. PS 5.1, admission, MOTW, busy/idle).

### T7. Reads follow Windows permissions

**Problem:** legacy read enforcement denied reads that Windows allowed.
**Done when:** authorized users read the exact justified bytes; unauthorized users receive Windows denial with no bytes.

- [x] `4a438b36`; B02 `m2t7o1`, `m2t7v1`, `m2t7b1` passed with ForbiddenByteCount=0 and restoration on that pair.
- [ ] Preserve these assertions in the final M2/combined gates.

### T8. Office/common apps and metadata

**Problem:** real application save/replace/delete sequences and publication metadata need qualification.
Owner-agreed [closure plan](docs/design/T8-CLOSURE-PLAN.md) (2026-10-22): native-parity catalog with zero unexplained refusals, then metadata/MOTW. First sweeps: [discovery 1](evidence/2026-10-22/t8-discovery-1.md) (harness `scripts/t8/`; 22 of 24 cases differ from the control folder: owner/group SYSTEM, a publication window that breaks Word in-place saves and other processes, budget-on creates fail, folder rename/delete and Recycle Bin refused).
**Done when:** Word, Excel, PowerPoint, WordPad, Explorer replace, browser download, robocopy and 7-Zip rows pass all three modes (Paint moved
after M2 with image OCR, owner 2026-10-16);
the publishing application can reopen the file and agreed metadata is preserved.

- [ ] Trace/replay real save sequences, including temporary/backup deletes under T5; respect staged rename limits.
- [ ] PowerPoint and archive inspection (owner 2026-10-16): PowerPoint `1d485942` merged, matrix
  [`t9-pptx1`](evidence/2026-10-16/exact-agent-matrix-t9-pptx1-summary.txt) ExactAgentMatrixGate=PASS (2,263 user + 25 SYSTEM per feature configuration);
  ZIP inspection and the default monitored extensions (agent and backend) `5c9bb10b`/`9561825a` merged, matrix
  [`t9-archives2`](evidence/2026-10-16/exact-agent-matrix-t9-archives2-summary.txt) ExactAgentMatrixGate=PASS (2,360 user + 25 SYSTEM; `t9-archives1`
  failed on an obsolete `.zip` test example, receipt kept). `.7z` is refused (`archive_7z_unavailable`): SharpCompress was rejected
  for unbounded header/dictionary allocation ([assessment](../agente/docs/T9-ARCHIVE-INSPECTION.md)); `.7z` support is **postponed after M2** (owner 2026-10-21) and stays refused.
- [ ] Implement and test the metadata contract decided 2026-10-16 (native owner/DACL/SACL/label, timestamps, attributes; Zone.Identifier
  carried with its file; other ADS, EAs, EFS, offline, reparse points and hard links refused).
  - [ ] Unbound `ux/meta` [basic metadata increment](docs/design/metadata/UX-METADATA.md): exact sealed dates/ordinary attributes and unsupported-storage checks;
    native descriptor construction, public metadata serialization and inspected atomic MOTW remain unfinished. No T8 completion or VM qualification.
  - [ ] `ux/meta2` [round-2 prerequisite checkpoint](docs/design/metadata/UX-METADATA-ROUND2.md): strict native absence/query validation and dormant descriptor/MOTW controls; whole-version producer, native construction and commit fence remain blocked/open. No T8 completion.
- [ ] Qualify application rows under the matched pair with independent byte observation and restoration.

### T9. Large files and complete inspection

**Problem:** old 16 MiB driver/seeding limits and whole-memory extraction prevent ordinary large-file use.
**Done when:** no fixed driver size cap; per-user/total stage budgets fail closed without harming other users; full-content inspection
uses bounded memory; incomplete inspection is Blocked with hand-back and policy-authorized justification; runtime rows prove privacy.

Design/qualification: [large-file budgets and upgrade](docs/design/large-files/UX-LARGE.md), [Windows rows](docs/design/large-files/UX-LARGE-VM.md),
[recovery](docs/design/large-files/UX-LARGE-RECOVERY.md), [inspection coverage](../agente/docs/INSPECTION-COVERAGE.md).
Owner-approved runtime budget/default formulas are in Owner decisions. Bounded scanner scratch does not prove bounded parser/capture memory.

- [x] T9: complete-or-refuse Office/PDF coverage implementation and independent fixtures (`a46124c7`, `52fbb7cb`); prior component matrices
  [coverage](evidence/2026-10-13/exact-agent-matrix-t9-coverage1-summary.txt), [round 2](evidence/2026-10-13/exact-agent-matrix-t9-round2-int2-summary.txt).
- [x] T9: implement failure classes, bounded worker concurrency, notifications, single-handle snapshot and scanner-integrity controls;
  [component evidence](evidence/2026-10-10/m2-agent-component-gates.json).
- [x] T9: owner resolves all-zero card and exact PANOSE/Office-owner-file/PowerPoint-thumbnail choices; preserve the remaining content refusals.
- [x] T9 growing reservations: design accepted with conditions at revision 5 (2026-10-22; initial window, retirement receipt, custody leases, maintained totals, lane ordering, startup table;
  [design](docs/design/large-files/UX-LARGE-CONCURRENCY.md)). **Owner approved the 120 s allocation/seed wait on 2026-10-27.** Concrete protocol/accounting implementation is next.
- [x] T9 prerequisite: maintained global/per-SID reservation totals replace the foreground reservation scan; reconstruction, durable adoption and exact retirement remain conservative.
  [Independent scoped review](evidence/2026-10-27/t9-reservation-totals-review-sol-high.md) ACCEPT WITH CONDITIONS; local compile, 36 focused controls and T5 offline controls pass. **Four-leg Windows gate `m2t9totalsb1` PASS** on `afd972ef`, builder2: 3,159 user + 25 SYSTEM per feature configuration, exact discovery, zero skips/warnings/errors, verified packages. The owner-authorized 14-case timing diagnostic also passed there; prior failed attempts remain preserved, without a proved cause. This closes the scoped totals delivery condition, not whole-allowance grants, metadata callback scans, later passive contracts or pair qualification. [Latest checkpoint](evidence/2026-10-28/t9-timing-checkpoint.md); [retained failures](evidence/2026-10-27/t9-reservation-totals-checkpoint.md).
- [x] T9 passive protocol prerequisite: [v32 layouts and parser contract](docs/design/large-files/UX-LARGE-RESOURCE-WIRE.md), [Sol high design review](evidence/2026-10-28/t9-resource-wire-review-sol-high.md) ACCEPT WITH CONDITIONS; 32 local mutation/layout controls and Debug/Release compile pass. At `c5e5c83c`, both WDK/static/import gates and the signed delivery-copy check pass ([kernel checkpoint](evidence/2026-10-28/t9-resource-wire-kernel-checkpoint.md)); no changed kernel boot. No negotiation success, receive-loop handler, worker or capacity consumer; metadata capability/custody/modern startup and every growth/MM integration condition remain open. [Local agent receipt](evidence/2026-10-28/t9-resource-wire-local/result.json) is not Windows/pair qualification.
- [x] T9 R3.3(a) completed-save metadata retirement (agent only): published saves, completed blocked hand-backs and acknowledged `PrivateVersion` discards stop charging the per-SID/global 1 MiB envelope after exact content release, live and after restart, and move into the conservative shared-history allowance; duplicate completion and crash-before-adoption are controlled. Local Linux subset 113/113 (pre-fix 3/13), [receipt](evidence/2026-10-28/t9-completed-retire-local/result.json) is not Windows/pair qualification. Open: ordinary `Discarded` has no disposal receipt and keeps four-copy capacity plus metadata; R3.3(b) lost initial allocation reply needs a driver fence of every possible CREATE/reply adoption plus abandonment evidence (restart alone proves nothing), so it moves into the growth protocol work.
- [x] T9 increment 2 (R3.5 bounded dispatch shell, agent only): the receive loop only dequeues, validates the header and hands each request to a connection-owned bounded lane (ordered FIFO 1 worker/32 queued for every former inline handler, bound-allocation 2/6, continuations 8/32, an empty growth lane 8/32 with its own reply credits); saturation returns the operation's existing correlated failure, revocation releases growth before dependent drains, workers join before port close. Local Linux subset 96/96 plus feature Debug/Release compile 0/0 ([receipt](evidence/2026-10-28/t9-lanes-local/result.json)); **Windows four-leg delivery gate `m2t9lanes1028a1` PASS** on `272a33d1` (builder2): 3,278 user + 25 SYSTEM per feature configuration, exact discovery, zero skips/warnings/errors, verified Release package ([receipt](evidence/2026-10-28/t9-matrix-m2t9lanes1028a1/result.json)). Not protected-pair qualification; native real-port saturation/reconnect/late-reply controls remain. No growth producer or handler exists.
- [x] T9 increment 1 (design): [revision 6 implementation contracts](docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md) proposed (wire/control ABI, 192-byte companion, replay, CREATE fence, deadlines, metadata capability map, Discarded receipt, shared history/downgrade marker, MM stop condition). Independent Sol 6.1 high [review](evidence/2026-10-28/t9-growth-protocol-review-sol-high.md): **REVISE** (5 high, 2 medium: metadata hook sits behind epoch admission, `_sendGate` control cycle, unaligned archive framing, shared-history recovery gaps, per-I/O growth deadline, kernel waiter bounds, anchors); revision 2 committed (`7867cf37`); a second independent [re-review](evidence/2026-10-28/t9-growth-protocol-rereview-sol-high.md) closed the seven original findings at the contract level and returned REVISE with three residual gaps (successful-intent handoff, retained kernel receipt credits, MDL buffer pinning; none gates increment 3). Revision 3 added pure fit models and the pre-increment-3 contracts. A third [review](evidence/2026-10-28/t9-growth-protocol-rereview2-sol-high.md) closed the three residual gaps in text and returned REVISE only for starting increment 3 coding (peak allocation under padding A>U; increment-3 scope cut). Revision 4 corrects both (independent A/U peak model with mutant, 70 local controls; opaque-buffer 'provisional metadata substrate' with Commit always NotReady and a test-only epoch-hold actor); the root verified the tests and text, no fourth full review. Increment 3 coding may start under the reviewer's ordered conditions; the first-boot kernel review, native builder mechanism controls and WDK gates remain required before any VM boot. Owner decisions O1 (3 s per application I/O) and O2 (existing trusted-storage boundary) were taken 2026-10-28; see Owner decisions. No implementation of increments 3-6 starts before the review conditions are closed.
- [ ] T9 increment 3 (provisional metadata substrate, dormant; Commit always NotReady): **agent half** implemented and locally controlled (opaque bounded-buffer native store with the 8.4 sequence, padded-peak L/P/Q accounting checked against the pure model incl. the logical-EOF mutant, metadata 8/0, resolution 2/8 and revoke 1/0 send classes with local Busy, provisional Probe parsing, 16 builder-native N-U4/N-U8 mechanism cases written but not yet run): feature+normal Debug/Release 12 builds 0/0, 203 Linux controls (root-verified). **Kernel half is partial**: pairing/authentication/revocation/reaper and typed control dispatch in `StageResourceMetadata.c`, Commit NotReady; root/child registration returns Refused, and outer pre-epoch routing, native leases/namespace claims and physical accounting are NOT implemented. Open inputs: trusted source for the installed roots (the driver hard-codes `\ProgramData\SafeUpload\staging\` only), the growth/non-growth transaction partition, and the test-only diagnostic actor ABI. Not boot-ready. **Agent half four-leg gate `m2t9i3a1028a2` PASS** on `a6958c10` (builder2): 3,534 tests per feature configuration with user+SYSTEM legs, zero skips/warnings/errors, verified Release package, including the 97 builder-native mechanism cases ([receipt](evidence/2026-10-28/t9-matrix-m2t9i3a1028a2/result.json); predecessor `a1028a1` failed 3 native cases and is retained). The kernel pre-boot review and Verifier rows remain. Native discovery on the builder ([results](evidence/2026-10-28/t9-inc3-native-results-2.md)): held-target replacement works only with `FileRenameInformationEx` REPLACE_IF_EXISTS|POSIX_SEMANTICS and a FILE_SHARE_DELETE predecessor (adopted); NTFS transient over-allocation under unpreallocated chunked writes is nondeterministic, so production preallocates P and charges max(Q, observed); strict N-U4-01/-05, N-U8-01 and 32 replacement rows pass. **Kernel pass 2 static gate `m2t9i3k1028a5` PASS** on `3acb631e` (both feature configs 0/0, PREfast, ApiValidator, imports 251/250, valid signature; [receipt](evidence/2026-10-28/t9-inc3-kernel-m2t9i3k1028a5/result.json); attempts `a3`/`a4` failed C4018/C6262 and are retained): registration, pools and outer routing, still dormant and not boot-ready. **Pass 3 (forwarded child CREATE, Active children, per-role enforcement, class-65 held-target replacement, retirement pins) static gate `m2t9i3k1028a7` PASS** on `8bd4d0f0` (both configs 0/0, PREfast, ApiValidator, imports 251/250, valid signature; [receipt](evidence/2026-10-28/t9-inc3-kernel-m2t9i3k1028a7/result.json); `a6` failed C6011 and is retained). The kernel source for increment 3 is complete but dormant; independent pre-boot review, native kernel-path controls and Verifier rows remain before any boot. **Independent pre-boot review ([REVISE](evidence/2026-10-28/t9-inc3-preboot-review-sol-high.md))** found two high lifetime/callback defects and a RegisterRoot/CLEANUP race; **pass 4** (`a2e5d428`) fixes them (1,526 offline mock assertions per compiler) and passes the static gate `m2t9i3k1028a8` (0/0, PREfast, ApiValidator, imports 252/251; [receipt](evidence/2026-10-28/t9-inc3-kernel-m2t9i3k1028a8/result.json)). A fresh independent [re-review](evidence/2026-10-28/t9-inc3-preboot-rereview-sol-high.md) of pass 4 is **ACCEPT WITH CONDITIONS**: the three findings are closed at source level, with no new source defect. Still required before any first boot of the substrate: (1) **N-U4-06 is closed: [PASS on the target](evidence/2026-10-28/t9-nu406-target.md)** (`nu406t2`, `77c78918`, 19045.2965, actor and admin, without the new kernel). The control gained the fault/retention/release rows the re-review required. Builder discovery measured the two FileId statuses ([discovery](evidence/2026-10-28/t9-nu406-builder-discovery.md)), and the first target attempt `nu406t1` failed only on the harness's 5-minute bound and is retained; (2) remaining: the real-port gate-independence control **N-U5-01**, on a separately authorized component host *before* the protected boot (owner-authorized debug3 component overlay). Its in-service harness (`7c3ab3e5`, feature build only) passes the four-leg gate **[`m2t9nu501a3`](evidence/2026-10-28/t9-matrix-m2t9nu501a3/result.json)**: 3,740 user + 25 SYSTEM per configuration, verified Release package. Attempts `a1`/`a2` each failed one unrelated timing test on a freshly cold-booted builder1 during Defender updates; they are retained, and nothing was changed. Running it during the first protected boot does not satisfy the gate. The re-review also fixes the first-boot protocol: runtime Verifier `0x13B` with `/query` readback, serial rows from legacy regressions through detach/unload, synchronization-callback controls, and stop on the first anomaly. **Kernel half static gate `m2t9i3k1028a2` PASS** on `60acb1a5` (both feature WDK configs, PREfast, ApiValidator, imports 248/247, valid recovery-signer signature; [receipt](evidence/2026-10-28/t9-inc3-kernel-m2t9i3k1028a2/result.json); the first attempt `m2t9i3k1028a1` failed C28023/C6001 and is retained). Design section 8.7 now proposes the signed fixed-path root table, the Growth/NonGrowth `TransactionId` pools and diagnostic-actor options; independent review of 8.7 pending.
- [ ] T9: qualify integrated identity-bound capacity grants, per-SID/total/free-space budgets, exact snapshot/orphan accounting, failed-prefix refusal,
  legacy upgrade and startup recovery; [latest local source receipt](evidence/2026-10-16/ux-large5-local/result.md) is not Windows pair qualification.
- [x] T9 passive schema prerequisite: [v2 custody representation/codec](docs/design/large-files/UX-LARGE-RESOURCE-STATE.md), [Sol high design review](evidence/2026-10-28/t9-resource-state-review-sol-high.md) ACCEPT WITH CONDITIONS; 33 local corruption/conservation controls and Debug/Release compile pass. No store, budget adoption or runtime consumer. Growth replay, native custody/metadata capabilities and shared history remain required; [local receipt](evidence/2026-10-28/t9-resource-state-local/result.json) is not Windows/pair qualification.
- [ ] T9: finish/qualify whole-file streaming, all required format/encoding/extraction coverage, seeding cost and capture/storage/parser bounds.
  - [ ] Include Office auxiliary/drawing/chart/VML/external/member payloads and PDF fields/annotations/metadata; inspect completely or refuse.
  - [ ] Keep corrupt/encrypted/password-protected/unsupported/incomplete content blocked; images remain refused except the exact approved thumbnail.
- [ ] T9: qualify policy-load/snapshot/parser/extraction-limit/timeout/disk-full failures, actionable UI, exact hand-back/digest and policy-bound justification.
- [ ] T9: measure cold/warm end-to-end throughput/latency (**postponed to M4**, owner 2026-10-21) and hostile-input process peak memory (M2), including publisher and concurrent/seed UX.
  Prior single warm scanner measurements do not close these gates.
- [ ] T9: pass large clean/EOF-CPF and failure rows on the matched protected pair, with independent bytes, Verifier and separate restoration.


### T10. Permission and owner changes

**Problem:** metadata-only security changes were redirected/refused instead of reaching the real public object.
**Done when:** Windows-authorized file/folder ACL and owner changes succeed; private backing ACLs remain private; permission changes
cannot publish unapproved bytes, proven by the observer.

- [x] Security-only opens use the public file/folder; staged backing remains inaccessible (`771a551b`).
- [x] Phase B: `m2t10rv5` stopped after 5/13 because the coordinator's own stage-ACL probe threw on the expected denial; fixed in
  `c71215a1`/`1f41c15f` (refusals recorded, not thrown). [`m2t10rv6`](evidence/2026-10-10/m2t10rv6-verdict.txt) passed 13/13 phase-B checks
  under runtime Verifier on the 10-10 component pair, including actor-level (non-admin) file ACL change, CPF-after-grant blocked,
  no blocked bytes published and the private backing closed to security changes. It records an admin ACE lost when a new version
  was published (`T10AceAfterPublication` False): carried into the T8 metadata contract.
- [ ] Rerun all modes on the final pair. Carry publication ACL/owner fidelity into T8.

### T11. Review conditions

**Problem:** remaining locking, generation, section-lifetime and journal-scaling findings need closure.
**Done when:** every finding has a tested change or row and the M2 adversarial review closes the working system.

Design: [unbound journal scaling](docs/design/lifetime/T11-UNBOUND-JOURNAL-SCALING.md); [review conditions](docs/reviews/M2-REVIEW-CONDITIONS.md).
Latest [integration evidence](evidence/2026-10-17/m2-integration-status.md) distinguishes source acceptance from qualification.

- [x] T11: nested sealed-stage guard (`203d31e9`), serial generation arithmetic (`b8394357`), cache eviction (`cb1d0930`) and bounded index/closure controls implemented.
- [ ] T11: qualify SOP startup/lifetime and exact context retirement on the final pair; the integrated pre-boot review is accepted with runtime conditions.
- [ ] T11: finish/qualify journal packing/compaction (beyond the 10k workload's needs **postponed after M2**, owner 2026-10-21) and crash recovery without losing full-identity generation barriers, unresolved cleanup, live-epoch replay or ancestry obligations.
- [ ] T11: prove bounded hot-set/end-to-end behavior through the protected 10k workload; component index timings do not close durable I/O scaling.
- [ ] T11: close every M2 review condition against the final matched pair, then obtain one adversarial review of the working milestone.


## M3 — after T21 and T22 (owner, 2026-10-21)

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

## New destinations — T21 and T22 after M2 and before M3; T23 after M3, before M4

### T21. USB and removable media

**Problem:** removal, changing volume identity and filesystems without stable file IDs challenge private staging and publication.
**Done when:** the owner-approved USB/removable scope, including surprise removal, keeps unapproved bytes private, has independent
destination-byte run evidence, and is ready for combined M4 qualification.

**Owner requirement, 2026-10-11:** surprise removal must reconcile automatically at remount, where the old handle can no longer
change the file. Prove that lifetime boundary and validate the returning volume/file state in the T21 design. Windows Restart is
not an acceptable removable-media recovery remedy; the M2 fixed-NTFS exception does not extend here. Do not implement this in M2.

- [ ] Complete the dedicated USB/removable design before implementation.
  - [x] [Design draft](docs/design/destinations/T21-USB-REMOVABLE-DESIGN.md) (2026-10-13, Astra): NTFS-first envelope, local private staging, two lifetime proofs
    for surprise removal, automatic remount reconciliation, decisions D1–D7 and native controls.
    [Independent Sol 6.1 xhigh review](evidence/2026-10-13/t21-design-review-sol61.md): REVISE — select a routing owner that survives
    removal for live upper streams; couple each external-copy exposure to current shared-head eligibility. Revised (StageFs routing
    owner, range admission coupled to head eligibility, device-resource ACK contract). [Re-review](evidence/2026-10-13/t21-design-rereview-sol61.md):
    REVISE — select the StageFs→USB public-delete relay; reconcile review provenance. [Third review](evidence/2026-10-13/t21-design-review3-sol61.md):
    REVISE — pre-attachment backend close ownership; original-present remount recovery for accepted ordinary deletes. [Fourth review](evidence/2026-10-13/t21-design-review4-sol61.md): **ACCEPT WITH CONDITIONS** —
    design accepted for owner decisions D1–D8; implementation still needs those decisions, the native controls and the T5 prerequisites.
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
  - [x] [Design draft](docs/design/destinations/T22-SMB-UNC-DESIGN.md) (2026-10-13, Astra): local fixed-NTFS stage, enrolled UNC identity, Kerberos caller
    authority, remote replacement gap and commit options, decisions D1–D13 and native controls.
    [Independent Sol 6.1 xhigh review](evidence/2026-10-13/t22-design-review-sol61.md): ACCEPT WITH CONDITIONS — forced-teardown
    coverage-loss gate, corrected cross-volume retargeting rationale, enumerated diagnostic candidates. Revised; [re-review](evidence/2026-10-13/t22-design-rereview-sol61.md):
    REVISE — atomic per-range ordering against destination-head changes. [Third review](evidence/2026-10-13/t22-design-review3-sol61.md): REVISE —
    cutoff contract for native application mutation handles; defined conflict outcome for intervening same-object edits. [Fourth review](evidence/2026-10-13/t22-design-review4-sol61.md): REVISE — keep
    payload-bearing EA writes off the native route after cutoff. [Fifth review](evidence/2026-10-13/t22-design-review5-sol61.md): REVISE —
    no enforcement boundary for fresh payload opens while callback coverage is lost; either specify one or present the contract limit
    as an owner decision. Fifth revision: the endpoint-only architecture cannot meet all-state SMB privacy; pending **D16** (documented
    exposure limit / server-side enforcement component, recommended / SMB unsupported). [Sixth review](evidence/2026-10-13/t22-design-review6-sol61.md):
    **ACCEPT WITH CONDITIONS** as an architectural decision proposal — D16 must be decided first; D16 B needs its own reviewed design.
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
  - [x] [Design](docs/design/admission/T18-COVERAGE-RETRY.md): up to three retries (10/20/40 ms) of exactly `0x800704D5` within one poll; nothing held or synthesized.
  - [x] [Sol 6.1 xhigh review](evidence/2026-10-13/t18-coverage-retry-review-sol61.md): ACCEPT WITH CONDITIONS; conditions folded into the design.
  - [x] Implementation (Sol worker, integrated here): `AdmissionCoverageRetry` retries only `Win32Exception.NativeErrorCode == 0x800704D5`
    with 10/20/40 ms delays; startup flags applied after the final receipt; retry/exhaustion counters in diagnostics; 31 controls.
    Draft [matrix `t18-retry1`](evidence/2026-10-13/exact-agent-matrix-t18-retry1-summary.txt) PASS; integrated
    [matrix `t18-integrated1`](evidence/2026-10-13/exact-agent-matrix-t18-integrated1-summary.txt): 1,241 normal / 1,611 feature tests
    per Debug/Release profile, no skips, 0/0.

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
