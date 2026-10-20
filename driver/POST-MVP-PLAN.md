# SafeUpload MVP status plan

Updated 2026-10-20. **Goal:** replace process-taint enforcement with owned-stream staged writes for every supported protected
destination, keeping unapproved bytes private throughout. M2 is the current milestone, not the completion boundary.
Historical implementation narratives remain in Git history, [POST-MVP-LOG.md](POST-MVP-LOG.md), and the local WIP branch noted below.

## Milestone order

| Order | Scope | Status |
|---|---|---|
| M1 | T0–T3: safe to leave loaded | Complete on the recorded M1 pair |
| **M2** | **T4–T11: everyday file work** | **Active; integrated kernel review accepted with conditions; build gates pass; T4 save/kernel defects fixed (`586ae7cb`, `d1068cc3`); 256-cycle smoke 256/256 apart from sampling; 10k and raw-cell rows in flight** |
| M3 | T12, T14: release configuration and lifecycle | After M2 |
| T21 | USB/removable | After M3; own design, owner decisions, Sol 6.1 high design review and destination qualification |
| T22 | SMB/UNC | After T21; own design, owner decisions, Sol 6.1 high design review and destination qualification |
| T23 | Cloud-sync folders | After T22; own design, owner decisions, Sol 6.1 high design review and real-client qualification |
| M4 | T15–T19: combined qualification | Qualify local NTFS and T21–T23 together |
| Later | T20 other Windows builds; T24 ReFS | Outside the current milestone sequence |
| Owner-deferred | T13 production signing/Secure Boot | Test mode remains in force |

USB, SMB/UNC and cloud-sync are required MVP work; they are no longer deferred until after M4. They remain disabled until their
respective support and qualification gates are met and the owner approves cutover.

## Owner decisions

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

**2026-10-19 — T4/T9 growing reservations.** Owner approved replacing the single-active-file resource allocation rule with
reservations that grow as files grow, keeping the approved total/per-user budgets, free-space floor and large-file support.
Replace the obsolete single-concurrent-winner strategy test with concurrent no-overspend controls; preserve all privacy,
resource, sharing and qualification assertions. Users should be able to save Word temporary files and overlapping small files;
real budget exhaustion still refuses the affected save. [Design](UX-LARGE-CONCURRENCY.md) and independent security/lifetime
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
  (metadata, partial), ux/large (opt-in), ux/t11 (SOP startup proof, compaction retention, [review checklist](M2-REVIEW-CONDITIONS.md)
  once merged to this branch). T4 `uxk5t4ord2` stopped at cycle 548 (journal scan O(n) -> reply timeout -> stranded name; receipt kept);
  rerun `uxk8t4ord` in progress. Dev-disk shutdown freeze = OneDrive DebugBreak into the absent kernel debugger (not SafeUpload).

**2026-10-16 — T9 large-file product defaults and upgrade.** Owner accepted total staging budget min(32 GiB, 10% of
available space), per-user min(8 GiB, total/4), free-space floor max(1 GiB, 5% of volume); resource refusal is fail closed
with a staging-space alert, isolated per SID, with no fixed per-file staging cap. Follow-up authorizes `StageSpace.Enabled`
to default true, runtime formulas with explicit overrides, a measured parser memory default, suitable inspection defaults
and safe existing-install migration. `ux/large` implementation on base `a2b67984`: [design](UX-LARGE.md),
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
  [controls](T5-NATIVE-PUBLIC-OPENS.md#descriptor-candidate-controls-2026-10-15) (equal access in all 30 rows; Windows re-marks it on
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
  nonpublication obligations, as specified in [T5-RECOVERY-HOLDS.md](T5-RECOVERY-HOLDS.md)) does not veto voluntary unload; the
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

Two feature WDK builds (Debug/Release), PREfast and ApiValidator at **0 warnings / 0 errors**, binary-import availability PASS,
and the complete four-leg feature agent matrix (Debug/Release × user/SYSTEM). Compile-time staging-out profiles were retired by the owner on 2026-10-15.
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

**Next delivery checkpoint:** qualify one matched local-NTFS pair, starting with T4. Planned M2 rows remain authorized on
win10-debug3 only (owner, 2026-10-13); no revised pair has qualified. Keep the unchanged raw-volume, Verifier, context/pool and
separate restoration gates. Current [integration evidence](evidence/2026-10-17/m2-integration-status.md) and
latest [development checkpoint](evidence/2026-10-19/m2-checkpoint.md) record retained artifacts and pending matrix/app results.

| T item | Current state | Next required result |
|---|---|---|
| T4 | Pair `d1068cc3` kernel (`t4pagefix1` gates 0/0, imports PASS) + agent `586ae7cb` (`m2t4refund2` 2,801 per configuration). Smoke `1020i` 256/256, 0 stage files, worker idle; only the pool-endpoint sampling was missing (rerun at 64-cycle sampling). Root causes and fixes: [checkpoint](evidence/2026-10-20/t4-checkpoint.md). | Smoke with sampling, one-boot 10k in three modes, raw-volume cells C01–C04/B01/B02/X01 in three modes, lost-reply row, separate restoration. |
| T5 | Native namespace corrections reviewed. Latest [real Notepad diagnostic](evidence/2026-10-19/m2dev1019f-result.md): unprotected control passes; protected old-dev-pair save refuses for space. | Passing four-leg agent matrix, forced native delete orders, clean/CPF Notepad and public operations in all three modes. |
| T6 | Copy-fallback component evidence and owner-approved folder/cross-drive metadata contract exist; merged namespace/folder source is unqualified. | Final-pair file/folder moves, idle rename and pending conflicts in all required modes. |
| T7 | Windows-authorized read design retained. | Final-pair authorized/denied reads and exact bytes. |
| T8 | Standard-user app dev evidence exists; final metadata implementation/qualification remains incomplete. | Eight required app workflows, matching owner/DACL/SACL/label/times/attributes/MOTW controls in all modes. |
| T9 | Whole-SID allocation causes overlapping-save refusals; proved-refusal repair passes 156 focused Windows controls. Growing reservations approved; [design revised after review](UX-LARGE-CONCURRENCY.md), acceptance pending. | Windows budgets/upgrade, parser bounds, large-file and failure UX on the matched pair. |
| T10 | Earlier runtime-Verifier component pass exists. | Final-pair permissions/ownership rows in all modes with metadata preservation. |
| T11 | Epoch/archive and context retirement repairs integrated; component controls are distinct from qualification. | Final journal/recovery/lifetime gates and one adversarial review of the working M2 pair. |

- [x] T4: build/agent prerequisites closed on the pair above; failed attempts and root causes in the [2026-10-20 checkpoint](evidence/2026-10-20/t4-checkpoint.md).
- [ ] T4: smoke with sampling, 10k in three modes, raw-volume cells and separate restoration (rows in flight).
- [ ] T5–T11: qualify the coherent pair against every existing assertion; component/dev passes do not complete these items.
- [ ] T11: perform final adversarial review only after the runtime evidence exists.

The superseded checkpoint narratives are in [POST-MVP-LOG.md](POST-MVP-LOG.md#archived-m2-checkpoint-narrative--replaced-2026-10-17).

### T4. Remove the 128-saves-per-boot ceiling

**Problem:** retired versions retained slots and contexts; later saves failed until reboot.
**Done when:** 10,000 mixed approve/block saves in one boot pass with flat nonpaged pool, no Verifier hit, no cap refusal, zero residual
versions/views/tombstones/stages and an idle worker; C01–C04, B01, B02 and X01 pass in all three modes.

Design: [stage lifetime](T4-STAGE-LIFETIME.md), [lease/retirement correction and reopen controls](UX-LEAK2.md).
Latest [source/build/review evidence](evidence/2026-10-17/m2-integration-status.md) is component evidence; Windows qualification is open.
[Boot-Verifier smoke](evidence/2026-10-19/m2t4smoke1019a-verdict.txt) failed after nine attempts; owner authorized focused diagnosis
on 2026-10-19. [Separate restoration](evidence/2026-10-19/m2t4smoke1019arestore-restoration.txt) passed; 10k has not started.
The [prior 10k contexts failure](evidence/2026-10-12/m2t4purge10ka1-verdict.txt) and
[attribution rows](evidence/2026-10-13/t4-delete-kd-attribution-result.md) remain preserved.

**Unchanged owner gates (2026-10-12):** 256-cycle slope is INFO only; retain the 64 KiB idle endpoint band. Long-row slope stays
<4 B/cycle from cycle 1,000 and the 64 KiB endpoint band. Registry occupancy must remain within capacity with zero idle capacity
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
- [ ] T4: qualify V20 allocation/Prepare lost-reply cleanup under protection; exact faults remain in the lifetime design.
- [x] T4: fix serial-save refusals (agent refund wait, `586ae7cb`) and the pageable-router double fault (`d1068cc3`).
- [ ] T4: pass 256-cycle boot-Verifier smoke with 64-cycle sampling: idle endpoint, purge statuses, release measurement (`1020i` passed all but sampling).
- [ ] T8: immediate-reopen control (moved from T4, owner may veto): original owner's reopen passes, a second process's read/write open fails Win32 32.
- [ ] T4: pass unchanged one-boot 10k ordinary/runtime-/boot-Verifier cells, including loaded-context and admission-recovery gates.
- [ ] T4: run C01–C04/B01/B02/X01 with the raw-volume observer in all modes, then repeat on the final M2 pair. Sampled bytes do not replace raw observation.


### T5. Empty saves, Notepad Save As and deletes

**Problem:** public probe deletion was refused and private-delete names stayed occupied until physical cleanup. EmptyHeld broke normal
zero-byte file operations and added a successor protocol. Empty is ordinary content; public deletes are M2.
**Done when:** clean saves publish exactly their bytes; CPF saves hand back and leave new names absent or existing prior bytes intact;
no empty probe is left behind; no uninspected nonempty byte reaches the public name. All existing other assertions pass in three modes.

Designs: [deletes/teardown](T5-DELETES.md), [native public opens](T5-NATIVE-PUBLIC-OPENS.md),
[bound publication/recovery](T5-BOUND-PUBLICATION.md), [current MVP namespace correction](T5-UX-NAMESPACE-GAP.md).
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
- [ ] T5: pass the complete four-leg feature agent matrix and deliver the reviewed matched driver/agent pair; two feature WDK profiles, PREfast/ApiValidator/import gates remain mandatory.
- [ ] T5: qualify native delete before seal and after independently observed publication; both DeleteFileW calls succeed, with failed-CREATE identity intact.
- [ ] T5: qualify real Notepad clean/CPF Save As in ordinary/runtime-/boot-Verifier modes with independent destination bytes and separate restoration.
- [ ] T5: qualify Explorer New Text Document → rename → another-process Notepad open; empty copy/move; clear-and-save; DELETE-authorized/refused public deletion;
  delete during a newer in-flight save; delete then blocked CPF save with no empty leftover.
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
- [ ] Directory moves (owner 2026-10-16: like copies; idle renames inside protection): design note (RCA `driver/evidence/2026-10-16/t6-dirmove-rca-sol61.md`),
  review, implementation, native caller traces, then D-rows in all three modes. The small unbound MVP [directory UX change](UX-DIRECTORIES.md) has local controls and Sol 6.1 xhigh acceptance with conditions; WDK/native three-mode qualification remains open.
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
**Done when:** Word, Excel, PowerPoint, WordPad, Explorer replace, browser download, robocopy and 7-Zip rows pass all three modes (Paint moved
after M2 with image OCR, owner 2026-10-16);
the publishing application can reopen the file and agreed metadata is preserved.

- [ ] Trace/replay real save sequences, including temporary/backup deletes under T5; respect staged rename limits.
- [ ] PowerPoint and archive inspection (owner 2026-10-16): PowerPoint `1d485942` merged, matrix
  [`t9-pptx1`](evidence/2026-10-16/exact-agent-matrix-t9-pptx1-summary.txt) ExactAgentMatrixGate=PASS (2,263 user + 25 SYSTEM per feature configuration);
  ZIP inspection and the default monitored extensions (agent and backend) `5c9bb10b`/`9561825a` merged, matrix
  [`t9-archives2`](evidence/2026-10-16/exact-agent-matrix-t9-archives2-summary.txt) ExactAgentMatrixGate=PASS (2,360 user + 25 SYSTEM; `t9-archives1`
  failed on an obsolete `.zip` test example, receipt kept). `.7z` is refused (`archive_7z_unavailable`): SharpCompress was rejected
  for unbounded header/dictionary allocation ([assessment](../agente/docs/T9-ARCHIVE-INSPECTION.md)); owner choice pending.
- [ ] Implement and test the metadata contract decided 2026-10-16 (native owner/DACL/SACL/label, timestamps, attributes; Zone.Identifier
  carried with its file; other ADS, EAs, EFS, offline, reparse points and hard links refused).
  - [ ] Unbound `ux/meta` [basic metadata increment](UX-METADATA.md): exact sealed dates/ordinary attributes and unsupported-storage checks;
    native descriptor construction, public metadata serialization and inspected atomic MOTW remain unfinished. No T8 completion or VM qualification.
  - [ ] `ux/meta2` [round-2 prerequisite checkpoint](UX-METADATA-ROUND2.md): strict native absence/query validation and dormant descriptor/MOTW controls; whole-version producer, native construction and commit fence remain blocked/open. No T8 completion.
- [ ] Qualify application rows under the matched pair with independent byte observation and restoration.

### T9. Large files and complete inspection

**Problem:** old 16 MiB driver/seeding limits and whole-memory extraction prevent ordinary large-file use.
**Done when:** no fixed driver size cap; per-user/total stage budgets fail closed without harming other users; full-content inspection
uses bounded memory; incomplete inspection is Blocked with hand-back and policy-authorized justification; runtime rows prove privacy.

Design/qualification: [large-file budgets and upgrade](UX-LARGE.md), [Windows rows](UX-LARGE-VM.md),
[recovery](UX-LARGE-RECOVERY.md), [inspection coverage](../agente/docs/INSPECTION-COVERAGE.md).
Owner-approved runtime budget/default formulas are in Owner decisions. Bounded scanner scratch does not prove bounded parser/capture memory.

- [x] T9: complete-or-refuse Office/PDF coverage implementation and independent fixtures (`a46124c7`, `52fbb7cb`); prior component matrices
  [coverage](evidence/2026-10-13/exact-agent-matrix-t9-coverage1-summary.txt), [round 2](evidence/2026-10-13/exact-agent-matrix-t9-round2-int2-summary.txt).
- [x] T9: implement failure classes, bounded worker concurrency, notifications, single-handle snapshot and scanner-integrity controls;
  [component evidence](evidence/2026-10-10/m2-agent-component-gates.json).
- [x] T9: owner resolves all-zero card and exact PANOSE/Office-owner-file/PowerPoint-thumbnail choices; preserve the remaining content refusals.
- [ ] T9: qualify integrated identity-bound capacity grants, per-SID/total/free-space budgets, exact snapshot/orphan accounting, failed-prefix refusal,
  legacy upgrade and startup recovery; [latest local source receipt](evidence/2026-10-16/ux-large5-local/result.md) is not Windows pair qualification.
- [ ] T9: finish/qualify whole-file streaming, all required format/encoding/extraction coverage, seeding cost and capture/storage/parser bounds.
  - [ ] Include Office auxiliary/drawing/chart/VML/external/member payloads and PDF fields/annotations/metadata; inspect completely or refuse.
  - [ ] Keep corrupt/encrypted/password-protected/unsupported/incomplete content blocked; images remain refused except the exact approved thumbnail.
- [ ] T9: qualify policy-load/snapshot/parser/extraction-limit/timeout/disk-full failures, actionable UI, exact hand-back/digest and policy-bound justification.
- [ ] T9: measure cold/warm end-to-end throughput/latency and hostile-input process peak memory, including publisher and concurrent/seed UX.
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

Design: [unbound journal scaling](T11-UNBOUND-JOURNAL-SCALING.md); [review conditions](M2-REVIEW-CONDITIONS.md).
Latest [integration evidence](evidence/2026-10-17/m2-integration-status.md) distinguishes source acceptance from qualification.

- [x] T11: nested sealed-stage guard (`203d31e9`), serial generation arithmetic (`b8394357`), cache eviction (`cb1d0930`) and bounded index/closure controls implemented.
- [ ] T11: qualify SOP startup/lifetime and exact context retirement on the final pair; the integrated pre-boot review is accepted with runtime conditions.
- [ ] T11: finish/qualify journal packing/compaction and crash recovery without losing full-identity generation barriers, unresolved cleanup, live-epoch replay or ancestry obligations.
- [ ] T11: prove bounded hot-set/end-to-end behavior through the protected 10k workload; component index timings do not close durable I/O scaling.
- [ ] T11: close every M2 review condition against the final matched pair, then obtain one adversarial review of the working milestone.


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
  - [x] [Design draft](T22-SMB-UNC-DESIGN.md) (2026-10-13, Astra): local fixed-NTFS stage, enrolled UNC identity, Kerberos caller
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
  - [x] [Design](T18-COVERAGE-RETRY.md): up to three retries (10/20/40 ms) of exactly `0x800704D5` within one poll; nothing held or synthesized.
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
