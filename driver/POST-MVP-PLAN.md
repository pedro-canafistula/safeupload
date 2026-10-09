# SafeUpload driver: post-MVP plan

Written 2026-10-08 on `feat/driver-post-mvp` (= `main` `aaab5c0c`, which carries the frozen MVP pair: driver `5ebe139a`, agent `51ba5873`).
Current status, gate results and known issues are in [MVP-PLAN.md](MVP-PLAN.md); this file is the work plan that follows them, in priority
order. Where a cause is not yet measured, the task says so and lists hypotheses from reading the code; treat those as leads, not findings.

## What "complete" means

The driver is complete for the local-NTFS product on Windows 10 22H2 build 19045.2965 when all of these hold:

1. **It can stay loaded on a real machine**: no CPU churn at idle, new users can sign in, large installers and Windows Update complete.
2. **Everyday file work behaves like Windows without the driver, plus inspection**: Notepad, Office and other common applications save into
   a protected folder; copies and moves into it are inspected the same way; reading and permission changes are left to Windows; no per-boot
   or small file-size ceiling a user would hit.
3. **It is a release build**: staging is the release configuration, the test-only diagnostics are out of it, and it installs, upgrades
   and uninstalls cleanly. It stays test-signed (test signing on, Secure Boot off) until the owner says otherwise.
4. **It is qualified**: the full invariant suite (all variants) passes in all three modes, plus soak, stress and coexistence runs.

Other Windows builds and destinations beyond local NTFS (USB, SMB, sync clients, ReFS) come after that.

## Rules for every task

Carried over from the MVP; they apply to every driver change on this branch.

- Every driver commit: the four WDK configurations build with PREfast and ApiValidator at 0/0; kernel changes that run on a VM run under
  runtime Driver Verifier; the affected suite rows pass end to end with the raw-volume observer (`ForbiddenByteCount` 0) and a clean
  restoration (`Get-StagedBaseline.ps1`).
- One adversarial review per milestone against the working system, plus one before the first VM boot of any change to object lifetime,
  lock order or the retirement gate (T4 and T6 in particular). Reviews only by Luna; implementation is done here.
- Each milestone ends with a new frozen pair (new build labels) and the full three-mode gate. BLOCK-window cells run serially on one VM.
- Harness changes pass `Invoke-HarnessWindowsGate.sh` (Windows PowerShell 5.1) before they are used for a gate run.
- Owner decisions in force stay in force (no process taint, no scan-based or timer-based fixes for writer state, sticky Unknown until
  reboot, Activating never reports Ready). A task that seems to need an exception stops and asks.
- Any change that removes a refusal must come with a suite row proving that unapproved bytes still cannot reach a protected folder.

## Priority order

Sizes are rough: S = a few days, M = about a week, L = several weeks.

| # | Task | Tier | Size | Depends on |
|---|---|---|---|---|
| T0 | Field diagnostics: deny ring and counters readable while the agent runs; installer quick fixes | P0 | S | - |
| T1 | Event-driven reclaim worker (no rescan loop); rerun the five boot-Verifier cells | P0 | M | T0 |
| T2 | Find and fix the denial that breaks new-profile creation | P0 | M | T0 |
| T3 | Large installers and Windows Update with the driver loaded (M365, cumulative updates) | P0 | M-L | T1, T2 |
| T4 | Reclaim stage slots: remove the 128-versions-per-boot ceiling | P1 | M-L | T1 |
| T5 | Notepad Save As | P1 | M | T0 |
| T6 | Moves into a protected folder are inspected like copies | P1 | S-L | T0 |
| T7 | Reads are never refused | P1 | S | - |
| T8 | Office and common-application save patterns, metadata fidelity | P1 | L | T4, T5 |
| T9 | Large files: no fixed size cap, whole-file inspection, "could not inspect" is blocked | P1 | M | T4 |
| T10 | Permission and owner changes reach the real file or folder | P1 | M | T0 |
| T11 | Close the review conditions (Luna P2s) | P1 | S-M | - |
| T12 | Release build: staging becomes the product configuration, diagnostics test-only | P1 | M | T11 |
| T14 | Driver install, upgrade and uninstall | P1 | M | T12 |
| T15 | Full suite: section-4.1 variants, P01-P06, RV4, dedicated latency | P2 | L | M2 |
| T16 | Soak, stress and fault injection | P2 | M | M2 |
| T17 | Coexistence: antivirus/EDR filters, BitLocker, VSS, indexer, backup, OneDrive | P2 | M | M3 |
| T18 | Operating Degraded/Unknown in the field | P2 | S | T0 |
| T19 | Continuous no-unapproved-byte evidence (mutation ledger, C05 denial ledger) | P2 | M | T15 |
| T13 | Altitude, production (attestation) signing, Secure Boot on (deferred: test mode only) | Later | M + lead time | owner |
| T20 | Other Windows builds (deferred by the owner) | Later | L | M4 |
| T21-T24 | USB/removable, SMB/UNC, cloud-sync folders, ReFS | Later | L each | M4 |

Milestones: **M1 "safe to leave loaded"** = T0-T3; **M2 "everyday file work"** = T4-T11; **M3 "release candidate"** = T12 and T14;
**M4 "qualified"** = T15-T19; then T13 and T20-T24, each on its own.

## P0: the driver can stay loaded (M1)

### T0. Field diagnostics and installer quick fixes

**Problem.** The three P0 bugs could not be root-caused on the manual-test VM: the Inspector cannot open the filter port while the agent
holds it (`0x800704D6`), and the kernel FileIo trace of the failing profile creation showed no `0xC0000022` create, so we do not know which
operation the driver refused.

**Work.**
- A bounded, always-on **deny ring** in the driver: every operation SafeUpload completes with a failure status (`ACCESS_DENIED`, `RETRY`,
  `SHARING_VIOLATION`, `DELETE_PENDING`, `INSUFFICIENT_RESOURCES`, `FILE_TOO_LARGE`, ...) records a call-site ID, major/minor function,
  status, requestor PID, IRQL, whether `IoGetTopLevelIrp()` was non-NULL, transaction present, and the name when it was already resolved.
  Fixed size, no allocation on the I/O path, no name query added just for the ring.
- Expose the ring and the key counters (reclaim passes, registry entries/limit, parked and unresolved probes, section slots in use, stage
  streams in use, Unknown reasons) through the agent: a query message the agent already authenticated forwards, and an admin-only command
  on the `SafeUpload.Agent` pipe. Field diagnosis must not need the Inspector.
- Installer quick fixes (agent side, needed by every manual test): register the service with
  `--Interception:Mode=Minifilter --Interception:StagingPrototype=true`, and accept `SERVICE_SID_TYPE:  UNRESTRICTED` in the final check.

**Done when** the ring shows a known refusal from a scripted test (for example a rename into `C:\Protected`) through the agent, with the
Inspector not running, and a clean install leaves `admissionCoverage` Ready without hand edits.

**Status 2026-10-09: done.** The deny ring recorded the real denied rename of C05 on a debuggee through the agent's diagnostics pipe with the Inspector not
running; the installer registers the minifilter flavour and leaves coverage Ready. Evidence and the diagnosis of every later refusal: `POST-MVP-LOG.md`.
- [x] deny ring + counters + pipe; installer quick fixes; agent gate green with the SYSTEM test step
- [x] ring seen recording the real C05 denial on a debuggee

### T1. Event-driven reclaim worker

**Problem.** `StageRegistryReclaimWorker` (`StageWriters.c`) sets `STAGE_RECLAIM_RESCAN` whenever a pass leaves an entry unfinished
(`unfinishedScan`: an unresolved or parked alias probe, a pending scope scan), and `StageRegistryReclaimWorkerFinish` requeues immediately.
An entry that cannot finish keeps the worker spinning: 2.5-5k passes/s measured, about 20,000 special-pool allocations/s under boot
Verifier, guest CPU at 100% for 20+ minutes. It is the likely cause of the five missing boot-Verifier cells and a suspect for the slow
M365 install.

**Approach (event-driven, no timer).** A pass requeues itself only when it made progress or new work arrived:
- keep the immediate requeue when the batch limit was reached (`reachedBatch`: real work remains);
- when the pass ends with only unfinished entries, compare the registry change sequence and the recheck flag with their values at pass
  start; if nothing changed, park instead of requeueing;
- audit every reason an entry can be unfinished and make sure the event that can resolve it queues a recheck (alias probe completion,
  cleanup/close/section release, which already call `SafeUploadStageWritersQueueRecheck`, rename-churn settle, policy commit, service
  reply). A reason with no wake-up event is a liveness bug to fix at its source, not with a timer. A parked entry stays gated
  (Activating, never Ready), so a missed wake-up fails closed.

**Done when** idle reclaim passes are about zero with a parked probe present (counter from T0); A01-A04, R02, X01, C04 and C05 pass in
all three modes; and boot-Verifier B02 plus C01-C04 BLOCK complete, taking the gate from 64/69 to 69/69. If they still do not
complete, measure what is CPU bound before changing anything else.

**Status 2026-10-09: worker done, boot-Verifier cells pending.** The spin was external wake-ups from every CLOSE/CLEANUP; the worker now requeues only for
bounded work and lifetime events wake it only for a stream something waits on (idle 3,100 passes/s -> about 10). Removing the unpaused requeue exposed a race
in R02 (the cache manager's own close is the only wake-up after a clean holder leaves; if the pass starts after NTFS tore the stream down the promotion is on the
replaced basis, which the harness refuses): fixed with an identity anchor (the pass keeps its by-ID handle while the entry is Activating with a live writer).
- [x] idle passes about zero (A01-A04 pass; counter in the diagnostics)
- [x] R02 passes on the held basis (2 of 2 on the anchor driver)
- [~] A01-A05, B01, R01, R03, X01, C03, C04 on the anchor driver (A02, A03, A05, X01, C03, C04 ok; A01/A04 repeat after an evidence-capture flake)
- [x] boot-Verifier B02 + C01-C04 BLOCK complete on the final driver line -> 69/69 (C01 `m1b1`, C03 `m1d1`, C04 `m1d2`, C02 `m1d3`; B02 `m1w1` on 8e506437, re-run queued)
- [x] runtime-Verifier slice (C05, C01-approve-absent, C01-block-absent, S01) on the final pair: `m1f1`-`m1f4` ok by the gate rule (tier 2) on `m1-driver4`/`m1-agent6`, also R02 `m1f5` and A01 `m1f6`; C05 `m1f2` ring: "recorded the denied rename: sequence 2, status 0xC0000022"

### T2. New user profiles

**Problem.** With the driver loaded (agent running or stopped), a new user's first sign-in fails: ProfSvc 1542 "cannot load classes
registry file. Access is denied", `CreateProfile` returns `0x80070005`, and the failed attempt leaks `HKU\<sid>` and `HKU\<sid>_Classes`
until reboot. `C:\Protected` is on the same volume as `C:\Users`, but the profile is outside every scope, so the driver should not refuse
anything there.

**Leads from the code (unverified).** About 40 call sites fall back to `SafeUploadPolicyMayMatchInstanceVolume` (true for any volume that
hosts a scope) when the operation arrives above PASSIVE_LEVEL, with a non-NULL top-level IRP, or when the name query fails; in those
contexts any operation on `C:` is treated as possibly in scope. Kernel registry hive I/O (the `Registry` process, mapped hive files, KTM
logs) is a plausible trigger. Other candidates: the TxF refusal in `Txf.c` (same fallbacks) and the policy-epoch `STATUS_RETRY`.

**Work.** Reproduce with the T0 ring on (`CreateProfile` for a fresh user), name the call site and operation, and fix the principle rather
than the one case: an operation outside every scope must never be refused. Where the name cannot be resolved in the current context,
resolve the identity some other safe way (file ID and the registry entry, or a deferred check) instead of a volume-wide answer. Add a suite
row for first sign-in of a new user with protection active (the harness pre-creates the actor profile today, which is why no row caught it).

**Done when** the new row passes in all three modes, the deny ring shows no refusal outside a scope during sign-in, and every existing row
still passes (no refusal was weakened inside a scope).

**Status 2026-10-09: fixed and verified by a real first sign-in; row U01.** Causes found with the ring: a lookup that proves the path absent was refused as
"unresolved"; the volume root counted as an ancestor of the protected scope for attribute changes; the alias probe followed reparse points (Store app-execution
aliases) and failed on `pagefile.sys`; an Activating entry for an unrelated name refused outside writers; and a network volume counted as in scope for any
local prefix (the `\Device\Mup` instance, early boot). Row U01 = `driver/scripts/Invoke-NewProfileDiagnosis.sh` (verdict file). U01 is not part of the 69 cells.
- [x] ring names the refusals; fixes without weakening a refusal inside a scope (the standard user is still refused directory creates in the protected folder)
- [x] row U01 written, with a verdict
- [~] U01 PASS on the final driver (all required lines pass except the two Mup refusals, fixed in 6b83f608, re-run pending)
- [~] U01 in boot-Verifier mode (`u01h`): everything passes except one transient refusal of a writable section of a pre-scope writer's file (FontCache) while its entry waits for its alias probe: **T2c** (options in the log)
- [ ] **T2c** also hits a registry hive: `t3cue` refused the Registry process's writable section of `config\DRIVERS` at boot (`policyScope`). Chosen design (not
  built yet): when the section gate would refuse only because the entry's alias probe is pending, at PASSIVE and not nested, it moves that entry to the front
  of the worker and waits a bounded time (about 2 s) for that probe, then decides; on timeout it refuses as today. Rejected: a "single link" name-only rule
  (a hard link made through another stream's handle does not reach the default-stream entry, so its rename version is not advanced).
- [x] FileStandardLinkInformation (0x36) on a staged stream answered from the backing file; U01 `u01n` and `u01o` (boot Verifier) all PASS on `m1-driver13` (T2c fixed too)

### T3. Large installers and Windows Update

**Problem.** The Microsoft 365 installer ran very slowly (about 21,000 metadata operations/s in `System`) and then failed with "couldn't
use a required file". Windows Update, Defender updates and Store updates were never exercised with the driver loaded, and a deployed
driver has to survive monthly updates. (The platform stays build 19045.2965 for now; these runs check that installing an update with the
driver loaded works, not that the driver is qualified on the updated build, which is T20.)

**Work.** Re-measure after T1 and T2 (some or all of this may be the same causes). Then add qualification runs, each with the driver
loaded and a protected folder on `C:`: Microsoft 365 install, an MSI install, a Windows cumulative update and reboot, a Defender platform
update. Record duration against the same run without the driver, the deny ring, and the writer-registry high-water mark: the registry
holds at most 4,096 entries (`SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT`) and exhaustion makes coverage Unknown until reboot, so an installer
that fills it would leave protection Degraded.

**Done when** all four complete with no refusal outside a scope, coverage still Ready afterwards, and an overhead number the owner accepts.

**Status 2026-10-09: runner written, not yet run.** `driver/scripts/Invoke-InstallerWorkload.sh <dom> <tag> msi|m365|cu|defender driver|control` (workloads in `driver/scripts/t3/`).
The debuggees have internet access and about 40 GB free; Defender is disabled by policy in the baseline (the defender workload removes the policy inside the
checkpoint). Known risk to check first: M365 and installers use by-ID opens and many concurrent writers, which the T2 gate changes address.
- [x] msi: driver 9.2 s, control 7.0 s, no refusal, Ready, registry high-water 225/4096
- [x] m365: `t3m365c` PASS on `m1-driver14` (402 s, control 418 s; empty deny ring, Ready, no overflow: the compact tier absorbed the burst after the T3c fix `b995943b`; with `m1-driver13` it installed but overflowed the registry and left coverage Degraded)
- [x] cu: `t3cuh` PASS on `m1-driver13` (1,135 s, empty deny ring, Ready, high-water 4,015/4,096 - thin margin, see T3c). Before: KB5066791 installs with the driver (19045.2965 -> 19045.6456 in `t3cub`/`t3cuc`/`t3cud`); 0 legacy-gate refusals since `c70a4354`; the nested TiWorker writes (23 install, 8 servicing) are still refused (T3d, `704146b8` names them). T3d cause: their entries are Unscoped but never classified (aux `0xE5000007`); fix `77b76faa` (create-time alias proof -> OUTSIDE, distrusted during a scope transition after Luna's P0), builds `m1-driver10`; CU `t3cuh` pending
- [x] defender: `t3defenderu` PASS, 170.4 s, no refusal, Ready, high-water 277/4096; control `t3defenderv` 172.3 s
- [x] control runs: msi 7.0 s, defender 172.3 s, cu 921.3 s (driver 1,135.3 s, +23 %), m365 418.3 s (driver 402.2 s)

## P1: everyday file work (M2)

### T4. Stage-slot reclamation (remove the 128-per-boot ceiling)

**Problem.** Retired versions stay on `StageStreams` until unload and keep their `StageStreamCount` slot (`STAGE_LIMIT` 128,
`StageStream.c`). After 128 staged versions in one boot, every create in a protected folder fails with `STATUS_INSUFFICIENT_RESOURCES`
until reboot. One user saving a document with autosave reaches that in a day.

**Approach.** Retired versions are kept today so no view, tombstone, directory overlay or process reference can dangle. Replace "keep
everything until unload" with references: once a version is retired and disposed of by the service, its stream structure is released on
the last reference, and only a small tombstone record (name, destination generation) stays in a bounded table. Count only live versions
against the cap. This is a lifetime change: design note first, Luna review before the first VM boot, special pool on.

**Done when** 10,000 save cycles in one boot (approve and block mixed) run with flat nonpaged pool and no Verifier hit, and C01-C04, B01,
B02 and X01 pass in all three modes.

### T5. Notepad Save As

**Problem.** Save As to `C:\Protected\ok.txt` published a 0-byte, SYSTEM-owned file (journal: State 5, SHA-256 of empty input) and Notepad
then reported "You don't have permission to modify files in this network location". The individual opens were not traced.

**Work.** Trace the sequence with the T0 ring and Process Monitor on the guest. Two hypotheses to confirm or reject: (a) the dialog's probe
create (possibly delete-on-close) became a version that was sealed and published; a delete-on-close or deleted version must be discarded,
never published; (b) Notepad's write-open arrived while the earlier version was `Sealed`/`Inspecting`/`Publishing` and was refused instead
of starting a new latest version (X01 already proves latest-wins for two live writers). Fix the cause and add a suite row that replays the
recorded Notepad sequence.

**Done when** Save As of clean content publishes that content, Save As of CPF content hands it back, no empty version is published, and
the new row passes in all three modes.

### T6. Moves into a protected folder are inspected like copies

**Owner decision (2026-10-08):** moves must not stay refused; they are analysed exactly like copies.

**Why it is refused today (C05).** On the same volume a move is a rename: NTFS moves the existing file into the folder and no byte is
written, so the staged write path never sees the content. Letting the rename through as it is would publish uninspected content.

**Approach, cheapest first.**
1. Answer a rename or hard link from outside into a protected folder with `STATUS_NOT_SAME_DEVICE` instead of `ACCESS_DENIED`. That is the
   answer Windows gives for a move to another disk, and callers that support cross-disk moves then copy and delete the source: `MoveFileEx`
   with `MOVEFILE_COPY_ALLOWED` (used by .NET `File.Move` and `cmd move`) and, expected but to verify first, the Explorer copy engine. The
   copy goes through the normal staged path, so it is inspected, published or handed back like any copy. If the copy is blocked the source
   is already gone, but the user's bytes are in the hand-back folder, so nothing is lost. Renames inside the folder (Office's temporary
   file to final name) are unchanged.
2. Only if Explorer does not fall back: do the conversion in the kernel (stage the moved file's content as a new version and remove the
   source after the copy). That is a much larger change with its own design review.

Callers that do not allow a cross-disk copy get the same error as a move to another drive. Directory moves into the folder take the same
path (Explorer then copies the tree).

**Done when** Explorer drag, `Move-Item`, `cmd move` and `MoveFileEx` of a clean file end with it published and the source removed; the same
with a CPF file ends with it handed back; C05 is rewritten from "refused" to "inspected", and no move publishes uninspected bytes (observer).

### T7. Reads are never refused

**Owner decision (2026-10-08):** the driver does not refuse reads; who may read a file is decided by its permissions and the
administrators.

**Work.** Remove the read refusal in the legacy post-create path (`Filter.c` `SafeUploadPostCreate`: `FltCancelFileOpen` of a file classified
sensitive in a destination scope unless an override covers it), and check no other path refuses an open that has no write, delete or
metadata-change access. Writes are unaffected: they still go through staging.

**Done when** a justified sensitive file can be opened and read by a standard user with read permission, a user without read permission
still gets the normal Windows denial, and a suite row covers both.

### T8. Office and common applications

**Work.** Record the real save sequences of Word, Excel and PowerPoint (temporary file in the same folder, rename original to backup,
rename temporary to the final name, delete backup), plus Paint, WordPad, Explorer copy with replace, a browser download into the folder,
`robocopy` and a 7-Zip extraction. For each, decide the expected outcome and add a suite row that replays the sequence. The rename support
is a two-slot transaction with at most 16 moves per version; check the Office pattern stays inside that.

Also check what the published file keeps from the user's version: owner (it is SYSTEM today), DACL inheritance, timestamps, attributes,
alternate data streams (for example `Zone.Identifier` on downloaded files) and EAs. Decide per item whether the service copies it or the
destination keeps the old one, and test it.

Install the applications before installing the driver (owner note) until T3 is done.

**Done when** each application row passes in all three modes and a user can open the published file with the same application afterwards.

### T9. Large files

**Today.** The driver caps a staged version at 16 MiB (`STAGE_MAX_BYTES`, `STATUS_FILE_TOO_LARGE`), the agent seeds at most 16 MiB of an
existing file into a stage (`StagedTransferAllocator.MaximumSeedBytes`), and the legacy policy value `MaxFileSizeMb` (20) returns
`AllowedWithoutInspection` above it, which in staged mode never publishes. Office files, PDFs and images often exceed 16 MiB.

**How commercial DLP products handle it.** They cap *inspection*, not the file: Symantec's endpoint agent inspects 30 MB by default
(150 MB tested maximum) and ignores larger files; Microsoft Purview scans the first 2 million characters of extracted text and lets a rule
match "content not scanned"; Forcepoint checks only name, size and a fingerprint above 100 MB. Skipping or truncating is a bypass in our
threat model: a standard user pads a file past the limit, or puts the CPF after the scanned part.

**Approach (owner agreed on 2026-10-08).**
- No fixed size cap in the driver. A staged version is an ordinary NTFS file, so its size is bounded by a **stage-space budget** (per user
  and in total, as a policy value) rather than by 16 MiB; exhaustion fails closed with a disk-full status and does not affect other users.
- The agent inspects the **whole** file, streaming with bounded memory; no truncation.
- One verdict for every case where the content cannot be fully inspected: larger than the inspection limit (policy value; default chosen
  after measuring scan throughput on the VM, starting the measurement at 256 MiB), encrypted or password-protected, corrupt, an archive past
  its extraction limits, inspection timeout. That verdict is **Blocked**, with hand-back, and justifiable when the policy allows overrides,
  so the product stays fail closed.
- Measure the cost of seeding: opening an existing large file for write copies it into the stage before the open returns.

**Done when** a file at the inspection limit is approved and published byte-exact, one over it is blocked and handed back, a CPF placed at
the end of a large file is found, and a stage-space exhaustion attempt by a standard user fails closed without affecting other users.

### T10. Permission and owner changes reach the real file or folder

**Problem.** With the driver loaded nobody, administrators included, can change the permissions of the protected folder or its files
(`icacls` was refused in the manual test). A handle to a protected file points at the private staged version, and `StageSecurity.c`
refuses `WRITE_DAC`/`WRITE_OWNER` on it ("never give a staged handle authority to weaken the backing file's private ACL"); directory
opens with those rights go through the directory-mutation admission and are refused too.

**Approach.** A permission or owner change adds no content, so it does not need inspection. Apply it to the destination file or folder (the
real one), never to the private backing, and let Windows' own access check decide who may do it. Keep auditing changes (`ACCESS_SYSTEM_SECURITY`)
for administrators only, as Windows does.

**Done when** an administrator can change the folder's and a file's permissions with `icacls` and Explorer while the driver is loaded, the
private backing's ACL never changes, and a standard user still cannot get unapproved bytes into the folder through a permission change
(suite row with the observer).

### T11. Review conditions

Small, independent fixes from the Phase 5 and gen4b reviews:
- `StageCreate` sealed-stage reopen calls `FltQueryInformationFile` under the namespace lock with no `IoGetTopLevelIrp()` guard
  (`StageStream.c` around line 1391): restrict that branch to a NULL top-level IRP context or route it safely.
- Policy generation is a signed `LONG` (`StageWriters.c` around line 5295): use an unsigned 64-bit generation, compare with wraparound-safe
  arithmetic, and add a test that starts near the old limit.
- Retire changed-SOP entries from the bounded registry.
- Turn the SOP-lifetime premise of `StageRegistryAssociateSectionPointer` into a start-up check that marks the volume Untrusted if it does
  not hold, alongside the existing canary.
- Agent: the journal scan cache clears at 50,000 entries and can then reread the whole history on every scan; replace the clear with
  eviction, and add journal compaction so it stops growing.

**Done when** each item has its own commit with a test or a suite row, and the M2 review closes them.

## P1: release candidate (M3)

### T12. Release build configuration

**Problem.** Staged writes compile only with `SafeUploadStagingPrototype=true` (`SafeUpload.Minifilter.vcxproj`); the release
configuration has none of `Stage*.c`. The staging build also carries diagnostics that must not ship: Inspector-only protocol extensions,
the admission trace, the canary hold, the volume-callback probe.

**Work.** Make staging the product configuration and move every test-only hook behind a separate test configuration (owner rule: test-only
hooks only in the test build). Review the communication port surface of the release build: which messages exist, who may connect (service
SID only), input validation. Keep `Test-NormalBuildIdentity.ps1` (or its successor) proving that the release binary contains none of the
test-only code. CodeQL, PREfast and ApiValidator at 0/0 on the release configuration.

**Done when** the release configuration passes the full gate and the identity test shows no test-only message or hook.

### T14. Install, upgrade, uninstall

**Work.**
- Driver install as part of the product installer: INF install, BootPolicy seeding, reboot (installation needs one reboot by design).
- Upgrade: driver and agent versions in the field differ for a reboot; define protocol version negotiation and test old-driver/new-agent
  and the reverse.
- Uninstall: back to a clean machine after reboot, no residue (`Reset-StagedProductResidue.ps1` is the starting point).

**Done when** install, upgrade and uninstall pass on a clean VM.

## P2: qualified (M4)

- **T15. Full suite.** The other section-4.1 variants of each row, P01-P06 and RV4 (deferred on 2026-10-06), dedicated latency runs, and
  the new rows from T2, T3 and T5-T10, all in three modes. Fix the parallel-pool flake in BLOCK cells (the agent's flush stalls under disk
  pressure when three guests run) or keep them serial.
- **T16. Soak, stress and fault injection.** Several days of scripted use with many saves; Driver Verifier with low-resources simulation;
  power loss during seal and publication (extends R01-R03); service crash loops; full disk; many concurrent writers.
- **T17. Coexistence.** Microsoft Defender and at least one third-party antivirus/EDR filter, BitLocker, VSS and System Restore, the search
  indexer, a backup agent, OneDrive in the user profile, `chkdsk` and defrag on the protected volume.
- **T18. Degraded and Unknown in the field.** Sticky Unknown stays until reboot (owner decision). Make it actionable: the reason (from T0)
  in the agent status and a durable notification an administrator can see, with the documented remedy.
- **T19. Continuous evidence.** If customers or audits need it: a driver-side mutation ledger proving no unapproved byte reached a
  destination continuously (the MVP proves it with sampled raw reads and the final image), and the deferred C05 denial ledger.

## Later

- **Network scopes (from the M1 review, F1).** A destination written as a UNC path is stored as given; the driver compares it with the
  provider-normalized names (`\Device\Mup\...`, `\Device\LanmanRedirector\...`). Canonicalize both sides to one form for exact
  matching, the resident volume cache and boot scopes before `networkPaths` or a UNC destination is offered. Until then the volume
  rules only err on the conservative side (a network volume may match when any prefix is a network path).

### T13. Altitude, INF and signing (deferred)

Deferred by the owner on 2026-10-08: the project runs only in test mode (test signing on, Secure Boot off) until told otherwise. The
provisional altitude is fine there as long as no other filter on the test VMs uses `321410`. Kept here for when it is picked up.

Today the driver is test-signed, which only loads on machines with test signing on and Secure Boot off. Since Windows 10 1607, a kernel
driver on a normal Windows 10/11 machine must carry Microsoft's signature, obtained through the Partner Center (Hardware Dev Center), which
requires an EV code-signing certificate. Two ways to get it:
- **Attestation signing**: submit the EV-signed driver package; Microsoft signs it without running tests, usually within hours. Valid on
  Windows 10/11 client editions, not on Windows Server. Enough for this product on Windows 10/11 PCs.
- **WHQL certification**: run Microsoft's Hardware Lab Kit tests for file-system filters on our own test machines and submit the results.
  Needed for Windows Server, Windows Update distribution, or customers who require certified drivers. Weeks of work.

**Work.**
- Request a minifilter altitude from Microsoft; `SafeUpload.inf` carries a provisional `321410` with a "must not ship" note. Confirm the
  class and load order group for the request (the INF says `ActivityMonitor` class with `FSFilter Anti-Virus` load order; a filter that
  blocks writes may belong in a different group).
- Finalize the INF (`DriverVer`, version resource, catalog).
- EV certificate, Partner Center registration, attestation signing (recommended for the first release; WHQL only if a customer needs it).
- Qualify with test signing off and Secure Boot on.

**Done when** the attestation-signed driver loads with Secure Boot on and passes the gate.

### T20 and new destinations

- **T20. Other Windows builds.** Deferred by the owner on 2026-10-08: the platform stays Windows 10 22H2 build 19045.2965 for now. When it
  is picked up: Windows 11 24H2/25H2 and current Windows 10 22H2 (Windows 10 support ended on 2025-10-14), rerunning the section-behavior
  experiments (`MmDoesFileHaveUserWritableReferences` is observed, not documented, behavior), the start-up canary and the full gate on each,
  and a clear "not qualified" coverage state on any other build.
- **T21-T24. New destinations**, each with its own design, owner decisions and qualification; none may be enabled by removing today's guards:
  USB and removable media (surprise removal; FAT/exFAT have no stable file IDs), SMB/UNC (redirector-level filtering), cloud-sync folders
  (the Cloud Files API and sync clients' own writers), ReFS.

## Outside the driver, needed for a complete product

- Notification app packaged and qualified (a blocked save is silent today), and hand-back copies named after the original file.
- Central policy distribution: the kernel policy message holds at most 16 destination prefixes of 260 characters and 32 extensions of 16
  characters, and the boot policy 32 prefixes (`Protocol.h`, `SAFEUPLOAD_MAX_*`); the server's policy format has to fit those bounds or
  the protocol has to change.
- The agent's TLS-inspection tests that fail without rights to create machine CNG keys (from `main`).

## Owner decisions

Decided on 2026-10-08:
- The platform stays Windows 10 22H2 build 19045.2965 for now (other builds moved to T20).
- The project runs only in test mode (test signing on, Secure Boot off) until the owner says otherwise (T13 deferred).
- The reclaim worker is event-driven, with no backoff timer (T1).
- Moves into a protected folder are inspected like copies, not refused (T6).
- Reads are never refused by the driver; permissions and administrators decide who reads (T7).
- File size: no driver cap, a stage-space budget, whole-file inspection, and anything that cannot be fully inspected is Blocked and
  justifiable (T9).
- Permission and owner changes go to the real file or folder, and Windows' own access check decides who may make them (T10).

No decision is open.
