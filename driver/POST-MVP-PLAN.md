# SafeUpload driver: post-MVP plan

Written 2026-10-08 on `feat/driver-post-mvp` (= `main` `aaab5c0c`, which carries the frozen MVP pair: driver `5ebe139a`, agent `51ba5873`).
Current status, gate results and known issues are in [MVP-PLAN.md](MVP-PLAN.md); this file is the work plan that follows them, in priority
order. Where a cause is not yet measured, the task says so and lists hypotheses from reading the code; treat those as leads, not findings.

## What "complete" means

The driver is complete for the local-NTFS product when all of these hold:

1. **It can stay loaded on a real machine**: no CPU churn at idle, new users can sign in, large installers and Windows Update complete.
2. **Everyday saves work**: Notepad, Office and other common applications save into a protected folder with the same result as without
   the driver (approved content published, blocked content handed back), with no per-boot or small file-size ceiling a user would hit.
3. **It is a shippable build**: staging is the release configuration, the test-only diagnostics are out of it, the altitude is assigned by
   Microsoft, the driver is production-signed and loads with Secure Boot on, and it is qualified on the Windows builds customers run.
4. **It is qualified**: the full invariant suite (all variants) passes in all three modes, plus soak, stress and coexistence runs.

Destinations beyond local NTFS (USB, SMB, sync clients, ReFS) are separate features after that (P3).

## Rules for every task

Carried over from the MVP; they apply to every driver change on this branch.

- Every driver commit: the four WDK configurations build with PREfast and ApiValidator at 0/0; kernel changes that run on a VM run under
  runtime Driver Verifier; the affected suite rows pass end to end with the raw-volume observer (`ForbiddenByteCount` 0) and a clean
  restoration (`Get-StagedBaseline.ps1`).
- One adversarial review per milestone against the working system, plus one before the first VM boot of any change to object lifetime,
  lock order or the retirement gate (T4 in particular). Reviews only by Luna; implementation is done here.
- Each milestone ends with a new frozen pair (new build labels) and the full three-mode gate. BLOCK-window cells run serially on one VM.
- Harness changes pass `Invoke-HarnessWindowsGate.sh` (Windows PowerShell 5.1) before they are used for a gate run.
- Owner decisions in force stay in force (no process taint, no scan-based or timer-based fixes for writer state, sticky Unknown until
  reboot, Activating never reports Ready). A task that seems to need an exception stops and asks (see "Owner decisions needed").
- Any change that removes a refusal must come with a suite row proving the refusal is still applied inside a protected scope.

## Priority order

Sizes are rough: S = a few days, M = about a week, L = several weeks.

| # | Task | Tier | Size | Depends on |
|---|---|---|---|---|
| T0 | Field diagnostics: deny ring and counters readable while the agent runs; installer quick fixes | P0 | S | - |
| T1 | Event-driven reclaim worker (no rescan loop); rerun the five boot-Verifier cells | P0 | M | T0 |
| T2 | Find and fix the denial that breaks new-profile creation | P0 | M | T0 |
| T3 | Large installers and Windows servicing with the driver loaded (M365, cumulative updates) | P0 | M-L | T1, T2 |
| T4 | Reclaim stage slots: remove the 128-versions-per-boot ceiling | P1 | M-L | T1 |
| T5 | Notepad Save As | P1 | M | T0 |
| T6 | Office and common-application save patterns, metadata fidelity | P1 | L | T4, T5 |
| T7 | Raise the 16 MiB version limit | P1 | M | T4 |
| T8 | Close the review conditions (Luna P2s) | P1 | S-M | - |
| T9 | Release build: staging becomes the product configuration, diagnostics test-only | P1 | M | T8 |
| T10 | Current Windows builds: Windows 11 24H2/25H2 and current Windows 10 22H2 | P1 | L | T9 |
| T11 | Altitude, INF, production signing, Secure Boot on (start the paperwork now) | P1 | M + lead time | T9 |
| T12 | Driver install, upgrade, uninstall and an administrator maintenance path | P1 | M | T9 |
| T13 | Full suite: section-4.1 variants, P01-P06, RV4, dedicated latency | P2 | L | M2 |
| T14 | Soak, stress and fault injection | P2 | M | M2 |
| T15 | Coexistence: antivirus/EDR filters, BitLocker, VSS, indexer, backup, OneDrive | P2 | M | T10 |
| T16 | Operating Degraded/Unknown in the field | P2 | S | T0 |
| T17 | Continuous no-unapproved-byte evidence (mutation ledger, C05 denial ledger) | P2 | M | T13 |
| T18-T21 | USB/removable, SMB/UNC, cloud-sync folders, ReFS | P3 | L each | M4 |

Milestones: **M1 "safe to leave loaded"** = T0-T3; **M2 "everyday saves work"** = T4-T8; **M3 "release candidate"** = T9-T12;
**M4 "qualified"** = T13-T17; **M5** = each P3 destination on its own.

Start the external lead-time items of T11 (altitude request, EV certificate, Partner Center account) now, in parallel with M1: they take
weeks and nothing in M1 depends on them.

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

### T1. Event-driven reclaim worker

**Problem.** `StageRegistryReclaimWorker` (`StageWriters.c`) sets `STAGE_RECLAIM_RESCAN` whenever a pass leaves an entry unfinished
(`unfinishedScan`: an unresolved or parked alias probe, a pending scope scan), and `StageRegistryReclaimWorkerFinish` requeues immediately.
An entry that cannot finish keeps the worker spinning: 2.5-5k passes/s measured, about 20,000 special-pool allocations/s under boot
Verifier, guest CPU at 100% for 20+ minutes. It is the likely cause of the five missing boot-Verifier cells and a suspect for the slow
M365 install.

**Approach (fits the "no timers, no scans" decision).** A pass requeues itself only when it made progress or new work arrived:
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

### T3. Large installers and Windows servicing

**Problem.** The Microsoft 365 installer ran very slowly (about 21,000 metadata operations/s in `System`) and then failed with "couldn't
use a required file". Windows Update, Defender updates and Store updates were never exercised with the driver loaded, and a deployed
driver has to survive monthly cumulative updates.

**Work.** Re-measure after T1 and T2 (some or all of this may be the same causes). Then add qualification runs, each with the driver
loaded and a protected folder on `C:`: Microsoft 365 install, an MSI install, a Windows cumulative update and reboot, a Defender platform
update. Record duration against the same run without the driver, the deny ring, and the writer-registry high-water mark: the registry
holds at most 4,096 entries (`SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT`) and exhaustion makes coverage Unknown until reboot, so an installer
that fills it would leave protection Degraded.

**Done when** all four complete with no refusal outside a scope, coverage still Ready afterwards, and an overhead number the owner accepts.

## P1: everyday saves work (M2)

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

### T6. Office and common applications

**Work.** Record the real save sequences of Word, Excel and PowerPoint (temporary file in the same folder, rename original to backup,
rename temporary to the final name, delete backup), plus Paint, WordPad, Explorer copy with replace, a browser download into the folder,
`robocopy` and a 7-Zip extraction. For each, decide the expected outcome and add a suite row that replays the sequence. The rename support
is a two-slot transaction with at most 16 moves per version; check the Office pattern stays inside that.

Also check what the published file keeps from the user's version: owner (it is SYSTEM today), DACL inheritance, timestamps, attributes,
alternate data streams (for example `Zone.Identifier` on downloaded files) and EAs. Decide per item whether the service copies it or the
destination keeps the old one, and test it.

Install the applications before installing the driver (owner note) until T3 is done.

**Done when** each application row passes in all three modes and a user can open the published file with the same application afterwards.

### T7. Larger files

**Problem.** A staged version is capped at 16 MiB (`STAGE_MAX_BYTES`); bigger writes fail with `STATUS_FILE_TOO_LARGE`. Office files, PDFs
and images often exceed that.

**Work.** Find what each side assumes (driver backing, cache and paging; agent seal and inspection, which must stream instead of reading the
whole file). Make the limit a policy value with a high default chosen by the owner, and bound the disk space staged versions can take per
user, so a standard user cannot fill the volume with stages. Measure seal and inspection latency at the new limit.

**Done when** a file at the new limit is approved and published byte-exact, one over it is refused cleanly, and a stage-space exhaustion
attempt by a standard user fails closed without affecting other users.

### T8. Review conditions

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

## P1: shippable build (M3)

### T9. Release build configuration

**Problem.** Staged writes compile only with `SafeUploadStagingPrototype=true` (`SafeUpload.Minifilter.vcxproj`); the release
configuration has none of `Stage*.c`. The staging build also carries diagnostics that must not ship: Inspector-only protocol extensions,
the admission trace, the canary hold, the volume-callback probe.

**Work.** Make staging the product configuration and move every test-only hook behind a separate test configuration (owner rule: test-only
hooks only in the test build). Review the communication port surface of the release build: which messages exist, who may connect (service
SID only), input validation. Keep `Test-NormalBuildIdentity.ps1` (or its successor) proving that the release binary contains none of the
test-only code. CodeQL, PREfast and ApiValidator at 0/0 on the release configuration.

**Done when** the release configuration passes the full gate and the identity test shows no test-only message or hook.

### T10. Current Windows builds

**Problem.** Only Windows 10 22H2 build 19045.2965 (May 2023) is qualified. Windows 10 reached end of support on 2025-10-14, so customers
run Windows 11 or Windows 10 with extended security updates at a current patch level. The design depends on observed, undocumented
behavior of `MmDoesFileHaveUserWritableReferences` for sections, which needs qualification on each build.

**Work.** Add debuggee VMs for Windows 11 24H2 and 25H2 and a current Windows 10 22H2. On each, rerun the section-behavior experiments
(retained section, view after handle close, cross-process section), the start-up canary, then the full gate. Make the driver refuse to
report Ready on a build it was not qualified for (fail closed, with a clear reason in coverage).

**Done when** each target build passes the full gate and an unqualified build reports a clear "not qualified" coverage state.

### T11. Altitude, INF and signing

**Work.**
- Request a minifilter altitude from Microsoft; `SafeUpload.inf` carries a provisional `321410` with a "must not ship" note. Confirm the
  class and load order group for the request (the INF says `ActivityMonitor` class with `FSFilter Anti-Virus` load order; a filter that
  blocks writes may belong in a different group).
- Finalize the INF (`DriverVer`, version resource, catalog).
- Production signing: EV code-signing certificate, Partner Center registration, attestation signing (enough for Windows 10/11 client); HLK
  (WHQL) only if the owner wants it.
- Qualify with test signing off and Secure Boot on.

**Done when** the attestation-signed driver loads with Secure Boot on and passes the gate on each T10 build.

### T12. Install, upgrade, uninstall, maintenance

**Work.**
- Driver install as part of the product installer: INF install, BootPolicy seeding, reboot (installation needs one reboot by design).
- Upgrade: driver and agent versions in the field differ for a reboot; define protocol version negotiation and test old-driver/new-agent
  and the reverse.
- Uninstall: back to a clean machine after reboot, no residue (`Reset-StagedProductResidue.ps1` is the starting point).
- Administrator maintenance: today even an administrator cannot change the ACL of a protected folder while the driver is loaded. Add a
  supported way (for example an authenticated maintenance request through the agent), since admins are trusted.

**Done when** install, upgrade and uninstall pass on a clean VM of each T10 build, and an administrator can change the folder ACL without
holding the driver.

## P2: qualified (M4)

- **T13. Full suite.** The other section-4.1 variants of each row, P01-P06 and RV4 (deferred on 2026-10-06), dedicated latency runs, and
  the new rows from T2, T3, T5 and T6, all in three modes. Fix the parallel-pool flake in BLOCK cells (the agent's flush stalls under disk
  pressure when three guests run) or keep them serial.
- **T14. Soak, stress and fault injection.** Several days of scripted use with many saves; Driver Verifier with low-resources simulation;
  power loss during seal and publication (extends R01-R03); service crash loops; full disk; many concurrent writers.
- **T15. Coexistence.** Microsoft Defender and at least one third-party antivirus/EDR filter, BitLocker, VSS and System Restore, the search
  indexer, a backup agent, OneDrive in the user profile, `chkdsk` and defrag on the protected volume.
- **T16. Degraded and Unknown in the field.** Sticky Unknown stays until reboot (owner decision). Make it actionable: the reason (from T0)
  in the agent status and a durable notification an administrator can see, with the documented remedy.
- **T17. Continuous evidence.** If customers or audits need it: a driver-side mutation ledger proving no unapproved byte reached a
  destination continuously (the MVP proves it with sampled raw reads and the final image), and the deferred C05 denial ledger.

## P3: new destinations (M5)

Each needs its own design, owner decisions and qualification; none may be enabled by removing today's guards.

- **T18. USB and removable media**: surprise removal, FAT/exFAT have no stable file IDs, teardown rules (writers dropped by volume teardown
  do not set machine-wide Unknown).
- **T19. SMB/UNC**: redirector-level filtering, different identity and caching model.
- **T20. Cloud-sync folders**: interplay with the Cloud Files API and sync clients' own writers.
- **T21. ReFS**.

## Outside the driver, needed for a complete product

- Notification app packaged and qualified (a blocked save is silent today), and hand-back copies named after the original file.
- Central policy distribution: the kernel policy message holds at most 16 destination prefixes of 260 characters and 32 extensions of 16
  characters, and the boot policy 32 prefixes (`Protocol.h`, `SAFEUPLOAD_MAX_*`); the server's policy format has to fit those bounds or
  the protocol has to change.
- The agent's TLS-inspection tests that fail without rights to create machine CNG keys (from `main`).

## Owner decisions needed

| Decision | Needed by | Recommendation |
|---|---|---|
| Reclaim worker: purely event-driven, or is a bounded backoff acceptable as a fallback? | T1 | Event-driven with a progress check; no timer. |
| Which Windows builds the first release supports | T10 | Windows 11 24H2 and 25H2, plus current Windows 10 22H2 for ESU customers. |
| File size limit and per-user stage space | T7 | Choose from customer files; start the measurement at 256 MiB. |
| Keep refusing moves into a protected folder, or turn a same-volume move into copy, inspect, then delete the source | T6 | Keep refusing in the first release; revisit with user feedback. |
| Reading a justified sensitive file: the post-create path refuses data-read opens without an override; intended? | T6 | Decide with the product owner; it affects users who justified a file. |
| Attestation signing only, or WHQL | T11 | Attestation for the first release. |
| Administrator maintenance path for protected-folder ACLs | T12 | Authenticated request through the agent. |
