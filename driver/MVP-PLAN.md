# SafeUpload driver: MVP status and plan

Updated 2026-10-11. The component results below describe the 2026-10-08 pair; the active MVP scope and status are in
[POST-MVP-PLAN.md](POST-MVP-PLAN.md). This file replaces the long working log that lived here during the MVP; that log, `STAGED-WRITES.md`'s
full history and all raw VM evidence are preserved under the git tag **`mvp-history-2026-10-08`**.

## What the MVP is

A boot-start file-system minifilter (`SafeUpload.sys`) plus a LocalSystem service (`SafeUpload.Agent.Service`) that protect one or
more **local fixed-NTFS folders** on **Windows 10 22H2 build 19045.2965 x64** (the only qualified platform). Every write by a standard
user into a protected folder goes to a private staged version first; the service inspects the staged bytes and only an approved version
reaches the folder. A blocked version is handed back to the user who wrote it. Administrators and SYSTEM are trusted; standard users are
the adversary. The product fails closed.

The full MVP also requires **T21 USB/removable → T22 SMB/UNC → T23 cloud-sync folders**, in that order after M3 and before combined M4 qualification.
Each is a separate required milestone with its own design note, recorded owner decisions, Luna 6 max-effort design review and destination
qualification. USB includes surprise removal; SMB runs against an actual server with independent server-side byte observation.
Supported removable filesystems and network configurations still require their design decisions. These capabilities remain disabled until their
approved support and qualification gates pass and the owner approves cutover; the historical local-NTFS results do not qualify them.

Historical qualification pair (later product changes require their own gates):

| Part | Label | Source commit | Artifact SHA-256 |
|---|---|---|---|
| Driver | `mvp4-gen4b` | `5ebe139a` | `SafeUpload.sys` `DA4EFA9A8FB2901AA2330F4D87E18B673DF76FE2BA719E1CF7A2691059C6985D` |
| Agent | `agent-gen3b` | `51ba5873` | `stage-service-publish.zip` `75A68ED25FB8F544E0C9726E396EC1D144F712F82899E7DAC66666A47EFCDA16` |

The driver is test-signed (signer thumbprint `A6D6CE1AA28835D509160A80ADB7894869AADF38`): test signing on, Secure Boot off, disposable VMs only.

## What the driver has (proven by the invariant suite)

Each line is backed by a suite row that passed on the frozen pair (rows in `driver/scripts/StagedInvariantCases.psd1`).

- **Protection from boot.** The policy scopes are seeded into the registry (`BootPolicy`) before the reboot, so protection starts before
  any user application can open a protected file. A write by a standard user after boot is refused until the service is Ready (S01).
  Installation needs one reboot.
- **Staged saves with inspection.** A standard user's write to a protected folder lands in a private stage; the service seals, inspects and
  either publishes it atomically (APPROVE) or blocks it (BLOCK). Covered for a new file (C01), a file written through a mapped view with the
  source closed (C02), a truncating overwrite of an existing file (C03) and an application-style private sibling replace (C04).
- **No unapproved byte at the destination.** Checked in every run by a raw-volume observer plus fresh and uncached reads
  (`ForbiddenByteCount` 0 in every run that measured it; the observer control is S00).
- **Hand-back of blocked versions** to the requesting user's profile (`%USERPROFILE%\SafeUpload\_bloqueados\<transfer-id>.<ext>`), bound to
  the requestor SID, failing closed if the hand-back folder is tampered with (B01).
- **Justified publication** of a blocked sensitive file when the policy allows overrides: the latest version is published once, a stale
  version is never published (B02).
- **Renames into a protected folder are refused** (an external file renamed in would bypass inspection) (C05).
- **Pre-existing writers are respected.** A folder added to the policy at runtime stays `Activating`, never `Ready`, while a file in it still
  has a writer from before protection (open handle, mapped view, retained section, duplicated handle); after the last such writer closes, new
  writes are staged and approved normally (A01-A04). With the service down, an unpermitted write is refused (A05).
- **Concurrent writers:** two live processes saving the same file get v1 blocked and the latest v2 released (X01).
- **Restart safety:** a service restart in the middle of a save (R01), a stop after a finalized policy change with a held writer (R02) and a
  boot with the service disabled (R03) end in a correct, approved state with nothing leaked.
- **Service down means no protected writes:** opens that would create or modify protected files are refused while the service is down (S02).
- **Readiness reporting:** the service publishes `admissionCoverage` (`Ready`, `Pending`/`Activating` with a reason, `Degraded`) on the
  `SafeUpload.Agent` pipe and in a durable notification record under `C:\ProgramData\SafeUpload\notifications`.

## What the driver does not have

- Protection for anything but local fixed NTFS on this pair. USB/removable, SMB/UNC and cloud-sync are required remaining MVP work
  (T21–T23); ReFS remains Later (T24). Supported removable filesystems will be decided in T21's design, rather than assumed qualified.
- Any Windows build other than 10 22H2 19045.2965 (no Windows 11).
- This staged-only test pair ran without read-side process taint. The current MVP keeps existing taint enforcement until the owner
  approves cutover after the combined qualification and taint-removal plan.
- Application compatibility beyond scripted saves and Explorer copies: Notepad "Save As" fails (see known issues); Word and other Office
  applications were never exercised, and the Microsoft 365 installer did not complete with the driver loaded.
- Files larger than 16 MiB in a protected folder, or more than 128 staged files per boot (both refused, see known issues).
- A user-facing notification: the tray app (`agente/SafeUpload.Agent.App`) is not part of the MVP package, so a blocked save is silent.
- A qualified installer: `agente/scripts/Install-SafeUploadAgent.ps1` is incomplete (see known issues).
- A continuous proof of "no unapproved byte": the MVP evidences it with sampled raw, fresh and uncached reads and the final raw image, not a
  driver-side mutation ledger.
- The other variants of each suite row, rows P01-P06 and the RV4 families (deferred by the owner on 2026-10-06), dedicated latency runs,
  authenticated per-file readiness events and host-independent cadence proofs.
- A production signature, and a build without the diagnostic Inspector/protocol additions (the staging build must not be shipped as is).

## Release gate result

Two-tier gate (owner decision 2026-10-08): tier 1 = no leak, clean restoration, no FAIL or error, the row's outcome proofs pass (trace and
coverage depth may be INCONCLUSIVE); tier 2 = every proof; latency is reported, not gating.

| Mode | Gate | Result |
|---|---|---|
| ordinary | tier 1 | **23/23** |
| runtime Driver Verifier | tier 2 (every proof) | **23/23** |
| boot Driver Verifier | tier 1 | **18/23** |
| total |  | **64/69** (strict all-proofs verdict: 40/69) |

The five boot-Verifier cells that did not complete (B02, C01/C02/C03/C04 BLOCK) are a documented gap (owner decision 2026-10-08): with
Verifier on from boot the guest stays CPU bound for 20+ minutes (measured about 20,000 `SafeUpload.sys` special-pool allocations per second),
every harness SYSTEM task outlasts its wait, and the cases end without a verdict. No run saw a leak; the same rows pass in the other two
modes. Latency, worst over the qualifying cells: cached write p95 2.2 ms / max 53 ms; close p95 4.0 / 305 ms; flush p95 162 / 917 ms;
writer-open p95 8.7 / 2240 ms; writer-open-deny p95 13 / 52 ms.

Reviews of the final pair: [Phase 5 review](evidence/2026-10-08/luna-phase5-final-review.md) and the
[review of the last driver change](evidence/2026-10-08/luna-gen4b-review.md), both ACCEPT WITH CONDITIONS (conditions are in the known issues).
Gate status: [mvp-gate-final.txt](evidence/2026-10-08/mvp-gate-final.txt). Manual test: [manual-test-win10-debug](evidence/2026-10-08/manual-test-win10-debug/README.md).

## Known issues

Product (all fail closed unless stated):
- **Reclaim-worker CPU.** An unresolved or parked alias probe keeps the reclaim worker rescanning with no backoff
  (`StageRegistryReclaimWorker`, `STAGE_RECLAIM_RESCAN`); measured 2.5-5k passes/s, and under boot Verifier the guest ran at 100% CPU. First
  post-MVP fix; it is also the likely cause of the boot-Verifier gap and of slow large installs with the driver loaded.
- **New user profiles cannot be created while the driver is loaded.** A new user's first sign-in fails ("The User Profile Service service failed
  the sign-in") and `CreateProfile` returns access denied; existing profiles are unaffected. Workaround: users sign in once before protection is
  installed. The denied operation is not identified yet.
- **Notepad "Save As"** into a protected folder publishes an empty file, then Notepad reports "You don't have permission to modify files in
  this network location". Explorer copies and scripted saves work.
- **Microsoft 365 / Word could not be installed** on the test VM with the driver loaded ("couldn't use a required file"); not investigated.
- **Blocked saves are silent** and the handed-back copy is named by transfer ID, not the original name.
- **Moving a file into a protected folder is refused** (by design; users must copy).
- **Reading a justified sensitive file**: the post-create path refuses a data-read open of a file classified sensitive in a monitored folder
  unless an override is present (attribute-only opens are allowed).
- **Stage-stream cap**: at most 128 distinct staged files per boot (`STAGE_LIMIT`, the slot is not reclaimed); after that, creates in a
  protected folder fail with `STATUS_INSUFFICIENT_RESOURCES` until reboot.
- **16 MiB file size limit**: a staged version is capped at 16 MiB (`STAGE_MAX_BYTES`); writing or extending a protected file beyond that
  fails with `STATUS_FILE_TOO_LARGE`.
- **Sticky Unknown**: a lost-tracking event leaves coverage Degraded until reboot (owner decision 2026-10-03).
- **Rename-churn parking** can defer a classification while churn never settles (gated, never reported Ready).
- Luna's P2 conditions: policy generation compared as a signed LONG (rollover after 2^31 commits); changed-SOP entries not retired from the
  bounded registry; the SOP-lifetime premise of `StageRegistryAssociateSectionPointer` is a target-build precondition; the delete-pending query
  in `StageCreate` runs under the global namespace lock without a top-level-IRP guard.
- Agent journal: never shrinks; the scan cache is bounded at 50,000 entries and clears when exceeded; an administrator who preserves size and
  all timestamps of a manifest could keep a stale scan projection until the next write.

Installer and tooling:
- ~~`Install-SafeUploadAgent.ps1` registered the service without the staged-mode arguments and threw on Windows 10's
  `SERVICE_SID_TYPE:  UNRESTRICTED` output.~~ Fixed on `feat/driver-post-mvp` (POST-MVP-PLAN T0); to be verified by an install on a clean VM.
- Main's TLS-inspection tests (`CertificateAuthorityTests`, `TlsInspectionProxyTests`) fail with "Access denied" when run without rights to
  create machine CNG keys (the same 21 tests fail on `main` itself on the builder).

## Install and test by hand (disposable VM)

Verified on 2026-10-08 on `win10-debug`; details and screenshots in the manual-test evidence.

1. Before installing anything: sign in once with every user account you will test with, and **install the applications you want to test
   (Word, browsers, ...)**, because new profiles and large installers do not work with the driver loaded.
2. Copy the signed `SafeUpload.sys` over `C:\Windows\System32\drivers\SafeUpload.sys` (the `SafeUpload` service must exist from the INF) and
   extract the agent package, for example to `C:\Program Files\SafeUpload\Agent`.
3. Write `C:\ProgramData\SafeUpload\policy.json` (example: `activeCategories ["Cpf"]`, `extensions [".txt"]`, `destinationPaths
   ["C:\\Protected"]`, `failOpen false`, `auditOnly false`). The directory and the file must be owned by SYSTEM with a protected DACL granting
   full control to SYSTEM and Administrators only.
4. Run `agente\scripts\Install-SafeUploadAgent.ps1 -ServiceExecutablePath <path>\SafeUpload.Agent.Service.exe`. It registers the service
   in staged minifilter mode (`--Interception:Mode=Minifilter --Interception:StagingPrototype=true`, written to the service's `ImagePath`
   and read back); `-ServiceArguments` overrides the arguments.
5. Grant the test users Modify on the protected folder now: with the driver loaded even administrators cannot change its ACL.
6. Reboot. The agent's status on the `SafeUpload.Agent` pipe must read `"auditOnly":false,"admissionCoverage":"Ready"`.
7. As a standard user: copy a clean `.txt` into the folder (published) and one containing `CPF: 529.982.247-25` (blocked, handed back to
   `%USERPROFILE%\SafeUpload\_bloqueados`).

Revert the VM: `rollback-vm.sh <domain> <run>` (new overlay on the pre-run parent of a harness run), or restore a snapshot.

## How the gate is run

- One case: `driver/scripts/Invoke-StagedSuiteBatch.sh <driver label> <driver commit> <agent label> <agent commit> <mode> <tag> <case...>` with
  `SAFEUPLOAD_DEBUGGEE=win10-debug|win10-debug2|win10-debug3`; modes `ordinary`, `runtime-verifier`, `boot-verifier`. The guest-side harness
  is `Test-StagedInvariantSuite.ps1`; restoration is checked independently with `Get-StagedBaseline.ps1`.
- Status of a pair: `python3 driver/scripts/Get-StagedMvpStatus.py <driver commit> <agent commit> [--strict]` over the retained `case.json`
  files (tests: `driver/scripts/test_staged_mvp_tiers.py`).
- Harness changes must pass `driver/scripts/Invoke-HarnessWindowsGate.sh <label> .` (Windows PowerShell 5.1 parse plus self-checks) on the
  builder VM; agent builds and tests run on the builder with `Invoke-ExactAgentBuild.sh`.
- Use `win10-debug3` only, at its current guest address `192.168.122.52`; `win10-debug2` must remain off because it shares that address.
  Test VMs have no TPM. Each run resets EFI variables, uses a disposable qcow2 disk that is deleted afterwards, and separately verifies
  the untouched base and unchanged domain XML with `Get-StagedBaseline.ps1`. See the recorded setup in POST-MVP-PLAN. BLOCK-window cells run serially.
- Raw evidence is written under `driver/evidence/` and stays local (ignored by git); curated summaries are added explicitly
  (`git add -f`), see `driver/evidence/README.md`.

## Owner decisions in force

- 2026-10-11: M2 T4–T11 → M3 T12/T14 → T21 USB/removable → T22 SMB/UNC → T23 cloud sync → M4 T15–T19 qualifying local NTFS and all
  newly supported destinations together. T20 other Windows builds and T24 ReFS remain Later; T13 production signing is owner-deferred.
  USB includes surprise removal; actual SMB and a real sync client need independent destination-byte observers. Taint stays, normal
  builds compile staging out, and unsupported capabilities stay disabled until owner-approved cutover. After all required evidence,
  write the taint-removal plan and wait for sign-off. This supersedes the earlier local-only completion scope.
  T21 and T22 each require a dedicated design, recorded owner decisions with user-visible effects and Luna 6 max-effort design review
  before implementation; their destination run evidence is required before combined M4 qualification.
- 2026-10-11: empty files are ordinary content: seal, inspect (trivially clean at a freshly verified stable zero length), and publish
  them normally. This replaces the 2026-10-10 EmptyHeld decision and removes EmptySavePrivate notices. Public deletes are part of M2;
  Windows checks the caller's DELETE authority against the real public file. Private deletes free the name at last close while exact
  cleanup proceeds asynchronously. See [T5-DELETES.md](T5-DELETES.md) for generation ordering, cleanup, and legacy-journal handling.
  Replace only the no-empty-publication test: no uninspected nonempty bytes may reach the public name; clean saves finish with the saved
  bytes, CPF saves to new names leave no file, and CPF saves to existing names retain prior contents, with no empty leftover. All other
  assertions remain required, including independent byte observation, Verifier, and verified VM restoration. Design review precedes code.
- 2026-10-10: startup requirement reconfirmed by the owner: protection starts before applications open protected files for editing;
  installation may require an initial restart. Starting protection after those editing handles or mappings already exist cannot claim
  the same privacy guarantee. This approval settles startup ordering; qualification of the implementation remains required.
- 2026-10-03: a sticky Unknown is never cleared before reboot; no timers or scans as fixes. The earlier isolated staged-only test
  configuration does not authorize removing existing taint from the current MVP.
- 2026-10-06: the historical component scope was local fixed NTFS (WinFsp owner prototype shelved on `wip/owner-prototype-20261006`);
  its completion scope is superseded above. Boot-start install with a reboot remains required;
  a scope whose files still have a pre-scope writer stays Activating and is never Ready; P01-P06 and RV4 deferred.
- 2026-10-08: historical pair `5ebe139a` + `51ba5873` was frozen for its two-tier gate, with five boot-Verifier cells left open.
  Later milestone changes need fresh gates; combined functional, crash/recovery, Verifier, stress and latency qualification remain required.

- 2026-10-11: an exceptional tracking failure after NTFS accepts native scheduled deletion preserves the accepted Windows result.
  Recovery must be automatic at the app's last-handle close and at service startup after a crash. Publication to the name stays held
  until exact reconciliation establishes absence or the original pre-open file; then the recovery hold ends automatically. Reuse
  durable pre-CREATE intent and existing startup recovery, adding only accepted/unresolved state. An undecidable result keeps the hold
  with a named-file, actionable tray notice and diagnostics. Fault-injection rows must prove release after close and restart.
  If the automatic guarantee cannot be met, return to the owner before implementation; see [T5-NATIVE-PUBLIC-OPENS.md](T5-NATIVE-PUBLIC-OPENS.md).

## Remaining MVP work

The status plan is [POST-MVP-PLAN.md](POST-MVP-PLAN.md). M1 is complete on its recorded pair. M2 is active, with the T4 10,000-cycle
run first and T5 deletes next. M3 covers release configuration and install/upgrade/uninstall. Then T21–T23 add and qualify USB,
SMB/UNC and cloud-sync before M4 qualifies them together with local NTFS. The MVP finishes only after all required evidence and the
owner's taint-removal sign-off. Production signing, other Windows builds and ReFS remain deferred.
