# SafeUpload driver: MVP status and plan

Status as of 2026-10-08. This file replaces the long working log that lived here during the MVP; that log, `STAGED-WRITES.md`'s
full history and all raw VM evidence are preserved under the git tag **`mvp-history-2026-10-08`**.

## What the MVP is

A boot-start file-system minifilter (`SafeUpload.sys`) plus a LocalSystem service (`SafeUpload.Agent.Service`) that protect one or
more **local fixed-NTFS folders** on **Windows 10 22H2 build 19045.2965 x64** (the only qualified platform). Every write by a standard
user into a protected folder goes to a private staged version first; the service inspects the staged bytes and only an approved version
reaches the folder. A blocked version is handed back to the user who wrote it. Administrators and SYSTEM are trusted; standard users are
the adversary. The product fails closed.

Frozen release pair (product code must not change without a new gate):

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

- Protection for anything but local fixed NTFS: no USB/removable media, SMB/UNC shares, cloud-sync folders, ReFS/FAT/exFAT.
- Any Windows build other than 10 22H2 19045.2965 (no Windows 11).
- Read-side protection: process taint (classifying data as it is read) is off in the MVP.
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
- `Install-SafeUploadAgent.ps1` registers the service without `--Interception:Mode=Minifilter --Interception:StagingPrototype=true`. Without
  them the agent runs outside staged mode (`admissionCoverage` `NotAvailable`, `auditOnly` true) and every standard-user save into a protected
  folder is refused. Its last check also throws on Windows 10's `SERVICE_SID_TYPE:  UNRESTRICTED` output after configuring everything.
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
4. Run `agente\scripts\Install-SafeUploadAgent.ps1 -ServiceExecutablePath <path>\SafeUpload.Agent.Service.exe` (ignore its final SID-type
   error), then set the service command line to the staged mode, for example by setting the service's `ImagePath` registry value to
   `"<path>\SafeUpload.Agent.Service.exe" --Interception:Mode=Minifilter --Interception:StagingPrototype=true`.
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
- Test VMs: `win10-debug`, `win10-debug2`, `win10-debug3` (192.168.122.51-.53) are clones of the same clean 19045.2965 disk with the same
  memory size, created by `New-ParallelDebuggees.sh` from a cleanly shut down `win10-debug`; each clone keeps the guest's static address .51
  until it is reconfigured, so start and readdress them one at a time. Their SMBIOS UUIDs are pinned in `Get-StagedBaseline.ps1` and
  `Test-StagedInvariantSuite.ps1`. BLOCK-window cells are reliable only when run alone (three guests in parallel stall the agent's disk I/O).
- Raw evidence is written under `driver/evidence/` and stays local (ignored by git); curated summaries are added explicitly
  (`git add -f`), see `driver/evidence/README.md`.

## Owner decisions in force

- 2026-10-03: a sticky Unknown is never cleared before reboot; no process taint (read classification only while taint is on); no timers or
  scans as fixes.
- 2026-10-06: local fixed-NTFS MVP only (WinFsp owner prototype shelved on `wip/owner-prototype-20261006`); boot-start install with a reboot;
  a scope whose files still have a pre-scope writer stays Activating and is never Ready; P01-P06 and RV4 deferred.
- 2026-10-08: freeze at `5ebe139a` + `51ba5873` (product changes only for a leak, a crash or a Verifier hit); two-tier gate; latency reported
  only; the five boot-Verifier cells are a known gap.

## Next steps (post-MVP)

The prioritized plan is in [POST-MVP-PLAN.md](POST-MVP-PLAN.md). In short: M1 makes the driver safe to leave loaded (reclaim-worker
rescan, new-profile creation, large installers and Windows Update); M2 makes everyday file work behave like Windows plus inspection (stage
slot reuse, Notepad and Office saves, moves inspected like copies, reads and permission changes left to Windows, large files, the review
conditions); M3 is the release candidate (release build configuration, altitude and production signing, install/upgrade/uninstall); M4 is
full qualification. Other Windows builds and destinations come later (owner decision 2026-10-08: stay on 19045.2965 for now).
