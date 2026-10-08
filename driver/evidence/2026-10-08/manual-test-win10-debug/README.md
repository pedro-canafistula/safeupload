# Manual test of the frozen MVP pair on win10-debug (2026-10-08, after the gate closed)

Owner-driven test "as a user would": the owner used the VM console (virt-manager/SPICE), the orchestrator installed and
observed from the host. Product: driver `mvp4-gen4b` (`5ebe139a`, `SafeUpload.sys` SHA-256 `DA4EFA9A…6985D`) and agent
`agent-gen3b` (`51ba5873`, `stage-service-publish.zip` SHA-256 `75A68ED2…CDA16`), the exact signed artifacts the gate ran.
Guest: Windows 10 22H2 build 19045.2965, test signing on, 2 vCPUs visible (4 configured), 4 GB. Times are guest clock
(GMT+1 on the guest), host times are UTC.

## Setup that was performed

1. Copied the signed driver, the agent zip and `agente/scripts/Install-SafeUploadAgent.ps1` to the guest; verified both hashes and
   `Get-StagedBaseline.ps1` = `BaselineClean=True`; backed up the original `SafeUpload.sys` (SHA-256 `ADA9D05A…DFCE`) to
   `C:\Users\vika\Documents\SafeUploadManual\original`.
2. Agent extracted to `C:\Program Files\SafeUpload\Agent`; folder `C:\Protected`; policy `C:\ProgramData\SafeUpload\policy.json`
   (same shape as the harness: `activeCategories [Cpf]`, `.txt`, `destinationPaths [C:\Protected]`, `failOpen false`, `auditOnly false`),
   directory and file owned by SYSTEM, protected DACL, SYSTEM + Administrators full control only.
3. Copied the signed driver over `C:\Windows\System32\drivers\SafeUpload.sys`, ran the official installer (seeds BootPolicy as SYSTEM,
   sets the driver to boot start, creates `SafeUploadAgent` auto start, LocalSystem, unrestricted service SID), rebooted.
4. Standard local users in Users only (`safeuser`, later `demo` / `Demo#2026Test`) with Modify on `C:\Protected`, autologon.

Revert everything: `~/Work/safeupload-tools/rollback-vm.sh win10-debug w165734g1` (new overlay on the pre-run parent of the last
harness run, which was a clean baseline).

## Findings

### F1. Installer leaves the agent outside staged mode: every standard-user save is refused
`Install-SafeUploadAgent.ps1` registers the service with only the executable path. The MVP agent needs
`--Interception:Mode=Minifilter --Interception:StagingPrototype=true` (the harness passes them in `binPath`,
`Test-StagedInvariantSuite.ps1` near line 5128). Without them `MinifilterInterceptor` has `_stagingEnabled = false` and the agent publishes
`{"protectionActive":true,"auditOnly":true,"admissionCoverage":"NotAvailable","nativePolicyGeneration":null}` (read three times, minutes
after boot), although `policy.json` says `auditOnly:false`. The driver fails closed: Notepad "You don't have permission to save in this
location" for a clean `C:\Protected\ok.txt` (`notepad-save-refused-before-staging-args.png`), and a scripted `Set-Content` as the user got
`UnauthorizedAccessException`. Setting the service `ImagePath` to the harness command line and restarting the service gave
`{"auditOnly":false,"admissionCoverage":"Ready","admissionCoverageReason":"Ready","nativePolicyGeneration":1}` within seconds.

### F2. Installer's last self-check throws after a successful install
It requires `sc qsidtype` output to match `SERVICE_SID_TYPE_UNRESTRICTED`; Windows 10 19045 prints `SERVICE_SID_TYPE:  UNRESTRICTED`, so
the script throws "SafeUploadAgent does not have an unrestricted service SID" after it has configured everything (the SID type is set).

### F3. A new user's profile cannot be created while the driver is loaded
First sign-in of a new local user: "The User Profile Service service failed the sign-in. User profile cannot be loaded"
(`profile-service-failed-sign-in.png`); Application log 1542 "Windows cannot load classes registry file. DETAIL - Access is denied",
1511, 1500. `userenv!CreateProfile` for a fresh throwaway local user:

| VM | SafeUpload driver | agent | result |
|---|---|---|---|
| win10-debug2 (clean baseline) | registered, not loaded | not installed | `hr=0x00000000`, UsrClass.dat present |
| win10-debug | held at demand start (not loaded) | stopped | `hr=0x00000000`, UsrClass.dat present |
| win10-debug | loaded (boot start) | running | `hr=0x80070005` |
| win10-debug | loaded (boot start) | stopped | `hr=0x80070005` |

So the loaded driver alone breaks new-profile creation; existing or pre-created profiles load (classes hive included). A failed attempt
leaks `HKU\<sid>` and `HKU\<sid>_Classes` (`reg unload` denied) until reboot, which poisons later attempts for that SID. A kernel FileIo
trace of one attempt showed no create completing with `0xC0000022` and no I/O on `UsrClass.dat`, so the denied operation is not
identified yet. No suite case covered it: the harness always pre-creates the actor profile before the reboot that loads the driver.
Workaround used here: let the user sign in for the first time with the driver held (`sc config SafeUpload start= demand`, reboot), then
re-enable boot start.

### F4. Notepad "Save As" into the protected folder publishes an empty file and then fails
With the agent Ready, Notepad Save As `hello` to `C:\Protected\ok.txt`: the dialog reported "You don't have permission to modify files
in this network location" (`notepad-modify-refused-0-byte-ok.png`) and `C:\Protected\ok.txt` is a 0-byte SYSTEM-owned file. The journal
record is `notepad.exe`, `State 5` (published), `Sha256Hex E3B0C442…B855` (the hash of zero bytes). Most likely the save flow's first
create/close produced an empty version that was inspected, approved and published, and Notepad's write of the content was then refused
(the sequence is inferred from the record and the dialog; the individual opens were not traced). Real applications were never part
of the suite (DEPLOY.md: the staged path was not validated with applications like Word).

### F5. What works, as the standard user `demo`, agent Ready

| action | result | journal |
|---|---|---|
| script save of a clean `.txt` (`ps-ok.txt`, PowerShell `Set-Content`) | published, 17 bytes, correct content | State 5 |
| script save of a CPF `.txt` (`ps-cpf.txt`) | absent from `C:\Protected`, handed back | State 6, hand-back 2 |
| Explorer copy of a clean `.txt` from the desktop | published, 21 bytes, correct content | State 5 |
| Explorer copy of a CPF `.txt` from the desktop | absent from `C:\Protected`, handed back; Explorer reports success | State 6, hand-back 2 |
| Explorer drag (a move on the same volume) | refused, "Destination Folder Access Denied" (`explorer-move-refused.png`) | none |

Hand-back copies land in `C:\Users\demo\SafeUpload\_bloqueados\<transfer-id>.txt` (named by transfer ID, not the original name; file
attributes `Archive`). The move refusal is the designed C05 behaviour (a rename into the folder would publish uninspected content).

### F6. No user-visible notification
The MVP package (`stage-service-publish.zip`) contains only the service. The tray/notification app (`agente/SafeUpload.Agent.App`, unchanged
since `51ba5873`) is not packaged or qualified, so a blocked save is silent: the program reports success and the only trace for the user is
the hand-back folder. The service still publishes on the `SafeUpload.Agent` pipe and in `C:\ProgramData\SafeUpload\notifications`.

### F8. Microsoft 365 / Word could not be installed with the driver loaded
The owner started the Microsoft 365 installer as `demo` with protection active. It ran very slowly (Task Manager: disk 100% in bursts;
measured from the host about 90 MB/s of writes, about 21,000 file-system metadata operations per second in the `System` process, 8,000 in
the Office installer and 860 in the agent) and then failed with "couldn't use a required file". Not investigated. Next time: make sure
installers work with the driver loaded (a deployment requirement), and for tests install the applications before installing the driver.

### F7. Observations, not attributed
- At 22:33 the agent status was `admissionCoverage:"Pending"`, `admissionCoverageReason:"WriterPromotionPending"` (it had been Ready since the
  restart at about 22:20) while the owner still had Notepad and Explorer windows open on the folder (`guest-state-2233.txt`).
- Right after one boot with the driver loaded the guest used both vCPUs fully for a few minutes (about 10 s of CPU per 5 s), then settled
  (65%, later 1%). Not attributed to a component.

## Test-method notes (not product findings)
- A profile created with `CreateProfile` and then used for an interactive sign-in shows a black desktop: `explorer.exe` runs but
  `Shell_TrayWnd`/`Progman` do not exist (probed from inside the session); a real first sign-in shows the Windows privacy pages first and
  then a normal desktop, also with the driver loaded (`demo-desktop-driver-loaded.png`).
- With the driver loaded, `icacls` on `C:\Protected` is refused even for an administrator; grant folder ACLs while the driver is held.
- From PowerShell 5.1, `sc.exe config … binPath= "<quoted path> args"` printed usage; setting the service `ImagePath` value works.
- The harness rollback of a crash-consistent snapshot can make the next boot run chkdsk and then land in WinRE ("Choose your keyboard
  layout", `winre-after-rollback.png`); Enter, then "Turn off your PC", then `virsh start` recovers it.

## Raw evidence
- `guest-state-2233.txt`: driver hash and start type, agent command line, policy, agent status frame, `C:\Protected` and hand-back listings,
  and the five raw journal records.
- Screenshots listed above.
