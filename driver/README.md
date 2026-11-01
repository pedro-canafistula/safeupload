# SafeUpload driver

## State (2026-11-01)

`SafeUpload.Minifilter/` still holds the in-kernel staging driver (about 51K lines of C) and its agent counterpart lives
in `agente/SafeUpload.Agent.Service/Interception/`. It works for Notepad, Excel and Explorer in local protected folders,
but Word saves still race, and USB, network shares and cloud folders were never enabled.

It is being replaced by a much smaller design:

| Part | Where | Job |
|---|---|---|
| SafeUpload drive | agent (user mode, WinFsp) | Serves each protected destination as a drive/folder. Writes go to a private stage; when a modified file is closed, a snapshot is inspected and only clean versions are copied to the real destination. |
| Gate minifilter | this folder (kernel) | Refuses direct writes to the real destinations (protected folders, removable and network volumes) for every process except the agent. |

WinFsp's own signed driver handles caching, memory mapping, locks and sharing, which is where most of the old kernel
code went.

**Spike result (2026-11-01):** `agente/SafeUpload.Agent.Drive` (about 900 lines of C#) passed all 22 user checks on
win10-debug3 with Office: text saves and in-place edits, Word SaveAs/save/overwrite while the document stays open,
Excel saves, Explorer copies, rename/delete and folders. Sensitive versions (CPF, card number) never reached the real
folder, which kept its previous clean version, and direct writes to the real folder were refused. Rerun it with:

```bash
driver/scripts/vm-session.sh begin <tag> --office
scp winfsp-2.1.25156.msi drive.zip vika@192.168.122.52:C:/Users/vika/Documents/    # drive.zip = published Agent.Drive
python3 driver/scripts/remote_ps.py 192.168.122.52 < agente/SafeUpload.Agent.Drive/smoke/setup.ps1
driver/scripts/vm-session.sh autologon
CLAUDE_JOB_DIR=<dir> ~/Work/safeupload-tools/vm-as-actor.sh agente/SafeUpload.Agent.Drive/smoke/user-test.ps1 900
driver/scripts/vm-session.sh end <tag>
``` The last state of the old design is tagged `archive/staging-final`; its plans, reviews and evidence are in
git history before that tag.

## Layout

| Path | What it is |
|---|---|
| `SafeUpload.Minifilter/` | Kernel minifilter (`.vcxproj`, `.inf`) and host-side tests in `tests/` |
| `SafeUpload.Inspector/` | Small user-mode client of the minifilter's communication port, for manual tests |
| `SafeUpload.Driver.sln` | Solution for both |
| `scripts/build-driver.sh` | Builds and test-signs the driver on a builder VM; output in `out/driver/` |
| `scripts/remote_ps.py` | Runs a PowerShell script on a builder or the test VM over SSH |
| `scripts/run-disk.sh` | Starts the test VM on a disposable overlay of its base disk and deletes it afterwards |
| `scripts/debuggees.txt` | Test VM addresses |
| `scripts/Update-DevPair.ps1` | Installs a driver/agent pair on the dev disk (old design; goes away with it) |

## Build

```bash
driver/scripts/build-driver.sh            # HEAD, Release
driver/scripts/build-driver.sh abc123 Debug
```

Requirements on the builder: Visual Studio 18 with the WDK (10.0.28000), and the test-signing certificate in
`LocalMachine\My`. The test VM trusts that certificate and runs with test signing on.

## Install on the test VM (manual)

```powershell
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall.NTamd64 132 .\SafeUpload.inf
fltmc load SafeUpload
fltmc instances -f SafeUpload
```
