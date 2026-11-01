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
code went. The last state of the old design is tagged `archive/staging-final`; its plans, reviews and evidence are in
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
