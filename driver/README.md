# SafeUpload driver

## How protection works

| Part | Where | Job |
|---|---|---|
| SafeUpload drive | `agente/SafeUpload.Agent.Drive` (user mode, WinFsp) | Each protected folder of the policy, and each USB stick when the policy protects removable media, appears as a drive (S:, T:, ...). Writes go to a private stage; when a modified file is closed, a snapshot is inspected and only clean versions are copied to the real folder. A blocked version never gets there (the folder keeps the previous version) and the user can justify it from the tray. |
| Gate driver | `SafeUpload.Minifilter/Gate.c` (kernel, about 450 lines) | Refuses writes to the real places (protected folders, and removable/network volumes when the policy says so) for every process except the agent: write-intent opens, and renames or hard links into them. Reads are never refused. |

WinFsp's own signed driver handles caching, memory mapping, locks and sharing. The gate driver only decides who may
write where. The agent identifies itself by holding the gate's communication port (only SYSTEM and administrators may
open it). If the agent stops, the protected places stay closed until it reconnects.

The previous design, an in-kernel staging driver of about 51K lines, is tagged `archive/staging-final`.

## Layout

| Path | What it is |
|---|---|
| `SafeUpload.Minifilter/` | The gate: `Gate.c`, `GateProtocol.h` (shared with `agente/SafeUpload.Agent.Service/Gate/GateClient.cs`), `.inf`, `.vcxproj` |
| `scripts/build-driver.sh` | Builds and test-signs the driver on a builder VM; output in `out/driver/` |
| `scripts/vm-session.sh` | Starts/ends a throwaway session of the test VM (optionally on the Office image) |
| `scripts/remote_ps.py` | Runs a PowerShell script on a builder or the test VM over SSH |
| `scripts/run-disk.sh` | The overlay mechanics behind `vm-session.sh` |
| `../smoke/` | End-to-end test: installs everything on a throwaway VM session and runs Office/Explorer/justification checks |

## Build

```bash
driver/scripts/build-driver.sh            # HEAD, Release -> out/driver/<commit>-Release/SafeUpload.{sys,inf}
```

Requirements on the builder: Visual Studio 18 with the WDK (10.0.28000) and the test-signing certificate in
`LocalMachine\My`. The test VM trusts that certificate and runs with test signing on.

## Test on the VM

```bash
# agent package: the service and, under App\, the tray app (self-contained)
dotnet publish agente/SafeUpload.Agent.Service -c Release -r win-x64 --self-contained true -p:EnableWindowsTargeting=true -o out/agent/pkg
dotnet publish agente/SafeUpload.Agent.App -c Release -r win-x64 --self-contained true -p:EnableWindowsTargeting=true -o out/agent/pkg/App
smoke/run.sh <tag> out/driver/<commit>-Release out/agent/pkg winfsp-2.1.25156.msi [--keep]
```

With `--keep` the VM stays up; `smoke/usb-test.ps1` then checks a USB stick: create a FAT image
(`truncate -s 64M usb.img && mkfs.fat -F 32 usb.img`), upload it to the libvirt `default` pool and attach it with
`virsh attach-disk win10-debug3 <image> sdc --targetbus usb --live`, then run the script as t5actor.

WinFsp 2.1 comes from https://github.com/winfsp/winfsp/releases (GPLv3 with an exception for open-source projects;
a closed commercial product would need its commercial license).

## Install by hand

`agente/scripts/Install-SafeUploadAgent.ps1 -PackagePath <pkg> -DriverPath <dir with .sys/.inf> -WinFspMsi <msi>`
installs WinFsp, the gate driver (demand-start; the agent loads it), the service and the tray app.
`Uninstall-SafeUploadAgent.ps1` removes them.
