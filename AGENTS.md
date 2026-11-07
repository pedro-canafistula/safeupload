# SafeUpload contributor guide

SafeUpload is an academic DLP prototype (UCB, 2026): a web admin console (`web/`), a Windows agent (`agente/`) that
inspects files for sensitive data (CPF, CNPJ, payment cards, secrets), and a kernel minifilter (`driver/`).

## Keep it simple

This project was simplified on 2026-11-01 after the driver work grew into a large review/qualification process,
and again on 2026-11-07 after the agent docs drifted the same way. These rules apply to every area (`web/`,
`agente/`, `driver/`, `smoke/`, `lab/`, `docs/`). Do not bring that process back:

- No T-item plans, review rounds, build matrices, "legs", verdict scripts or evidence trees.
- No dated status, integration or acceptance documents, no per-SHA evidence records, and no multi-agent role or
  handoff notes ("Agente 1/2/3") in the repo.
- A change is done when it builds, its tests pass, and it works on the test VM. Status and what you tested go in the
  commit message or the PR description, not in a file.
- Each area keeps one current README that describes what is true now; update it in the same change. The
  console ↔ agent contract lives only in [docs/console-agente.md](docs/console-agente.md).
- Prefer deleting code over adding guards for cases nobody hits. Explain designs in a few paragraphs, not documents.
- The only target is Windows 10 x64 (22H2).

The old plans, reviews, harnesses and evidence are in git history (tag `archive/staging-final`).

## Repository map

| Path | What it is | Owner |
|---|---|---|
| `web/back`, `web/front` | Spring Boot + Angular admin console, with its own CI | web team |
| `agente/` | .NET 10 Windows agent: inspection (`Agent.Core`), service (`Agent.Service`), SafeUpload drive (`Agent.Drive`), tray app (`Agent.App`), clipboard, TLS proxy (`Agent.Network`), tests, installer; see [agente/README.md](agente/README.md) | agent team |
| `driver/` | Gate minifilter and the build/VM scripts; see [driver/README.md](driver/README.md) | Victor |
| `smoke/` | End-to-end VM test of the agent + driver | Victor |
| `lab/` | Packer/Ansible/Terraform recipes that build the Windows test VM | Victor |
| `docs/` | The console ↔ agent contract (`console-agente.md`) and design notes for the clipboard and TLS channels | team |
| `db/` | MySQL DDLs (`db/initdb`) and the Docker database | team |

Do not rewrite another team's area as part of driver work. Never touch untracked personal files (`.ai-memory.toml`,
`reports/`, `research_notes/`).

## How protection works

1. **SafeUpload drive (agent, user mode, WinFsp):** each protected folder (and each USB stick, when removable media is
   protected) appears as a drive. Writes go to a private stage. When a modified file is closed, the agent inspects a
   snapshot; clean versions are copied to the real folder, sensitive ones never reach it and the user gets the block
   notification (with justification).
2. **Gate minifilter (kernel, `driver/SafeUpload.Minifilter/Gate.c`):** refuses direct writes to the real places for
   everyone except the agent. No inspection, staging or process taint in the kernel.

Product rules: nothing uninspected reaches a protected destination; an inspection that fails, times out or cannot read
the file blocks (fail closed); reads are never blocked; a justification covers exactly one version.

## Build and test

```bash
# Agent (Linux, using the local SDK; WPF needs EnableWindowsTargeting)
dotnet build agente/SafeUpload.Agent.sln -p:EnableWindowsTargeting=true
# Tests: run on Windows. On Linux about one in eight fail because they use Windows APIs (pipes, ACLs, certificate store).
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj

# Driver (on a Windows builder VM, signed with the test certificate)
driver/scripts/build-driver.sh [commit] [Release|Debug]

# End to end on a throwaway VM session (see driver/README.md)
smoke/run.sh <tag> <driver-dir> <agent-pkg-dir> <winfsp.msi>
```

## Lab

- Test VM: **win10-debug3** `192.168.122.52` (Windows 10 19045.2965 + Office, test signing on, Secure Boot off). Use a
  throwaway session for experiments (`driver/scripts/vm-session.sh`).
- Builder: `192.168.122.210` (libvirt `win10`, Visual Studio + WDK, the test-signing certificate). One job at a time.
- Host-wide changes (libvirt, polkit, systemd, sudoers) need the owner's OK.
