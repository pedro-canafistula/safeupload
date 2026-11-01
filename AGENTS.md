# SafeUpload contributor guide

SafeUpload is an academic DLP prototype (UCB, 2026): a web admin console (`web/`), a Windows agent (`agente/`) that
inspects files for sensitive data (CPF, CNPJ, payment cards, secrets), and a kernel minifilter (`driver/`).

## Keep it simple

This project was simplified on 2026-11-01 after the driver work grew into a large review/qualification process.
Do not bring that back:

- No T-item plans, review rounds, build matrices, "legs", verdict scripts or evidence trees.
- A change is done when it builds, its tests pass, and it works on the test VM. Write down what you tested in the
  commit message or the PR.
- Prefer deleting code over adding guards for cases nobody hits. Explain designs in a few paragraphs, not documents.

The old plans, reviews, harnesses and evidence are in git history (tag `archive/staging-final`).

## Repository map

| Path | What it is | Owner |
|---|---|---|
| `web/back`, `web/front` | Spring Boot + Angular admin console, with its own CI | web team |
| `agente/` | .NET 10 Windows agent: inspection (`Agent.Core`), service (`Agent.Service`), tray app (`Agent.App`), clipboard, TLS proxy (`Agent.Network`), tests | agent team |
| `driver/` | Gate minifilter and the build/VM scripts; see [driver/README.md](driver/README.md) | Victor |
| `smoke/` | End-to-end VM test of the agent + driver | Victor |
| `lab/` | Packer/Ansible/Terraform recipes that build the Windows test VM | Victor |
| `docs/`, `db/`, `tests/` | Team documents and older material | team |

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

- Test VM: **win10-debug3** (Windows 10 19045.2965, test signing on, Secure Boot off). Keep win10-debug2 off; it shares
  the guest IP. Use a throwaway session for experiments (`driver/scripts/vm-session.sh`).
- Builders: builder1 `192.168.122.210` (libvirt `win10`) and builder2 `192.168.122.211` (`su-builder2`). One job per
  builder at a time.
- Host-wide changes (libvirt, polkit, systemd, sudoers) need the owner's OK.
