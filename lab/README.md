# SafeUpload lab images

**Linux route validated; Hyper-V route postponed and untested.** Build K (2026-10-21) passed the complete image build and the
Terraform create/first-boot/acceptance/reboot/destroy lifecycle. The VHDX export is byte-verified, but no Hyper-V host has booted it.
See [VALIDATION.md](VALIDATION.md).

Reproducible Windows 10 22H2 (build **19045.2965**) lab VMs for development, built from a clean Microsoft ISO with
Packer and Ansible, and created on Linux with Terraform/libvirt or on Windows with Hyper-V. The clean image contains the local `vika` administrator with a discarded random password, Windows built-in accounts,
and no personal identity, SSH keys or signing certificates. Each person's credentials are injected at first boot from a seed disk.

| Directory | Role |
|---|---|
| `packer/` | Unattended Windows install (UEFI, no Secure Boot, no TPM, virtio disk, e1000e NIC) and the build definition. |
| `ansible/` | Roles run inside the build: `win_base` (exact build, no updates, test signing), `debuggee`, `lab_seed` (first-boot identity), `sanitize` (secret and cache removal + sysprep). |
| `terraform/` | Creates the VM from the image on a libvirt host (`qemu:///system` or remote) and attaches the seed disk. |
| `terraform.sh`, `bin/mkisofs` | Runs that module with private file permissions and xorriso's mkisofs compatibility mode. |
| `build-debuggee.sh` | Checks the ISO hash, prepares the throwaway build key and the storage driver, runs Packer. |
| `hyperv/New-LabVM.ps1` | Creates a Generation 2 VM locally on Windows from an exported VHDX and a private seed VHDX. |
| `export-hyperv.sh` | Converts a finished qcow2 to VHDX, compares all logical bytes and writes its SHA-256. |
| `mise.toml`, `requirements.txt` | Pinned Packer, Terraform and Ansible controller. |

**Scope.** This is a *development candidate* environment with the Windows build used by `win10-debug3`. Linux uses
Q35/OVMF, virtio storage and e1000e; Hyper-V uses its own Generation 2 UEFI, SCSI storage and synthetic NIC. It is **not**
the qualified target. The harness checks the qualified machine's name and UUID, so
qualification rows still run only on `win10-debug3`; promoting an image to a baseline is a separate owner decision
(see `driver/docs/operations/LAB-WORKFLOW-DESIGN.md`, section 5). The image has no SafeUpload driver, agent, policy or
test accounts: the row launchers install a matched pair on every disposable run disk.

## Which hosts can use this

Image construction runs on Linux with QEMU/KVM. A finished image can run locally on either Linux or Windows. The guest is always Windows.

| Colleague's machine | Build the image | Run the VM from a finished image | Automated qualification rows |
|---|---|---|---|
| Linux with KVM + libvirt | Packer + Ansible | Terraform + qcow2 | Only the approved lab target, with the existing identity checks |
| Windows 10/11 Pro/Enterprise with Hyper-V enabled | Use the image built on Linux | `hyperv/New-LabVM.ps1` + VHDX | No: the row launchers require bash/libvirt and the approved target |
| Windows Home / WSL2 | No supported local build route | Hyper-V host required for this Windows route | No |
| macOS | not supported (no usable x86 KVM) | not supported | not supported |

The Windows route uses native PowerShell/Hyper-V cmdlets and an existing virtual switch. Terraform/libvirt stays on Linux;
do not run this module natively on Windows or assume a remote libvirt URI makes the provider portable. Neither route changes
the qualified harness identity checks. These are development machines, not newly authorized qualification targets.

## What you need

- A Linux host with KVM (`/dev/kvm` access), libvirt (including `virsh`) that your user may manage as `qemu:///system`
  (usually the `libvirt` group), Python 3, QEMU, `xorriso`, `7z`, [mise](https://mise.jdx.dev), ~70 GB free for the build.
- The Microsoft ISO `Win10_22H2_EnglishInternational_x64v1.iso`, SHA-256
  `edc53c5c5fe6926dea23fc3e884fbcf78cc2b9e76364be968f806fc6d42b59d2` (May 2023 media, install image build 19041 SP build 2965).
  The build refuses any other hash. Newer media would not be build 19045.2965.
- `virtio-win.iso` containing the storage driver pinned in `packer/viostor.sha256` (the image needs no other virtio driver).
  Tested media: volume label `virtio-win-0.1.302`, ISO SHA-256
  `303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d`; viostor version `100.103.104.30200`.
- A Windows 10 Pro license of your own. The image installs with Microsoft's public *generic* Pro key, which selects the
  edition and does not activate. Activate it yourself; do not redistribute the image beyond what your license allows.

```bash
cd lab
mise install                       # Packer 1.16.1, Terraform 1.16.6
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
(cd ansible && ../.venv/bin/ansible-galaxy collection install -r requirements.yml -p collections)
mise exec -- ./build-debuggee.sh --iso ~/Downloads/Win10_22H2_EnglishInternational_x64v1.iso --virtio-iso ~/Downloads/virtio-win.iso
# ~30 min on the reference host; add --validate-only to check inputs
```

The result is `lab/output/debuggee/safeupload-debuggee-19045.2965.qcow2` plus `packer-manifest.json` and `image.sha256`.
Share the qcow2 and its hash through your team's storage, never through Git.
The wrapper finds common Arch and Debian/Ubuntu OVMF paths. For another layout set both `LAB_OVMF_CODE` and
`LAB_OVMF_VARS` to matching non-Secure-Boot firmware files. The wrapper uses `.venv` automatically, refuses existing
output directories, preserves failed attempts and removes the private build key on success, validation and failure.
Packer's temporary config CD holds the build password, so it is kept inside the private `work/debuggee.*` directory and
removed with the key. A failed build leaves its VM running for console diagnosis; the wrapper says how to stop it.
Treat `work/` as private; share only the finished generalized image and its receipts.
The image playbook requires the unique UUID supplied to QEMU for that build and the fresh `SU-LAB-BUILD` name, and
rejects the recorded target/builder UUIDs before configuration. This OS ships OpenSSH **7.7.2.3**, below
[Ansible SSH's supported minimum](https://docs.ansible.com/projects/ansible/latest/os_guide/windows_ssh.html).
Packer uses SSH to retrieve the candidate's public TLS certificate; Ansible then uses **HTTPS WinRM with NTLM and
certificate validation**, trusting only that certificate. Credentials stay in private variable files. The temporary
WinRM listener, TLS key/certificate, local-account remoting exception and temporary Private NAT profile are removed/restored by finalization;
WinRM is disabled in the shared image. Ordinary SSH access after seeding uses each colleague's own keys.

## Create a VM (any libvirt host)

```bash
cd lab/terraform
cp terraform.tfvars.example terraform.tfvars   # image_path, image_sha256, SSH public key, optional public certificate
mise exec -- ../terraform.sh init && mise exec -- ../terraform.sh apply
mise exec -- ../terraform.sh output -raw admin_password     # generated unless you set admin_password
virsh -c qemu:///system domifaddr su-lab-debuggee && ssh vika@<address>
```

First boot takes several minutes. During Windows setup, a private per-instance answer names the existing `vika` account
(Windows 10 client ignores `HideLocalAccountScreen`; naming the account is what skips "Who's going to use this PC?") and
enables one automatic login with the seed password. A SYSTEM task removes that answer, cached answers and autologon credentials
before applying the seed and restarting. The shared image contains no autologon password. The seed applies: new SSH host keys, only your keys authorized, the admin password, the
computer name, the time zone and your **public** test-signing certificate in `LocalMachine\Root` and `TrustedPublisher`.
Each person should generate their own test-signing certificate; the private key never goes into an image or a seed.
Keep the admin account as `vika`; the image contains that account. Domain names must start with `su-lab-`. Each instance
gets its own pool and disk directory, mode 0700 owned by the QEMU runtime uid/gid discovered from libvirt capabilities.
The module refuses hosts that do not advertise that DAC identity; it changes no host-wide permissions or configuration. Firmware paths in `terraform.tfvars` refer to the **libvirt host**; on Debian/Ubuntu
set `ovmf_code = "/usr/share/OVMF/OVMF_CODE_4M.fd"` and `ovmf_vars = "/usr/share/OVMF/OVMF_VARS_4M.fd"` as appropriate.
Terraform state and the seed ISO hold the admin password; keep them private and out of Git. `terraform destroy` removes
only this module's candidate resources; never import qualified lab resources into this state.
After initialization, a changed seed is refused rather than silently replacing administrator credentials.
The Linux seed ISO is readable within the guest; detach it after initialization before adding untrusted guest accounts.

## Create a local Windows VM (Hyper-V)

On the Linux image-building host, export the **finished, never booted after generalization** image:

```bash
./lab/export-hyperv.sh lab/output/debuggee/safeupload-debuggee-19045.2965.qcow2 <qcow2-sha256> lab/output/hyperv
```

Share the VHDX and `image.sha256`. Use a checkout of this repository on the Windows colleague's machine for the scripts.
On a Windows 10/11 Pro/Enterprise Hyper-V host, open **Windows PowerShell 5.1 as
Administrator**. Hyper-V and an existing virtual switch must already be available (`Get-VMSwitch`); the script does not
change host features or networking. The execution-policy command below applies only to this PowerShell process. An existing external switch or the Windows client Default Switch supplies DHCP.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Get-VMSwitch
$settings = @{
    ImagePath = 'D:\Images\safeupload-debuggee-19045.2965.vhdx'
    ImageSha256 = '<VHDX hash from image.sha256>'
    VMRoot = 'D:\SafeUploadLab'
    SwitchName = 'Default Switch' # or an existing external switch
    SshPublicKeyFiles = @("$env:USERPROFILE\.ssh\id_ed25519.pub")
    Name = 'su-lab-debuggee'
    Hostname = 'SU-LAB-DEBUG'
}
.\lab\hyperv\New-LabVM.ps1 @settings -ValidateOnly
.\lab\hyperv\New-LabVM.ps1 @settings -Start # prompts for your new vika password
vmconnect.exe localhost su-lab-debuggee
Get-VMNetworkAdapter -VMName su-lab-debuggee | Select-Object -ExpandProperty IPAddresses
```

Supply an OpenSSH **public** key (`ssh-keygen -t ed25519` creates a pair if needed), never the private key. Optional
`TrustedCertificateFiles = @('D:\Certificates\my-test-signing.cer')` imports only your public test-signing certificate.
The script verifies the image hash and copies it to a new private VM directory, creates an NTFS `cidata` seed disk with a SYSTEM/Administrators-only ACL before writing credentials, selects
Generation 2, disables Secure Boot and checkpoints, and adds no TPM. The guest uses Windows' inbox Hyper-V storage and
network drivers. First boot reads the same seed JSON as Linux, sets the password/keys/hostname and restarts once.

The seed VHDX holds the password: keep the VM directory private. Existing VM names/directories are refused; a failed
creation is preserved for diagnosis. To remove your candidate, stop it, remove its VM registration in Hyper-V Manager,
then delete only that VM's directory. The shared source VHDX is never attached or changed.

## Verify the tooling and a new guest

These offline controls create no VM:

```bash
python3 lab/selfcheck.py                           # real sparse qcow2 -> VHDX conversion + byte comparison/refusals
(cd lab && mise exec -- ./terraform.sh init && mise exec -- ./terraform.sh test)  # mocked providers, seven safety controls
```

On Windows: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\lab\Test-LabScripts.ps1` parses all lab scripts in
PowerShell 5.1, including embedded Ansible shell bodies, and exercises preflight with simulated Hyper-V cmdlets. It explicitly reports `NativeHyperVRun=NOT_RUN`.
It does not replace a boot test on a real Hyper-V host.

After a new VM has applied its seed/restarted, copy `Test-LabGuest.ps1` and your public key into it, then run elevated:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-LabGuest.ps1 -ExpectedHostname SU-LAB-DEBUG -ExpectedSshPublicKeyFiles .\id_ed25519.pub
```

This checks Windows 19045.2965, test signing, Secure Boot off, no TPM, CPU count, seeded keys/hostname, running SSH and
absence of product installation. Record its UUID/host-key receipt and confirm SSH rejects an unrelated key. Reboot once
more to check the seed remains idempotent. This candidate acceptance is separate from product qualification.

## What is removed before the image is generalized

`ansible/roles/sanitize` and `safeupload-finalize.ps1` remove, and a verification step fails the build if any remain:
the autologon values (`DefaultPassword` etc.), the build account's password (replaced by a random value nobody holds), the
cached setup answer files (they held the build password), PowerShell history, recent items, caches, temp, crash reports,
stored credentials, DNS/ARP caches and every event log; then the build SSH key and the machine's SSH host keys.
The verification also reads every remaining file under `Windows\Panther`, `System32\Sysprep`, `Windows\Temp` and the seed
directory and fails if the build password appears in any of them; a planted control file proves the scan detects it.
Setup's `UnattendGC` logs stay locked by the build's signed-in session and are removed only when possible; they are logs,
not answer files, and the content scan covers them. A self-removing SYSTEM task runs `sysprep /generalize` and waits for it, so ending the last SSH session does not kill Sysprep. Hibernation is off, so no `hiberfil.sys` carries memory into the image.

Check an image before sharing it, without booting it: `virt-ls`/`guestmount` (read-only) or `7z l` the qcow2's NTFS
partition for `Users\*\AppData`, `Windows\Panther`, `ProgramData\ssh`. The first boot of the generalized image is the
authoritative test: only the seeded administrator, Windows built-in accounts and the `sshd` account of the Windows OpenSSH
Server feature exist, and SSH accepts only the keys from your seed.

## Not included (by design)

- **Builder image.** The kernel/agent builders need Visual Studio, the WDK/SDK and .NET 10 from pinned offline payloads and
  hold the test-signing key; they follow once their payload hashes are recorded (design section 4).
- **Office / Microsoft 365** (licensed, interactive sign-in) and any signed-in account state.
- **Windows updates.** The build stays at 19045.2965 on purpose; Windows Update is disabled in the image.
