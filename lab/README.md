# SafeUpload lab images

Reproducible Windows 10 22H2 (build **19045.2965**) lab VMs for development, built from a clean Microsoft ISO with
Packer and Ansible, and created on any libvirt host with Terraform. The images contain no personal data, accounts you
chose, SSH keys, certificates or caches: each person's identity is injected at first boot from a seed disk.

| Directory | Role |
|---|---|
| `packer/` | Unattended Windows install (UEFI, no Secure Boot, no TPM, virtio disk, e1000e NIC) and the build definition. |
| `ansible/` | Roles run inside the build: `win_base` (exact build, no updates, test signing), `debuggee`, `lab_seed` (first-boot identity), `sanitize` (secret and cache removal + sysprep). |
| `terraform/` | Creates the VM from the image on a libvirt host (`qemu:///system` or remote) and attaches the seed disk. |
| `build-debuggee.sh` | Checks the ISO hash, prepares the throwaway build key and the storage driver, runs Packer. |
| `mise.toml` | Pinned Packer and Terraform; ansible-core `>=2.18,<2.20` (Windows over SSH needs 2.18+). |

**Scope.** This is a *development candidate* environment: same Windows build, firmware definition, disk and NIC model as
`win10-debug3`. It is **not** the qualified target. The harness checks the qualified machine's name and UUID, so
qualification rows still run only on `win10-debug3`; promoting an image to a baseline is a separate owner decision
(see `driver/docs/operations/LAB-WORKFLOW-DESIGN.md`, section 5). The image has no SafeUpload driver, agent, policy or
test accounts: the row launchers install a matched pair on every disposable run disk.

## What you need

- A Linux host with KVM (`/dev/kvm` access), libvirt, QEMU, `xorriso`, `7z`, ~70 GB free for the build.
- The Microsoft ISO `Win10_22H2_EnglishInternational_x64v1.iso`, SHA-256
  `edc53c5c5fe6926dea23fc3e884fbcf78cc2b9e76364be968f806fc6d42b59d2` (May 2023 media, install image build 19041 SP build 2965).
  The build refuses any other hash. Newer media would not be build 19045.2965.
- `virtio-win.iso` (storage driver only is used; the image needs no other virtio driver).
- A Windows 10 Pro license of your own. The image installs with Microsoft's public *generic* Pro key, which selects the
  edition and does not activate. Activate it yourself; do not redistribute the image beyond what your license allows.

```bash
cd lab
mise install                       # Packer 1.16.1, Terraform 1.16.6
pipx install 'ansible-core>=2.18,<2.20'
ansible-galaxy collection install -r ansible/requirements.yml -p ansible/collections
./build-debuggee.sh --iso ~/Downloads/Win10_22H2_EnglishInternational_x64v1.iso   # ~1 h; add --validate-only to check inputs
```

The result is `lab/output/debuggee/safeupload-debuggee-19045.2965.qcow2` plus `packer-manifest.json` and `image.sha256`.
Share the qcow2 and its hash through your team's storage, never through Git.

## Create a VM (any libvirt host)

```bash
cd lab/terraform
cp terraform.tfvars.example terraform.tfvars   # image_path, your SSH public key, optional test-signing certificate
terraform init && terraform apply
terraform output -raw admin_password           # generated unless you set admin_password
virsh -c qemu:///system domifaddr su-lab-debuggee && ssh vika@<address>
```

First boot (about a minute) applies the seed: new SSH host keys, only your keys authorized, the admin password, the
computer name, the time zone and your **public** test-signing certificate in `LocalMachine\Root` and `TrustedPublisher`.
Each person should generate their own test-signing certificate; the private key never goes into an image or a seed.

## What is removed before the image is generalized

`ansible/roles/sanitize` and `safeupload-finalize.ps1` remove, and a verification step fails the build if any remain:
the autologon values (`DefaultPassword` etc.), the build account's password (replaced by a random value nobody holds), the
cached setup answer files (they held the build password), PowerShell history, recent items, caches, temp, crash reports,
stored credentials, DNS/ARP caches and every event log; then the build SSH key and the machine's SSH host keys, followed
by `sysprep /generalize`. Hibernation is off, so no `hiberfil.sys` carries memory into the image.

Check an image before sharing it, without booting it: `virt-ls`/`guestmount` (read-only) or `7z l` the qcow2's NTFS
partition for `Users\*\AppData`, `Windows\Panther`, `ProgramData\ssh`. The first boot of the generalized image is the
authoritative test: no account except the admin exists, and SSH accepts only the keys from your seed.

## Not included (by design)

- **Builder image.** The kernel/agent builders need Visual Studio, the WDK/SDK and .NET 10 from pinned offline payloads and
  hold the test-signing key; they follow once their payload hashes are recorded (design section 4).
- **Office / Microsoft 365** (licensed, interactive sign-in) and any signed-in account state.
- **Windows updates.** The build stays at 19045.2965 on purpose; Windows Update is disabled in the image.
