# Lab portability validation — 2026-10-21

Working-tree validation based on commit `b822143ca2032259d6ea31dde6ea9cf2c3f48d2e`; changes are uncommitted.
This tests development images, separate from driver/agent qualification or baseline promotion.
Raw receipts are retained locally in `driver/evidence/2026-10-21/lab-portability/`; the receipts cited here are tracked there
(K: `linux-build-k.txt`, `terraform-k-*.txt`, `hyperv-k-export.txt`; reclamation: `lab-reclamation-k.json`).

| Check | Result |
|---|---|
| Pinned Windows ISO and viostor hashes | PASS |
| Linux offline controls | 3/3 PASS (`linux-controls-final-k.txt`); Ansible syntax PASS |
| Terraform mocked controls | 7/7 PASS (`terraform-tests-final-k.txt`) |
| Native Windows PowerShell 5.1 gate | PASS (`windows-gate-o.txt`): 12 scripts and 11 embedded Ansible bodies parse; generated per-instance OOBE answer checked with .NET XML |
| Seed certificate parsing (PS 5.1) | DER and PEM accepted, PFX refused before key import (`seed-cert-parse-n3.txt`) |
| Fresh complete Linux image build K | PASS: 26 min 58 s, 23/23 tasks, generalized; qcow2 SHA-256 `81a9715fd5f4f934d606078e11ee9d86bb2fe18e54577d165039aff55aec5c88` |
| Linux Terraform lifecycle on K | PASS: scoped create; private pool 0700 QEMU-owned; unattended first boot to seeded SSH in ~4 min; `Test-LabGuest` acceptance; public certificate in Root/TrustedPublisher without private key; unrelated SSH key refused; seed password accepted; reboot idempotent; scoped destroy with shared image unchanged |
| VHDX export of K | PASS: `qemu-img compare` identical; SHA-256 `21f673bc59a15470b60885a11e284fc85fa1c53a3dc1f986e54fcaffb2efd9d7` |
| Hyper-V route (`New-LabVM.ps1`, native Windows SSH client) | POSTPONED by owner; never booted. Nested test scripts prepared (`Invoke-NestedHyperV.ps1`, `hyperv-nested-k.py`); host candidate created and destroyed unused |
| Qualified target | Off; inactive XML SHA-256 `cf139830e40d4f3c8e08a8d895b40573579d6d798b7c9c516b60e7daf4f63698` unchanged before/after each candidate |

K is the delivered candidate. It is not shared yet: qcow2 in `lab/output/linux-portability-1021k/`, VHDX in
`/mnt/storage/safeupload-lab/export-1021k/`. Distribution is the owner's choice of team storage, never Git.

## Defects found and fixed after G

| Found on | Defect | Fix and verification |
|---|---|---|
| Build H | Strict removal of `Panther\UnattendGC` failed: the build's signed-in session (`taskhostw`, `CloudExperienceHostBroker`) holds the Setup logs open | Answer-file paths stay strictly removed; logs best-effort; verification now scans every remaining Panther/Sysprep/temp/seed file for the build password with a planted positive control. Before the change, a scan of H with a planted control found only the control (`build-h-secret-scan-control.txt`); the new tasks passed on the H VM (`build-h-sanitize-fix-replay.txt`) and in builds I and K |
| Build H | An aborted Packer run leaves its temporary config CD, which holds the build password, in `/tmp` (all attempts A–H) | `TMPDIR`/`PACKER_TMP_DIR` point at the private work directory and the exit trap removes it; confirmed on I, J and K. The wrapper now says how to stop a failed VM |
| F2, verified on I | Windows 10 client ignores `HideLocalAccountScreen` (Server only), so OOBE asked "Who's going to use this PC?" | Per-instance answer (`New-OobeAnswer.ps1`) names the existing `vika` account like the install answer; I and K reached the desktop unattended |
| I | Seed `Import-Certificate` is denied for `TrustedPublisher` as SYSTEM (admin succeeds); reproduced natively (`terraform-i-system-cert-test.png`) | `X509Store` for both stores, content-type gate before construction, `HasPrivateKey` refusal |
| I | `Confirm-SecureBootUEFI` throws `0xC0000100` on OVMF without Secure Boot | Only that status counts as off; other errors still fail |
| I | OpenSSH Server feature creates the local `sshd` account | Allowed by `Test-LabGuest.ps1`; README corrected |

Candidate I was completed from the console with the fixed seed for diagnosis (`terraform-i-check-d.txt`,
`terraform-i-reboot.txt`); that is not counted as a pass. Build J was cancelled during Windows installation to include
the content-type gate and produced no artifact. After the run the owner asked to clean the disk: images A–J and the I
export (103.4 GiB) were deleted; their receipts, screenshots and the F diagnostic extracts remain. No assertion was
relaxed to accept a failure.

## Remaining

- Hyper-V: run `hyperv/New-LabVM.ps1` with the K VHDX on a Hyper-V host (nested on KVM is prepared; a physical host is
  stronger); verify acceptance, unrelated-key refusal, reboot, cleanup and unchanged shared VHDX.
- Builder image (VS/WDK/.NET payloads, signing key) and Office remain later work.
