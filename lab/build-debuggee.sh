#!/usr/bin/env bash
# Build the generalized SafeUpload lab debuggee image (Windows 10 22H2 Pro, build 19045.2965) with Packer + Ansible.
#
# Usage: lab/build-debuggee.sh --iso /path/Win10_22H2_EnglishInternational_x64v1.iso [--virtio-iso /path/virtio-win.iso]
#                              [--out lab/output/debuggee] [--validate-only]
#
# Inputs are checked before anything runs: the ISO must have the pinned SHA-256 (override with LAB_ISO_SHA256 only to
# register a new, reviewed media build), the virtio ISO must contain the Windows 10 amd64 storage driver. The build uses a
# throwaway SSH key and a random password, both discarded; the image carries neither (see ansible/roles/sanitize).
# Needs: KVM access (/dev/kvm), qemu-system-x86_64, xorriso, 7z, ssh-keygen, ~70 GB free in the output directory, 4 GiB RAM.
set -euo pipefail
lab=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
iso=""; virtio=/var/lib/libvirt/images/virtio-win.iso; out="$lab/output/debuggee"; validate_only=no
while [ $# -gt 0 ]; do
    case "$1" in
        --iso) iso=$2; shift 2 ;;
        --virtio-iso) virtio=$2; shift 2 ;;
        --out) out=$(realpath -m "$2"); shift 2 ;;
        --validate-only) validate_only=yes; shift ;;
        *) echo "unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -n "$iso" ] && [ -f "$iso" ] || { echo "needs --iso <Windows 10 22H2 ISO>" >&2; exit 2; }
[ -f "$virtio" ] || { echo "virtio-win ISO not found: $virtio" >&2; exit 2; }
expected=${LAB_ISO_SHA256:-edc53c5c5fe6926dea23fc3e884fbcf78cc2b9e76364be968f806fc6d42b59d2}
for tool in packer 7z xorriso ssh-keygen qemu-system-x86_64 sha256sum; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "no access to /dev/kvm" >&2; exit 2; }
actual=$(sha256sum "$iso" | cut -d' ' -f1)
[ "$actual" = "$expected" ] || { echo "ISO SHA-256 mismatch: got $actual, expected $expected" >&2; exit 3; }
echo "ISO verified: $actual"

work="$lab/work/debuggee"; rm -rf "$work"; mkdir -p "$work/drivers/viostor" "$out"
[ -z "$(ls -A "$out" 2>/dev/null)" ] || { echo "output directory $out is not empty; choose a fresh one" >&2; exit 4; }
rmdir "$out"
echo "virtio storage driver:"
7z e -y -o"$work/drivers/viostor" "$virtio" 'viostor/w10/amd64/viostor.inf' 'viostor/w10/amd64/viostor.sys' 'viostor/w10/amd64/viostor.cat' >/dev/null
for f in viostor.inf viostor.sys viostor.cat; do [ -s "$work/drivers/viostor/$f" ] || { echo "virtio ISO lacks $f" >&2; exit 3; }; done
(cd "$work/drivers/viostor" && sha256sum viostor.inf viostor.sys viostor.cat)

ssh-keygen -q -t ed25519 -N '' -C 'safeupload-lab-build-throwaway' -f "$work/build_key"
cp "$work/build_key.pub" "$work/build_key.pub.txt"; chmod 600 "$work/build_key"

cd "$lab/packer"
packer init debuggee.pkr.hcl
args=(-var "iso_path=$iso" -var "iso_sha256=$expected" -var "config_dir=$work" -var "build_private_key=$work/build_key" -var "output_dir=$out")
packer validate "${args[@]}" debuggee.pkr.hcl
[ "$validate_only" = no ] || { echo "validate-only: done"; exit 0; }
PACKER_LOG=1 PACKER_LOG_PATH="$lab/work/packer-debuggee.log" packer build -on-error=ask "${args[@]}" debuggee.pkr.hcl
echo "image: $out/safeupload-debuggee-19045.2965.qcow2"
sha256sum "$out"/*.qcow2 | tee "$out/image.sha256"
rm -rf "$work"
