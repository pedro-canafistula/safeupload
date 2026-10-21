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
# Prefer the documented project-local controller; do not require a machine-wide Python install.
if [ -x "$lab/.venv/bin/ansible-playbook" ]; then export PATH="$lab/.venv/bin:$PATH"; fi
while [ $# -gt 0 ]; do
    case "$1" in --iso|--virtio-iso|--out) [ $# -ge 2 ] && [[ "$2" != --* ]] || { echo "missing value for $1" >&2; exit 2; } ;; esac
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
iso=$(realpath "$iso"); virtio=$(realpath "$virtio")
expected=${LAB_ISO_SHA256:-edc53c5c5fe6926dea23fc3e884fbcf78cc2b9e76364be968f806fc6d42b59d2}
for tool in python3 packer ansible-playbook 7z xorriso ssh-keygen qemu-system-x86_64 sha256sum; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "no access to /dev/kvm" >&2; exit 2; }
# Arch and Debian/Ubuntu package OVMF in different locations. Explicit overrides must be a matching pair.
ovmf_code=${LAB_OVMF_CODE:-}; ovmf_vars=${LAB_OVMF_VARS:-}
if [ -z "$ovmf_code" ] && [ -z "$ovmf_vars" ]; then
    for pair in /usr/share/edk2/x64/OVMF_CODE.4m.fd:/usr/share/edk2/x64/OVMF_VARS.4m.fd \
                /usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd \
                /usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd; do
        if [ -r "${pair%:*}" ] && [ -r "${pair#*:}" ]; then
            ovmf_code=${pair%:*}; ovmf_vars=${pair#*:}; break
        fi
    done
fi
[ -n "$ovmf_code" ] && [ -n "$ovmf_vars" ] && [ -r "$ovmf_code" ] && [ -r "$ovmf_vars" ] || {
    echo 'needs matching OVMF firmware; set LAB_OVMF_CODE and LAB_OVMF_VARS' >&2; exit 2;
}
actual=$(sha256sum "$iso" | cut -d' ' -f1)
[ "$actual" = "$expected" ] || { echo "ISO SHA-256 mismatch: got $actual, expected $expected" >&2; exit 3; }
echo "ISO verified: $actual"

[ ! -e "$out" ] || { echo "output directory $out exists; choose a fresh one" >&2; exit 4; }
mkdir -p "$lab/work"
umask 077
work=$(mktemp -d "$lab/work/debuggee.XXXXXXXX")
# Packer's temporary config CD holds the build answer file (password) and an aborted build keeps it: confine it here.
mkdir "$work/tmp"; export TMPDIR="$work/tmp" PACKER_TMP_DIR="$work/tmp"
# Always remove the private key and credentials, including after validation or a failed build. Keep other failure evidence.
trap 'rm -rf "$work/build_key" "$work/build_key.pub" "$work/build_key.pub.txt" "$work/build.pkrvars.json" "$work/ansible-vars.json" "$work/tmp"' EXIT
mkdir -p "$work/drivers/viostor"
echo "virtio storage driver:"
7z e -y -o"$work/drivers/viostor" "$virtio" 'viostor/w10/amd64/viostor.inf' 'viostor/w10/amd64/viostor.sys' 'viostor/w10/amd64/viostor.cat' >/dev/null
for f in viostor.inf viostor.sys viostor.cat; do [ -s "$work/drivers/viostor/$f" ] || { echo "virtio ISO lacks $f" >&2; exit 3; }; done
(cd "$work/drivers/viostor" && sha256sum -c "$lab/packer/viostor.sha256")

ssh-keygen -q -t ed25519 -N '' -C 'safeupload-lab-build-throwaway' -f "$work/build_key"
cp "$work/build_key.pub" "$work/build_key.pub.txt"; chmod 600 "$work/build_key"
python3 - "$work" <<'PY'
import json, pathlib, secrets, socket, sys, uuid
work = pathlib.Path(sys.argv[1])
password = 'B' + secrets.token_urlsafe(24) + '!a9'
identity = str(uuid.uuid4())
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
(work/'build.pkrvars.json').write_text(json.dumps({'build_password':password, 'build_uuid':identity, 'winrm_host_port':port}))
(work/'ansible-vars.json').write_text(json.dumps({
    'ansible_connection':'winrm', 'ansible_host':'localhost', 'ansible_port':port, 'ansible_user':'vika',
    'ansible_password':password, 'ansible_winrm_transport':'ntlm', 'ansible_winrm_scheme':'https',
    'ansible_winrm_server_cert_validation':'validate', 'ansible_winrm_ca_trust_path':str(work/'winrm.pem'),
    'image_build_uuid':identity,
}))
PY

cd "$lab/packer"
packer init debuggee.pkr.hcl
args=(-var-file="$work/build.pkrvars.json" -var "iso_path=$iso" -var "iso_sha256=$expected" -var "config_dir=$work" -var "build_private_key=$work/build_key" -var "output_dir=$out"
      -var "ovmf_code=$ovmf_code" -var "ovmf_vars=$ovmf_vars")
packer validate "${args[@]}" debuggee.pkr.hcl
[ "$validate_only" = no ] || { echo "validate-only: done"; exit 0; }
if ! PACKER_LOG=1 PACKER_LOG_PATH="$work/packer.log" packer build -on-error=abort "${args[@]}" debuggee.pkr.hcl; then
    # -on-error=abort keeps the failed VM and its disk for diagnosis (console only: the trap removes its credentials).
    echo "build failed; log: $work/packer.log. The failed VM may still run (VNC address in the log):" \
         "stop the qemu-system-x86_64 process named safeupload-debuggee-19045.2965.qcow2 (pgrep -a qemu-system)." >&2
    exit 1
fi
echo "image: $out/safeupload-debuggee-19045.2965.qcow2"
(cd "$out" && sha256sum safeupload-debuggee-19045.2965.qcow2) | tee "$out/image.sha256"
echo "build log: $work/packer.log"
