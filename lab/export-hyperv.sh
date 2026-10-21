#!/usr/bin/env bash
# Export a finished, generalized image. Never boot the shared source image before exporting it.
# Usage: lab/export-hyperv.sh <image.qcow2> <expected-sha256> <new-output-directory>
set -euo pipefail
[ $# -eq 3 ] || { echo "usage: $0 <image.qcow2> <expected-sha256> <new-output-directory>" >&2; exit 2; }
image=$(realpath "$1"); expected=$2; out=$(realpath -m "$3")
[[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'invalid SHA-256' >&2; exit 2; }
[ "$(sha256sum "$image" | cut -d' ' -f1)" = "${expected,,}" ] || { echo 'image SHA-256 mismatch' >&2; exit 3; }
[ ! -e "$out" ] || { echo 'choose a new output directory' >&2; exit 4; }
qemu-img info --output=json "$image" | python3 -c '
import json, sys
i = json.load(sys.stdin)
if i["format"] != "qcow2" or i.get("backing-filename"):
    sys.exit("needs a standalone qcow2, not a run overlay")
'
qemu-img check -q -f qcow2 "$image"
umask 077
mkdir -p "$out"
vhdx="$out/safeupload-debuggee-19045.2965.vhdx"
qemu-img convert -p -f qcow2 -O vhdx -o subformat=dynamic "$image" "$vhdx"
qemu-img compare -f qcow2 -F vhdx "$image" "$vhdx"
(cd "$out" && sha256sum "$(basename "$vhdx")" > image.sha256)
echo "Hyper-V disk and checksum: $out"
