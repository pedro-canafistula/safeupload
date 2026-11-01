#!/usr/bin/env bash
# Start or end a throwaway session on the test VM (win10-debug3). Nothing is written to the base disks.
#
#   driver/scripts/vm-session.sh begin <tag> [--office]   boot on a fresh overlay (of the Office image with --office)
#   driver/scripts/vm-session.sh end <tag>                power off, delete the overlay, restore the normal base disk
#   driver/scripts/vm-session.sh autologon                with --office: log the Office test user (t5actor) on, then reboot
#
# The guest answers SSH as vika@192.168.122.52. Use driver/scripts/remote_ps.py to run PowerShell on it.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
V="virsh -c qemu:///system"
source driver/scripts/run-disk.sh
dom=win10-debug3; host=192.168.122.52
normal_base=/var/lib/libvirt/images/win10-debug3.base-20261014.qcow2
office_base=/var/lib/libvirt/images/win10-debug3.office-base-20261029.qcow2
office_secret="$HOME/Work/safeupload-tools/secrets/office-base-20261029-t5actor.txt"
ssh_opts=(-F /dev/null -i "$HOME/.ssh/id_ed25519" -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)

wait_ssh() {
    for _ in $(seq 120); do ssh "${ssh_opts[@]}" "vika@$host" exit 2>/dev/null && return 0; sleep 5; done
    echo "guest did not answer SSH"; return 1
}

case "${1:-}" in
begin)
    tag="${2:?tag}"
    [ "$($V domstate win10-debug2)" = "shut off" ] || { echo "win10-debug2 must be off (same guest IP)"; exit 1; }
    [ "$($V domstate $dom)" = "shut off" ] || { echo "$dom is running; end the current session first"; exit 1; }
    [ "$(_rd_vda $dom --inactive)" = "$normal_base" ] || { echo "$dom is not on its normal base disk"; exit 1; }
    if [ "${3:-}" = "--office" ]; then
        [ "$(_rd_vol "$office_base" backing)" = "$normal_base" ] || { echo "unexpected Office image chain"; exit 1; }
        _rd_repoint $dom "$office_base" || exit 1
    fi
    if ! run_disk_begin $dom "$tag"; then
        _rd_repoint $dom "$normal_base"; exit 1
    fi
    wait_ssh || exit 1
    echo "session $tag running on $(_rd_vda $dom "")"
    ;;
end)
    tag="${2:?tag}"
    run_disk_end $dom "$tag" || exit 1
    [ "$(_rd_vda $dom --inactive)" = "$normal_base" ] || _rd_repoint $dom "$normal_base"
    echo "session $tag ended; $dom is off on $(_rd_vda $dom --inactive)"
    ;;
autologon)
    # The password goes from the owner-only file straight into the remote channel; it is never printed.
    python3 - "$office_secret" <<'PY' | python3 driver/scripts/remote_ps.py "$host" >/dev/null
import base64, sys
password = open(sys.argv[1], encoding="utf-8").read().strip()
encoded = base64.b64encode(password.encode("utf-8")).decode("ascii")
print("""$ErrorActionPreference='Stop'
$password=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('""" + encoded + """'))
$key='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
foreach($v in @{AutoAdminLogon='1';DefaultUserName='t5actor';DefaultDomainName=$env:COMPUTERNAME;DefaultPassword=$password}.GetEnumerator()){
 New-ItemProperty -LiteralPath $key -Name $v.Key -Value $v.Value -PropertyType String -Force | Out-Null }
New-ItemProperty -LiteralPath $key -Name AutoLogonCount -Value 1 -PropertyType DWord -Force | Out-Null
Restart-Computer -Force
""")
PY
    sleep 30; wait_ssh || exit 1
    for _ in $(seq 60); do
        out=$(python3 driver/scripts/remote_ps.py "$host" 2>/dev/null <<'PS' | tr -d '\r'
Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User }
PS
)
        grep -qx t5actor <<<"$out" && { echo "t5actor is logged on"; exit 0; }
        sleep 5
    done
    echo "t5actor did not log on"; exit 1
    ;;
*) echo "usage: $0 begin <tag> [--office] | end <tag> | autologon"; exit 2 ;;
esac
