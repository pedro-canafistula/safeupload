# Sourced by the harness runners (needs $V = "virsh -c qemu:///system" and image-store.sh).
# Disposable run disks. A debuggee idles SHUT OFF on its base disk, and no run ever writes the base. run_disk_begin creates a fresh qcow2
# overlay on the base, points the domain at it and starts the guest. run_disk_end powers the guest off, points the domain back at the base
# and deletes every file the run stacked above the base (the run overlay and any live checkpoint taken during the run). So nothing piles up,
# the chain above the base is never deeper than two, and every run starts from the same disk. The evidence of a run is copied off the guest
# over SSH before run_disk_end; nothing is kept in the overlay.
# State: $RUN_DISK_STATE/<domain> names the base, the run overlay, the tag and the base's mtime and size (checked unchanged at the end).
# Overlays go next to the base unless SAFEUPLOAD_RUN_DISK_DIR names another libvirt pool directory; SAFEUPLOAD_MIN_FREE_GB (default 20)
# is the free space the overlay's filesystem must have before a run starts.
RUN_DISK_STATE="${XDG_STATE_HOME:-$HOME/.local/state}/safeupload/run-disks"

_rd_log() { printf '%s run-disk %s\n' "$(date -u +%FT%TZ)" "$*"; }
_rd_vda() {  # $1 domain, $2 "--inactive" or "" -> file of the vda disk
    $V dumpxml $2 "$1" | python3 -I -c '
import sys, xml.etree.ElementTree as ET
for d in ET.fromstring(sys.stdin.read()).iter("disk"):
    t = d.find("target"); s = d.find("source")
    if d.get("device") == "disk" and t is not None and t.get("dev") == "vda":
        print(s.get("file", "") if s is not None else ""); break'
}
_rd_vol() {  # $1 path, $2 field (backing | format | capacity) -> value from the volume's libvirt description
    local pool; pool=$(image_pool_of "$(dirname "$1")") || { echo "no libvirt pool for $(dirname "$1")" >&2; return 1; }
    $V pool-refresh "$pool" >/dev/null && $V vol-dumpxml --pool "$pool" "$(basename "$1")" | python3 -I -c '
import sys, xml.etree.ElementTree as ET
r = ET.fromstring(sys.stdin.read()); f = sys.argv[1]
if f == "backing":
    p = r.find("backingStore/path"); print(p.text if p is not None and p.text else "")
elif f == "format":
    print(r.find("target/format").get("type"))
else:
    print(r.find("capacity").text)' "$2"
}
_rd_repoint() {  # $1 domain, $2 file: the persistent definition's vda now names $2 (the domain must be shut off)
    local xml rc; xml=$(mktemp)
    $V dumpxml --inactive "$1" > "$xml"
    python3 -I - "$2" "$xml" <<'PY'
import sys, xml.etree.ElementTree as ET
t = ET.parse(sys.argv[2]); n = 0
for d in t.getroot().iter('disk'):
    tg = d.find('target')
    if d.get('device') == 'disk' and tg is not None and tg.get('dev') == 'vda':
        d.find('source').set('file', sys.argv[1]); bs = d.find('backingStore')
        if bs is not None: d.remove(bs)
        n += 1
if n != 1: raise SystemExit('expected exactly one vda disk, found %d' % n)
t.write(sys.argv[2])
PY
    rc=$?; [ $rc -eq 0 ] && { $V define "$xml" >/dev/null; rc=$?; }
    rm -f "$xml"; [ $rc -eq 0 ] && [ "$(_rd_vda "$1" --inactive)" = "$2" ]
}
_rd_named_elsewhere() {  # $1 domain, $2 file -> success if any OTHER domain's definition names the file
    local d
    for d in $($V list --all --name); do
        [ "$d" = "$1" ] && continue
        { $V dumpxml "$d"; $V dumpxml --inactive "$d"; } 2>/dev/null | grep -qF "'$2'" && return 0
    done
    return 1
}
_rd_shutdown() {  # $1 domain, running on its base: shut Windows down from inside, so the base stays a clean shutdown
    local host; host=$(awk -v d="$1" '$1==d{print $2}' driver/scripts/debuggees.txt)
    [ -n "$host" ] && python3 driver/scripts/remote_ps.py "$host" <<<'Stop-Computer -Force' >/dev/null 2>&1
    for _ in $(seq 1 60); do [ "$($V domstate "$1")" = "shut off" ] && return 0; sleep 5; done
    $V shutdown "$1" >/dev/null 2>&1
    for _ in $(seq 1 60); do [ "$($V domstate "$1")" = "shut off" ] && return 0; sleep 5; done
    _rd_log "$1 did not shut down; refusing to power off a guest that runs on its base"; return 1
}

run_disk_begin() {  # $1 domain, $2 tag -> the domain is started on a fresh overlay of its base
    local dom=$1 tag=$2 state base dir pool fmt cap ov xml free min
    mkdir -p "$RUN_DISK_STATE"; state="$RUN_DISK_STATE/$dom"
    if [ -f "$state" ]; then
        _rd_log "$dom: run $(sed -n 's/^tag=//p' "$state") was never ended; discarding it first"
        run_disk_end "$dom" "$(sed -n 's/^tag=//p' "$state")" || return 1
    fi
    [ "$($V domstate "$dom")" = "shut off" ] || _rd_shutdown "$dom" || return 1
    base=$(_rd_vda "$dom" --inactive)
    case "$(basename "$base")" in *.safeupload-run-*|*.safeupload-pre-*)
        _rd_log "$dom: its disk $base is a run file with no run state; end that run by hand first"; return 1;; esac
    [ -e "$base" ] || { _rd_log "$dom: base $base does not exist"; return 1; }
    dir=${SAFEUPLOAD_RUN_DISK_DIR:-$(dirname "$base")}
    pool=$(image_pool_of "$dir") || { _rd_log "no libvirt pool for $dir"; return 1; }
    free=$(df --output=avail -BG "$dir" | tail -1 | tr -dc '0-9'); min=${SAFEUPLOAD_MIN_FREE_GB:-20}
    [ "${free:-0}" -ge "$min" ] || { _rd_log "$dir has ${free} GB free, need $min"; return 1; }
    fmt=$(_rd_vol "$base" format) && cap=$(_rd_vol "$base" capacity) || return 1
    ov="$dom.safeupload-run-$tag.qcow2"
    [ -e "$dir/$ov" ] && { _rd_log "$dir/$ov already exists"; return 1; }
    xml=$(mktemp)
    printf "<volume><name>%s</name><capacity unit='bytes'>%s</capacity><target><format type='qcow2'/></target><backingStore><path>%s</path><format type='%s'/></backingStore></volume>\n" \
        "$ov" "$cap" "$base" "$fmt" > "$xml"
    $V vol-create "$pool" "$xml" >/dev/null; local rc=$?; rm -f "$xml"; [ $rc -eq 0 ] || return 1
    printf 'base=%s\noverlay=%s\ntag=%s\nbasestat=%s\n' "$base" "$dir/$ov" "$tag" "$(stat -c '%Y %s' "$base")" > "$state"
    _rd_repoint "$dom" "$dir/$ov" || { _rd_log "$dom: could not point the domain at $dir/$ov"; return 1; }
    $V start "$dom" >/dev/null || return 1
    _rd_log "$dom: run $tag on $dir/$ov (base $base)"
}

run_disk_end() {  # $1 domain, $2 tag -> guest off, domain back on its base, every run file deleted
    local dom=$1 tag=$2 state base ov stat0 top cur n f p files=()
    state="$RUN_DISK_STATE/$dom"; [ -f "$state" ] || { _rd_log "$dom: no run state"; return 1; }
    base=$(sed -n 's/^base=//p' "$state"); ov=$(sed -n 's/^overlay=//p' "$state"); stat0=$(sed -n 's/^basestat=//p' "$state")
    [ "$(sed -n 's/^tag=//p' "$state")" = "$tag" ] || { _rd_log "$dom: the open run is $(sed -n 's/^tag=//p' "$state"), not $tag"; return 1; }
    local tops; tops=$(_rd_vda "$dom" ""; _rd_vda "$dom" --inactive)
    [ "$($V domstate "$dom")" = "shut off" ] || $V destroy "$dom" >/dev/null || return 1
    # Every file between each current top and the base belongs to this run: it must sit in the overlay's directory, carry this
    # domain's run-file name and be at most two levels above the base; anything else stops the cleanup with the files kept.
    for top in $tops; do
        cur=$top; n=0
        while [ "$cur" != "$base" ]; do
            n=$((n + 1)); [ $n -le 2 ] || { _rd_log "$dom: $top does not reach the base within two files; nothing deleted"; return 1; }
            case "$cur" in "$(dirname "$ov")/$dom".safeupload-run-*|"$(dirname "$ov")/$dom".safeupload-pre-*) ;;
                *) _rd_log "$dom: $cur above the base is not a run file of $dom; nothing deleted"; return 1;; esac
            [[ " ${files[*]} " == *" $cur "* ]] || files+=("$cur")
            cur=$(_rd_vol "$cur" backing) || return 1
            [ -n "$cur" ] || { _rd_log "$dom: the chain from $top ends before the base; nothing deleted"; return 1; }
        done
    done
    [[ " ${files[*]} " == *" $ov "* ]] || { [ -e "$ov" ] && [ "$(_rd_vol "$ov" backing)" = "$base" ] && files+=("$ov"); }
    _rd_repoint "$dom" "$base" || { _rd_log "$dom: could not point the domain back at $base; nothing deleted"; return 1; }
    for f in "${files[@]}"; do
        _rd_named_elsewhere "$dom" "$f" && { _rd_log "$dom: another domain names $f; nothing deleted"; return 1; }
    done
    for f in "${files[@]}"; do
        p=$(image_pool_of "$(dirname "$f")") && $V vol-delete --pool "$p" "$(basename "$f")" >/dev/null || { _rd_log "could not delete $f"; return 1; }
        _rd_log "$dom: deleted $f"
    done
    rm -f "$state"
    if [ "$(stat -c '%Y %s' "$base")" = "$stat0" ]; then echo "RunDiskBaseUntouched=True"; else echo "RunDiskBaseUntouched=False base $base changed during run $tag"; return 1; fi
    _rd_log "$dom: run $tag ended; the domain is shut off on $base"
}
