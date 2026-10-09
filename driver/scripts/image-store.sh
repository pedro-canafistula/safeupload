# Sourced by the harness scripts (needs $V = "virsh -c qemu:///system").
# VM overlays are created next to the domain's current disk, so a VM whose disk lives on the Storage disk keeps every checkpoint and
# recovery overlay there. The project must not fill the main disk: a directory on the same filesystem as / is refused unless
# SAFEUPLOAD_ALLOW_MAIN_DISK=1 is set deliberately.
image_dir_of_domain() {  # $1 domain -> directory of its current top disk
    dirname "$($V dumpxml "$1" | grep -o "source file='[^']*'" | head -1 | cut -d"'" -f2)"
}
image_pool_of() {  # $1 directory -> libvirt pool whose target path it is
    local p
    for p in $($V pool-list --name); do
        [ "$($V pool-dumpxml "$p" | sed -n 's:.*<path>\(.*\)</path>.*:\1:p' | head -1)" = "$1" ] && { echo "$p"; return 0; }
    done
    return 1
}
image_dir_check() {  # $1 directory
    [ "${SAFEUPLOAD_ALLOW_MAIN_DISK:-0}" = 1 ] && return 0
    if [ "$(stat -f -c %i "$1")" = "$(stat -f -c %i /)" ]; then
        echo "REFUSED: $1 is on the main disk. Move the VM disk to the Storage disk (flatten onto /mnt/storage/libvirt/images) or set SAFEUPLOAD_ALLOW_MAIN_DISK=1." >&2
        return 1
    fi
}
