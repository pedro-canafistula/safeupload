# Sourced by the harness scripts (needs $V = "virsh -c qemu:///system").
# VM overlays are created next to the domain's current disk (see run-disk.sh: each run's overlay is deleted when the run ends).
# The main disk may hold them (the owner allows it when it is faster) but nothing may pile up: a directory whose filesystem has
# less than SAFEUPLOAD_MIN_FREE_GB (default 20) free is refused.
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
    local free min=${SAFEUPLOAD_MIN_FREE_GB:-20}
    free=$(df --output=avail -BG "$1" | tail -1 | tr -dc '0-9')
    [ "${free:-0}" -ge "$min" ] || { echo "REFUSED: $1 has ${free} GB free, need $min (delete finished run files first)" >&2; return 1; }
}
