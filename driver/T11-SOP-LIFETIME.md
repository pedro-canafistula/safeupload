# T11 SOP startup proof and incarnation retirement

2026-10-16, `ux/t11`, base `2ed2b20b`. Unbound UX line; pre-boot review input,
not Windows qualification. The evening owner direction is recorded in the main
checkout's status plan: real standard-user workflows first; parked bound census
and V30 hardening are not prerequisites for this unbound increment.

## Startup proof

The old simultaneous-open check ran after FILE_DELETE_ON_CLOSE (or the test hold's
explicit delete disposition). A delete-pending name is not a valid reopen probe.
The startup canary now creates a unique SYSTEM-only ordinary file, verifies the
applied descriptor first, sets one-page EOF, and captures full volume/file ID.
`StageCanaryCheckSopLifetime` then:

1. Opens a second handle while the first exact object lives; nonnull SOPs agree.
2. Creates a writable section, closes the original handle (CLEANUP), releases the
   driver's FILE_OBJECT reference, and retains only the section handle. It never
   dereferences the recorded SOP token during that interval.
3. Reopens by name with no-follow, requires exact full volume/file ID and the same
   nonnull SOP, and transfers the verified handle/object back to the caller before
   closing the section. A different object is closed without deletion or mutation.
4. Runs the existing optional DACL hold, explicitly marks deletion, and executes
   the unchanged retained-writable-section YES / released-NO checks. Trust requires
   all existing checks, exact success, deletion confirmation and the deadline.

The canary uses existing DDIs, no new pool/storage allocation, two file opens and
one section at peak. All new/moved helpers declare and repeat PASSIVE SAL, PAGE
placement and PAGED_CODE. No lock, admission resource or spin lock spans file I/O,
section creation, close or wait. Instance/volume pins belong to the joined startup
worker. Failures attempt cleanup of all locally owned handles/references; before ownership is
consumed the caller keeps the original cleanup object. A failed reopen after the
original close can leave one uniquely named SYSTEM-only canary file (one page);
it fails trust and requires administrator diagnosis. No substituted object is
removed to conceal that failure. This is a platform canary, not a universal proof
for every filesystem, Windows build, view/MDL schedule or context implementation.

## Registry lifetime and changed SOP

An entry's SOP and `SopLifetime` are immutable incarnation tokens. The witness has
no object/context back-reference and cannot extend NTFS lifetime. Its context and
each bound entry own references. Natural stream-context cleanup alone publishes
Ended; mandatory teardown, lost writers, context removal or invalid bookkeeping
invalidate the witness. Unknown remains sticky until reboot.

A reopen with a changed SOP, missing context or wrong witness never samples the
new stream's MM predicates for the old entry. `StageRegistryOpenIdentity` refuses
it; activation defers without promoting or inventing Unknown. The old entry
retires through the existing reclaim worker only after its original Ended receipt
and all H/W/T, reservations, transactions, section callbacks, spill counts, rename,
owner and Unknown checks resolve under RegistryLock -> SectionLock. The worker
can retire ended Activating/alias-pending entries without opening a replacement.
Natural cleanup queues the worker; retirement wakes a waiting sibling. A recycled
SOP address cannot override a different live witness. This deliberately preserves
the existing retirement implementation instead of treating changed address as
new lifetime evidence. Tests execute the actual retirement predicate and prune
body, including refusal with each unresolved obligation and exact map/history/pin
release; existing bind/detach controls continue unchanged.

The live-incarnation alternative remains original context + exact owned object +
MmCanFileBeTruncated and sequence recheck. All unlink/counter/witness operations
are resident. References/pins are released outside locks. There is no forced
context deletion, timer-based expiry, new scan or new retirement authority.

## Local and Windows controls

Run `TMPDIR="$PWD/.scratch/tmp" python3 driver/scripts/t11/sop-lifetime-selfcheck.py`
and all existing writer/UX/T5 shims. Host DDIs enforce ownership/order only; they
do not establish Filter Manager cleanup, IRQL or MM lifetime behavior.

Before qualification boot: independent Sol 6.1 xhigh coherent review; feature
Debug/Release WDK + PREfast + ApiValidator 0/0 and both binary import gates.
The exact standard-user/native rows are T11-S01–S04 in
[M2-REVIEW-CONDITIONS.md](M2-REVIEW-CONDITIONS.md). Run ordinary, runtime-Verifier
and boot-Verifier with matched artifacts and separate restoration. Section-only,
view-only, same-address reuse, delayed context cleanup and failure cleanup remain
native qualification conditions. No staging activation/cutover is authorized here.

## API evidence and limits

[Microsoft SECTION_OBJECT_POINTERS](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_section_object_pointers)
defines one SOP per stream shared by its file objects; its members stay opaque.
[FltClose](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltclose)
returns NTSTATUS and requires PASSIVE. Both proof closes require exact SUCCESS;
a failed close cannot establish a section-only interval. A repeated cleanup-close
failure fails trust and remains a kernel-resource diagnostic; the canary never
converts it to lifetime evidence. The canary does not test an independent mapped
view after closing the section handle; that remains T11-S04 native coverage.
[Context deletion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/deleting-contexts)
can also occur on detach/unload or explicit deletion. The Ended proof therefore
excludes those invalidation paths rather than treating every cleanup callback as
natural stream death. These API contracts support the design; the scheduled
native rows must establish actual target behavior.
