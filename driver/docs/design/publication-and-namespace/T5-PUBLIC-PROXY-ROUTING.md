# T5 public proxy routing and local lifetime

Date: 2026-10-11. Proposed implementation detail for [T5-DELETES.md](T5-DELETES.md) section 4.1.
Review base: `1e04bfec`; checked-backend implementation: `4e070ab2`. **NOT READY; do not implement this routing.**
The [independent Luna review](../../../evidence/2026-10-11/t5-public-proxy-routing-design-review-luna6.md) rejects the synthetic FCB/native
section-pointer pairing and identifies positioning and elevated-IRQL release gaps. This proposal is superseded by the still-unapproved
[native app-object correction](T5-NATIVE-PUBLIC-OPENS.md) and its focused review findings; retain this file as the rejected proposal.
This does not change empty-file publication, delete authority, generation ordering, cancellation/failure policy or supported destinations.

## Purpose

A DELETE-capable open of an existing public file must not create a private copy merely to run DeleteFileW. Its non-writing proxy must
also support legitimate reads, query classes, positioning, byte-range locks and read mappings. The existing private path caps reads at
16 MiB, uses private byte locks and rewrites identity. Reusing it unchanged would violate section 4.1.

The public proxy uses an owned app-facing FILE_OBJECT/FCB, distinct from the checked native backend FILE_OBJECT. A combined content-write
and DELETE open continues using a private stage for data; its checked public capability is separate. Private backing identity or ACLs are
never returned through the public proxy. A CREATE which can create/truncate content is not a non-writing public open.

## Native routing on the original volume

For the public proxy only, keep the original IRP and change only `Iopb->TargetFileObject` to the checked native backend, followed by
FltSetCallbackDataDirty and a post callback. Do not change TargetInstance, MajorFunction, Thread, RequestorMode, buffers, MDLs, the
original cancellation path or transfer the operation onto a worker thread. Prove the backend belongs to the proxy's exact original
instance/volume; reject a mismatch before forwarding. No cross-volume retarget is allowed. The private C:-backing path retains its
existing separately allocated paging requests and T11 stack-size protections.

This follows Microsoft's [FLT_IO_PARAMETER_BLOCK contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_io_parameter_block):
TargetFileObject may be changed only to a file on the TargetInstance's volume. Lower filters see the changed target; this filter's post
callback and upper filters retain their original input parameters. No manual post-operation target restoration or Thread mutation is used.

The routing whitelist is explicit:

| Operation | Route / handling |
|---|---|
| READ, including paging reads | Native public backend; respect original access, native locks, EOF and noncached alignment. No private 16 MiB bound. |
| QUERY_INFORMATION, QUERY_SECURITY, QUERY_EA, QUERY_VOLUME_INFORMATION | Native public backend. Real public size, identity, name, streams and volume. |
| LOCK_CONTROL | Original IRP to the native backend, preserving requestor and cancellation; real locks must conflict with ordinary native readers. |
| FLUSH_BUFFERS | Native read backend; never flush a private version into public content. |
| FilePositionInformation | Maintain the app-facing FILE_OBJECT position. Resolve implicit read offsets from it; return it in Position/All queries. |
| SET_SECURITY | Only the existing T10 public permission surface under the original native grant. Never redirect to a private stage ACL. |
| Disposition / on-close intent | Existing T5 durable transaction and one-use permit; never pass the outer request directly to NTFS. |
| Data write, resize/allocation, rename, EA/attribute write, reparse/FSCTL and unknown mutation | Never use this forwarding whitelist. Content writers use private stages; other mutations use their existing explicitly supported paths or refusal. |
| Fast I/O / QUERY_OPEN | Existing fallback to IRP, with no foreign decoding of the owned FCB. |

The proxy classification must exclude content/EA/attribute writers and mutating create dispositions, and must consider the actual grant
for MAXIMUM_ALLOWED/generic requests. It cannot grant a writing app handle to a public proxy. WRITE_DAC/WRITE_OWNER are not content-write
authority (T10); unsupported combinations on a private data handle are not made publishable by this routing.

## Read sections and filesystem restrictions

Non-writing proxies must preserve native public cache/section identity so a read/image mapping participates in NTFS's own delete checks.
Proposed mechanism: the non-writing app FILE_OBJECT uses the native backend's SectionObjectPointer, with an owned FCB for upper-object
lifetime; section/CC-flush acquire/release callbacks route to the exact native backend on the same volume. No private stream uses that
native SectionObjectPointer. No writable file section or paging write can pass the public branch, even if originated by a kernel callback.
Copy-on-write section behavior must be reviewed explicitly; it cannot create file-backed public writes.

The implementation must prove that sharing the native SectionObjectPointer with this owned FCB is valid for MM/CC and that no native
callback decodes the owned FCB. If this is not a supported pairing, the reviewer must reject it and identify a supported mechanism; do not
silently disable legitimate read/image mappings or bypass their native delete restrictions to make the DeleteFileW-only control pass.

## Backend cleanup is separate from object retirement

Split last app-handle cleanup from final backend destruction. Last proxy cleanup removes the driver's native handle hold, outside namespace,
stream and spin locks, without waiting on the service. Keep the checked native FILE_OBJECT, identities and required local references for
still-live read sections, paging requests, post callbacks and exact reconciliation. Closing the native handle cannot invalidate a paging
request which was already accepted or prematurely release the owned FCB. Ordinary new operations are closed after app cleanup.

For combined private-write opens, the public native handle is also released at last app cleanup, while private paging/sections retain their
existing independent drain. A retained reconciliation record holds identity and durable intent; it must not keep a native handle which
prevents physical deletion. Final backend destruction occurs only after its local operations and exact required acknowledgements drain.

Each routed operation pins the native backend and the original app FILE_OBJECT before changing the target. Its post callback releases
exactly once on both normal and draining paths. Nonpaged post-release bookkeeping is safe at DISPATCH_LEVEL and drops operation holds
before the app FILE_OBJECT hold; final object destruction remains on a PASSIVE_LEVEL worker. No source pointer is looked up after its last
reference is dropped. No service wait, timeout-based release or orphan reaper is added.

The proxy's NativeSectionObjectPointer can be shared by unrelated legitimate native public readers. A retirement check cannot mistake
their sections for private-stage ownership or retain a private stage slot forever. The local lifetime proof must distinguish references
which can still use this app proxy from unrelated native references, and keep all actual proxy users safe through mandatory teardown.
Voluntary unload vetoes outstanding proxy/native operation/cleanup work; mandatory teardown only drains actual local references.

## Required verification

- Kernel lifetime/lock-order/retirement review before the first revised VM boot, including the concrete implementation.
- Four WDK configurations at 0 warnings/0 errors with PREfast/ApiValidator, plus the agent matrix after service changes.
- Non-writing DELETE+READ proxy: real public bytes/length/ID/name/streams/security/volume, reads beyond 16 MiB, implicit positioning and All.
- Byte locks in both directions with an ordinary native reader, duplicate-handle owner changes, waiting-lock cancellation, and no stuck operation.
- Read and image mappings held after app handle cleanup, native delete/mapping restrictions, and rejection of writable sections/paging writes.
- Existing private mapping/byte-observer assertions unchanged, plus all required T5 native-order and real Notepad rows under Verifier.
- Separate VM restoration on every run under the owner-approved disk/XML/EFI/no-TPM rule.
