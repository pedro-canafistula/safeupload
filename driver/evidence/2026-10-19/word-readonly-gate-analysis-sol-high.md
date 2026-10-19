# Word SaveAs readonly: private reopen versus deferred rename/seal

2026-10-19; analyst **gpt-6.1-sol, high**. Read-only analysis/proposal, **not acceptance of its own fix**.
Analyzed checkout `2bc3da862d6029f88229fec69935170e80356d84`; `StageStream.c` has no delta from deployed
`f8e99d25`. No code, build, test or VM action performed by this analyst. Preserve the current T4 priority;
this note does not authorize another kernel deployment or replace coherent review.

## Diagnosis supported by evidence

[Retained diagnostics](m2dev1019a-word-failure-diagnostics.txt) show same-Word PID 6448 CREATE failures on the
saved `.docx`: READ_ATTRIBUTES `0x80` and read `0x120089`, STATUS_SHARING_VIOLATION, reason 17, aux `0x406`.
`SafeUpload.Minifilter/StageStream.c:2966` encodes gate plus ReadOnly `0x100`, Sealed `0x200`, RenameExchange
`0x400`, and FileObjects in the upper 16 bits. Thus these failures mean **gate 6, pending RenameExchange,
ReadOnly=false, Sealed=false, FileObjects=0**. They do not mean NTFS readonly attributes or an active app
handle caused a native sharing refusal. The eventual public file has attribute 32, exact clean text and
SHA256 `61437258B964525CF3947B5E4C8F03CE47F8F949B855E39995A38142C131EFE3`.
Word's Saved=True/ReadOnly=True is consistent with its immediate reopen/probe failures; the ring alone does
not prove which particular Office probe determines its internal ReadOnly property. Later owner-file
`~$...` gate-3 failures are a separate allocation/receipt issue, not evidence that gate 6 is fixed.

The race is concrete:

1. `StageRename` prepares the exact service transaction, retargets the owner's private view locally,
   changes the retained operation to COMMIT and returns success before COMMIT acknowledgement
   (`StageStream.c:5624`, `:5690–5713`). The retained exchange intentionally freezes the namespace.
2. Word closes the save handle and immediately opens the destination. `StageAdmit`'s existing
   `StageWaitHandleReceiptSettled(..., TRUE)` path (`:9408–9433`) pins the exact stream but its busy
   predicate (`:5276–5282`) covers op19 receipts and **ReadOnly && !Sealed**, not RenameExchange or the
   closed-but-not-yet-ReadOnly phase. `StageSettleCurrent` only queues pending rename work (`:6416`).
   `StageCreate` therefore reaches gate 6 (`:2616–2625`) and refuses the read.
3. Some READ_ATTRIBUTES probes use CREATE options `0x01200000`: FILE_OPEN plus FILE_OPEN_REPARSE_POINT.
   `StageMvpNamespaceCreateEligible` excludes that flag (`:9066–9083`), so those probes do not even enter
   the existing wait. Extending only its busy predicate misses this observed access form.

This is a deferred transaction/liveness issue. The candidate-lifetime retirement repair does not remove
this private namespace gate, and eventual successful publication does not repair Word's earlier decision.

## Smallest candidate fix: wait only for work independent of the blocked caller

Retain gate 6 and the original reader access/share checks. Add a narrowly scoped **owner-reopen settlement**
path in admission, reusing the existing pin/wait/readmit structure; do not bypass directly to public or
private backing bytes. Use a dedicated read predicate rather than changing the general native-routing
eligibility predicate:

- Exact referenced owner EPROCESS, same instance/name/private-view generation and current stream; ordinary
  local fixed NTFS, IRP CREATE at PASSIVE_LEVEL, no transaction and no top-level IRP. FILE_OPEN, default
  stream only; read/query/synchronize grants only. No write/append/EA/attributes/security/delete grant,
  delete-on-close, destructive disposition, by-ID reinterpretation or arbitrary reparse traversal.
  A pure FILE_OPEN_REPARSE_POINT probe can wait for this already-resolved non-reparse private object;
  that flag does not authorize following a real reparse point or bypassing existing admission checks.
- Under NamespaceResource capture the exact stream/view/transfer/stage ID and boot/driver identity;
  take one RpcReferences pin and queue the stream. For the **closing** case establish existing cleanup
  evidence and zero app shares/FileObjects; no private delete/cancellation or unresolved attachment.
  Already-ReadOnly sealing may use the existing wait. If an active app handle or user mapping is the
  missing owner, do not start a new wait for that app-dependent lifetime. Leave its native sharing/
  existing routing behavior intact. This wait must not create an upper FILE_OBJECT or cache/section
  merely to keep the version alive.
- Wait outside NamespaceResource, stream resource and spin locks, on the existing bounded monotonic
  budget. The terminal predicate is exact settlement, not elapsed time: finish **rename -> op19 ->
  local drain/read-only backing reopen -> seal ACK**, or detect that the original private mapping is
  no longer current and readmit. Include the closed-but-not-yet-ReadOnly phase; otherwise a reader can
  enter immediately after rename ACK and itself prevent StageDrain until Word closes it. A bound hit,
  service refusal/disconnect, cancellation, teardown, changed tuple or unknown result never means ready.
- Never wait for inspection, publication, disposition acknowledgement or global callback quiescence.
  This CREATE owns an admission epoch; publication can require that epoch to end. The wait's version
  pin may also defer retirement. Waiting for public visibility would introduce an unnecessary cycle.
- After every wake/check, revalidate the exact snapshot under NamespaceResource. A rename COMMIT may
  legitimately update DestinationGeneration: accept that only through the existing typed ACK/apply
  path, not by silently adopting a different stream. A successor, retarget, detach or cancellation
  returns to full admission against current state. Drop the exact pin and queue under the same
  lifetime discipline as `:9415–9427`; reset transient view pointers. Keep one deadline across readmits
  so eight readmit attempts cannot multiply the wait. Honor request cancellation/mandatory teardown.
- Let existing `StageCreate` re-run security, native-style IoCheckShareAccess, attachment gates and
  sealed backing DeletePending validation (`:2583`, `:2627–2655`, `:2876`). A new writer uses the ordinary
  generation path; this read settlement must not turn a writer into a reader or grant access.

An event can replace the helper's 10-ms polling later, but is not necessary to establish this narrow
candidate. Queue/coalesce work and preserve exact RPC retry rules; do not reissue COMMIT from CREATE or
clear RenameExchange/ReadOnly/Sealed to make the probe pass. A failed bounded wait remains a diagnosed
retryable conflict; it cannot guarantee Word's UX during a real unavailable service.

## Why that bounded wait has an independent progress path

`StageProcessStream` handles rename **before** op19 and sealing (`StageStream.c:6576`).
`StageCollectRenameRpcs` pins/snapshots the exchange (`:6673`); `StagePerformRenameRpcs` sends outside
NamespaceResource and applies only the exact reply (`:7149`). `StageApplyRenameReply` adopts the typed
committed generation, clears the exchange and queues work (`:5093–5163`). Op19 collection explicitly
waits for rename to finish (`:6907–6923`), and its successful reply queues the next worker pass (`:6951`).
The worker then drains/seals (`:6368`, `:6230`); the RpcReferences pin prevents release (`:6535`) but is
not an app FileObjects/share owner in StageDrain. Sealing also sends outside resources (`:7107`).

Agent `MinifilterInterceptor.cs:684–742` and `StagedTransferJournal.cs:2565–2671` complete the prepared
rename from exact durable state/epoch and do not need Word to close a newly created reader.
The seal handler (`MinifilterInterceptor.cs:1261–1304`) acknowledges the ordinary stable seal rather than
waiting for content inspection/publication. Consequently, for the observed zero-FileObjects closed tuple,
rename/receipt/seal can settle while Word's CREATE is blocked, without exposing bytes to another process.
This is a source-level dependency argument, not measured timing or proof every failure settles within 10 s.

The helper must not silently generalize to arbitrary active writers, mappings or native/publication waits.
A mapped old version can require a genuine application unmap; a receipt counter or timeout cannot replace
that lifetime. All delayed/paging I/O still drains through the existing rundown before backing close.

## Why a new direct sealed-owner read path is larger and unnecessary here

This failure occurs **before Sealed**, and existing code already serves authorized owner reads from a
sealed read-only backing (`StageStream.c:2627`, `:6251`, `StageReadWrite :4765`). Allowing direct reads while
RenameExchange is unresolved would have to define which name/generation is authoritative and ensure a
new handle cannot keep the unsealed version alive forever. It would not be a sealed-read fix.

If a future implementation adds a specialized immutable read handle, it must still bind the exact
referenced owner and current effective CREATE subject, requested READ_DATA/READ_ATTRIBUTES grants,
original logical security/share result, exact stage ID/generation and transfer lineage. No raw service
handle/path is exported. Mutation stays denied, paging/read/cache and cleanup lifetimes own explicit
references, deletion/retirement is synchronized, and view replacement cannot redirect the handle.
An owning PID, the stage's service READ grant, a content hash or same-SID process is insufficient.
Seeded bytes additionally require the approved source read/export provenance; a write-only editor cannot
obtain prior unreadable bytes through a convenience reopen. The owner's option-1 decision preserves
write-only editing while keeping blocked unreadable seeded versions private; it grants no blanket read.
The bounded wait grants nothing new and should preserve those existing gates.

## Review and focused evidence needed for a later coherent patch

Before another kernel update, independently review the wait predicate, exact pin balance and lock/lifetime
interaction together with any other coherent kernel delta. Focused controls should cover delayed COMMIT
ACK, op19, pre-ReadOnly drain and seal ACK; same-owner read/metadata/reparse-open probes; concurrent reader
arrivals and successor/retarget/delete races; native sharing refusal; service loss/cancel/teardown; blocked
content and write-only seeded data; and a mapped/active writer whose cleanup must never be required to
unblock the current CREATE. Require unchanged foreign-process private-byte refusal and no new cap/leak.
Then repeat the actual Word SaveAs/edit/save/reopen workflow as standard user and record Saved/ReadOnly,
exact independent bytes and owner-file behavior separately. This note performs none of those runs and
claims no T4/M2 qualification result.
