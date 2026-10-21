# Published-file read-write admission

2026-10-16, `ux/activating`, base `59c7e319`. Implementation task for the
unbound MVP profile. No activation/cutover of V30 is implied.

The evening owner direction (M2 user experience first) is in the main
worktree's [status plan](/home/victor/Work/safeupload-staging/driver/POST-MVP-PLAN.md#owner-decisions);
this checkout's status plan predates that paragraph. The original boot-start
writer-state design is retained there as
`driver/evidence/2026-10-03/writer-state-design-v2.txt`. Both were read without
changing the main worktree.

## Cause and design delta

Publication renames a service-written physical file into protection. Rename
completion starts an alias probe, which classifies the stream in scope and
sets Activating. A subsequent content-writing FILE_OPEN reaches
`StageAdmit`'s activating-name gate before private allocation. Truncating
reopens through an existing requester-private view can bypass that name gate;
their success does not prove public FILE_OPEN admission works.

The activation worker requires null DataSectionObject/SharedCacheMap after a
flush-and-purge, in addition to writer-free checks. Those pointers describe
cache presence, including cache populated by allowed reads; retained cache
alone does not establish a writer or lost lifetime tracking. Promotion parks
when either pointer survives. The name gate never requests another observation,
and the last mapped-writer release need not produce a callback to wake the
worker. Idle time and repeated pure name lookups cannot repair that hold.
These are source-proven liveness defects consistent with the reported
activatingName/WriterPromotionPending; the reported run has no captured
classification-step receipt proving which individual condition held.

Promotion must instead use the exact original live SOP/context witness, the
existing writer/operation/section/transaction/rename/spill checks, S=NO and a
successful synchronous ordinary filesystem flush below the instance. Recheck the
original SOP/context and writer state after that I/O, then retain all current
policy, rename-loss, sibling, marker-generation and final CAS checks. Retained
cache pointers may remain. Both existing `MmCanFileBeTruncated(SOP, NULL)`
checks remain: they guard outstanding data-section write probes, including a
prepared MDL whose prepare IRP's W has already ended. Checking before the flush
prevents a probe completing/dirtying just after that flush from supplying a
false drained-cache proof. This also conservatively holds read-only mapped
views/image sections; this patch does not claim to distinguish those from
outstanding probes. Retirement is unchanged; no old incarnation or Unknown is
discarded to make admission succeed.

Diagnostic basis must distinguish a successful flush from an actually empty
SOP; do not assert the old empty/purge facts when they were not observed.
Existing harness assertions remain unchanged and must not be counted as
passing a different receipt schema.

## Lifetime and waiting

The worker continues to own its entry, instance, volume, exact by-ID file object
and original context references through the flush and final rechecks. No lock
is held over filesystem I/O. It adds no file-object owner, allocation, periodic
timer or background rescan. Sticky Unknown and missing/invalid natural lifetime
witnesses remain fail closed. Timeout never supplies authority.

A public write-open can request one fresh pass and wait at most two seconds
(monotonic interrupt time, ten-millisecond sleeps, at most four waiters), outside
all filter locks and only at PASSIVE with no top-level IRP. Known live H/W/C/T,
spill/rename state, missing/invalid witnesses, Unknown, global owner pins,
teardown, policy transition and the reclaim thread skip this wait. The caller
always rechecks the current name gate afterward; a timeout or a retired old
entry never directly grants anything. Polls do not requeue the worker.

## Staging and authority

Removing an obsolete Activating hold does not forward a writable public open.
`StageAdmit` still queues `StageAttachQueueCreate`, and `StageCreate` still
captures caller security and creates an owned private stream. The existing
unbound allocator seeds FILE_OPEN/FILE_OPEN_IF with current bytes, within its
16 MiB bound, before returning the private backing. Inspection/seal/publication
are unchanged. The owner's same-user readable seed direction applies here;
this does not enable bound coherent-seed or unreadable-seed export gates.

## Required Windows acceptance

Use matched committed packages, hashes and the unbound profile as standard
user **t5actor** on **win10-debug3 / 19045.2965**. Before qualification: independent
Sol 6.1 xhigh review, feature Debug/Release WDK/PREfast/ApiValidator at 0/0,
both binary import gates. Repeat ordinary/runtime-Verifier/boot-Verifier;
independent destination/raw byte observation and separate restoration remain
required. This local task does not run those gates.

1. Publish clean text and DOCX, close publisher/app handles, then native
   FILE_OPEN with access `0x12019F`, options `0x1400060`, at 4 s and 60 s.
   Repeat after several minutes, from a fresh process with no private view.
   Require RW success, exact original private seed and unchanged public bytes
   while editing; clean bytes publish only after inspection.
2. Repeat with a second buffered read-only reader and cached reads between
   publication and open. Cache presence alone must not hold Activating. A live
   read-only mapped view/image section conservatively stays held by the retained
   MM guard; release it, then require the next open to request a pass and progress.
   Capture H/W/C/T/S, global owners, global/instance Unknown, witness,
   classification step and promotion trace. Compare sharing and NTFS denied-write results with native
   controls; denied callers must remain denied.
3. Open published DOCX in Word: title is not Read-Only, edit + Save, close and
   reopen to verify the edit. Repeat fresh/60-s/minutes-idle documents and
   Word's backup/temp rename sequence.
4. Add the policy's known CPF, Save, and verify blocked notification/hand-back
   and unchanged prior public bytes. Observe all temporary/backup public names
   throughout: no uninspected nonempty bytes. Repeat clean save afterward.
5. Keep a pre-scope writer, writable mapping (including section/view after
   handle cleanup), mutating IRP or TxF writer live. Refuse until its actual
   lifetime evidence resolves. Exercise failed flush, invalid/missing witness,
   outstanding prepared MDL, sticky Unknown, policy/rename race and service disconnect; none may grant
   a writable public handle or clear Unknown. Rerun writer and T4/T5 rows,
   including held-incarnation proofs, without relaxing existing assertions.

## API audit and residual conditions

The [MM truncation contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-mmcanfilebetruncated)
distinguishes outstanding write probes from mere cache-pointer presence, but
also rejects mapped views, data-section references and image sections. The
[MDL preparation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccpreparemdlwrite)
and [completion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccmdlwritecomplete)
contracts explain why W through an individual IRP cannot replace that guard.
The [filesystem flush](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltflushbuffers2)
is synchronous and sent below the instance. It is called at PASSIVE, outside
all locks, using the pinned exact file object; only STATUS_SUCCESS is accepted.
No new DDI identifier, allocation, owner or wire-layout change is introduced.

The cache defect is not proof of the sole blocker in the reported run. Global
writer-owner pins, policy-generation mismatch, instance/global Unknown and
same-ID sibling history can still legitimately hold admission; capture them
with the VM rows. A busy work queue can exhaust the bounded wait and require
a later application retry. An individual synchronous filesystem flush has the
filesystem's own I/O latency, independent of the caller's wait deadline.

## Local verification

The production activation, final promotion predicate, original-context check,
name lookup and bounded admission wait compile under GCC and Clang with
warnings as errors and UBSan. Controls separate retained cache from live
mapped views/write probes, cover failed/pending flushes, stale identity/context,
policy/marker movement, live/lost lifetime blockers, waiter saturation and
deadline oversleep. The original base worker compiles and fails the retained
cache control; seven compiled semantic mutations also fail. No pre-existing
test, assertion or gate was changed.

All 14 T5 Python controls, three existing kernel fixtures, both UX controls,
T4 verdict, matrix/import controls and writer controls completed successfully.
The two writer controls initially failed because historical evidence was absent
from this checkout; the unchanged scripts pass in a scratch copy with the real
retained fixtures (including the exact pinned disposition hash). Both failed
receipts remain retained. Feature Debug/Release local offline builds of Service,
App and Tests pass; these are compile diagnostics, not Windows matrix legs.

The full borrowed kernel API audit has the same pre-existing missing
`InsertHeadList` header exception at `Taint.c:356` on the base and changed source.
The separate delta audit passes with zero new external DDI identifiers and all
99 audited host stub declarations supported. The missing exception was not
suppressed. This is not a new binary import, WDK, PREfast or ApiValidator pass.

A Sol 6.1 xhigh sub-agent gave advisory ACCEPT after identifying and correcting
the MDL/write-probe issue. Under the status plan's review provenance rule this
worker-launched review is advisory, not the fresh orchestrator-launched
qualifying review. No VM, remote builder or Windows gate ran. Raw receipts are
under `.scratch/verification`; generated failed fixtures remain under
`.scratch/activating-*`. The [delivery receipt](../../../evidence/2026-10-16/ux-activating/result.txt)
records source hashes and remaining Windows obligations.
