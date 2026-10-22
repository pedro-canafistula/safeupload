# T5 D7 revision 5 re-review (registry post last) — Sol 6.1 high (gpt-6.1-sol, reasoning_effort=high, no fast tier), read-only, 2026-10-22

Resumed session, reviewed commit `3a16ec0f`. Brief: `~/Work/safeupload-tools/workers/t5-d7-rev5-rereview-brief.md`; raw log `t5-d7-rev5-rereview.log` (EXIT=0). Verbatim result:

**ACCEPT WITH CONDITIONS — no remaining source blocker to the first boot after the required build/import gates. Windows qualification remains outstanding.**

1. **[Closed] Finding 1: registry post is last on all three routes.**  
   [StageStream.c:10494](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10494), [StageStream.c:10771](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10771).

   D7 validation refusal, D7/D1 legacy denial, and DOC identity or pending-version cancellation failure all establish the final failure status before registry consumption. Legacy denial prevents DOC’s subsequent cancellation block from running, preserving single cancellation. The unchanged registry failure branch releases without inserting a node ([StageWriters.c:2933](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:2933)).

   D7/D1 draining bypasses legacy and consumes the reservation. DOC draining calls legacy, whose production implementation immediately returns, then consumes the reservation through registry draining. NULL remains guarded, owner fields are cleared before consumption, and each completion has one consumption point. I found no reservation leak or double consume.

2. **[Condition: Windows evidence] Finding 2 is closed as a preboot blocker for this corrected delta.**  
   [design:524](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T5-UX-NAMESPACE-GAP.md:524), [StageStream.c:10437](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10437).

   I no longer require a host fixture compiling the production registry success/cleanup bodies before first boot. The decisive change is removal of registration followed by this filter’s cancellation—not the size of the registry’s dependency closure. The remaining integration passes the final status to unchanged registry code and uses its existing cleanup path.

   Host contract controls plus the stated Windows capture are sufficient to proceed. **Qualification still requires complete zero Unknown masks/origins through `T5WriterRegistryKnown` and a subsequent approved publication succeeding.** Those observations must not be described as exhaustive proof of registry accounting.

   A smaller production fixture covering failure/reparse, draining and actual `CancelReservation` accounting would be meaningful optional coverage: assert consume-once, released reservations/resources, no node insertion, and teardown Unknown only where required. It would not establish successful insertion, `H` balancing or exact-object cleanup.

3. **[Informational] No new ordering, context or locking defect found.**  
   [StageStream.c:10774](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10774), [Context.c:638](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Context.c:638), [StageWriters.c:2732](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:2732).

   Legacy-first context creation uses the same initialized, leased, `KEEP_IF_EXISTS` context helper that registry binding subsequently uses. Legacy releases its context lease before registry processing.

   The reservation remains outstanding through DOC’s V28 cancellation RPC; no registry lock spans that RPC. RPC failure reaches the final-status release branch. Registry completion still finishes before fence/epoch release ([StageStream.c:11502](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:11502)). DOC draining introduces no legacy inspection or cancellation work because legacy returns immediately on draining.

Verification at `3a16ec0f`: native controls passed with both compilers; all **53 mutations** were rejected. The seven-test suite retained only the disclosed clang `rechecks` warning failure. No repository edits, product builds or remote actions were performed.