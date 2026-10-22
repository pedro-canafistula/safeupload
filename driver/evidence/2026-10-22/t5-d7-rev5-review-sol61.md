# T5 D7 revision 5 review — Sol 6.1 high (gpt-6.1-sol, reasoning_effort=high, no fast tier), read-only, 2026-10-22

Reviewed design revision 5 + implementation at commit `b3c87c70`. Brief: `~/Work/safeupload-tools/workers/t5-d7-rev5-review-brief.md`; raw log `t5-d7-rev5-review.log` (EXIT=0). Verbatim result:

**REVISE — revision 5 closes the unload and nullable-ownership issues, but cancellation retirement and production-registry controls remain required before boot.**

1. **[High / blocking] Registration before a later cancellation lacks exact-node retirement.**  
   [StageStream.c:10513](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10513), [StageStream.c:10770](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10770), [design:495](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T5-UX-NAMESPACE-GAP.md:495).

   Registry post can insert the writer node and transfer its entry reference before legacy denial or DOC identity/cancellation failure calls `FltCancelFileOpen`. Normal removal depends on the exact-object cleanup path ([StageWriters.c:3130](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:3130)). Without that cleanup, `H` and opener/reference accounting remain outstanding; eventual context destruction marks the lost writer Unknown ([StageWriters.c:3190](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:3190)). Publication can remain held meanwhile.

   `FltCancelFileOpen` sends cancellation cleanup/close **below the supplied instance**; its caller must not expect its own ordinary cleanup callback. I did not fetch Microsoft documentation during this offline review, and the repository contains no local implementation establishing contrary delivery.

   Generic parity is insufficient justification. My revision 4 registry-first requirement was incomplete here. Before boot, either consume the reservation after every potentially denying native-route step, using the final status, or provide exact-node cancellation retirement with balanced writer/opener/reference accounting. Cover legacy denial as well as DOC failure. Do not clear sticky Unknown afterward.

2. **[High / blocking] The fixture still does not satisfy revision 4’s production post/cleanup requirement.**  
   [namespace_ux_fixture.c:92](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/tests/namespace_ux_fixture.c:92), [namespace_ux_fixture.c:549](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/tests/namespace_ux_fixture.c:549), [design:516](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T5-UX-NAMESPACE-GAP.md:516).

   The stub consumes the reservation and increments `RegRegistered`; it creates no node, holds no entry reference and models no cleanup. Consequently, “registered, then cancelled” passes `d7_done()` despite the unresolved production lifetime.

   **Require additional host coverage before boot:** production registry post/cleanup bodies with injected DDIs, asserting exact-object insertion/removal, balanced `H` and references, preservation of another writer’s node, and no residual node after cancellation. Include failure/reparse, draining, tracking-loss/capacity paths and concurrent objects. The proposed Windows Unknown/origin/counter capture and subsequent publication are necessary runtime evidence, but do not replace these controls.

3. **[Informational / closed] Unload guard, nullable reservation ownership and diagnosis wording are addressed.**  
   [StageStream.c:10571](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10571), [StageStream.c:10464](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10464), [StageStream.c:10803](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10803).

   The post-epoch recheck covers `reparseOpen || writerCreate` before namespace name/identity/reservation I/O. Legacy context and callback state survive a NULL reservation; registry post is guarded against NULL; owner fields are cleared before consumption; legacy COMPLETE reserves nothing. D7 refusal and draining skip legacy processing as specified. The diagnosis now correctly distinguishes the confirmed bypass from the unproved first Unknown origin.

   Thus revision 4 items **1 and 2 are closed**; item **3 is explicit but needs the correction in finding 1**; item **4 remains open**.

4. **[Informational] No new fence/RegistryLock deadlock found.**  
   [StageStream.c:8755](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:8755), [StageWriters.c:7022](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:7022).

   Fence acquisition briefly holds the namespace resource and refuses contention; it does not wait for the active fence. Registry workers release `RegistryLock` before activation/I/O, and registry polling waits likewise release it first. I found no path holding that lock, or a worker needed by these calls, while awaiting this fence. DOC reserve/post add blocking work inside the logical fence, without retaining the namespace resource.

5. **[Informational] No additional reservation/context leak, singleton or IRQL blocker identified.**  
   [StageStream.c:10491](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10491), [StageStream.c:10807](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:10807), [StageStream.c:11499](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:11499).

   The per-CREATE owners remain separate from the fenced DOC singleton, and completion finishes before fence/epoch release. The pageable helpers remain CREATE-only under its PASSIVE completion contract; SET draining retains resident/deferred handling. No additional SAL defect emerged from source inspection; this is not PREfast acceptance.

Verification: the permitted unittest run executed seven tests with only the disclosed clang `rechecks` warning failure. Native controls passed with both compilers; all 51 native mutations were rejected. No repository edits, remote actions or product builds were performed. HEAD advanced concurrently to `b9e56697`; the reviewed minifilter and design files remained unchanged from `b3c87c70`.