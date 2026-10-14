# m2t5boot14 root-cause analysis (saves after a block; allocation replay loop) — Sol 6.1 xhigh (2026-10-14)

Analyst: `gpt-6.1-sol`, `reasoning_effort=xhigh`, read-only, web search enabled (Codex session `01a13b2f-63be-7382-afda-fb05666fa9ec`), on `ece69b72`. Verbatim final report; checkout paths shortened.

**The symptoms are connected.** The evidence supports a cleanup deadlock followed by a rejected follow-up allocation; the retained allocation receipt then creates the `DELETE_PENDING` barrier and the fast replay loop.

1. **Blocked-stage cleanup cannot finish — proven source defect, corroborated by Win32 32.**  
   After BLOCK and verified hand-back, [StagedTransferPublisher.cs:785](agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:785) requires exact deletion **and confirmed absence before notifying disposal**. Its helper opens with sharing zero ([StagedStageFile.cs:143](agente/SafeUpload.Agent.Service/Interception/StagedStageFile.cs:143)), while the driver retains a read-only backing handle sharing READ/DELETE ([StageStream.c:1638](driver/SafeUpload.Minifilter/StageStream.c:1638)). That exclusive open necessarily conflicts.

   Boot14 logs confirm error 32 for blocked transfers `…22e` (`same-5`) and `…231` (`map-0`). Their journals remain Blocked, hand-back Verified, cleanup started, deletion incomplete. Consequently, `CleanedUp` disposal never arrives. `StageRetireDeletedStream` at line 5612 requires the **owned backing object** to report `DeletePending`; the failed deletion never establishes that condition. `StageDeleteReleasedStage` at line 5802 serves disposed **Released** versions, so it cannot rescue these blocked versions.

   These are sealed Blocked versions, not ordinary private-discard requests: their discard fields are null. The last-cleanup detach rule at line 5397 applies to `DiscardOnClose && !Sealed`. Tombstones are also not responsible: the final count is zero.

2. **The first new saves are rejected; their retained receipts cause subsequent `DELETE_PENDING` — high confidence.**  
   With the blocked view still attached, the next writer CREATE selects its sealed predecessor and sends a FOLLOWUP allocation ([StageStream.c:2383](driver/SafeUpload.Minifilter/StageStream.c:2383)). Both [MinifilterInterceptor.cs:824](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:824) and [StagedTransferJournal.cs:308](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:308) exclude **Blocked** predecessors. The interceptor returns Deny before allocation.

   Nevertheless, [StageProtocol.c:934](driver/SafeUpload.Minifilter/StageProtocol.c:934) preserves `MayHaveReachedService` even for an answered denial. The failed CREATE therefore retains an unresolved shell. [StageStream.c:1942](driver/SafeUpload.Minifilter/StageStream.c:1942) sets its `PrivateDeleteReserved`, `DiscardOnClose` and recovery flags, and pins the predecessor with `AllocationReceiptReferences`. Later CREATEs find that reservation and return `STATUS_DELETE_PENDING` at line 2257 **before settling the old view**. The predecessor pin also prevents release at line 5894, including after owner exit.

   The final ring’s relevant entries are observer PID **1776**, not actor PID 4892. They demonstrate the resulting cross-owner reservation; they do not establish that the original failed saves encountered an NTFS public-file deletion.

   Intended behavior is explicit in [T4-STAGE-LIFETIME.md:100](driver/T4-STAGE-LIFETIME.md:100): after blocked-version retirement, the owner sees the pre-save public content. A later save uses ordinary allocation and inspection. T5 adds no permanent ban after BLOCK; private discard likewise permits ordinary max+1 allocation after detachment. None of this cancels a prior public delete unless a successor has actually published.

3. **Requests 568/601 loop outside the corrected retry accounting — proven mechanism; attribution remains an inference.**  
   The strongest attribution is **568 → cycle 21**, **601 → cycle 24**. Their IDs fall between the surrounding successful attachment receipts. Cycle 29 should hit the existing same-5 reservation without issuing another allocation. The captured evidence lacks the original request/path tuples, so those mappings are not directly proven.

   After owner exit, the agent first looks for a durable reservation at [MinifilterInterceptor.cs:777](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:777). Neither request resolves one, so handling falls through to live-process lookup; line 811 throws because PID 4892 has exited. Existing durable allocations already have a replay-before-process-lookup path.

   The hot loop is exact:
   - [StageStream.c:5965](driver/SafeUpload.Minifilter/StageStream.c:5965) changes pending allocation recovery back to EXCHANGE, overriding refusal parking.
   - The collector at line 6124 checks neither SERVICE parking nor a monotonic retry deadline.
   - The reply handler at line 6187 unconditionally queues another inline pass, including after denial.

   Thus the event immediately drives another exchange. Refusals temporarily empty the timer census, allowing cancellation/backoff reset. Boot14 records **5,556 refusals per request in about 17.3 seconds**; `wakeInline=12647` versus `wakeTimer=31` confirms inline replay dominates. Four live streams are consistent with two blocked predecessors plus two retained receipt shells.

**Proposed changes:**

- **Separate blocked deletion disposition from physical completion.** At `StagedStageFile.cs:143` and `StagedTransferPublisher.cs:785`, add a blocked-cleanup-specific operation that opens no-follow, verifies full volume/file identity, permits READ/DELETE sharing while denying writers, and marks that exact object for deletion. Then notify/wake retirement **before waiting for absence**. Persist enough exact disposition evidence to resume safely; `StageCleanupStarted` alone is not a deletion receipt. Set `StageDeleted` only after confirmed completion. Keep retirement’s real handle/object/section/rundown exclusions.
- **Restore coherent follow-up eligibility.** Align `MinifilterInterceptor.cs:824` and `StagedTransferJournal.cs:308` to permit exact stable Blocked predecessors while cleanup has not begun, preserving owner, epoch, generation, identity and seed-export checks. Serialize this against cleanup. Once retirement starts, detach and use ordinary allocation from the public destination.
- **Provide an exact terminal “no allocation committed” result.** Handle it at `StageProtocol.c:934/:1508` and the retained-receipt apply path. Serialize resolution with allocation: an existing manifest returns its exact tuple for unattached cleanup; an exited requester with no committed allocation receives terminal rejection after any unjournaled backing is safely cleaned. Release only the matching receipt reservation and predecessor pin. **Generic Deny cannot authorize this**, because the current catch also covers failures after allocation committed.
- **Extend retry accounting to allocation recovery.** At `StageStream.c:5965/:6124/:6187/:6495`, retain a per-cause SERVICE/EXCHANGE state and monotonic deadline through collection and flight. Queue immediate work only when successful resolution enables cleanup. Refusals park until reconciled reconnect; transient failures use the existing 250 ms–8 s backoff.

**Tests:** add agent controls for BLOCK → same-name resave, cleanup with a simulated driver read handle, pending deletion versus confirmed absence, replacement identity refusal, and crash/retry without repeating hand-back or publication. Add allocation-handler tests for exited/reused PID, existing manifest, definitive rejection, and uncertain post-commit failure. Extend kernel source controls with negative mutations for allocation parking, deadline enforcement, in-flight accounting, unconditional requeue, and exact reservation/pin release.

Read-only analysis completed at `ece69b72`; supplied kernel/agent tree comparisons match. No edits, builds, tests or VM actions were performed.