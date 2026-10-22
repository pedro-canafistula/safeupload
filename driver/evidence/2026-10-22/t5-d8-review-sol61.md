# T5 D8 review — Sol 6.1 high (gpt-6.1-sol, reasoning_effort=high, no fast tier), read-only, 2026-10-22

Resumed session, reviewed commit `13ea6fbf`. Brief: `~/Work/safeupload-tools/workers/t5-d8-review-brief.md`; raw log `t5-d8-review.log` (EXIT=0). Verbatim result:

**ACCEPT WITH CONDITIONS — the scoped unbound-cancellation change is sound. Tighten the `Held` claims, add the recovery negative controls below, and complete the Windows verification.**

1. **[Informational] The cause is supported, with a narrower meaning for `Held = 0`.**  
   [StageStream.c:5281](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:5281), [StageStream.c:6578](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:6578), [StageStream.c:7675](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:7675).

   Accepted cancellation detaches the current view. `StageTryRelease` can subsequently unlink the sealed version without service disposal, after checking handles, file objects, sections, RPCs and outstanding receipts. Disposal then finds no matching transfer and returns zero. The service exceptions establish that exact-stage cleanup succeeded and the old code rejected a false disposal result. The journals and counters support this explanation; aggregate counters do not identify each release’s cause.

   A lost cancellation reply or a version parked behind RPC/receipt references **does not itself produce false**: that stream remains listed, so disposal returns held. An uninitialized driver returns an error, which the transport throws.

   There are nevertheless narrower counterexamples to “the driver holds nothing”: an unlinked stream can still be on the worker’s `Released` list awaiting teardown ([StageStream.c:6558](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:6558)). A new driver instance can also report no matching transfer without certifying the old instance’s lifetime.

2. **[Low / required wording correction] `Held` is not a deletion or lifetime receipt.**  
   [design:545](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T5-UX-NAMESPACE-GAP.md:545), [StagedTransferRecovery.cs:153](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedTransferRecovery.cs:153).

   Replace “no reference to the stage remains” with **“no matching version remains in the responding driver’s live transfer list.”** Also qualify “Held = 1 … accepted disposal”: the API returns one for stale and deferred disposal too ([StageStream.c:7680](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:7680)).

   These qualifications do not invalidate this change. Completion records **service cleanup of an irrevocably cancelled unbound version**, supported by:

   - The validated, durable cancellation receipt.
   - Exact-identity deletion or an already-absent stage, with access/identity failures retained.
   - A successful, structurally validated disposal exchange.
   - A fresh cancellation-receipt and absence check before journaling completion.

   No timer, digest or counter supplies authority. This does not satisfy—and must not be reused for—the separate BOUND deletion/lifetime receipts.

3. **[Informational] No new resurrection, successor-delete or crash-replay defect found.**  
   [StagedUnboundNamespaceJournal.cs:40](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedUnboundNamespaceJournal.cs:40), [StagedUnboundNamespaceJournal.cs:80](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedUnboundNamespaceJournal.cs:80), [StagedTerminalArchive.cs:378](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedTerminalArchive.cs:378).

   Cancellation validates the exact version and serializes against final publication. The cancellation record continues to reject publication and remains preserved in the archive, including its generation claim. Cleanup targets the private stage, not the public destination; a later same-name save has separate transfer authority.

   A crash after disposal but before completion leaves cancellation pending. Replay can confirm absence, receive false, and complete without repeating a public mutation. A crash after completion preserves the cancellation and `StageDeleted`; archive replay is already supported.

   The old throw added no missing lifetime evidence: it merely required the service to encounter a still-listed version. Released, handback and discard branches are unchanged.

4. **[Medium / verification condition] The three new cases cover the boolean change, but miss an important negative control.**  
   [StagedUnboundNamespaceTests.cs:159](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Tests/StagedUnboundNamespaceTests.cs:159), [StagedUnboundNamespaceTests.cs:177](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Tests/StagedUnboundNamespaceTests.cs:177).

   Add a cancelled-recovery case with a **different object at the saved stage path**, using a gate configured to return false. Require preservation of that object, **zero disposal calls**, `StageDeleted = false`, and pending recovery. Existing helper tests cover replacement refusal, but not this recovery branch.

   Also cover interruption after successful disposal and before completion: restart journal/publisher, return false on replay, and require one durable completion with cancellation preserved and no publication. Have the gate assert transfer ID, `CleanedUp` outcome and committed-rename count.

   Then run the required four-leg agent matrix and matched Windows row, including `T5JournalSettledAfterRun` and the existing byte/privacy assertions.

Reviewed at `13ea6fbf`, offline and read-only. No edits, builds, tests or remote actions performed.