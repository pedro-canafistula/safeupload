# Independent review: T4/T9 growing reservations, revision 3 (2026-10-22)

Reviewer gpt-6.1-sol, reasoning effort high, no fast tier; read-only. Reviewed HEAD 8128a2d5. Verdict REVISE (initial formula and compatibility matrix accepted); answered by revision 4.

**REVISE.** R3 resolves the initial-window ambiguity and improves the compatibility and progress design. Acceptance remains blocked by the retained-charge calculation, the unspecified driver retirement proof, cross-lane ordering, and the allocation-deadline contract.

Reviewed `8128a2d5f169ef3691ed7f6efcbff86791fe103e` on `feat/driver-m2`, against the previous review and current implementation. Read-only and offline; no files changed, builds run, or machines contacted.

1. **R3.1 — The initial formula is correct; preserve separate legacy and replay paths.**  
   [UX-LARGE-CONCURRENCY.md:245](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:245)

   The formula now specifies an exact initial window:

   `AlignUp(max(16 MiB, checked seed requirement), max(stage granularity, destination allocation unit))`

   With checked arithmetic and the validated power-of-two allocation units, this rounds to both units. It removes whole-allowance contention without imposing a per-file cap, provided growth remains required and available beyond the window. Removing the grace eliminates that deliberate 1500 ms stall; it does not alone prove bounded allocation latency.

   The removal must apply **only to newly negotiated growable allocations**. The current common allocation path invokes both foreground reconciliation and `ReserveAfterPendingRefundsAsync`: [StagedTransferAllocator.cs:230](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedTransferAllocator.cs:230). Preserve legacy/v1 admission and retry behavior through an explicit mode branch.

   A committed exact replay must bypass fresh sizing/admission and return the existing object, generation and persisted capacity—even if remaining space has since fallen. Current resolution already completes `Bind` against that committed object: [StagedAllocationResolution.cs:75](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedAllocationResolution.cs:75). Modern replay must complete pending companion bookkeeping without resetting capacity to the initial window, reseeding, double charging, reopening closed growth, or retrying attachment for a CREATE already returned as failed. An uncommitted retry still needs the existing exact absence/cleanup proof.

2. **High — R3.2’s retained-charge formula does not yet bound physical storage.**  
   [UX-LARGE-CONCURRENCY.md:254](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:254)

   Ending write authority is necessary, but it does not establish:

   `RetainedCharge = 4 × AlignUp(sealed length, granularity) + metadata`

   In particular, **allocation size can exceed EOF**. The current driver supports allocation changes independently of file length: [StageStream.c:5999](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:5999). A version can therefore finish with a tiny sealed length and substantial preallocated backing storage. Charging four tiny rounded lengths can undercharge even that single backing object.

   Specify one of these mechanisms before implementation:

   - Prove every retained object’s allocation fits the reduced per-copy bound, with any permitted normalization completed before refund.
   - Retain a larger conservative envelope covering existing allocation and all permitted subsequent copies; otherwise keep the full charge.

   Inventory must include retained/deletion-pending objects pinned by readers, snapshots and hand-back copies. A read-only handle does not create new write authority, but it can keep storage allocated. Snapshot or copy task completion likewise does not prove storage release.

   Preserve four **simultaneous copy slots**, accounting for each object’s allocation rounding and future permitted work. “Every consumer respects the reduced envelope” needs an enforceable admission rule. Consumers must not continue using historical `AuthorizedCapacity` as their storage ceiling after reduction. Empty sealed files particularly need coverage for residual allocation.

3. **High — R3.2 names the desired facts, but not the driver proof that establishes them.**  
   [UX-LARGE-CONCURRENCY.md:254](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:254)

   An acceptable concrete starting point already exists: successful `StageDrain`, followed under the existing exclusion by closing the writable backing and setting irreversible `ReadOnly` in `StageDrainAndSeal`: [StageStream.c:6276](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:6276), [StageStream.c:6419](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:6419).

   The design should explicitly require that boundary, extended for growth:

   - Exclude fresh writable opens, section creation and growth adoption.
   - Establish zero upper handle/share and FILE_OBJECT custody; drain/purge cache and sections, complete paging rundown, and check flush results.
   - Resolve queued/in-flight growth and reply-adoption ownership so no late grant can restore mutation authority.
   - Irreversibly close writable backing authority before producing the retirement evidence.

   Communicate that proof through an authenticated, exact version-bound receipt, and persist its accepted state before reducing the charge. Define recovery when delivery or persistence fails; uncertainty retains the full debit.

   `CLEANUP`, zero user handles, “growth closed,” a length query, or a seal request merely queued are insufficient individually. Clarify that “no outstanding growth grant” means no remaining ability to consume/adopt authority; historical grants still exist.

   Also distinguish accounting **Retired-proven** from the existing driver `Retired` state, which concerns deleted backing custody. They are different transitions. Later read-only readers may retain storage without undoing a correctly proved write retirement.

4. **High — R3.3 has the right dependencies, but omits the allocation deadline and its user-visible failure contract.**  
   [UX-LARGE-CONCURRENCY.md:263](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:263)

   Items (a)–(d) are appropriate. The proposed implementation order is reasonable, although not every item strictly depends on its predecessor. All must precede a default-budget success claim. Completed metadata must move into reconstructible charged storage while preserving replay and generation evidence.

   Extend (c) to cover the **whole allocation deadline**, including queueing, preparation, seeding and persistence. The observed roughly 3-second wait is not a dedicated allocation constant: the shared exchange obtains `SafeUploadPolicyVerdictTimeout`: [Communication.c:1731](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Communication.c:1731). Meanwhile, seeding has a separate 120-second budget: [StagedSpaceBudget.cs:13](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:13).

   Small-window admission cannot make a genuinely large seed finish within that shorter RPC wait. Recommend an explicit, bounded staged-allocation deadline/protocol, separate from the legacy inspection timeout, with a monotonic overall deadline that retries do not restart. Do not simply extend every verdict wait. Settle whether long seeding uses a bounded pending/completion exchange or another reviewed mechanism.

   On expiry, the user sees the save/create fail after the declared bound. The destination must remain protected; a late committed allocation stays charged until exact resolution and cleanup. Recovery must release the stranded name automatically when proved safe, without attaching the failed CREATE or requiring the original process to exit. Diagnostics must distinguish timeout from genuine space exhaustion.

   Removing full-history reconciliation is also insufficient if `Reserve` still sums every historical reservation: [StagedSpaceBudget.cs:206](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:206). Specify maintained accounting totals or another demonstrably history-independent admission mechanism.

5. **High — R3.4’s compatibility matrix is sound; R3.5 needs explicit ordering across lanes.**  
   [UX-LARGE-CONCURRENCY.md:273](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:273), [UX-LARGE-CONCURRENCY.md:284](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:284)

   The matrix and NotReady boundary are correct. Negotiated mode must remain attached to each allocation: reconnect or capability loss cannot convert existing growable custody into a v1 immutable window.

   Dispatch-only receive removes the identified receive-loop dependency, but independent bounded lanes do not preserve processing order. Require these guarantees:

   - **Allocation:** serialize duplicate preparation/resolution for the same intent; binding and grant persistence precede dependent growth or lifecycle use.
   - **Growth versus closure:** linearize through the ledger. Growth committed first remains charged; closure committed first rejects growth. Late replies cannot undo closure, retirement or sticky failure.
   - **Lifecycle and namespace:** preserve required attachment/cleanup/seal/discard ordering and destination-generation/rename barriers. Worker scheduling cannot determine semantic order.
   - **Epoch/connection:** capture connection identity at dispatch and revalidate before authority-changing work. Drain revokes admission before draining dependent work; old workers cannot publish readiness or mutate through a replacement connection.
   - **Completion:** correlate replies exactly. Reply completion may reorder where permitted by the state machine; request arrival order alone is insufficient.

   Implement ordering with short state transitions and appropriate existing serialization. A per-transfer lock held across lifecycle I/O could recreate the MM→growth dependency.

   Saturation must yield a valid failure without claiming `NoAllocationCommitted` while an exact duplicate may still commit elsewhere. Growth execution and reply progress must remain independent of exhausted lifecycle/allocation workers.

6. **Medium — R3.6 improves recovery coverage but is not yet a complete startup algorithm.**  
   [UX-LARGE-CONCURRENCY.md:292](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:292)

   The current constructor rejects non-`.json` residue and all record versions except 1 before inventory runs: [StagedSpaceBudget.cs:84](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:84). Inventory recognizes the recorded stage, `.space` and snapshot paths, but no companion replacement: [StagedSpaceBudget.cs:164](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:164).

   Specify startup order: validate trusted storage, classify supported schemas and recognized residue, reconstruct conservative charges and exact bindings, resolve permitted transactions, verify inventory, then enable admission. Ordinary rejection must follow recognized-state classification.

   Add or disambiguate:

   - Replacement already current **without** predecessor residue.
   - Predecessor current with replacement absent, incomplete, or fully prepared. A proved unperformed replacement needs the native replacement step; an already-performed replacement needs only bookkeeping.
   - Committed Retired-proven records, interrupted reduction, and recovery of retained snapshot/reader/copy custody.
   - Missing ledger with modern companion/content: hold; never reinterpret as legacy.
   - Preservation of v1 `LegacyGuard`, `ContentReleased`, legacy upgrade and shared completed-history accounting.

   “Ledger current, companion at ledger capacity → normal” must require no unresolved transaction and matching format, identity and binding—not numerical equality alone. Modern records need a distinct rejected-by-old-readers schema version; adding fields to version 1 would not enforce downgrade refusal.

7. **Medium — The checklist now covers most previous omissions; add controls for these remaining boundaries.**  
   [UX-LARGE-CONCURRENCY.md:313](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:313)

   Add explicit controls for:

   - Tiny EOF with large preallocation, zero-length retained custody, and physical allocation observations across reduction/restart.
   - Retirement proof lost, duplicated or stale; growth racing the irreversible boundary; read-only readers retaining objects afterward.
   - Deliberately reordered allocation/growth/lifecycle work and epoch drain with queued work in every lane.
   - Allocation deadline expiry during queueing, seeding and post-commit reply delivery; late completion, automatic name recovery and application-visible diagnostics.
   - Exact replay after capacity has grown and available budget has fallen.
   - Admission against increasing completed history, measuring queue time and end-to-end allocation time.
   - Legacy/v1 grace/replay preservation and unsupported downgrade with modern retained accounting.

   Explicitly retain concurrent policy/namespace/publication stress. The budget-on T5 reruns carried by the status plan also remain required. Keep F3/F4 publication-window failures separate from F5 accounting results.

Before implementation, settle findings 2–6 in the design: physical retained-storage bounds, the exact retirement receipt, staged-allocation deadlines and failure UX, cross-lane ordering, and startup classification. Preserve the accepted initial formula and compatibility matrix. Freeze the required C/C# layouts and mutation controls before implementing their consumers. Any changed waiting/failure policy needs the owner’s concrete product decision.

Before the **first changed-kernel VM boot**, require independent review of the coherent implementation covering those contracts, MM dependencies, metadata capabilities and local teardown; feature WDK Debug/Release builds with PREfast/ApiValidator at zero warnings/errors and both import gates passing; the complete four-leg feature agent matrix; and applicable PowerShell 5.1/native harness checks. Record committed source and matched artifact hashes.

The first focused run should cover fresh budget-on overlap, a window crossing, seeded allocation, retirement accounting and lost-reply recovery on **`win10-debug3` only**, with `SAFEUPLOAD_DEBUGGEE=win10-debug3` explicit. Full matched-pair three-mode qualification, budget-on 10k/T5 reruns, independent bytes, separate restoration and final milestone adversarial review remain distinct later gates.