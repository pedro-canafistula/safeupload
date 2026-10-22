# Independent review: T4/T9 growing reservations, revision 4 (2026-10-22)

Reviewer gpt-6.1-sol, reasoning effort high, no fast tier; read-only. Reviewed 31b17d87. Verdict REVISE; R3.1, the R3.4 matrix, R4.4 ordering and R4.5 startup accepted (with conditions); answered by revision 5.

**REVISE.** R4 fixes the EOF-based arithmetic and states sound requirements for retirement ordering, allocation deadlines, lane ordering and startup. Acceptance remains blocked by the missing mechanism that joins driver write-retirement proof to a complete, stable inventory of service-owned storage. R4.3 also needs to cover the remaining foreground metadata scans.

Reviewed `31b17d873bb286cda3d6dc495040495501f6f236`, branch `feat/driver-m2`, read-only and offline. No files changed, builds/tests run, or machines contacted. The accepted R3.1 formula and R3.4 compatibility matrix remain accepted.

1. **High — R4.1’s formula can bound physical storage, but the inventory supporting it is not yet established.**  
   [UX-LARGE-CONCURRENCY.md:315](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:315)

   Using measured allocation instead of EOF resolves the previous preallocation defect. Failed normalization retains the larger allocation; zero-length files retain their residual allocation charge. Those changes are correct.

   The formula is conservative provided that, at reduction and afterward:

   - Every charged content object occupies one of the four simultaneous slots.
   - Each object’s allocation fits the charged slot envelope.
   - New copies, allocation increases and slot reuse require admission before consuming storage.
   - Deletion-pending objects retain their slots until exact storage-release evidence exists.

   R4 names these objects but does not establish a stable inventory across their different owners. The existing drain boundary concerns one driver stream. Inspection snapshots are created by the service, registered with the budget, and subsequently written: [StagedInspectionSnapshot.cs:30](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedInspectionSnapshot.cs:30). Hand-back temporaries are also service-created and written outside that driver stream: [StagedHandbackCopier.cs:139](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedHandbackCopier.cs:139).

   Consequently, a snapshot registered while empty and still being copied cannot safely contribute its momentary allocation to a reduced envelope. Ending upper-stream write authority does not finish that copy.

   **Required revision:** define the custody/lease protocol joining these objects to reduction. Either wait for mutable copy leases to finish, retain their reserved maximum allocations, or keep the full debit. Persist exact object identities, occupied slots and pending obligations. Define the all-content-gone case explicitly as metadata-only accounting.

   For reader-held deletion-pending objects, “observed deleted” must mean exact object lifetime/storage release, with conservative holding where that proof is unavailable. Directory/path disappearance alone must not retire a slot.

2. **High — R4.2 identifies a sufficient driver boundary, but overstates what that boundary proves and leaves the exact receipt contract incomplete.**  
   [UX-LARGE-CONCURRENCY.md:325](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:325)

   The proposed kernel boundary is sound in principle. Current `StageDrain` checks shares, sections, FILE_OBJECT custody, paging rundown and flush results: [StageStream.c:6278](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:6278). `StageDrainAndSeal` then closes writable backing and irreversibly sets `ReadOnly`: [StageStream.c:6427](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:6427). Extending that boundary to exclude growth adoption addresses the relevant new authority.

   It proves retirement of that stream’s write authority. It does **not**, without the mechanism in finding 1, prove the allocation and mutation state of every service snapshot or hand-back object.

   Recommend separating:

   - A driver receipt proving exact stage write retirement and stable stage measurements.
   - Agent-owned, durable custody evidence covering the other slots.
   - A reduction transaction that accepts both only against still-current accounting state.

   The receipt’s listed “exact tuple” contains transfer, driver instance and allocation/destination generations, but does not explicitly include the complete stage volume/file identity, per-object identities, or connection/replay validation rules. Specify those bindings directly or through an exact, validated immutable ledger reference. Measurements alone are insufficient.

   **Receive → validate → durably persist → reduce is the correct crash-safe order**, provided the durable transition contains the accepted proof, custody inventory, closed-growth state and resulting debit. Before durable acceptance, retain the old charge. After acceptance but before updating memory, restart reconstructs the committed debit. Ambiguous persistence faults admission rather than allowing competing accounting.

   Clarify the duplicate language: an exact duplicate of an already accepted receipt is a no-op, including after restart; it neither refunds twice nor restores the full debit. Conflicting or unaccepted evidence grants no reduction.

3. **Medium — R4.3 fixes the reservation sum, but maintained reservation totals alone do not make foreground admission independent of completed history.**  
   [UX-LARGE-CONCURRENCY.md:343](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:343)

   Global/per-SID running totals, rebuilt conservatively at startup, are the right replacement for `Reserve`’s historical summation. However, current metadata admission also enumerates the journal directory: [StagedSpaceBudget.cs:419](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:419). Its transitive journal-growth admission rebuilds hot allocation bytes through `MetadataFiles`: [StagedSpaceBudget.cs:346](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:346).

   Moving completed records into shared accounting does not itself remove those enumerations. Routing them through anchored metadata capabilities fixes routing dependencies, but does not fix their duration under `_gate`.

   **Required revision:** explicitly include these callbacks in the maintained-accounting design. Use maintained hot/shared physical totals and bounded per-transfer metadata lookup, with full reconstruction confined to startup or maintenance. Preserve debit-before-write and conservative failure handling. Measure the complete allocation path with growing retained history, not just the `Reserve` call.

   The dedicated monotonic allocation deadline and bounded pending/completion exchange are accepted requirements. The proposed **120-second whole-allocation bound remains an owner decision**, not an approved consequence of the existing seed timeout.

   Before implementation, specify the deadline’s origin and terminal point, including queueing and reply delivery/adoption, and preserve its remaining duration across retries. Define pending-operation bounds, cancellation and the exact abandonment/resolution evidence used for automatic name recovery. Expiry may end the CREATE promptly while cleanup continues charged; it cannot release a possibly committed name.

   The stated user failure contract is appropriate: distinguish timeout from exhaustion, preserve the destination, never attach a late success to the failed CREATE, and recover the name automatically once exact evidence permits it. “Small saves complete in milliseconds” remains a performance claim requiring measurement.

4. **Accepted with implementation conditions — R4.4’s ordering guarantees are sufficient and can be implemented without holding a per-transfer lock across lifecycle I/O.**  
   [UX-LARGE-CONCURRENCY.md:349](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:349)

   The important semantic edges are now explicit: binding before dependent use; growth/closure linearization; lifecycle and destination-generation barriers; epoch validation; and exact reply correlation. Persistent negotiated mode and duplicate-aware saturation handling close the earlier compatibility/progress gaps.

   An implementable approach is to claim a transition/lease under short serialization, capture exact state and generation, release serialization for lifecycle I/O, then complete only the still-matching transition. Conflicting work observes the claimed state. Completed native mutations retain their receipts and retry only bookkeeping.

   Preserve the existing journal→budget order. Growth must neither acquire lifecycle/journal serialization nor wait for content-I/O leases. Revocation must release growth waiters before dependent drain waits. The implementation review must verify these properties through transitive helpers and error cleanup, including reply/pin release.

5. **Accepted with integration conditions — R4.5 now supplies the missing startup algorithm, and a new schema version provides real downgrade rejection in the current reader.**  
   [UX-LARGE-CONCURRENCY.md:359](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:359)

   Classification before unknown-residue rejection, conservative reconstruction before transaction repair, and inventory verification before admission are correct. The added replacement states distinguish an unperformed replacement from completed mutation awaiting bookkeeping. Preserving `LegacyGuard`, `ContentReleased` and legacy/shared accounting is also correct.

   This must change the startup entry path, not merely add a recovery method after construction. The current budget constructor rejects non-JSON residue before recovery and accepts only version 1: [StagedSpaceBudget.cs:84](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:84). `InitializeStagingSubsystem` constructs that budget before subsequent inventory/recovery: [MinifilterInterceptor.cs:1714](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1714).

   A modern version other than 1 therefore causes the current reader to reject it. Current initialization failure clears the subsystem rather than admitting through its preliminary allocator: [MinifilterInterceptor.cs:1737](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1737).

   Preserve that refusal through migration and metadata retirement: wherever unsupported modern accounting semantics remain, an old reader must still encounter a rejected format or marker. Test both budget-enabled and accounting-disabled startup; neither may reinterpret modern custody as legacy or repair away its evidence.

6. **Medium — R4.6 covers the previous omissions; add controls for the newly exposed custody and accounting boundaries.**  
   [UX-LARGE-CONCURRENCY.md:369](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:369)

   Retain the listed controls and add:

   - Snapshot/hand-back creation and copying racing reduction, including an object registered at zero allocation before its first write.
   - Four occupied slots plus an attempted fifth object; a deletion-pending reader must prevent premature slot reuse.
   - Allocation-normalization failure, residual allocation on empty files, and differing relevant allocation units.
   - Crashes before acceptance persistence, after durable acceptance, and before in-memory totals change; duplicate delivery and conflicting same-version measurements afterward.
   - Forged/substituted object identities and stale-connection retirement evidence.
   - Completed-history latency measurements through metadata callbacks, plus downgrade attempts after modern accounting has moved into shared/completed storage.

   Existing privacy, failed-prefix, policy/publication stress, budget-on T5 and three-mode qualification requirements remain unchanged.

**Before implementation:** revise findings 1–3 into concrete custody, receipt and accounting contracts; obtain the owner’s allocation wait/failure decision; and define the fixed-width protocol layouts, schema transitions and mutation controls before implementing consumers. The accepted initial-window formula, compatibility matrix, ordering requirements and startup algorithm can remain.

**Before the first changed-kernel VM boot:** independently review the coherent implementation, including MM dependencies, retirement/slot leases, metadata confinement, connection rundown and local teardown. Require feature WDK Debug/Release builds with PREfast/ApiValidator at zero warnings/errors and both import gates passing; the complete feature agent Debug/Release × user/SYSTEM matrix; applicable PowerShell 5.1 parsing/native-signature checks and harness self-checks; and committed source with matched artifact hashes.

Any subsequent authorized VM work remains on **`win10-debug3` only**, with `SAFEUPLOAD_DEBUGGEE=win10-debug3` explicit and separate restoration. Design acceptance, component verification and matched-pair qualification remain distinct results.