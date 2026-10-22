# Independent review: T4/T9 growing reservations, revision 5 (2026-10-22)

Reviewer gpt-6.1-sol, reasoning effort high, no fast tier; read-only. Reviewed e188faaf. Verdict ACCEPT WITH CONDITIONS (design acceptance only; not an implementation review, not qualification).

**ACCEPT WITH CONDITIONS.** Revision 5 addresses the prior review’s findings 1–3 and 6 sufficiently for design acceptance. R3.1, the R3.4 compatibility matrix, R4.4 ordering and R4.5 startup remain accepted with their existing conditions. The implementation must establish the concrete transitions and evidence described below.

Reviewed `e188faaf909e89e19af33873f25e99a35147a7c0` on `feat/driver-m2`, against the R4 review and current status plan. Read-only and offline: no repository writes, builds, tests or machine contact.

1. **R5.1 — Accepted with implementation conditions: the custody inventory and leases can provide a stable basis for reduction.**  
   [UX-LARGE-CONCURRENCY.md:392](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:392)

   Reserving a mutable slot at `ReservedMax`, rather than its momentary allocation, closes the zero-allocation snapshot race. Retaining that maximum during abandoned copying, limiting occupancy to four objects, requiring admission before another copy, and explicitly representing metadata-only accounting resolve the corresponding R4 omissions.

   The implementation must preserve these details:

   - Claim and persist the slot/reservation obligation **before native creation**. Until the new object’s identity is captured and persisted, the pending creation remains charged and prevents conflicting reuse or reduction. This requires restructuring the current snapshot path, which creates the file before `BeginSnapshot`: [StagedInspectionSnapshot.cs:30](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedInspectionSnapshot.cs:30).
   - Join lease admission, closure, slot reuse and reduction through the same serialized accounting state. An old completion must not release a reused slot; validate the exact object and slot incarnation.
   - Enforce `ReservedMax` throughout copying. Lease closure must end mutation authority and settle outstanding writes before substituting measured allocation. A flush and identity query alone do not prevent a later write.
   - Interpret “final close” as exact object-lifetime/storage-release evidence. Closing an owned handle is insufficient while another handle, section or outstanding operation can retain storage. Uncertain release keeps the slot charged.
   - Enter metadata-only accounting only after every content slot and pending creation/copy obligation is resolved. Later content creation requires fresh admission.

   With those constraints, reduction can safely retain open leases at their reserved maxima or retain the full debit; it need not wait under a lock spanning content I/O.

2. **R5.2 — Accepted with implementation conditions: the separated proofs and durable reduction transaction are sound.**  
   [UX-LARGE-CONCURRENCY.md:407](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:407)

   The receipt now explicitly binds the transfer, driver instance, allocation and destination generations, complete stage identity, authenticated connection and receipt sequence. Separating stage write retirement from agent-owned custody evidence corrects R4’s overstatement of the driver boundary.

   The specified durable order is crash-safe: retain the old debit until acceptance persists; commit the accepted receipt, inventory, closed-growth state and resulting debit together; then update memory. Restart reconstructs the committed debit. Ambiguous persistence faults admission.

   Implementation conditions:

   - Define the receipt sequence’s scope and full wire validation before consumers are implemented.
   - Validate and commit against the **same current custody revision**, including outstanding leases and pending obligations. A measured inventory cannot become stale between validation and persistence.
   - Keep competing admission serialized until the durable result and maintained totals agree.
   - Persist enough accepted-receipt evidence for duplicate handling after restart. An exact duplicate changes nothing; conflicting measurements or stale-connection evidence authorize no reduction.
   - Treat subsequent reductions caused by independently proved object release as new accounting transitions using the retained proof—not another refund triggered by receipt delivery.

   This is an accepted crash-safety contract, not verification that the current persistence implementation already supplies it.

3. **R5.3 — Accepted: maintained accounting now covers the previously missed metadata callbacks.**  
   [UX-LARGE-CONCURRENCY.md:421](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:421)

   Maintained hot/shared physical totals and bounded per-transfer lookup directly address both foreground directory enumeration and rebuilding hot allocations through `MetadataFiles`. Measuring the complete allocation path, including queue time, also corrects the earlier overly narrow performance criterion.

   Every metadata mutation path must participate: creation, replacement overlap, failed residue, deletion, movement into completed/shared storage and interrupted maintenance. Debit must precede allocation; uncertain cleanup cannot decrement totals. Moving a record between accounting classes must preserve its charge without a gap.

   Maintenance reconstruction must not reintroduce history-sized work under the admission gate. Verify the transitive callbacks and failure cleanup, not just the replacement for `Reserve`.

4. **R5.3 — Accepted with protocol conditions: the deadline endpoints and recovery authority are now correctly separated.**  
   [UX-LARGE-CONCURRENCY.md:426](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:426)

   Driver issuance through driver adoption is an appropriate whole-allocation interval. It includes queueing, preparation, seeding, persistence and reply delivery; retries preserve the remaining duration. Expiry may terminate the CREATE while unresolved allocation remains charged.

   Before implementation, define the monotonic clock representation, concrete pending limits and terminal-resolution transitions. Bounds must cover retained work after cancellation or disconnect, so abandoning the driver waiter cannot create unbounded unresolved service work.

   The required name-recovery proof is appropriate: exact intent/object identity **plus evidence that no CREATE can still adopt it**. A timeout, cancellation notification or missing waiter alone cannot supply that evidence. Bind resolution to the existing exact replay/abort/cleanup protocol, preserving its attachment-ambiguity holds: [T4-STAGE-LIFETIME.md:343](/home/victor/Work/safeupload-staging/driver/docs/design/lifetime/T4-STAGE-LIFETIME.md:343). Automatic recovery must also work when the initial reply was lost before the driver learned the allocation identity.

   **The proposed 120 s wait remains a pending owner decision.** This review neither selects that value nor derives approval from `SeedTimeout`.

5. **R5.4 — Accepted: the added controls cover the prior review’s missing boundaries.**  
   [UX-LARGE-CONCURRENCY.md:434](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:434)

   The listed races, fifth-slot attempt, deletion-pending reader, physical-allocation cases, persistence crash points, identity substitutions, metadata latency and downgrade cases answer prior finding 6.

   Make the controls distinguish the critical transitions: crash after reserved intent but before identity binding; stale lease completion after slot reuse; closing one reader while another retains storage; and metadata-only state across restart. Pending-limit controls should include cancellation/reconnect churn. Recovery controls must demonstrate fresh successful name use after exact resolution, alongside refusal to release an ambiguous allocation.

   Retain the R4 controls and existing privacy, failed-prefix, budget-on T5 and qualification assertions.

**Before implementation:** specify the fixed-width wire layouts, schema/state transitions, slot incarnation and pending-creation representation, exact release/adoption evidence, maintained-total update rules and concrete pending bounds. Obtain the owner’s allocation wait/failure decision before implementing that dependent behavior. Preserve the accepted lock order, metadata capability confinement, compatibility and startup requirements.

**Before the first changed-kernel VM boot:** independently review the coherent implementation, including transitive MM dependencies, custody/reduction races, metadata I/O, connection rundown and mandatory local teardown. Require feature WDK Debug/Release builds with PREfast and ApiValidator at **zero warnings/errors**, both import gates passing, the complete feature agent Debug/Release × user/SYSTEM matrix, applicable PowerShell 5.1 parsing/native-signature checks and harness self-checks, and committed source with matched artifact hashes.

Subsequent authorized VM work remains restricted to **`win10-debug3`**, with `SAFEUPLOAD_DEBUGGEE=win10-debug3` explicit, the existing disposable-overlay rules and separate restoration. Design acceptance, component verification and protected-pair qualification remain distinct results.