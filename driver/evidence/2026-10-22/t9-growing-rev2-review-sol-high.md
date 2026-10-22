# Independent review: T4/T9 growing reservations, revision 2 (2026-10-22)

Reviewer gpt-6.1-sol, reasoning effort high, no fast tier; read-only. Reviewed HEAD 51661d10. Verdict REVISE; answered by revision 3 of the design.

**REVISE.** The revision substantially addresses the prior MM-recursion, retirement and metadata-reentrancy findings. Its direction is defensible, but it does **not yet specify a complete fix for F5**: the initial grant is insufficiently constrained, refund-grace behavior is unchanged, and retained versions still carry their whole grant.

Reviewed HEAD `51661d10a951805733f799868b1d7654d03657b9` on `feat/driver-m2`, read-only and offline. No files changed, builds run, or machines contacted.

1. **High — Specify the initial grant exactly and remove the foreground refund-grace dependency.**  
   [UX-LARGE-CONCURRENCY.md:26](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:26)

   “At least” 16 MiB does not prohibit another whole-allowance initial grant. Require, for newly negotiated growable allocations:

   `initial capacity = AlignUp(max(16 MiB, checked seed requirement), alignment)`

   An unseeded small file gets that initial window; a larger seed gets its checked requirement before copying. Future writes obtain additional capacity through growth. This creates no fixed per-file cap.

   The design also never disposes of `ReserveAfterPendingRefundsAsync`. The current allocator invokes it with a full reconciliation pass, and the helper checks its deadline only between passes: [StagedTransferAllocator.cs:230](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedTransferAllocator.cs:230), [StagedSpaceBudget.cs:244](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:244). The earlier checkpoint already records that this overshot its nominal bound.

   Require immediate admission when the small reservation fits, with no grace delay or full-history scan. Actual exhaustion must retain the existing refusal and diagnostics. Any retained refund retry must have bounded work and must not occupy the receive loop. Merely reducing the grant should eliminate the observed contention in ordinary overlapping saves, but does not establish those latency properties.

   The unchanged total/per-SID/floor formulas, four-copy increment, metadata debit and exact-fit fallback are otherwise sound. Four copies of a 16 MiB window plus ordinary metadata cost about **65 MiB per active small version**. Concurrency remains budget-limited; it is not unlimited.

2. **High — Retained/held accounting remains grant-based, not based on what is retained.**  
   [UX-LARGE-CONCURRENCY.md:32](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:32), [UX-LARGE-CONCURRENCY.md:85](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:85)

   The document explicitly keeps capacity monotonic, prohibits active shrinkage, and permits full refund only through cleanup. It defines no partial release of unused authority. Therefore a tiny held version can retain its initial window, and a version grown geometrically can retain substantial unused headroom. The current implementation charges exactly that way: [StagedSpaceBudget.cs:209](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:209).

   **Closing growth is not proof that existing write authority has ended.** A driver may still possess the last grant; mapped/cache activity, snapshots and outstanding copies also matter. Refunding from a file-length query would be unsafe.

   To meet the requested retained-storage behavior, add a distinct durable accounting transition after proven write/section retirement. Keep the historical authorized capacity separate from the charge for closed retained custody. The latter must conservatively cover allocation rounding, every retained object/copy and permitted subsequent snapshot/publication/hand-back work, preserving the approved four-copy envelope and metadata accounting. Every consumer must respect that reduced envelope or reserve additional space first.

   Ambiguous or still-live custody keeps its full charge. Old immutable v1 grants also keep their original accounting behavior. This needs a written lifecycle and crash contract, rather than an implementation-time subtraction.

3. **High — Growing reservations alone do not resolve the other demonstrated budget-on blockers.**  
   [UX-LARGE-CONCURRENCY.md:244](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:244)

   Two existing defects must be explicit dependencies of delivery:

   - Completed ordinary saves retain a per-SID metadata charge; current retirement covers only selected discard kinds: [StagedSpaceBudget.cs:655](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:655).
   - A lost **initial allocation reply** can strand the allocation and wedge later saves. Idempotent **growth** replay does not fix allocation attachment/recovery.

   Both are documented alongside the latency defect in [t4-checkpoint.md:48](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-20/t4-checkpoint.md:48).

   They can remain separate coherent changes, but must precede a claim that default-budget everyday saving or the budget-on 10k workload is fixed. Moving completed history into reconstructible shared accounting must preserve its actual storage debit, replay evidence and generation barriers.

4. **Medium — The architecture is reasonable for full growth, but the smallest useful increment and upgrade behavior need explicit boundaries.**  
   [UX-LARGE-CONCURRENCY.md:58](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:58), [UX-LARGE-CONCURRENCY.md:197](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:197)

   I would retain one monotonic reservation per version. A shared SID pool would introduce new member authority, reconstruction and refund machinery; it is not an evident simplification.

   The smaller coherent delivery is **exact initial-window allocation, with the existing kernel fast path below capacity and growth invoked only when the required extent exceeds it**. That directly targets overlapping Office temporary files. It avoids imposing the growth exchange on every small write.

   It does **not** eliminate the difficult boundary mechanism. Supported mapped/EOF/allocation paths crossing the window still need the growth protocol and dependency fence. Implementing ordinary-write growth first is useful development work, but cannot qualify the feature while those paths retain a 16 MiB ceiling. Keep incomplete growth behind readiness gates.

   Specify this compatibility matrix:

   | Combination | Required behavior |
   |---|---|
   | New driver + new agent | Small initial grants only after exact growth negotiation and recovery readiness. |
   | Old driver + new agent | Preserve supported immutable v1 behavior, including its limitation, or keep growable admission NotReady. A new 16 MiB immutable grant would introduce a cap. |
   | New driver + old agent | Preserve v1 immutable behavior; never infer growth authority from driver capability alone. |
   | Old agent encountering modern persisted accounting | Refuse unsupported downgrade safely; no reinterpretation, deletion or accounting-disabled fallback. |

   Existing v1 grants must never be converted to small-window grants or refunded as though they were growable records. The source currently reads a companion once into immutable capacity: [StageStream.c:1762](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:1762).

5. **High implementation condition — The lock graph is coherent only if receive and completion progress are made concrete.**  
   [UX-LARGE-CONCURRENCY.md:83](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:83), [UX-LARGE-CONCURRENCY.md:94](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:94), [UX-LARGE-CONCURRENCY.md:203](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:203)

   With **all** stated fences enforced, I find no necessary remaining journal/budget/MM cycle. Journal→budget is acceptable because growth never acquires journal, every budget-held metadata operation uses the early capability route, and content I/O occurs outside the budget monitor under leases. Signal-before-dereference also removes the worker’s final-CLOSE dependency from the waiter.

   The remaining potential cycle, if implementation merely adds a growth lane, is:

   **MM holds upper resource → waits for growth → growth awaits receive dispatch → receive loop is blocked in existing lifecycle/allocation work → that work, or its dependency, waits for namespace/upper progress → MM.**

   The current receive loop still executes ordinary allocation, lifecycle, rename and epoch-drain handlers inline: [MinifilterInterceptor.cs:418](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:418), [MinifilterInterceptor.cs:458](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:458). A separate downstream queue cannot rescue a request that has not been received.

   Enumerate which handlers move off receive and which are proved bounded and independent. Include reply transport and shutdown ordering. Connection cancellation/revocation must release growth waiters before any drain that could depend on those waiters.

   Likewise, any missed budget-held generic metadata operation restores the prior **upper→growth→budget→metadata→namespace→upper** cycle. Audit transitive free-space/alignment/security queries and error cleanup, not just JSON replacement.

6. **Medium — Recovery needs an explicit startup state table and reconnect contract.**  
   [UX-LARGE-CONCURRENCY.md:44](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:44), [UX-LARGE-CONCURRENCY.md:79](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:79), [UX-LARGE-CONCURRENCY.md:176](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:176)

   Ledger-before-companion-before-reply is correct. The bounded predecessor/replacement tuple is a substantial improvement. Missing startup details are:

   - Classification of initial bind/companion creation separately from later replacement, including missing companion and create-before-identity capture.
   - Ledger replacement `.new` residue and interrupted pending-tuple/finalization writes.
   - Exact predecessor still current, exact replacement already current, and replacement already current with obsolete predecessor residue.
   - Repair/finalization interrupted a second time.
   - Service reconnect versus driver restart: which fields are durable allocation authority and which belong to the new authenticated connection. Old-cookie work must fail; reconnect must not reopen closed growth.
   - Closure racing growth, followed by journal persistence failure: closed custody remains charged and cannot be revived by replay.

   The existing constructor rejects non-`.json` reservation residue and every ledger version except 1; inventory also knows no replacement companion: [StagedSpaceBudget.cs:84](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:84), [StagedSpaceBudget.cs:164](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:164). Modern recovery must classify its recognized pending states before blanket rejection.

   Unknown objects, torn/ambiguous authority and ahead-of-ledger companions may legitimately remain held. Known committed states should finish bookkeeping without repeating successful native replacement. Explicitly reject an observed capacity ahead of the ledger, and ensure late success cannot clear sticky failed-space/nonpublishable state.

7. **Medium — The delivery checklist omits decisive controls for these mechanisms and the new evidence.**  
   [UX-LARGE-CONCURRENCY.md:236](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md:236)

   Add explicit controls for:

   - **F5 regression:** fresh budget-on state; overlapping distinct-name one-line files; Word temporary/target saves; Excel SaveAs/edit/reopen; retained-state repetition. Observe successful exact reservations without the 1500 ms grace. Record backend cause and application result.
   - **Held/completed accounting:** charge before/after proven retirement, retained oversized grants, shrink/truncate cases, live mappings/readers, copying hand-back, repeated restart, and enough completed ordinary saves to expose cumulative metadata debt.
   - **MM and progress:** cached/noncached/append/MDL/EOF/allocation/section boundary crossings; concurrent policy/namespace/publication work; all continuation/worker slots occupied; timeout, disconnect and mandatory teardown; exact pin release and bounded queue/storage.
   - **Capability confinement:** private roots covered by policy, wrong process/token/connection, impersonation, root/target substitution, links/reparse/ADS/by-ID escapes, unsupported operations, noncached alignment, revocation and FILE_OBJECT address reuse.
   - **Crash/replay:** every state in finding 6, lost initial-allocation replies separately from growth replies, mixed versions, exact-fit growth through many small increments, no duplicate debit/refund and no successful-prefix publication.

   Keep the separate publication-window defect visible. The new evidence also identifies F3/F4; budget repair alone cannot promise that every Word reopen or overwrite now succeeds.

Before implementation, revise the document to settle findings 1–4 and 6, and make the progress proof and missing controls explicit. Preserve all approved budget formulas, four-copy accounting, metadata charges, caller authority and fail-closed behavior. Any retained-surplus release needs its own proven authority boundary.

Before the **first changed-kernel VM boot**, require independent review of the coherent implementation covering growth, metadata capabilities, receive dispatch and local teardown; feature WDK Debug/Release PREfast/ApiValidator/import gates at 0 warnings/errors; the complete four-leg agent matrix; and applicable Windows PowerShell 5.1/native harness checks. Identify committed source and matched artifact hashes.

The first focused boot should exercise fresh budget-on small overlap, the 16 MiB crossing and real Word/Excel cases on `win10-debug3` only. Subsequent ordinary/runtime-/boot-Verifier, budget-on 10k, independent-byte and separate restoration gates remain required. Design acceptance, component passes and protected-pair qualification remain distinct results.