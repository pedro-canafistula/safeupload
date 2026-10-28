**REVISE.** The addendum preserves the accepted product decisions, but its metadata dependency fence, archive persistence contract and growth deadline composition still need corrections before implementation.

Reviewed the 1,141-line proposal against its declared `b066c30b` source baseline and the requested designs, reviews and decomposition. During review, HEAD advanced to `f35ee490`; the proposal’s bytes remained unchanged. I distinguished those concurrent dispatch changes from incorrect baseline citations. Read-only and offline: no repository writes, builds, network, builder or VM access.

References below use repository-relative filenames.

1. **High — The cited metadata insertion point is already behind epoch admission.**

   **Document:** `UX-LARGE-GROWTH-PROTOCOL.md:632`, `:1091`.  
   **Code:** `StageStream.c:10908`, `:11296`, `:11333`, `:11348`, `:11425`.

   Section 8 requires metadata routing before epoch/BP/namespace/writer dispatch, but points to `StageStream.c:10928`. That location is inside `StageDispatchCore`, after the outer `StageDispatchEpoch` has already acquired or refused an admission token. It is also after `SafeUploadBoundPublicationPre`.

   **Failure scenario:** an application holds an epoch while waiting for growth. A policy transition closes that epoch. Growth accounting attempts its ledger create/replace. A capability branch inserted at the cited location cannot intercept the operation before epoch admission refuses it or sends it through dependency-bearing classification. The supposed dependency fence therefore does not exist at that insertion point.

   Specify the actual outer pre-epoch hook and its matching post-operation/context ownership. Include invalid matched operations, failed CREATE, draining postoperations, CLEANUP and CLOSE. Recognition must not require generic name/policy/namespace work first.

   **Close before increment 3 starts.** The implementation requires the first-boot metadata security/lifetime/lock-order review. R3-M01 must explicitly exercise accounting while epoch admission is closed; merely covering the roots with policy is insufficient.

2. **High — Independent request/reply lanes do not remove the existing service-to-driver control dependency.**

   **Document:** `UX-LARGE-GROWTH-PROTOCOL.md:417`, `:566`, `:588`, `:652`, `:767`, `:1123`.  
   **Code:** `FilterPort.cs:89`, `:108`, `:568`, `:578`; `Policy.c:1155`, `:1169`; `StageStream.c:11354`.

   Every existing synchronous `FilterSendMessage` uses the same `_sendGate`. Section 8 adds control calls for child registration on the accounting path, but does not specify how they progress independently of policy, lifecycle and fencing controls. U5 discusses reply delivery; it does not close this opposite-direction dependency.

   **Failure scenario:** `SetPolicy` holds `_sendGate` while the kernel drains an epoch. An operation counted in that epoch waits for growth. Its growth worker needs `RegisterChildIntent` to persist the grant, and blocks behind `_sendGate`. The cycle ends only through failure/timeouts; separate growth workers and reply pumps do not break it.

   `FenceAllocation` creates another risk if its synchronous callback waits for tickets whose owners need further service/control progress. “Return Busy or do local rundown” leaves both implementations permissible.

   Define bounded control admission, send ownership, disposal and kernel callback progress. Metadata registration must not queue behind a control that waits for its completion. A fence must return Busy rather than synchronously wait through a service-dependent cycle. This is not permission to remove the existing send-lifetime protection.

   **Close before increment 3 starts; apply the fence-specific proof before increment 5.** Include these edges in both first-boot lock-order reviews and saturation controls.

3. **High — The retained archive byte layout is incompatible with the specified noncached writes without an additional storage protocol.**

   **Document:** `UX-LARGE-GROWTH-PROTOCOL.md:678`, `:741`, `:759`, `:925`, `:929`.  
   **Code:** `StagedTerminalArchive.cs:140`, `:150`, `:397`, `:424`, `:448`, `:553`; `StagedJournalFile.cs:66`.

   Existing frames are contiguous, variable-length `60 + payload.Length` bytes. The writer separately writes a 60-byte header, arbitrary JSON and a 48-byte frontier. Subsequent frame offsets are generally not sector-aligned.

   Requiring synchronous noncached handles and saying “sector-pad each write” does not define how this format works:

   - Adding padding changes the next-frame offset, but the specified frame grammar contains no padding/stride rule.
   - Rounding writes to sectors requires preserving adjacent bytes, including previously committed frames.
   - Rewriting a shared tail sector introduces a crash boundary affecting committed history.
   - The 48-byte frontier also needs an explicit aligned physical write and preservation rule.

   **Failure scenario:** a frame ends midway through a sector. The next append either fails noncached alignment requirements, inserts padding that the reader interprets as another header, or overwrites the previous frame’s tail. A cached fallback violates the dependency fence.

   Select a concrete aligned framing or sector-update protocol, including committed-tail protection, frontier updates, compaction and physical overlap accounting. Resolve the inconsistent Segment permissions as well: `:669`–`:670` reserve EOF rights to New roles, while `:741` gives Segment EOF/replacement operations.

   **Close before increment 3 starts**, because its native store and capability permissions depend on this choice. Freeze the resulting archive format before increment 4. Kernel routing requires first-boot review; native controls must test unaligned logical frame ends and interrupted sector updates.

4. **High — Shared-history recovery does not yet cover all states that section 5 permits.**

   **Document:** `UX-LARGE-GROWTH-PROTOCOL.md:471`, `:496`, `:510`, `:868`, `:908`, `:940`, `:954`.  
   **Code:** `StagedAllocationResolution.cs:50`; `StagedTerminalArchive.cs:88`, `:118`, `:315`, `:435`, `:467`; `ResourceStateV2.cs:25`.

   Three concrete cases need an executable contract.

   **First, an abandoned initial allocation can have no journal Entry or bound K.** Section 5 explicitly permits binding-null closure and a stage proved never created. Section 9’s modern manifest nevertheless requires an existing journal `Entry`, and section 10 describes completed records in terms of K and generation barriers. The existing archive consumes journal entries; it has no resource-only closed-intent record.

   Such an allocation needs a durable tombstone without inventing a stage identity, allocation generation or ordinary `Discarded` namespace event. Otherwise implementation either retains its SID metadata indefinitely or manufactures inappropriate journal semantics.

   **Second, ACK completion can follow shared handoff.** The service may persist CleanupComplete in shared history before sending `ResolveAllocationAck`. The design also has a later `ResolutionAcknowledged` state. It does not define where that update persists after ledger deletion. Existing archive loading rejects duplicate TransferIds and requires hot/packed equality; it cannot simply accept a second changed frame.

   Without a defined acknowledgment representation, restart can reconstruct already-resolved allocations as unresolved debt, eventually exhausting the eight/four pending limits.

   **Third, append-before-frontier recovery remains unspecified.** `HistoryHandoff` contains no segment identity, offset or expected frontier. The crash table explains discovery of committed transactions, but not a successful append outside the committed frontier. The current reader truncates that tail at `StagedTerminalArchive.cs:467`. Reusing it conflicts with the proposal’s instruction to finish successful append bookkeeping without another append.

   Define resource-only tombstones, post-handoff ACK persistence/version selection, and incomplete-tail classification. Also close the durability sequence: `:251` and `:759` flush **before** setting exact EOF, without specifying a subsequent durability barrier. Atomic replacement and noncached writes alone do not establish the complete crash contract. State the supported native primitives, barriers and conservative outcomes explicitly.

   **Close before increment 4 starts.** The no-manifest/ACK cases also gate increment 5. The associated retirement/fence lifetime changes require first-boot review. R4-H01 needs these specific crashes, not just crashes around a completed frontier.

5. **High — Joined growth requests can exceed the advertised growth wait.**

   **Document:** `UX-LARGE-GROWTH-PROTOCOL.md:325`, `:599`, `:604`, `:995`, `:1132`.  
   **Code:** `StageStream.c:4841`, `:4863`, `:5990`, `:6009`.

   Section 4 gives a higher-extent waiter the current operation’s deadline, then permits it to start another sequence with **its own** deadline. Section 7 tells the owner that a crossing write pauses for at most the remaining selected growth wait.

   **Failure scenario:** A requests growth to 32 MiB. B needs 64 MiB and joins A just after issuance. A consumes nearly three seconds and succeeds at 32 MiB. B then starts its own three-second operation. B’s single write has waited almost six seconds. Append recomputation after another writer advances EOF can introduce another such interval.

   Define a deadline for the original application operation at its first crossing, separate from the semantic RPC’s immutable deadline. Joining, waiting for a sufficient subsequent grant, reacquisition and extent recomputation must respect that original deadline if the owner-facing promise remains a per-I/O bound.

   Alternatively, explicitly present a per-RPC bound and its cumulative stall consequences to the owner. The current text promises both interpretations.

   **Close before increment 6 starts and before presenting O1 as complete.** Add joined higher-extent and append-race deadline controls. First-boot growth/MM review is required.

6. **Medium — The pending bounds omit kernel growth waiters.**

   **Document:** `UX-LARGE-GROWTH-PROTOCOL.md:325`, `:559`, `:981`.  
   **Code:** `StageStream.c:4813`, `:5931`, `:6134`.

   One semantic operation per K bounds service requests, not the number of application callbacks joining its heap waiter group. Sections 6 and 8 give numeric worker, message, reply and metadata-transaction bounds, but no per-stream/global waiter or pin bound.

   **Failure scenario:** many threads write beyond the same capacity while its one growth operation stalls. Every callback joins that operation and retains waiter/callback/upper-file ownership. The service remains within 40 growth messages while kernel retained work continues growing.

   Specify the shared-operation object, per-waiter storage, global/per-K limits, admission before allocation/pinning, and saturation completion. If no separate waiter node is needed, describe the ownership that makes that true. Cancellation and closure must release every joined owner exactly once.

   **Close before increment 6 starts.** Add a many-waiters/one-K control, rather than only filling the service queue. Include the ownership in first-boot lifetime review.

7. **Medium — Several anchors are inaccurate, and the MDL anchor can produce misleading coverage.**

   **Document:** `UX-LARGE-GROWTH-PROTOCOL.md:174`, `:453`, `:536`, `:823`, `:978`, `:1003`.

   Corrections against the declared baseline:

   | Document claim/citation | Actual source |
   |---|---|
   | Binding at `StageStream.c:2941` | That is overwrite-resize failure cleanup. General binding is at `:2961`; the temporary resize binding is at `:2937`. |
   | FileObjects increment at `StageStream.c:2964` | Increment is at `:2969`. |
   | Seed timer at `StagedTransferAllocator.cs:237` | `:237` passes RefundGrace; timer creation/arming is at `:238`–`:239`. |
   | StageDeleted rejection at `StagedTransferJournal.cs:1919` | Relevant predicate is at `:1922`–`:1929`. |
   | Upper flush stays on caller at `StageStream.c:4790` | Caller-flush explanation/action is at `:4783`–`:4788`; `:4790` concerns retry-livelock status conversion. |
   | Exact grant comparison illustrated by `ResourceWireV32.cs:135` | That line checks retirement measurement bounds. Growth comparison is at `:141`–`:148`; allocation comparison at `:181`–`:184`. Both consume supplied committed values; neither establishes native custody. |

   More materially, `StageStream.c:11044` is the **unowned** MDL fallback branch. Owned streams have already returned through `StagePreOperation` at `:10927`. That path rejects fast I/O at `:5903` and routes IRP writes to `StageReadWrite` at `:5948`; it does not thereby establish the proposed MDL preparation/completion contract.

   **Failure scenario:** R4-MM01 uses an ordinary native writer, observes W/paging rundown through the unowned branch, and reports MDL growth coverage while never exercising an owned staged stream crossing C.

   Correct the anchors and require controls to prove routing through the intended owned-stream path. U6 must explicitly inventory MDL minors and completion ownership there.

   **Correct metadata anchors before increment 3; complete the owned-MM inventory before increment 6.** The latter requires first-boot review.

The remaining contracts that I found sound, subject to their stated implementation proofs, are:

- **ABI arithmetic:** the proposed 64-byte header, 96/112-byte negotiation payloads, 192-byte companion, 1224/128-byte fence payloads, 1208-byte ACK, 64/40-byte root messages, 640-byte child request and 128-byte marker/inventory add up correctly. A canonical 160-byte growth request encodes to 216 Base64 characters. The passive 1192/104/160/352/376-byte layouts agree with source.
- **Semantic replay:** one unresolved semantic growth operation, complete canonical equality, a durable HighWater floor and rejection of older sequences are sufficient for bounded replay. Replacing only terminal Latest entries avoids an unbounded per-growth history. Preserve this through closure and shared-history reconstruction.
- **Companion authority:** exact identity/binding checks, no modern missing-companion fallback, monotonic C/G, one replacement and conservative ambiguous-state holds are appropriate. The storage protocol issues above remain unresolved.
- **Custody/reduction:** separating driver stage-write retirement from service-owned copies is correct. ReservedMax for mutable/abandoned copies, measured immutable allocation, retained original-stage release evidence and one durable receipt/inventory/debit transition address the revision-5 races. The document correctly refuses pathname absence as a complete modern release proof.
- **Compatibility and invariants:** I found no deliberate change to the approved 120-second allocation interval, four-copy accounting, modern absence of a per-file cap, bound-head NotReady or unbound v1 behavior. Sticky Unknown and uncertain cleanup remain holds. No threshold/assertion weakening is authorized.

The CREATE fence is a credible proposed structure, **not yet a verified complete fence**. U2 remains mandatory. Its audit must include capture reservations before queue visibility (`StageStream.c:3363`, `:3421`), cancellation, provisional binding, all v20 lifecycle exchanges, the final `ExposeClaimed` decision (`:4559`) and callback completion (`:4408`). The existing serial attach worker at `:4634` and pre-completion retirement at `:4606` also need examination: changing only the allocation exchange timeout does not enforce the whole issuance-to-final-success interval through later lifecycle calls.

Expiry must close adoption promptly while cleanup continues separately. A successful allocation must also have an explicit durable “initial intent resolved” transition for pending-count reconstruction; the text’s ACK-oriented decrement rule should not accidentally count attached saves as unresolved initial allocations.

Abandonment receipts must originate from the authenticated kernel control result and match its exact outstanding request/FenceId. An agent-populated record or echoed nonzero sequence is not independently unforgeable evidence. Persisted receipts rely on the existing trusted-service/private-storage boundary; ACK must still validate the retained kernel shell. Ordinary non-driver peers must not be able to manufacture that transition through duplicated handles or cross-request correlation.

The implementation prerequisites should be scheduled as follows:

| Must close before | Required closure | First-boot review |
|---|---|---|
| **Increment 3** | Findings 1–3; U4 native anchor/target exclusions and complete role audit; U5 control/reply progress; U8 physical padding/format fit | Metadata security, lifetime, post-context ownership and transitive lock order |
| **Increment 4** | Finding 4; U3 release adapters for every slot role; retirement capture/rundown; marker/startup classification and strict modern archive grammar | Retirement, release/custody and teardown lifetime |
| **Increment 5** | U1 boot identity/old-instance boundary; U2 complete CREATE audit; no-manifest abandonment and ACK persistence; deadline propagation through attach/failure completion; successful-intent count retirement | CREATE/adoption/cancellation/fence lifetime and lock order |
| **Increment 6** | Findings 5–7; owner-selected growth duration; U6 actual MM entry inventory; complete replay/companion integration and waiter bounds | Coherent growth/MM/pin/retirement lifetime and lock order |

The seven-increment order is otherwise reasonable. These are prerequisites to the dependent integrations, not matters to defer until increment 7 or qualification.

**O1 is incomplete until finding 5 is resolved.** Its timeout/private-failure trade-off is accurately described, and three seconds is explicitly a proposal requiring target measurements. It must also explain whether the limit applies per application I/O or per semantic exchange, and that a long save can encounter multiple pauses. I do not select the duration.

**O2 correctly identifies the complete-erasure limit**, but “installer-owned” alone is not a stronger trust boundary. If expanded erasure detection is required, specify which authority cannot erase or roll back the independent anchor and how repair/uninstall works. If the existing trusted-private-storage boundary remains authoritative, preserve the stated surviving-evidence holds without implying protection against arbitrary privileged erasure. I do not decide that boundary.

Finally, section 11’s stop condition is honest. The current resize worker proves a narrow existing separation, not feasibility of every growth/MM path. A green model, parser, dispatcher or native-unowned row must not close that condition. Keep modern admission closed until the corrected contracts, native mechanisms, coherent kernel reviews and matched-pair qualification establish it.