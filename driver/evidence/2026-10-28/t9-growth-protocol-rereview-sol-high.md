**REVISE.** The revision fixes the original outer-hook, framing and deadline defects at the contract level. Three remaining gaps concern successful-intent retirement, archive handoff eligibility and buffer pinning. These need explicit rules before the dependent integrations.

Reviewed HEAD `7867cf37f17520660adf07071d9554615122f29b`, including the complete prior review. The subject is 1,742 lines, SHA-256 `b2ce71f310d2060fb807d7e9258166ccc104239583915f33d31d7fc243623287`. Work was read-only and offline; no repository writes, builds, network, builder or VM access.

Below, **P** means `driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md`. “Closed” means the original **design finding** is closed, not that its implementation or qualification is proved.

**Severity-ranked findings**

1. **High — Archive eligibility does not explicitly exclude a successful allocation whose initial intent is still unresolved.**

   **Document:** [P:562](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:562), [P:570](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:570), [P:1236](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1236), [P:1330](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1330).  
   **Code:** [StagedTerminalArchive.cs:88](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedTerminalArchive.cs:88), `:119`; [StagedSpaceBudget.cs:662](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:662).

   The sentence “Successful handoff retains InitialResolved” expresses the intended outcome, but the strict `TransferClosure` grammar requires only terminal `Entry` plus MetadataOnly `ResourceClosure`. It does not require successful initial resolution before the ledger disappears. MetadataOnly concerns content custody; it does not itself prove final CREATE success.

   **Failure scenario:** CREATE succeeds, the application closes immediately, and retirement/disposal completes before the service’s success query commits. A closure base captures `Open`/`Attached`, shared handoff deletes the ledger, and the subsequent query returns authenticated Attached. The successful-resolution procedure requires a **ledger transition**, but that ledger is gone. The only permitted history delta is CleanupComplete → ResolutionAcknowledged; it cannot record InitialResolved. Rewriting the base is corruption. The initial pending debt therefore cannot complete through the specified transitions.

   Existing archive eligibility has no hidden protection against this race; modern eligibility must add it.

   **Required correction:** define legal initial-resolution states for every closure base. The smallest correction is to prohibit successful-transfer handoff until InitialResolved is durable, while preserving CleanupComplete abandonment bases and their ACK delta. Alternatively, specify another typed success-resolution delta. Add the delayed-query/immediate-close crash case to R3-A05/R4-H01.

   **Gates:** increments 4 and 5.

2. **Medium — Successful intent counts and retained kernel receipt storage need separate credits.**

   **Document:** [P:461](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:461), [P:562](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:562), `:568`, [P:679](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:679).  
   **Code:** [StageStream.c:4461](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:4461), `:4629`; [StagedRequestDispatcher.cs:27](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedRequestDispatcher.cs:27).

   InitialResolved releases the service’s 8/4 pending count **before** ACK, while the kernel must retain the successful receipt until ACK. The document gives no separate numeric limit/admission transition for those retained success shells. Bounded concurrent control sends do not bound their accumulated storage.

   **Failure scenario:** repeated service interruptions after durable InitialResolved but before ACK leave successful receipt shells in the same surviving driver instance. Reconstructed initial debt is zero, permitting fresh allocations. Either kernel storage accumulates outside the stated bound, or an undocumented kernel limit refuses new saves despite the service reporting available initial slots.

   The present code does not already provide this proposed retained-success registry: attachment currently clears allocation recovery information and later removes the attach lookup.

   **Required correction:** distinguish durable initial-request debt from occupied kernel registry capacity. Give retained success shells an explicit bounded credit, reserved before CREATE capture and retained through actual kernel ACK eviction. Specify reconnect reconstruction, bounded ACK scheduling and saturation behavior. InitialResolved may still release the service’s initial-debt count exactly once.

   **Gate:** increment 5; encode the distinction in increment 1’s model.

3. **Medium — The waiter admission rule bounds upper-file references, but misses existing user-buffer locking before the crossing check.**

   **Document:** [P:1495](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1495), [P:1542](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1542), [P:1553](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1553).  
   **Code:** [StageStream.c:4824](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:4824), `:4832`, `:4841`, `:4863`.

   `StageReadWrite` calls `FltLockUserBuffer` before acquiring the stream resource and before computing the effective append/file-pointer extent. The new rule explicitly reserves before heap work, extra callback references and **upper-file** pins, but does not address this earlier MDL allocation/page locking.

   **Failure scenario:** a permitted MM growth waiter retains the upper resource. Many ordinary writers lock their buffers and then block acquiring that resource, before reaching growth admission. The 32/256 waiter limits can remain satisfied while additional requests retain locked buffers outside those limits. The stated 320 upper-file-pin bound remains arithmetically correct, but is not a bound on these resources.

   **Required correction:** inventory buffer/MDL ownership separately from FILE_OBJECT references. Specify where crossing-related admission occurs relative to `FltLockUserBuffer` and resource acquisition, which already-owned MDLs may be retained, and how rejection/cancellation releases them. Do not describe pre-allocation/pinning admission as complete until this path is covered.

   **Gate:** increment 6.

**Closure of prior findings 1–7**

| Prior finding | Status | Evidence and remaining boundary |
|---|---|---|
| **F1 — outer metadata routing** | **Closed as a design correction** | P:778 and :894 now place recognition at entry to `StageDispatchEpoch`, before directory/disposition classification and admission. Source confirms `StageDispatchEpoch` at `StageStream.c:11296`, admission at `:11333`, and BP routing later at `:10910`. P:900 also carries a discriminator past the generic deny path at `:11431`. P:906–932 assigns failed CREATE, normal/draining post, CLEANUP and CLOSE ownership without generic routing. U4 must still establish actual IRQL, cancellation and deferral behavior. |
| **F2 — `_sendGate` dependency** | **Closed for the identified control-cycle contract; native proof open** | P:1004–1054 explicitly bypasses `_sendGate` for bounded metadata sends, retains common send lifetime, and requires snapshot-only fence callbacks. That breaks the stated SetPolicy → epoch → growth → registration cycle. It is a proposed refactor: `FilterPort.cs:93–123` still serializes sends, and `:745–759` drains them before closing. Separate receive progress remains open U5. |
| **F3 — noncached archive framing** | **Closed at layout/protocol level** | P:1352–1409 defines aligned strides, separate frontier slots and F1/F2/F3. Segment permissions now permit the required monotonic extension at P:824–828. Native persistence and complete envelope fit remain U4/U8 conditions. |
| **F4 — shared recovery** | **Partly closed** | Resource-only bases, linked ACK deltas, append location/intents, append-before-frontier recovery and successful InitialResolved are now specified. Findings 1–2 above leave successful-intent handoff and retained kernel capacity incomplete. |
| **F5 — renewed growth deadline** | **Closed as a design correction** | P:726–750 separates immutable per-I/O and semantic deadlines, limits subsequent sequences to remaining I/O time, includes reacquisition/recomputation, and rejects late adoption. No specified join/append/retry path grants another full interval. O1 selection and U6 feasibility remain open. |
| **F6 — waiter/pin bounds** | **Partly closed** | P:1534–1588 now supplies operation/node ownership, reserve-before-allocation rules, terminal winners and saturation failure. It also correctly counts retiring predecessor objects. Finding 3 leaves buffer pinning outside that account. The numerical choices are proposals, not measured or fully sized limits. |
| **F7 — anchors and owned MDL coverage** | **Closed as a documentation correction** | Binding, FileObjects, seed timer, StageDeleted predicate, caller flush and grant comparison anchors now match source. P:1492–1514 correctly distinguishes `:10927 → :5903/:5948` from unowned `:11044`; R4-MM01 requires owned routing and actual minors/completion ownership. This does not establish that owned MDL support currently exists. |

For **F2**, the source supports concurrent-handler feasibility: `Communication.c:1980` obtains a counted connection use, `:2003` allocates per-invocation scratch, and its message-acquisition path at `:1138` is a short reference operation rather than a callback-wide mutex. Policy draining occurs inside the policy handler (`Policy.c:1169`), not under a common message-dispatch lock. I found no repository-level reason that the proposed early metadata branch must serialize behind it.

That is not offline proof of simultaneous `FilterSendMessage` completion on the real port. U5 must demonstrate it. “Immediate Busy” is implementable as specified using a short intent-state snapshot and nonblocking namespace claim; calling existing blocking namespace/rundown helpers would violate that contract.

For **F3**, the byte arithmetic is consistent:

- The frame header occupies exactly 60 bytes; payload begins at 60.
- `AlignUp(60 + payload, A)` keeps successive frames disjoint.
- The frontier’s fields occupy 128 bytes; its digest covers bytes `[0,96)`, and remaining slot bytes are validated zero.
- At A=64 KiB, a maximum 128 KiB payload occupies a 192 KiB stride; the two frontier slots occupy 128 KiB.
- Alternating slots preserve the last selected frontier while writing the next. Recovery requires the retained append intent rather than treating a torn newer slot as permission to roll back.

Within the stated aligned-write/flush fault model, I found no append that rewrites committed frame sectors or the currently selected frontier. Compaction likewise copies before durable inventory selection. NTFS EOF/rename durability remains an explicit prerequisite; noncached I/O and checksums alone do not establish it.

Existing readers and compaction are **incompatible until deliberately replaced**: `StagedTerminalArchive.cs:397`, `:410`, `:435`, `:478` and `:545` implement contiguous version-1 frames, one frontier, tail truncation and replacement compaction. The revision correctly identifies those changes rather than claiming compatibility.

The prior review’s other sound conclusions survive this revision:

- Proposed ABI sizes still add up: 64-byte header, 96/112-byte negotiation payloads, 192-byte companion, 1224/128-byte fence exchange, 1208-byte ACK, 64/40-byte root exchange, 640-byte child request and 128-byte marker/inventory. The passive resource sizes remain unchanged.
- HighWater plus one canonical Latest entry still provides bounded semantic replay.
- Companion authority remains bound to exact identity and monotonic C/G.
- Reduction still joins driver retirement with service custody; mutable copies retain ReservedMax and original-stage release evidence survives slot reuse.
- I found no deliberate change to the approved 120-second allocation interval, four-copy formula, absence of a modern per-file cap, bound-head NotReady or unbound v1 behavior.

**U1–U8: what must be decided, and what can be proved where**

The dependency assignments are broadly right. The checklist needs one scheduling clarification: it mixes **contracts/facts required before implementation**, **implemented source required before first boot**, and **runtime controls requiring that implementation**. R3-M01’s protected epoch-closed execution cannot literally pass before increment 3 exists.

| Item | Before the dependent increment | Builder-native controls without booting the proposed kernel | Kernel review/runtime obligation |
|---|---|---|---|
| **U1 — boot/old instance; before 5** | Choose the boot-identity source and old-instance exclusion evidence. This needs an explicit mechanism now. `StageStream.c:4369` offers an existing BootId use, not sufficient proof for the proposed BootDomain. | Identity/clock APIs, restart persistence and representation experiments. | Review reload/rundown/adopter exclusion before first boot of increment 5; target evidence remains necessary. |
| **U2 — whole CREATE; before 5** | Complete the source ownership/state audit and choose prompt expiry versus separately owned cleanup. Include findings 1–2. | Agent receipt acceptance, exact request correlation, count reconstruction and cancellation/storage controls. | First-boot review must cover capture, provisional binding, all lifecycle calls, ExposeClaimed, callback completion and teardown. Actual races need kernel execution. |
| **U3 — release adapters; before 4** | Specify evidence for each slot role and each crash/unknown state. “Final close” without defining the owner is insufficient. | Real handles, sections, copies, deletion-pending objects and native release adapters can be exercised on a builder. | Driver stage-write retirement, paging/growth rundown and measurement capture require kernel review before boot. |
| **U4 — metadata/store; before 3** | Select supported exclusion, post ownership and persistence primitives. Durable replacement cannot remain an unnamed future barrier. | Relative noncached I/O, alignment, EOF/flush order, security/share exclusions and native replacement mechanisms. | Outer pre/post routing, draining, map incarnation/rundown and transitive lock order require first-boot review and subsequent protected controls. |
| **U5 — progress; before 3, fence specifics before 5** | **Choose the bounded receive-intake strategy.** P:688 correctly identifies the problem but does not choose a solution. Also assign negotiation/revoke send admission and teardown ordering explicitly. | Client lifetime, private buffers, cancellation and real-port concurrency where an appropriate existing server is available. Models alone do not prove port behavior. | Review new handlers and callback dependencies before boot. Prove metadata progress during epoch drain and prompt fence Busy on the implemented pair. |
| **U6 — owned MM; before 6** | Finish the Major/Minor/IRQL/resource/completion inventory, acquisition strategy and buffer-pin accounting. These are design inputs, not facts to discover after integration. | Native actors and user-side mechanisms provide inputs, not owned-stream proof. | Coherent growth/MM/MDL/pin/retirement review before first boot; routed execution and Verifier controls afterwards. |
| **U7 — trust scope; before 4** | Architectural scope decision, not a native-proof item. Retain the existing boundary explicitly or obtain a separately reviewed stronger architecture. | Cannot prove a privileged-erasure trust boundary through file tests. | A stronger boundary needs security review; a VM boot does not settle it. |
| **U8 — fit before 3; grammar/recovery before 4** | Pure maximum-size, padding, overlap, migration and selection models. Check complete Entry + ResourceClosure envelopes, not each bound separately. | Confirm modeled physical allocation and native crash classifications. | Review any changed kernel permissions. Archive codecs and selection models themselves do not require a kernel boot. |

Builder results remain mechanism evidence on the builder OS, not qualification of Windows 10 19045.2965. Component fault injection also does not by itself establish power-loss durability.

The new 32/256/64 limits have a useful ownership structure, but their **values are not yet justified**. Before increment 6, provide actual structure sizes and worst-case retained bytes, including cancellation owners and buffer/MDL custody, plus saturation evidence. There need not be numerical equality with the service’s 40-message capacity: retiring operations and retries can explain a difference, provided all populations remain accounted.

**Readiness and review contents**

**Increment 3 may start once its metadata-specific prerequisites are closed.** The minimal set is:

1. A settled U4 operation/role/exclusion/IRQL contract and concrete supported persistence sequence.
2. U5’s selected bounded intake strategy, complete send-class assignment and lifetime/teardown mechanism.
3. U8 physical-fit models covering aligned outputs, replacement overlap and shared controls.
4. Accepted outer pre/post ownership and send-progress contracts, including the required test cases.

Do not require completed protected R3-M01/M04 execution before writing the implementation. Require their coverage before implementation, the coherent implemented source review before its first boot, and their actual results afterwards.

The **increment-3 first-boot review** must contain both dispatch wrappers, tag-3 classification before existing tag/draining logic, failed/draining CREATE handling, CLEANUP/CLOSE and address reuse, connection/instance/unload rundown, authenticated control handlers, send/reply buffer lifetime, and the complete journal → budget → registration → native-I/O dependency graph. Include target/anchor exclusions, every actual role/query/import, physical accounting on failure, and preserved legacy behavior. Reviewing only the new metadata module is insufficient.

- **Increment 4:** close finding 1, U3/U7 and strict U8 archive/startup recovery; review retirement, receipt capture, release/custody, teardown and any added metadata permissions before boot.
- **Increment 5:** close finding 2, U1/U2 and fence-specific U5; review capture-to-callback CREATE ownership, deadline expiry, success/non-adoption receipts, ACK eviction and local cancellation.
- **Increment 6:** close finding 3, U6, measured bounds and owner-selected O1; review the complete growth/replay/companion/MM/MDL/paging/pin integration before boot.

Modern admission must remain closed through these increments until the complete readiness conjunction and matched-pair qualification pass. The new compaction protocol is not approval to expand M2 implementation beyond the owner’s required 10k workload.

**O1/O2 framing**

**O1 is now complete and accurate as a proposed choice.** It distinguishes per-I/O from per-RPC time, covers joins/reacquisition/append recomputation, explains repeated pauses during a long save and preserves private permanent failure. Three seconds remains unselected and requires measurements. The hard-real-time caveat at P:749–752 is appropriate.

**O2 is also accurately framed.** It includes rollback as well as erasure, identifies the inadequacy of installer ownership on the same machine, and asks for custody, availability, repair and uninstall/reset rules if stronger protection is required. Surviving-evidence holds remain required under the existing boundary. I select neither owner option.