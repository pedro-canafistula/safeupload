**REVISE — for starting increment 3 source implementation as currently described.**

The three residual findings now have substantially adequate contract text. The remaining coding blockers are an incorrect physical-output fit model and an increment-3 boundary that assigns later integration work to its own verification. Neither requires deciding O1 or O2.

Reviewed branch `feat/driver-m2`, HEAD `8ae881b9b9878b905c7457a1f931d781e71d8b1d`, including both prior reviews, the 2,028-line proposal, fit models and relevant cited implementation paths. Work remained read-only and offline. I independently recalculated the arithmetic; I did not execute the C# suite, build, contact a builder or access a VM.

Below, **P** means `driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md`; **M** means `agente/SafeUpload.Agent.Tests/GrowthArchiveFitModelTests.cs`.

1. **High — U8 undercounts the peak allocation of padded native outputs. Close before coding increment 3.**

   **Document:** [P:1191](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1191), `:1205–1208`, [P:1528](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1528), `:1549–1556`.  
   **Model/code:** [M:75](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Tests/GrowthArchiveFitModelTests.cs:75), `:99–105`, `:146`, `:326`; [StagedSpaceBudget.cs:354](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:354), `:429–436`.

   The native sequence writes an aligned padded extent **before** setting exact logical EOF. The output model instead charges `Round(logicalBytes,U)` without accepting the independent I/O alignment **A**.

   **Concrete failure:** a 192-byte companion with A=65,536 and U=4,096 receives a modeled allocation of 4,096 bytes, but its first padded write spans 65,536 bytes. A failure before EOF normalization can leave that entire extent allocated. Measuring allocation after EOF—or subsequently holding admission—does not establish reserve-before-write.

   The same omission affects tiny marker/inventory outputs, variable-length JSON, replacement overlap and failed residue. Even the supplied U=512 vector charges a 128-byte output as 512 bytes, although the archive/native alignment contract starts at 4,096.

   **Required correction:** model each output’s logical length, padded write extent and peak allocation separately. At minimum, precharge the allocation-unit rounding of the padded extent, plus every simultaneously retained predecessor/replacement/residue. Reduce only after an explicit supported measurement/release transition. Exercise A and U independently, including A>U.

   The existing worst-case envelopes might still fit after correction; this finding does **not** establish that their sizes must increase. It establishes that the claimed fit proof is incomplete.

   Add a mutant that charges logical EOF instead of padded peak extent and require the admission/conservation check to reject it. N-U8-01 must observe allocation before normalization and at injected failures, not only the final file.

2. **Medium — Increment 3’s implementation and exit obligations still depend on increments 4–6. Settle the cut before coding.**

   **Document:** [P:1040](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1040), `:1177–1181`, `:1267–1272`, [P:1887](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1887), `:1915`, `:1975–1978`.  
   **Code:** [StagedRequestDispatcher.cs:17](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/StagedRequestDispatcher.cs:17), `:87–130`; [Communication.c:1754](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Communication.c:1754); [ResourceStateCodecV2.cs:66](/home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Interception/ResourceStateCodecV2.cs:66).

   The metadata module, native store and paired transport infrastructure can be implemented independently. However:

   - R3-M01/M04 require a counted application operation waiting for growth, ledger/companion accounting and a growth reply. The production growth consumer belongs to increment 6.
   - Fence/ACK/snapshot behavior requires increment 5’s intent registry.
   - N-U8-02/03 require archive classification, migration and selection implemented in increment 4.
   - R3-M03’s reduction stress requires increment 4.
   - “After 1” remains a real dependency: HEAD has the strict v2 codec and the new fit tests, not the proposed complete schema-3 codec and transition module.

   **Concrete failure:** a worker attempts to make the increment-3 exit table green by introducing partial growth admission, archive consumers or CREATE fencing. Alternatively, primitive-only tests get reported as completed end-to-end rows.

   **Required correction:** name the increment-3 deliverable and its test seams explicitly. It should include provisional pairing/registration, metadata pre/post routing, bounded native store operations, physical accounting and lifetime infrastructure, with Commit remaining NotReady. Use a separately identified diagnostic actor to hold an epoch and exercise metadata progress if needed; retain the real growth-dependent assertions for later integration.

   Likewise, distinguish raw archive-storage primitives from the increment-4 archive selector/recovery implementation. Complete increment 1’s required source contracts before their increment-3 consumers, or explicitly review an opaque bounded-buffer store interface that avoids that dependency.

**The three residual findings**

| Residual | Assessment |
|---|---|
| Successful handoff versus InitialResolved | **Closed in the text.** P:574–580 forbids candidate preparation, shared selection and ledger deletion before durable InitialResolved. P:1418 excludes Open/Attached/Closing/Fenced successful bases. The delayed-query/immediate-close crash appears at P:612, `:1702` and R3-A05/R4-H01. This directly fixes the race; current archive eligibility at `StagedTerminalArchive.cs:88/:119` supplies no equivalent protection. |
| Retained successful kernel shells versus 8/4 durable debt | **Closed at contract level.** P:626–678 specifies eight global kernel credits, reservation before capture, retention through actual ACK eviction, reconnect snapshot reconciliation and bounded ACK scheduling. Debt can reach zero while occupancy remains eight. The model exercises that distinction. U1/U2 and the actual registry/eviction implementation remain increment-5 gates. |
| User buffers/MDLs before crossing admission | **The missing ownership contract is supplied; U6 remains open.** P:1836–1879 moves owned-I/O admission before buffer locking/resource waiting, distinguishes borrowed and Filter Manager-created MDLs, and requires byte/PFN/cancellation accounting. Source confirms the earlier locking path at `StageStream.c:4824–4832`. Actual minor-function routing, legal completion ownership and measured bounds still gate increment 6. |

One wording correction should accompany U6: P:1843–1845 groups paging with completion/release minors as finding an original counted owner and releasing its credit. Paging bridge work has its separate PagingRundown ownership, as P:1855 correctly says. State those cases separately; paging does not generally release an owned nonpaging credit.

The earlier confirmed ABI sizes remain arithmetically unchanged. ShellSnapshot adds a new payload: `32 + 8×1232 = 9888` bytes, plus the 64-byte control header. Its 24-byte side-port context is also new. These need their own layout/mutation controls, but do not resize the confirmed exchanges.

**Increment-3 readiness against the second review’s minimal set**

| Item | Result |
|---|---|
| **U4: operation/exclusion/IRQL and persistence sequence** | **Substantially settled as a conservative contract.** Relative create, padded write, F1, exact EOF, F2, relative rename and F3 are concrete. Root no-SHARE_DELETE and replace-target SHARE_DELETE plus store exclusion resolve the earlier sharing contradiction. Native feasibility and implemented cancellation/rundown still require proof. |
| **U5: bounded intake, sends and lifetime** | **Sound architectural choice, conditional on implementation/native proof.** Physical growth intake removes the existing ordinary-credit bottleneck. Independent metadata sends remove the `_sendGate` edge. Shared lifetime protection remains explicit. |
| **U8: aligned outputs, overlap and controls** | **Not closed before coding**, because of finding 1. Frame arithmetic and combined-envelope arithmetic are correct; generic output peak-allocation accounting is not. |
| **Outer pre/post ownership and tests** | **Adequate contract for implementation.** Recognition, refusal routing, context discrimination and failed/draining CREATE/CLEANUP/CLOSE ownership are specified. The actual source must receive the coherent pre-boot review. |

For **U4**, the Microsoft references are relevant to the narrow API claims. They do not establish an atomic durable transaction across these files or an NTFS directory-entry persistence guarantee. P:1217–1232 explicitly acknowledges that limitation and requires conservative reconstruction/holds. F3 must therefore remain a requested flush and process-crash mechanism boundary, never a certificate of power-loss-safe namespace commitment.

The cited pages were not fetched in this offline review; I cannot certify their current wording. The implemented review should include the exact native create, rename, EOF, flush and alignment-query contracts actually used. In particular, the existing helper at `StagedHandbackCopier.cs:884` uses **FileRenameInformationEx**; the proposal selects **FileRenameInformation**. Reusing its mechanics is reasonable, but its recorded behavior does not prove the selected class.

For **U5**, the proposed cycle break is credible:

- `FilterPort.cs:108` currently serializes metadata registration behind SetPolicy.
- `Policy.c:1155/:1169` closes and drains the epoch.
- `MinifilterInterceptor.cs:365` currently reserves ordinary reply credit before receiving.
- P:754–789 separates growth reception physically, and P:1118–1142 gives metadata controls independent nonwaiting admission.
- P:1155–1167 retains native handle/buffer leases until return.

That removes both identified dependency edges without discarding send protection. It does not prove real-port concurrency or finite teardown. Also preserve the dispatcher’s distinction between accepted work and failure credits: accepted dispatch releases its pre-dequeue credit at `StagedRequestDispatcher.cs:130`. Forty growth failure/intake credits are not a forty-message bound on all accepted-plus-rejected retained work.

**Fit models and ledger retention**

The following calculations are correct:

- `128 KiB + 64 KiB + 8 KiB = 200 KiB`.
- With closure=64 KiB and wrapper=8 KiB, Entry must be at most **56 KiB**.
- At A=64 KiB, the maximum frame stride is **192 KiB**.
- Two frontier slots plus that frame occupy **320 KiB**.

Consequently, “full independent Entry+Closure maxima do not fit; retain the ledger” follows from the stated bounds.

Retaining the exact ledger preserves accounting if refusal occurs before selecting a handoff or removing its SID/global debit. It must neither create another reservation charge on retry nor infer release from failed handoff. Any candidate or residue already created remains independently accounted. P:1519 deliberately permits conservative overlap between charge classes during a successful handoff; that is distinct from duplicating a replay’s debit.

The boundary vectors, overflow checks, combined-envelope refusal and debt-versus-occupancy tests are useful. Some purported mutation controls are weaker:

- `ApprovedParameters` at M:342 checks equality with constants.
- M:312’s `Math.Min` assertion does not exercise send admission.
- `Reconnect()` copies both dictionaries; it does not exercise unmatched snapshot reconciliation.
- Selection tests establish numeric range continuity, not preservation of base/delta witnesses or migration capacity.

Those limitations are acceptable only with the document’s later codec/recovery gates retained. They cannot close the omitted peak-allocation proof.

**Builder-native experiments**

The proposed experiments cover the right mechanisms, but need these explicit acceptance details:

- **[before-first-boot]** Run positive baselines with the exact role access masks, sharing and native information classes. FullControl handles or a different rename class cannot validate the selected contract.
- **[before-first-boot]** Record logical length, padded extent, EOF and AllocationSize at every relevant boundary, including before EOF normalization and with retained failed output.
- **[before-first-boot]** Predetermine each fault’s expected classification: committed, recoverable bookkeeping, or held. A hold may satisfy preservation; it cannot satisfy a positive completion/recovery assertion.
- **[before-first-boot]** Exercise successful replacement while the old target remains held. Account the deletion-pending predecessor until the store’s relevant handles, operations and pins have drained.
- **[before-first-boot]** Distinguish native failure from lost completion/bookkeeping. Observe mutation counts independently and interrupt recovery again to prove no repeated successful rename.
- **[before-first-boot]** For alignment negatives, specify whether the adapter rejects before issue or the native API rejects. Do not infer that every device must reject every misaligned buffer identically.
- **[before-qualification]** Complete actual archive migration, tail/frontier, base/delta and selected-range recovery controls after increment 4. Arithmetic range tests cannot supply those results.

Process termination remains mechanism evidence, not physical power-interruption evidence. Builder OS results remain separate from target 19045.2965 qualification.

**Pre-boot review content**

Retain the second review’s complete list. Add explicit coverage of the new two-port architecture and corrected physical accounting:

- Both dispatch wrappers, tag-3 classification before draining/epoch decoding, matched-invalid denial telemetry, failed/invalid successful CREATE, CLEANUP/CLOSE and address reuse.
- Both server ports; provisional pairing; process/token/SID/cookie authentication; wrong-channel rejection; disconnect of either member; callback-source removal and group rundown.
- Every send class, receive OVERLAPPED/event, accepted/rejected reply owner, queued cancellation and native buffer/handle lease.
- Root/target exclusion, store namespace claims, every actual role/query/import, four-child-handle scheduling and preallocated PASSIVE rundown ownership.
- The complete journal → budget → registration → native-I/O graph, including failure cleanup.
- Peak padded allocation, replacement predecessors, failed residue, maintained totals and release evidence.
- Explicit dormant integration boundaries and regression evidence preserving shipped unbound v1 behavior.

**Required order**

1. **[before-coding]** Correct the A/U peak-output model and its conservation/mutation controls.
2. **[before-coding]** Define the bounded increment-3 source/test cut and settle its increment-1 interfaces/prerequisites. Preserve all later integration assertions.
3. **[before-first-boot]** Complete the coherent source review above, applicable native mechanism controls, paired WDK/static/import gates and full agent delivery matrix.
4. **[before-qualification]** Complete increment-4 archive/custody proofs, increment-5 CREATE/shell/fence proofs and increment-6 routed growth/MM/MDL proofs, followed by matched-pair qualification.

Modern admission remains closed. O1 and O2 remain undecided.