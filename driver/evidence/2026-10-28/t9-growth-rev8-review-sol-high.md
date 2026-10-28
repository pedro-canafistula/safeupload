# T9 growth protocol revision 8: independent review (Sol 6.1 high)

Reviewer: Codex `gpt-6.1-sol`, effort high, standard service tier, fresh read-only session `01a18477-defe-7f63-92b6-e9f4042460fd`, 2026-10-28. Subject: revision 8 at `7869a8ac` (`fdb8c903` + `7869a8ac`). Verbatim report follows.

**REVISE — for starting increment-4 integration after increment 3’s first boot.** The revision correctly preserves an unmet before-coding serializer prerequisite. The proposed authorization representation and several model controls also need correction.

Reviewed `feat/driver-m2` at `7869a8ac`, read-only and offline. No writes, builds, network, builder or VM access. The supplied diff range starts at `fdb8c903`, so excludes that commit’s changes; I additionally inspected `fdb8c903^..fdb8c903` to cover both intended revisions.

Below, **P** is [UX-LARGE-GROWTH-PROTOCOL.md](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md), and **M** is [GrowthArchiveContractModelTests.cs](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs). Model counterexamples are derived from source; I did not execute them.

1. **High — The actual serializer prerequisite remains unmet. Increment 3’s first boot cannot discharge it.**

   **Document:** [P:2884](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:2884), P:3271, P:3312.

   The audit accurately says complete schema-3 serializers and their maximum-shape/limit+1 proof do not exist. The models measure synthetic envelopes, strings and control rows. They do not serialize the complete proposed ledger, including both retained O3 completions, authorization Entries, claims, native receipts and replay evidence.

   **Concrete input/crash:** an otherwise valid authorization Entry of 65,536 encoded bytes cannot fit inside the 65,536-byte ledger once wrapped in an O3 completion. If discovered only after successful promotion, the public mutation has completed but its accounting transfer cannot be persisted. FullDebitHeld is the correct outcome; repeated ordinary cases could nevertheless exhaust staging capacity.

   **[before-coding]** Complete the prerequisite passive codecs and actual serialization controls before dependent increment-4 consumers. Include whole-envelope depth, default escaping, both completion cells and rejection before native creation. Where supported ordinary shapes cannot progress, obtain the documented reviewed format delta. This is an acknowledged readiness blocker, not a falsely closed checkbox.

2. **Medium — The persisted publication approval needs an explicit policy-fingerprint representation.**

   **Document:** [P:2330](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:2330), P:2360.  
   **Source:** [InspectionResult.cs:44](../../../agente/SafeUpload.Agent.Core/Domain/InspectionResult.cs:44), [InspectionService.cs:108](../../../agente/SafeUpload.Agent.Core/Application/InspectionService.cs:108).

   `PublicationApproval` selects the existing `{Operation, Inspection, Justified}` values, but `InspectionResult.PolicyContentFingerprint` has `[JsonIgnore]`. That fingerprint is explicitly required by the existing current-policy approval and justification checks.

   **Concrete byte input:** two inspection results differing only in `PolicyContentFingerprint` serialize identically with the existing type’s JSON contract. For a clean publication, the pre-promotion Entry does not supply that missing inspection fingerprint. After journal completion, crash and policy replacement, the proposed snapshot must distinguish the policy actually checked without consulting today’s policy.

   **[before-coding]** Specify a strict durable approval schema that explicitly preserves the fingerprint and validates its relationship to the operation, inspection and justification evidence. Require a round-trip test proving two different fingerprints remain distinguishable. “Complete existing values” is insufficiently precise given the existing serialization attribute.

3. **Medium — The O3 model permits a second public mutation after restart. Its crash tests never attempt it.**

   **Document:** [P:2404](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:2404).  
   **Model:** [M:1182](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:1182), M:1208.

   This sequence is permitted by the model:

   ```text
   NativeSuccess()
   Restart()
   NativeSuccess()   → Copies=2, Renames=2
   ```

   `Restart()` clears `_liveSuccess`; `NativeSuccess()` checks neither a durable MayHaveIssued claim nor `_boundFacts`. The existing tests attempt completion after restart and inspect counters, but never challenge the forbidden mutation entry point.

   **Crash point:** rename succeeds before the completion journal becomes durable. Recovery must hold or finish exact bookkeeping; the model instead allows another native success.

   **[before-coding model acceptance]** Represent durable issue uncertainty and drive the actual recovery decision through it. Assert that another copy/rename is refused after this crash for all three proof kinds. Also cover unrelated budget-revision changes and replay of the original zero-acceptance completion, rather than only the constructed positive-revision receipt.

4. **Medium — The physical-release model tests asserted drain fields, not drain of the held owners.**

   **Document:** [P:2201](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:2201), P:2212.  
   **Model:** [M:1225](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:1225).

   `CanRelease` ignores `held.Readers`, `held.Sections` and `held.Operations`. With matching identity/incarnation/revision, `held.Readers=1` and `proof.Readers=0` returns true.

   **Interleaving:** a parser retains a duplicate while cleanup presents a zero-reader witness for the same claim. There is no modeled admission fence, reader disposal or joined operation completion that establishes which count is authoritative. The current mutants merely change the proof’s count to one.

   **[before-coding model acceptance]** Model owner admission, closure and actual drain separately from the persisted witness. Exercise a reader surviving cancellation, a native operation completing late, and attempted admission after closure. Keep the current representation tests, but do not count them as every-role drain proof.

5. **Medium — Frontier recovery can report bookkeeping-only without validating the committed frame.**

   **Document:** [P:2924](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:2924).  
   **Model:** [M:955](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:955).

   When the target slot validates, `Recover()` checks sequence/end/transaction and immediately returns `BookkeepingOnly`. It never parses or compares the selected frame. Indeed, supplying a 4,096-byte zero candidate with a matching target end still reaches that result. Committed-frame bytes are absent from the model’s inputs.

   **Crash/byte input:** target frontier is valid at sequence 2/end 12,288, but the selected frame contains a changed payload, bad hash or nonzero padding. The document requires Held; the model cannot express that defect.

   Recovery also fixes the old slot at index 0 and target at index 1, leaving alternate-parity recovery untested.

   **[before-coding model acceptance]** Supply independent segment/frame and candidate bytes, validate the selected prefix before bookkeeping, and test both slot parities and repeated recovery interruption.

The remaining contract checks support these conclusions:

- **O3 binding and ordering are substantially sound in the text.** The 2,048-byte layout and 2,732-character Base64 length add up. Kind=5 is distinct from archive RecordKind values; Stage/Snapshot cannot use it. Retained receipt lookup precedes reused-slot access, journal completion precedes budget adoption, unrelated holds survive, and later legitimate public edits do not invalidate a proved historical transfer.
- **The cited completion sources exist.** Bound native receipts contain the stated seven fields and 2,112-byte facts. `ConfirmedPublication` retains the live output identity, operation and inspection; persisted unbound Released does not. Hand-back Verified likewise omits output identity. The document correctly identifies these limitations. Existing hand-back path/digest recovery must therefore gain the proposed identity-bound adapter before supplying modern release authority.
- **U3’s owner inventory is materially improved.** It includes kernel stage custody, parser duplicates, publication owners, hand-back leases and metadata predecessors. `EndSnapshot` really only drops the memory lease. Actual drain, release persistence and shared metadata reconstruction remain implementation obligations.
- **U8’s migration holds are conservative.** The bounded cursor, one-at-a-time assignment, preservation comparison and >32-target stop retain sources and charge. The migration tests using `{}` or `{"saved":true}` establish byte-layer behavior, not migration progress for validated terminal Entries.
- **O1/O2/O3 match the recorded owner decisions.** I found no changed ABI-size conflict, silently closed checkbox, weakened qualification assertion or new activation authority.

The saved diagnostic receipts match the current document/test source hashes and contain 268 passing rows per configuration: 198 contract cases and 70 fit cases. This corroborates the reported local execution counts; it does not resolve the model gaps above.

| Timing | Required work |
|---|---|
| **before-coding** | Resolve the approval representation and model findings; complete the prerequisite actual schema-3 serializer/strict-reader/transition proof, including full retained evidence, depth and limit+1 controls. |
| **before-first-boot** | Independently review coherent retirement/capture/paging/growth rundown, role adapters, O3 source retention, hand-back identity/export capture, journal→budget ordering and teardown. Complete the required agent matrix and applicable kernel/static/import gates. |
| **before-qualification** | Execute R3-X/R4-H/R5-S04/S05 and N-U8-02/03 with actual selectors/adapters, lost completions, ambiguous persistence, slot reuse and repeated recovery. Require independent mutation counts, physical totals, destination bytes, matched artifacts, Verifier and separate restoration. |

U1/U2 remain increment-5 prerequisites; U6 and implementation of decided O1 remain increment-6 prerequisites. No further O1/O2/O3 owner decision is needed.