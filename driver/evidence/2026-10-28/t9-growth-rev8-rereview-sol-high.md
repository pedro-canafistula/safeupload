# T9 growth protocol revision 8: independent re-review (Sol 6.1 high)

Reviewer: the same independent Codex `gpt-6.1-sol` (effort high, standard tier) session `01a18477-defe-7f63-92b6-e9f4042460fd`, resumed. The resumed sandbox was workspace-write by default; the brief required no writes and the working tree was verified unchanged afterwards. Subject: `4b2bdfe6..44f8b589`. Verbatim report follows.

**REVISE — for starting increment-4 consumer coding after increment 3’s first boot.** Findings 2–5 are closed at the contract/model level. Finding 1 remains open. §12.1.4 is sufficiently concrete to implement the passive prerequisites, but those prerequisites must pass before consumers. One additional recovery-model defect remains below.

Reviewed `4b2bdfe6..44f8b589` at HEAD `44f8b589`, read-only and offline. Nothing written; no tests, builds, network, builders or VMs used. Counterexample results below follow source reasoning.

**Disposition of findings 1–5**

1. **Finding 1 — OPEN; the implementation work list is adequate.**

   [§12.1.4:3443](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:3443) provides a usable dependency order: complete types → leaf codecs → composed ledger/journal codecs → archive codecs/selection → transitions → complete serialization limits → independent acceptance.

   It covers the important compositions: both retained O3 completions, nested authorization Entries, explicit approval, native facts, legal simultaneous pending states, closure/delta/legacy records, and bounded migration controls. It also preserves the distinction between typed scaffolding and an accepting codec.

   **Original counterexample:** a 65,536-byte authorization Entry inside a 65,536-byte ledger still has no actual product serializer demonstrating rejection. Step 6 explicitly requires whole-record refusal before creation/promotion; step 7 requires a reviewed format change if ordinary supported combinations cannot progress.

   **Before increment-4 consumers:** the actual composed serializers, strict readers and transition implementation must exist, pass full-shape/boundary controls and receive independent acceptance. A limit constant, passing surrogate model or increment-3 boot cannot substitute.

2. **Finding 2 — CLOSED at design/model level.**

   [§9.3.2:2421](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:2421) explicitly persists the fingerprint and relates it to the checked operation, inspection, policy recheck and consumed justification.

   **Original counterexample:** in [M:814](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:814), the JsonIgnore-style projection still collides, while the new explicit DTO produces different bytes for fingerprints `AAAA…` and `BBBB…` at policy version 7. Reading and rewriting preserves each fingerprint. Missing and mismatched fingerprints are rejected.

   Actual product codecs and producer correlation remain prerequisites; the model is not their implementation.

3. **Finding 3 — CLOSED.**

   [M:1495](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:1495) retains `_issue` across restart and gates native mutation through `RecoveryDecision`.

   **Original sequence:** `NativeSuccess → Restart → NativeSuccess` now refuses the second mutation for all three proof kinds. Bound proof permits completion bookkeeping; unbound and hand-back without surviving proof hold. MayHaveIssued without any result also holds.

   The added revision/replay control additionally advances R from 9 to 11, accepts at 12, then replays the original zero-acceptance completion after reuse and restart without another commit or refund.

4. **Finding 4 — CLOSED.**

   [M:1605](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:1605) now checks held owner counts as well as witness counts. `OwnerInventory` separately models admission closure and actual drain.

   **Original input:** held `Readers=1`, matching proof `Readers=0/Persisted=true` now returns false. Cancellation and restart retain the reader; witness persistence refuses until that owner completes. New admission after closure refuses. Reader, section and late-operation cases are covered.

5. **Finding 5 — CLOSED for the original frame-validation defect.**

   [M:1164](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:1164) now receives independent observed segment bytes and candidate bytes, validates the selected prefix and compares the target frame before returning `BookkeepingOnly`.

   **Original inputs:** a zero candidate, corrupted selected payload/hash/padding, and corrupted earlier-prefix bytes now produce `Hold`. The added scenarios exercise both physical slot parities and repeated frontier-only/bookkeeping recovery.

**Additional finding**

**Medium — Recovery can authorize a frontier repair using the previous append’s transaction ID.**

Document: [P:3007](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:3007). Model: M:1175–1209.

The model checks distinct transaction IDs when the target frontier already exists, but not before `IssueOnce` or `FrontierOnly`.

**Concrete input:**

- Start with `RecoveryScenario(2)`: selected slot 1 has sequence 2, end 12,288, transaction `Segment`.
- Replace slot 0 with the valid initial frontier: sequence 1, end 8,192, zero transaction.
- Keep the complete valid observed prefix and candidate.
- Change `plan.Transaction` to `Segment`, matching the selected frontier’s transaction.

`Recover()` returns **`FrontierOnly`**. Following that decision writes sequence 3 with the same transaction as sequence 2. Subsequent `SelectSlots()` rejects the pair because their transaction IDs are equal.

**[before-coding model/selector acceptance]** Reject `plan.Transaction == expected.Transaction` before either issue or repair. Add negatives with a valid older inactive slot and a torn inactive slot, plus positive recovery cases. This is a model defect that could guide incorrect recovery; no production runtime regression is demonstrated by this docs/models-only commit.

**Remaining conditions**

| Timing | Required condition |
|---|---|
| **before-coding** | Fix the additional recovery case. Complete and independently accept §12.1.4’s actual passive codecs, transitions and full serialization proof before dependent increment-4 consumers. Demonstrate supported-shape progress and refusal before mutation. |
| **before-first-boot** | Review the integrated retirement/rundown, release adapters, O3 proof retention, hand-back identity/export capture, journal→budget ordering and teardown; complete applicable agent/kernel delivery gates. |
| **before-qualification** | Run actual selector/migration and custody crash controls, including repeated interrupted recovery, independent mutation counts, physical accounting, slot reuse, matched artifacts, destination bytes, Verifier and separate restoration. |

The receipt’s source, artifact, result and compile-log hashes match the retained files. It reports 309 passing cases per configuration and six local compile passes; I did not execute them. No ABI resize, owner-decision reversal or silently closed readiness gate appears in this diff.