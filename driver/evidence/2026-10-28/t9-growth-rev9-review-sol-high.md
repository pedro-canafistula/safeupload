# T9 growth protocol revision 9: independent review (Sol 6.1 high)

Reviewer: fresh read-only Codex session `01a184ce-85af-7661-ae3a-e4d4f9a479f8`, `gpt-6.1-sol`, effort high, standard tier, 2026-10-28. Subject: `d96f26de`. Verbatim report follows.

**REVISE — resolve the finding-record layout mismatch before implementing the passive binary codecs.** The out-of-line design otherwise provides a workable direction for §12.1.4. Full codec acceptance and qualification remain open.

Reviewed `d96f26de` at HEAD `b8e42ab9`; the subject document and tests are unchanged between them. Read-only and offline: no writes, builds, test execution, network or VM access.

1. **Medium — The normative finding layout and model disagree, permitting different reconstructed evidence from identical bytes.**

   **Document:** [protocol:3308](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:3308).  
   **Model:** [writer:1107](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:1107), [reader:1140](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:1140).

   The document orders fields as **member index, category, snippet length**. Both model directions use **category, member index, snippet length**.

   **Concrete bytes:** with two member names, the prefix `01 00 00 00 00 00 00 00`, followed by a valid snippet length/payload, means category 1/member 0 to the model and member 1/category 0 to the document. Both interpretations satisfy the stated ranges. File/chunk hashes cannot distinguish those interpretations.

   Select one exact order and align the document and model. Add an independently specified byte vector with differing category/member values; the current writer→reader round trips conceal the mismatch.

2. **Low — U8 retains the superseded inline-fit conclusion without identifying it as historical.**

   **Document:** [protocol:3919](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:3919).

   It still states that full independent Entry+closure maxima do not fit and retain the ledger.

   **Concrete input:** a 131,072-byte Entry core, 65,536-byte closure and 8,192-byte wrapper exceeded the old inline envelope. Revision 9 moves that Entry out of line; its stated reference/state/wrapper bound is **75,266 bytes**, within 131,072.

   Label the old conclusion as revision-8 history and state the remaining v4 actual-serializer obligation directly.

The remaining checks support the proposed architecture, subject to those corrections and the existing implementation gates:

- **Reference authority and ordering:** [§10.7:3280](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:3280) requires the persisted owner tuple, held exact identity, security, length, whole-file digest and complete payload correlation. The surrounding completion supplies slot/incarnation/claim authority. Under O2’s trusted-storage boundary, I found no missing binding that authorizes substitution or replay. Missing/truncated chunks, changed generation, mismatched records and same-byte replacement objects must yield Held.

  The [specified order:3435](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:3435) preserves the required dependencies: persisted creation uncertainty → capture/write/F1/EOF/F2 → immutable Prepared evidence → durable owning reference → promotion MayHaveIssued → native completion → durable journal completion → budget acceptance. Orphans remain charged. Lost or uncertain publication completion permits reconciliation/bookkeeping/Held, never another public mutation. This is a sound required ordering within §8.4’s stated guarantee boundary; native durability at every interruption remains unproved.

- **Bounds:** the producer constants and display pipeline support the conservative derivation. Aggregate raw-name bytes are bounded by `floor(4,194,304/3)`; escaping, replacement/separator allowance and surrogate-safe front coding give the selected **8,699,904 suffix units**. Current numeric, secret and password masks fit 32 units.

  | Calculation | Recomputed result |
  |---|---:|
  | `131072 + 65536 + 16384×(76+8) + 2×8699904` | **18,972,672 bytes** |
  | `ceil(18972672/130816)` | **146 chunks** |
  | Last chunk’s payload at that maximum | **4,352 bytes** |
  | `65536 + 146×131072` | **19,202,048 bytes** |

  Interning/front coding preserves the existing displayed names; finding records preserve order and multiplicity once the layout is corrected. The metadata projection retains the remaining approval fields. No required evidence is deliberately dropped or truncated.

  I independently checked the retained ASCII/non-ASCII approval and ledger files: their sizes and hashes match the receipt. The split accommodates those shapes. **Complete simultaneous v4 ledger/manifest fit remains an actual-codec acceptance obligation**, correctly left open in §12.1.4.

- **Accounting, GC and O3:** [protocol:3402](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:3402) explicitly adds physical evidence debt, including uncertain reservation and replacement overlap. O3 releases the delivered content slot’s responsibility while evidence remains charged. Shared ownership must persist before removing transfer/SID debt. GC requires stable reachability, irreversible admission closure, actual drain, exact deletion and persisted storage-release proof. Thus a crash after delete but before release adoption retains charge; selected historical authorization remains a root. I found no new contract-level refund or retirement shortcut.

- **Model quality:** the reported **50 new cases and 15 guard-removal counterexamples per configuration** are accurate. The counterexamples reject their selected invalid inputs with guards enabled and accept them with the corresponding bypass: digest, identity, generation/binding, presence, plus eleven owner-binding variations. They exercise those modeled comparisons.

  They do **not** establish complete durability or accounting transitions. [The lifecycle model:1365](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:1365) makes preparation atomic and `Crash()` preserves all modeled state. A crash between the final write and F2 cannot be represented. Shared accounting transfer, complete source grants, kind-2/hand-back payloads and maximal composed ledgers also await the explicitly required production controls.

- **Consistency and evidence:** the 192-byte reference, 256-byte headers, Base64 lengths and container arithmetic agree. Existing ledger/manifest/O3 limits and ABI sizes remain unchanged; role 21 and capability `0x100` are gated extensions. O1/O2/O3 remain consistent with the status plan. No checkbox or qualification gate is closed by the commit.

I verified the retained source, artifact, runner and result hashes. Results contain 368 distinct passing rows per configuration, including the claimed new cases; the final compile log records six passes. Diff checks and the offline documentation-link check passed, with zero new broken links. These receipts corroborate the author’s execution claims; they do not constitute fresh execution or v4 acceptance.

## Re-check (dd08c574, same reviewer resumed read-only): ACCEPT WITH CONDITIONS

**ACCEPT WITH CONDITIONS — for implementing the §12.1.4 passive codecs under revision 9.**

Both findings are closed. I found no new regression in `dd08c574`.

1. **Finding 1 — CLOSED.** [The document:3316](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:3316) now agrees with both model directions: Category@0, MemberIndex@4, SnippetUnits@8, UTF-16LE@12.

   I independently decoded the literal vector containing the original `01 00 00 00 00 00 00 00` counterexample. With names `["a","b"]`, the findings are `(1,"A","a")` and `(0,"B","b")`. Swapping the interpretation produces `(0,"A","b")` and `(1,"B","a")`: valid ranges, incorrect evidence.

   [The new oracle:1105](../../../agente/SafeUpload.Agent.Tests/GrowthArchiveContractModelTests.cs:1105) checks independently specified decoded values and exact writer bytes. I also verified that the retained temporary mutant changes only the reader’s field order; its hashed results record the three stated failures, including both new controls.

2. **Finding 2 — CLOSED.** [U8:3943](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:3943) explicitly labels the inline overflow as revision-8 history, states the **75,266-byte** v4 bound, and preserves the actual simultaneous serializer/strict-reader/maximal-shape obligations.

The diff adds controls and clarifies the contract. It changes no product source, ABI size, evidence limit, owner decision, readiness gate or checkbox.

Remaining conditions:

- **[before-use passive codecs / before dependent increment-4 consumers]** Complete and independently accept §12.1.4’s actual v4 codecs, strict readers, selectors and transitions. Prove complete simultaneous legal shapes, producer-derived bounds, lossless evidence reconstruction, the independent finding vector, limit+1 refusal before native issue, exact owner binding, replay, accounting transfer and GC. Reproduce both measured ZIP cases. Passing surrogate models cannot discharge this condition.
- **[before-first-boot]** Independently review integrated role-21/capability/marker handling, native I/O barriers, physical accounting, proof retention and rundown. Complete applicable agent, kernel/static/import and native prerequisite gates.
- **[before-qualification]** Complete N-U8-04 and carried selector/migration/O3 controls: partial/orphan/substituted evidence, lost barrier/completion/budget replies, restart, slot reuse, retained readers, shared ownership and exact release. Require matched artifacts, independent mutation/byte observations, Verifier and separate restoration.

Read-only verification confirmed receipt source/artifact/runner/result hashes, **370 distinct passing rows per configuration**, six recorded compile passes, clean commit diff checks and zero new broken documentation links. I independently checked the byte vector in memory; I did not rerun builds or model executables. Nothing was written, and no network or VM was accessed.