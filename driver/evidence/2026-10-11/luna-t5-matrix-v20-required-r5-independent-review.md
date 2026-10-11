# Independent security/tool review: v20 required matrix R5

**Scoped disposition: GO for the frozen R5 matrix tools to drive a fresh diagnostic Windows matrix only.** R5 closes the new managed-test admission gap by requiring all 19 v20 methods and the exact reviewed case displays in each normal/feature Debug/Release profile. The public-discovery check uses a case multiset, so omission, substitution, and consistent duplicate rows fail before TRX results are accepted. This review does not establish that Windows tests ran or passed, nor does it approve installation, pairing, runtime use, or product qualification.

## Scope and integrity

The reviewed candidate is `output/review-candidates/m2-t5-matrix-v20-required-1011-r5/src`. Its root capture receipt is `driver/evidence/2026-10-11/m2-t5-matrix-v20-required-r5-root-review-capture.json`, SHA-256 `a4fc654e0345d8d08daf9f0145502b4335d6ba3078bb8182c87145516303522a`. The receipt records a closed six-file source set, frozen equality, `AuthorFrozen: true`, and `SourceAccepted`, build, pair, Windows-matrix, upload, and VM qualification flags as false. The author note is SHA-256 `1fd2b0e7e7cb67a956e1e309a9d969ee317a8d2337739083f0632c29f8ac2266`; its delta is SHA-256 `2cff98f21091a6a963f1f67053214a4dc39b7f30137436d59bb72e6a26432e88`. The prior R4 capture SHA-256 is `b737dee67cce0a14b45d566f6fde4689325d8acf6470c027f39929b85503f3b7`.

I checked the exact frozen file set and all six live and frozen hashes before and after the review; both sets matched the R5 receipt each time. R5 changes only `Invoke-ExactAgentMatrixBuild.py` and `Invoke-ExactAgentMatrixBuild.SelfCheck.py` relative to R4. `Build-ExactAgentMatrix.ps1`, both source-preparation helpers, and `remote_ps.py` remain byte-identical to R4. I made no source changes and performed no Git, network, builder, VM, upload, package, or product operation.

| R5 source input | SHA-256 |
|---|---|
| `driver/scripts/Build-ExactAgentMatrix.ps1` | `90aebd88352c4c23265508a244437895d0a84218bc7815d031de7e81bec45ac7` |
| `driver/scripts/Invoke-ExactAgentMatrixBuild.SelfCheck.py` | `4ab066f1d1f691f155bb62126e1dc389a311f6c61e05cf0db238ca84b9fa74f6` |
| `driver/scripts/Invoke-ExactAgentMatrixBuild.py` | `ecd48f18f81542398e7a2aaab0d8e8e932d6d42122797a4150c6b9d971a9c4ca` |
| `driver/scripts/Prepare-ExactAgentWorktreeSource.py` | `137002d23758ca8bd700abce891c2e3e0f7b43614eedfd38ffa944ba0b27de83` |
| `driver/scripts/Prepare-ExactWorktreeSource.py` | `67386727e63ac8ff961548101276bdaa4b9bf0d0f970d23e801a915e6adff107` |
| `driver/scripts/remote_ps.py` | `39ed7a7892555d61b1577380fd84888ab39278a0115a7ca9b47b16ca6c52995b` |

## Review findings

The production verifier now requires 19 v20 methods in every profile. Its case inventory requires the existing identityless/different-epoch theory rows exactly, the new `Legacy_v19_create_after_preserves_all_legacy_chain_and_rejects_mixed_epoch_request` fact as a bare FQN display, and the three exact `receiptShape` rows `missing`, `pending`, and `wrong-receipt-tuple`. I matched all 19 names to decorated test declarations in the frozen R13 managed-test source. The fact display is represented as one required row; the theory values are represented individually.

The exact required public displays are:

- `SafeUpload.Agent.Tests.StagedTransferAllocatorTests.V20_create_after_rejects_identityless_or_different_epoch_v1_before_child_intent(parentEpochShape: "identityless")`
- `SafeUpload.Agent.Tests.StagedTransferAllocatorTests.V20_create_after_rejects_identityless_or_different_epoch_v1_before_child_intent(parentEpochShape: "different-epoch")`
- `SafeUpload.Agent.Tests.StagedTransferAllocatorTests.Legacy_v19_create_after_preserves_all_legacy_chain_and_rejects_mixed_epoch_request`
- `SafeUpload.Agent.Tests.StagedTransferAllocatorTests.V20_create_after_requires_exact_op19_before_any_journal_mutation(receiptShape: "missing")`
- `SafeUpload.Agent.Tests.StagedTransferAllocatorTests.V20_create_after_requires_exact_op19_before_any_journal_mutation(receiptShape: "pending")`
- `SafeUpload.Agent.Tests.StagedTransferAllocatorTests.V20_create_after_requires_exact_op19_before_any_journal_mutation(receiptShape: "wrong-receipt-tuple")`

For each profile, the verifier binds every public VSTest display to exactly one discovered fully qualified method, requires every method to have a public display, then compares each required method’s discovered display multiset to its exact expected multiset. A consistent omission, an added or substituted argument, and a duplicate row all differ from that expected multiset. The later exact discovery-to-user/SYSTEM/merged TRX comparisons preserve the same cases through execution, while complete passing counters, unique execution IDs, and required-result-ID cardinality ensure each exact required case passed once in the correct partition.

I also confirmed the unchanged gates remain in the frozen R5 verifier: all four normal/feature Debug/Release profiles and warning/error summary rows; required public discovery and discovery-FQN binding; user/SYSTEM/merged case and result-ID equality; user identity and SYSTEM identity plus job/task cleanup evidence; required SYSTEM test families; MachineFact SYSTEM-only routing; release package membership, path safety, hashes, service executable presence, and summary hash binding; and stale `SafeUploadOwnedWinFspPrototype` profile rejection. R5 does not modify the builder, source-capture, package, or remote execution helpers.

## Independent controls

I ran the frozen R5 self-check with `python3 -B`; all eight test methods passed. I also ran the frozen R4 self-check unchanged; all five methods passed. The R5 controls exercise 141 synthetic profile scenarios: a complete positive matrix; eight exact epoch-row omissions; four wrong epoch arguments; 76 required-method omissions; four skipped-case profiles; and 16 each of consistent omission, display substitution, and consistent duplicate rows for the four newly required displays across four profiles. The three theory cases use the exact named `receiptShape` arguments; the fact control rejects a synthetic suffixed display because its expected display is the bare FQN.

As a separate R5 check, I added one exact `identityless` epoch display consistently to normal Debug public discovery and to user/merged TRX, with valid counters and a fresh unique execution ID. The production verifier rejected it at the mandatory case-multiset check. I compiled all five frozen Python inputs in memory with `python3 -B`; compilation passed. No `__pycache__` was written in the frozen candidate.

These are offline synthetic/source controls, not VSTest discovery or a Windows run. R13 is a separate managed-source checkpoint; this review checked the required declarations there but does not convert local compilation results into Windows test evidence.

## Evidence boundary

R5 may proceed to a fresh diagnostic Windows matrix using the exact frozen six-file inputs and fresh run label. The resulting matrix must be reviewed on its own raw build, discovery, user/SYSTEM/merged TRX, cleanup, and package evidence. This scoped GO is not Windows qualification, service/driver pair acceptance, installation authorization, or runtime/product approval; the owner's final cutover definition remains open.
