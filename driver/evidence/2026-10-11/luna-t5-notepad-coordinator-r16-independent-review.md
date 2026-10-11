# T5 coordinator R16 independent source review

**Disposition: GO for one fresh, standalone Windows PowerShell 5.1 diagnostic using only the two root-captured R16 source files.** This permits the bounded source self-check under the reviewed R15 runner/controls design, with fresh R16 labels and the R16 self-check hash. It does not accept coordinator runtime behavior, qualify the service pair, or authorize the broader harness or product VM.

## Frozen inputs

This review is bound to `m2-t5-notepad-coordinator-r16-root-review-capture.json`, SHA-256 `479cd969a36c6d010efcd0758caf1f3f6a798f235b6accffef8d7a638ccd8411`. Its closed inventory records stable two-FD reads, post-copy equality, and 4 source, 27 context, and 5 author files. The independently checked source hashes are:

| Input | SHA-256 |
|---|---|
| `notepad-coordinator.ps1` | `c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d` |
| `notepad-coordinator.SelfCheck.ps1` | `e64729a084d6d87db93bfc99a41cc95537cbf3e5e2f2977bf53c49761758afe8` |
| `StagedTransferJournal.cs` | `4b270eaef4616c06ba52e0b88deb701d72463dcef8ed6c9c8cc4c39893b23f8d` |
| `StagedJournalFile.cs` | `5f4a5ae360513425f1ff79c3ad8c0c4fc8c2b3464f416cecc43c57c42224053a` |

## Findings

The root-captured self-check differs from the R15 baseline by exactly one line. It replaces `@((Get-T5FixtureErrors $legacyParent) + (Get-T5FixtureErrors $legacyChild))` with `@( Get-T5FixtureErrors $legacyParent; Get-T5FixtureErrors $legacyChild )`. `Get-T5FixtureErrors` returns an array of schema errors. PowerShell success output enumerates both sequential calls into the enclosing array subexpression: no errors yields `Count = 0`, and one or two errors remain observable as one or two entries. This preserves both validators and removes the `$null + $null` singleton produced by the old expression when both calls emit nothing.

The attached PS 5.1 cardinality probe records the relevant behavior on Windows PowerShell `5.1.19041.6456`: old empty-sum count 1 containing `$null`; direct empty count 0; direct one-error and two-error counts 1 and 2. It records that project source was not invoked and no files were written. The R15 diagnostic evidence independently shows that the original standalone run reached the preserved all-legacy assertion and failed there after zero parser errors. Its root verification binds terminal PID `2672`, start FILETIME `134361997802714102`, both original source hashes, and unchanged-input post-checks. The failure is consistent with the empty-output aggregation defect; it does not demonstrate a production lineage regression.

Static comparison confirms the all-legacy positive assertion's lineage and schema conjuncts remain unchanged, as do the impossible-history negative control and the mixed legacy-parent/V20-child rejection. The R16 diff adds no helper, control, or weakened condition. The coordinator and both managed-schema source files match their pinned R15 values. The previously reviewed R15 plan (independent review SHA-256 `e648834a47c9405783c601f3c518dfcba88bbd643b6de125502ccd6b227122f8`) confines execution to parsing the two pinned files and invoking only the standalone self-check; it verifies the builder identity, PS 5.1 Desktop x64 and ordinary-user SID, exactly two regular non-reparse source files with expected hashes before and after, and one complete PASS sentinel. It does not invoke the coordinator top level, actor, service, driver, or product VM.

For R16, use a new absent diagnostic directory and fresh runner/control/evidence labels, with the self-check pin updated only to `e64729a084d6d87db93bfc99a41cc95537cbf3e5e2f2977bf53c49761758afe8`; retain the coordinator pin above and all R15 identity, parse, membership, pre/post hash, and single-PASS checks. The previous R15 diagnostic process is recorded terminal, so this is a separate fresh run. Do not treat its result as coordinator, pair, harness, or product qualification.

## Boundary

This review used static source comparison, artifact inspection, and hash checks only. I did not execute PowerShell, project source, the coordinator top level, a Windows builder, a network action, actor/service code, a product VM, host policy, or Git. R16 remains a source-only candidate until a separately captured diagnostic result is reviewed.
