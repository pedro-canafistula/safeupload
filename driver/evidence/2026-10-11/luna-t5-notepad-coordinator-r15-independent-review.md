# T5 coordinator R15 independent source review

**Disposition: GO for the prepared standalone Windows PowerShell 5.1 diagnostic only.** This is a bounded source-readiness decision. It does not accept coordinator runtime behavior, the broader harness, a service pair, product behavior, or Windows qualification; the diagnostic has not been run as part of this review.

## Frozen inputs

The review is bound to root capture `m2-t5-notepad-coordinator-r15-root-review-capture.json`, SHA-256 `6cba85a7b71c30b5ad6a35a243a6c6834fb85388ef554d502fc70c61b1c23186`. Its closed inventory pins two runtime inputs, two managed-schema review inputs, thirteen context inputs, and five author artifacts. The root capture records two-FD stable reads and post-copy equality. The runtime and schema hashes also match the candidate-local source capture:

| Input | SHA-256 |
|---|---|
| `notepad-coordinator.ps1` | `c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d` |
| `notepad-coordinator.SelfCheck.ps1` | `dbc00a84c456b97f6903cfcb4ccc0ba37c5ff763fc6b67e83aab3e86e807245f` |
| `StagedTransferJournal.cs` | `4b270eaef4616c06ba52e0b88deb701d72463dcef8ed6c9c8cc4c39893b23f8d` |
| `StagedJournalFile.cs` | `5f4a5ae360513425f1ff79c3ad8c0c4fc8c2b3464f416cecc43c57c42224053a` |

## Findings

The R14 rejection assertion was not exercising an impossible transition: `SealPending -> Sealed` (`10 -> 1`) is permitted by both the coordinator table and the managed journal. R15 preserves the assertion and changes the history to `[0,10,2,1]`. `0 -> 10` and `2 -> 1` are permitted; `10 -> 2` is forbidden. The change is confined to the self-check, preserves its assertion, and is byte-identical to the frozen R18 self-check. The coordinator and the two managed-schema review files are unchanged.

The two ancestry controls are suitable for this diagnostic. The all-legacy fixture validates both projections without V20 authority and compares the child’s raw parent identity with the parent’s transfer ID, generation, and stage identity. The mixed fixture gives the child V20 identity while retaining a legacy parent; the child passes its V20 schema check and the lineage check rejects the missing V20 parent authority. The coordinator’s V20 lineage pass is limited to measured entries, so legacy records remain on their existing path.

The validator covers the relevant managed schema shape: exact volume/FileId stage identity, version identity including transfer ID and destination generation, positive process creation time for V20, a maximum of 64 state-history entries, and matching transition rules. The `10 -> 1` versus `10 -> 2` distinction is consistent with the C# transition table. The two managed files are review inputs only; this source review makes no claim that the project or service was built or run.

The self-check parses the coordinator with the PowerShell AST parser, selects an explicit allowlist of 30 named function definitions, and evaluates those definitions without dot-sourcing or invoking the coordinator’s top level. The allowlist is fixed in the pinned self-check. `Get-JournalFor` among those helpers performs file reads, but the self-check invokes it only after setting its journal directory to its fresh `%TEMP%` fixture and writing its own manifests there; the fixture tree is removed in `finally`. Other fixture writes and cleanup are also under that fresh temporary root. No actor, service, driver, raw observer, or native product path is invoked by this self-check.

The prepared runner and controls plan are limited to this check. The controls require the expected computer name, system UUID, adapter MAC, Windows PowerShell 5.1 Desktop x64, and ordinary-user SID; require exactly the two expected files with matching hashes and reject reparse-point files; parse both scripts; invoke only the self-check with the coordinator path as data; require one exact PASS line; and repeat the file/hash check afterward. The plan emits the current PowerShell process ID and `StartTime.ToFileTimeUtc()` as an integer in its stdout log. The Python runner preserves the stdout/stderr logs and records their hashes, copies only the two pinned source files into a previously absent diagnostic directory, uses strict SSH host-key checking, and does not invoke the coordinator script. Its `ExecutionPolicy Bypass` applies to the pinned self-check script. No product VM, service install, native probe, or host-policy action is part of the prepared path.

The runner and controls-plan hashes checked for this review are `29c2ad25b8922a0cf123356f5a41340e517aa97b844e4b7175555100e079dbee` and `8a655779fbe22061fd2dc76422f6d5903d6e8eb0322777248544baf243d715a6`; the transport helper is `39ed7a7892555d61b1577380fd84888ab39278a0115a7ca9b47b16ca6c52995b`. Their source capture records that Windows execution has not yet occurred.

## Boundary

This review used source inspection and hashing only. It did not execute PowerShell, connect to the builder, run the standalone diagnostic, start a VM, call the coordinator, alter host policy, or mutate Git. The next permitted evidence is the isolated diagnostic result with its exact process ID/FILETIME and pre/post pin checks. A pass would qualify only the standalone source self-check on that builder.
