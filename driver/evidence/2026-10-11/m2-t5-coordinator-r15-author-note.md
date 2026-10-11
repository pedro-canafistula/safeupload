# T5 coordinator R15 standalone source candidate

**Author source decision: GO for root’s independent source review and a fresh, isolated Windows PowerShell 5.1 standalone diagnostic of the two runtime inputs. This is not root acceptance, Windows qualification, coordinator/runtime qualification, service-pair qualification, product acceptance, or acceptance of the broader harness.**

## R14 negative-control correction

The root R14 diagnostic record (`m2-t5-coordinator-r14-diag-a1-root-verification.json`, SHA-256 `60b5ec053da0d06f774578ae754607c587419affa9de81a5587b3d87e417bec5`) reports that the pinned scripts parsed in Windows PowerShell 5.1 x64, while the standalone self-check failed at `impossible history transition must fail`. The R14 self-check used `[0,10,1]`. In the pinned coordinator, state 10 is `SealPending`, and the transition table permits `10 -> 1` (`Sealed`) at `notepad-coordinator.ps1:336`; the managed journal likewise permits `SealPending -> Sealed` at `StagedTransferJournal.cs:3157`. The negative fixture was therefore valid at the edge under test.

R15 keeps that rejection assertion and uses `[0,10,2,1]`. The transition tables permit `0 -> 10` and `2 -> 1`, but do not permit `10 -> 2` (`SealPending -> Inspecting`). The same assertion now exercises an impossible edge. No production transition, validation rule, or assertion was weakened.

## Legacy ancestry controls

R15 takes the self-check bytes directly from frozen R18 (`dbc00a84c456b97f6903cfcb4ccc0ba37c5ff763fc6b67e83aab3e86e807245f`). They retain the all-legacy parent/child positive at self-check lines 236–253 and the mixed legacy-parent/measured-V20-child negative at lines 255–260. The positive requires both projections to remain non-V20, both schemas to pass, no lineage errors, and the child’s parent version identity to match the legacy parent’s transfer ID, destination generation, and stage identity via `Get-T5VersionIdentityKey` (`notepad-coordinator.ps1:385–398`). This compares raw identity objects accepted by that helper. The mixed negative requires a schema-valid V20 child and a lineage error against its legacy parent. The coordinator’s V20 lineage pass iterates measured entries only (`notepad-coordinator.ps1:970–977`), preserving the legacy path without granting it V20 measurement authority.

These are the three requested controls: impossible-history rejection, all-legacy positive, and mixed-chain negative. The R15 source review found no active-goal or pinned acceptance requirement to add separate legacy allocation-reference assertions. R15 adds no helper, mutation case, instrumentation, or new acceptance gate.

## Exact pins and delta

`author/exact-delta-from-r14.patch` records the complete self-check delta from the frozen R14 baseline. Its SHA-256 is `6aa7645f9cd9dfb5a3ef67a6d10e5358a9fcc228f0cc012fdbe8adaf813a1d27.` The self-check is byte-identical to R18; there is no R18 delta patch. Runtime pins are:

| Runtime input | SHA-256 |
|---|---|
| `driver/scripts/t5/notepad-coordinator.ps1` | `c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d` |
| `driver/scripts/t5/notepad-coordinator.SelfCheck.ps1` | `dbc00a84c456b97f6903cfcb4ccc0ba37c5ff763fc6b67e83aab3e86e807245f` |

The unchanged managed-schema review inputs are `StagedTransferJournal.cs` (`4b270eaef4616c06ba52e0b88deb701d72463dcef8ed6c9c8cc4c39893b23f8d`) and `StagedJournalFile.cs` (`5f4a5ae360513425f1ff79c3ad8c0c4fc8c2b3464f416cecc43c57c42224053a`). The source capture pins 2 runtime inputs, 2 managed-schema review inputs, and 13 context files. The R18 root review capture is pinned at `4da629bbdc11533484c4a2ed0b2aebfe587f47f2518d5b23c5727d369f81c100`; its disposition `b545b9211ad6b4f4bfba6c41b1fa019ed17fb6b29b4c2aa757aaa731b856c130` is `NO_GO` for separate broader-gate findings. That harness is outside this standalone candidate and is not accepted here.

## Qualification boundary

Author work used source reading, candidate-local copying, and hash/diff bookkeeping only. No PowerShell or project script was run. No coordinator top level, actor, service, driver, Windows builder, network, product VM, host policy, or Git mutation was used. Root should independently inspect the exact pins and run the standalone diagnostic in a fresh isolated folder. Until that result exists, the R14 failure is corrected in candidate source only; R15’s Windows standalone status remains pending.
