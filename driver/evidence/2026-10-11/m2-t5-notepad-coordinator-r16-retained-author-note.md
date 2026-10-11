# T5 coordinator R16 narrow source candidate

**Disposition: GO for independent source review of this one-line self-check correction only. No diagnostic rerun, coordinator acceptance, runtime qualification, service-pair qualification, or product acceptance is claimed.**

## R15 failure diagnosis

The root-run R15 Windows PowerShell 5.1 standalone diagnostic parsed both pinned scripts with zero parse errors, then failed at the preserved assertion `an exact all-legacy ancestry chain remains accepted without V20 measurement authority`. The bound raw controls stdout/stderr, result, post-check logs, and root verification are under `context/r15/`. Root verification binds the two source hashes, confirms the original diagnostic process was terminal, and records PID 2672 with start FILETIME `134361997802714102`.

The assertion's schema-error aggregate used `@((Get-T5FixtureErrors $legacyParent) + (Get-T5FixtureErrors $legacyChild))`. The separately pinned PowerShell 5.1-only probe reproduces the cardinality behavior without invoking project source or writing files: two empty command outputs through `+` wrapped in `@()` yield a one-element array containing `$null`; direct command enumeration yields 0 items for two empty validators, 1 item for one error, and 2 for two errors. This explains the failure as a self-check aggregation defect. It is not evidence of a production legacy-chain regression.

## Exact correction and preserved assertions

R16 changes only the aggregate expression to:

```powershell
$legacyChainSchemaErrors = @( Get-T5FixtureErrors $legacyParent; Get-T5FixtureErrors $legacyChild )
```

Both schema validators still run and their emitted errors are collected. The following lineage-error calculation and all conjuncts in the original all-legacy positive assertion remain byte-for-byte unchanged. The impossible-history negative, all-legacy positive, and mixed legacy-parent/V20-child negative remain present. No helper, optional control, assertion weakening, coordinator change, or managed-schema change was made. The coordinator remains SHA-256 `c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d`; the two managed schema inputs remain `4b270eaef4616c06ba52e0b88deb701d72463dcef8ed6c9c8cc4c39893b23f8d` and `5f4a5ae360513425f1ff79c3ad8c0c4fc8c2b3464f416cecc43c57c42224053a`.

The exact R16 self-check delta is recorded in `author/exact-delta-from-r15.patch`. R15 source, evidence, prior fixtures, and live source were not changed. This authoring step used byte comparison, static source review, and hash bookkeeping only. No PowerShell, project source, coordinator top level, Windows builder, network, actor, service, product VM, host policy, or Git operation was used for R16.

The standalone R15 diagnostic did run and failed; it is retained as historical evidence, with no retry here. The independent PowerShell cardinality probe did run separately and passed. Neither result is coordinator/runtime qualification. R16 remains a source-only candidate pending another independent review and any separately authorized diagnostic decision.
