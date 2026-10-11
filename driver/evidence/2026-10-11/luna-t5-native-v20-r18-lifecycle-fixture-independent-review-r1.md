# T5 lifecycle fixture independent source review (R1)

Date: 2026-10-11  
Scope: independent source review of the additive 946-line PowerShell lifecycle fixture, its pinned helper, the readiness note, and the root source-acceptance receipt. This review made no changes to the fixture, helper, driver, or service sources. I did not execute the fixture, start a VM, install or load a driver, or mutate host policy. A separate root-owned PowerShell 5.1 parse-only receipt is recorded below; parsing is not runtime qualification.

## Verdict

The fixture contains useful, separately reportable probes for voluntary pre-commit refusal and mandatory unload with a real staged `FileStream` owner. It captures one structured command result at a time with raw stdout, stderr, and exit files; status helper functions do not accidentally emit event-log strings into their result pipeline; and final `FAIL` status remains sticky through cleanup. The independently launched observer establishes an absent baseline before test writes and checks exact destination hashes.

**Do not execute this frozen revision yet.** Its filter-presence queries treat a failed `fltmc` command as “filter absent.” In the finalizer, that result can authorize copying the original driver over an image that is still loaded. The cleanup path also removes recovery files after some restoration checks have failed. Findings 1 and 2 below are source safety issues, separate from the fixture’s intended test coverage.

This is not a runtime result. The voluntary rollback and mandatory held-owner subcases are source-valid test intents, not observed outcomes. The exact op17 wire request/ACK is not captured; startup failure inside `FltStartFiltering`, stale-disconnect ordering, and callback/worker overlap at unregister are not forced by this fixture. Those boundaries remain unobserved/inconclusive. I do not infer that they are additional cutover requirements: the active goal’s definition of done remains controlling. The accepted R18 receipt still says runtime and pair qualification are false and cutover is unauthorized.

## Frozen inputs

| Input | SHA-256 |
|---|---|
| Active goal attachment `pasted-text-1.txt` | `a982e6762ab1e18664509339c40a333eb7a0fab4b0794dd83c0630a7a7f1232d` |
| `driver/scripts/Test-StagedMinifilterUnloadLifecycle.ps1` (946 lines) | `d96f40d1563df2c8c48c57d03fd49199fd580f7a96fac04ed8994a74468d4378` |
| `driver/scripts/StagedTestAgent.ps1` | `abd9c67925a4a18b4635bb4b1d21b35cd033453d6ca0c03acf46246472aa6dd7` |
| `driver/evidence/2026-10-11/luna-t5-native-v20-r18-runtime-qualification-readiness.md` | `d08ce66165588ee9ee9202488bc84ed8e0f8d68327927fdcda9f3ceacf4e7ee5` |
| `driver/evidence/2026-10-11/m2-t5-driver-wire-v20-r18-root-source-acceptance-a1.json` | `9e0ae87e8b17712a1f8967ccae0561cb29e21344c03c221e66622a869604492b` |
| Root parse-only receipt `m2-t5-lifecycle-fixture-r1-parser-a1-root-result.json` | `2377e1eef14e0c174aacfdac2cc48a486d1984613d7710f4c29efa36062bb7d3` |
| `driver/SafeUpload.Minifilter/Filter.c` | `46224c3b8a72da759395a15742ad4e3ec3de4f2fe5b1e20ba48fa612229a20cd` |
| `driver/SafeUpload.Minifilter/Protocol.h` | `d36e22d05087b708f51410d4436ced8353af72ca7245a57e1eb1ae4c064d72cb` |
| `driver/SafeUpload.Minifilter/StageStream.c` | `6967314cba4a6a593325575d0102ece591d038fe42780b55e30e4922c4925475` |
| `agente/SafeUpload.Agent.Minifilter/FilterPort.cs` | `f752d17cc002d6865850739dac232e3128156efe8b2177308915e419ce6f71f2` |
| `agente/SafeUpload.Agent.Minifilter/Protocol.cs` | `865120edcaa5ec9dad587e5223e221f2ae93597e68990ac32b261bcbc4c60222` |
| `driver/SafeUpload.Inspector/main.c` | `8a6e125f48bf212d2e7c68a098ae01ecd0ad8aeb058be79504de2f63b547129d` |

The fixture’s embedded helper pin matches the helper file. The separately supplied root parser receipt records PowerShell 5.1 parsing both frozen files with zero errors, `SourceExecuted=false`, `FixtureExecuted=false`, `HelperExecuted=false`, and `RuntimeQualified=false`. No parser output is treated as lifecycle evidence.

## Coverage and evidence shape

`Write-StageFile` creates a real `FileStream`, writes and flushes the benign payload, waits for its state-0 journal entry, records cleanup paths, then transfers that still-open stream to the caller. The voluntary case samples `stageFileObjects`, calls `fltmc unload`, and requires a resident filter plus `lastUnloadVeto=4`; the inspected `Protocol.h` maps 4 to `SAFEUPLOAD_UNLOAD_VETO_STAGE_OBJECTS`. It then closes a second staged owner to exercise service work after rollback, closes the original owner, checks state-5 publication and exact hashes, and retries unload. This is a meaningful source-level rollback probe, not proof that it ran or passed.

The mandatory case retains the same kind of open owner and samples the owner handle, filter list, SCM state, and asynchronous `sc.exe stop` process separately. After owner release it waits for actual filter absence and then for the `sc.exe` process to exit. The source correctly avoids using the child process’s lifetime alone as proof of kernel unload completion. An owner-held `STOP_PENDING` observation is distinct from the final filter-removal observation.

`Invoke-CapturedCommand` writes stdout, stderr, and exit status to separate files and returns one `PSCustomObject`; it also records arguments and start/end times. `Invoke-WriterStatus` preserves the command script and child outputs, checks both child exit and scheduled-task result, and retains a task that is still running rather than cancelling it. `Write-Event` uses the host stream, so the helpers’ structured return values are not polluted by event strings.

The byte observer is a separate process and opens destination files through its own read handles. It starts before test writes, reports `ObserverReady` only after all three test paths sample as `ABSENT`, rejects sampled hashes outside `ABSENT` and the exact benign payload hash, and requires an exact final hash after state 5. This is independent destination-path sampling. It polls sequentially every 40 ms, so it cannot prove the absence of a transient value shorter than its sampling interval. Also, `Set-ObserverAllowance` adds the exact hash immediately before the caller disposes the owner; the observer can therefore accept that exact value from the allowlist update onward, rather than proving it stayed absent up to the precise close boundary. Treat it as sampled baseline/publication evidence, not a continuous temporal proof.

## Findings

1. **High: filter query failures are interpreted as absence and can make restoration unsafe.** `Test-FilterLoaded` returns only a text match and ignores `ExitCode` (`Test-StagedMinifilterUnloadLifecycle.ps1:132-135`). `Write-FilterSnapshot` and `Test-FilterAttached` similarly parse text without requiring successful commands (`:137-144`, `:172-175`). In `finally`, a false result overwrites the prior `$filterLoaded` value (`:848-855`); the unloaded branch then calls `Restore-StagedTestDriver $backup $false` (`:880-887`). The pinned helper interprets `$false` as already unloaded and copies the backup without attempting an unload (`StagedTestAgent.ps1:259-266`, `:293-303`). A nonzero `fltmc filters` exit with no matching text can therefore cause the fixture to overwrite a still-loaded image. Make filter status tri-state: only a successful query can establish present/absent; on query failure preserve the backup and mounted fixture and do not restore or delete recovery material.

2. **Medium: temporary recovery data can be deleted after a failed restoration check.** The finalizer records agent-stop/configuration errors and verifier/service-config/hash errors as finalization issues (`:867-906`), but those failures do not gate the later deletion condition (`:919-927`), which checks only `$restoreComplete` and `$mounted`. Since `$restoreComplete` is set after the driver-restore helper returns, an agent-service verification failure or a later baseline-check failure can still be followed by removal of the service package and driver backup. The process exits inconclusive, so the failure is not silently promoted to success, but it may discard material needed to recover the VM. Gate temporary deletion on a separate all-restoration-checks-passed state; otherwise retain the package, backup, and volume for recovery.

3. **Evidence precision: the mandatory path records SCM response, status, and filter presence separately, but does not require a successful final service-state query.** `Get-DriverServiceSnapshot` retains and returns its exit code but does not reject a nonzero result (`:154-160`). `MandatoryStopCompleted` records that exit code, then checks only `sc.exe`’s exit and filter presence (`:799-803`); it does not require a successful final query parsed as `STOPPED`. `Record-ScStopControlResponse` labels a service state and filter state from neighboring sequential observations as “at response” (`:162-169`, `:734-749`), not an atomic sample. The fixture can support separate observations of a stop-command response, a sampled `STOP_PENDING`, and filter disappearance. It should not claim an exact SCM-state-at-response or final `STOPPED` result when those observations are unavailable. This narrows the subcase evidence; it does not create a new goal gate.

## Status boundaries

Both runtime branches explicitly set the aggregate `scenarioResult` to `INCONCLUSIVE` after logging their observed subcases (`:712-716`, `:819-826`), because the exact op17 request/reply frame is unavailable. The durable epoch JSON is copied byte-for-byte and checked for matching driver instance plus nonzero request ID/nonce and a drain timestamp; that is correlated receipt evidence, not the raw ACK. Keep the API rollback and held-owner observations independently visible, and keep exact op17 status inconclusive. Do not treat this aggregate status as proof that a bounded lifecycle subcase failed, and do not upgrade the receipt to a wire ACK.

The fixture does not inject failure inside a failing `FltStartFiltering` call, force an old disconnect to overlap a newer connection generation, or place callback/RPC/worker activity at unregister. Those cases remain unobserved by this fixture. The accepted source receipt continues to record `RuntimeQualified=false`, `PairQualified=false`, and `CutoverAuthorized=false`; this review changes none of those dispositions.

The script’s terminal handling is conservative: ordinary exceptions set `FAIL`; finalization problems cannot downgrade an existing `FAIL`; observer exit 2 keeps a leak as `FAIL`; other restoration issues leave an `INCONCLUSIVE` result. The current successful source paths also intentionally never emit aggregate `PASS` because the exact ACK subcase is absent.
