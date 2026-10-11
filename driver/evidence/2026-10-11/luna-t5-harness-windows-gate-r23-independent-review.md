# R23 harness Windows gate independent review

**Source-only integration: ACCEPTED. Bounded Windows full-gate execution: NO-GO.**

This review is bound to `output/review-candidates/m2-t5-harness-windows-gate-r23-root-a1`, whose root review capture is SHA-256 `7f4cd75757bddd4e02a2b88142d9773a59b96e9069883976048535c9f253788c`. I did not run an R23 PowerShell parser or self-check, invoke the gate, connect to Windows, or perform a host, VM, service, actor, product, network, or Git action.

## Source integration

I recomputed the 63 source hashes in the frozen R23 tree against its source capture. All match. Comparing the frozen R22 and R23 source inventories shows identical path sets, exactly three changed sources, and 60 byte-identical files:

- `t5/notepad-coordinator.SelfCheck.ps1` is the exact R18 reviewed file, SHA-256 `abc6b472a16e772bdd11fea7ab88e8e3de82579fc2691c6ef2436229c88d74bb`.
- `HarnessWindowsGate.manifest.json` changes only that T5 source pin and hashes to `2494b0411213f07df94d43f501330f2f5d9b27195f26bedc8444709b98d2c71a`.
- `Invoke-HarnessWindowsGate.sh` changes only the expected manifest digest and hashes to `5ad2092573fe2fd9f636c7fc2a5d39b8a542cfc536e7869b2797a7c7e2a201b7`.

The T5 predicate now checks exactly two state-6 receipts whose UInt64 request text is `19`, with one receipt associated to the parent transfer ID and one to the child. The coordinator and journal schema sources do not change. The manifest retains the ordered 15 main inputs, 17 root self-checks, and one T5 self-check; the eight gate support pins and 33 execution roles are unchanged. The root-captured offline controls report the 15 manifest-helper assertions, 41-input manifest verification, shell syntax check, and stale-pin/altered-input controls passing.

The R18 context supports this bounded source disposition: its independent source review approved a two-file standalone diagnostic, and the captured Windows PowerShell 5.1 run recorded one complete `T5 coordinator schema self-check PASS (162 assertions)` with zero parse errors. The verification binds the original diagnostic process as terminal and the two source inputs as unchanged. That result is diagnostic-only: the coordinator top level, service pair, actors, full gate, recovery, and product runtime were not qualified. R21's atomic keeper-ready publication and exact job-containment sources remain unchanged at their previously reviewed hashes. R21's failed receipt-control wrapper result remains preserved separately from its actual isolated writer-control PASS; neither is represented here as an R23 runtime result.

## Bounded execution scope reviewed

The prepared invocation supplied by root, **not executed**, is:

```sh
bash /tmp/m2-t5-harness-r23-full-gate-1011-a1-root/tree/driver/scripts/Invoke-HarnessWindowsGate.sh r23-1011-a1 /tmp/m2-t5-harness-r23-full-gate-1011-a1-root/tree
```

The pinned gate targets only builder `DESKTOP-O1LP5DG`, UUID `c6440689-d11c-4c63-a463-f3722b7ddb69`, MAC `52:54:00:63:87:7a`, ordinary user SID `S-1-5-21-316478115-1595729549-2803163825-1001`, and Windows PowerShell 5.1 Desktop x64. The client uses the fixed builder address `192.168.122.210`, user `vika`, and strict SSH host-key checking. It uploads the closed 40-file remote tree only after preflight.

The worker parses, but does not execute, all 33 main/self-check source files. It executes the 18 self-check scripts only; it also launches two small generated output-overflow children under the exact diagnostic job. The main files containing actors, coordinators, and build scripts are parse inputs only. The separate lifecycle fixture creates two unique, kill-on-close jobs and a fixture job, starts only the pinned PowerShell gate supervisor/keeper/control processes, and targets the two keeper startup barriers. The reviewed paths do not call the product driver, install or start the service, invoke an actor or coordinator top level, or start a product VM.

Bounds are explicit in source: the remote worker deadline is 1,800 seconds, the local run observation deadline is 2,700 seconds, the fixture transport deadline is 360 seconds, worker and child output are capped, and native children are created suspended in exact jobs with explicit inherited-handle lists. The native job source rejects an existing deterministic name, verifies kill-on-close-only limits, requires exact bounded PID lists and process creation times, retains the same process handles through termination waits, and fails closed on incomplete query or drain. The unchanged R21 receipt writer flushes exact bytes to an exclusive same-directory staging file before atomic move; its keeper retains both job handles if readiness publication fails. The normal success path performs VERIFY, post-delivery pins, then success-only CLEANUP with exact main/keeper job termination, zero-count and zero-PID-list rechecks, and exact process-handle waits.

The success cleanup is process/job cleanup, not deletion of audit files. The remote uploaded tree and run state/output evidence remain available; failure paths retain the remote tree. The fixture's failure fallback attempts exact-token job containment and reports incomplete drains without turning them into PASS. Root's prepared observation wrapper is also specified to preserve stdout/stderr, wait on the original shell without outer timeout/restart, recheck all 63 source pins after the run, and require the pinned final review before execution.

## Full-gate blocker

The lifecycle fixture cannot pass either requested startup-recovery case with the current `CANCEL` path.

In `HarnessWindowsGateRemote.ps1`, `BeforeKeeperPublication` occurs after creating the keeper suspended but before persisting its PID/start identity; `BeforeKeeperResume` occurs after persisting the identity but before `ResumeChild`. The fixture confirms the keeper is still suspended at both barriers (`HarnessWindowsGateLifecycleFixture.ps1`, lines 272–303), kills the exact supervisor handle, confirms the keeper remains active in its exact job, and calls `CANCEL` (`lines 305–329`). The keeper writes its readiness receipt only after it has resumed and completed its startup checks (`HarnessWindowsGateRemote.ps1`, lines 262–265 and the pinned keeper script), so these fixture states have no ready receipt.

For `CANCEL`, `HarnessWindowsGateRemoteControl.ps1` does attempt the intended exact recovery: it accepts only one job-listed PID for an unpublished keeper, opens that process from the held job, reads its creation FILETIME, checks exact job membership and pinned script path/run token, then durably records the recovered identity (`Open-KeeperProcess`, lines 181–231). But immediately afterward, its shared live-keeper branch calls `Assert-KeeperReadyReceipt` unconditionally for every active keeper, regardless of mode (`lines 358–363`). That assertion rejects the expected missing hash/receipt (`lines 118–139`). The `CANCEL` termination block is later (`lines 379–413`), so it is unreachable in both pre-ready cases. The fixture therefore receives a nonzero CANCEL result, emits no two-case PASS, and the shell exits at the lifecycle-fixture step before running the 18 self-checks (`Invoke-HarnessWindowsGate.sh`, lines 195–198 and 205–209). This is a source-level control-flow conclusion, not a claimed runtime result.

Minimum safe correction for the next candidate: keep the ready-receipt assertion mandatory for `VERIFY` and successful-run verification. In `CANCEL`, permit the pre-ready recovery branch only after the same exact state/token, held named-job, configured-limit, job-listed PID, process-handle creation-time, job-membership, and pinned keeper path/token checks have succeeded. Then retain the existing main-job and keeper-job termination, exact-handle waits, exact zero active-count/PID-list checks, post-pin checks, and terminal receipt. Add a negative control that mismatched or ambiguous identities still fail closed, and make the fixture require both barriers to finish `CANCELLED_TERMINAL` with exact drains while no ready receipt exists. This change must not synthesize readiness or weaken VERIFY.

Because that recovery path is part of the preflight fixture and currently fails by construction, **do not execute the prepared command against the builder**. A passing R18 standalone self-check and a correct R23 source delta do not resolve this R23 full-gate blocker. After correction, root should freeze and capture a new closed candidate and obtain a fresh bounded review before any run. No full-harness acceptance, runtime qualification, service-pair qualification, product qualification, or cutover is granted by this report.
