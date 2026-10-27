# T9 maintained totals execution checkpoint — 2026-10-27

**Scoped implementation complete; Windows delivery gate failed/incomplete. M2 stays open.**
No new driver/agent pair was installed or qualified. Activation gates, existing
assertions and thresholds are unchanged. Further Windows runs stop under the
repeated-failure rule in `POST-MVP-PLAN.md` and `AGENTS.md`, pending owner direction.

## Implementation and accepted scope

Published commit `eabda0e6` maintains global and ordinal per-SID reservation
charges at durable adoption and exact retirement. Constructor reconstruction,
binding, snapshots, content release and legacy import use those same paths;
checked arithmetic fails closed. Four added cases exercise replay/retirement/
restart boundaries, aggregate startup overflow and retained metadata charges.
The [independent Sol 6.1 high review](t9-reservation-totals-review-sol-high.md)
accepts this scoped change with delivery conditions.

This replaces the foreground reservation summation only. Growing grants,
completed-save shared metadata debt, metadata callback scans, protocol/custody
and allocation-lane work remain open. The approved 120-second allocation/seed
deadline is recorded, not implemented by this accounting prerequisite.

Local feature Debug/Release service/app/test compilation passed at 0 warnings/
errors. All 36 focused reservation controls, all 14 T5 offline self-checks and
the 21-case matrix-runner self-check passed. Required-case preflight found no
removed controls. These results do not replace Windows or protected-pair gates.

## Required Windows matrix — m2t9totalsa1

Builder1 (`DESKTOP-O1LP5DG`, build 19045.6466), feature profiles. Source in the
original receipt is `996fb8a0`, identical tree to published `eabda0e6`;
[commit mapping](m2-resume/privacy-commit-mapping.json). The original source and
archive hash remain unchanged in the receipts.

Feature Debug service/app/tests build and discovery passed at 0 warnings/errors.
The user leg failed three required assertions:

| Control | Observed failure |
|---|---|
| Publisher failed-inspection / timeout / override allowed | Five-second publication wait timed out |
| Clean Office package, spreadsheet | Expected Approved, got legacy AllowedWithoutInspection |
| Queue plus parser single deadline, legacy | 17,181 ms, outside unchanged 5,500–7,500 ms band |

The exact PID/start-bound testhost was then stopped. Partial TRX: **3,003 passed /
3,006 executed**, versus **3,159 discovered user cases**. Debug SYSTEM and both
Release legs did not run; no delivery packages or pair were qualified. All four
new accounting cases passed in this partial leg. [Structured failed receipt](t9-totals/partial-windows-result.json)
binds the retained raw TRX and matrix summary by SHA-256.

The concurrent T8 FileIO diagnostic produced severe host I/O pressure and dropped
events. This is a correlation, not attribution of these assertion failures.

## Focused Windows diagnostic — m2t9diag1027a1

Same exact test DLL, feature Debug/user only; dev target off and FileIO trace
stopped. No test-source or assertion changes. **80 passed / 83 executed, three
failed, zero skips**:

| Control | Result |
|---|---|
| Reservation controls | 36/36 PASS |
| Defaults / integration / allocation recovery | 18/18, 10/10, 5/5 PASS |
| Clean Office package controls | 2/2 PASS |
| Queue plus parser single deadline, staged | PASS at about six seconds |
| Queue plus parser single deadline, legacy | Repeated FAIL: 9,940 ms |
| Publisher timeout / override allowed | Repeated FAIL: five-second wait |
| Publisher image / override allowed | FAIL: five-second wait |

[Structured diagnostic receipt](t9-diagnostic-m2t9diag1027a1/result.json) includes
exact failures, DLL hash and SHA-256 bindings to retained raw output. This subset
does not satisfy the four-leg matrix. The absence of the broad trace means that
trace cannot be the sole explanation. No third run was launched.

The same job passed Windows PowerShell 5.1 parse/native signatures and a real
owned-process cleanup control for T8 harness commit `96423808`. That validates
the cleanup mechanism, not successful Edge/Explorer operation or MOTW authority.

## Source diagnosis and prepared next action

The failing tests do not instantiate `StagedSpaceBudget`; no causal link to the
maintained totals has been established. The single-deadline implementation
subtracts queue time and checks monotonic elapsed time. Its legacy result then
awaits the real `LocalQueueAuditSink`, including durable flush, after stopping
the result's elapsed clock. The test's outer stopwatch includes that audit wait
and waiting for the first two inspections. The publisher's five-second wait
also includes journal persistence, current-policy checks, inspection and exact
hand-back. Current receipts do not locate the delayed stage or prove an audit,
scheduling or storage root cause. The Office failure reason was not captured;
an inspection timeout remains a hypothesis.

Prepared test-only diagnostics keep every case, assertion and time limit:

- Queue-deadline control records monotonic release/parser-entry/cancellation/
  return offsets and the result's pre-audit elapsed time through xUnit output.
- Failed-inspection control captures existing journal timing scopes and buffered
  publisher logs through xUnit output; prior Console output was absent in TRX.
  Original worker-release cleanup remains in `finally` even if output fails.

The final diagnostic test sources compile in feature Debug/Release at 0 warnings/
errors ([compile receipt](t9-prepared-diagnostics-local/compile.txt)). The two
unchanged platform-independent deadline cases pass locally at about six seconds,
and their new timing output is retained in TRX
([Linux diagnostic receipt](t9-prepared-diagnostics-local/result.json)). This
checks the observation path only; no new Windows execution is claimed.

**Proposed next authorized job:** one fresh committed feature Debug/user build,
then the three affected methods only (14 cases), one approved builder, no dev
target, broad trace, full-matrix retry or threshold change. Inspect captured
timings before proposing a fix or another run. Even a green diagnostic would
leave the complete feature Debug/Release × user/SYSTEM gate required.

## Lab closure and retained evidence

The exact failed testhost was closed; the focused diagnostic returned failure
normally. Builder idle inspection found no build/test processes or running
SafeUpload tasks. The hypervisor shutdown request left it running; a subsequent
non-forced Windows shutdown completed. Both builders and both debug targets are
[verified off](m2-resume/final-vm-state.txt). `win10-debug3` was shut down
with recorder and owned Edge processes absent. Its Office dev overlay and failed
trace remain preserved; base and inactive XML were unchanged. This is dev-session
closure, not fresh-disk qualification restoration. [Target closure](m2-resume/closure.json).
Unrelated local user files were preserved.
