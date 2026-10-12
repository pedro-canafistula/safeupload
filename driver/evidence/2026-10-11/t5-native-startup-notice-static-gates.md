# T5 unresolved startup notification gates

Agent source: `9e9dea9d968e4f9ffd470833c2d886ba018f8f5f`. **Agent/static gates PASS; automatic reconciliation and protected runtime remain open.**
The real startup preflight now reports each durable accepted/unresolved native hold through the existing owner-scoped notification
and diagnostics helper before refusing readiness. A reporter failure also refuses readiness; reporting cannot modify or release a hold.
No driver source changed; the four WDK/PREfast/ApiValidator 0/0 builds at `589e9034` remain applicable
([driver gate evidence](t5-native-query-static-gates.md)). No revised pair was installed or booted.

| Agent profile | Passed / discovered / unique executions | Startup cases | Observation cases |
| --- | ---: | ---: | ---: |
| Normal Debug | 857 / 857 / 857 | compiled out | compiled out |
| Normal Release | 857 / 857 / 857 | compiled out | compiled out |
| Feature Debug | 1026 / 1026 / 1026 | 10 / 10 | 42 / 42 |
| Feature Release | 1026 / 1026 / 1026 | 10 / 10 | 42 / 42 |

`t5-native-startup-notice1` exits 0 with `AgentMatrixGate=True` and independent discovery/execution gate PASS.
Every user/SYSTEM TRX result was independently recounted: all Passed, unique execution IDs, totals matching the full discovered
case inventory. Service/tray/test/discovery builds, test legs and both Release packages report 0 warnings / 0 errors.
The two added feature tests verify real notification emission-record reopening, exact owner SID/session isolation, the retained
AcceptedUnresolved record, no accepted startup epoch, and the same fail-closed outcome when the reporter throws.

Raw output remains local under `output/exact-agent-matrix/t5-native-startup-notice1/`, the matching
`exact-agent-matrix-t5-native-startup-notice1-*` prefixes and `t5-native-startup-notice1-agent-matrix-host.txt`.
This is a builder agent gate, not protected destination-byte, Verifier, restoration or automatic hold-release evidence.
Allocation/publication head integration, exact last-close/startup reconciliation, native record acknowledgements and teardown
remain required before the single integrated kernel review and revised protected VM rows.
