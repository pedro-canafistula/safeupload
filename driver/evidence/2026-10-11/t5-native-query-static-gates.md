# T5 authenticated native name observation component gates

Driver source: `589e90341445988793fa146fc200ea7c8e5d0e91`. Agent/matrix source:
`1756bfe93a15d26d8c526b833af3da8a1b1708b8`. **Static gates PASS; automatic hold release and protected runtime remain unqualified.**
Driver sources are unchanged between these commits. Product implementation starts at `13a8fb8b`; the receiver/test sources are
unchanged after `1d67949b`. No revised pair was installed or booted.

| WDK profile | Warnings / errors | PREfast / ApiValidator |
| --- | ---: | --- |
| Normal Debug | 0 / 0 | enabled / enabled |
| Normal Release | 0 / 0 | enabled / enabled |
| Feature Debug | 0 / 0 | enabled / enabled |
| Feature Release | 0 / 0 | enabled / enabled |

`t5-native-query2` exact-source build exits 0. Inspector normal/feature Release and writer fixture also pass at 0/0.
The signed feature Debug artifact SHA-256 is `6CA10A976C3E0B36DF7DD24D95C678FD3AF8F3516B28E6A09A7C05B721BF9582`;
signature validation passes. The first WDK build found a missing topology annotation and a query-status branch that did not inspect
the returned status on every path; `589e9034` fixes both without suppressing either analysis finding. Normal builds omit the query.

| Agent profile | Passed / discovered / unique executions | Unique discovery methods | New query cases |
| --- | ---: | ---: | ---: |
| Normal Debug | 857 / 857 / 857 | 505 | compiled out |
| Normal Release | 857 / 857 / 857 | 505 | compiled out |
| Feature Debug | 1024 / 1024 / 1024 | 560 | 42 / 42 |
| Feature Release | 1024 / 1024 / 1024 | 560 | 42 / 42 |

Agent `t5-native-query2` exits 0 with `AgentMatrixGate=True` and independent discovery/execution gate PASS.
User/SYSTEM TRX legs were independently counted: every result is Passed, every execution ID is unique, and each total matches the
complete discovered case inventory. Service/tray/test/discovery builds, test legs and both Release packages pass at 0 warnings / 0 errors.

The new transport binds the authenticated current driver/connection/boot/replay revision, original Mount Manager GUID, full root/parent
identities, case mode and canonical leaf. The driver observes two complete restarted extended-ID directory scans through local
directory opens, checks anchors/admission/retirement/topology, then releases directory/instance references before returning metadata.
It opens no child and exports no handles, kernel addresses, mutation permit or cleanup ACK. The receiver refuses malformed, partial,
stale or mismatched replies, invalid presence/identity facts and foreign volumes; tests preserve both full child-ID halves.
This implements the [reviewed observation transport](t5-native-observation-transport-review-luna6.md), not the live recovery coordinator.

The first agent run passed all execution legs but failed the host inventory gate: VSTest repeated `ValidatorTests.Cnpj_segue_a_RN002`
across cases 1000/1001. Microsoft's [FQN discovery implementation](https://github.com/microsoft/vstest/blob/main/src/vstest.console/Processors/ListFullyQualifiedTestsArgumentProcessor.cs)
deduplicates within each batch. The harness now uses the documented [BatchSize runsettings](https://github.com/microsoft/vstest/blob/main/docs/configure.md)
for discovery; it keeps the existing duplicate-inventory rejection and every case/execution assertion. The installed VSTest rejected
the direct batch command-line option; the supported settings form passed Windows PowerShell 5.1 parsing, all eight host self-checks,
native-process cleanup self-checks, a real 560-unique-method discovery control, and the full rerun. No Luna harness review or disposition was added.

Raw output remains local under `/tmp/claude-1000/exact-t5-native-query2/`, `output/exact-agent-matrix/t5-native-query2/`,
the matching `exact-t5-native-query2-*` / `exact-agent-matrix-t5-native-query2-*` prefixes and host logs. First-run build/discovery failures
remain under the corresponding `query1` prefixes. Harness controls are `t5-native-query-batch-settings-control.txt`,
`t5-native-query-harness-cleanup-selfcheck.txt` and `/tmp/safeupload-native-query-agent-harness-selfcheck-settings.txt`.
These are build/agent controls on the unprotected builder, not protected destination-byte or Verifier evidence.

Live native CREATE/admission and checked physical-commit dispatch, exact-close/startup hold release, native record acknowledgements,
and service-independent teardown remain open. Complete their integration and the single kernel lifetime/lock/retirement review
before first revised boot, then qualify the protected Verifier/fault/application rows with separate VM restoration.
