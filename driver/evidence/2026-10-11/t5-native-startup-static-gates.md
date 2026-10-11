# T5 startup recovery component gates

Agent source: `9c1f9737e762144f017a53cdc8812955aced4aea`. **Agent matrix PASS; live native-delete recovery and runtime remain unqualified.**

| Agent profile | Passed / discovered / unique executions | Epoch cases | Visible readiness cases | Async native startup cases |
| --- | ---: | ---: | ---: | ---: |
| Normal Debug | 848 / 848 / 848 | 17 / 17 | 7 / 7 | compiled out |
| Normal Release | 848 / 848 / 848 | 17 / 17 | 7 / 7 | compiled out |
| Feature Debug | 970 / 970 / 970 | 17 / 17 | 7 / 7 | 7 / 7 |
| Feature Release | 970 / 970 / 970 | 17 / 17 | 7 / 7 | 7 / 7 |

`t5-native-startup2` exits 0 with `AgentMatrixGate=True` and independent exact discovery/execution gate PASS. Raw user/SYSTEM TRX
legs were independently counted, including every case in the three new startup test classes. All results are Passed; no case is
skipped or duplicated. Service/tray/test/discovery builds and both Release packages pass at 0 warnings / 0 errors. The three durable
destination-head discovery cases introduced in `e97585cb` are included in each profile.

The tests reopen real epoch/head files and establish that replacement waits for private recovery, failures/cancellation/stale replay
preserve the old epoch, missing/equal/lower/wrapped boot evidence fails closed, only the same live driver can capture a legacy baseline,
and exact concurrent drain receipts are not overwritten. Unsaved private bytes and the original manifest driver binding remain intact.
The asynchronous startup cases show responsive not-ready results while recovery waits, reject a changed final authenticated replay,
and refuse to bypass a durable exceptional hold. Readiness tests prevent a good coverage receipt from advertising Ready prematurely.

The first attempt (`t5-native-startup1`, `225d6056`) failed one new test because its fixture omitted required allocation fields;
the corrected fixture supplies ordinary allocation disposition/reference fields. No assertion or product gate was relaxed.

Driver/inspector/fixture sources are unchanged from `aa1a2a46`: `git diff aa1a2a46..9c1f9737 -- driver/SafeUpload.Minifilter
driver/SafeUpload.Inspector driver/SafeUpload.WriterFixture` is empty. Their four WDK 0/0 builds with PREfast/ApiValidator and signed
artifact are recorded in the [replay static gates](t5-native-replay-static-gates.md); this agent-only change needed no driver rebuild.

Raw output stays local under `output/exact-agent-matrix/t5-native-startup1/`, `t5-native-startup2/`, matching
`exact-agent-matrix-t5-native-startup*` evidence prefixes and host logs. Cleanup removed only generated bin/obj from completed,
archive-verified earlier matrices; their source archives, packages and raw evidence remain retained.

No revised driver/service pair was installed or booted. Native CREATE admission, anchored hold reconciliation, notification emission,
shared physical commit dispatch and teardown integration remain open. Until that recovery is connected, the startup path fails closed
on an exceptional hold rather than allowing the existing publisher to bypass it. Verifier/fault rows and separate VM restoration
remain required; this readout does not qualify the owner's automatic-close/startup guarantee.
