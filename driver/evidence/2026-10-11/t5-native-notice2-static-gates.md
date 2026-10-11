# T5 native recovery guidance component gates

Agent source: `a3b3b81e48ca75c4fccd397542694659b6f45ed9` (component introduced in `eccb7848`).
Result: **component gates PASS; live recovery and protected runtime NOT QUALIFIED**.
Raw logs remain local; this curated readout omits machine/account metadata.

| Agent profile | Passed / discovered | Recovery guidance cases | Service/tray/test builds |
| --- | ---: | ---: | --- |
| Normal Debug | 816 / 816 | 17 / 17 | 0 warnings / 0 errors |
| Normal Release | 816 / 816 | 17 / 17 | 0 warnings / 0 errors |
| Feature Debug | 880 / 880 | 17 / 17 | 0 warnings / 0 errors |
| Feature Release | 880 / 880 | 17 / 17 | 0 warnings / 0 errors |

The matrix runner exited 0. Its independent discovery/execution check confirms every discovered case ran exactly once without
failure or skip, including user and SYSTEM execution. All 17 guidance results were additionally checked individually in each
profile's raw TRX. Normal builds omit admission evidence; feature builds include it. Existing recovery and observer cases remain
in the matrix.

The new cases verify exact owner-session/SID delivery, no unscoped broadcast, session-zero recording without interactive delivery,
rejection of unknown advice, wrong phases and overrides, and the exact durable unresolved-native-intent guard. Guidance uses the
existing Retained notification phase and crosses the existing pipe without adding a recovery state or unlock action. The real
notification emission record retains transfer/session/phase and reopens with its existing hash chain; structured warning diagnostics
carry the named destination, operation, generation, full file identity and reason. The record schema was not changed to store advice.

The first attempt, `t5-native-notice1`, stopped at two xUnit2031 analyzer errors in the added persistence test. `a3b3b81e` changed
only the Assert.Single predicate overload; both exact-count assertions remain intact. The complete corrected matrix above passed.
Both attempts' raw output is retained locally.

Driver/inspector source is unchanged from `960ba2d7`; its four WDK/PREfast/ApiValidator gates remain 0/0
([readout](t5-native-recovery2-static-gates.md)). No new kernel code, VM installation or protected run occurred.
The notification helper is not connected to live recovery. Authenticated native record/anchor export, close/startup dispatch,
kernel lifetime review, protected fault injection, Verifier, destination-byte observation and separate restoration remain required.
The owner approved the forced-instance recovery exception for M2 local fixed NTFS; implementation remains pending
([review](t5-native-instance-teardown-feasibility-luna6.md)).

Local raw output uses `exact-agent-matrix-t5-native-notice2` for the summary, execution check, build/discovery logs and four profiles'
main/user/SYSTEM TRX files, plus `t5-native-notice2-agent-matrix-host.txt`. Raw files are not uploaded by this commit.
