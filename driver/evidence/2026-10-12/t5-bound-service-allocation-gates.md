# T5 connected native lifecycle and allocation — builder gates

Driver and agent source: `da66fef4df9215cfd87d85d6825a154174f43138`.
WDK label **t5-native-lifecycle4**; agent matrix **t5-native-lifecycle3**.
**Four WDK profiles 0 warnings / 0 errors, PREfast/ApiValidator; AgentMatrixGate=True.**
No revised pair was installed or booted. Bound-head capability remains unadvertised and admission disabled.

| Agent profile | Passed / discovered / unique executions | Native lifecycle controls | Bound allocation controls |
| --- | ---: | ---: | ---: |
| Normal Debug | 866 / 866 / 866 | compiled out | compiled out |
| Normal Release | 866 / 866 / 866 | compiled out | compiled out |
| Feature Debug | 1139 / 1139 / 1139 | 22 / 22 | 13 / 13 |
| Feature Release | 1139 / 1139 / 1139 | 22 / 22 | 13 / 13 |

Root independently verified aggregate execution files equal the disjoint user + SYSTEM union:
841 + 25 normal, 1114 + 25 feature; every result Passed, unique IDs, no skipped cases.
Every service/tray/test/discovery/Release-package leg passes at 0/0. Inspector/writer builds and
signature verification also pass ([raw WDK summary](exact-t5-native-lifecycle4-summary.txt)).
Signed feature Debug SHA-256: `9052C6FB76BC0E7443AE1B0AC6F9571168350E2B2E633D053870BF3D80844B3B`.

The gated kernel producer now captures the original CREATE subject and metadata anchors without a
second target-file open, reserves its bounded record and sends a strict V24 prepare. The service
reads exact authenticated replay, includes retained manifests/tombstones in max+1 and flushes the
pre-CREATE intent before its typed receipt. Map revision and local channel-authority revision fence
forwarding of the unchanged original CREATE; generic verdicts/timeouts cannot authorize it.

CREATE/CLEANUP/canceled-CLOSE/teardown facts feed the event-driven worker and asynchronous service
lifecycle dispatcher. It records immutable original request/outcome facts, reconciles last close
with exact lifetime/name evidence, and retains terminal receipts until authenticated record removal.
The pre-ACK map revision is durable; same-revision absence is refused. Later cleanup-coverage loss
or undecidable name reconciliation restores the existing AcceptedUnresolved hold, with approved
named-file diagnostics/Restart guidance. No persisted enum is renumbered or new recovery state added.

Controls cover lost prepare/terminal replies, exact replay, negative never-forwarded receipts,
live-handle refusal, automatic dispatch after cleanup, journal reopening, stale bindings, changed
request/outcome facts, malformed carriers, premature receipt removal and both initially checked
and unbound recovery failures. They use the real journal with injected driver replay/name observations:
**journal reopening is not a qualified service restart; these are not protected FilterPort/Verifier runs.**
The 13 bound allocation controls retain their Windows filesystem/replay/continuation coverage.

Normal Release package SHA-256: `FA5D6B11F79BB75CA61E7B9A623949961AB9BB3394AF7C8C0323E911204ED470`.
Feature Release package SHA-256: `C2217C7A68CF74434684164493824CDEF30977DB0D806E079D84F542B250CD46`.
Raw output remains local in `output/exact-agent-matrix/t5-native-lifecycle3/`,
`exact-agent-matrix-t5-native-lifecycle3-*`, `t5-native-lifecycle3-agent-host.txt`,
`exact-t5-native-lifecycle4-*` and `t5-native-lifecycle4-wdk-host.txt`.

Earlier attempts remain retained: lifecycle1 WDK feature builds found C28170/C28172 paging annotation
errors; corrected without relaxing PREfast. Lifecycle2/3 WDK and earlier agent matrices passed their
recorded sources. The final source adds later coverage-loss/undecidable-reconciliation holds.

T5 remains open: ordinary public disposition/proxy handling, kernel bound-writer authority and
seeding, all physical publication/delete permits, startup activation and resolving directory events
must share the head. Then perform the single integrated pre-boot lifetime review and both forced
orders, real Notepad/fault/compatibility rows in all modes, independent bytes and separate restoration.
No host-wide configuration or product VM state changed during these builder gates.
