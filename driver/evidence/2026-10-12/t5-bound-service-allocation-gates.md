# T5 connected native lifecycle and allocation — builder gates

Latest agent source: `fa687b61495f47c0bb9485ccf6547552a197254a`; matrix **t5-ordinary-highwater1**.
WDK source: `da66fef4df9215cfd87d85d6825a154174f43138`; label **t5-native-lifecycle4**.
The kernel subtree is identical at both commits (`dc44387caeabeae1ae38437523031885068b60b7`);
the newer source changes ordinary-delete high-water accounting and its agent regression, plus design documentation.
**Four WDK profiles 0 warnings / 0 errors, PREfast/ApiValidator; AgentMatrixGate=True.**
No revised pair was installed or booted. Bound-head capability remains unadvertised and admission disabled.

| Agent profile | Passed / discovered / unique executions | Native lifecycle controls | Bound allocation controls |
| --- | ---: | ---: | ---: |
| Normal Debug | 866 / 866 / 866 | compiled out | compiled out |
| Normal Release | 866 / 866 / 866 | compiled out | compiled out |
| Feature Debug | 1140 / 1140 / 1140 | 22 / 22 | 14 / 14 |
| Feature Release | 1140 / 1140 / 1140 | 22 / 22 | 14 / 14 |

Root independently verified aggregate execution files equal the disjoint user + SYSTEM union:
841 + 25 normal, 1115 + 25 feature; every result Passed, unique IDs, no skipped cases.
Every service/tray/test/discovery/Release-package leg passes at 0/0. Inspector/writer builds and
signature verification also pass ([raw WDK summary](exact-t5-native-lifecycle4-summary.txt),
[raw agent summary](exact-agent-matrix-t5-ordinary-highwater1-summary.txt)).
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
The 14 bound allocation controls retain their Windows filesystem/replay/continuation coverage, including ordinary and native
delete generation allocation above a retained bound manifest after destination-head loss.

Normal Release package SHA-256: `7C2EF7E6E44507E235E1C463AE2DD324596312855548D601EAA7463B5C90D799`.
Feature Release package SHA-256: `91AC4602D8FD8330ACB7A4E76C9DB4DBD5D0E6F24805C7A5080BA363D37BBB20`.
Raw output remains local in `output/exact-agent-matrix/t5-ordinary-highwater1/`,
`exact-agent-matrix-t5-ordinary-highwater1-*`, `t5-ordinary-highwater1-agent-host.txt`,
`exact-t5-native-lifecycle4-*` and `t5-native-lifecycle4-wdk-host.txt`.

Earlier attempts remain retained: lifecycle1 WDK feature builds found C28170/C28172 paging annotation
errors; corrected without relaxing PREfast. Lifecycle2/3 WDK and earlier agent matrices passed their
recorded sources. The final source adds later coverage-loss/undecidable-reconciliation holds.

T5 remains open: ordinary public disposition/proxy handling, kernel bound-writer authority and
seeding, all physical publication/delete permits, startup activation and resolving directory events
must share the head. Then perform the single integrated pre-boot lifetime review and both forced
orders, real Notepad/fault/compatibility rows in all modes, independent bytes and separate restoration.
No host-wide configuration or product VM state changed during these builder gates.
