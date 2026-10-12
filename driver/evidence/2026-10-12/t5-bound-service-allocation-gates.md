# T5 connected native lifecycle and allocation — builder gates

Driver and agent source: `dcf4b27640c56e78202e41cb22274fa9cde90425`.
WDK and agent label: **t5-native-reconcile2**.
**Four WDK profiles 0 warnings / 0 errors, PREfast/ApiValidator; AgentMatrixGate=True.**
No revised pair was installed or booted. Bound-head capability remains unadvertised and admission disabled.

| Agent profile | Passed / discovered / unique executions | Native lifecycle controls | Allocation / native Windows controls |
| --- | ---: | ---: | ---: |
| Normal Debug | 876 / 876 / 876 | compiled out | compiled out |
| Normal Release | 876 / 876 / 876 | compiled out | compiled out |
| Feature Debug | 1156 / 1156 / 1156 | 26 / 26 | 16 / 16 |
| Feature Release | 1156 / 1156 / 1156 | 26 / 26 | 16 / 16 |

Root independently verified aggregate execution files equal the disjoint user + SYSTEM union:
851 + 25 normal, 1131 + 25 feature; every result Passed, unique IDs, no skipped cases.
Every service/tray/test/discovery/Release-package leg passes at 0/0. Inspector/writer builds and
signature verification also pass ([raw WDK summary](exact-t5-native-reconcile2-summary.txt),
[raw agent summary](exact-agent-matrix-t5-native-reconcile2-summary.txt)).
Signed feature Debug SHA-256: `CE023D283F8C1AD829E27EA4C906A2A0FB5F092D3B3A3B35527685006B81D1D2`.

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

Ordinary native-open head capture allocates no delete version. FALSE without an ordinary intent uses existing
ClearDisposition/PendingCommit plus exact name observation, records the real NTFS result, and leaves scheduled on-close state
and generation floors unchanged. Ten journal controls cover no-op success/failure, retained intent across reopening, queue wake,
wrong/incomplete name refusal and unchanged scheduled records; every previous completed-delete/wrong-object assertion stays.
Two actual Windows controls use checked DELETE handles and stable directory enumeration: FALSE preserves the exact bytes/identity,
and an independent CREATE delete-on-close still removes the name after all original handles close.

The connected kernel worker now dispatches canceled/cleanup/coverage facts even when CREATE acceptance is unknown. Four lifecycle
controls require exact cancellation lifetime evidence and anchored original/absent state without inventing a failed CREATE receipt.
A broad counterpart-close wake was removed: metadata observation could wake itself, while excluding all service reads would miss
real source readers. Resolving directory-event activation remains open; this readout does not claim that wake-up is implemented.

Normal Release package SHA-256: `6495B9F95443A361467215B2A6EEE64E4C4525A7B6BC7195589542C2D6770E58`.
Feature Release package SHA-256: `E3D6824AC527621B679BE66BE299FEA0D99FD5819747DCAF93E1888E33C635D8`.
Raw output remains local in `output/exact-agent-matrix/t5-native-reconcile2/`,
`exact-agent-matrix-t5-native-reconcile2-*`, `t5-native-reconcile2-agent-host.txt`,
`exact-t5-native-reconcile2-*` and `t5-native-reconcile2-wdk-host.txt`.

Earlier attempts remain retained: lifecycle1 WDK feature builds found C28170/C28172 paging annotation
errors; corrected without relaxing PREfast. Lifecycle2/3 WDK and earlier agent matrices passed their
recorded sources. Native-reconcile1 found a wrong expectation in the new cancellation fixture; `dcf4b276` corrects it to the
reviewed canceled-before-handle or exact canceled-close evidence. No existing assertion or product policy changed.

T5 remains open: ordinary public disposition/proxy handling, kernel bound-writer authority and
seeding, all physical publication/delete permits, startup activation and resolving directory events
must share the head. Then perform the single integrated pre-boot lifetime review and both forced
orders, real Notepad/fault/compatibility rows in all modes, independent bytes and separate restoration.
No host-wide configuration or product VM state changed during these builder gates.
