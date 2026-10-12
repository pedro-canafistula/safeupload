# T5 connected native lifecycle and allocation — builder gates

Agent source: `8ef80fcca6ee7eeb7ccc56986c2885c3a900cd43`; label **t5-public-open3**.
WDK source: `450c8d745c8a0ad6ee69d0dc8be5b1d78a89d65e`; label **t5-public-open2**.
Their kernel subtree is identical (`57c0c69d3e17d308b9bc9a459986d33f5c4b325f`). Later changes correct test construction/fixtures only.
**Four WDK profiles 0 warnings / 0 errors, PREfast/ApiValidator; AgentMatrixGate=True.**
No revised pair was installed or booted. Bound-head capability remains unadvertised and admission disabled.

| Agent profile | Passed / discovered / unique executions | Native lifecycle controls | Allocation / native Windows controls |
| --- | ---: | ---: | ---: |
| Normal Debug | 876 / 876 / 876 | compiled out | compiled out |
| Normal Release | 876 / 876 / 876 | compiled out | compiled out |
| Feature Debug | 1171 / 1171 / 1171 | 26 / 26 | 16 / 16 |
| Feature Release | 1171 / 1171 / 1171 | 26 / 26 | 16 / 16 |

Root independently verified aggregate execution files equal the disjoint user + SYSTEM union:
851 + 25 normal, 1146 + 25 feature; every result Passed, unique IDs, no skipped cases.
Every service/tray/test/discovery/Release-package leg passes at 0/0. Inspector/writer builds and
signature verification also pass ([raw WDK summary](exact-t5-public-open2-summary.txt),
[raw agent summary](exact-agent-matrix-t5-public-open3-summary.txt)).
Signed feature Debug SHA-256: `438DB93E817C8E74B5FAE304BDF127861F99BFA0514E081D58D9DF5DC0A95AA4`.

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

Normal Release package SHA-256: `740050096393655CE70219267DB849C39E83142CC45FBF8581223C8C2A3E2CD0`.
Feature Release package SHA-256: `EE2C7891D8515C4D68E0CFABC4309796A449F452705C5F94FC480F129C6E7934`.
Raw output remains local in `output/exact-agent-matrix/t5-public-open3/`,
`exact-agent-matrix-t5-public-open3-*`, `t5-public-open3-agent-host.txt`,
`exact-t5-public-open2-*` and `t5-public-open2-wdk-host.txt`.

The ordinary FILE_OPEN producer now uses a separate V25 carrier and authenticated replay, a short connection-owned
destination binding turn, and a zero-generation Published snapshot. The unchanged original CREATE performs access checks;
only its successful exact identity/DeleteAccess check records the explicitly requested grant subset. Failed metadata tracking
does not grant disposition authority. The record owns no extra FILE_OBJECT reference, ordinary idle records do not veto unload,
and closed/failed binding cells retire rather than accumulating a per-boot ceiling. Native V22 scheduled records remain separate.
Fourteen binding controls cover zero generation, held/released turns, lost-reply snapshot mismatch, stale bindings, opaque carriers
and forged/mixed replay facts. They use the real journal with injected native replay; they do not qualify a protected open.
**Ordinary SetInformation phases are still refused.** Connecting their one-use permit/result/recovery path remains the next step.

Earlier attempts remain retained: lifecycle1 WDK feature builds found C28170/C28172 paging annotation
errors; corrected without relaxing PREfast. Lifecycle2/3 WDK and earlier agent matrices passed their
recorded sources. Native-reconcile1 found a wrong expectation in the new cancellation fixture; `dcf4b276` corrects it to the
reviewed canceled-before-handle or exact canceled-close evidence. No existing assertion or product policy changed.
Public-open1 PREfast caught oversized stack frames; `450c8d74` uses the existing transaction allocation and direct revision reads.
The new test carrier now uses managed spans; the old replay fixture now includes its scheduled flag. Existing assertions stay intact,
with an added ordinary/scheduled kind rejection.

T5 remains open: ordinary public disposition/proxy handling, kernel bound-writer authority and
seeding, all physical publication/delete permits, startup activation and resolving directory events
must share the head. Then perform the single integrated pre-boot lifetime review and both forced
orders, real Notepad/fault/compatibility rows in all modes, independent bytes and separate restoration.
No host-wide configuration or product VM state changed during these builder gates.
