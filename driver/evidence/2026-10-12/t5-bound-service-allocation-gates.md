# T5 native lifecycle, ordinary disposition and allocation — builder gates

Source: **`d5779d5a57ddc776738c6b7772a6d935e5560b2b`** for both agent and WDK.
Labels: **t5-public-relay2**. Kernel subtree: `8330a8f7b20fd824030f18a0ae6cba791c18f186`.
**Four WDK profiles 0 warnings / 0 errors, PREfast/ApiValidator; AgentMatrixGate=True.**
No revised pair was installed or booted. Bound-head capability remains unadvertised and admission disabled.

| Agent profile | Passed / discovered / unique executions | Ordinary controls | Native lifecycle | Allocation / native Windows |
| --- | ---: | ---: | ---: | ---: |
| Normal Debug | 880 / 880 / 880 | compiled out | compiled out | compiled out |
| Normal Release | 880 / 880 / 880 | compiled out | compiled out | compiled out |
| Feature Debug | 1183 / 1183 / 1183 | 22 / 22 | 26 / 26 | 16 / 16 |
| Feature Release | 1183 / 1183 / 1183 | 22 / 22 | 26 / 26 | 16 / 16 |

Root independently verified aggregate execution files equal the disjoint user + SYSTEM union:
855 + 25 normal, 1158 + 25 feature; every result Passed, unique execution IDs, no skipped cases.
Every service/tray/test/discovery/Release-package leg passes at 0/0. Inspector/writer builds and
signature verification pass ([raw WDK summary](exact-t5-public-relay2-summary.txt),
[raw agent summary](exact-agent-matrix-t5-public-relay2-summary.txt)).
Signed feature Debug SHA-256: `09290A71D8DF4C0ADC02E268AE3C6FBE305690311AB88713931DF066F3AB11F9`.

The native CREATE/close path captures the original subject and metadata anchors without a second target-file open,
persists the V24 pre-CREATE intent, and forwards once behind strict typed/revision/channel checks.
Exact cleanup/cancellation/coverage facts drive the scheduled-delete lifecycle. Durable terminal receipts remain
until authenticated record removal; lost coverage retains the approved hold. Ordinary FILE_OPEN uses its separate
zero-generation V25 binding and actual NTFS identity/DeleteAccess check. Its map owns no extra application handle
or target FILE_OBJECT reference; ordinary idle records do not veto unload.

Ordinary native SetInformation now has its kernel producer, service intent/result dispatcher and known-cleanup path
(`10a8ea4e`, `d5779d5a`). It serializes the original I/O outside namespace/spin locks, captures immutable current-actor
metadata, durably prepares the exact operation, accepts only a complete successful typed permit and forwards once.
The original FILE_OBJECT, callback thread, requestor mode and flags remain intact. Postoperation records the real NTFS
status without rewriting an accepted result; missing bookkeeping retains replayable facts and the durable barrier.
No worker reissues SetInformation.

TRUE gets max+1 including retained bound manifests. FALSE gets no generation and cancels matching ordinary intents
after actual native acceptance, preserving CREATE delete-on-close. A newer proven Published replacement suppresses
name effect; allocated/blocked successors do not. A recorded native result cannot authorize another forwarding.

An authenticated operation-slot ACK is separate from physical cleanup. Accepted delete holds remain while the original
link can still be pending behind another reader. Last cleanup plus exact anchored absence (or proven newer Published
replacement) completes the generation barrier. Cleanup ACKs stay durable until later authenticated replay proves the
flag/record removal; same-revision absence cannot retire receipts. MaxAllocated/CommittedDelete survive compaction.
The independent cleanup-outstanding replay fact prevents a missing durable receipt from silently releasing a kernel hold.

Twenty-two ordinary controls cover open binding, lost prepares/results/cleanup replies, current inherited-handle actors,
native FALSE/failure/no-forward outcomes, other-reader retention after last cleanup, exact ACK/removal, missing receipts,
generation retention and second-forwarding rejection. Four additional journal controls preserve exact intent/result replay
across reopening in every profile. The native lifecycle and bound-allocation controls retain their prior assertions.
These use the real journal with injected authenticated-replay/name inputs, plus the existing Windows allocation controls:
**they are not protected FilterPort/Verifier runs; journal reopening is not qualified service restart.**

T5 remains open: bound-writer permission/sharing/security/seeding and combined DELETE+write backends, owner tombstones,
every physical publication/delete through the shared head, startup activation, resolving directory events and complete
teardown must finish together. Unknown-result/forced-teardown startup recovery and named guidance need protected fault rows.
Then perform the single integrated pre-boot lifetime review, both forced orders, real Notepad and all fault/compatibility
rows in every required mode, independent destination bytes and separate restoration. Capability stays off until then.

Normal Release package SHA-256: `519010964F875B354509C543213809065ACD4A573E7967BEB0B50E97C05E987E`.
Feature Release package SHA-256: `3AFCD3E3D3C9E24C683736E96C5094B9D4355282AED1708E4AA1843DA8E2F4D0`.
Raw output remains local in `output/exact-agent-matrix/t5-public-relay2/`,
`exact-agent-matrix-t5-public-relay2-*`, `t5-public-relay2-agent-host.txt`,
`exact-t5-public-relay2-*` and `t5-public-relay2-wdk-host.txt`.

Earlier failed attempts remain local. Public-relay1 found two signed/unsigned comparisons in the feature kernel builds;
`d5779d5a` adds explicit wire-field casts without relaxing warnings-as-errors or static analysis.
Its initial agent matrix passed 880/1182; the final matrix adds the second-forwarding guard/control.
Earlier oversized-stack, fixture and cancellation failures remain recorded in Git history and their raw outputs.
No product assertion, VM baseline or host-wide configuration changed during these builder gates.
