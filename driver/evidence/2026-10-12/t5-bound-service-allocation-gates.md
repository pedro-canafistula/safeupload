# T5 shared pipeline — latest builder gates

Agent source: **`a7e238ff73d4d003bb0c502f17ddce107e24aeed`**, label **t5-publication-journal4**.
WDK source: **`19d5f33c1c4d0de024227a5b6e12a8cad96adc61`**, label **t5-publication-journal1**;
kernel subtree `15251c35099a789e4ca1556428c399c373aea64e` is unchanged through the agent source.
Agent subtree: `4ffceecab5f0035a7bbfe859c29b9e658335b363`.
**Four WDK profiles 0 warnings / 0 errors, PREfast/ApiValidator; AgentMatrixGate=True.**
No revised pair was installed or booted. Bound-head capability remains unadvertised and admission disabled.

| Agent profile | Passed / discovered / unique executions | Ordinary controls | Native lifecycle | Allocation / native Windows | Publication client | Native-result journal |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Normal Debug | 880 / 880 / 880 | compiled out | compiled out | compiled out | compiled out | compiled out |
| Normal Release | 880 / 880 / 880 | compiled out | compiled out | compiled out | compiled out | compiled out |
| Feature Debug | 1230 / 1230 / 1230 | 22 / 22 | 26 / 26 | 16 / 16 | 34 / 34 | 13 / 13 |
| Feature Release | 1230 / 1230 / 1230 | 22 / 22 | 26 / 26 | 16 / 16 | 34 / 34 | 13 / 13 |

Root independently verified aggregate execution files equal the disjoint user + SYSTEM union:
855 + 25 normal, 1205 + 25 feature; every result Passed, unique execution IDs, no skipped cases.
Every service/tray/test/discovery/Release-package leg passes at 0/0. Inspector/writer builds and
signature verification pass ([raw WDK summary](exact-t5-publication-journal1-summary.txt),
[raw agent summary](exact-agent-matrix-t5-publication-journal4-summary.txt)).
Signed feature Debug SHA-256: `0F9A576611D3F1DCB53A92A37BA9F2944F1D8F13E5AD0F056D6715F65D7BE7C7`.

The [corrected publication contract](../../T5-BOUND-PUBLICATION.md) received READY WITH CORRECTIONS from Luna 6 max before code.
`a15fc758` adds matching feature-only C/managed v26 layouts and a FilterPort client, preserving core v18 and all existing layouts.
The client rejects changed authority, result-only renewal, short/nonzero-status transport, incomplete/stale/duplicate replay,
unfenced or in-flight renames, changed target/source identity, pending native results and cleanup after accepted rename.
Conclusive failed CREATE can retire without a nonexistent temporary cleanup; malformed outcomes and coverage loss cannot ACK.
All 34 publication-client controls pass per feature profile. C layout assertions pass in the feature WDK builds.

`19d5f33c` connects exact native-result persistence to the shared destination head. Unknown rename outcomes retain PendingCommit;
known outcomes atomically retain the complete native status/identity/operation row before its Boolean projection and Published
floor. Bound manifests cannot use Boolean-only completion. Later cleanup replay is monotonic and cannot republish an older
generation, including after manifest compaction. All 13 controls pass on the real private journal with injected native receipts.
Publication pre-CREATE intent, ACK retirement, publisher calls and integrated startup are still open.

This is the **wire/client and durable-result side**, not the kernel permit producer or execution map. Control 33 has no live producer/handler,
and the existing bound publisher still refuses publication. These tests inject native control receipts. They do not prove actual
driver fencing, target serialization, descriptor assignment or recovery. The exact-mask
[native PowerShell 5.1 control](bound-publication-native-ab6dc0b9.txt) separately proves 0/37-byte parent-relative NTFS create,
aligned noncached write, exact EOF/flush and rename with actual granted rights; it is unprotected and supplies no privacy qualification.

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

Normal Release package SHA-256: `5E0125CAFB98FA14F40B52EF308D2E7E6AE6444243C381F9B678F501747BC4DD`.
Feature Release package SHA-256: `F60692902011271D1024A91B535CE3A5F2E95857422430DEC9BE99957CF9EE5A`.
Raw output remains local in `output/exact-agent-matrix/t5-publication-journal4/`,
`exact-agent-matrix-t5-publication-journal4-*` and `exact-t5-publication-journal1-*`.

Earlier failed attempts remain local. Journal attempts 1–3 found a collection analyzer error, missing fixture inspection digest
and wrong expected rejection type. Commits `b2414dea`, `07a748a6`, `a7e238ff` correct them; no assertion is removed.
The first native-mask control queried a creation-only flag as an I/O mode; `ab6dc0b9`
corrected that harness assumption without changing CREATE rights/options, then passed. Public-relay1 found two signed/unsigned comparisons in the feature kernel builds;
`d5779d5a` adds explicit wire-field casts without relaxing warnings-as-errors or static analysis.
Its initial agent matrix passed 880/1182; the final matrix adds the second-forwarding guard/control.
Earlier oversized-stack, fixture and cancellation failures remain recorded in Git history and their raw outputs.
No product assertion, VM baseline or host-wide configuration changed during these builder gates.
