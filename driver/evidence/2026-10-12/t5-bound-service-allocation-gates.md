# T5 shared pipeline — latest builder gates

Source: **`a15fc7584f74a2797f93db528eda4961a0f39766`** for both agent and WDK.
Labels: **t5-bound-publication-wire1**. Kernel subtree: `15251c35099a789e4ca1556428c399c373aea64e`.
Agent subtree: `dc7af491b16849f50023ed60e39a7b23ddc3f179`.
**Four WDK profiles 0 warnings / 0 errors, PREfast/ApiValidator; AgentMatrixGate=True.**
No revised pair was installed or booted. Bound-head capability remains unadvertised and admission disabled.

| Agent profile | Passed / discovered / unique executions | Ordinary controls | Native lifecycle | Allocation / native Windows | Publication client |
| --- | ---: | ---: | ---: | ---: | ---: |
| Normal Debug | 880 / 880 / 880 | compiled out | compiled out | compiled out | compiled out |
| Normal Release | 880 / 880 / 880 | compiled out | compiled out | compiled out | compiled out |
| Feature Debug | 1217 / 1217 / 1217 | 22 / 22 | 26 / 26 | 16 / 16 | 34 / 34 |
| Feature Release | 1217 / 1217 / 1217 | 22 / 22 | 26 / 26 | 16 / 16 | 34 / 34 |

Root independently verified aggregate execution files equal the disjoint user + SYSTEM union:
855 + 25 normal, 1192 + 25 feature; every result Passed, unique execution IDs, no skipped cases.
Every service/tray/test/discovery/Release-package leg passes at 0/0. Inspector/writer builds and
signature verification pass ([raw WDK summary](exact-t5-bound-publication-wire1-summary.txt),
[raw agent summary](exact-agent-matrix-t5-bound-publication-wire1-summary.txt)).
Signed feature Debug SHA-256: `2E346764EA6F6E654372635776B9D2FE51F37408ADA4D0AAD37B6EF1023415D2`.

The [corrected publication contract](../../T5-BOUND-PUBLICATION.md) received READY WITH CORRECTIONS from Luna 6 max before code.
`a15fc758` adds matching feature-only C/managed v26 layouts and a FilterPort client, preserving core v18 and all existing layouts.
The client rejects changed authority, result-only renewal, short/nonzero-status transport, incomplete/stale/duplicate replay,
unfenced or in-flight renames, changed target/source identity, pending native results and cleanup after accepted rename.
Conclusive failed CREATE can retire without a nonexistent temporary cleanup; malformed outcomes and coverage loss cannot ACK.
All 34 publication-client controls pass per feature profile. C layout assertions pass in the feature WDK builds.

This is the **wire/client side**, not the kernel permit producer or execution map. Control 33 has no live producer/handler,
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

Normal Release package SHA-256: `1A99807DAC55A5D2B58AE94A269975B320047C60DDEC884B4BF5AD128E65E6E0`.
Feature Release package SHA-256: `20822873E82EE3AE4FA05DC384D0F156F8A1C58D91DF4401874306BF677D340C`.
Raw output remains local in `output/exact-agent-matrix/t5-bound-publication-wire1/`,
`exact-agent-matrix-t5-bound-publication-wire1-*` and `exact-t5-bound-publication-wire1-*`.

Earlier failed attempts remain local. The first native-mask control queried a creation-only flag as an I/O mode; `ab6dc0b9`
corrected that harness assumption without changing CREATE rights/options, then passed. Public-relay1 found two signed/unsigned comparisons in the feature kernel builds;
`d5779d5a` adds explicit wire-field casts without relaxing warnings-as-errors or static analysis.
Its initial agent matrix passed 880/1182; the final matrix adds the second-forwarding guard/control.
Earlier oversized-stack, fixture and cancellation failures remain recorded in Git history and their raw outputs.
No product assertion, VM baseline or host-wide configuration changed during these builder gates.
