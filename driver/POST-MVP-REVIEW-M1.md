# M1 independent review (Luna, 2026-10-09)

Scope: the driver diff `59b65b59..8e506437` (deny ring, event-driven reclaim worker, identity anchors, the T2 refusal fixes, the
network volume rule). Static review; Luna could not run the driver. The reviewer's report is reproduced as delivered (it could not
write its own file), followed by the disposition of each finding.

## Disposition

| Finding | Verdict | What was done |
|---|---|---|
| F1 P1 UNC prefix does not match the normalized network name | Partly pre-existing, partly mine | Matching a UNC-form prefix against provider-normalized names for exact matching is a limitation of the MVP (network scopes are outside it: `networkPaths` is not supported yet) and was already there. What the diff added is a "volume cannot match" early exit in `StageAdmit` and a looser network rule in the legacy gate: both now also treat a network volume as possibly in scope when any prefix is itself a network path (`d0c53ecb`, `6b83f608`). The canonical-form work for network scopes is recorded in `POST-MVP-PLAN.md` (later list). |
| F2 P2 teardown of one instance invalidates a visit on another | Real | The anchor epoch was global. An anchor is now refused only when its own instance began teardown (instance token, checked under the anchor lock; teardown marks the token before it scans) (`d0c53ecb`). |
| F3 P2 the 32-anchor cap can be filled to starve named streams | Real (fail-closed) | The cap is now the registry's own limit, 4,096 (`d0c53ecb`). |
| F4 P3 deny-ring pagination advances past unread records | Real | The cursor is one past the last record of the page (`d0c53ecb`). The harness and the diagnostics script already paged by the last record's sequence, so they never lost records. |
| Areas 2, 4, 5, 6 | No finding | Nothing to do. |

## Reviewer's report

**Delivery note:** I could not write `/home/victor/Work/safeupload-tools/workers/m1-review-report.md`: that path is outside the workspace’s writable roots. I did not write another file or modify the repository. The report is below.

# Independent review — driver diff `59b65b59..8e506437`

Static review only. Findings:

- **F1 — P1:** A network destination configured as a UNC prefix can be writable outside the scope.
- **F2 — P2:** Teardown of one instance can invalidate an anchor visit on another instance.
- **F3 — P2:** The 32-anchor limit can leave named streams permanently Unknown after scope activation.
- **F4 — P3:** Deny-ring pagination can skip records.

## Findings

### F1 — P1: UNC prefix does not match the normalized network name

**Files:** [PolicyBuilder.cs:203](</home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Minifilter/PolicyBuilder.cs:203>), [Policy.c:745](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Policy.c:745>), [Policy.c:595](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Policy.c:595>), [StageStream.c:2791](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:2791>).

**Scenario:** Configure a destination with `WithDestination(@"\\server\share\Protected")` and leave the broad NETWORK volume flag clear. The builder returns that UNC path unchanged. For a network instance whose normalized name is in NT device form, such as `\Device\Mup\...`, exact policy matching compares the stored UNC prefix directly with the normalized name and misses. The resident volume cache also compares the instance’s device-form volume name with the raw UNC prefix. `StageAdmit` then takes its “volume cannot match” early exit and lets the write continue. The prefix classifier added in this diff recognizes UNC prefixes for `SafeUploadPolicyMayMatchVolume`, but that does not fix these successful-name matching paths.

The same mismatch affects the legacy create gate when name lookup succeeds: it uses exact destination matching at [Filter.c:1379](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Filter.c:1379>).

**Impact:** A write to the configured network destination can reach the share while the agent is disconnected; the path comparison also remains mismatched when the agent connects. This violates the protected-scope invariant.

**Minimal fix:** Canonicalize network prefixes and normalized network names to one representation, and use it consistently for exact matching, the resident volume cache, and boot scopes. Do not solve a folder-specific prefix mismatch by setting a flag that scopes every network volume.

### F2 — P2: An unrelated instance teardown invalidates a live anchor visit

**Files:** [StageWriters.c:5738](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:5738>), [StageWriters.c:5656](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:5656>), [StageWriters.c:5684](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:5684>), [StageWriters.c:5770](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:5770>), [StageWriters.c:6096](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:6096>).

**Scenario:** The single reclaim worker visits an Activating entry on instance A and takes or opens its identity anchor. Before the visit ends, instance B begins teardown. `StageAnchorReleaseInstance` increments the global epoch but removes only B’s listed anchors. When the A visit tries to put its anchor back, the epoch comparison fails; a taken A anchor is destroyed, and a newly opened A handle is returned to the caller and closed.

If A’s writer and cache owner then close before another visit, the old stream incarnation can disappear. The replacement-incarnation path is restricted to base streams at [StageWriters.c:5918](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:5918>). A named stream whose exact identity can no longer be opened instead reaches the Unknown path at [StageWriters.c:5964](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:5964>), leaving it fail-closed and unable to complete promotion.

**Minimal fix:** Track teardown invalidation per instance, or otherwise ensure teardown of B cannot invalidate an A visit’s anchor.

### F3 — P2: The global 32-anchor cap can starve named-stream promotion

**Files:** [StageWriters.c:5614](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:5614>), [StageWriters.c:5656](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:5656>), [StageWriters.c:6096](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:6096>), [StageWriters.c:5918](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:5918>).

**Scenario:** Before a scope is applied, an unprivileged process holds writable handles to more than 32 named streams that become candidates for activation. The first 32 anchors occupy the list. For a later entry, insertion fails at the cap; the visit’s handle is then closed on exit. If the writer and last cache owner for that stream close before another visit, its old SOP can disappear. The named stream is not eligible for the base-stream replacement fallback and can become Unknown.

**Impact:** This fails closed, but an unprivileged actor can induce sticky denial or degraded coverage for protected named streams.

**Minimal fix:** Do not discard an anchor required by a live activation because the global list is full. Provide capacity for the supported set of live waiters, or keep coverage unready while required anchors cannot be retained; preserve refusals inside scope.

### F4 — P3: Deny-ring pagination advances past unread records

**File:** [DenyRing.c:305](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/DenyRing.c:305>).

**Scenario:** With 40 unread denials, the first request after sequence 0 returns only the first 16 records, but sets `NextSequence` to the global next sequence. The diagnostics client is instructed to pass the prior `nextSequence - 1` as its next `after` value at [DiagnosticsPipeServer.cs:107](</home/victor/Work/safeupload-staging/agente/SafeUpload.Agent.Service/Diagnostics/DiagnosticsPipeServer.cs:107>). That cursor is already caught up according to the driver, so the next request returns no records and skips the unread page.

**Minimal fix:** When a page contains records, return one past the last sequence in that page as `NextSequence`. Return the global next sequence only when there are no unread records.

## Seven requested areas

1. **Identity anchors — findings F2, F3.** No separate UAF, double-free, or lock-order finding from static inspection. Anchor insertion failure closes the visit handle; the two findings above concern lost identity retention and liveness.
2. **Activating-name gate refinement — no finding.** The relaxed create gate is conditioned on the protected-name predicate; out-of-scope writer creates still reach the named-alias check at [StageStream.c:2827](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:2827>). The physical-mutation gate repeats its namespace predicate before policy checks at [StageStream.c:2915](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:2915>). I found no bypass through those changes.
3. **Network volume rule — finding F1.** UNC prefix recognition does not canonicalize the prefix for exact policy matching or the resident volume cache.
4. **Alias probe — no finding.** The probe uses `FILE_OPEN_REPARSE_POINT` for identity and link-count inspection; its root system-file exception strips stream suffixes and compares the exact root names case-insensitively at [StageAlias.c:143](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageAlias.c:143>). The source states that a create through a symbolic link re-enters under the target name at [StageAlias.c:186](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageAlias.c:186>).
5. **Reclaim worker — no finding.** I found no specific wait state without a resolving event: scan continuations and exhausted budgets request more work, while parked waits rely on lifetime or policy events.
6. **Ancestor rule and absent-path lookups — no finding.** The absent set is limited to `OBJECT_PATH_NOT_FOUND`, `OBJECT_NAME_NOT_FOUND`, `NO_SUCH_FILE`, and `NOT_A_DIRECTORY` at [StageStream.c:2599](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:2599>). Other lookup failures remain volume-scoped. I found no source-based case where those statuses hide an existing protected object that the filesystem would then allow the create to modify.
7. **Deny ring and diagnostics — finding F4.** The reply buffer is fixed-size and count-bounded. The port accepts one LocalSystem client and binds messages to that process at [Communication.c:319](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Communication.c:319>) and [Communication.c:619](</home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Communication.c:619>); read-only diagnostics do not require the service SID, but remain within that SYSTEM-client trust boundary. I found no ordinary-user disclosure path or substantial ring-lock issue.

## Could not verify

- I did not run the driver on Windows 10 build 19045.2965, so I could not exercise detach, dismount, shutdown, unload, or concurrent instance teardown behavior.
- I could not verify actual normalized names for UNC shares and mapped drives under the target Windows setup. The UNC configuration and direct string comparisons support F1 statically; runtime name forms were not exercised.
- I did not exercise app-execution aliases, cross-volume reparse points, or other reparse tags on the target build.
- I could not reproduce a lower filter returning one of the four absent statuses while still allowing access to an existing protected object. No tests or builds were run.
