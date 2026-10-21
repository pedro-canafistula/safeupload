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

---

# Delta review (Luna, 2026-10-09), `8e506437..a53e42ee`

Follow-up changes reviewed: the per-instance anchor teardown scheme, the writable-section gate that decides an unresolvable name from the stream's registry entry,
the ring cursor, and the cache's network-prefix rule.

## Disposition

| Finding | Verdict | What was done |
|---|---|---|
| D1 P1 `RtlPrefixUnicodeString` under the cache spin lock | Real | The comparison is a resident ASCII case-insensitive loop and its result is computed into the cache (`NetworkPrefix`) when the cache is built; the locked readers read the flag (`ea925022`). |
| D2 P1 a stale stream-context entry can read as "known outside" | Real | `SafeUploadStageWritersSopKnownOutside` validates the entry under the registry lock (listed, not retired, this instance, this SOP, Unscoped, classified outside, no Unknown reason, no alias probe or scope scan pending, no rename in flight); anything else falls back to the volume-wide answer (`ea925022`). |
| D3 P2 a network prefix makes every network volume possibly scoped | By design for now | Network scopes are outside the MVP and the rule errs on the conservative side; the component boundary for provider roots was added (`\Device\MupFoo` is not MUP). The canonical per-instance share identity stays under "Later". |
| Areas 1, 3, 5 | No finding | Nothing to do. |

## Reviewer's report

## Findings

### D1 — P1: Network-prefix check calls a PASSIVE-only routine under a spin lock

[Policy.c:605](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Policy.c:605) calls `SafeUploadPolicyPrefixIsNetwork`, which calls `RtlPrefixUnicodeString` at [Policy.c:1743](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Policy.c:1743). The caller, `SafeUploadPolicyVolumeCacheQueryNoInline`, holds `SafeUploadVolumeScopeCacheLock` while checking prefixes ([Policy.c:701–705](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Policy.c:701)). A UNC or provider-form prefix can miss the volume-name comparison and reach this new call while the lock has raised IRQL to DISPATCH_LEVEL. Microsoft documents `RtlPrefixUnicodeString` as PASSIVE_LEVEL-only ([Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlprefixunicodestring)). This can bugcheck, especially under Driver Verifier.

**Minimal fix:** Precompute a network-prefix flag while building the cache at PASSIVE_LEVEL, or use a bounded resident case-folding comparison in the locked path.

### D2 — P1: A stale stream-context entry can be treated as proof that a stream is outside scope

[StageWriters.c:6904–6916](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:6904) treats any non-null SOP or stream-context entry as proof that the stream is known, then returns the inverse of `SopMatchesPolicy`. But that function also returns `FALSE` when its entry is retired, unlisted, or bound to a different instance/SOP ([StageWriters.c:6978–6980](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:6978)). The wrapper therefore turns “this entry does not describe this SOP” into “known outside.”

One scenario is a writable handle opened before filter attachment, followed by a tracked writer that creates an outside-classified entry. After the tracked writer closes, reclaim can prune that entry because its quiescence checks count tracked H/W/T/C and section state, not the pre-attachment handle ([StageWriters.c:3995–4001](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:3995), [StageWriters.c:4017–4022](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:4017)). The stream context can retain the retired entry until context cleanup or a later writer insertion ([StageWriters.c:2355–2365](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:2355)). If a scope is then added for that file, the retired entry is not reactivated. An unresolved writable-section request through the old handle can find the stale context entry; `SopMatchesPolicy` rejects it, and the new gate returns success before checking the volume ([StageStream.c:3332–3340](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:3332)).

**Minimal fix:** Return “known outside” only after validating the same pinned entry against the current instance and SOP, and confirming it is listed, unretired, classified outside, and has no unknown, alias-pending, rename, or activation state. Treat any invalid or mismatched entry as unresolved so the existing volume-scope refusal still applies.

### D3 — P2: A network prefix makes every Network-kind volume possibly scoped

[Policy.c:601–605](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/Policy.c:601) returns “may match” for a Network-kind volume if any cached prefix looks like a network path, even when that volume’s provider name does not match the prefix. For example, with a UNC scope on share A, an unresolved writable-section request on unrelated share B with no valid outside registry entry reaches the volume fallback and is denied. That is an outside-scope refusal. The missing component boundary also classifies `\Device\MupFoo` as a MUP path. The new loop is restricted to Network-kind volumes, so I found no new local-volume match from it.

**Minimal fix:** Compare a canonical per-instance network share identity to the configured prefix, including a component-boundary check after provider roots. Preserve the refusal for unresolved streams on volumes that can actually contain a configured scope.

## Requested areas

1. **Anchor teardown — no finding.** With an instance context, insertion checks the teardown token and adds the anchor under the same lock that teardown later uses to scan. If teardown wins first, insertion refuses; if insertion sees ACTIVE first, teardown’s scan waits for the lock and sees the inserted anchor. A taken anchor cannot be put back after teardown marks the token. The no-context branch cannot pass `StageAnchorInstanceActive`. The context lookup and push-lock operations are within their documented IRQL limits here because these paths run at PASSIVE_LEVEL ([FltGetInstanceContext](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetinstancecontext), [FltAcquirePushLockExclusive](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltacquirepushlockexclusive)). I found no lock-order cycle. Failed attach cannot create registry anchors; unload stops the worker and unregisters the filter with the teardown callback registered. The O(n) scans are bounded: at most 4,096 entries per walk, with at most 128 candidate visits per reclaim pass. I found no liveness issue from those scans.

2. **Writable-section gate — finding D2.** No separate bypass found through policy changes, rename, or alias activation: policy transitions gate writable section operations over the current/pending union, and listed entries are re-probed before the transition ends. A handle with no SOP or stream-context entry does not qualify as known outside. The stale-entry case is D2.

3. **Deny-ring cursor — no finding.** Empty reads return the global next sequence. Gap reads begin at the oldest retained record and return one past the last record in that page, so the next request continues without skipping records ([DenyRing.c:289–308](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/DenyRing.c:289)).

4. **Resident volume cache — findings D1 and D3.** The prefix comparison is case-insensitive. The new fallback does not broaden Fixed local volumes, but it has the IRQL fault and the unrelated-network-volume overmatch above. The prior review’s UNC/provider-form exact-match limitation remains: this delta adds a volume-level fallback but does not canonicalize successful-name matching.

5. **By-ID refusals — no finding.** The saved delta does not change the by-ID refusal predicates or status path. The added deny-detail recording is diagnostic metadata; it does not change the I/O status.

## Could not verify

This was a static review; I did not build or run the driver. I could not exercise teardown or unload timing on Windows 10, or reproduce the stale stream-context case on the target filesystem. I also could not verify the target network provider’s normalized volume names.
