# Adversarial review: `91da9534` and `94fcc04c`

Source review only, on branch `feat/mvp-replaced-incarnation`. No VM was available; I did not run tests. I left the worktree unchanged and wrote only this report.

## Verdicts

| Commit | Verdict | Findings |
|---|---|---|
| `91da9534` — define the `0x20` basis per data stream | **ACCEPT** | No new P0/P1/P2 issue found. The resulting contract is explicitly per target data stream; a named-stream writer can coexist with promotion of the base-stream row, but the named-stream row continues to gate aggregate Ready. Unknown stream identity remains conservatively blocking and can hold the base row pending indefinitely. |
| `94fcc04c` — record why an Activating entry was not promoted | **REJECT — P2** | A changing diagnostic mask can advance the shared `RegistryChangeSequence` and cause coverage/status queries to return `STATUS_RETRY` even when coverage state did not change. One new ScopeDeferred write can also overwrite a more specific failure status. No promotion bypass found. |

## 1. `91da9534`: per-data-stream promotion basis

**Finding: none at P0/P1/P2.** The revised `0x20` description is honest for the path that sets it, provided promotion means promotion of the specific data stream and `--admission-coverage` remains the readiness authority.

The replacement fallback is only reachable for a known base-stream entry: `StageRegistryEntryIsBaseStream` requires `StreamIdentityKnown`, `!CompactStream`, and `StreamChars == 0` (`StageWriters.c:5331-5339`), and the fallback is guarded by it (`:5487-5511`). Thus the promoted entry is for the unnamed data stream. The sibling census is under `RegistryLock`, matches instance/volume/serial/file ID, and skips only a row whose stream identity is known and whose `CompactStream` or nonzero `StreamChars` proves it is a different named stream (`:4990-5008`). Compact ADS rows set `CompactStream` even though their stored `StreamChars` is zero; full-name ADS rows retain nonzero `StreamChars` (`:1500-1516, 1605-1612`). Other base-stream incarnations, including compact default-stream rows, remain in the census.

A named-stream row does not get promoted by the base stream's replacement path. Its own open requires known stream identity and resolves/uses that row's stream suffix (`:4138-4165`); it fails the base-stream predicate, so it cannot take the relaxed base-stream replacement fallback. Promotion of the base row neither retires nor rewrites the ADS row. The reclaim worker promotes/prunes each candidate row independently (`:5896-5925`). If the ADS name is scoped, its alias probe is counted while pending and its scoped result sets `ActivationEnforced`; the coverage walk counts pending/enforced rows and treats any non-Protected row as not ready (`:6588-6596, 6894-6917`). Therefore a pre-scope writable view on `F:meta` can keep the ADS row Activating/Unknown while the base row reaches Protected, but aggregate coverage remains not Ready until the ADS row clears its own gate.

**Concrete boundary scenario:** a standard user has a pre-scope writable mapped view of `F:meta`. After the base stream's old SOP is gone, the base entry may pass its per-stream sibling check and promote with `0x20` while the ADS entry remains pending. This is not a whole-file-identity Free proof; it is a base-stream proof, exactly as the updated `Protocol.h:1149-1152` says. It remains safe only while consumers use aggregate coverage for Ready and do not treat this base-row Protected state as proof that every named stream of the file is free.

An entry with `StreamIdentityKnown == FALSE` can in fact represent a different stream: an unresolved normalized-name/stream parse can still reserve a compact row with `UnknownReasons` set and an Unknown state (`:1460-1476, 1519-1526, 1622-1624`). The new walk does not skip it, and the Unknown reason/state rejects the base promotion (`:5004-5007`). Such an ambiguous ADS row can therefore block base promotion indefinitely if its Unknown state is sticky. That is a conservative false block, not a regression from the prior broader walk; the previous code also checked unknown-identity rows. It matches the fail-closed rule and does not create a Ready escape.

Relative to the prior walk, the only omitted checks are H/W/T/C/Unknown on **known different named streams**. Those states remain enforced and represented by their own rows. S/cache on those rows are intentionally absent from the base-stream proof; the live base SOP's S/cache barrier is still sampled on the reopened base stream, while a named stream's S/cache is evaluated by that named stream's own activation pass. I found no other lost same-stream predicate.

## 2. `94fcc04c`: promotion-mask and diagnostic review

### Predicate equivalence and decision path

The new mask has the same polarity for every term in the old conjunction at `git show 94fcc04c^:driver/SafeUpload.Minifilter/StageWriters.c`, `StageRegistryTryPromoteEntry`:

| Old required predicate | New failure bit when it is false |
|---|---|
| `Listed && !Retired` | `NOT_LISTED` for `!Listed || Retired` |
| `State == ACTIVATING` | `STATE` for `!= ACTIVATING` |
| `H == 0` | `H` for `!= 0` |
| `T == 0` | `T` for `!= 0` |
| `W == 0` | `W` for `!= 0` |
| `UnknownReasons == 0` | `UNKNOWN` for `!= 0` |
| `RenameInFlight == 0` | `RENAME_IN_FLIGHT` for `!= 0` |
| `!directoryRenameInFlight` | `DIRECTORY_RENAME` when true |
| `RenameVersion == snapshot` | `RENAME_VERSION` for `!=` |
| `ActivationGeneration == CurrentGeneration` | `ACTIVATION_GENERATION` for `!=` |
| `ActivationEnforced != 0` | `NOT_ENFORCED` for `== 0` |
| `ScopeNameClassification == SCOPED` | `NOT_SCOPED` for `!= SCOPED` |
| original compact/full-name compound predicate | `NAME` when the equivalent `nameOk` is false |
| `SnapshotSpilledWriters == 0` | `SPILLED_WRITERS` for `!= 0` |
| `SnapshotSpilledMutatingIo == 0` | `SPILLED_MUTATING_IO` for `!= 0` |
| `SopEmpty` | `SOP_NOT_EMPTY` when false |
| `SnapshotC == 0` | `C` for `!= 0` |
| `siblingsFree` | `SIBLING` when false |
| `ReplacedLiveSop == NULL || Entry->SOP != ReplacedLiveSop` | `REBOUND` when non-NULL and equal |

The conjunction at `StageWriters.c:5063-5088` is therefore equivalent to the old one. The separate pre-call map-generation failure is `SOP_MAP_MOVED` (`:5639-5651`); a false result from the unchanged final `StageRegistryTryPromoteStateNoInline` is represented as `STATE_RECHECK` (`:5088-5098`). That final CAS is still called only when the new mask is zero. Its internal false outcomes remain aggregated in `STATE_RECHECK`, as the previous caller had no per-term result there.

`nameOk` is computed early, but the caller holds exclusive `RegistryLock` at this point, which stabilizes the name/stream identity just as the old predicate did. The sibling scan and directory-rename sample were already evaluated before the state lock in the old function. The early `FltGetInstanceContext` and rename-loss failures retain the same Unknown marking, activation preparation, global-Unknown publication where applicable, and return behavior (`:5041-5055`); the new caller records their returned bit only after releasing `RegistryLock`.

The three snapshot predicates are reads: `StageRegistrySnapshotSpilledWriters`, `StageRegistrySnapshotSpilledMutatingIo`, and `StageRegistrySnapshotC` take `SectionLock` and sample counts/slots (`:7279-7322`). The old conjunction already called them while `Entry->StateLock` was held whenever earlier predicates passed. The new code can call them after an earlier predicate failed, but they add no mutation; the nesting order remains `RegistryLock -> StateLock -> SectionLock`, already used by the old successful-predicate path. I found no reverse nested `SectionLock -> StateLock` path in the reviewed section-slot/map helpers. Activation and all new record calls run at PASSIVE_LEVEL; the record helper is APC-or-lower and takes only `StateLock` (`:4342-4357`). Every new record call is outside spin locks: the map-generation status write follows `FltReleasePushLock(&RegistryLock)` (`:5647-5651`); LinkScanMore follows classifier return after its locks are released (`:5442-5446`); ScopeDeferred follows the alias resolver/state-lock return or the link-scope helper return (`:5464-5484`); MarkersLive follows the marker-scan return (`:5603-5608`).

### P2 — diagnostic changes can churn the shared snapshot sequence

**Location:** `StageWriters.c:4350-4357, 5647-5651`; readers retry on sequence movement at `:6808-6810, 6920-6922`.

The helper correctly avoids sequence increments when the status/step pair is unchanged. It still increments for every *changed* pair. A changing mask therefore makes the diagnostic row itself a source of `RegistryChangeSequence` movement. `SafeUploadStageWritersAdmissionCoverage` uses this same sequence even though its readiness calculation does not consume classification status/step; the activating-status page also retries on it.

**Scenario:** an old base-stream entry remains Activating because an ambiguous same-stream sibling stays Unknown. Ordinary read-only activity can make the live SOP's cache pointers reappear between the pre-CAS empty check and the CAS call. One pass records `SIBLING`; another records `SIBLING | SOP_NOT_EMPTY`. The promotion remains refused in both passes, and the coverage counts/readiness remain unchanged, but `StageRegistryRecordClassificationResult` changes the visible diagnostic pair and increments the shared sequence on each transition. If those transitions continue during each coverage/status snapshot, the calls keep returning `STATUS_RETRY`. The cache state can vary without changing the entry's H/W/C/T/Unknown tuple; the new diagnostic is the additional coupling. This is fail-closed availability loss, not a promotion bypass. A successful link-name classification also increments `RegistryChangeSequence` unconditionally at `:4733` in pre-existing code, so this diagnostic is not the only sequence movement during a worker pass. The new write is still an additional post-classification sequence change: a query that begins after that scan increment and overlaps the mask update can independently return `STATUS_RETRY`.

This is conditional on an actually alternating mask; a stable mask is deduplicated and does not churn. Still, the commit's diagnostic-only claim overlooks that the diagnostic fields share the readiness snapshot sequence. Split diagnostic sequencing or otherwise account for changing diagnostic rows in the query contract before treating the queries as immune to this churn.

### Diagnostic status/step and consumer impact

The added step values 12–15 are distinct from the existing 0–11 values. `PROMOTE_DEFERRED` uses `0xE0000000 | mask`; the mask bits are disjoint and all fit below the high prefix. The other new statuses (`STATUS_MORE_ENTRIES`, `STATUS_RETRY`, `STATUS_PENDING`) are used with distinct steps. I found no existing SafeUpload status/step constant collision. The Inspector prints the status as raw hex and maps all four new step codes (`Inspector/main.c:1424-1463`), so the encoded mask remains inspectable. The diagnostic extension struct/control layout is unchanged; no new field was inserted. Harness scripts invoke `--activating-status` but do not parse or branch on these new step/status values (`driver/scripts` search); no harness compatibility break found.

There is one accuracy defect in the new `ScopeDeferred` write: when `StageRegistryResolveAliasProbeForGeneration` fails to get the instance context, that helper first records the real failing status with step `OTHER` (`StageWriters.c:5247-5254`), marks Unknown, and returns false. The new caller then unconditionally overwrites it with `STATUS_RETRY / SCOPE_DEFERRED` (`:5468-5470`). A transient context failure is consequently reported as an ordinary retry. This does not change gating, but it can hide the cause the commit is meant to expose. The `ScopeDeferred` write should only replace the helper's result when no more specific failure was recorded, or the helper should return the reason to the caller.

## Overall

`91da9534` fixes the named-stream overclaim by narrowing the proof and leaves the separate ADS gates visible to aggregate coverage. Unknown stream identity can still pin a row indefinitely, intentionally failing closed. `94fcc04c` preserves the promotion decision and lock/IRQL behavior, but its changed diagnostic masks can advance the readiness sequence, and one alias-probe failure is mislabeled. No P0/P1 security bypass was found; the P2 query-retry coupling is the reason for the reject verdict.
