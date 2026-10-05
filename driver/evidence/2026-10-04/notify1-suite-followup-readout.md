# notify1 suite collection follow-up

Authoring base: `fd8ce62f`. No Windows commands or trials were run, and no commit
was made. The notify1 directories named in the request are absent from this
worktree; their existing `case.json`, CLIXML and transport artifacts were read
from `/home/victor/Work/safeupload-staging/driver/evidence/2026-10-04/`.
Earlier wp4proof1/wp4proof3 artifacts were also read there for comparison.

## S00: identity publication race

`Errors[0]` is the `ReadAllText` sharing violation on `actor/identity.clixml`.
The writer's `Write-DurableFile` uses CreateNew, FileAccess.Write and
FileShare.Read. The name becomes visible before its handle closes, whereas
`ReadAllText` opens with sharing that refuses an existing writer. The suite
mistook name visibility for completed publication. S00 aborted before it
collected operations, baseline/samples, service-after or a complete writer fence.

The pre-release provenance read now uses a share-all stream and bounded retries,
including partial CLIXML deserialization. This is necessary before releasing the
writer because OS provenance must be checked while that process is alive. After
S00's validated task completion, the suite reuses `completion.Value.Actor`.
It does not reopen the identity file. S01/S02 use the same bounded reader before
release. Identity provenance and task-completion checks remain mandatory.

## S01/S02: snapshots were attempted; their private-root authentication failed

Both trials contain `service-before.clixml`, `service-after.clixml` and
`service-timeline.clixml`. Both snapshots have `Status=INCONCLUSIVE` and
`Errors: Non-exact journal ACE.` Their `Objects` contain only `C:\` and
`C:\ProgramData`: authentication fails on the next ancestor,
`C:\ProgramData\SafeUpload`. `JournalAbsent` is unset; collection never reaches
the journal inventory. wp4proof3 has the same failure, so it predates the durable
notification-record change. wp4proof1's S01 has no trials to compare.

The reader constructed `FileSecurity` for directory security descriptors.
That is a non-container ACL view and loses OI/CI inheritance flags, so the
exact directory ACE check rejects the correct inheritable descriptor prepared
by `Set-ProtectedPolicyAcl`. The fix uses `DirectorySecurity` for directories
and `FileSecurity` for files, with the same exact owner, protected DACL,
trustees, rights, inheritance/propagation, reparse and link-count checks.
No ACL is repaired or requirement relaxed during evidence collection.

All QPC receipts below use frequency 10,000,000 and the active boot of that case.

| Trial | Before snapshot QPC | Writer release → completion QPC | After snapshot QPC |
| --- | --- | --- | --- |
| S01 | 310162162 → 353539129 | 384074432 → 385324060 | 395443789 → 436649882 |
| S02 | 302998319 → 346255364 | 377298109 → 378724534 | 390699893 → 431967283 |

`ServiceEvidence.WindowBound=true` and both operation fences are complete.
There is no missing operation fence. No disappeared prior manifest is
established: neither journal inventory got past root authentication. Evaluation
now names the rejected before/after snapshot and object, identifies disappeared
manifests when present, and distinguishes an unbound fence. Missing numeric QPC
receipts cannot be coerced into an apparently valid fence.

### Notification record existence and coverage

Both notification snapshots fail at the same private-root ACL check. No
`notifications-*.jsonl` or head artifacts were exported. Consequently notify1
does **not** establish whether the guest notification directory existed.
That is a collection limit, not evidence of absence.

The provenance pins `AgentSourceCommit=fd8ce62f`, service tree
`87C1F8ECE5838D25F130E73864B38B09BE90A4DA3274432D8362D4EDE469A2B5`,
and package `1525974FC6725186BC837BB74E41CF6ABE05EA191DF78DED827ECF60A72317E5`.
This agent supports durable notification records, but `Program.Main` returns
from `--seed-boot-policy` before constructing its host/NotificationRecord.
The suite invokes only that seed mode and requires the agent process absent
during attempts. It cannot produce current-boot continuous emission heartbeats.
An older record, if present, cannot bracket this boot's operation window.

After authenticating the pinned parent, collection now records the notification
directory's existence and child inventory. It retains authenticated, parseable
stale segments/head with SHA-256/length receipts before checking current-boot
coverage; the host validates their copied bytes, even for INCONCLUSIVE snapshots.
Failure reasons propagate through NotificationExpectation and
ActualServiceTimelines. A rerun will distinguish:

- `Authenticated notification directory absent: ...` when the private parent
  proves there is no directory. This remains INCONCLUSIVE for emission coverage.
- `Notification tail boot mismatch: recorded=...; required=...` for a prior-boot
  record, retaining its bytes.
- `Notification tail precedes snapshot fence: tailQpc=...; minimumQpc=...;
  tailKind=...` for a stopped/stale same-boot record.
- Missing/unrecognized children, ACL/authentication failures or torn/invalid
  chains, with inventory/object/error details.

The strict notification-chain coverage evaluator is retained. A stopped or
absent agent is not silently substituted for complete authenticated emission
coverage. NotificationExpectation and therefore ActualServiceTimelines remain
INCONCLUSIVE for these agent-down seeds without such coverage. Journal negative
expectations can pass on a fresh rerun once both authenticated inventories exist
and the existing complete fence brackets them; historic notify1 is unchanged.

## S01/S02: cadence has receipts, but actor operations intersect the intervals

Every native attempt and each unaccounted interval already has QPC receipts.
Each trial has all 101 `writer-open-deny` calls with Win32 code 5. The exact
unaccounted receipts in `CadenceProof.Intervals` are:

| Trial | Assertion / sample | Start → end QPC | Duration ms | Intersecting attempts |
| --- | --- | --- | --- | --- |
| S01 | CadenceGap / 2 | 365754092 → 384299820 | 1854.5728 | 0 |
| S01 | CadenceCoverage / 2 | 384299820 → 386105967 | 180.6147 | 1–100 |
| S02 | CadenceCoverage / 2 | 377087854 → 378060056 | 97.2202 | 0–16 |
| S02 | CadenceGap / 3 | 378060056 → 378256088 | 19.6032 | 17–100 |

For example, S01 attempt 0 ran at 384215117 → 384218291; S02 attempt 0
ran at 377874747 → 377878100 and attempt 100 at 378209604 → 378209955.
These are actual overlapping operations, not a missing or zero-valued receipt.
The writer is released between samples and operates while the observer takes
full images. QPC records establish when the calls happened; neither a gap nor
a sequential full-image capture observes every intervening storage state.

The exact preserved reason is:
`Actor attempt may occur unobserved; no lower ledger exists to bridge this interval.`
Cadence evaluation is unchanged. Re-labelling denied user-mode calls as a lower
mutation ledger or delaying all attempts outside observation would weaken or
change the trial. All four assertions and actor ExternalCoverage remain
INCONCLUSIVE on notify1. The existing PredicateCoverage/NoUnapprovedByte also
lack the driver's lower admission/completion mutation ledger, and LiveTaintFlags
lacks Inspector readback of live TEST_DISABLE_TAINT flags.

## Local validation

- PowerShell adapter self-check: 60/60, including shared-handle/partial identity
  publication, bounded failures and exact snapshot/fence diagnostics.
- Python proof-adapter tests: 9/9, including retained stale-notification hashes,
  lengths and traversal rejection.
- PowerShell parsing and evidence C# helper compilation passed on Linux. Native
  evidence-reader APIs were not invoked.
- Observer module and its 77-check self-check are byte-for-byte unchanged from
  fd8ce62f. A temporary Linux authoring copy passed the 73 portable checks; the
  four LZNT1 checks require Windows `ntdll!RtlDecompressBuffer` and cannot run
  here. The required actual 77/77 Windows check remains for the orchestrator.
- `git diff --check` passed. No historic case verdicts or artifacts were changed.
