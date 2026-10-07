# SafeUpload MVP plan: driver + service, local NTFS, no taint

Agreed 2026-10-03. Design basis: [writer-state design v2](evidence/2026-10-03/writer-state-design-v2.txt)
and [retained-section findings](evidence/2026-10-03/retained-section-findings.txt).

## Scope decision and 2026-10-06 state (owner decision, 2026-10-06)

**The MVP is the goal below: one local fixed-NTFS folder on build 19045.2965.** On 2026-10-06 a Codex
session rewrote this section into a "full replacement of taint for every destination" objective and
started a WinFsp filesystem owner (`SafeUpload.OwnedFspHost`, owner ECP/broker/registry, protocol v19)
to make writes through *pre-existing* mappings private. The owner reviewed that and chose the local
NTFS MVP. The owner prototype and Codex's full 2026-10-06 tracker are preserved unreviewed on local
branch `wip/owner-prototype-20261006` and are out of the MVP. USB, SMB/UNC and sync clients stay in
"Out of scope for the MVP" below.

Why the owner is not needed for the MVP: the mapping repros M1/M2 write through a section that existed
before protection started. M1 (mapping created before the driver loads) cannot happen in a normal
deployment (boot-start driver, installation requires a reboot, owner decision 2026-10-04). For M2 (a
writable section retained across a policy expansion) the owner decided on 2026-10-06 that **protection
starts before apps open files for editing, and an initial restart is acceptable**. That is the Activating
rule already in Phase 3: a scope whose files still have a writer from before the scope existed stays
Activating and must never be reported Ready/protected. The M1/M2 acceptance is therefore: Ready is
never reported while such a writer exists, and once Ready is reported no unapproved byte reaches the
destination. Private writes through a pre-existing NTFS section are a post-MVP item.

Kept from 2026-10-06 (uncommitted work, owner prototype stripped):
- Destination readiness: Control 24 admission coverage, create/section gates, managed and UI
  Pending/Degraded/Ready states, the tracking-loss false-Ready repair and unknown-epoch rejection
  ([design](evidence/2026-10-06/admission-coverage-readiness-source-design.txt),
  [repair review](evidence/2026-10-06/admission-coverage-readiness-luna-repair-review.txt)).
- Known-SOP paging-write refusal for protected/pending scopes in `StageDispatchCore`.
- Default-off admission-evidence diagnostic channel (controls 19/20/23) and its capture client.
- Inspector Control 19 limit fix; W01 parent/diagnostic harness fixes; exact-build helpers.
- Replacement test-signing key on the builder (signer `A6D6…`), proven by signing a fresh artifact
  ([proof](evidence/2026-10-06/signing-artifact-proof-v10-root-readout.json)). The debuggee does not
  trust it yet.

The pre-strip agent source (snapshot D: 327/327 normal, 356/356 feature tests) was validated
([verification](evidence/2026-10-06/exact-agent-matrix-admission-ready-20261006d-independent-root-readout.json)).
The stripped tree needs its own four driver builds and agent matrix before it is used on the VM.

**MVP release gate scope (owner decision, 2026-10-06):** the expanded proof families P01-P06 and all
RV4 families (W01/W02, M01/M02, C01/C02 capacity/binding) are deferred to post-MVP. The MVP gate is the
Phase 4 workload rows S00-S02, C01-C05, A01-A05, B01-B02, R01-R03 and X01 in ordinary, runtime-Verifier
and boot-Verifier modes, with independent restoration and the latency budget, then the Phase 5 review.
Deferred work is not dropped: it stays in the tracker and is the first hardening milestone after the MVP.

**2026-10-06 evening progress (orchestrator):**
- Phase 4 suite: C01 (cached write, APPROVE/BLOCK, absent final) and A01-A03 (pre-scope handle, view,
  retained section through Activating) implemented and merged (`612dff79`); 8 cases now runnable.
- First C01 VM runs found a product blocker, not a harness one: on a real boot the service never reported
  coverage Ready because out-of-scope system writers stayed Unknown(IDENTITY) after the activation alias
  probe (pagefile/swapfile/dedicateddump, deleted temp files, locked state files). Fixed in steps with evidence
  per entry (Inspector `--admission-coverage`, Control 25 classification status): name-gone statuses incl.
  NTFS's STATUS_INVALID_PARAMETER for a freed file reference (verified on 19045), SL_OPEN_PAGING_FILE
  exclusion, and sharing-violation identities whose only name is a volume-root file (standard users cannot
  create files there). Unknown entries per run: 20 -> 22 -> 2 -> (c01g pending).
- Fresh adversarial review of the alias-probe change: BLOCK, two P0 accepted and being fixed:
  rename/link SET_INFORMATION not drained by the admission epoch (pre-existing, affects runtime scope
  expansion) and TxF-private streams misread as name-less; plus P2 header-only hard-link result.
- Staged hand-back implemented (`07853914`): per-user `_bloqueados` copy bound to the requestor SID, read-only
  user ACE, cleanup only after re-verification and window close. Fresh review found 1 P0 (session reuse), 3 P1,
  2 P2; all fixed before merge. Windows-only bugs found on the builder: CreateFile disposition 1 vs 3, real
  profiles are SYSTEM-owned, kernel32 rename rejects RootDirectory.

**2026-10-06 late (handoff):** C01 APPROVE under runtime Verifier now reaches coverage Ready (c01h), stages the
actor's write and gets it inspected and approved, then hangs in Publishing with a 0-byte `.safeupload-<id>.pending`
(c01i). Suspected cause, NOT yet confirmed: the 10-06 known-SOP paging-write refusal in `StageDispatchCore` denies
paging writes for any tracked SOP in a protected scope, including the service's own permitted publication file
(written cached + write-through). Next: read run c01j's `agent-events-final.txt` (debug publisher steps), then
exempt permitted publication streams from that refusal (mark the stream at `SafeUploadPublicationCreate`) or
publish non-cached. Also fixed on this path today: alias-probe Unknowns (20 -> 0), epoch-token decode bugcheck
0x3B (`ba8006e9`), actor profile and restoration harness issues. Hand-back runtime (C01 BLOCK) and A01-A03 not yet
run on the VM.

**Process decision (orchestrator, 2026-10-06, from the owner's "MVP ASAP" priority):** stop iterating verifiers of verifiers:
one exact build per increment, one VM run per case with checkpoint and independent restoration, and
one milestone review. Evidence stays, but no new layer of tooling unless a run actually failed on it.

**2026-10-07 early (orchestrator, handoff to Sol overnight):**
- C01 APPROVE under runtime Verifier: run c01o, 83 PASS, 0 FAIL, ForbiddenByteCount 0, released raw image
  exactly A, restoration clean. The 10-06 Publishing hang was the known-SOP paging-write refusal hitting the
  service's own cached publication write; the service now publishes non-cached and write-through on the
  permitted handle (`ba6ac1e0`). There is no driver exemption, and the driver is unchanged at `326eb512` (build mvp4-b10).
- C01 BLOCK under runtime Verifier: run c01b3 (agent-mvp4-b17 from `12ad8e96`), 131 PASS, 0 FAIL, 21
  INCONCLUSIVE, ForbiddenByteCount 0, hand-back delivered and verified, restoration clean.
- **Decision (orchestrator): the hand-back is bound to the requestor SID, not to a session.** The SID is
  persisted at allocation from the requesting process token. Session binding is kept only for UI delivery and
  justification (`f58b2856`). Why: run c01b2 showed that a session-0 requestor never binds, and a logoff or
  reboot would otherwise invalidate a verified copy. The SID is the identity that already defeats session reuse.
- A01 run a01r1 stopped because the harness never armed runtime Verifier on the activation path. Fixed in
  `7d8f4c49`, not yet rerun.
- C02-C05 (7 variants, Sol) merged in `eb9e10c7`. Windows PowerShell 5.1: 0 parse errors, 224/224 self-checks.
  None has run on the VM yet.
- Harness gap: C01BlockedStageRetained is INCONCLUSIVE because the admin harness gets "Access is denied"
  opening `C:\ProgramData\SafeUpload\staging\<id>.txt`.
- New helper `driver/scripts/Invoke-StagedSuiteBatch.sh` runs cases serially with a guarded rollback.
  Untested: watch the first rollback it performs.

**MVP gate (orchestrator decision, 2026-10-07; the owner should confirm):** the strict `GatePassed` and
`Phase4Suite` gates stay exactly as they are, and they remain the post-MVP target. The MVP release uses a
separate per-run `MvpGatePassed`, computed by the runner. It requires all of the following:
- no FAIL anywhere
- `ForbiddenByteCount == 0`
- `RestorationClean`
- Disposal OK and no Errors
- every assertion PASS, except INCONCLUSIVE on this fixed allowlist of proofs that need instrumentation
  deferred to post-MVP:
  - driver lower admission/completion mutation ledger: `PredicateCoverage`, `NoUnapprovedByte`,
    `*PublicationAndTemporalCoverage`
  - host-independent cadence: `CadenceCoverage`, `CadenceGap`, `ExternalCoverage`
  - authenticated per-file readiness event stream: `NeverReadyWholeHolderInterval`
  - `*UnheldLatency`, only when a dedicated latency run for the same write path passes (at least 100 unheld
    samples, p95 <= 250 ms, max <= 1000 ms)
  - `LiveTaintFlags`, only until live evidence replaces it: Inspector counters showing that no taint
    decision occurred during the run. That evidence is MVP work, not deferred.

The runner records the names it tolerated (`MvpDeferred`). Any other INCONCLUSIVE fails the MVP gate. For
the MVP, NoUnapprovedByte is therefore evidenced by sampled raw-volume, fresh and uncached reads across the
window plus the raw final image, not by a continuous proof; the release notes must say so. C01-C05 are
covered by their Ready variants. Any umbrella-row variant still NotReady is implemented if cheap; otherwise it
is recorded here as deferred, with the reason.

## Goal

Target platform for the MVP (owner decision 2026-10-03): **Windows 10 22H2, build 19045.2965 only**, the
build on the test VM. Windows 11 and other Windows 10 builds are not MVP requirements.

One protected folder on a local fixed NTFS volume where **no byte that was not approved by the
service ever reaches the destination**, proven by an independent raw-volume observer, with:

- the driver loading at boot and protecting the folder before any user program runs;
- writes staged, inspected and published by the service (the existing owned-stream data path);
- policy changes applied without scans (free-of-writers test plus the Activating state);
- process taint switched off for the test, so it cannot be what provides the guarantee.

## What already exists and is reused

The owned-stream data path in the feature build: own upper stream and cache, private noncached
backing, conservative seal, journal `Allocated -> Sealed -> Inspecting -> Approved -> Publishing ->
Released`, real inspection, authenticated expiring publication permits, POSIX replacement publish,
approval UI. It already passes runtime Verifier and boot Filter Verifier for generated backing I/O on
local NTFS (see STAGED-WRITES.md, "Implemented architecture" and the remaining-acceptance tracker).
The MVP adds admission correctness and boot behavior around it. It does not rewrite it.

## Out of scope for the MVP (kept in the architecture, done afterwards one at a time)

USB/removable, SMB/UNC, sync clients, ReFS/FAT, transactional NTFS (TxF), hard-link aliases,
alternate data streams, raw-disk writes, Windows 11 and every Windows build other than 19045.2965,
hibernation/fast startup. On another build the start-up canary still runs and fails closed (volume
Untrusted) if the mapping answer differs, but no other build is qualified. Inside a protected scope these fail closed: transacted write opens,
volume write opens on a volume with a protected scope, and the existing alias/ADS refusals stay on.
The production policy that enables removable and network scopes stays rejected
(`ERROR_NOT_SUPPORTED`, run 34) until those destinations are qualified. The MVP runs with a dedicated
VM test policy that names only the local folder.

## Working rules for the MVP

- Every commit: four WDK builds (normal/feature, Debug/Release) with PREfast,
  DriverRecommendedRules and ApiValidator, 0 warnings/0 errors (`Invoke-ExactSourceBuild.sh`), plus the
  agent tests when service code changes.
- Every kernel change that runs on the VM: runtime Driver Verifier (0x13B) at least once.
- From phase 1 on: the end-to-end invariant test runs and must not regress.
- VM only, checkpoint before each run, independent restoration after each run. Staging stays off in any
  build a real user could receive.
- Adversarial review per milestone instead of per commit. Exception: boot-start loading gets one review
  before it first goes on the VM.

## Phases

### Phase 1: free-of-writers primitives, observe-only

Progress 2026-10-03: H(F)'s 43 fixture checks passed both ordinarily and under runtime Verifier,
including true handle inheritance, delete-on-close, and an actual NTFS junction;
the file-ID S(F) worker and canaries passed on both active fixed NTFS volumes.
C(F)'s corpus passed ordinarily and under Verifier with 5,320 balanced writable acquire/release
pairs, including mixed protections on a shared file object. The detached-volume
fix also passed this corpus with a disposed VHDX still visible to Filter Manager:
the two active NTFS identities matched independent enumeration and the detached
entry remained explicitly reported. All four exact-source WDK configurations
passed PREfast and ApiValidator with zero warnings/errors; relevant service tests
passed 283/283. The local publication regression previously passed with a dedicated
folder policy; its existing taint mode and fresh-reader observer make it regression
evidence, not MVP acceptance. A subsequent observer failure remains recorded as failed evidence. Its rerun passed
under runtime Verifier with 400 fresh-reader samples and clean restoration.

The isolated lower-filter experiment passed ordinarily and under runtime Verifier:
one actual failed lower acquire matched upper post-acquire cleanup, and an exact-file-object
hold showed C=1 before release and C=0 after successful completion. The companion port
rejected the ordinary identity; attachment order and clean restoration were verified.

Table-capacity qualification passed ordinarily and under runtime Verifier: 66 held
callbacks overflowed the 64-slot table; after release and a later successful mapping,
the file-ID probe retained C Unknown (0x80000040). Independent restoration passed.

Writer-node allocation failure qualification passed on Windows 10 build 19045 (run 4): a real Verifier
low-resources failure (counter 0 -> 1, tag `SUwH`, fixture `SUHFail.exe` only) gave untrackedCreates +1,
no counted node, and a sticky Unknown on that stream through a later writer and both cleanups, while a
control stream stayed known. The armed window is LRS-only because `/volatile /faults` replaces the flags
with 0x4 and `/volatile /flags` resets the filters; 0x13B holds in every window with injection off
([readout](evidence/2026-10-03/writer-fault-run4-readout.txt)).

The X2 handle corpus gained cancelled creates and cached/query fast-path I/O, both passing 291/291 checks
ordinarily and under runtime Verifier on Windows 10 19045 (runs 17-18): 20 deterministic cancels of a create
proven pending behind an acknowledgment-requiring oplock break plus 200 seeded races left H(F)=0 with balanced
accounting, and 2000 cached writes, 10,000 attribute queries and an eight-thread open/close storm left H(F) exact.
Whether the calls took FASTIO_* callbacks is consistent with the trace but not proven
([readout](evidence/2026-10-03/writer-count-run16-18-readout.txt)).

Primitive cost (X6) passed the absolute budget with a wide margin on Windows 10 19045 (primitive-cost run 1, ordinary, 2-vCPU guest):
worst phase-F p95 211 us and max 3.4 ms across six operations, against p95 <= 250 ms and max <= 1000 ms. The feature driver as a whole makes a
create about 100 us (5-6x) slower than no filter, and uncounted controls pay about the same as counted opens, so the H(F)/C(F) share is within noise and
not separable from this run; no relative threshold was set
([readout](evidence/2026-10-03/primitive-cost-run1-readout.txt)).

Canary security passed under runtime Verifier (canary-security run 4, 18/18): every canary now reads back the applied
owner/group/DACL and requires exactly one protected SYSTEM FILE_ALL_ACCESS ACE (checks 15), and while a test-only hold kept a
canary alive, 12/12 non-SYSTEM opens (privilege-disabled administrator and restricted token, six access types) were refused with
access denied ([readout](evidence/2026-10-03/canary-security-run1-4-readout.txt)). The section draining fix also passed under
Verifier ([readout](evidence/2026-10-03/section-lower-run5-sectiondrain-verifier-readout.txt)).

Newly attached volumes passed under runtime Verifier (canary-newvolume run 6, 20/20): a fresh VHDX's canary passes; an external
writable section on a held canary makes it fail closed (NTFS refuses the delete mark) with reruns refused and the volume Untrusted; a real
Verifier failure of the canary-only pool tag fails a second fresh volume at step 1 with no file left. The released-NO timeout branch itself is
not reachable without a race and remains unexercised ([readout](evidence/2026-10-03/canary-newvolume-run1-6-readout.txt)). Run 3 also
found that the SYSTEM Inspector wrapper had recorded every exit code as 0; fixed, and earlier variants should be rerun once with the fix.

Nested mixed pairing and teardown passed under runtime Verifier (section-teardown run 10, 59/59): C stays exact across two threads on
one file object; a forced dismount with an acquire held loses nothing (Filter Manager completes the held acquire and still delivers the
old writers' cleanups); old handles and an old writable view provably cannot write after dismount or reattach; a writer record dropped
while mounted sets the machine-wide Unknown (scoped rule). The draining and dropped-at-teardown branches remain unexercised
([readout](evidence/2026-10-03/section-teardown-run1-10-readout.txt)). The regression pass with the corrected exit-code wrapper
passed ([readout](evidence/2026-10-03/regression-wrapperfix-readout.txt)); writer-count run 21 then passed 287/287 under
Verifier on the scoped-teardown driver 88875b67.

Phase 1 status: every listed experiment has a qualifying run on Windows 10 19045.2965. The milestone review
([report](evidence/2026-10-03/mvp1-phase1-milestone-review.txt), [triage](evidence/2026-10-03/mvp1-phase1-milestone-triage.txt))
found two P0s that belong to later phases (late-attach trust -> Phase 2, TxF -> Phase 3) and one P1 fixed now (teardown reason).
Carried forward: Phase 2 must make trust require a newly mounted attach (experiment E1); Phase 3 must refuse transacted writes in a
protected scope (E2) and require a cache flush before promotion (E4). Assumption: other kernel drivers are trusted. Release rule:
SAFEUPLOAD_STAGING_PROTOTYPE builds are test-only and never user-receivable. Empty-file mapping errors
did **not** exercise failed lower acquire. Windows 11 is out of MVP scope (owner decision 2026-10-03).
Phases 2–5 remain open.
[Progress evidence](evidence/2026-10-03/mvp1-idprobe-canary-progress.txt) and
[detached-volume review](evidence/2026-10-03/mvp1-detached-adversarial-review.txt).

- **H(F)**: count of open file objects with write access per stream (create +1, cleanup -1), stream
  context based, on attached fixed NTFS volumes.
- **S(F)**: `MmDoesFileHaveUserWritableReferences` queried off the I/O path through an attribute-only
  open by file ID below the instance (generalized explicit-probe worker).
- **C(F)**: writable CreateSection acquired but not yet released.
- Start-up canary per attached volume: retained writable section reads YES, released reads NO,
  otherwise the volume is Untrusted and staging stays off for it.
- Inspector readout of the three values per stream.
- Experiments: **X2** (handle corpus: duplicate, inherited, failed/cancelled/reparsed create,
  delete-on-close, fast I/O) and **X3** (acquire/release pairing, failed section creation) compared
  against ground truth.

Exit: X2 and X3 show no case where Free(F) reads true while a writer exists; canary passes; cost
measured with the latency harness. All on Windows 10 build 19045.2965.

### Phase 2: boot start with a durable policy

- Production INF: boot start in `FSFilter Anti-Virus`, dependent on `FltMgr`, with explicit
  `ErrorControl=1` (`SERVICE_ERROR_NORMAL`). Ordinary load/init failure is logged and boot
  continues. `ErrorControl` cannot recover from a driver bugcheck; the VM harness takes a disk-only
  external checkpoint first and requires offline restore of that checkpoint if the guest cannot
  boot. Test/prototype builds retain the test-only unload; production registration has no voluntary
  unload callback.
- Durable boot policy: service key
  `SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters\BootPolicy`, binary values `Scopes`
  and `PendingScopes`. Both `Parameters` and `BootPolicy` use owner SYSTEM and protected DACL
  `O:SYD:P(A;;KA;;;SY)(A;;KA;;;TI)` (only SYSTEM and TrustedInstaller have Full Control). The
  service flushes and reads each value back before it reports policy applied. `PendingScopes` is the
  union of prior committed scopes and the candidate, written before the authenticated port update;
  a crash during replacement can retain the old/new union but cannot lose either.
- The prototype reads the service `Start` DWORD before filtering. `Start=0` and an unreadable start
  value disable the existing scan-based fence refresh/retry path for this boot-start mode, including
  policy updates and test unload; boot admission comes from the bounded registry policy and the
  separate attachment trust state. `Start=3` keeps the existing demand-load Phase 1 diagnostic flow
  and its corpora. No file-system scan is added to DriverEntry or the boot-mode policy push.
- Record v1 is an exact 16,656-byte little-endian record: 16-byte version/size/count/destination
  flags header and 32 fixed 260-WCHAR NT-prefix slots. DriverEntry performs bounded PASSIVE_LEVEL
  reads and exact owner/DACL checks before `FltStartFiltering`. Committed records allow at most 16
  prefixes; pending unions allow 32. It accepts strict records only; for corrupt but readable
  records it retains complete independently valid slots and known v1 destination flags.
  Missing/corrupt/unreadable/ACL-rejected states are reported in prototype admission status and the
  driver trace. Only scopes identified from readable data are enforced; when none can be identified,
  no scope is enforced and the explicit state records why. Protocol layout stays at version 18.
  The first authenticated SET_POLICY installs the live snapshot while retaining the boot union;
  only after `Scopes` is durable and `PendingScopes` is removed does the service send the same
  SET_POLICY with `Control.Reserved=1` to clear that union. A registry or finalization failure keeps
  the union enforced and prevents the service from reporting policy applied.
- Agent not running (boot, crash, restart): identified protected scopes fail closed for new
  writable creates and new writable sections. Reads and operations outside a matched scope keep
  their existing behavior. A port connection alone is not authorization: the accepted client must
  be SYSTEM, control messages are bound to its process ID, and authentication becomes active only
  after a valid SET_POLICY succeeds.
- Trust requires both `FLTFL_INSTANCE_SETUP_NEWLY_MOUNTED_VOLUME` and a passed startup canary.
  Pending, failed, timed-out, unsupported, or detached instances stay Untrusted. Trust loss is
  sticky until reboot, including a canary diagnostic reset. A late load after boot reports
  `protection pending reboot` and leaves its volumes Untrusted. Agent-down creates still fail
  closed; the demand-start Phase 1 diagnostic path does not claim volume trust without the canary.
- `Test-StagedBootStart.ps1` and the `boot-start` wrapper path prepare a durable C: policy scope,
  configure one-boot standard Verifier, reboot, durably record filter readiness before the first
  unique marker write, and compare the marker's allocated bytes through an independent raw-volume
  observer. The harness exercises agent stop/restart, trusts C: and a fresh VHDX, then runs E1 on
  S: with a writable mapping created before late filter attachment. E1 passes when the late-loaded
  volume reports Untrusted and `protection pending reboot`; its raw bytes are recorded and may
  change because late attachment cannot protect an already-existing mapping. The harness restores
  the original driver/policy and reboots for final checks.
- One adversarial review of the boot path is required before the first VM boot. X4 must establish
  the first user-mode attempt versus observed filter readiness and that no destination bytes appear
  before readiness; the post-boot VHDX must be newly mounted/trusted, while E1's already-mounted
  instance stays Untrusted even if its canary passes.

Exit: boot with the feature driver under boot Verifier, folder protected before user logon, agent
start and stop handled, test-only unload restores the VM.

### Phase 3: policy changes without scans

- Pending policy plus one admission epoch held to lower completion on every admission path (create,
  write open, writable section, rename/link, set-information, delete, selected FSCTLs, publication),
  drained before the pending policy becomes current.
- **Boot-path assertion:** before the service's first authenticated `SET_POLICY`, admission uses only the
  `BootPolicy` snapshot. It may refuse a mutating open only when its resolved target is in that scope or
  its unresolved target could be in that scope; the driver's private staging namespace keeps its own
  access gate. Read-only opens and image loads outside the scope stay pass-through; an unavailable epoch
  may not turn a known out-of-scope operation into a refusal. Writer-tracking loss only withholds
  promotion and never refuses I/O.
- Registry of streams that had a writer since boot; a stream in the added scope with H, S or C
  nonzero is Activating, otherwise Protected at once. Activating refuses new writers and publication
  into that file and is promoted when Free(F) and its cache is flushed. The service reports which file
  is held, and the holder process when known.
- Policy flag (feature build only) that turns taint enforcement off, used by every MVP test.
- The scan-based fence (`StageFence.c`) is taken out of the MVP admission path. It is deleted after
  the milestone review if nothing depends on it.

Exit: the expansion, shrink and retained-section scenarios below pass the invariant test.

### Phase 4: invariant suite and release gate

One harness, every case judged by an independent raw-volume observer of the destination's allocated
extents plus fresh and uncached readers:

- cached write, mapped write, overwrite and replacement save, rename into the folder;
- writer that existed before the scope was added (handle, mapped view, retained section, handle
  duplicated into another process), each through Activating;
- approve, block and justification paths; service restart in the middle; agent down at boot;
- concurrent writers and readers;
- ordinary run, runtime Verifier and boot Verifier; latency against the budget (p95 <= 250 ms,
  max <= 1000 ms).

Exit: zero unapproved bytes observed in every case, under all three modes, with clean restoration.

### Phase 5: milestone review

A fresh adversarial review attacks the running system with the harness, not the paper design.
Fix what it finds, rerun phase 4. Then decide the order of the deferred destinations.

## Dependencies and decisions

- **Platform:** the MVP targets Windows 10 build 19045.2965 only (owner decision 2026-10-03, replacing the
  earlier deferred Windows 11 gate). Windows 11 and other builds are post-MVP qualification work.
- Fail closed on the protected scope while the agent is down: follows the agreed rule; noted here
  because users will see saves into the folder refused until the service starts.
- Taint stays compiled in normal builds; the MVP proves the guarantee without it. Removing it from
  production is a later cutover decision.
- Owner decisions 2026-10-03 (Phase 1 remainder):
  - Test-only controls (for example holding the canary open, a dedicated canary pool tag for fault
    injection) are allowed only in the test build, never in a build a user could receive.
  - A volume whose start-up canary fails or times out stays Untrusted until reboot; no retry.
  - If C(F) or H(F) tracking is lost (instance teardown or draining with work in flight), writer state
    stays Unknown until reboot. No recovery scan, no timers: an unexpected unload or crash is a bug to
    fix, not a state to clean up.
  - No relative cost threshold for the MVP; the absolute budget stands.
- Blocked staged versions (owner decision 2026-10-03, option 1): the user gets their own blocked version
  back. After a version is `Blocked`, the service copies that exact sealed snapshot (digest-checked) into
  a per-user location readable only by that user and SYSTEM (the earlier `SafeUpload\_bloqueados`
  pattern in the user's profile), and the block window says where it is. Nothing reaches the protected
  destination. Requirements:
  - The copy target must never be a protected destination or a synced folder; if it would be, fail
    closed and keep the version in staging.
  - The service runs as SYSTEM and writes into a user-controlled profile: it must not follow junctions,
    symlinks or hard-link tricks (open the target relative to a verified handle, refuse reparse points,
    create new files only), or a user could redirect a SYSTEM write anywhere on the machine.
  - The staging copy is deleted only after the hand-back copy is written and verified and the
    justification window has closed; a failed hand-back keeps the version in staging and is audited.
  - Test it in phase 4 together with the blocked-save cases.
- Lost writer tracking is scoped (owner decision 2026-10-03, refines the rule above): writer records dropped because their
  volume was torn down (dismount, removal, detach; instance teardown flagged before contexts are freed) do not set the
  machine-wide Unknown, because Windows invalidates those handles permanently and a remounted volume is a new attachment
  with its own canary. A writer record dropped while its volume is still mounted (a missed cleanup) still sets the machine-wide
  Unknown until reboot. Conditions: the premise is proven on this build (an old handle and an old writable mapped view cannot
  write after dismount and remount), both cases are counted and visible in the Inspector, and anything ambiguous falls back to
  machine-wide Unknown.
- Trust boundary (owner decision 2026-10-04): local administrators and SYSTEM are trusted for the MVP. The MVP protects against
  standard users; admin/SYSTEM tampering (taking ownership of the policy key, loading/unloading drivers, a SYSTEM process talking
  to the port) is out of scope and documented. Cheap hardening still applies: the port accepts only the SafeUpload service's own
  service SID (not any SYSTEM process), and policy values are never used after an ACL mismatch. The agent's local `policy.json`
  and `%ProgramData%\SafeUpload` directory use protected explicit ACLs for SYSTEM and Administrators, with no inherited ACEs.
- Installation requires a reboot (owner decision 2026-10-04): the installer stages the driver as boot-start and does not start it;
  nothing is protected until the first reboot, so there is no late-attach period in normal deployment. A driver loaded late anyway
  (manual load/attach) leaves its volumes Untrusted until reboot and claims no protection there.
- Phase 3 design v1 accepted ([design](evidence/2026-10-04/phase3-design-v1.txt)), with this orchestrator decision made unattended on
  2026-10-04 (owner asleep; revisit if you disagree). **Stores through a writable view that predates a new scope**: a file-system
  minifilter cannot stop CPU stores into an existing view, but it can stop them reaching disk. Cutoff rule: at the epoch swap that adds
  a scope, each registry entry that becomes Activating gets one `CcFlushCache`+`FltFlushBuffers` (data written before the cutoff is
  legitimate and reaches disk), after which **paging writes to that stream are denied** until promotion. A file with dirty pages created
  after the cutoff can never be promoted (its pages cannot be cleaned without writing them): it stays Activating until reboot and is
  reported to the service ("close the application; unsaved in-memory changes will be lost"). The on-disk bytes therefore never change
  after the cutoff, the invariant holds, and no scan or taint is needed. This replaces the design's "grandfathered bytes" caveat.
  Implementation order: (1) TxF refusal + transaction tracking; (2) writer registry since boot, Free(F) evaluation by file ID,
  Activating classification and status page; (3) admission epoch + two-phase policy apply; (4) Activating enforcement, cutoff flush,
  paging-write denial, cache-barrier promotion; (5) remove StageFence from the admission path; then the Phase 4 suite.

Phase 2 status (2026-10-04): boot start qualified on the guest under boot Verifier (boot-start run 13, [readout](evidence/2026-10-04/boot-start-run13-readout.txt)):
X4 first write after boot denied with durable readiness recorded first and raw bytes identical; agent-down fail-closed for new opens and writable sections; fresh
VHDX trusted; E1 shows a late-attached volume Untrusted with "protection pending reboot" and records that a pre-attach mapped writer DID change bytes there (documented
limit). Open carried-forward item before release: N-01 (normal build needs a canary/trust path). N-02 implementation now has a SYSTEM-only agent seed mode and installer gate before restoring driver boot-start; Windows verification of the installer path and final registry read-back remains required.

Phase 4 design v1 accepted (2026-10-04, [design](evidence/2026-10-04/phase4-suite-design-v1.txt)): one observer module + case table + runner; work packages WP1-WP7
(observer library and VM self-tests can start before Phase 3 enforcement exists; case batches need Phase 3). A flush at the cutoff that includes post-cutoff stores (case A05) would
falsify the Phase 3 cutoff mechanism; the harness must test it, never reinterpret the cutoff.
- **2026-10-04, owner-approved: the writer registry is a ledger, not a gate.** registry-txf runs 2-4 showed the Phase 3
  registry denying every writer create on a volume once the instance was Unknown (a handle that predates the driver closing,
  a full table, an allocation failure): the guest's own SYSTEM tasks could not write files. Decision: tracking loss never
  refuses or cancels I/O. It records Unknown at the narrowest correct scope (entry, else instance, machine-wide only under the
  scoped lost-tracking rule), sticky until reboot; Unknown only withholds protection claims and promotion (files stay
  Activating) and is reported loudly. Scoped writes stay fail-closed in exactly one place, the existing admission path. An
  unmatched writer cleanup counts as loss only on a trusted (boot-attached) instance; late-attached volumes claim nothing.
  Registry capacity stays bounded per instance; overflow can only stop new scopes from activating, never stop writes (a
  per-user quota may come later). Free/promotion tests run in boot-start mode (trusted instance); late-load harness runs
  assert H/S/C/T and Unknown reporting only.
- **2026-10-04, unattended (under the ledger-not-gate decision): Unknown is scoped by what was lost.** A loss about one file
  (identity open, transaction enlistment, section binding) marks only that entry, keyed by file ID, which then can never be
  Free. A rename loss widens to the instance, because the entry's name is stale and scope classification matches by name.
  Diagnostics (Evaluate) are reads and never persist reasons they merely derive (untrusted volume, instance Unknown, work in
  flight); run 8 showed the first probe on a late-attached volume poisoning it. Section-object pointers are rebound, not
  refused: NTFS keeps one SCB per live stream, so a reused or changed pointer proves the old incarnation dead. Retiring an
  entry releases its instance/volume references (an entry pinning its instance deadlocked instance teardown). Harness
  consequence: registry-txf in late-load mode starts the agent with staging off (the private staging namespace requires a
  trusted instance since Phase 2) and accepts TRUST as the only Unknown reason.
- **2026-10-04, owner-approved: registry pruning.** An entry is removed once its file is provably quiescent: no writer
  handle, no writable section in flight, no transaction, no rename in flight, no recorded Unknown, and the live stream has
  neither a data section nor a shared cache map (no mapping, no dirty cache). Checked by one reclaim worker (open by the
  64-bit file reference, all 128 ID bits verified, then the stream's section pointers), queued when an instance or the total
  crosses 3/4 of its limit or on a capacity failure; the prune itself re-checks under the registry lock. No timers, no
  file-system scan. The registry is bounded by concurrency, not uptime; an absent entry keeps meaning provably free.
  Run 10 motivated it: ordinary Windows activity filled the 1,024-entry instance limit within minutes.
- **2026-10-04 status: Phase 3 increments 1-2 qualified.** registry-txf run 19 passed 93/93 under runtime Verifier with a clean unload and
  independent restoration (readout: evidence/2026-10-04/registry-txf-run1-19-readout.txt). Next: increments 3-5 (admission epoch and two-phase
  apply, Activating enforcement with cutoff flush and cache-barrier promotion, removal of StageFence from admission), then Phase 4 S00 in
  boot-start mode, where Free/promotion are exercised on a trusted instance.
- **2026-10-04 status: Phase 4 S00 lifecycle verified.** The invariant suite ran its first case end to end in boot-start mode (prepare,
  activating reboot, standard-user writer, raw-volume samples, restoration reboot, finalize; independent BaselineClean=True), ForbiddenByteCount
  0, latency p95 1.3 ms. Verdict INCONCLUSIVE until the proof adapters exist (lower mutation ledger, metadata expectations, cadence accounting,
  live taint readback, service timelines). Open product finding: a trusted boot-attached C: reports writer tracking Unknown minutes after boot
  (suspected untracked open-by-ID writers); must be fixed before promotion can work on a real boot. Readout: evidence/2026-10-04/s00-attempt1-7-readout.txt.
- **2026-10-05, unattended (test evidence, consistent with "admins/SYSTEM trusted"):** the Phase 4 notification-absence proof accepts process
  creations in the case window without per-process service-SID evidence only when authenticated SCM evidence shows the SafeUploadAgent service
  absent at both edges and never installed in the window: only the SCM assigns a per-service SID, to the process of the service it starts, so
  no process can carry it except through privileged token forgery, which the owner decision trusts. With the service installed, the gap still
  makes the proof INCONCLUSIVE; the agent image/user check always applies.
- **2026-10-05 finding (blocking): the increments 3-5 driver is not boot-safe yet.** Seed case S01 (boot policy with one protected
  scope) bugchecks 0xEF at the activating reboot: wininit.exe dies (exit 14001, SxS activation context) because early-boot I/O outside
  any scope is refused or broken. Deterministic; increments 1-2 (mvp3-a10) boot the same policy fine. Invariant restated: at boot, with
  only the BootPolicy snapshot, the driver may refuse only mutating access into protected scopes; reads, image loads and executes outside
  any scope are never refused. Guest recovery needs an owner-run rollback: evidence/2026-10-05/s01-bugcheck-rollback.sh.
- **2026-10-05 decisions (unattended, from the Phase 3 milestone review, evidence/2026-10-05/phase3-milestone-review.txt; build mvp3-b11
  5faa232e, 0/0 on all four builds, not yet run on the VM):**
  - Refusals for an unresolved name, raised IRQL or a top-level IRP apply only on volumes that can hold a current, pending or boot scope
    (cached, IRQL-safe per-volume classification). A volume proven outside every scope is never refused. (P0-1, P1-1)
  - Adding a scope and admitting paging writes share one atomic cutoff. A paging write that starts after it is denied or makes the entry
    permanently non-promotable; promotion never rests on a flush that may contain post-transition writes. (P0-2)
  - Alternate data streams are tracked per file (file ID + section pointer + stream suffix), joined to candidate scopes at expansion, and
    their paging writes are gated. An ADS open never marks the volume Unknown. A failed join keeps the candidate Unknown. (P0-3)
  - Expansion classifies a file against every hard-link name (PASSIVE worker). If enumeration fails, the file stays gated. (P0-4)
  - A lost directory-rename record advances a per-volume rename-loss generation; later expansions treat names older than it as
    unresolved and gate them before the transition completes. (P0-5)
  - The prototype TxF path no longer hard-codes a bootstrap scope; scope decisions use configured policy only. (P1-2)
- **2026-10-05 decisions (unattended, from the fix-round re-review, evidence/2026-10-05/phase3-fix-review.txt; build mvp3-b14
  15ae3f4d, 0/0 on all builds, not yet run on the VM):**
  - Ledger, not gate, extended to paging writes: losing tracking never refuses a paging write. Instance Unknown only blocks promotion and
    activation on that volume.
  - Two-tier registry. Names are optional: the hard-link classifier derives every name from the file ID. When the name tier is full, a
    file gets a compact record (volume, file ID, section pointer, stream flag and suffix hash; fixed pool 4x the name tier), classified
    by ID at expansion and gated when in scope or undecidable. A full registry no longer drops ADS writers. Only when the compact tier
    is also full does the owner rule "lost tracking => Unknown until reboot" apply (per section pointer when known, else per volume).
    Accepted residual: a user holding thousands of live writable handles on a scoped volume can stop promotions there until reboot;
    it never refuses I/O. (Flagged to the owner.)
  - The activation worker's own cutoff flush is admitted by owner (thread + epoch), serialized at the paging admission boundary; a
    failed flush is retried with bounded backoff, then stays Unknown. Denied tracked paging writes set the sticky DirtyAfterCutoff;
    promotion requires it clear. Resumed cutoffs requeue reclaim.
  - By-ID mutating opens follow the volume rule: pass on volumes that cannot hold a scope; on a possibly scoped volume, classify all
    link names by ID at PASSIVE and refuse only in scope or undecidable.
  - Link classification dedupes parent-name queries and runs a 32-identity budget per pass; unfinished identities stay gated.
- **2026-10-05 decision (unattended): activation waits for Free(F); no paging-write cutoff.** Three review rounds
  (phase3-milestone-review, phase3-fix-review, phase3-fix2-review) each found new holes in the epoch paging-write cutoff, ending at a
  fundamental one: a filter cannot prove that a page flushed after the cutoff holds only pre-cutoff stores. Replaced by the owner's
  original model: a file entering a scope becomes Activating. New writable opens and new writable section creations into it are refused,
  but existing writers (handles, mappings, cached data, paging writes) are never refused. The file becomes Protected only when Free(F)
  (H=0, no data section, no shared cache map, C=0, T=0) is observed after the Activating gate is in place, so no new writer can appear.
  Bytes written before that point count as content that predates protection (baseline). Removed: owner-admitted cutoff flush,
  DirtyAfterCutoff, volume-wide transition paging denial, paging-write gate. Paging I/O is never refused by the registry (ledger, not
  gate), so the boot-safety invariant holds by construction. A file held open forever stays Activating and is reported. Unknown SOP
  markers from overflow are pruned once their SOP is quiescent; while any marker on an instance is live and not provably out of scope,
  promotion on that instance waits.
- **2026-10-05 review 4 disposition (source changes; VM qualification pending):** add per-entry W rundown for tracked nonpaging
  mutating IRPs and require W=0 in final promotion serialization; classify live overflow SOP markers by file ID, all hard-link names,
  ADS suffix, and current/pending/boot union; retain exact per-acquire section spill records so capacity state clears after matching
  failure/release and stream quiescence. If there is no stable file identity or an exact completion record cannot be retained, keep
  fail-safe Unknown sticky because scope/recovery cannot be proved; accepted availability limit. No paging I/O refusal is introduced.
  Required VM cases: cleanup racing a pending noncached write, mutating SET_INFORMATION/FSCTL completion, in-scope/out-of-scope/
  undecidable overflow markers across a policy change, ADS and hard-link marker classification, and section spill acquire failure,
  release, marker binding, and identityless/allocation-loss fallback.
- **2026-10-05 decision (unattended, from evidence/2026-10-05/phase3-w-review.txt): prefer deletion for availability-only findings.**
  Live overflow markers block promotion on their instance until quiescent (no per-marker OUTSIDE classification: it raced in-flight
  renames). Section-slot overflow uses only the fixed 64-slot table; beyond it the exact entry (or the instance) becomes sticky Unknown
  and the acquire still passes (no unbounded spill records). Accepted limit: capacity Unknown does not recover until reboot. Fast-I/O
  PREPARE_MDL_WRITE is disallowed so cached MDL writes are reissued as counted IRP writes.
- **2026-10-05 continuation, b22 S01 boot-Verifier attempt (blocking):** exact archive/manifest validation matches
  the driver tree at `c95a8eef` and current HEAD `e85f87d6`, not the older `4ea9b793` attribution. The signed
  feature SHA-256 is `92D4FED4EF3C226DABD9AEC03C735E2599D2FCA6D5BD4C83E04C6A7FE00C9BE7`;
  all four committed WDK logs remain 0 warnings/0 errors with PREfast/ApiValidator. The recovered guest's only
  baseline residue was an unloaded orphan test-profile registration; the owner approved its guarded removal,
  after which the independent baseline and the wrapper's baseline both returned `BaselineClean=True`.
  S01 `b22s01a` reached product-policy preparation and the activating reboot under boot Verifier, then its display
  showed `IRQL_NOT_LESS_OR_EQUAL`. The wrapper stopped with recovery required; no successful boot, readiness,
  denied-write or independent restoration qualification is claimed. The external checkpoint and original memory
  ELF are retained. CPU 1's captured stack confirms bugcheck `0xA`: the volume-scope-cache spin-lock path calls
  `SafeUploadPathUnderPrefix` -> `RtlPrefixUnicodeString` at IRQL 2; that routine requires PASSIVE_LEVEL. CPU 0
  is frozen in Verifier trimming and is not the faulting stack (the broad `!analyze` synthetic `0x161` bucket must
  not replace `KiBugCheckData` or CPU 1's stack). Fix the resident cache comparison without widening admission
  semantics, then get a fresh review, four builds and a new checkpointed boot qualification. Evidence:
  `evidence/2026-10-05/s01-b22s01a-cdb-cpu1-analysis.txt`, `evidence/2026-10-05/phase4-suite-b22s01a-index.txt`,
  `evidence/2026-10-05/boot-start-invariant-S01-denied-write-after-boot-boot-verifier-b22s01a-recovery-required.txt`.
  Exact owner-run recovery: `evidence/2026-10-05/s01-b22s01a-rollback.sh`; the agent does not repoint VM disks.
- **2026-10-05 design reconciliation (unattended, applies the existing decisions):** Phase 4 design v2
  (`evidence/2026-10-05/phase4-suite-design-v2.txt`) supersedes v1's cutoff/paging-denial expectations with final
  Free(F)/W promotion, conservative live-marker waiting and sticky fixed-section-capacity Unknown. It retains
  every original case family, storage/outcome variant, observer, mode, latency, hand-back and release gate, and
  adds explicit review-4 race/capacity families. Existing-writer bytes during Activating are recorded history;
  the baseline must be bound to the proven promotion boundary. An unexplained Protected mutation is never
  rebaselined. The current three Ready seed cases and 22 NotReady family placeholders do not qualify Phase 4;
  lower mutation ledger, live taint readback, observer self-tests and full case implementations remain required.
- **2026-10-05 b23 build checkpoint (runtime qualification pending):** source `39406a55` replaces only the
  resident scope-cache prefix comparator used under its spin lock. The general PASSIVE comparator remains
  unchanged. A fresh adversarial source review found no blocking defect; the extracted production helper
  passed 24 literal semantic vectors with GCC and Clang. Four exact-source WDK builds (normal/feature,
  Debug/Release) passed with PREfast, DriverRecommendedRules and ApiValidator, zero warnings/errors;
  the orchestrator read all four builder logs and validated the archive, manifest and signed artifact.
  Signed feature SHA-256: `02BDF87DC646D9D64D62EAE3E3C5DED5892F85C119FC04B8A528D9C86FCE79`.
  Evidence: `evidence/2026-10-05/exact-mvp3-b23-root-validation.txt`,
  `evidence/2026-10-05/s01-b22-irql-fix-review.txt`,
  `evidence/2026-10-05/volume-cache-prefix-check.txt`. Boot and runtime Verifier qualification remain
  required. The debuggee still points to the failed b22s01a checkpoint overlay; a new VM run awaits the
  exact owner recovery above followed by an independent clean-baseline check. Offline observer-corpus
  implementation can proceed while waiting; it does not advance a VM acceptance gate.
- **2026-10-05 b23 compiled review and WP2 offline increment:** the matching PDB GUID/age and linked PE
  section map place the new comparator and its cache/lock call chain in nonpaged `.text`; the comparator's
  disassembly contains no calls. Root checked the retained symbol/disassembly evidence. This proves linked
  placement, not successful boot or runtime residency (`evidence/2026-10-05/b23-residency-review.txt`).
  The new driver-off observer corpus adds actual resident conversion, 1-byte/4-KiB classification,
  sparse/compressed/fragmented allocation, replacement/EOF/slack, directory-index and MFT cross-run checks,
  and malformed copied raw-record/run/short-read controls. It uses the existing raw decoder and requires
  matching fresh buffered/unbuffered and retained readers. Windows PowerShell 5.1 parsed the exact corpus
  with zero errors, compiled the fixture stimulus, and passed nine literal assertion controls after a
  validation-fixture type-alias fix; both attempts are retained at
  `evidence/2026-10-05/observer-corpus-builder-attempt-a.txt` and `observer-corpus-builder-attempt-b.txt`.
  No corpus VM run is claimed. Actual MFT/index fragmentation and raw slack may remain unavailable;
  unproduced representations are INCONCLUSIVE. Temporal write-then-erase proof still needs the lower
  ledger. The checkpoint coordinator is being authored separately; all Phase 4 acceptance gates stay open.
  The review-4 fixture capability map (`evidence/2026-10-05/review4-fixture-capability-map.txt`) records the
  exact reusable stimuli and missing lower-completion/W/marker receipts; older aggregate counters are not
  substituted for the required races.
- **2026-10-05 b24 build checkpoint:** the observer source increment `fb704ed2` has all four required
  exact-source WDK builds at 0 warnings/0 errors with PREfast, DriverRecommendedRules and ApiValidator.
  Root read the builder logs and validated all 26 source files, archive/manifest and artifact hashes
  (`evidence/2026-10-05/exact-mvp3-b24-root-validation.txt`). The kernel source manifest is identical to
  b23; this increment adds harness code only. Signed feature SHA-256:
  `59D78808F5AB37ECC4668DCB921715BE65E7FC00B87F469B269DBCBBA2749BE6`.
  Neither b23 nor b24 has a qualifying VM run; owner recovery and an independent clean baseline still
  precede S01. The new driver-off coordinator remains under offline review and is not VM-qualified.
- **2026-10-05 WP2 coordinator offline increment (VM gates unchanged):** the new host/guest adapter freezes
  corpus/observer/coordinator bytes, runs through the existing disk-checkpoint wrapper, retains child streams
  and a verified evidence ZIP, and requires independent baseline/audit restoration before exporting an
  ObserverCorpus result. Phase4Suite always remains NOT_QUALIFIED. Root read the actual Windows PowerShell
  5.1 logs: final coordinator parsing, exclusive directory creation/duplicate rejection, child exits 0/1/2,
  ZIP SHA/CRC readback and owned TEMP cleanup passed; the corrected corpus passed nine reader controls.
  Earlier failures are retained: a generic-list array conversion and a stale tracked validation hash pin.
  The host's production validator passed seventeen synthetic rejection controls plus positive controls;
  these are explicitly not VM evidence. It requires matching fresh/retained readers, actual target byte
  transitions, classification captures and MFT/index physical run coverage, with overlapping maps rejected.
  A fresh independent Luna review found no remaining source blocker; root checked its claims against source
  and raw logs (`evidence/2026-10-05/observer-coordinator-final-review.txt`,
  `evidence/2026-10-05/observer-coordinator-root-validation.txt`).
  **Unattended harness decision:** on timeout or forced child termination, preserve fixture/evidence trees
  and report recovery required because native descendants may remain live. Do not archive or delete them
  to make the failed run finish. Host recovery collection requires an already-complete coordinator marker
  and matching ZIP SHA; collection never establishes restoration. This changes no driver admission,
  cutover or lost-tracking policy. Four exact-source builds for this source increment remain required.
  Owner recovery of the failed b22s01a overlay and a clean independent baseline still precede the next S01;
  no corpus, b23/b24, review-4 or full Phase 4 VM qualification is claimed here.
- **2026-10-05 b25 build checkpoint:** coordinator source commit `6174dfda` has four exact-source WDK
  configurations at zero warnings/errors with PREfast, DriverRecommendedRules and ApiValidator. Root
  read all four builder logs and verified the 26 source files, archive/manifest, signing, Inspector and
  WriterFixture artifacts (`evidence/2026-10-05/exact-mvp3-b25-root-validation.txt`). The driver source
  manifest is unchanged from b23/b24. Signed feature SHA-256:
  `03A127AC8B41BADE8FB005B1E190CEC436B2BAF7361CDEF29BD725DD8B4D23CA`.
  A prepare-only observer package freezes three exact guest inputs at
  `evidence/2026-10-05/observer-corpus-wp2prep1-d39d6c5358c4-inputs/provenance.json`; source selection
  was clean and no VM was touched. This is lifecycle preparation, not a case result. S01 remains first
  after owner rollback and independent clean-baseline verification; b25 has not run on the debuggee.

## Current acceptance queue (2026-10-05 continuation)

This queue applies the owner's priority: finish S01 and independent restoration first, then missing
proof instrumentation and critical Phase 3 races, then complete end-to-end acceptance. Implemented,
run on the VM, and qualified are separate states. A compiled fixture or a synthetic parser control
does not close a VM requirement. The full contracts remain in `phase4-suite-design-v2.txt`.

- **S01 b25s01b actual result:** the activating boot completed with the exact b25 feature driver under
  boot Verifier (`0x1209bb`), changed boot identity, valid one-scope BootPolicy, and durable readiness
  on trusted C: (canary checks 15). No bugcheck was observed. The writer task ran but its first
  `Add-Type` failed: the compiler could not find `C:\Windows\TEMP\bhqubgdv.0.cs`, before token
  identity publication. There are zero recorded operations, so scope denial is **not qualified**.
  The precise temporary-file permission/lifecycle cause is not established by the retained evidence.
  Independent restoration has a changed final boot, original driver/policy, Verifier off, no owned
  actors/tasks/fixtures, restored process audit, and `BaselineClean=True`. Evidence prefix:
  `evidence/2026-10-05/boot-start-invariant-S01-denied-write-after-boot-boot-verifier-b25s01b`;
  inspect `-artifacts/actor/completion.clixml`, `-artifacts/readiness.json`, `-artifacts/case.json`,
  `-final-restored-state.txt`, and `-root-readout.json`. The seed remains INCONCLUSIVE and Phase 4
  remains unqualified. Trusted C: already reports `instanceWritersUntracked=1` at readiness; this
  carried finding still requires diagnosis and a proof that promotion is usable after real boot.
- **Unattended S01 harness decision:** direct only the writer process's TEMP/TMP to its already
  writable actor fixture directory before compilation. This is necessary to execute the scope-denial
  requirement with the existing standard-user token; do not grant it administrator rights, change
  machine temporary-directory permissions, or weaken admission. Review and validate this narrow
  change, then repeat checkpointed S01 and independent restoration. No diagnostic guard is needed
  to rediscover the already retained compilation failure.

| Work package / acceptance requirement | Implemented | Run on VM / qualified | Evidence required to close it |
| --- | --- | --- | --- |
| S01 boot safety and first protected write | Resident comparator fix and seed lifecycle; writer temp repair `6a833c91`, exact b30 four-build proof | b30s01c ran and narrow boot-safety gate qualified; full Phase 4 seed stays INCONCLUSIVE | [Root readout](evidence/2026-10-05/s01-b30-root-readout.json), [independent review](evidence/2026-10-05/s01-b30-independent-review.txt), actual case/raw/readiness and separate clean restoration |
| Preserve Phase 3 increments 1–2, registry-TxF 93/93 | Existing corpus | run 19 qualified on its original source; b30 run 20 failed 19/93 with independent clean restoration | Exact-source runtime-Verifier 93/93 corpus and independent restoration after S01 |
| WP3A live proof instrumentation | Upper W producer/parser and context Unknown receipt integrated in `3011cc8b`, exact b31 builds; controlled lower fixture/controller source integrated | b31 context Unknown readout ran; upper W-ticket observation and lower fixture not exercised; no race qualified | Loss-detecting upper/lower identity and completion pairing, live taint flags, coherent promotion/epoch/Free boundary, marker/section receipts, real service permit/journal/notification coverage; gaps stay INCONCLUSIVE |
| RV4-W01 / A05 cleanup versus pending noncached write | Aligned writer, exact-FO lower hold and always-INCONCLUSIVE child implemented; safe parent lifecycle pending | Pending | Actual cleanup/H=0 while W>0, Activating retained, matched lower success/failure/cancel/draining or explicit unavailable outcomes, raw images and promotion boundary; missing-completion Unknown and Protected control |
| RV4-W02 mutating SET_INFORMATION/FSCTL and MDL retry | Existing native encodings only; completion fixture pending | Pending | Each metadata/FSCTL class, actual lower completion and same W ticket through rename transfer, cleanup race, disallowed fast MDL retried as counted IRP, exact names/IDs/metadata/raw runs |
| RV4-M01/M02 overflow, ADS and hard-link classification across policy | Product paths exist; exact marker receipts and expanded cases pending | Pending | Distinct tier exhaustion, live inside/outside/undecidable marker wait, rename/link races, full identity/ADS binding, loss generation, safe quiescent retirement, sticky loss and independent-volume controls |
| RV4-C01/C02 fixed section capacity, binding and fallback | Existing separate section HOLD/FAIL fixture; distinct-identity corpus pending | Pending | Exactly 64 identified slots and overflow, lower acquire failure/release/draining, exact-entry or instance sticky Unknown, binding/identity/allocation/no-SOP fallback, reboot reset and no false paging refusal |
| WP2 independent observer qualification | Corpus and checkpoint coordinator in `fb704ed2` / `6174dfda`; builder-only controls passed | New corpus has not run on VM; temporal completeness open | Driver-off raw representation/reader/corruption self-tests on this VM and artifact, complete allocated extents/MFT/index/slack, cadence gaps, transient write-erase detection with lower ledger |
| N-01 normal-build canary and trust | Isolated draft under review; capacity liveness defect open | Pending | Reviewed normal-build path, four exact builds, boot newly-mounted canary/trust, failed/late/detached controls; test hooks absent from normal |
| N-02 installer path on Windows | Isolated source `fc0d7ff6`; mock validation only; stale agent test repair pending | Installer has not run on debuggee; not qualified | Owner-authorized real Windows install, native ACL/SCM/SYSTEM seed readbacks, no demand start, reboot and standard-user tamper controls, independent restoration |
| Trusted C: tracking Unknown after boot | Feature-only successful-context reason/site receipt in `3011cc8b` | b31 S01 records cleanup `0x40`, site 2333; originating object/status unresolved | Identify exact tracking loss from live evidence, fix with fresh kernel review/builds, runtime Verifier and boot proof; do not reset Unknown or add a scan |
| WP4 real saves and hand-back: C01–C05, B01–B02, X01 | Case-family placeholders; underlying owned-stream/inspection path exists | Complete acceptance pending | Cached/mapped/overwrite/replacement/rename, approve/block/justification, exact sealed version, safe user-only hand-back and failures, concurrent writers/readers, real app/service and raw observer |
| WP5 policy and representations: A01–A05, P01–P03 plus all RV4 families | Case-family placeholders and older diagnostic stimuli | Complete acceptance pending | Handle/view/retained-section/duplicate holders; expansion/shrink epochs, TxF, cache barrier and every required storage/outcome variant bound to Protected transition |
| WP6 lifecycle/refusals: R01–R03, P04–P06 | Seed agent-absence path only; other family placeholders | Complete acceptance pending | Restart mid-save and mid-policy, agent down at boot and reconnect, capacity/loss, boot/trust/install, authorization/refusal corpus |
| WP7 complete Phase 4 gate | Table reserves S00–S02 plus 22 original families; RV4 variants still need expansion | No complete three-mode run qualified | Every expanded required case in ordinary, runtime-Verifier and boot-Verifier modes; zero unapproved bytes, real service outcomes, latency p95 ≤250 ms/max ≤1000 ms, separate restoration per case |
| Phase 5 fresh adversarial running-system review | Pending | Pending | Fresh Luna attacks actual running system with harness, retained attack evidence, fixes with fresh review/builds, then rerun complete Phase 4 |
| Remove obsolete StageFence after milestone review | Out of admission path | Deletion pending milestone dependency review | Source/dependency inspection showing no remaining dependency, coherent deletion and required builds |

All original families remain required: S00–S02, A01–A05, C01–C05, B01–B02, R01–R03,
P01–P06, X01, and expanded RV4-W01/W02/M01/M02/C01/C02. A seed-only S01 pass will close
the immediate boot-safety gate, not the missing Phase 4 proof adapters or the full acceptance suite.

**2026-10-05 S01 b30s01c disposition:** exact source `6a833c91` booted with one protected BootPolicy scope under active boot Verifier `0x001209bb`. Same-boot readiness QPC 626682325 precedes release 2277718731 and first standard-user attempt 2278134449 at 10 MHz; OS provenance matches the unelevated actor. All 101 native opens returned access denied (5). Root checked all 59 retained raw manifest artifacts and absence of 303 distinct forbidden blocks; this proves sampled unchanged bytes, not temporal completeness. Independent final restoration reports `BaselineClean=True`, original driver/policy, Verifier off, removed actors/tasks/fixtures and restored audit. Root read the independent review against actual source and evidence ([readout](evidence/2026-10-05/s01-b30-root-readout.json), [review](evidence/2026-10-05/s01-b30-independent-review.txt)). The immediate S01 boot-safety gate is qualified. The exported seed verdict remains INCONCLUSIVE: lower mutation ledger, live flags, temporal and authenticated service proof are still missing. Phase 3 increments 3–5 and complete Phase 4 remain unqualified. Trusted C still reports instance tracking Unknown at readiness; its cause is not established.

## RV4 W proof preparation integrated after S01

RV4 W observation preparation checkpoint (2026-10-05): source `f99989f19cc6642cf59c7ab8f24b9b94d85f08fe` built as b27 with all four exact WDK configurations at zero warnings/errors, PREfast/DriverRecommendedRules and ApiValidator. Root read all actual driver/Inspector logs, matched every archived source file and fetched artifact hash, and accepted the independent matched-PE/PDB placement review of the resident snapshot helper ([root readout](evidence/2026-10-05/exact-mvp3-b27-root-readout.json), [placement review](evidence/2026-10-05/exact-mvp3-b27-residency-review.txt)).

Unattended harness decision: the host W trace parser checks only one successful ordinary upper IRP_MJ_WRITE ticket pair. It requires a bounded complete loss-free window, exact caller-pinned identity/range/alignment, noncached nonpaging flags, equal nonzero SOP and full STATUS_SUCCESS completion information. Errors, cancellations, metadata/draining and foreign W traffic are inconclusive here, not inferred covered. Thirty-two synthetic rejection controls and a fresh adversarial source review are retained ([controls](evidence/2026-10-05/rv4-w-trace-validator-fix2-check.txt), [review](evidence/2026-10-05/rv4-w-trace-validator-post-fix-review.txt)); root narrowed the README guarantee for argparse failures. This parser authenticates neither the capture nor a CLEAR/boot epoch; controller, actual lower hold/completion, cleanup overlap, raw bytes and runtime Verifier remain separate required evidence. W01/W02, Phase 3 increments 3-5 and Phase 4 remain unqualified. This changes no core accounting or failure policy.

**Unattended boot-Unknown evidence decision (source-only, 2026-10-05):** keep the existing instance-scoped sticky Unknown and I/O pass-through unchanged. The retained b25 readiness reports trusted boot C with `instanceWritersUntracked=1`, successful canary, other trusted NTFS volumes clear, and global Unknown zero; it does not retain the loss reason or source. The feature-only admission-volume readout now exports the already-maintained per-instance unknown-reason mask plus a fixed-size first successfully published context reason/source-line pair. This is publication order, not event chronology: an earlier deferred event can be overtaken by a later direct mark. Direct and deferred Unknown marking share that first-wins record, and deferred work carries the originating callsite line rather than reporting its worker line. This is bounded proof state only: no scan, reset, retry, gate, taint, paging, or lost-tracking behavior changes. A clean next boot/readiness capture must have successful ContextStatus and provide the C reason/source line against the pinned source before attributing that recorded mark. A line has no file identifier; ambiguous same-line callsites stay unattributed. Failed context/queue, entry-local and global-only losses are outside this pair coverage. Normal protocol layout and W-trace producer/parser schema remain unchanged. Source is not built or runtime-qualified.

The integrated upper W-ticket producer and parser remain unexecuted on the VM. Exact builds of this main-checkout integration and matched binary residency checks precede runtime Verifier; lower-W controller and independent observer proof remain separate. This work closes implementation of narrow W identity/completion observation and successful-context Unknown attribution, not RV4-W01 or full WP3A acceptance.

**Unattended W01 evidence-boundary decision (2026-10-05):** the fresh main integration review found that pre-operation callbacks can sample an old trace-control epoch before rundown admission, then resume after CLEAR/ENABLE without a ticket/loss increment. The bounded controlled W01 must establish target-writer quiescence across control transitions and trigger its write only after successful control completion. Zero observer loss is not exhaustive temporal proof; foreign W records remain inconclusive under the narrow parser. Keep full WP3A temporal coverage open. This changes no product ledger, admission or failure policy ([review](evidence/2026-10-05/w-proof-main-integration-review.txt)). Exact b31 has four zero-warning/error builds with root-read raw logs, matched 26-source archive, and nonpaged hot-helper placement; it has not run on VM ([readout](evidence/2026-10-05/exact-mvp3-b31-root-readout.json)).

**2026-10-05 registry-TxF run 20 disposition:** frozen b30 source `6a833c91` ran the existing demand-load corpus under runtime Verifier (`0x13B`). Actual verdict is **19 passed / 74 failed**; repeated registry probes report HistoryPresent=false, Unknown `0x00000084` (IDENTITY `0x04` plus TRUST `0x80`). This is a failed regression gate, not qualification. The source already tolerates only TRUST alone for late attachment; the added identity reason and missing H/T/history require source/evidence diagnosis. Do not reset Unknown, force late trust, revive a scan, or rerun the same failing lifecycle without disposition. Root read all emitted RT verdict rows and the separate original-driver/policy, unloaded-filter, Verifier-off, actor/fixture-clean baseline ([gate](evidence/2026-10-05/registry-txf-run20-gate.txt), [restoration](evidence/2026-10-05/registry-txf-run20-final-restored-state.txt)). The b31 S01 boot capture is a distinct scoped test to attribute successful-context Unknown; it is not a replay or a substitute 93/93 result.

**Unattended RV4-W01/A05 fixture decision (source-only):** use one exact referenced FILE_OBJECT and one queued noncached nonpaging write in the existing test-only lower filter. The arm reply must complete before the sole controlled writer can issue I/O. Separate preoperation and queued/post rundown owners preserve state through immediate cancellation; request fields are copied before queue publication. The watchdog resumes the same operation, and the genuine lower post records native status/information/flags; cancellation and synthetic pre-dispatch errors are distinct and never count as real filesystem errors. Disarm waits for real rundown and may remain pending indefinitely: preserve the writer, native OVERLAPPED/buffer and controller port, record recovery, and withhold restoration/reboot on uncertainty. This changes no product gate, ledger, cutover, capacity or failure policy. The fresh exact-source lower-kernel review is [retained](evidence/2026-10-05/rv4-lower-w-final-adversarial-review.txt); all cancellation interleavings and actual completion remain VM requirements.

The bounded W01 child now binds the canonical GUID fixture target, closes its duplicated user handle before write/cleanup, saves full decoded raw captures and unfiltered traces/control snapshots, rejects draining completion, and waits for exact native IOCP completion without killing pending storage. It requires a trusted parent to prove exclusive CreateNew ownership, no external hard links, protected roots, exact signed artifacts and actual upper/lower placement. Its verdict is always INCONCLUSIVE. Source reviews and actual Windows PowerShell 5.1 parse logs establish syntax/source checks only ([pins](evidence/2026-10-05/rv4-lower-w-main-integration-pins.json), [parent boundary](evidence/2026-10-05/rv4-w01-checkpoint-parent-integration-plan.txt)). The parent plan's S01 source references are from the older isolated checkout and must be rebound to current exact main source during implementation. A safe parent is still needed because existing actor timeout/restore paths can kill pending I/O. Four product WDK builds, two exact companion builds/signing, matched residency, runtime Verifier, the actual cleanup/W overlap and host joins precede any W01 acceptance. No lower fixture, controller or aligned writer has run on the VM.

**2026-10-05 W01 build disposition:** coherent fixture increment `5cba8fdf` has all four exact product WDK configurations at zero warnings/errors, plus both Inspector builds, with root-read raw builder logs and matched 26-file source archive. The exact lower fixture build failed in both Debug and Release with seven compiler errors: its reply pointer typedef was undeclared. No signed lower artifact exists from that attempt. Replace only the two parameter type spellings with `SECTION_FAULT_WRITE_REPLY *`, preserving fields, ABI and behavior; a fresh Luna source review verifies the exact substitution ([review](evidence/2026-10-05/rv4-lower-w-reply-typedef-review.txt)). Keep the failed build evidence and require fresh four product builds and both companion builds before using the revised source ([readout](evidence/2026-10-05/exact-mvp3-b32-root-readout.json)).

**2026-10-05 b31 S01 observation:** exact source `3011cc8b` completed the activating boot under active boot Verifier and all 101 native scope opens returned access denied. Root independently hashed all 59 raw artifacts and verified absence of all 303 distinct forbidden blocks; the full seed remains INCONCLUSIVE for the same five coverage/live-state requirements. The separate restoration returned BaselineClean=True. Root checked the independent review against actual case, raw artifacts, source, actor and Verifier receipts. The narrow boot-safety gate is qualified; broader S01/Phase 4 remains INCONCLUSIVE ([root checks](evidence/2026-10-05/s01-b31-root-readout.json), [review](evidence/2026-10-05/s01-b31-independent-review.txt)). The new successful-context receipt binds the first published C: mark to CLEANUP `0x40` at exact source line 2333 in StageWriters.c, inside the failed-FltGetStreamContext cleanup branch; contextStatus=0, instance reason mask=0x40, global Unknown=0 and the other trusted NTFS instance remains clear. It does not identify the file object, lookup error, object type or event chronology. Further source diagnosis and targeted proof are needed before changing accounting; no Unknown reset or scan is authorized.

The run-20 source disposition also confirms that its IDENTITY result bit is a diagnostic umbrella for instance/global tracking Unknown, not proof that the target's file-ID query failed. Late-load canary success does not grant trust. Preserve the 93 functional requirements in a boot-start/readiness lifecycle without driver replacement/load inside the stimulus body, while keeping the late-load trust diagnostic distinct ([source disposition](evidence/2026-10-05/registry-txf-run20-source-disposition.txt)). Both the unexpected late-load loss and the boot C: cleanup mark remain open; no current-source 93/93 qualification is claimed.

**2026-10-05 TxF snapshot instrumentation (built; runtime qualification pending):** added control 23 and `--admission-volume-observe`, which returns the admission-volume payload without running the legacy canary-deadline transition; `--admission-volume-status` keeps its prior behavior. The registry-TxF harness requires the all-volume canary barrier, preserves byte-exact registry and volume responses with per-command UTC/hash sidecars after readiness and around `NeverWritten_0`, validates target-volume reason/site fields, and stops before further corpus cases if global Unknown is set. Luna's static rereview found no remaining source blocker. These are sequential interval samples, not an atomic or causal trace. The current worktree passed four WDK builds and both Inspector builds with zero warnings/errors; the harness parsed in PowerShell 5.1. VM behavior and the overdue-canary observer/legacy comparison remain unverified; the 93/93 gate remains open ([build readout](evidence/2026-10-05/exact-mvp20261005mapgate-root-readout.json), [authoring validation](evidence/2026-10-05/mapgate-authoring-validation.txt), [harness](scripts/Test-StagedAdmissionDiagnostic.ps1), [Inspector](SafeUpload.Inspector/main.c), [control](SafeUpload.Minifilter/Protocol.h)).

**Unattended WP3A promotion-proof decision (source-only, 2026-10-05):** retain a separate bounded feature-build receipt for the successful `ACTIVATING -> PROTECTED` CAS and a read-only trace batch. The existing upper W ticket schema remains unchanged. This is necessary MVP evidence because a state/status sample cannot establish that a real production promotion CAS occurred or bind that exact edge to the entry serial/FileId/SOP and expected-versus-at-CAS marker generation. The four serialized `PredicateFlags` report only name match, empty SOP, no user-writable reference, and clear marker scan; they are not the complete Free(F) predicate. H/W/T/C/S/Unknown/rename/count/generation/policy/registry-sequence values are labeled samples, not a coherent tuple. The registry-change sequence is sampled after CAS and may include unrelated increments; current policy flags/generation are read under the policy lock before entering RegistryLock. Batch output validates the pinned snapshot/cursor/entry sequence and rejects gaps, loss, overwritten prefixes, malformed responses, and no progress. Receipt contention and ring overwrite remain observation loss only; they do not alter core Unknown/accounting/admission behavior. The kernel has no live `TEST_DISABLE_TAINT` control/readback, so the receipt reports that setting unavailable; that live-policy requirement remains open. Marker/section boundary and service/permit proof also remain open. This draft is not built or runtime-qualified.

**2026-10-05 b33 exact-build disposition:** source `85f13bef` has four exact product WDK builds and both Inspectors at zero warnings/errors; root read all raw logs and independently matched archives, logs and artifact hashes. The companion failed both configurations with six errors rooted at undeclared `PSECTION_FAULT_WRITE_REQUEST`; no companion binary was linked or signed. The reviewed one-token `SECTION_FAULT_WRITE_REQUEST *` correction changes no ABI or behavior. New promotion receipts and this correction require fresh exact builds before VM use ([root readout](evidence/2026-10-05/exact-mvp3-b33-root-readout.json), [request review](evidence/2026-10-05/rv4-lower-w-request-typedef-review.txt), [promotion review](evidence/2026-10-05/rv4-promotion-proof-final-adversarial-review.txt)).

**2026-10-05 WP2 preflight disposition:** wp2vm1 stopped before corpus execution because its exact hash-qualified observer module remained from S01. The wrapper retried the same preflight three times; stop and reassess rather than add guards. A separate read-only baseline confirmed original driver/policy, unloaded filters, Verifier off and `BaselineClean=True`; it confirmed that the sole existing input has the exact expected SHA-256. Preserve the failed wrapper verdict and independent check separately. Reuse only a regular immutable input with an exact matching hash; reject different bytes and unsafe paths before retrying with a fresh run identity ([independent state](evidence/2026-10-05/observer-corpus-wp2vm1-0cc053bd5a83-independent-state.txt)). No corpus case ran or qualified.

**2026-10-05 b34 exact-build disposition:** source `8d3e641b` has four exact product WDK builds and both Inspectors at zero warnings/errors, with the writer fixture built and the driver signed ([summary](evidence/2026-10-05/exact-mvp3-b34-summary.txt)); the promotion receipts compile. The lower companion failed both configurations with two errors rooted at one C4701 in `FaultPreWrite` (`status` assigned only on the armed branch, line 249 reachable only after it). No companion binary was linked or signed. The one-declaration fix `NTSTATUS status = STATUS_SUCCESS;` is behavior-neutral (the unarmed path returns before the check); a fresh Luna source review accepted it ([review](evidence/2026-10-05/rv4-lower-w-status-init-review.txt)). Unattended build decision: the fix touches only `driver/SafeUpload.SectionFault`, so product source is byte-identical to the b34 product builds; rebuild only the companion (b35) and record the b34 product manifest as the matched product evidence instead of repeating four identical builds. Nothing ran on the VM.

**2026-10-05 b35/b36 companion disposition:** b35 (`1018447e`) cleared the C4701 compile error and exposed seven PREfast errors in the hold queue that the compile error had hidden: CBDQ lock callbacks lacked IRQL annotations (C28167, C6011), two plain reads of the Interlocked-managed held flag (C28112), the worker lacked the `KSTART_ROUTINE` class (C28023) and `FltObjectReference` status was ignored (C6031). Evidence retained ([b35 summary](evidence/2026-10-05/section-fault-mvp3-b35-summary.txt)). Commit `6efd9cf3` makes annotation, Interlocked-read and status-check changes only; a failed reference now leaves the queue unused and fails attach instead of continuing. Exact companion b36 builds Debug and Release at zero warnings/errors with PREfast and ApiValidator and signs ([summary](evidence/2026-10-05/section-fault-mvp3-b36-summary.txt)); the builder reports the same untrusted-test-signer status as every earlier companion build. The b36 binary is not VM-run, residency-checked or reviewed against the full hold-queue source; a fresh adversarial lower-kernel review of the final source and matched binary residency precede runtime Verifier.

**2026-10-05 b36 lower-fixture review:** fresh Luna source review of `Fault.c` `3dabbdfd…` / `Protocol.h` `306b0e57…` returned ACCEPT WITH CONDITIONS ([review](evidence/2026-10-05/rv4-lower-w-b36-final-adversarial-review.txt)). No double/lost completion or lock-order defect in the serialized one-write path; the three recent commits change behavior only on the failed-`FltObjectReference` attach path, which is source-safe. Conditions carried into the experiment record: (1) the sole writer must not issue I/O until the arm reply succeeded (a write racing the arm with a failed worker create can leave disarm waiting on rundown); (2) the 30 s watchdog does not bound lower completion, and disarm/disconnect/unload wait on rundown without timeout, so a stall preserves the pending writer and VM and is INCONCLUSIVE, never killed; (3) the lower reply is not an atomic snapshot, so evidence must come from a quiescent receipt with the expected `LowerPosts`, zero `Canceled`/`SyntheticFailures`/`TimedOut`, joined to the upper trace and native IOCP completion (the existing child already enforces this at `Test-StagedW01Diagnostic.ps1` 215/247/252); (4) the receipt shows status as seen at this filter's post callback, not NTFS in isolation, so lower/upper placement is verified independently and `LowerCallbackData` is only a correlation hint. Cancellation interleavings, exact placement, alignment and bounded teardown remain VM requirements. This review does not qualify W01.

**Unattended decision, trusted-C: cleanup Unknown (2026-10-05, source `e4faa498` + layout-assertion fix; hypothesis, not runtime-proven):** the b31 receipt placed the first sticky Unknown at the unmatched-cleanup branch with no stream context (StageWriters.c, pinned b31 line 2333). Static reading finds a concrete cause class: post-create deliberately skips directories (`DirectoryCreatesSkipped`), but cleanup excluded only volume and paging objects, so every write- or delete-access directory handle (FILE_ADD_FILE is FILE_WRITE_DATA; DELETE) closed on a trusted instance had no writer node and set sticky Unknown(CLEANUP). Boot-time servicing opens such handles constantly; a freshly mounted non-boot NTFS volume sees none, which matches C: Unknown with the second trusted NTFS volume clear. Change: `FltIsDirectory` classification at PASSIVE_LEVEL before the two unmatched branches; a failed or non-PASSIVE classification keeps the existing loss behavior; the writer-node path (`found != NULL`) is untouched; no scan, reset, retry, taint or gate change. New counter `CleanupDirectoriesSkipped` uses the former `Reserved` word (offset 100, assertion updated) and is printed by the feature Inspector. Exact b38 builds all four driver configs and both Inspectors at zero warnings/errors with PREfast and ApiValidator and signs ([summary](evidence/2026-10-05/exact-mvp3-b38-summary.txt)); the first b37 attempt failed only on the stale `Reserved` layout assertion ([b37](evidence/2026-10-05/exact-mvp3-b37-summary.txt)). The fix is proven only if a boot capture on this build reports C: instance Unknown reasons 0 with `cleanupDirectoriesSkipped` > 0 and `cleanupUnmatched` explained; if CLEANUP persists, add a bounded first-event detail receipt (name tail, FO flags, access bits, status) before any further change. A fresh adversarial review precedes the boot capture. The W01 parent requires a C: with Unknown=0, so this precedes W01 on the VM.

**2026-10-05 directory-cleanup review and W01 parent integration:** fresh Luna review of StageWriters.c `c31efa7c…` / Protocol.h `2f92e222…` returned ACCEPT WITH CONDITIONS for a source-matched boot capture ([review](evidence/2026-10-05/dir-cleanup-unknown-adversarial-review.txt)). No ordinary rename/link/reparse/delete-pending path turns a regular file into a directory, the `found != NULL` node path is untouched, and a failed or non-PASSIVE classification keeps the loss. One unresolved risk: how `FltIsDirectory` classifies a directory's named alternate stream (`dir:stream`) and `dir::$INDEX_ALLOCATION`. Orchestrator note: post-create already applies the same `FltIsDirectory` predicate and skips tracking when it is TRUE, so cleanup now mirrors the create-side decision and adds no new class of blind spot unless the predicate is unstable between the two points; if directory ADS opens classify as directory, ADS writers on directories were already untracked before this change and become a separate corpus finding. Conditions for the capture: C: stays trusted with Unknown reasons 0 and `cleanupDirectoriesSkipped` > 0; explain any remaining `cleanupUnmatched` with a first-event receipt (lookup status, FO flags incl. `FO_STREAM_FILE`, access bits, IRQL, FltIsDirectory result, name tail); controls for an ordinary file, a write/delete directory handle, a directory ADS, `::$INDEX_ALLOCATION` and a matched-node cleanup. Likely non-directory alternatives named by the review: handles predating attach, early hive/system files, `FO_STREAM_FILE`, swapfile.

The safe W01 checkpoint parent was written by Sol and checked by root: Windows PowerShell 5.1 `Parser::ParseFile` reports 0 errors on `Test-StagedW01Parent.ps1` (`91FD26D1…`) and `Test-StagedW01Diagnostic.ps1` (`C793CC32…`); `StagedW01Stimulus.cs` compiles to an x64 exe at `/warn:4 /warnaserror` (`B4EEBE3D…`) and `StagedSectionFaultClient.cs` compiles as a library on the builder; the Linux structural self-check passes. Root rebound the host from b34 to the exact b38 upper (the directory fix is required because the parent refuses to issue a write unless C: is Unknown-free) with the b36 lower; draft host pins are retained ([pins](evidence/2026-10-05/w01-b38b36-host-draft-pins.json)). Nothing has run on the VM; an independent review of the parent's no-kill/terminal-state-only restoration is still required before its first run.

**2026-10-05 W01 parent review and S01 b38 boot capture (run `s01b38dir`):** Luna's independent review of the W01 parent returned ACCEPT WITH CONDITIONS ([review](evidence/2026-10-05/w01-parent-adversarial-review.txt)): no reachable restoration, reboot, task-removal or Verifier-reset path can act before the terminal-state predicate, stale/foreign receipts are bound out by the run GUID, and the only finding (a literal `PASS` in the Linux self-check output) is fixed. Source review only; no W01 run yet. The first S01 boot capture on exact b38 (`6f312cd6`) retained a readiness status in which both trusted NTFS volumes report instance Unknown reasons `0x00000000`, first-Unknown 0, `instanceWritersUntracked` 0, global Unknown 0 and 15 canary checks, where b25 and b31 reported the trusted C: instance Unknown (CLEANUP `0x40`). This is consistent with the directory-handle cause but is one sample: the `cleanupDirectoriesSkipped` counter was not retained, so the attribution is not proven. That run is NOT an S01 re-qualification: after readiness the SYSTEM body `Add-Type` (QueryDosDevice) did not complete within its 90 s deadline (`Task completion unavailable`), so zero scope-denial operations ran, no `readiness.json`/after-Verifier artifacts were written, verdict INCONCLUSIVE with the usual seed reasons, forbidden bytes 0, and the separate restoration is `BaselineClean=True` with Verifier off ([case](evidence/2026-10-05/boot-start-invariant-S01-denied-write-after-boot-boot-verifier-s01b38dir-artifacts/case.json), [restored state](evidence/2026-10-05/boot-start-invariant-S01-denied-write-after-boot-boot-verifier-s01b38dir-final-restored-state.txt)). The cause of the missing completion is not established: the host was swapping (13 GB swap in use, two qemu processes at 8.5 and 7.4 GB) which would slow a first-boot C# compile, but a hang introduced by the cleanup change (the task may have been `Running`, not just late) is not excluded. One identical rerun on the same exact build decides between the two; a repeat stops for diagnosis rather than a third run.

**2026-10-05 S01 b38 rerun disposition and unattended harness decision:** the identical rerun (`s01b38dir2`) failed at the same step with zero operations, so the identical lifecycle is not repeated a third time. Retained evidence shows the failing SYSTEM body (the BootPolicy readback) did complete with ExitCode 0 and wrote its completion record at 245.5 s uptime, after the suite's 90 s `Invoke-SystemBody` deadline; it was not lost. In the passing b31 run the same readback completed at 140.8 s and the following `Add-Type` body took 82 s, so the 90 s deadline had under 10 s margin on this VM. The retained status again shows both trusted NTFS volumes Unknown-free. Decision: raise only the `Invoke-SystemBody` wait to 240 s (the `Wait-TaskCompletion` default); token binding, exit-code and stale-record checks are unchanged, and Windows PowerShell 5.1 parses the suite with 0 errors. This is a harness-timing change, not a product change; it is not proof that the b38 driver adds no boot latency, which is checked by comparing the completion QPCs of the same bodies in the next capture against b31 (140.8 s, +82 s, 287.4 s). If the next capture still fails or shows the readback/`Add-Type` bodies much slower than b31 under comparable host memory, bisect exact b34 (`8d3e641b`, no directory change) before any further change.

**2026-10-05 S01 b38 third run (`s01b38dir3`, 240 s SYSTEM-body deadline):** the activating boot completed under active boot Verifier with exact b38 (`6f312cd6`). All 101 native scope opens returned access denied (Win32 5, write/flush/close never called); forbidden byte count 0; the independent final restoration reports `BaselineClean=True` with Verifier off; both trusted NTFS volumes report instance Unknown reasons 0, first-Unknown 0, `instanceWritersUntracked` 0, global Unknown 0 and 15 canary checks. This is the third consecutive b38 boot (runs 1-3) with the trusted C: instance Unknown-free, against two of two earlier boots (b25, b31) where it was Unknown(CLEANUP): strong support for the directory-handle cause, though the `cleanupDirectoriesSkipped` counter still has not been read back. The exported verdict is **FAIL**, not the usual INCONCLUSIVE, because of the Phase 4 latency rule alone (max <= 1000 ms): one denied open (sample 76) took 1888.5 ms (p95 3.4 ms, every other sample < 50 ms; b30 max 10 ms, b31 max 4 ms). The 101 opens ran inside a 2 s window that overlapped the observer's 6 s raw-volume capture (QPC 471.31-477.44 s); the stall began 0.11 s into the burst and lasted 1.89 s. The cause is unattributed (raw-capture disk contention on a swapping host, a guest/VM stall, or a driver wait cannot be separated from one sample) and must not be waved away: it needs a repeat and, if it recurs, a bounded latency receipt. It does not touch the boot-safety facts above (all denied, no forbidden bytes). Luna independently checked the actual b38 manifest and root repeated its comparisons: all **49** artifacts (the earlier b30 had 59) match their lengths/hashes, none contains any of the 303 distinct forbidden 128-byte blocks, and all five 12,288-byte marker logical images are identical. The restoration hash matches the case export and records `BaselineClean=True` ([root readout](evidence/2026-10-05/s01-b38-run3-root-readout.json)). This establishes absence in retained sampled bytes only; temporal completeness and the mutation ledger remain unproven, and the latency **FAIL** remains unchanged.

**2026-10-05 operator disposition of historical recovery markers (user decision):** the W01 host latched on any `*recovery-required*` file under `driver/evidence`, which found 20 markers from earlier failed runs of other experiments (boot-start runs 2-14, registry-txf-run4, S00/S01 variants, b22s01a, wp2vm1; 12.5 KB of text, the 20 overlays they name total 2.5 GB). The user chose to treat them as resolved and scope the block. A pinned note lists each marker's relative path and SHA-256 ([note](evidence/2026-10-05/recovery-marker-disposition-20261005.json), SHA-256 `ABF1CFC2…`) and cites the independent `BaselineClean=True` of s01b38dir3; the resolution is an inference from later clean baselines, not an inspection of each old overlay. The host now clears a marker only on an exact (path, SHA-256) match; every new, modified or renamed marker, anything with `w01` in its path, the active W01 lease and any symlink under the evidence root still latch, and a missing, altered or malformed note fails closed. Luna reviewed it (ACCEPT WITH CONDITIONS; [review](evidence/2026-10-05/w01-marker-disposition-review.txt)); the symlink-directory condition and non-object-JSON caveat are fixed with self-check controls. No overlay was deleted or merged.

**2026-10-05 W01 run 1 (`w01-b38b36-20261005`, run GUID `ab961697…`) — Prepare failed on a parent-script bug, before any hazard:** the new checkpoint parent threw `Private ACL readback mismatch` at its first ACL step (`Test-StagedW01Parent.ps1:86`), after creating only its state/evidence directories and one phase task. No driver, policy, Verifier, lower filter, fixture file, child or writer had been touched, so no I/O could be pending. Cause (reproduced on the builder): the in-memory SDDL reads `D:P(...)` and the applied descriptor reads back `D:PAI(...)`; Windows adds the auto-inherited flag and every ACE is identical. Fix: compare with that single flag normalized on both sides; the patched helper passes on the builder for a directory and a file. The failed run's guest leftovers (two GUID-named directories under Documents and one never-started Ready phase task, all owned by this run GUID, copies already on the host) were removed and the independent baseline is `BaselineClean=True` with `NoGuidFixtureDirectories=True` ([baseline](evidence/2026-10-05/w01-run1-prepare-failure-guest-baseline.txt)). The wrapper wrote its recovery marker and left the VM on this run's checkpoint overlay, as every run does; its offline rollback could not resolve the backing file, which is not needed here. The host's three W01-family latch files remain in place and are not cleared by design; they need the operator's disposition before W01 run 2. This was the first execution of the parent's guest code, so further first-run script bugs are possible; each failed Prepare before the lower filter loads is hazard-free by construction.

**2026-10-05 W01 run 2 (`w01-b38b36-20261005b`, GUID `fe004c32…`) — passed Prepare and the reboot; AfterBoot failed on a second parent bug, still before any child or write:** Prepare completed (`W01_PREPARED=True`) and AfterBoot attached the lower filter and read both drivers verified under flags `0x001209bb`, then threw `Active/configured Verifier missing: SafeUpload.sys`: the check also required `/querysettings` to list the drivers, but a one-boot Verifier configuration is consumed by the boot that applied it (settings read back `Verified Drivers: None`). Fix: the active check now uses the live `/query` module list (each module once, loaded, not unloaded) and exact flags. Read-only guest state afterwards: no W01/stimulus/child process, phase task Ready (not running), lower filter loaded and attached on C: but never armed, Verifier active on both, the run's three fixture roots on C:; nothing can be pending. The parent recorded RecoveryRequired and the host wrote three W01 latch files, so the guest restoration and the latch disposition await the operator. Bulk copies (87 MB guest service tree, 36 MB staged inputs) are retained locally, untracked, and pinned by hash in `provenance.json` / `input-staging-verified.json`. Unexecuted AfterBoot code after the Verifier step is being walked against these artifacts before a third run.

**Owner-directed upstream reuse (2026-10-05):** before designing a new mechanism or experiment for unresolved Windows behavior, inspect the corresponding WinFsp implementation and tests against a concrete question, pin sources, and record what applies, differs and changes the next action. Reuse targeted WinFsp/Winfstest/Windows FSX stimuli for W01/A05 pending-write/cleanup, M01/M02 surviving mappings and C/B/X replacement saves through the existing checkpointed harness. Retain raw observations and SafeUpload-specific state, completion, service and byte assertions. Upstream workload success alone closes no MVP qualification gate. Keep current tracking-Unknown and 93-case regression diagnosis on the critical path and every remaining requirement in the table visible.

## 2026-10-07 overnight (Sol)

- [x] Read handoff and checked current checkout (`3be557de`); isolated host work in
  `feat/sol-overnight-20261007` at `/home/victor/Work/safeupload-wt-sol`.
- [x] Independent pre-run debuggee baseline returned `BaselineClean=True`; A01 run
  `sol-a01r2` pins driver `mvp4-b10`/`326eb512` and agent `agent-mvp4-b17`/`12ad8e96`.
- [x] A01 runtime-Verifier rerun restored clean; stopped at harness launcher-path mismatch: `evidence/2026-10-07/phase4-suite-sol-a01r2-index.txt`.
- [x] Separate MVP gate implemented; 7 synthetic MVP tests and 18 existing proof-adapter
  tests pass. Assessment: `evidence/2026-10-07/sol-mvp-historical-reassessment.txt`.
  Strict gate remains unchanged; both historical cases correctly fail the MVP gate.
  - Decision: `*UnheldLatency` cannot be tolerated before dedicated evidence for the same
    write path, mode, driver/Inspector/service artifact hashes, 100 unheld samples per
    class plus a cold sample passes. No assumed future latency pass.
  - Evidence correction: c01o saved authoritative JSON has additional unallowlisted
    `C01RawCapture`, `C01OutcomeNotification`, `C01ReleasedNotificationDigest` gaps.
    They remain blocking; historical summary is not substituted for saved assertions.
- [ ] Blocked stage proof: `SUProofFile.Open` already uses `FILE_FLAG_BACKUP_SEMANTICS`
  (`0x02200000` also includes OPEN_REPARSE_POINT). Driver `StageAdmit` deliberately
  denies every staging-namespace open except its authenticated service PID. SYSTEM
  alone is not an exception. Use a read-only raw-volume/MFT proof; do not weaken driver.
- [ ] Remaining Ready rows, live taint evidence, dedicated latency, NotReady MVP rows,
  ordinary/boot modes and Phase 5 review remain pending.

- [ ] Harness repair awaiting VM requalification: A01 checks `activation-writer.ps1`,
  but Prepare creates and starts `writer.ps1` for every actor. Match the actual launcher,
  retaining PID/session/token/OS-owner checks; 3 synthetic identity checks added.
- [ ] Raw private-stage reader implemented without product changes: bind exact filename
  through parent raw index, MFT record sequence and FILE_NAME parent, require one link,
  reject ADS/reparse/EFS, read complete resident/nonresident bytes twice, bracket records
  and parent index; preserve raw containers. Candidate builder validation passed 0 parser
  errors, 224 adapter checks and 77 observer checks before the identity regression additions.
- [ ] Live taint flag needs a driver change: `TestDisableTaintState` is explicitly
  `SAFEUPLOAD_PROMOTION_TEST_DISABLE_TAINT_UNAVAILABLE` in `StageWriters.c`; there is no
  TEST_DISABLE_TAINT policy bit or readback in the current product. Control 24 exposes live
  policy flags but cannot attest an absent flag. Keep `LiveTaintFlags` on the fixed allowlist
  and report this limitation; counters alone cannot manufacture live flag confirmation.

- [x] Candidate harness Windows gate PASS: `evidence/2026-10-07/sol-harness-windows-validation-b.txt`
  (0 parser errors, 227 proof-adapter checks, 77 native observer checks). Python
  18 proof tests plus 7 MVP tests pass; raw helper compiles on .NET/PowerShell 5.1.

- [ ] A01 `sol-a01r3` exposed a second harness bug before creating its pre-scope
  holder: the actor's `ReadAllText(command-0001.clixml)` races the producer's open
  write handle and exits on sharing violation. Reuse the bounded monotonic
  `Load-State` implementation inside the generated actor and validate sequence/action.
  Next run follows Windows 5.1 publication regression checks.

- [x] Bounded actor command reader validated on builder: 229 proof-adapter
  checks, 77 native observer checks, 0 parser errors (`evidence/2026-10-07/sol-harness-windows-validation-c.txt`).
- [ ] Source review found the next A-path stimulus passed uninitialized `$flush`/`$written`
  by reference; initialize both before `StageWrite` so PowerShell can call the native
  fixture. This is harness-only; full A-path qualification remains pending.
- [ ] A-path service observation requires repair: Inspector uses the one-client
  `SafeUploadPort`; once the real agent owns it, the suite's direct epoch/registry/trace
  Inspector commands cannot connect. Preserve service ownership and state continuity;
  do not stop/reconnect the agent to obtain a fabricated continuous observation.

- [x] A01 r3 restoration independently clean; full failure evidence retained under
  `evidence/2026-10-07/boot-start-invariant-A01-runtime-verifier-sol-a01r3-artifacts/`.
- [x] Actor command publication/native-ref repairs pass Windows 5.1 gate: 229 adapter
  checks, 77 observer checks, zero parser errors (`evidence/2026-10-07/sol-harness-windows-validation-d.txt`).

- [x] A01 `sol-a01r4` reached the standard-user holder; restored independently clean.
  Evidence: `evidence/2026-10-07/phase4-suite-sol-a01r4-index.txt`. It stopped before
  the epoch update because the newly created file's on-disk MFT record was stale.
- [ ] A fixture durability repair: prepare known P before reboot and have the actor
  open the existing file (OPEN_EXISTING), rewrite/flush P while Unscoped and retain
  its writable holder. This follows A01's physical-open contract and preserves all
  raw identity/byte checks, without volume writes or observer rebaselining.

- [x] Pre-reboot P fixture repair passes Windows 5.1 validation: 0 parse errors,
  229 adapter checks and 77 observer checks (`evidence/2026-10-07/sol-harness-windows-validation-e.txt`);
  Python MVP (7) and proof adapter (18) tests pass. VM qualification pending.

- [x] C01 BLOCK `sol-c01b4` completed/restored clean with forbidden byte count 0,
  but MVP gate remains false (`evidence/2026-10-07/phase4-suite-sol-c01b4-index.txt`).
  `C01BlockedStageRetained` failed to locate the name in the raw parent index; the
  terminal journal had StageDeleted=false, verified hand-back and a closed
  justification window (session 0 is not the actor's interactive WTS session).
  Preserve this distinction; absence from one raw capture does not prove deletion.
  Second-user hand-back denial, safe relative creation receipt, window/restart
  proof and dedicated latency also remain unallowlisted blockers.
- [ ] Prototype diagnostic relay: keep service port ownership and continuity; use
  a separate SUPF wire branch in the existing feature-only diagnostic pipe, with
  an explicit default-off `Diagnostics:StagedProofProxy` switch and SYSTEM-only
  caller. Allow only observation and admission-trace instrumentation controls;
  prohibit policy/publication/override/capacity/fault/trust mutations. Normal builds
  exclude it. Existing capture protocol stays read-only (19/20/23). Inspector
  requires explicit environment opt-in and verifies the server SYSTEM token.
  New exact agent feature build/matrix, four driver builds, Windows gates and
  independent Luna review precede using these artifacts on the guest.

- [x] Independent Luna source review ACCEPT WITH CONDITIONS: `evidence/2026-10-07/sol-proxy-luna-review.txt`.
  It found no authorization/framing/allowlist or A-fixture-contract blocker.
  Response I/O deadlines do not cancel a synchronous native service send; preserve
  the send lease through actual completion and do not claim a whole-request bound.
- [x] First hash-pinned feature agent candidate compiles/tests/publishes with zero
  warnings (`evidence/2026-10-07/sol-proxy-agent-candidate-validation.txt`).
  This is not the committed exact-build/matrix gate and is never installed.
- [ ] Review conditions: added all allowed control mappings, disconnected/backpressured
  readers, binding drift, expired response deadline during slow native send, and
  shutdown drain regressions. Exact Windows test/build and fresh follow-up review pending.
- [x] C02 APPROVE `sol-c02a1` attempted on original exact b10/b17 artifacts; restored
  clean, sampled forbidden bytes 0 (`evidence/2026-10-07/phase4-suite-sol-c02a1-index.txt`).
  Mapped actor never published its held receipt and did not cooperatively cancel.
  Native operation localization is required before calling this a product bug.

- [x] Exact driver/Inspector build `mvp4-sol-b11` at `6a20c49f` passed all four WDK
  configurations with 0 warnings/errors, PREfast and ApiValidator clean; Inspector
  normal/feature Release builds also clean (`evidence/2026-10-07/exact-mvp4-sol-b11-summary.txt`).
- [ ] Exact agent `agent-mvp4-sol-b18` failed a new timing-sensitive cancellation
  regression; its isolated rerun passed (`sol-expired-test-diagnostic.txt`). Replace
  the 20 ms timer assumption with explicit cancellation while native send is held.
  Retain native stderr and exit status in build helper even when tests fail (PS 5.1
  ErrorAction=Stop previously aborted before saving the test status). Rebuild with
  a fresh label; do not use the failed artifact or call it a passing gate.

- [x] Exact feature agent `agent-mvp4-sol-b19` at `b0e7f8be` passes all 416 tests,
  publish exit=0/warnings=0 (`evidence/2026-10-07/sol-agent-b19-build.txt`).
- [x] Exact agent matrix `sol-agent-b19-matrix` PASS: normal Debug/Release 353/353,
  feature Debug/Release 416/416 (`evidence/2026-10-07/sol-agent-b19-matrix.txt`).
- [x] Fresh Luna follow-up ACCEPT WITH CONDITIONS (`sol-proxy-luna-review2.txt`).
  Decision: preserve the existing absolute five-second response cutoff from
  request handling, including validation/native-send elapsed time. It controls
  response I/O eligibility and never cancels or bounds native send completion;
  timeout means incomplete diagnostic evidence, with no successful fallback.
  An expired response/canceled reader cannot abandon the service port lease.
  Deterministic cancellation regression fixes only test scheduling assumptions.
- [x] C03 APPROVE `sol-c03a1` restored independently clean but stopped at raw
  baseline parent-index/file-reference binding after the real service approved
  initial B (`evidence/2026-10-07/phase4-suite-sol-c03a1-index.txt`).
  No valid baseline exists; forbidden count is unknown, not zero.
- [ ] Runtime-Verifier A01 requalification on gated `mvp4-sol-b11`/`6a20c49f`
  and `agent-mvp4-sol-b19`/`b0e7f8be`, with real service-owned relay continuity.
