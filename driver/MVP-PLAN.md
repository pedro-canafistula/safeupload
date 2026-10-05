# SafeUpload MVP plan: driver + service, local NTFS, no taint

Agreed 2026-10-03. Design basis: [writer-state design v2](evidence/2026-10-03/writer-state-design-v2.txt)
and [retained-section findings](evidence/2026-10-03/retained-section-findings.txt).

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
