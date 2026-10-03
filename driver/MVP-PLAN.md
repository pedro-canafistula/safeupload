# SafeUpload MVP plan: driver + service, local NTFS, no taint

Agreed 2026-10-03. Design basis: [writer-state design v2](evidence/2026-10-03/writer-state-design-v2.txt)
and [retained-section findings](evidence/2026-10-03/retained-section-findings.txt).

## Goal

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
alternate data streams, raw-disk writes, other Windows builds beyond the canary check below,
hibernation/fast startup. Inside a protected scope these fail closed: transacted write opens,
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

Phase 1 remains open: cancelled creates and explicit fast I/O remain;
nested mixed pairing, the other teardown/fault-injection cases, canary security
and newly mounted-volume qualification, and cost remain. Empty-file mapping errors
did **not** exercise failed lower acquire. Windows 11 qualification is deferred by
the user because no VM is available. Phases 2–5 remain open.
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
measured with the latency harness. One short Windows 11 run of the canary and the section
experiments (needs a Windows 11 VM).

### Phase 2: boot start with a durable policy

- Production INF: boot start in an appropriate FSFilter load-order group; test builds keep a
  test-only unload so the VM harness can restore the original driver.
- Durable boot policy: the service writes the protected scopes to a protected registry key under the
  driver's service key; the driver reads it in `DriverEntry` before `FltStartFiltering`.
- Agent not running (boot, crash, restart): protected scopes fail closed for new write opens and new
  writable sections; nothing outside the scopes changes. This already matches "a disconnected service
  cannot authorize new protected writes", now also before the first connection.
- Volumes attached while the system is running but not newly mounted are Untrusted (fail closed on
  scope until reboot).
- One adversarial review of the boot path before the first VM boot. Experiment **X4**: first
  user-mode write versus filter readiness at boot; newly mounted VHDX attach flags before the first open.

Exit: boot with the feature driver under boot Verifier, folder protected before user logon, agent
start and stop handled, test-only unload restores the VM.

### Phase 3: policy changes without scans

- Pending policy plus one admission epoch held to lower completion on every admission path (create,
  write open, writable section, rename/link, set-information, delete, selected FSCTLs, publication),
  drained before the pending policy becomes current.
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

- **Windows 11 VM** for the canary and section experiments (phase 1). The user deferred this gate on 2026-10-03 because no VM is available. It remains unqualified and prevents an overall completion claim; continue all independent Windows 10 work.
- Fail closed on the protected scope while the agent is down: follows the agreed rule; noted here
  because users will see saves into the folder refused until the service starts.
- Taint stays compiled in normal builds; the MVP proves the guarantee without it. Removing it from
  production is a later cutover decision.
