You are a Codex worker on the SafeUpload repo at /home/victor/Work/safeupload-staging (branch feat/staged-kernel-prototype). DESIGN ANALYSIS ONLY. Do not build, do not run any VM/virsh/ssh/scp command, do not edit any source file, do not use the network.

## 1. Objective
Produce design v2 for blocking two confirmed leaks (writable memory-mapped sections that predate filter attachment, or predate the agent's first policy push / a later scope expansion), with concrete data structures, call sites, lock order, and an observe-only diagnostic slice, so an implementation worker can start without re-deriving anything.

## 2. Read first (do not trust summaries, verify and cite file:line)
- driver/evidence/2026-10-02/admission-epoch-design.txt (round 1 design; its option 3 was REJECTED, see 3).
- driver/STAGED-WRITES.md: lines 1-60, 101-190 (leak a + callback constraints), 191-330 (leak b, decision record "Decision: admission barrier design review"), tracker lines ~482-615 only if needed.
- driver/SafeUpload.Minifilter: Filter.c 100-260 and 439-560 (registration, InstanceSetup/QueryTeardown), StageStream.c (use grep -n; read the create path StageAdmit/StageCreate ~450-550 and ~1494-1660, section sync ~1185-1200, paging-write fallthrough ~90-103 and ~1623-1650, detach/unload counting ~1375-1409), Context.c 150-300 and 460-560, Policy.c 200-345 and 630-670, Communication.c ~690-718, Filter.h 170-260 and 380-410.
- driver/scripts/Test-StagedPreAttachmentMapping.ps1 and Test-StagedPolicyTransitionMapping.ps1 (the two repro scripts and their observers).
Use grep -n and sed -n 'A,Bp'; never cat a whole large file.

## 3. Facts established by the orchestrator (verified; build on them)
- Round 1 option 3 (blanket paging-write fence for every unowned file object without a current epoch tag) is rejected: paging I/O cannot resolve scope by name, so it would refuse paging writes for pre-attachment objects of ANY file on the volume (system stability), and a paging-write refusal alone does not hide dirty mapped pages from cached readers because file objects share the file's data section/cache.
- Both repro observers use a default buffered FileStream read. They cannot distinguish cache from disk. The v2 test plan must add an uncached (no-buffering, write-through) reader of the physical bytes plus the cached reader.
- Documented and verified on Microsoft Learn: MmDoesFileHaveUserWritableReferences(PSECTION_OBJECT_POINTERS), ntifs.h, Windows Vista+, IRQL <= APC_LEVEL, returns 1 if the file has user-mapped sections; Learn states it can detect writable views for a file object even when all file handles and section handles have been closed. NOT verified: whether read-only mappings also return 1; whether an attribute-only physical open on NTFS yields section object pointers identical to those of the mapping's file object. MmCanFileBeTruncated is documented (< DISPATCH_LEVEL) and already used on owned streams.
- FltMgr InstanceSetup receives flags distinguishing automatic attachment, manual attachment and newly mounted volume (documented; PASSIVE_LEVEL, must not synchronize or do IPC). Treat "newly mounted volume" as unable to have pre-attachment sections only as a design hypothesis to test, and say what could falsify it (for example volumes mounted while the filter is already loaded, volume dismount/remount, stack-attached later).
- Callback constraints (STAGED-WRITES.md ~183-195): CreateSection may fail only with STATUS_INSUFFICIENT_RESOURCES; SyncTypeOther cannot be failed; filesystem name queries are unsafe in paging and acquire/release callbacks; cache-only name lookup can miss.
- Direction chosen: per-stream admission records plus a documented per-file proof, failing closed (refuse the protected open) when user-mapped sections exist; distinguish mount-time attach from late/manual attach; any write fence is scoped to identified protected streams, never volume-wide.

## 4. Constraints
Documented APIs only, no internal offsets/undocumented structures. Feature build only (SafeUploadStagingPrototype compiled in); normal builds unchanged. Fail closed; unsupported capabilities stay disabled. Windows 10 19045.2965, NTFS, FltMgr 10.0.19041.1. Mark every external contract you cannot confirm from the repo as UNVERIFIED.

## 5. Steps
1. DESIGN: exact data structures (name, fields, lifetime, which documented context type), where each is created/queried/freed (file:line for the insertion point), lock/rundown order including the existing SafeUploadPolicyLock, StageStream resources and the service-allocation IPC wait; IRQL for each callback touched; how a protected open decides to refuse (status, user-visible effect) when MmDoesFileHaveUserWritableReferences returns 1 or the proof cannot be obtained; how late/manual attach is handled; how policy expansion re-evaluates already-seen streams without name queries in paging I/O; behavior across detach/unload/dismount.
2. SELF-ATTACK: a section with at least 12 concrete bypasses or races you tried against your own design, each with the outcome (closed / still open / needs experiment). Include: a writable handle opened before attachment or policy that later calls CreateFileMapping; duplicated/inherited handles; image sections; a mapping created between the proof and stream admission; opens by file ID or alias or short name; a view mapped on a file object whose stream context was never created; delete-pending and rename; oplock breaks; volume dismount/remount; policy push racing create/map; publication racing policy change; service restart; and what a paging-write refusal does or does not accomplish.
3. DIAGNOSTIC SLICE (observe-only, no denials): specify exactly what to log or count, at which existing callbacks (paging IRP_MJ_WRITE fallthrough for unowned objects, section synchronization, protected create, InstanceSetup flags), with what fields (instance, target file object pointer, its SectionObjectPointer value, IRP flags, MmDoesFileHaveUserWritableReferences result obtained from section pointers, whether a context exists), how the output is retrieved on this VM without a debugger-only workflow if possible (for example through the existing filter communication port or counters; check what exists with grep -n), and the cost and IRQL safety of each probe. It must answer the four unknowns listed in STAGED-WRITES.md "Unknowns to settle empirically".
4. TEST PLAN: the revised blocked-result definition (cached and uncached readers); how each repro changes from REPRODUCED to blocked; concurrent open/map/attach and policy-change race tests; Verifier requirements; restoration checks.
5. Write driver/evidence/2026-10-02/admission-design-v2.txt (plain text, at most 300 lines). Create only that file.

## 6. May edit / forbidden
Create exactly one file: driver/evidence/2026-10-02/admission-design-v2.txt. Forbidden: editing any other file; git commit/push/reset/clean/checkout/stash; deleting anything; VM/virsh/ssh/scp/network.

## 7. Done when
The file exists with sections DESIGN, SELF-ATTACK (>= 12 items), DIAGNOSTIC SLICE, TEST PLAN, and an UNVERIFIED list, with file:line citations for every claim about current behavior.

## 8. Final message (at most 150 words)
What you produced and where; the one-sentence core of the design; how many self-attack items remain open; the UNVERIFIED contracts; what you did not verify. Do not paste the design.
