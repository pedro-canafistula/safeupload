You are a Codex worker on the SafeUpload repo at /home/victor/Work/safeupload-staging (branch feat/staged-kernel-prototype, HEAD 3b3bfa0). You are doing DESIGN ANALYSIS ONLY. Do not build, do not run any VM/virsh/ssh/scp command, do not edit any source file.

## 1. Objective
Write a short design (2-3 options + a recommendation) for a race-safe volume/file admission barrier ("epoch barrier") that makes two confirmed leaks blocked, so the integrated owned-stream (staged writes) design can own every write to a protected destination.

## 2. Background you must verify in the files (do not trust this summary)
Staged writes: for a file inside the policy's destination scopes, the filter redirects writes into a private owned stream so unapproved bytes never reach the protected physical file. Two leaks are CONFIRMED on the current feature SYS:
 (a) A writable memory-mapped section created while the filter was NOT attached survives attachment; after the original file handle is closed, writes+flush through the old view change the protected destination, visible to a fresh file object. Evidence: driver/evidence/2026-10-02/physical-mapping-handle-closed-gate.txt. Write-up: driver/STAGED-WRITES.md lines 101-190.
 (b) A writable section created with the filter attached but BEFORE the agent pushed any policy, and still alive when the real agent expanded policy to include the file, changes the protected destination the same way. Evidence: driver/evidence/2026-10-02/policy-transition-eof-map-gate.txt. Write-up: driver/STAGED-WRITES.md lines 191-262.
The existing section has no newly admitted protected stream object for the feature path to seal or redirect. Repro scripts: driver/scripts/Test-StagedPreAttachmentMapping.ps1 and driver/scripts/Test-StagedPolicyTransitionMapping.ps1.

## 3. Read (line ranges; do not read whole files)
- driver/STAGED-WRITES.md lines 1-262 (milestone, both leaks, callback constraints recorded at lines ~170-190), 482-615 (tracker), 775-900 (implemented architecture; use `sed -n`).
- driver/SafeUpload.Minifilter/Filter.c lines 100-260 (registration/operations), 439-560 (SafeUploadInstanceSetup / QueryTeardown).
- driver/SafeUpload.Minifilter/StageStream.c lines 1100-1300 (section synchronization, mapped-write handling) and use `grep -n` to find how a file is admitted to a stream, how seals/pending transactions work, and the paging-write path.
- driver/SafeUpload.Minifilter/Policy.c and Communication.c: find the policy-update path (use grep -n 'Policy' and read only what you need): what changes when the agent pushes or replaces policy, and under which lock.
- driver/SafeUpload.Minifilter/Context.c lines 150-300 and Filter.h lines 170-260 (instance/stream contexts).
Use `grep -n` and `sed -n 'A,Bp'`. Cite file:line for every statement about CURRENT behavior.

## 4. Constraints the design must respect
- Documented Windows/WDK APIs and callbacks only. No private APIs, no internal offsets, no undocumented structures. If you believe a specific documented API would help (for example one that reports whether a file has user-writable mapped references, or a cache/section flush or purge routine), name it and its documented IRQL/context requirements. You have NO network access: mark every external API contract you cannot confirm from the repo as UNVERIFIED so the reviewer can check Microsoft Learn.
- Callback constraints already established (STAGED-WRITES.md ~170-190): InstanceSetup is PASSIVE_LEVEL and must not synchronize or do IPC; a SyncTypeCreateSection acquire-for-section callback may fail section creation only with STATUS_INSUFFICIENT_RESOURCES; SyncTypeOther cannot be failed; filesystem name queries are unsafe in paging I/O and in acquire/release callbacks; cache-only name lookup can miss.
- Fail closed: if the barrier cannot be established, the volume/file must not be admitted to staged protection (taint enforcement and normal staging-disabled builds remain in force). Unqualified capabilities stay disabled.
- Windows 10 19045.2965, NTFS, FltMgr 10.0.19041.1. Normal builds keep staging compiled out (SafeUploadStagingPrototype); the change belongs to the feature build only.
- The agent restarts on policy changes (real agent pushes policy at startup); the driver may be loaded manually or at boot with pre-existing mapped files.
- Concurrency: new opens/maps racing attachment, policy push/replace, and approved publication must all be considered.

## 5. Steps
1. Summarize in <=25 lines how admission works today: where a file becomes owned/staged, what decides scope, and exactly why an existing section escapes (cite lines).
2. Propose 2 or 3 genuinely different options (for example per-file admission check at create/first-open versus a volume-level epoch that refuses activation until a scan or flush proves no outstanding writable references versus a hybrid). For each: mechanism and the documented APIs/callbacks used; why it closes leak (a), leak (b), or both; what it does to a section created AFTER the barrier; races (open/map/attach, policy change, publication) and how they are closed; IRQL/locking/lifetime/unload considerations; failure policy and what a user sees on refusal; what remains uncovered; performance/complexity (functions/files that would change); and an observable test plan using the two existing repro scripts (REPRODUCED -> blocked) plus concurrent open/map/attach and policy-change cases.
3. Give a recommendation with reasons, the minimal first implementation slice, and the top 3 risks you could not resolve from the repo.
4. Write the result to driver/evidence/2026-10-02/admission-epoch-design.txt (plain text, at most 250 lines). Create only that file.

## 6. May edit / forbidden
- You may create exactly one file: driver/evidence/2026-10-02/admission-epoch-design.txt.
- Forbidden: editing any other file; git commit/push/reset/clean/checkout/stash; deleting anything; any VM, virsh, ssh, scp or network use; reading outside this repo except to run basic shell utilities.

## 7. Done when
driver/evidence/2026-10-02/admission-epoch-design.txt exists with the sections in step 2-3 and file:line citations for current-behavior claims.

## 8. Final message format (at most 150 words)
What you produced; the file path; your recommended option in one sentence; which claims are UNVERIFIED external API contracts; what you did NOT verify; open questions. Do not paste the design into the message.
