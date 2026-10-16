<!-- Read-only Sol 6.1 xhigh memo on 304d078c, 2026-10-16. Its strict source-retention target came from the brief and is superseded by the owner decision of 2026-10-16 (folders follow the copy rule); the RCA, caller table and controls remain valid. -->
**T6 RCA and design memo — source `304d078c`**

**Allowing protected directory creation alone would not safely resolve directory moves.** It would unblock recursive copy engines, but those engines can delete source files before SafeUpload’s asynchronous inspection and publication finish.

The smallest safe immediate behavior is to retain directory-move refusal. Successful folder moves need a coordinated tree transaction. For same-volume NTFS, inspecting an immutable tree and then forwarding the caller’s original directory rename is the strongest candidate; it requires new kernel authority and lifetime machinery.

I inspected the requested source tip and the current decisions in the staging checkout. No files changed; no builds, native controls or VM runs were performed. The recorded `m2t6rv4` result remains component evidence, not final-pair directory qualification. [Current T6 status:1024](/home/victor/Work/safeupload-staging/driver/POST-MVP-PLAN.md:1024)

**RCA: the current directory gate**

`StageAdmit` routes requests carrying `FILE_DIRECTORY_FILE` to `StageAdmitDirectoryMutation`, before ordinary file staging. This applies to the authenticated service too; there is no service exemption from that directory gate. [StageStream.c:8859](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:8859)

The gate classifies the following requests as mutations:

| Native request | Current classification |
|---|---|
| `FILE_CREATE` or `FILE_OPEN_IF` | Mutating, irrespective of desired access or whether `OPEN_IF` finds an existing directory |
| `FILE_SUPERSEDE`, `FILE_OVERWRITE`, `FILE_OVERWRITE_IF` | Mutating; these are not valid ordinary directory dispositions |
| `FILE_OPEN` with directory add-file/add-subdirectory rights, write EA/attributes, delete-child, `DELETE`, `GENERIC_WRITE`, `GENERIC_ALL` or `MAXIMUM_ALLOWED` | Mutating |
| `FILE_DELETE_ON_CLOSE` | Mutating; a separate directory cleanup guard also exists |
| `FILE_OPEN` for enumeration/read/query, without those rights | Passes this mutation predicate |
| `WRITE_DAC`/`WRITE_OWNER` alone | Deliberately excluded for T10; Windows decides authorization |

The predicate is explicit in [StageStream.c:8752](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:8752). Microsoft documents `FILE_CREATE`, `FILE_OPEN` and `FILE_OPEN_IF` as the supported dispositions with `FILE_DIRECTORY_FILE`. [NtCreateFile documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile)

A mutating directory request receives `STATUS_ACCESS_DENIED` when its normalized name matches:

- A current or pending protected destination, including ancestor matching.
- The protected namespace tracked by staging.
- An unresolved name on a potentially protected volume, except recognized absence results that should reach the filesystem.

This happens **before NTFS creates the directory**. It is a blanket namespace guard, rather than an inspection verdict. [StageStream.c:8780](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:8780)

Directories also have no ordinary staged-file implementation waiting behind that guard: writer reservations skip directory creates, post-create excludes actual directories, and `StageCreate` rejects `FILE_DIRECTORY_FILE`. [StageWriters.c:1591](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageWriters.c:1591), [StageWriters.c:2806](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageWriters.c:2806), [StageStream.c:2421](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:2421)

The rename path has a separate limitation. `StageExternalRename` does **not** distinguish files from directories. If an outside source targets protection, it returns `STATUS_NOT_SAME_DEVICE`; protected-source moves generally receive `STATUS_ACCESS_DENIED`. A directory therefore receives the same fallback hint as a file, despite having no recursive-copy contract behind it. [StageStream.c:9263](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:9263), [StageStream.c:9355](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:9355)

**Caller behavior: what is established and what remains inferred**

The driver source establishes what happens **if a request reaches a particular gate**. It cannot establish the exact native dispositions, access masks, fallback choices or localized messages used by closed-source Windows callers. Those require traces. In particular, a caller can fail while opening a source or destination directory before reaching the rename refusal.

| Caller/workflow | Current expected result and evidence boundary |
|---|---|
| Explorer **New folder** | A directory-create request under protection reaches the blanket refusal: no folder is created; Explorer should display an access-related error. Exact native request and wording remain unmeasured here. |
| Explorer folder move | The recorded observation is source retained because destination directory creation is refused. The harness uses `Shell.Application.MoveHere`, not real interactive drag. Its flags suppress error UI, so returning from the automation call does not establish success. |
| `cmd md` / `mkdir` | Fresh protected directory creation is refused. Deep creation eventually fails at the first protected component. Access-denied output is expected; native request details require capture. |
| `cmd move` — directory | A native directory rename into protection receives the fallback hint if it reaches `StageExternalRename`; earlier directory opens may fail instead. Recursive fallback must not be assumed from the successful **file** row. |
| PowerShell `New-Item -ItemType Directory` | Fresh creation is refused. `-Force` on an existing directory may return that object without creating anything; such success is not evidence that the mutation gate allowed creation. `-ItemType File` follows the file path, including ordinary empty-file handling. |
| PowerShell `Move-Item` — directory | Expect an error and source retention for the native-rename path. Windows PowerShell 5.1 behavior needs native verification. Current open-source PowerShell contains conditional recursive fallback, but that is not proof of the installed 5.1 implementation. |
| `MoveFileEx`, flags `0` | No copy fallback is requested. A directory rename reaching the outside→protected branch fails with Win32 `ERROR_NOT_SAME_DEVICE` rather than moving the tree. |
| `MoveFileEx`, `MOVEFILE_COPY_ALLOWED` | File fallback exists. **Directory recursive fallback is not promised.** Microsoft requires directory moves to remain on the same drive. |
| Robocopy | A newly required protected destination directory is refused. Existing-directory copies can progress through file staging, while directory metadata operations can fail separately. `/MOV` and `/MOVE` delete sources after copying; they do not require an initial directory rename. They therefore expose the publication-ordering problem directly. |

Microsoft’s [`MoveFileEx`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw) contract does not turn a directory error into recursive copy/delete. Explorer’s shell engine is a separate implementation: the observed folder attempt supports that particular failure path, not a universal fallback guarantee.

[`Folder.MoveHere`](https://learn.microsoft.com/en-us/windows/win32/shell/folder-movehere) returns no result value. For structured shell tests, use `IFileOperation` execution, progress results and abort state alongside independent observations. [`MoveItem` merely declares the operation](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-moveitem).

PowerShell’s [documented directory restrictions](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/move-item) and [current provider source](https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/namespaces/FileSystemProvider.cs) are useful controls, but do not replace a Windows PowerShell 5.1 trace. Robocopy separately documents `/E`, `/MOV`, `/MOVE`, security-copy options and destination deletion through `/PURGE` or `/MIR`. [Robocopy documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)

**The existing 28/28 result does not establish source-preserving moves**

Two source facts matter:

1. Staged cleanup queues further work and returns `STATUS_SUCCESS`. Sealing is subsequently queued, and publication runs in a separate agent loop. A successful copy/close is therefore not a publication receipt. [StageStream.c:5885](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:5885), [StageStream.c:6249](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:6249), [MinifilterInterceptor.cs:1527](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1527)
2. The old harness requires the source to be gone for **both clean and CPF moves**, accepting a blocked hand-back as the CPF outcome. Its folder move is informational and contributes no required assertion. [moves-coordinator.ps1:99](/home/victor/Work/safeupload-design/driver/scripts/t6/moves-coordinator.ps1:99), [moves-coordinator.ps1:124](/home/victor/Work/safeupload-design/driver/scripts/t6/moves-coordinator.ps1:124), [moves-coordinator.ps1:148](/home/victor/Work/safeupload-design/driver/scripts/t6/moves-coordinator.ps1:148)

Consequently, that pass proves neither **publication before source deletion** nor **source retention when blocked**. The stronger requirement in this task needs explicit assertions; a hand-back is not its substitute.

**Required directory semantics**

| Operation | Required safe behavior |
|---|---|
| Fresh directory creation inside protection | May create an ordinary empty directory under the caller’s native Windows checks. This grants no authority to introduce existing file contents, directory streams, reparse targets or unchecked EA payloads. |
| Outside→protected directory move | Every file and supported content-bearing stream must receive an exact, current destination inspection decision before its bytes become public. No source removal before successful destination publication. |
| Protected→protected move or rename | Treat changed destinations as new authorization/publication work. Prior publication alone does not authorize another destination, policy or generation. Coordinate every descendant’s outstanding state. |
| Protected→outside move | Move only the public content the caller can move under Windows semantics. Private stages must remain private. Retire or fence old source-name publication authority so an old save cannot recreate the moved tree. Inspection requirements follow the destination policy, as for a copy. |
| Protected root or an ancestor | Continue refusing ordinary moves/deletes that relocate the configured protection namespace. Moving a child directory is a different case. |
| Empty directory | No regular-file inspection is needed, but emptiness, streams/metadata, identity, authority and namespace stability still need proof. “Empty” is not a bypass. |
| Empty file in any tree | Ordinary stable-length seal, trivial clean inspection and exact publication. No `EmptyHeld`, placeholder-success or omission from the manifest. |
| Nested tree | Enumerate completely, including hidden/system entries. An unreadable, unstable or unsupported member fails the operation; skipped entries cannot count as success. |
| One CPF file | Under the strict contract requested here, reject before deleting **any** source member. The simplest failure policy also performs all inspection before publishing clean siblings. |
| Existing destination/merge | Refuse initially. Merge, replacement and skipped-existing-file semantics materially enlarge ordering and rollback requirements. |

A directory already inside protection is not automatically safe to rename. Its descendants can have private versions, checked public backends, accepted deletes, pending publication or unresolved recovery holds. The existing directory-rename registry code rewrites retained tracking names and handles tracking loss; it does not provide a transactional migration of T5 publication authority. [StageWriters.c:1893](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageWriters.c:1893)

**Smallest safe design and the boundary of that recommendation**

For the immediate M2 change, retain directory-move refusal and make the refusal type-aware and diagnosable. A directory refusal should not advertise the file copy-fallback contract through `STATUS_NOT_SAME_DEVICE`. Select and qualify a hard failure status and caller behavior.

**Do not claim that this alone guarantees source retention for recursive tools.** Robocopy `/MOVE`, a script, or a shell path can independently create destinations, copy children and delete sources without submitting a directory rename. Child creates contain no trustworthy “this belongs to a move” bit. PID, timing, pathname and matching digest are insufficient authority.

Likewise, standalone `mkdir` support is a reasonable separate improvement, but enabling it also enables those recursive flows. It cannot close T6’s strict move contract by itself. Until coordination exists, the current directory-create refusal should not be relaxed as the purported folder-move fix.

For successful same-volume folder moves, the preferred **candidate architecture** is an exact tree seal followed by one original native rename:

1. **Capture the original operation.** Bind the source directory object, mount/volume, source and destination parents, canonical leaf/case rules, caller grants, flags, policy epoch and operation nonce. Initially support an absent destination on the same local fixed NTFS volume.
2. **Reserve and freeze before enumeration.** Establish a kernel-owned namespace guard covering the tree and relevant parents. Bound admission, manifest storage and all required completion/recovery state before mutation.
3. **Build a complete exact manifest.** Bind every member to its full identity, destination and generation. Refuse reparse points, unsupported streams/EAs, hard-linked members or other shapes lacking a complete authority proof.
4. **Refuse conflicting T5 state initially.** Any descendant private view, live writer/mapping uncertainty, pending delete/publication or recovery hold causes a clean failure. Supporting their rebinding is a later extension.
5. **Seal and inspect every member.** Maintain exact immutability throughout inspection and commitment. Empty files take the same seal/inspect/publication state progression as other members. Revalidate current destination policy before commitment.
6. **Forward the original NTFS rename once.** Preserve its caller authorization and native security/identity behavior. The root namespace operation publishes the already-inspected tree and removes its old link together; there is no earlier recursive source deletion.
7. **Retain the guard through exact result recording and descendant authority installation.** A lost result becomes an unresolved transaction. Reconcile exact native evidence and retry bookkeeping only.

This is a new publication primitive, **not** an exemption to the current file publication permit. Its per-member sealing, generation and publication receipts need a concrete protocol design before implementation.

Its hardest lifetime issue is the gap before the native rename: Microsoft documents restrictions on renaming directories containing open child files. Scanner/anchor child handles therefore cannot themselves constitute the tree seal. They may have to close while a separately enforced kernel seal continues to exclude mutations. [FILE_RENAME_INFORMATION documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)

A coordinated copy broker is the alternative where actual recursive copies are required. It must retain exact source authority, inspect the complete private workload, publish through T5, and delete exact source members only after the entire intended destination has durable publication evidence. This is larger and introduces publication/delete failures that can leave approved destination copies or duplicate sources. Whole-tree atomic publication would need another tree publication design; existing per-file commits do not provide it.

**Kernel lifetime and lock-order deltas for review**

| Delta | Required ownership and ordering |
|---|---|
| Pending tree operation | Counted ownership of callback data, source operation, instances, subject context and transaction state; explicit cancel/disconnect/teardown transitions |
| Tree seal | Cover child insertion/removal/rename/link, source/destination ancestor changes, streams/EAs/reparse/security mutation, outstanding delete-on-close and cleanup effects |
| Object immutability | Exact writer, section, paging-I/O and alias evidence; share modes, scans and elapsed time cannot replace missing lifetime evidence |
| Publication transition | Keep exclusion after scanner handles close, through lower rename completion and installation of destination authority |
| Namespace bookkeeping | Preserve source generation barriers and every affected destination binding; no pathname-only rewrite of manifests or permits |
| Uncertain completion | Retain exact native result obligations; never retry a possibly completed rename or synthesize unchanged failure |
| Teardown | Close admission, cancel unforwarded work, drain actual callbacks/local owners; preserve unresolved durable work without service-dependent mandatory teardown |

All enumeration, inspection RPCs, queue waits and file I/O must run outside namespace/stream resources and spin locks. Do not hold an admission epoch while waiting behind a destination operation that must drain that epoch. The current T5 dispatch explicitly avoids that dependency for deletes. [StageStream.c:10157](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:10157)

For a first implementation, a serialized tree coordinator is simpler than taking many descendant turns opportunistically. It still needs a defined relationship to T5 destination turns and journal locking; “one global lock around inspection” is unsafe.

**Agent changes and T5 interaction**

The agent needs a bounded durable tree manifest, per-member inspection evidence, current-policy validation, exact native-result recording, startup reconciliation and named diagnostics. It must distinguish “rejected before commitment” from “committed, bookkeeping unresolved.”

For a copy broker, inspection preparation must be separated from publication: the current publisher combines snapshot inspection and commitment for one transfer. It cannot simply be called once per child while promising whole-tree rejection on CPF. [StagedTransferPublisher.cs:178](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:178), [StagedTransferPublisher.cs:384](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:384)

T5 rules remain:

- Only an already-published successor supersedes a delete; an approved or inspecting tree member does not. The journal checks `LatestPublished`, not approval. [StagedDestinationCommitJournal.cs:400](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedDestinationCommitJournal.cs:400)
- A delete that wins bars older publication. Tree operations must participate in those barriers rather than bypass them. [StagedDestinationCommitJournal.cs:758](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedDestinationCommitJournal.cs:758)
- A broker deletes source files through exact caller-authorized operations, postorder, root last. A successfully published destination does not authorize deleting a substituted or subsequently changed source.
- Native tree rename needs no recursive T5 source dispositions, but does need durable source-name retirement and destination publication results.
- `/MIR` and explicit delete-then-save retain their approved T5 semantics. A later blocked save does not resurrect explicitly deleted public content.

Preserve the caller’s requested operation semantics. A native directory rename’s authorization and ACL behavior differ from recursive copying. Converting it into SYSTEM-owned copies must not manufacture child read/delete rights or replace native owner/DACL behavior.

**Limits and capacity**

Reserve for member count, depth/path storage, identity records, snapshots, parser workers, receipts, disk headroom and retained recovery state. Account for simultaneous lifetimes and actual NTFS quota failures. Once admitted, completion and reconciliation must not depend on finding another unreserved receipt slot.

The source currently retains a 128-live-version limit and a 16 MiB staged-size bound; these are implementation limitations, not recommended new tree defaults. A tree cannot evade them by silently skipping members, and changing them belongs with replacement accounting. [StageStream.c:40](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:40), [StageStream.c:4842](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:4842)

**Required controls and qualification rows**

First capture native mechanisms on an approved builder, without treating its Windows build as target qualification:

| Control group | Required observations |
|---|---|
| Directory creates/opens | All six dispositions; directory/non-directory options; read/query versus add-child/write/delete/security rights; delete-on-close; absent/existing/deep paths; exact NTSTATUS and `IoStatus.Information` |
| Caller traces | Explorer New folder and real move drag; `md`; directory `cmd move`; Windows PowerShell 5.1 `New-Item`/`Move-Item`, including `-Force`; `MoveFileEx` with/without copy allowed; robocopy copy, `/MOV`, `/MOVE` and existing destination |
| Native move semantics | Empty/populated/nested trees, absent/existing destination, same-parent rename, other-parent move, real cross-volume behavior, open children, mappings and sharing |
| Security | Original grants, owner/DACL/SACL/label, inheritance, restricted/impersonated callers, denied create/read/delete, and native versus copy behavior |
| Payload shapes | Empty files/directories, hidden/system members, directory/file ADS, EAs, reparse points, hard links, sparse/compressed/EFS shapes |
| Failure mechanisms | Quota/disk exhaustion, cancellation and source mutation; verify which operations already occurred before each error |

Real cross-volume controls establish API behavior, but do not prove that a shell reacts identically to an artificial same-volume `STATUS_NOT_SAME_DEVICE`.

After implementation, builds, component gates and the coherent pre-boot review, run the following on the **matched final pair in ordinary, runtime-Verifier and boot-Verifier modes**:

| Row | Required verdict |
|---|---|
| D01 — standalone directory operations | Approved create/open surface works; denied operations preserve native authority and fail closed |
| D02 — every supported caller | Clean tree succeeds, or documented whole-operation refusal preserves the source; actual drag tested separately from automation |
| D03 — mixed tree, CPF first/middle/last | No blocked bytes public; no source deletion before rejection; clean-sibling outcome matches the chosen tree policy |
| D04 — empty/nested trees | Complete identity/content manifest; zero-byte files use ordinary publication; no skipped hidden/system members |
| D05 — into/within/out and ancestor cases | Correct policy at each destination; protected root/ancestor guards remain effective |
| D06 — T5 races | Delete versus inspecting/approved/published member; old-name reuse; pending private save; publication wins and delete wins |
| D07 — immutability races | Existing/new writers, mappings, paging writes, alternate links, child insertion, ancestor rename, ACL/reparse changes |
| D08 — limits and recovery | Capacity exhaustion, source/destination quotas, cancel, requester exit, service disconnect/restart and lost native/result receipts |
| D09 — source cleanup, if brokered | Entire destination publication precedes first source removal; exact deletion; changed source retained; root removed last |
| D10 — teardown/restoration | Required lifetime assertions, no repeated public mutation, separate restoration verdict |

Independent observation must cover the **whole destination subtree and supported streams**, throughout the critical window, with `ForbiddenByteCount=0`. Final hashes or the actor’s private view alone are insufficient. Record source identities and disappearance ordering against exact publication receipts; delayed-inspection controls must make an early-delete defect observable.

Replace the folder `INFO` probe with required assertions. Preserve failed evidence and stop rules. These rows remain proposals here; no lab action was initiated.

**Owner decisions needed before dependent implementation**

| Decision | Recommendation and user-visible effect |
|---|---|
| Can M2 accept directory-move refusal, or must clean folder moves succeed? | Keep refusal until the new mechanism qualifies. Do not mark T6 complete merely because refusal is safe. |
| Must arbitrary recursive tools, particularly robocopy `/MOVE`, satisfy the strict contract transparently? | Treat this as explicit additional coordination scope. Root-rename interception cannot guarantee their source retention. |
| First successful tree scope | Same-volume fixed NTFS, absent destination, plain tree, no conflicting T5 state. Refuse merge/replacement and unsupported shapes cleanly. |
| Publication architecture | Prefer the sealed native-rename candidate for native directory moves, subject to design review. Choose a broker separately for recursive-copy workflows. |
| Tree failure policy if brokered | Inspect everything before any source deletion; reject the whole move on CPF. Specify whether operational publication failures may leave approved partial copies. |
| Resource defaults | Set measured, configurable limits with upfront reservation and actionable refusal; do not reinterpret receipt ceilings as a tree-size policy. |

The source-retention requirement in this task is the design target, not an unanswered preference. Its mismatch with the old CPF harness must be reconciled explicitly before qualification.

A Sol 6.1 xhigh advisory check agreed with the central boundaries above. Formal design acceptance and pre-boot review remain outstanding under the current review policy; this memo and that advisory check are not qualification.