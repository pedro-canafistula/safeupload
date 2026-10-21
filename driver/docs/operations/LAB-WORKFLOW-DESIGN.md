# SafeUpload lab and development workflow design

2026-10-13 · proposal for independent **Sol 6.1 xhigh** review · source checkout `6128a892b30c0151a9cc2684b45d2cee56040cb1`.
This note specifies future tooling; it implements nothing and reports no new Windows or VM measurements.
Repository references use `file:line` at this checkout. External documentation was checked on 2026-10-13.

## Authorization and product boundary

The accepted starting point is [driver/M2-COMPLETION-PLAN.md:84](../../M2-COMPLETION-PLAN.md#development-workflow-changes).
The controlling later decision authorizes designs now, while tooling implementation still waits for the T5 integration checkpoint
([driver/POST-MVP-PLAN.md:52](../../POST-MVP-PLAN.md#owner-decisions), especially lines 61–64).
Neither this note, its review, nor a green readiness report releases the T4 runtime stop at
[driver/POST-MVP-PLAN.md:184](../../POST-MVP-PLAN.md#m2--active).
The single authorized hand-back attribution diagnostic retains its unchanged pair, scope and nonqualifying status; it is not a
standing permission for a new run ([driver/POST-MVP-PLAN.md:37](../../POST-MVP-PLAN.md#owner-decisions)).

M2 remains local fixed NTFS, with taint retained and staging compiled out of normal builds.
The completion order remains M2 → M3 → T21 USB → T22 SMB → T23 cloud sync → M4 → owner-approved taint removal
([driver/POST-MVP-PLAN.md:7](../../POST-MVP-PLAN.md#milestone-order), [AGENTS.md:34](../../../AGENTS.md#product-invariants)).
Tooling must never broaden product destination support, turn partial inspection into approval, discard unresolved private stages,
or use SYSTEM rights to manufacture caller authority. Empty content uses ordinary seal/inspect/publish; pending or blocked saves
do not cancel deletes ([driver/docs/design/publication-and-namespace/T5-DELETES.md:19](../design/publication-and-namespace/T5-DELETES.md#1-invariants)).
Recovery retries unfinished bookkeeping, not an accepted filesystem mutation
([driver/docs/design/publication-and-namespace/T5-BOUND-PUBLICATION.md:229](../design/publication-and-namespace/T5-BOUND-PUBLICATION.md#durable-outcomes-and-recovery)).
The fixed-NTFS forced-teardown Restart exception does not extend to removable remount recovery
([driver/POST-MVP-PLAN.md:88](../../POST-MVP-PLAN.md#owner-decisions)). Lab reclamation concerns build output, never product recovery data.

Historical summaries are context, not current authority: [driver/MVP-PLAN.md:3](../../MVP-PLAN.md),
[driver/docs/architecture/STAGED-WRITES.md:37](../architecture/STAGED-WRITES.md#admission-and-identities), and
[driver/docs/architecture/ARQUITETURA.md:8](../architecture/ARQUITETURA.md#protótipo-isolado-de-escrita-em-estágio).
For example, the old staging limits and the architecture's removable/network aspirations do not change today's gates.
The approved unreadable-seed choice remains private retention without full-file hand-back until read/export authority exists
([driver/docs/design/publication-and-namespace/T5-NATIVE-PUBLIC-OPENS.md:638](../design/publication-and-namespace/T5-NATIVE-PUBLIC-OPENS.md#owner-choice--unreadable-seeded-bytes)).

## Observed starting point

| Evidence | Current behavior and design consequence |
|---|---|
| [driver/scripts/Invoke-ExactAgentMatrixBuild.py:528](../../scripts/Invoke-ExactAgentMatrixBuild.py#L528) | Fresh label, committed `agente` archive, source/archive receipts, builder identity before SCP, independent discovery/TRX/package validation. Preserve these. |
| [driver/scripts/Build-ExactAgentMatrix.ps1:795](../../scripts/Build-ExactAgentMatrix.ps1#L795) | Four separate profile source trees; user and SYSTEM legs; two Release packages; completed-profile cleanup at line 935. Disk failures are not evidence that cleanup is absent. |
| [driver/scripts/Invoke-ExactSourceBuild.sh:71](../../scripts/Invoke-ExactSourceBuild.sh#L71), [driver/scripts/Build-ExactSource.ps1:79](../../scripts/Build-ExactSource.ps1#L79) | Builder identity and fresh destinations; four Rebuild/PREfast/ApiValidator profiles. Signing is coupled into the current runner at PowerShell line 136. |
| [driver/scripts/Invoke-HarnessWindowsGate.sh:14](../../scripts/Invoke-HarnessWindowsGate.sh#L14) | Hardcoded builder endpoint; uploads before a shared identity/capacity gate. Parses selected scripts and executes self-checks, not a product qualification row. |
| [driver/scripts/debuggees.txt:5](../../scripts/debuggees.txt#L5) | Inventory is broader than approval; debug2/debug3 share `192.168.122.52`. Address reachability cannot select the target. |
| [driver/scripts/Invoke-StagedSuiteBatch.sh:17](../../scripts/Invoke-StagedSuiteBatch.sh#L17) | Explicit approved target and serial cases; failed/missing verdict stops after disk cleanup. This accepted fix already exists. |
| [driver/scripts/suite_case_verdict.py:31](../../scripts/suite_case_verdict.py#L31) | Exact case/index/restoration checks; child exit 1 is acceptable only for the deliberately incomplete table with all selected gates passing. Reuse its semantics. |
| [driver/scripts/run-disk.sh:68](../../scripts/run-disk.sh#L68) | Shared-IP sibling check, stale-state refusal, overlay space floor, TPM/NVRAM checks and reset-NVRAM start. End restores XML and checks base mtime/size, not a full base content digest. |
| [driver/scripts/Verify-RunDiskRestoration.sh:31](../../scripts/Verify-RunDiskRestoration.sh#L31) | Separate fresh overlay boot and guest baseline check. Retain this independent result; an end-of-run disk deletion is insufficient. |
| [driver/scripts/Invoke-StageCycles.sh:49](../../scripts/Invoke-StageCycles.sh#L49) | T4 uses a 15 GiB overlay floor; general run-disk default is 20. SCP uses `accept-new` at line 51; shared config must require previously pinned keys. Loop deadline is monotonic at line 344; total elapsed reporting uses `date` at line 400. |
| [driver/scripts/remote_ps.py:26](../../scripts/remote_ps.py#L26) | Long commands upload a temporary script. A doctor must avoid this branch to maintain its read-only contract. |

Retained disk receipts demonstrate repeated near-exhaustion: 337,358,848 free bytes before one cleanup, and another receipt reports
zero free bytes ([driver/evidence/2026-10-13/t9-office-notes1-preflight-cleanup.stdout.txt:3](../../evidence/2026-10-13/t9-office-notes1-preflight-cleanup.stdout.txt),
[driver/evidence/2026-10-13/t9-formula1-preflight.stdout.txt:5](../../evidence/2026-10-13/t9-formula1-preflight.stdout.txt)).
The scoped rule checked retained package/manifest hashes and every unpacked member before removal, preserving source and receipts
([driver/evidence/2026-10-13/t9-formula1-preflight.stdin.ps1:12](../../evidence/2026-10-13/t9-formula1-preflight.stdin.ps1#L12)).
The task also reports a later 8 GB completed-folder recovery, host use at 98–99%, and roughly 15 minutes per full agent matrix.
Those exact later totals were not independently located in the inspected receipts; treat them as supplied planning context.
The documented host incident includes 239 GB of dumps, duplicate conversions, overlay chains and snapshot-pinned space
([driver/docs/history/POST-MVP-LOG.md:333](../history/POST-MVP-LOG.md#host-disk-and-disposable-run-disks-2026-10-09-afternoon)).
The 878-file/~680k-line evidence growth is recorded at [driver/M2-COMPLETION-PLAN.md:95](../../M2-COMPLETION-PLAN.md#development-workflow-changes).
Inventory and measured before/after free bytes, rather than estimated deletion sizes, will settle current capacity.

## 1. One configuration and a read-only doctor

Propose `driver/lab-config.json`, parsed by Python's standard library with a strict schema and no command interpolation.
It contains expected facts and policy, never passwords, private keys, arbitrary shell fragments or executable hooks.
Use one configuration for all runners; generate Ansible inventory from it later. Keep credentials in existing protected locations.
Changes to target approval, baseline identity or infrastructure remain explicit owner decisions; configuration cannot approve itself.
For CI, trusted launch code supplies the reviewed configuration; a PR's copy cannot change the permitted destination.

| Configuration group | Required fields and initial values |
|---|---|
| Controller | Expected controller identity, libvirt URI `qemu:///system`, existing SSH identity reference, pinned known-host keys, local lock/queue directory. Controller identity must be inventoried, not guessed. |
| Builder | Address `192.168.122.210`, user `vika`, computer `DESKTOP-O1LP5DG`, UUID `C6440689-D11C-4C63-A463-F3722B7DDB69`, MAC `52-54-00-63-87-7A`, recorded OS `19045.6466` (revalidate), scratch root `C:\Users\vika\Documents`. |
| Target | Only `win10-debug3`, address `192.168.122.52`, UUID `FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3`, hostname `WIN10-DEBUGGED`, OS `19045.2965`; explicit exclusion of debug2 and all unapproved domains. |
| Toolchain | Exact VS instance/product/component versions; x64 MSBuild/compiler versions; SDK/WDK full versions; rule/validator identity; .NET SDK `10.0.400`, runtime versions, Windows PowerShell 5.1. Unknown fields prevent delivery. |
| Baseline | Approved base path/content hash, inactive XML hash, firmware binary/template hashes, NVRAM reset method, no TPM, Secure Boot off, testsigning on, original driver/policy hashes and last independent baseline receipt. |
| Capacity | Physical filesystems/storage pools, byte reserves and operation-specific peaks from section 2, artifact root, maximum queued jobs and capture limits. |
| Safety | T4 stop reference, currently allowed operation classes, explicit exceptions from recorded owner direction; no generic `force`/`ignore-doctor` flag. |

Builder identity values already occur at [driver/scripts/Invoke-ExactAgentMatrixBuild.py:570](../../scripts/Invoke-ExactAgentMatrixBuild.py#L570).
Guest baseline currently accepts several clone UUIDs, so the wrapper must additionally require the exact selected UUID
([driver/scripts/Get-StagedBaseline.ps1:46](../../scripts/Get-StagedBaseline.ps1#L46)). Microsoft documents the SMBIOS UUID source [W1](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystemproduct).
These are lab routing checks under pinned SSH trust, not hardware attestation or product object authority.
The kernel project selects SDK `10.0.28000.0`; the builder script selects VS `18\Community` and x64 MSBuild
([driver/SafeUpload.Minifilter/SafeUpload.Minifilter.vcxproj:18](../../SafeUpload.Minifilter/SafeUpload.Minifilter.vcxproj#L18),
[driver/scripts/Build-ExactSource.ps1:29](../../scripts/Build-ExactSource.ps1#L29)). These paths do not establish installed patch versions.

Proposed interface: `python3 driver/scripts/lab.py doctor --operation agent-matrix --label <fresh-label> --commit <sha>`;
target operations additionally require `--target win10-debug3`. No target default is allowed, even with one approved domain.
`--offline` checks schema and retained evidence only and always prints `LiveReadiness=UNVERIFIED`.
An online doctor may query the existing builder; it never boots, shuts down, uploads, repairs, clears locks, resynchronizes clocks,
loads drivers, changes services, refreshes libvirt pools or starts a baseline check.
Queries use bounded inline PowerShell commands below the helper's upload threshold; reject oversized probes before execution.
Read-only means no requested persistent configuration/data mutation; OS access/audit activity caused by queries is not claimed absent.

Doctor emits JSON plus a short human table: check ID, expected/observed values, PASS/FAIL/UNKNOWN/NOT_APPLICABLE, reason and remedy.
Output records source commit, configuration digest, operation, endpoint identities, observed free bytes and monotonic duration.
Exit 0 means all checks required for that operation passed; exit 2 means invalid invocation/configuration; exit 3 means refusal.
Missing, timed-out, stale, duplicate or malformed observations cannot count as PASS. UTC is correlation metadata, not a deadline.
Scope matters: a shut-off target does not prevent an agent-only build; unrelated target observations remain clearly unverified.

The host-side target preflight requires shut-off-on-approved-base, no residual run state, unchanged XML/base/firmware identity,
known storage topology, no TPM and all shared-address peers **shut off**, including paused or otherwise indeterminate peers.
Use read-only libvirt/QEMU inspection; never call `_rd_vol` from doctor because it refreshes the pool
([driver/scripts/run-disk.sh:21](../../scripts/run-disk.sh#L21)). A missing permission causes refusal, not privileged repair.
Secure Boot/testsigning are guest facts: host firmware selection alone cannot prove them. The retained independent guest receipt
must match approved immutable inputs before boot; fresh guest checks run on the disposable disk **before product delivery/install**.
An absent/mismatched receipt refuses product boot; a separately authorized baseline-only boot may establish one.
`Confirm-SecureBootUEFI` returning false is distinct from unsupported/access-denied [W2](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi); TESTSIGNING needs explicit verification [W3](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option).
No TPM is the owner's lab setting, not a Microsoft claim that test signing requires TPM removal.

Get-StagedBaseline remains authoritative for original SYS/policy hashes, unloaded filter, Verifier off, manual/stopped driver and
fixture/account/profile/task absence ([driver/scripts/Get-StagedBaseline.ps1:49](../../scripts/Get-StagedBaseline.ps1#L49), lines 67–144).
Add version/boot-policy observations without replacing its existing assertions. Verifier query and configuration are separate [W4](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier).
A prior baseline receipt establishes approved input provenance; it does not become a fresh guest observation by aging gracefully.
Full base hashing at enrollment/restoration can be expensive: retain that limitation and the existing per-run mtime/size check.
Any content-hash cache requires immutable storage or equivalent proof; size/mtime alone must not be labelled content equality.

**Acceptance:** fixture-driven doctor rejects omitted/wrong target, spoofed identity, changed key, debug2 running/paused, unresolved
job, unknown free bytes, wrong tool versions, stale run state, changed XML/base, TPM and missing NVRAM reset support.
Assert refusal happens before SCP, overlay creation or domain start; assert all probes belong to a read-only allowlist.
A fake transport records calls and rejects upload/mutation; finite native D1 validates actual queries and privilege needs.
Existing checks stay in their runners during migration; conflicting config versus old constants fails rather than choosing one.

## 2. Capacity and safe builder reclamation

Preflight runs before local archive creation, before source upload, again inside each Windows build script before extraction, and
before every next profile/package/capture. Windows direct invocation must not bypass the same schema-derived budget.
At execution time use `free_available >= reserve + remaining_peak + other_reserved_growth`, with checked 64-bit byte arithmetic.
Deduplicate paths on one physical filesystem; sum simultaneous demand rather than treating host scratch, evidence and overlays
as independent space when they share storage. Thin-pool exhaustion and snapshot-pinned bytes require pool-specific checks.
Use Win32_LogicalDisk for volume inventory [W5](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk); account for caller-available versus total free space under quotas [W6](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexa).
The measured result is still a snapshot, not an OS reservation. Poll between stages and stop safely if another process consumes it.

Initial proposed engineering budgets below are conservative admission defaults, **unmeasured**, subject to decision B1.
One GiB means 1,073,741,824 bytes; do not preserve the current rounded `df -BG` comparison as exact byte admission.

| Operation/location | Permanent free reserve | Additional admitted peak | What the peak includes |
|---|---:|---:|---|
| Agent matrix, builder C: | 2 GiB | max(8 GiB, measured estimate) | Upload archive, extracted source, retained profile source copies, one active profile's bin/obj/tests, both retained Release publish trees and ZIPs, restore/temp growth. |
| Kernel gate, builder C: | 2 GiB | max(12 GiB, measured estimate) | Archive/extraction, four build outputs, analyzer scratch, inspectors/fixture, signing copy and logs. |
| Focused builder diagnostic | 2 GiB | max(4 GiB, measured estimate) | One profile, selected controls, restore/temp/logs; never borrows the permanent reserve. |
| Host build scratch/artifact landing | 10 GiB | max(4 GiB, actual archive + projected fetched output) | Source archive, incoming files, validation expansion and compatibility copies. |
| Target overlay pool | 20 GiB | Planned maximum growth of run plus restoration overlay | Run workload, reboot/checkpoint overlap, plus emergency collection; restoration is budgeted before the product row. |
| Raw artifact/capture storage | 10 GiB | 2 GiB per build; 32 GiB per dump-enabled row minimum | Increase for actual dump size and conversions: three 8 GiB copies already approach 24 GiB. Never silently truncate required observations. |

Target guest admission provisionally requires 2 GiB untouched reserve plus max(4 GiB, the declared workload's overlapping stage,
snapshot, hand-back, journal and installation growth). A large-content row increases that peak before scheduling, not after filling C:.
Harness parse/self-check jobs use the focused-builder budget; candidate image/layout builds require their own measured estimates.
The 20 GiB overlay reserve preserves the general floor; adopting it for T4 instead of 15 is a tooling policy change, not a gate change.
Long/large-file rows must supply finite workload-derived growth above this floor. Unknown/unbounded growth refuses scheduling.
Separate target guest free-space requirements cover installation, private stages, snapshots, hand-backs and journal/test data;
they do not replace the T9 product accounting design or confer permission to remove its resource caps.
Native D2 measures one permitted full matrix, one kernel gate and one separately authorized capture/restoration operation.
Sample free bytes and directory allocated sizes at stage boundaries; record peak delta, unexplained background growth and margin.
Three subsequent coherent checkpoints must fit their declared peaks before lowering any provisional budget.

Retain the existing completed-profile cleanup and source recheck
([driver/scripts/Build-ExactAgentMatrix.ps1:425](../../scripts/Build-ExactAgentMatrix.ps1#L425), lines 928–935).
Retention eligibility is explicit: active, failed/unresolved, successful/retained, or successful/reclaimable. Age is never success.
Missing status or interrupted collection means unresolved. A retry gets a fresh label and does not rewrite the failed receipt.

Propose separate `lab.py reclaim --plan <receipt> --apply`; `reclaim --plan-only` is the default.
The plan names exact completed labels/paths, retained source/package/evidence hashes, expected members and expected byte savings.
It is a deletion inventory, not a per-revision source-freeze or review-disposition framework.
Acquire the same builder/host-storage exclusions as builds; revalidate identities, retention and all candidates before any deletion.
Reject roots/children that are junctions, reparses, symlinks or outside the approved scratch subtree; use literal paths and no globs.
Reject any failed/unresolved label, live job/task/process using the label, unknown process inventory or changed evidence/package.

First eligibility class is exact unpacked Release duplicates: validate the retained host ZIP and member manifest against the
original successful matrix summary; compare remote ZIP/manifest hashes; require exact member inventory and hashes in the tree.
Keep source archives, extracted source, ZIPs, manifests, logs, TRX, summaries and first failed attempts.
This formalizes the 2026-10-13 rule at
[driver/evidence/2026-10-13/t9-formula1-preflight.stdin.ps1:35](../../evidence/2026-10-13/t9-formula1-preflight.stdin.ps1#L35).
Second class is known completed bin/obj output with the existing source-input/reparse exclusion and retained required symbols.
Removing a whole old matrix folder, including its only source/receipts, is outside the initial rule; no emergency wildcard cleanup.
Full completed-folder reclamation needs verified off-builder retention of every required input/artifact/receipt and decision B2.
After each deletion, recheck surviving hashes and actual free bytes. Partial failure records exact progress; retry only remaining
eligible deletions. Neither a disk-full emergency nor a plan estimate permits deleting unresolved failures.

**Acceptance:** simulated low headroom blocks all delivery; tests cover shared-filesystem double counting and integer boundaries.
Reclaim controls retain active/unresolved labels, modified/extra package members, source under bin/obj, reparses and missing receipts.
One authorized native recovery removes only prelisted duplicates; retained hashes match before/after and free bytes actually rise.
If snapshots prevent reclamation, report zero usable recovery and stop; do not change host snapshot policy.

## 3. Fast feedback, checkpoints and serialization

Provide a visibly separate diagnostic entry point, sharing identity, capacity, process cleanup and evidence collection with gates.
Example proposed selection: feature Debug + an explicit FQN set for journal recovery or native security; print
`RunKind=Diagnostic`, `AgentMatrixGate=False`, `RuntimeQualification=False` at start and in the final receipt.
Record requested filter, discovered matching cases, executed outcomes, identity, build flags and elapsed time.
Empty discovery, duplicate/missing selected cases, skips and incomplete TRX fail the diagnostic itself; they never become a green gate.
Keep machine-dependent cases on the existing SYSTEM leg; other cases stay on the original user leg.
Current compile-only mode already separates its result
([driver/scripts/Build-ExactAgentMatrix.ps1:948](../../scripts/Build-ExactAgentMatrix.ps1#L948)); focused execution is a proposed extension.
Microsoft documents test filtering [W7](https://learn.microsoft.com/en-us/dotnet/core/testing/selective-unit-tests); the exact theory-case comparison remains the repository's stronger delivery requirement.

An incremental diagnostic workspace belongs to one developer/profile/toolchain/dependency identity and has a finite storage cap.
Its source commit is recorded each invocation; recopy changed inputs and invalidate outputs on compiler, SDK, flags or lock changes.
No mixing normal/feature or Debug/Release outputs. Treat dirty local source feedback as diagnostic, never delivered artifacts.
A source/assembly mismatch invalidates `--no-build`. Caches accelerate feedback only; checkpoint builds use fresh existing runners.
Do not add per-revision freeze manifests; the committed checkpoint identifies delivery source
([AGENTS.md:45](../../../AGENTS.md#build-and-verification)).

| Stage | Work and result |
|---|---|
| During editing | Local/offline harness checks and focused builder diagnostics; aim for <3 minutes for an agreed small set, unverified until D3. |
| Coherent agent checkpoint | Existing full normal/feature × Debug/Release matrix; exact discovered/executed cases, zero skips, 0/0 builds, both verified packages. |
| Coherent kernel checkpoint | Four WDK profiles, PREfast and ApiValidator 0/0; retain unsigned/signed artifact and symbol identities. |
| Authorized protected checkpoint | Matched pair, required ordinary/runtime-Verifier/boot-Verifier rows, independent bytes and separate restoration. Currently stopped except the recorded exception. |
| Milestone completion | Complete required gates, final Sol adversarial review and owner decisions; no cached component pass substitutes for final-pair qualification. |

Use a thin host queue under the controller's existing user state, not a daemon, polkit rule or systemd service.
Requests are immutable labels/source/operation/resources; controller lock allocation and state updates are atomic local operations.
Builder and target have separate exclusive resource keys; target exclusion also locks its shared-IP group, including restoration.
Run builds serially on the mutable builder. Run BLOCK windows and target jobs serially. Distinct resources may overlap only when
combined host CPU/memory/storage budgets permit; expensive image builds and dump conversions also reserve host capacity.
A target job consumes already-built retained artifacts: release builder ownership before reserving target, avoiding nested waits.
Batch children and the restoration child inherit the parent's reservation token; they do not reacquire and deadlock.

The builder wrapper acquires one cross-session Windows mutex with an explicit lab-account/SYSTEM DACL, holding ownership on its
own thread through child execution, collection and Job Object emptiness. Mutex naming/ownership/abandonment are documented [W8](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw).
The host resource lock is taken before readiness; the trusted remote wrapper obtains its mutex **before source SCP** and acknowledges
the exact pending label. It retains ownership while awaiting upload, executes the build, and remains through collection/cleanup.
Thus a read-only doctor PASS is never a reservation. Repeat identity/capacity checks under ownership before delivery and extraction.
Direct Windows entry points acquire ownership themselves or validate the live parent wrapper's bound reservation; a caller-supplied
token alone cannot bypass it. Nested build/self-check children use that parent ownership rather than deadlocking on a second mutex.
The doctor only reads job receipts/process/task inventories; it does not acquire/create this mutex.
Queue admission is advisory; the execution wrapper performs the final mutex acquisition and repeats readiness under ownership.
An abandoned mutex or controller death marks the job unresolved; availability alone cannot erase its active descendants/receipts.
Microsoft's abandoned-wait result grants ownership but requires protected-state consistency checks; it is not a clean-job receipt
([abandoned mutex waits](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)).
Existing suspended-start Job Object containment and cleanup are retained
([driver/scripts/Build-ExactAgentMatrix.ps1:194](../../scripts/Build-ExactAgentMatrix.ps1#L194), lines 599–613).
Job Objects contain associated processes, not arbitrary scheduled-task/CIM/service descendants [W9](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects); inspect those separately.
No heartbeat expiry, PID alone or guest wall time releases ownership. Confirm actual child/task cleanup and retained results first.
After controller loss, residual run state blocks target reuse until existing recovery and separate restoration complete.

Queue policy: FIFO per resource; explicit priority changes record who/why, without preempting a running protected row.
Cancellation removes waiting jobs; running jobs use cooperative stop, collect first failure, then existing cleanup/restoration.
No automatic identical-source retry after a required failure. Notify the operator with label, blocker and next evidence to inspect.
Use Python monotonic time and Windows Stopwatch/QPC [W10](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps); retain UTC for correlation and preserve current clock-sync evidence.
Full Windows Restart versus Fast Startup remains a product lifetime distinction [W11](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation), not a queue timeout workaround.

**Acceptance:** D3 compares three scoped edits with fresh checkpoint results and records wait/build/test/collection times separately.
D4 submits two builds, two target jobs and one build/target overlap; no conflicting execution or shared-IP boot occurs.
Kill the controller and builder wrapper at fixed boundaries; descendants/stale state keep the next request refused.
Inject ±4-hour wall-clock steps on a candidate control guest; deadlines and ownership remain unchanged. No qualified-base clock change.

## 4. Ansible for builder and candidate configuration

Apply only after the T5 checkpoint and specific infrastructure approvals; use a user-local pinned controller environment initially.
Inventory roles distinguish builder, candidate target and qualified target. Apply to the qualified target is denied by role and
immutable identity unless a new explicit owner authorization names that change; `--limit` alone is not sufficient protection.
Generated inventory reads the same lab configuration; Ansible must not become a second source of target approval.

| Role | Pinned inputs and verified outputs |
|---|---|
| Builder toolchain | VS Build Tools product/version/component list and offline layout hash; exact MSVC/x64 MSBuild; matching SDK/WDK build numbers and full package versions; analyzer/rules and signtool. |
| .NET/dependencies | SDK 10.0.400 installer hash, runtime identities, future checked-in SDK selection and lock files for delivered app/test roots; approved package sources and locked restore. |
| Test prerequisites | Windows PowerShell 5.1, native compiler/runtime requirements, machine CNG/network controls, test accounts and scheduled-task capability; no blanket weakened assertions or privileges. |
| Scratch/services | Finite scratch/temp/package-cache directories, explicit ACLs, approved transport/time/update service configuration; pending reboot reporting and bounded reboots on candidates only. |
| Candidate applications | Versioned installer hashes/licensing and exact applications required by the acceptance matrix; no dynamic latest Office/browser installation during measurement. |

Do not silently replace current Community with Build Tools. First reproduce the existing tool inventory, then compare the candidate
product/component set on the same checkpoint. Microsoft's SDK/WDK matching-build rule and installed-QFE caveat apply [W12](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).
Retain x64 MSBuild: the historical ApiValidator extractor issue was architecture-sensitive
([driver/docs/architecture/ARQUITETURA.md:871](../architecture/ARQUITETURA.md#release-validação-resolvida-em-1-de-outubro-de-2026)).
Offline VS layouts support component selection and verification [W13](https://learn.microsoft.com/en-us/visualstudio/install/create-an-offline-installation-of-visual-studio); retain the payloads and hashes, not just a moving URL.
Exact SDK selection uses `global.json` with `rollForward: disable` [W14](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json). NuGet locked restore fails on graph changes [W15](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies).
Place these inputs where committed source archives actually include them; the agent archive currently includes only `agente`
([driver/scripts/Invoke-ExactAgentMatrixBuild.py:540](../../scripts/Invoke-ExactAgentMatrixBuild.py#L540)). A root-only pin would be lost.
Retained .NET info reports 10.0.400 and no global.json
([driver/evidence/2026-10-13/exact-agent-matrix-t9-formula1-dotnet-info.txt:2](../../evidence/2026-10-13/exact-agent-matrix-t9-formula1-dotnet-info.txt)).
Installed VS/WDK patch versions and payload availability remain unverified until D1; do not fill them from path names.

Transport is an explicit experiment. Ansible official Windows SSH support starts at ansible-core 2.18, requires Windows-shipped
OpenSSH ≥7.9.0.0, and excludes the upstream package; shell type must match the configured default [A1](https://docs.ansible.com/projects/ansible/latest/os_guide/windows_ssh.html).
Existing `remote_ps.py` SSH success proves neither server package provenance nor supported Ansible module execution.
Keep current SSH runners while testing Ansible on a candidate. Do not change the qualified target's transport to make a tool fit.
If supported SSH is unavailable, compare PSRP/WinRM over validated HTTPS on a candidate [A2](https://docs.ansible.com/projects/ansible/latest/os_guide/windows_winrm.html). Keep credentials out of logs/inventory.
Do not suppress host-key/TLS validation or enable unconstrained delegation as a convenience. Avoid network double-hop by staging
pinned installers locally. Ansible documents WinRM restrictions around installers/WUA/DPAPI; test the needed installer set [A2](https://docs.ansible.com/projects/ansible/latest/os_guide/windows_winrm.html).
Any scheduled-task/become workaround is candidate-only, explicit, and must prove identity/process/task cleanup.

`--check --diff` reports desired-versus-observed versions, services, paths and ACLs. It never silently repairs drift.
Unsupported check-mode tasks report UNKNOWN, not compliant: Ansible check mode is simulation and modules may do nothing [A3](https://docs.ansible.com/projects/ansible-core/stable-2.21/playbook_guide/playbooks_checkmode.html).
Separate pure probe tasks from installers; allow check-mode execution only of audited nonmutating probes, with secret diffs disabled.
**Acceptance:** D5 runs check → apply → reboot if required → second apply → check on one disposable candidate.
Second apply has zero unexplained changes; intentional drift is detected; fresh candidate recreation reaches the same inventory.
Also test wrong endpoint, invalid key/certificate, Unicode output, one long command, installer failure, reboot and interrupted transport.
Check-mode success alone is not idempotence, reproducibility or target qualification.

## 5. Packer images and promotion

Start after the Ansible candidate role is repeatable. Packer owns only image construction, not per-test domains/overlays.
Pin Packer/QEMU plugin versions, machine/CPU settings, firmware/templates, ISO SHA-256, Windows edition/build, unattended setup,
ordered update packages, VS/SDK/WDK/.NET payloads, application installers and Ansible/controller dependencies.
QEMU builder accepts ISO or disk-image inputs and checksum validation [H1](https://developer.hashicorp.com/packer/integrations/hashicorp/qemu/latest/components/builder/qemu). Record consumed bytes/versions in the image receipt.
No online latest updates or hidden builder mirror state. Retain legally usable media locally with access controls.

Produce a builder candidate without signing secrets, and separately a test candidate for the exact approved Windows build.
A newer Windows image is a candidate for a later platform decision, never an implicit replacement for 19045.2965.
Transport provisioning keys are temporary and unique; replace them with approved lab identities before acceptance.
Candidate creation must not clone the qualified domain UUID/IP or connect simultaneously with an address-sharing peer.
Host/network resources for the candidate require decision B4; no new VM is created by this note.
Use resource reservations for ISO/layout/image peaks before starting construction; the current near-full host is not assumed adequate.

Candidate target acceptance executes Get-StagedBaseline on a disposable overlay, preserving every existing assertion, plus exact OS,
firmware/boot settings and inventory checks. Its identity requires a reviewed candidate profile; do not weaken the qualified UUID check.
Record input recipe commit, installed inventory, image hash, baseline result and restoration result. Builder candidates additionally
run one complete agent and kernel checkpoint with the same source; compare inventories/outcomes and package contents.
Reproducibility means a repeatable accepted environment first; Windows image and signed ZIP byte identity are not assumed.
Two clean constructions must match declared semantic inventory and required outcomes; unexplained image/package differences remain open.

Promotion is a separate owner decision B5 after review of candidate versus current baseline and migration costs.
Keep original base/XML and acceptance evidence; assign a new baseline identity, never overwrite the approved original in place.
Record rollback location and required affected qualification rows. Candidate baseline acceptance does not carry old product passes forward.
Per-run disks remain solely in run-disk.sh; reset NVRAM at each start, no TPM, test signing/Secure Boot settings unchanged.
Separate restoration still boots a fresh overlay and verifies the original input state
([driver/POST-MVP-PLAN.md:96](../../POST-MVP-PLAN.md#owner-decisions), [driver/scripts/image-store.sh:1](../../scripts/image-store.sh#L1)).

**Acceptance:** D6 builds two fresh candidates from pinned inputs, verifies inventory and baseline, and deliberately changes one
ISO/update/toolchain hash to prove refusal. No product pair is installed on the qualified base and no automatic promotion occurs.
Before promotion, one authorized disposable run proves overlay deletion, untouched original base and unchanged XML independently.

## 6. Terraform remains unadopted

The owner explicitly did not adopt Terraform ([driver/POST-MVP-PLAN.md:55](../../POST-MVP-PLAN.md#owner-decisions)).
One host and one active target do not justify a second domain/disk lifecycle owner. Terraform state maps managed resource identity [H2](https://developer.hashicorp.com/terraform/language/state);
managing disks/XML that run-disk.sh temporarily repoints/deletes would create competing desired states and hazardous recovery plans.
It does not solve capacity estimation, test coverage, parser correctness, retained failures or the T4 stop.
Reconsider only after approved remote builders, multiple independent targets/networks or managed artifact infrastructure require
repeatable provisioning across hosts. Present a new proposal with state security, locking, import/rollback and ownership boundaries.
Terraform could then own persistent infrastructure; Packer owns image construction; the harness alone owns disposable run disks.
**Acceptance:** no Terraform state/provider/resources enter this rollout; a future adoption requires an explicit owner decision and
a disposable lifecycle control proving apply/destroy cannot select qualified bases, active overlays or retained evidence.

## 7. Driver/agent CI with a trusted execution boundary

Current main-only CI has a normal Windows agent/contract job, not the required four-profile lab gate
([.github/workflows/functional-web.yml:3](../../../.github/workflows/functional-web.yml#L3), lines 58–77).
Propose paths for `driver/**`, `agente/**`, shared SDK/dependency pins and lab workflow/configuration files; web-only changes keep web CI.
Changes to gates/toolchain always trigger their relevant checks. A classifier/status job reports intentional non-applicability so
path filtering cannot present a missing required status as a passing driver gate.
Within those paths, kernel source/projects select the kernel gate; agent source/projects select the agent matrix; shared protocol
or toolchain inputs select both. Harness scripts select offline controls and Windows parsing/native-signature checks; changes to a
build/verdict runner also select the component gate it validates. Design/evidence-only changes select documentation/link checks.
Use an explicit dependency map for indirect imports/build properties; ambiguous changes select both component gates.
This classification never substitutes a documentation result for a component check required by changed executable inputs.

Untrusted PRs run only hosted or separately disposable, credential-free checks with no lab route, signing key or privileged persistent
builder access. Never check out PR code under `pull_request_target` on the lab; internal PR authors are also a trust boundary.
GitHub documents persistent compromise of self-hosted runners and cautions that secret approval alone does not isolate them [C1](https://docs.github.com/en/actions/reference/security/secure-use#hardening-for-self-hosted-runners).
Trusted reviewed commits may enter the lab queue through a restricted self-hosted controller runner using trusted launch/config code.
Workflow input is a validated commit/label/operation, not shell text; the job cannot redefine target approval or bypass the T4 stop.
Register the runner only after owner approval of its location/service/credentials. A user process pilot avoids host-wide service changes.
Minimal token scope is contents read plus explicitly needed artifact/status permissions; pin actions to reviewed commit hashes.

The current kernel build signs automatically; an unsigned CI mode and separate trusted signing step are prerequisites, not existing
features ([driver/scripts/Build-ExactSource.ps1:136](../../scripts/Build-ExactSource.ps1#L136)). Preserve all four build/analyzer assertions.
An unsigned result is a static component result, not the current signed delivery gate. The trusted delivery path still verifies the
signer, unsigned unchanged copy and delivered signed hash. No production signing material enters CI; T13 remains deferred.
Simply skipping signtool is insufficient if the same persistent account can read its key: use a key-free builder candidate for CI.
Signing consumes only verified retained unsigned artifacts in a trusted operator-controlled step outside PR execution.
Until that separation exists, do not enable unattended PR-driven lab CI; manual trusted checkpoint invocation remains usable.

The controller queues existing agent/kernel/harness gates with recorded source and fresh labels. It collects receipts on failure,
validates the structured verdicts and distinguishes component, product and restoration results. Missing collection fails the job.
GitHub concurrency is useful for workflow duplication but not mutual exclusion with interactive commands [C2](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency); use the same lab locks.
Do not cancel an active qualification on a newer push. Coalesce queued redundant commits only when their gates have not begun.
No automatic product VM jobs while T4 is stopped; any later runtime schedule needs owner-authorized rows, pair hashes and restoration.

**Acceptance:** a malicious fork/internal PR changing config, runner scripts or workflow inputs cannot reach the builder/target,
read signing material or invoke SYSTEM tests on persistent lab storage. Trusted CI and interactive submission never overlap a resource.
One authorized trusted CI checkpoint reproduces all full matrix/kernel checks with 0/0, no skips and independently verified packages.
Missing discovery/TRX, failed child, incomplete table beyond the documented exception and failed restoration all reject the aggregate.

## 8. Evidence storage and citations

Preserve [driver/evidence/README.md:3](../../evidence/README.md): raw output stays local/ignored; track concise cited decision evidence.
Keep existing tracked history and tag `mvp-history-2026-10-08` intact. No history rewrite, blanket evidence removal or force-added trees.
Immediate landing remains `driver/evidence/<day>/` and `output/exact-agent-matrix/<label>/`; kernel `/tmp/claude-1000/exact-*` is scratch,
not durable retention ([driver/scripts/Invoke-ExactSourceBuild.sh:7](../../scripts/Invoke-ExactSourceBuild.sh#L7)).
Propose durable raw storage at `/mnt/safeupload-artifacts/lab/v1/<source-commit>/<label>/` on an **owner-approved existing storage volume**.
That mount/path is a proposed destination, not an observed available service; creating a mount, storage pool or remote service needs B3.
Until B3, retain current local copies and refuse jobs without headroom. Merely moving within the full root filesystem saves nothing.

Retain source ZIP, trusted runner/config identity, full logs/stdout/stderr/TRX, discovery lists, packages/manifests, unsigned/signed SYS
and matching symbols, native receipts, raw observer captures, original and final baseline/XML/restoration evidence, and failed attempts.
Bundle by label with an index of relative path, byte count and SHA-256; hash the bundle too. Use restricted access, synthetic fixtures
and encryption appropriate to any captured user/security data. Never place credentials/private signing keys in a bundle.
Complete retention requires destination re-read/hash verification and a retrieval receipt, not successful upload exit.
The Git summary cites immutable storage-relative URI, bundle/index hash, source/pair hashes, exact cases/modes and separate verdicts.
An authorized reviewer resolves the URI through the configured store; a missing artifact is an audit gap, not an inferred pass.
Only after verified retrieval may redundant local/build copies enter reclaim eligibility; never erase a first failure to make room.

Proposed new-output retention: active/unresolved failures indefinitely until resolved and explicitly released; cited milestone/native
decision bundles for product lifetime; successful uncited diagnostic bundles 30 days, full component checkpoints 180 days minimum.
Expiry only marks eligibility; deletion needs a reviewed exact list and verifies no citation, open failure or active job depends on it.
These terms need B3 approval and do not authorize deleting existing history/evidence. Keep a second verified copy of cited bundles on
an independent approved storage destination; without it the store is single-copy and reclamation of the only original is refused.
**Acceptance:** an offline reviewer retrieves one prior pass and one failure by summary citation and recomputes every hash.
Interrupted upload, missing member, changed bundle and expired-but-cited data prevent deletion and mark retention incomplete.
Measure new tracked evidence bytes/files per coherent checkpoint; raw-volume growth must remain outside Git without losing auditability.

## 9. Decisions, finite controls and rollout

All choices below are **pending**, not approvals inferred from this design. Lab users means developers/operators; product behavior
and qualification requirements stay unchanged. Specific host-wide and baseline actions still require the owner's authorization.

| ID / choice | Options and what users notice | Risk | Concrete recommendation |
|---|---|---|---|
| B1: capacity defaults | Admit with the proposed reserves/peaks; or keep today's smaller/ad hoc limits. Larger budgets may refuse a build earlier; small limits allow more attempts but more disk-full interruption. | Unmeasured estimates can over-refuse or underestimate; lowering limits can lose collection capacity. | Adopt conservative section-2 budgets after T5; calibrate with D2, never lower silently. |
| B2: builder retention | Keep source/packages/receipts on builder and reclaim only duplicates; or offload verified complete labels and reclaim full completed directories. Operators either wait for more space or retrieve older results from storage. | Full-folder removal can lose uncollected inputs/symbols or unresolved failures. | Start with duplicates only; add full-folder eligibility only after B3 retrieval/backup proof. |
| B3: artifact storage/retention | Approved existing independent volume with second copy; new remote object store; or retain all current local copies. Reviewers gain stable citations, remote authentication overhead, or continued disk pressure respectively. | New service cost/data access; local single-copy loss; premature expiry. | Existing approved volume plus verified second copy, proposed retention above; no old evidence deletion. |
| B4: candidate/CI transport and infrastructure | Candidate with supported SSH; candidate with validated HTTPS WinRM; or existing manual SSH only. Operators gain automated configuration or keep manual setup. New VM/IP/storage/runner permissions must be named separately. | Unsupported OpenSSH, installer/session differences, duplicate IP, host-wide access expansion. | Inventory first; supported SSH if proved, otherwise candidate WinRM; never modify qualified transport to adopt Ansible. |
| B5: baseline promotion | Keep current qualified image; promote accepted same-build candidate; or adopt a newer Windows build through its own qualification. Users see unchanged evidence continuity, reproducible setup with rerun cost, or a changed support platform. | Lost baseline provenance or carrying old passes to a changed image/platform. | Keep current baseline through M2; evaluate same-build candidate later with explicit promotion and affected gates. |
| B6: CI trust/signing | Manual trusted checkpoints; trusted-commit CI on key-free candidates; or persistent lab execution of PR code. Developers get slower manual feedback, safe automation, or apparent speed with lab compromise risk. | SYSTEM/key access makes the last option unacceptable for this design. | Manual now; trusted-commit CI after key-free isolation and runner approval; untrusted PRs stay off the lab. |

Finite native controls below are proposals; **none ran**, and target controls remain subject to the runtime stop and separate approval.
Offline fakes can exercise refusal ordering first; builder observations remain mechanism evidence rather than 19045.2965 qualification.

| Control | Bounded experiment and settling observation |
|---|---|
| D1: inventory/doctor | One read-only builder inventory and host domain inspection; report full OS/VS/WDK/SDK/.NET/sshd identity, known-host matching, free bytes and privilege failures. Determine supported Ansible SSH provenance and unknown config fields. |
| D2: capacity | One permitted agent matrix and kernel gate, plus one separately authorized dump/restoration control; stage-boundary free-space samples determine each peak and shared-filesystem growth. No repeated fill-the-disk trial. |
| D3: fast feedback | Three representative edits in one profile; compare selected discoveries/outcomes to a fresh full checkpoint and measure queue/build/test/collection durations. Empty/omitted selection must refuse. |
| D4: ownership | Candidate builder two-client contention; wrapper/controller termination; candidate wall-clock step. Confirm abandoned job refusal, actual descendant/task cleanup, serialization and monotonic deadlines. |
| D5: Ansible | Candidate transport queries, one installer failure/reboot/disconnect, then check/apply/apply/check with deliberate drift. Settle support, privilege, idempotence and installer restrictions. |
| D6: Packer | Two pinned candidate constructions, changed-input rejection, baseline acceptance and separately authorized restoration. Settle reproducible inventory, firmware/NVRAM reset reliability and promotion readiness. |
| D7: CI/storage | One trusted CI checkpoint plus simulated malicious PR/config, interrupted artifact transfer and pass/failure retrieval. Settle credential isolation, queue sharing and retention integrity. |

Costs/savings below are planning estimates of engineer effort, not measured delivery dates or promises of shorter product rows.
Each phase may stop independently; no Ansible/Packer/CI work becomes a prerequisite for the current T5 product integration.

| Phase | Authorized timing / deliverable | Cost and expected saving | Exit/owner boundary |
|---|---|---|---|
| 0 | Now: this design, source audit and offline acceptance specifications only. | 1–2 engineer-days; exposes duplicated routing/capacity assumptions. | Sol 6.1 xhigh review; no implementation, remote run or host change in this task. |
| 1 | After T5 checkpoint: config, doctor, in-runner capacity checks and plan-only reclaim; retain old checks. | 2–4 days plus D1; prevents wrong-target/low-space delivery and manual repeated preflights. | B1; offline controls and PowerShell 5.1 parse/native signatures; approved real harness check. |
| 2 | Focused/incremental feedback, user-state queue, duplicate-only reclaim and verified local retention. | 3–5 days plus D2–D4; fewer full ~15-minute matrices during edits and no conflicting builder/target use. | B2/B3 where needed; failure/abandonment controls; no SYSTEM/key exposure added for PRs. |
| 3 | Pinned Ansible builder/candidate role and drift report. | 3–5 days plus payload disk/network cost; repeatable setup and visible drift. | B4, approved candidate/IP/storage; D5 before any builder cutover. |
| 4 | Packer candidates, key-free trusted CI and retained artifact retrieval. | 4–8 days plus image space/build hours; reproducible replacement and unattended component feedback. | B3/B4/B6; D6/D7; promotion B5 separately; T4 stop persists. |
| 5 | Evaluate promotion/fleet only when evidence and actual demand justify it. | New qualification rows and infrastructure cost; possible extra isolated capacity. | Explicit baseline/new VM/IP/host approvals; Terraform still absent without a new decision. |

Concrete first implementation checkpoint after T5: centralize existing identity/target values, add read-only doctor and pre-upload
byte budgets, then a plan-only duplicate report. These need no host-wide configuration, baseline promotion or new VM.
Keep component/result/restoration status separate and preserve the already-fixed batch verdict helper.
Next add the queue and one explicit focused-test path; measure the saved feedback time before introducing image/CI infrastructure.
Design review acceptance is not component acceptance, and neither is qualification of a protected driver/agent pair.

## Documentation supporting platform claims

- [W1: Win32_ComputerSystemProduct UUID](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystemproduct).
- [W2: Confirm-SecureBootUEFI results and privileges](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi).
- [W3: TESTSIGNING and Secure Boot](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option).
- [W4: Driver Verifier queries/testing](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier).
- [W5: Win32_LogicalDisk byte-valued free space](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk).
- [W6: GetDiskFreeSpaceEx caller quota and 64-bit values](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexa).
- [W7: .NET test filter option](https://learn.microsoft.com/en-us/dotnet/core/testing/selective-unit-tests).
- [W8: Named mutex ownership](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw) and [abandoned waits](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject).
- [W9: Job Object inheritance, breakaway and accounting](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
- [W10: QPC elapsed time and independence from external clock changes](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps).
- [W11: Fast Startup versus full boot](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation).
- [W12: WDK/SDK version matching and installation](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).
- [W13: VS offline installation/layout verification](https://learn.microsoft.com/en-us/visualstudio/install/create-an-offline-installation-of-visual-studio).
- [W14: Exact .NET SDK selection](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json).
- [W15: NuGet dependency locking](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies).
- [A1: Ansible Windows SSH support, minimum version and shell](https://docs.ansible.com/projects/ansible/latest/os_guide/windows_ssh.html).
- [A2: Ansible WinRM transport, HTTPS and installer limitations](https://docs.ansible.com/projects/ansible/latest/os_guide/windows_winrm.html).
- [A3: Ansible check/diff simulation and unsupported modules](https://docs.ansible.com/projects/ansible-core/stable-2.21/playbook_guide/playbooks_checkmode.html).
- [H1: Packer QEMU builder inputs/checksums](https://developer.hashicorp.com/packer/integrations/hashicorp/qemu/latest/components/builder/qemu).
- [H2: Terraform resource/state ownership](https://developer.hashicorp.com/terraform/language/state).
- [C1: GitHub self-hosted runner trust and hardening](https://docs.github.com/en/actions/reference/security/secure-use#hardening-for-self-hosted-runners).
- [C2: GitHub concurrency controls](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).
