# Post-MVP work log

Unattended work on `feat/driver-post-mvp` (plan: [POST-MVP-PLAN.md](POST-MVP-PLAN.md)). Newest entries at the bottom. Each entry says what
was done, the evidence, and every decision taken without asking, with the reason, so it can be reviewed or reversed in the morning.

Standing rules for unattended runs (owner, 2026-10-08 night): never stop to ask. On a failure or an open decision take the conservative
option, record it here, and continue with the next item. Never force-push, never push `main`, never override an owner decision, never
weaken a gate or an assertion.

## 2026-10-08 evening to night

### T0: field diagnostics and installer fixes

Done and verified so far:
- Driver deny ring + counters (`DenyRing.c`, control commands 27 and 28): exact-source build `t0-denyring4` (commit `1877d3ec`): all four
  configurations 0 warnings / 0 errors, PREfast and ApiValidator pass, feature driver signed. Two PREfast errors found and fixed on the
  way: `DriverStart` is off limits (C28175), and the port-message routine is at the stack-use limit (C6262), so new commands build their
  replies in the pool scratch buffer.
- Agent: administrator-only diagnostics pipe `SafeUpload.Agent.Diagnostics` and `Get-SafeUploadDiagnostics.ps1`; installer registers staged
  mode and accepts Windows 10's SID-type output.
- Exact agent gate `t0-agent5` (commit `2f151e0f`): 512 of 512 tests pass, publish clean.
- Harness Windows PowerShell 5.1 gate passes (`harness-windows-gate-t0-harness4`).

Decisions taken without asking:
1. **NETWORK deny entry removed from the diagnostics pipe.** My first DACL denied the NETWORK group; an SSH or scheduled-task logon of an
   administrator carries that group, so it rejected the harness and a unit test. The pipe still grants only SYSTEM and Administrators.
2. **The agent unit-test gate now runs each test group in the account it needs** (`Build-ExactAgent.ps1`). The 21 CA/TLS tests from `main`
   fail on the builder only because its SSH logon (S4U) has no DPAPI user secret, so current-user CNG key creation is denied; as SYSTEM they
   pass. The hand-back tests must run unprivileged (the product refuses to hand back to SYSTEM). So: build with warnings as errors in the SSH
   session, run the CA/TLS classes as SYSTEM through a one-shot scheduled task, run everything else as the normal user, and merge the two trx
   files with summed counters into the single `agent-tests.trx` the pair qualification reads. Every test runs exactly once; the strict
   qualification rules (`total == passed == executed`, nothing skipped, no warnings) are unchanged. This is an environment fix, not a weakening.
3. **`SAFEUPLOAD_MACHINE_TESTS=1` is set for the SYSTEM run on the builder only.** The machine-CA test adds and removes a uniquely named test
   CA in the machine root store; it is documented for the disposable test VM, and the pair qualification rejects a skipped test. Reversible:
   remove the `-Environment` argument in `Build-ExactAgent.ps1`.
4. **C05 proves the denial through the deny ring.** `C05DenialLedger` was INCONCLUSIVE ("exact denial ledger unavailable"). It is now PASS
   when the ring holds the denied rename for the actor process with the target name, FAIL when the ring is readable but lacks it, and stays
   INCONCLUSIVE when the pipe is unreachable (older agent). This strengthens the row.
5. **Local commits are squashed before pushing.** Several fix-up commits exist locally; they are regrouped into logical commits at push time.

### Finding: the agent after the merge of `main` no longer uses `policy.json` by default

First debuggee run of the T0 pair (`t0rv1`, C05) ended INCONCLUSIVE: the guest never reached Ready (coverage Degraded, reason 15
VolumeIdentityUnknown, 3 scopes instead of 1). Cause, from the retained agent events: `appsettings.json` (brought in by `main`) ships
`CentroAdministracao:BaseUrl = http://127.0.0.1:8080/agent/`; with any address configured `Program.cs` registers `HttpPolicyStore`, which
cannot reach the panel and falls back to the built-in default policy (folder `C:\SafeUpload\Escopo Monitorado`, removable and network scopes
on). The network scope has no supported volume, so coverage stays Degraded. This is independent of T0: the frozen pair predates `main`'s policy
store. It would also hit anyone following the manual install in MVP-PLAN with the merged agent.

Decision 6 (taken without asking): pin the local policy file explicitly where the MVP flow needs it, and leave the central-policy design alone.
`StagedTestAgent.ps1`, `Test-StagedW01Parent.ps1` and `Test-StagedInvariantSuite.ps1` pass an empty `--CentroAdministracao:BaseUrl=` when they
register the agent; `Install-SafeUploadAgent.ps1` gets `-AdminBaseUrl` (default empty = autonomous, reads `policy.json`). The policy format
the panel should send (the open question from the earlier session's handoff) is not touched.

Process note: a batch started with the broken harness was stopped by PID and the debuggee rolled back with `rollback-vm.sh win10-debug2 t0rv2`
(baseline verified clean afterwards). The qualification runner requires the worktree's driver and agent sources to equal the builds under test, so
the T0 pair runs from a worktree at `2f151e0f` with only `driver/scripts` overlaid from the fixed harness commit.

### T1: event-driven reclaim worker (in progress)

`StageRegistryReclaimWorker` now requeues itself only when bounded work remains: a full batch, an exhausted scan budget, or an entry that reports
`MoreWork` (a link scan or marker scan that ran out of budget). A scan or alias probe that is merely waiting on an outside event stays pending
(and so gated: Activating, never Ready) and the pass parks; every event that can end such a wait already queues a reclaim pass (handle
cleanup/close, section release, rename completion, policy and boot-policy changes, registry pressure), so no timer is involved. Counters
`parkedPasses` and `moreWorkRequeues` are exposed through the diagnostics pipe, and every cached suite trial now ends with a
`ReclaimWorkerIdleRate` assertion (limit 10 passes per second over 15 s, PASS/FAIL, INCONCLUSIVE if the pipe is missing).
Open risk to watch in the gate: an entry whose wait has no event would now stay Activating instead of being retried; A01-A04, R02, X01, C03 and
C04 are the rows that would show it.

Pending: debuggee run `t0rx` (C05, C01-approve-absent, S01, C01-block-absent, runtime-verifier, win10-debug2); T1 builds `t1-reclaim1` and
`t1-agent1` are being produced on the builder.

### Harness pair must be the feature flavour (finding, 01:50)

Second C05 attempt after pinning the policy file: still `ready-timeout`, now with `Admission coverage Degraded: UnknownReceiptFlags`. The
harness runs the feature driver (test taint control compiled in), whose receipt carries `TestTaintControlFlag`; only the agent built with
`SAFEUPLOAD_ADMISSION_EVIDENCE` sets the matching `TestDisableTaint` policy flag, so the plain agent I had built could never reach Ready with
it. The gate pair is always feature driver + feature agent (`SAFEUPLOAD_ADMISSION_EVIDENCE_BUILD=true Invoke-ExactAgentBuild.sh`). The feature
agent gates are green (`t0-agent6`, `t1-agent3`). Reminder for T12: the release build must not need a test-only flag to reach Ready.
S01 on the T0 driver already passed the MVP gate with a clean restoration (`t0rx3`).

### T2: new-profile denial named (diagnosis experiment `t2diag3`, T0 driver, 01:52)

`Invoke-NewProfileDiagnosis.sh` (checkpoint, install pair through the installer, reboot, `userenv!CreateProfile` for a new user, read the ring,
roll back) reproduces `CreateProfile = 0x80070005` and the deny ring names the refusals: **about 235 `STATUS_ACCESS_DENIED` refusals within
one second, all `CREATE` of directories and files under `\Users\t2probe\...`** (open-for-write-attributes of directories, `FILE_CREATE` of
directories and files) by the Profile Service's process, plus two kernel-mode `SET_INFORMATION` (FileBasicInformation) refusals just before
it. None is inside a protected scope (the scope is `C:\Protected`). `volumeWideFallback` shows 2266 of 2295 calls answered "the whole volume
may be in scope" by boot time, which confirms the suspected mechanism: `StageAdmitDirectoryMutation` (and `StagePhysicalMutationEx` for the
`SET_INFORMATION` case) ask for the normalized name; when that lookup fails they fall back to
`SafeUploadPolicyMayMatchInstanceVolume` and refuse, so every unresolved mutation on a volume that hosts any scope is denied. Windows creates a
profile tree deepest-first and creates parents on `PATH_NOT_FOUND`, so an ACCESS_DENIED instead aborts the whole recursion. The deny record now
carries the status of the failed lookup (`AuxStatus`) to confirm which failure it is before the fix.

### T2 fix part 1 verified, part 2 named (01:56-03:00)

Fix 1 (`7331f2a0`): a normalized-name lookup that fails with PATH_NOT_FOUND, NAME_NOT_FOUND, NO_SUCH_FILE or NOT_A_DIRECTORY no longer refuses a
create (`StageNameLookupProvesAbsent`, used by `StageAdmit` and `StageAdmitDirectoryMutation`). Verified on a guest with the driver loaded and the
agent Ready (`t2diag7`/`t2diag8`): `CreateProfile` for a brand-new user returns 0, zero refusals recorded during it. Every other unresolved lookup still
fails closed and is recorded in the ring with its status.

First sign-in through a scheduled task as a new user still did not run (`USER_TASK_RESULT` = task not run). The ring, now carrying a reason code and the
resolved name (`eb358ec2`), names the remaining refusals exactly: 24 kernel-mode `SET_INFORMATION` (FileBasicInformation) refusals, reason `policyScope`,
name `\Device\HarddiskVolume3\`, the volume root, which is an ancestor of the protected scope `C:\Protected`. `StagePhysicalMutationEx` was called with
`IncludeAncestors = TRUE` for every non-rename SET_INFORMATION; the Profile Service sets basic information on `C:\` while it builds a profile.
Fix 2 (`8c9adc21`): the ancestor rule applies only to a delete (FileDispositionInformation/Ex); attribute, time and size changes of an ancestor leave the
scope's bytes alone. Renames and links of an ancestor are still checked by `StageExternalRename`. Security reasoning: the rule exists so a protected folder
cannot be removed from under the driver; none of the relaxed classes can move or remove a directory or change protected bytes.

### T1 verified on C05 (02:55)

With the first T1 build the idle reclaim rate was still 3,111 passes/s (`parked=0`, `moreWorkRequeues=8`): the worker was not requeueing itself, it was
woken by every `IRP_MJ_CLOSE` and every successful `IRP_MJ_CLEANUP` on the machine. `51c4c96e` makes those wake-ups targeted (interest flag set at the
source when an entry enters a waiting state, recomputed each pass; O(1) lookup through the section-pointer map for the closing stream; skipped
wake-ups counted). C05 on the pair `t1-wake1`/`t1-agent4` (ordinary): idle rate 8.1 passes/s (limit 10), `C05DenialLedger` PASS, verdict INCONCLUSIVE with
latency-only blockers (tier-1 pass). Rows A01-A04, R02, X01, C03, C04, C01 (approve and block) run next.

### T2 verified end to end by a real first sign-in (03:35, experiment `t2diag13`, driver `t2-anc1` = `8c9adc21`)

The experiment now does a real interactive first sign-in (batch-logon tasks load no profile, which is why no suite row ever caught this; the harness
pre-creates the actor profile): after the install the guest reboots with the driver loaded and the agent Ready, a brand-new account `t2user` has
autologon and a logon-triggered task. Result: the account signs in (console session active, explorer running, profile `C:\Users\t2user` created,
Profile Service events only 1531/1532 and one non-fatal 1534 component notification) and the scope behaves as designed for a standard user:
`mkdir C:\Protected\dirA` and a deep `mkdir` in the protected folder are refused (reason `policyScope`), a clean save into it is staged and published
(`ok.txt`, 7 bytes), a deep tree and a file under the profile work. Before the fixes the same account could not sign in at all.

The ring since boot still held refusals outside every scope that did not block sign-in; named by the ring:
- 66x `aliasCheckFailed` / `STATUS_IO_REPARSE_TAG_NOT_HANDLED` on `WindowsApps\...`: Store app-execution aliases are reparse files and the alias
  probe followed the reparse. Fixed in `68ad4ee4` (probe opens with FILE_OPEN_REPARSE_POINT; it needs identity and link count; a create through a
  symbolic link re-enters the filter under the target's name).
- 2x `aliasCheckFailed` / `STATUS_SHARING_VIOLATION` on `pagefile.sys` (kernel-mode, at boot): fixed in `68ad4ee4` by excluding `pagefile.sys`,
  `swapfile.sys`, `hiberfil.sys` at the volume root by name (exact; they cannot be hard links of a protected file).
- 5x `activatingName` on out-of-scope files (`NTUSER.DAT`, SPP store, Libraries): a transient property of the pre-scope-writer rule (a name whose alias
  probe is still pending refuses a second writer). Not redesigned here; carried to T3 because heavy concurrent writers (installers) are the workload
  that would hit it, and it is the leading suspect for the Microsoft 365 install failure.
- 2x refusals of `\;LanmanRedirector` creates and 1 `QUERY_INFORMATION` without a reason: not yet named.

### T1: R02 concern (03:36)

On the event-driven build R02 (ordinary) did not pass: the final Free/Protected proof saw the promotion on the replaced-incarnation basis instead of the
held one (`predicateFlags` 0x2F, bit 0x20 set), i.e. the reclaim pass that promotes Y ran after the file system had torn the stream down. A01-A04 pass.
Hypothesis: the machine-wide wake storm used to make a pass start almost immediately after the holder's cleanup; the targeted worker still queues a
pass at the last writer's cleanup (unconditional, `SafeUploadStageWritersOnCleanup`) but a delayed-work-queue pass can start later. Not assumed:
R02 is being repeated twice on the T1 pair (`t1r`) and will be compared with the T0 pair before anything is changed.

### T1 slice judged by the gate's tier-1 rule (04:05)

Pair: driver `t1-wake1` + feature agent `t1-agent4`, both from `51c4c96e`; `cellok.py` (the gate's own judge) per row:
- ok: A01, A02, A03, A04, C04-approve, C01-block-absent (and C05, C01-approve-absent earlier).
- X01 and C03-approve-existing: `retry`. Both fail in the observer's raw MFT reader (`Still-truncated MFT map after one refresh; requested
  record=231296; mappedEnd=236716032`: a file record beyond the on-disk extent of $MFT, because NTFS has not yet written the grown run list). X01
  fails the same way on the T0 pair (`t0s2`), so this is the known raw-capture flakiness (the pool retries these cells), not a T1 effect.
- R02: fails deterministically on the T1 pair (3 of 3: `t1q7`, `t1r1`, `t1r2`) and passes on the T0 pair (`t0s1`, no blockers). The difference is the
  promotion basis: T0's receipt has predicateFlags 31 (held incarnation, cache flush/purge needed); T1's has 47 = 0x2F (bit 0x20: incarnation replaced,
  the old stream was gone before the pass reached it). The harness is right to refuse the replaced basis for R02 ("a replacement-basis CAS cannot
  substitute without independent incarnation continuity proof") and I will not relax it. The old unbounded requeue made a pass land while the stream was
  still alive; the event-driven worker must start its pass at the right moment instead. Measuring where the time goes with scratch diagnostic notes in
  the deny ring (branch `diag/reclaim-trace`, never merged).

### R02 root cause and the identity anchor (04:25)

Scratch notes in the deny ring (branch `diag/reclaim-trace`, driver `t1-diag3`, never merged) show the sequence around the holder's release:
cleanup (last writer, entry Activating) -> passes that find the cache retained (the cache manager keeps the holder's file object as its cache file
object) -> ~190 ms later the cache manager's own close reaches the filter (pre-close, pid 4) -> a pass flushes and purges, the shared cache map is
gone, and the entry promotes. That pass can only promote on the held incarnation if it opens the stream by ID before NTFS has processed the close; with
the notes compiled in it starts ~10 microseconds after the wake-up and R02 passes (`t1e1`, MvpGatePassed true); without them it starts later, the
stream is already torn down and the promotion is on the replaced basis (`predicateFlags` 0x2F), 3 of 3. So this is a race, not a logic error, and the
old worker hid it because it requeued itself without pause: one of its passes always held the stream open.

Decision (conservative, the harness stays as it is): make the held incarnation deterministic. The reclaim pass keeps the by-ID identity handle it
already opens as the entry's anchor while the entry is Activating with a live writer (`StageAnchor*` in StageWriters.c): at most 32, closed when the
entry resolves or retires, at the start of every pass for entries that are gone, and at instance teardown. I did not relax the R02 assertion and did
not add a poll to the worker. Commit `34febe77`.

### Follow-up found by the first sign-in (T2b, not done)

After the alias fixes the ring of a real first sign-in holds 11 records (`t2diag14`): 2 expected `policyScope` refusals of the standard user's
directory creates in the protected folder, and 9 that are outside every scope and still refused:
- 5x `activatingName` (FontCache `~FontCache-S-1-5-18.dat`, `Windows\System32\spp\store\2.0\data.dat.bak`, the four `Libraries\*.library-ms`): a
  writer open of a name whose registry entry is Activating (or has an alias probe pending) is refused until the entry resolves, even when the file
  has no scoped name at all. Design to try: before refusing, run the create's own alias check; if the file provably has no name inside any current or
  pending scope, allow it (the refusal exists for names that may be in scope). This is the leading suspect for installer failures, so it belongs at the
  start of T3.
- 2x `STATUS_ACCESS_DENIED` CREATE of `\;LanmanRedirector` with no reason (a deny site without detail: find it).
- 1x `QUERY_INFORMATION` completed by the driver with `STATUS_NOT_SUPPORTED`, kernel mode, no name.

### Verification of the anchor and the T2b gates (04:30-05:00)

Driver `t1-anchor3` (`78214468`: T1 worker + identity anchor + T2 fixes) with agent `t2-agent3`:
- R02: 2 of 2 pass on the held basis (`predicateFlags` 15), tier-1 ok (`m1r2`, `m1r3`). The first attempt (`m1r1`) was a harness pre-run failure, not a
  verdict: the VM had been switched between three agent packages and the pre-run threw `Preserved package collision`; fixed in `09af473b` (identical content
  is already preserved; different content still throws).
- A02, A03, X01 (retry of the raw-capture flake), C03-approve-existing and C04-approve: tier-1 ok.
- A01 and A04: tier-1 `retry` for `LiveTaintFlags`, whose cause in the export is `Before: null` with `Child process exit code absent` (the harness
  could not read the Inspector's exit code for the first coverage receipt of the case). It happened under load (two guests and a build running) and is an evidence
  capture failure, not a product assertion; to be repeated on a quiet host before it counts either way.
- First sign-in (row U01) on `t1-anchor3`: all required lines pass except `U01NoRefusalOutsideScope`; the ring held 5 records (down from 76 before the T2
  fixes, 11 after the alias fixes): two `\;LanmanRedirector` creates and the three expected in-scope records. The `activatingName` refusals are gone with
  the T2b gate change (`23ee822b`).
- The remaining two were named by `t2-gate1` (`a48a0d98`, legacy create gate detail): reason `legacyCreateGate`, volume kind 3 (Network), volume `\Device\Mup`.
  Cause: `SafeUploadPolicyMayMatchVolume` counted a network volume as possibly in scope for any policy with a path prefix, even when all prefixes are local
  paths; before the agent connects (early boot) the legacy create gate refuses such a create. Fixed in `6b83f608`: a network volume matches through the
  NETWORK flag or a prefix that is itself a network path (UNC, MUP, the redirectors, DFS); an unclassified volume still fails closed.
- Also seen: `STATUS_NOT_SUPPORTED` for `FileStandardLinkInformation` (class 0x36) on a staged stream (the staged view answers only Basic, Standard,
  NetworkOpen, AttributeTag and Id). Recorded for the application-compatibility work (T5/T8), where the ring will list every class real programs ask for.

### M1 candidate pair, Luna reviews, and open items (06:50)

Two independent reviews of the driver changes (`driver/POST-MVP-REVIEW-M1.md`; the second, a delta review of `8e506437..a53e42ee`, is recorded in the commit message of
`ea925022`). The first found F1-F4 (fixed in `d0c53ecb`); the second found two real defects in my follow-up changes, both fixed in `ea925022`: a PASSIVE-only string
routine called under the cache spin lock (a Verifier bugcheck waiting to happen: the network-prefix test is now a resident comparison whose result is computed into the
cache when it is built) and a stale registry entry that could read as "known outside" (the entry is now validated under the registry lock). Both reviewers found no bypass
in the Activating-name gate refinement, the alias probe change or the worker.

Verification of the pair so far (all judged with the gate's own rule, `cellok.py`):
- Runtime Verifier on `8e506437`: S01, C05, C01-approve-absent (after one raw-capture retry), C01-block-absent, R02 and A01 pass. Boot Verifier: B02 passes (it used to hang
  the guest); C01-block-absent failed when it overlapped a runtime-Verifier run and a build (BLOCK cells need a quiet host, see the lessons) and is re-run alone.
- Ordinary on the anchor driver: A01-A05, B01, R01, R02 (4 of 4 quiet runs; one run under load failed with X Unknown/IDENTITY), R03, X01, C03, C04.
- T3: MSI (PowerShell 7) with the driver: ok, 9.1 s against 8.2 s without it, no refusal, registry high-water 224 of 4,096.
- U01 (first sign-in): PASS on `m1-driver2`; one sporadic early-boot refusal of a writable section whose name could not be queried (fixed in `a53e42ee` by deciding it from the
  stream's registry entry; reviewed in the delta review).

Open item: under load (two guests, a build and a review running) one R02 run ended with X `Unknown` for `UNKNOWN_IDENTITY` before the policy apply: a transient failure of the
by-ID identity open marks the entry Unknown for good (fail-closed, but sticky until reboot). The four quiet runs did not show it. To investigate with the deny ring's sibling
(`classificationStatus` of the entry) if it recurs; candidate fix: retry the identity open a bounded number of times before marking Unknown.

### Incident: I deleted live backing overlays of win10-debug3 (07:15-07:45) - recovery needs the owner

To make room on the host disk (13 GB free, btrfs) I deleted what my script computed as "unreferenced" overlays of the two clone VMs through libvirt (`vol-delete`, 115
volumes, about 74 GB by libvirt's allocation figure). The computation walked each domain's disk chain with `vol-dumpxml`, but the `default` pool's volume cache was stale
(an overlay created by the harness after the last `pool-refresh` is unknown to `vol-dumpxml`), so the walk of win10-debug3, which was in the middle of a batch, stopped at its
newest overlay and everything below it was classed as orphaned and deleted. The deletion also freed far less space than reported (7 GB), so it did not even achieve its aim.

Consequences:
- win10-debug2 is intact (its chain, 90 overlays on `safeupload-debug2-pre-shrink-20261008.qcow2`, was walked correctly) and keeps working.
- win10-debug3 is shut off and cannot start: its top overlays `...m1b1`, `...m1b2`, `...m1b3` survive but their backing `...R02-ordinary-m1z2-20261009` and every older
  `win10-debug3.*` overlay are gone. The harness rollback (`rollback-vm.sh`) fails with "Could not open backing file". Nothing of value was lost: every run restores the
  baseline and rolls back, so the content of those overlays is run-by-run noise; the evidence lives in the run worktrees and `driver/evidence`.
- The base images are safe on the second disk: `/mnt/storage/libvirt/images/safeupload-debug{1,2,3}-pre-shrink-20261008.qcow2` (the libvirt pool `cold-storage`,
  started during the recovery attempt; it points there and was inactive).
- The boot-Verifier C03-block-existing run that was in flight on debug3 (`m1b3`) ended in a guest `System.OutOfMemoryException` in `ConvertTo-Json` and a failed restoration;
  that failure is separate from the deletion (it happened first) and is reported below.

Recovery plan (not executed: the auto-mode classifier denied the VM redefinition, and I did not work around it): create a new qcow2 overlay of 128849018880 bytes on
`safeupload-debug3-pre-shrink-20261008.qcow2` (`vol-create-as default <name> 128849018880b --format qcow2 --backing-vol safeupload-debug3-pre-shrink-20261008.qcow2
--backing-vol-pool cold-storage --backing-vol-format qcow2`), repoint the domain's `vda` source to it exactly as `rollback-vm.sh` does (remove the `<backingStore>` element),
define and start, then `Get-StagedBaseline.ps1` must report `BaselineClean=True`. The pre-shrink base is the root of both clones' chains, so it is a clean baseline.

Remaining work continues on win10-debug2 alone, serially (which is also what the BLOCK cells need).

### Boot-Verifier BLOCK cells on the final pair (08:35)

Final pair: driver `m1-driver4` (ea925022) + agent `m1-agent6` (91e957cc). Judged with the gate's rule (`cellok.py`, tier 1 for boot-Verifier):
- C01-block-absent `m1b1` ok (debug3, quiet host); C03-block-existing `m1d1` ok; C04-block `m1d2` ok; C02-block-absent `m1d3` ok (debug2, serial, nothing else running).
- B02 ok on `8e506437` (`m1w1`); re-run on the final pair is in the queue.
- Failures on the way, none a driver fault: C01-block-absent on 8e506437 (`m1w2`) overlapped runtime-Verifier runs and a build; C02 `m1b2` raw MFT capture error (retried
  ok); C03 `m1b3` guest `System.OutOfMemoryException` in `ConvertTo-Json` (the 4 GB guest under the boot Verifier), fixed in the harness by always writing the compact JSON
  (`6b64ae42`; the content is unchanged), after which `m1d1` passed.
So the five cells that never completed (B02, C01-C04 BLOCK) now all complete under the boot Verifier: the 64/69 gate becomes 69/69 (the 64 were closed on the earlier pair; the
final pair carries the confirmation slices listed above and in the queue).

### U01 under the boot Verifier: one transient section refusal outside every scope (09:40) - open (T2c)

Final pair, `u01h` (boot Verifier on, whole run): CreateProfile, the real first sign-in, the profile tree, the in-scope refusals and the clean in-scope save all pass, the driver is
listed as verified for the whole run, and the ring holds four records: the two expected in-scope `policyScope` creates, the staged-stream `FileStandardLinkInformation` query, and one
`STATUS_ACCESS_DENIED` for `ACQUIRE_FOR_SECTION_SYNCHRONIZATION` of the writable section of `LocalService\AppData\Local\FontCache\~FontCache-FontSet-S-1-5-18.dat`. So
`U01NoRefusalOutsideScope` FAILS in this mode (it passes in ordinary mode on the same driver: `u01f`).

Cause (reasoned from the code, not yet reproduced with a name for the entry's state): the FontCache service opened that file for write before the agent connected and the policy was
applied, so its registry entry is a pre-scope writer: after the apply it is Activating with its alias probe pending until the single reclaim worker classifies it (hard-link names
decide whether the stream is reachable from a scope). The writable-section gate asks the entry (`SopMatchesPolicy`: alias-pending or unresolved means "matches", fail closed), so a mapping
created inside that window is refused. The window is short on an idle guest and longer under the boot Verifier (a backlog of such entries after the apply). It is the same class as the
`activatingName` create refusals fixed in T2; the create gate could be refined because it has an exact alias check at hand (`SafeUploadStageCheckNamedAliases`), the section gate cannot
(no file I/O is allowed in the section-synchronization callback: a deadlock risk with the caller's locks).

Options (none done, each needs a design and a review): (a) classify pre-scope entries before the apply is published (a bounded wait in `SafeUploadSetPolicy` for the first backlog),
(b) let the section gate wait a bounded time for the entry's classification, then decide, (c) give entries of files that are provably outside every scope by name a fast path in the
worker (classify outside-by-name entries first, ahead of the ones with a scoped-looking name), (d) accept the window for pre-scope handles and document it. (c) is the smallest.

### T3 first results (10:50)

Runner `Invoke-InstallerWorkload.sh`, final driver `m1-driver4` + agent `m1-agent6`, win10-debug2 (win10-debug3 is down, see the incident):
- **MSI** (PowerShell 7.4.5): driver 9.2 s against control 7.0 s (earlier run: 9.1 s against 8.2 s). Installs, registry high-water 225 of 4,096, no Unknown reason, Ready.
- **Cumulative update** (the 2025-10 CU for 22H2, KB5066791, via the Windows Update Agent API): completes with the driver loaded, 1,017 s (control run killed at the host-disk
  limit, see below). It exposes three defects and the registry limit:
  1. 3 creates of a delete-pending file (`spool\drivers\x64\3\Old\1\FXSAPI.DLL`) refused as `aliasCheckFailed` (the probe's `STATUS_DELETE_PENDING`).
  2. 8 kernel-mode `WRITE`s (pid 1668) issued from inside another file-system call (top-level IRP set) on untracked file objects, refused for lack of a queryable name.
  3. The writer registry reached its per-volume cap of 1,024 entries (977 live at the peak, 3,247 capacity failures); the volume was marked Unknown for
     CAPACITY|ALLOCATION|IDENTITY|CLEANUP, and such a reason stays until the next boot (coverage Degraded). After the reboot that finishes the update, the servicing phase (also
     under the driver) pruned 11,296 entries with 57,464 reclaim passes and ended with 292 entries.
  Fixed in `1989f86a` (not yet verified on a VM): the per-volume cap is the whole registry (4,096); every 64th insertion above 512 live entries wakes the pruner; a
  delete-pending probe lets the file system answer; a nested write is decided by the stream's validated registry entry when it is classified outside every scope. The sticky
  capacity reason itself (T3c: a transient burst must not leave coverage Degraded until reboot) is open: the loss is real for the streams opened while the registry was full, so
  clearing it needs the untracked handles to be accounted for; a design is needed.
- **Defender**: both runs (driver and control) failed identically with `0x80070652` (ERROR_INSTALL_ALREADY_RUNNING right after boot); the workload now retries; re-run queued.
- **Microsoft 365**: not run yet. The host disk had 5.5 GB free (btrfs with snapshots does not give back files that existed at the last snapshot; every run leaves its multi-GB
  overlay behind after the rollback). I deleted the discarded run overlays that my own rollback lines name after checking them against the libvirt chain (frees 16 GB), and the
  runner now refuses to start with less than 12 GB free (30 GB for Microsoft 365). Auto-deleting overlays from the runners was denied by the auto-mode classifier and is not done.
- Boot-time refusals: the runner now evaluates refusals after the ring cursor taken at the workload start; ones before it (the FontCache section window, T2c) are listed separately.

### T3 cumulative update: what the ring named (14:10)

With names in the ring (`2d32bbff`: a nameless refusal now carries the file object's open name or the requestor's image path), the cumulative update with the driver (`m1-driver6`)
shows two separate problems:
1. **smss's servicing-boot deletes were refused by the legacy create gate.** The ring of the servicing boot of `t3cuc` holds 17 `legacyCreateGate` refusals by pid 344 (smss, before the
   agent connects): delete-access creates (access 0x110000) of paths whose name lookup failed. The legacy fail-closed create gate treats a failed lookup as 'this volume may hold a
   scope' and refuses; the new gate already had the T2 rule 'a lookup that proves the path absent touches nothing protected'. Fixed in `c70a4354` (one shared predicate
   `SafeUploadNameLookupProvesAbsent`); verified in `t3cud` (`m1-driver7`): the servicing ring has 0 `legacyCreateGate` refusals (it had 17), only the 8 nested writes of item 2 remain.
   **Correction (17:00):** the first version of this entry, the commit message of `c70a4354` and the comment in `Filter.c` say the refusals "reverted the update". That is wrong: I read the
   two captures of `t3cuc` in the wrong order. The build goes 19045.2965 to 19045.6456 in every CU run (`t3cub`, `t3cuc`, `t3cud`), so the update was never rolled back. The refusals are
   real and the fix is right, but the claim that they broke the update is unsupported. The comment in `Filter.c` is corrected with the next driver change.
2. **TiWorker.exe's kernel-mode MDL writes from inside another file-system call (top-level IRP) are refused** for lack of a queryable name: 23 during the install (pids 3120/4848)
   and 8 in the servicing boot, 2 MB in 256 KB chunks per file. The update survives them in 3 of 4 runs, but the refusals are real (T3d). Options: resolve the name from the name
   cache only (`FltGetFileNameInformationUnsafe` with `FLT_FILE_NAME_QUERY_CACHE_ONLY` is allowed in a nested call) and trust the create-time alias check of a file object that passed
   the create gate; or classify by the stream's registry entry (there is none for these file objects, so they were opened outside this filter's view, which is itself worth explaining).
Registry: with the per-volume cap at 4,096 and the pruner woken every 64th insertion above 512 live entries the update runs without overflow or Unknown reasons (high-water
1,299 / 3,097 / 2,206 of 4,096 in the three runs).

### The T3b driver line (`m1-driver5`, `1989f86a`) on win10-debug2: confirmation campaign (13:00)

Frozen worktree at `1989f86a`, agent `m1-agent6`, judged with `cellok.py` (two-tier gate):
- ordinary mode: R02, A01, A02, A04, R03 all `ok` (`m1k1`..`m1k5`);
- runtime Verifier: A01 and C05-denied-external-rename `ok`; R02 first came back `retry` on `LiveTaintFlags` (the known evidence flake: the guest's child process object returned before
  its exit code was set). The harness now re-reads the exit code of a just-exited child a few times before calling it absent (`b14b2d0a`; no gate or assertion changed), and the rerun
  `m1o1` of R02 under the runtime Verifier is `ok`;
- boot Verifier: B02 and C04-block `ok` (`m1m1`, `m1m2`);
- U01 (first sign-in of a new user, ordinary): every row PASS except `U01StagedStreamQueries`, INCONCLUSIVE: a `FileStandardLinkInformation` (class 0x36) query on a staged stream is
  answered `STATUS_NOT_SUPPORTED` (pid 5172); it is a query, not a write, and nothing is leaked, but the refusal is outside the in-scope write path and stays open.
Not run on this line: the rest of the A/R/C rows, the other three BLOCK cells and B02 for C01-C03. `1989f86a` changes the registry limit, the delete-pending probe, the nested-write
rule and the pruner wake-up, so the full regression of the 69-row gate on the final driver is still owed; the rows above are a sample, not the gate.


### Host disk and disposable run disks (2026-10-09 afternoon)

The main disk filled because of the project, not because of the owner's files: about 239 GB of memory dumps from the Oct 1-7 hang and bugcheck investigations sat in
`/var/tmp` (each 8 GB capture kept up to three times: libvirt's ELF, a readable copy, the WinDbg conversion), every suite case and T3/U01 run left its multi-GB checkpoint
overlay stacked on the debuggee's disk (chains reached 126 files), and a snapper snapshot of the root subvolume (#39, taken by an update at 11:16) pins whatever existed at that
moment, so deleting those files gives nothing back until the snapshot goes. The dumps are deleted (the owner's `sudo rm`); win10-debug2 was merged into one file
(`blockcopy --pivot`, now `/mnt/storage/libvirt/images/win10-debug2.flat-20261009.qcow2`) and its 128 old chain files deleted after a chain check of every domain.
The owner now allows the main disk when it is faster (it is NVMe; the Storage disk is a spinning HDD), on the condition that nothing piles up again.

Harness change `f8be9da9`: a debuggee idles shut off on a base disk that no run writes. `run_disk_begin` (`driver/scripts/run-disk.sh`) creates a fresh overlay of the base,
points the domain at it and starts the guest; `run_disk_end` powers the guest off, points the domain back at the base and deletes every run file above it (the run overlay and the
wrapper's live checkpoint; anything else, anything deeper than two, or anything another domain names stops it with the files kept), and checks the base's mtime and size are
unchanged (`RunDiskBaseUntouched=True`). The suite batch, the T3 runner and the U01 runner use it; rollback and recovery overlays are gone, and every run now starts from the same
disk (it used to start from the previous run's restored state). Tested on win10-debug2 (`rdtest1`): boot 110 s, `BaselineClean=True`, overlay deleted, base untouched.
Still open: 8 project overlays that win10-debug's chain does not use (about 27 GB, created before snapshot #39) - deleting them was refused by the session's permission check, so
they wait for the owner; win10-debug's own 75-file chain is left as it is (not used by the harness now).

### T3d: why the cumulative update's nested writes were refused, and the fix (`4d02039a`, verification pending)

The driver8 ring (`2d32bbff` names a nameless refusal's file object, `704146b8` adds why its stream was not known outside) read live during
`t3cue`: the refused nested WRITEs (pid 6000, TiWorker) are on `\Windows\servicing\Sessions\<id>.xml`, with aux `0xE5000007` = the stream HAS a
registry entry, state Unscoped, but class 0 (UNRESOLVED). The earlier runs' records (`t3cud`) only had TiWorker's image as the name: the file
objects carry no open name and the name cache did not know them.

Cause: the nested-write rule from `1989f86a` trusts an entry only when its class is OUTSIDE, and only a finished alias probe ever set OUTSIDE.
An ordinary writer of a name outside every scope gets an entry that starts Unscoped/UNRESOLVED and is never probed (probes begin on renames,
links, directory renames and policy applies), so its class stayed UNRESOLVED for the entry's whole life and the rule never applied.

Fix: the create gate already proves what a probe proves for such an open: `SafeUploadStageCheckNamedAliases` enumerates the file's hard
links and refuses the open when one is in a current or pending scope. The check now records the file it examined (`FileIdInformation`, or that
no file had the name), `StageAdmit` records the policy scope sequence read before the check, and the writer reservation carries both to
post-create, where `StageRegistryApplyCreateAliasProof` classifies the entry OUTSIDE when the same file is bound (or this open created it)
under the same scope sequence and a stable rename-loss generation, for an untouched plain entry only, with the probe receipt's lock order.
Only a non-transacted open of the default stream by name gets a proof. Why it holds: while the scope sequence holds, `StageExternalRename`
refuses every external rename or link whose destination is in a current or pending scope (a directory moved into a scope included), so the
file cannot gain an in-scope name; every later rename, link, directory rename or policy apply resets the class exactly as for a probed entry.
The one apply path that begins no probe (an Unknown instance) now drops a plain entry's OUTSIDE class back to UNRESOLVED (fail closed).
Same commit: a staged stream answers `FileStandardLinkInformation` (0x36) from its backing file like `FileStandardInformation` (U01's
INCONCLUSIVE query; reads are never refused). Builds: `m1-driver9`, 4 configurations, 0 warnings / 0 errors, PREfast and ApiValidator clean.
Luna's review of that first version (`52430692`, never pushed) found a P0, which I accept: a scope that grows the current+pending union is
published before the epoch drain and the apply sweep that resets every entry's class, and ordinary writes are not held by the drain, so in that
window an OUTSIDE class proven against the old scope was trusted by the nested-write rule and by the section gate's OUTSIDE shortcut (the
pre-existing probe-classified OUTSIDE entries had the same window; the create proof made it far more reachable). Fix, squashed into `77b76faa`:
`SafeUploadPolicyScopeTransitionActive()` reports the scope cache's apply flag, which every growing publication sets in the same publication and
only the end of the apply that probes every live entry clears (it stays set when the apply fails); during a transition the nested-write rule
refuses (`SAFEUPLOAD_SOP_OUTSIDE_TRANSITION`, aux `0xE500000C`, agent name `scopeTransition`) and the section gate decides an OUTSIDE entry by
its retained name like an unresolved one (the section epoch gate checks the opened name), or by the volume when it has no name. Rejected
alternative: stamping each OUTSIDE with its scope sequence, because the boot-policy finalize republishes (the sequence advances) with a shrinking
union and no reprobe, which would leave every OUTSIDE entry stale for the rest of the boot. Builds `m1-driver10` / `m1-agent9`; Luna re-reviews
the fix. The driver8 CU run `t3cue` on the HDD-backed disk confirms the class: its 23 workload refusals are all nested WRITEs with aux
`0xE5000007` on `\Windows\servicing\Sessions\*.xml` (pids 3024, 6000); its verdict is otherwise unusable (the workload took 3,510 s on the
spinning disk and the guest did not answer SSH afterwards), so run overlays move to the NVMe disk for the next runs.
Also in `t3cue`, before the workload: one writable section of `\Windows\System32\config\DRIVERS` refused for the Registry process (pid 92,
`policyScope`), which is the T2c class (a pre-scope writer's entry waits for its alias probe after the policy apply; the section gate fails
closed meanwhile) hitting a registry hive; T2c needs a real fix, not a note.

### T3d and T2c after three Luna reviews: `4d02039a` (builds `m1-driver13` / `m1-agent11`, VM runs queued)

The local commits (`52430692`, `77b76faa`, `3195dd54`, `feba0116`; none pushed) are squashed into `4d02039a`. Review rounds, all accepted:
1. First review of T3d: P0, a stale OUTSIDE across a scope publication -> the transition flag (`SafeUploadPolicyScopeTransitionActive`).
2. Re-review: P0, during a transition the retained name misses a third hard link in the new scope -> during a transition `SopMatchesPolicy`
   answers every non-reclassified entry by the volume; P1, an untracked direct write held no W -> `SafeUploadStageWritersAdmitNestedMutation`
   counts the admitted nested operation in W under the entry's state lock (promotion needs W == 0: verified by the reviewer at the predicate).
3. T2c review: P1, the opened name was not rechecked after the wait -> re-decided under an unchanged scope sequence; P2, unbounded waiters
   -> at most 4 waiters, others decide at once (10 ms polling kept: the resolve paths run under spin locks).
4. Third review: P1, "no entry" or a stale stream-context entry answered "no match" before the transition check -> every negative answer
   is fail closed during a transition; P2 (accepted, bounded): a section callback holding a pre-publication epoch token can wait on a
   transition that ends only after that token drains; it times out after 2 s and refuses (only in the instant between a publication and
   the epoch replacement).
Still deferred (from the M1 review): network-scope canonicalization (UNC/provider names), plan "Later".
Queues: `m1-t3queue6.sh` (CU `t3cuh`, U01 `u01n` and `u01o` boot-Verifier, runtime-Verifier slice `m13r`, Microsoft 365 `t3m365a`, CU and
Microsoft 365 controls) then `m1-regress13.sh` (the 65 other cells; boot Verifier last, alone), judged by `Get-StagedMvpStatus.py` on
`4d02039a`; both wait for win10-debug3 to be shut off (its rebuilt clone answers at debug2's address).

### T3 cumulative update on the final driver: PASS (`t3cuh`, `m1-driver13` / `m1-agent11`, 18:35)

KB5066791 with the driver loaded, run overlay on NVMe: workload PASS (installResult 2, 1,135 s), driver loaded afterwards, coverage Ready,
the deny ring EMPTY (0 of 0: the 23 nested TiWorker refusals of T3d are gone, nothing refused at boot, so no T2c `config\DRIVERS`
refusal either, nothing in the servicing boot), no registry overflow, no Unknown reason; run disk deleted, base untouched (verdict rc=0).
Watch item: the writer registry's high-water was 4,015 of 4,096 (earlier CU runs 1,299 / 3,097 / 2,206). It did not overflow, but an
overflow makes coverage Unknown until reboot (T3c), so the margin is thin on a fast disk; Microsoft 365 is the next test of it.

### U01 and the runtime-Verifier slice on the final driver (18:35-19:10)

- U01 `u01n` (ordinary) and `u01o` (boot Verifier on for the whole run): every line PASS, including `U01NoRefusalOutsideScope` under the boot
  Verifier (T2c: FontCache's section is no longer refused) and `U01StagedStreamQueries` (the 0x36 answer); the ring holds the 2 expected in-scope
  refusals; CreateProfile 0x0 and a real first sign-in.
- Slice `m13r` (runtime Verifier), judged by the gate's rule: C01-approve-absent `m13r2` ok, C01-block-absent `m13r3` ok, S01 `m13r4` ok;
  C05 `m13r1` blocked only by `FailureOrErrorsInEvidence`: the agent-execution inventory's "Process inventory PID 4960: The parameter is
  incorrect" (a process exited while the harness enumerated it; the harness treats any vanished process as defeating the proof, by design,
  and that is kept). Its own assertions pass, among them `C05DenialLedger` PASS: "Driver deny ring recorded the denied rename: sequence 1,
  status 0xC0000022". Restoration clean in all four. C05 is rerun in the regression's retry round.

### T3c: Microsoft 365 found the compact registry tier was never usable (`b995943b`, build `m1-driver14`)

Microsoft 365 with `m1-driver13` (`t3m365a`): the install itself passes (407 s, exit 0, Word present, the deny ring empty, driver loaded), so the
original M365 failure ("very slow, then couldn't use a required file") is gone; but coverage ended Degraded: the writer registry overflowed (727
failed insertions, Unknown reasons, `T3CoverageReady` / `T3RegistryNeverOverflowed` / `T3NoUnknownReason` FAIL). The sampler shows why: the live
entry count stays at 250-435 for the whole run, then jumps from 293 to 3,739 in one 3 s sample (the installer holding about 3,800 files open at once;
about 3,000 reclaim passes pruned 17), sits at 4,096 for about 12 s and drops back when about 3,800 entries are pruned together; the compact tier
stayed at 0 throughout. Cause: `StageRegistryGetOrInsert` releases the reservation's capacity, which clears `CompactSlotReserved`, and then chose the
tier from that flag, so every compact reservation (the D2 fallback, 16,384 records) was checked against the full-name tier and could not be inserted
once that tier was full. Fix: the tier is the shell's (`Shell->Compact`), as at the insertion. Luna review: no P0/P1; the tier fix and the per-tier
accounting are correct, compact entries stay fail closed for every consumer. Follow-ups (fail closed or performance, not done): compact entries get
no create-time alias proof, so a nested write on one is still refused (only beyond 4,096 concurrent named writers); the activation anchor cap
(4,096) is below the compact population, so more than 4,096 activating writers at an apply could leave a compact ADS entry Unknown; with the
name tier above 75 % every compact insertion wakes the reclaim worker. True exhaustion of both tiers (more than 20,480 concurrent writers) still
makes coverage Unknown until reboot (the original T3c design question). Verification: `m1-final14.sh` (Microsoft 365 `t3m365c`, CU `t3cui`,
U01 `u01p`/`u01q`, then the 69 cells on `b995943b` + agent `4d02039a`).

### T3 complete with the driver loaded (19:57)

- Microsoft 365 `t3m365c` on `m1-driver14`: every line PASS: workload 402.2 s (exit 0), driver loaded, coverage Ready, the deny ring empty, no
  refusal outside the scope, no overflow (high-water 8,038 = the 4,096 full-name records plus about 3,940 compact ones: the compact tier absorbed
  the burst), no Unknown reason. Control `t3m365b`: 418.3 s.
- Cumulative update: `t3cuh` on `m1-driver13` PASS, 1,135.3 s; control `t3cuf` 921.3 s (+23 %). The driver14 run `t3cui` is queued for the final
  driver line.
- Defender `t3defenderu` 170.4 s against control 172.3 s; MSI 9.2 s against 7.0 s.
Overhead numbers for the owner: Microsoft 365 and Defender none measurable, the cumulative update +23 %, an MSI about 2 s.
