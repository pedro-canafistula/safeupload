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

