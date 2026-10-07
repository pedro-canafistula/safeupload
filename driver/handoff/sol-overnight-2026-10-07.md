# SafeUpload MVP: overnight run (Sol), 2026-10-07

You drive the SafeUpload MVP toward its release gate while the owner sleeps. The orchestrator (Claude) has
stopped. You are the only agent using this checkout, the builder VM and the debuggee VM. Work in
`/home/victor/Work/safeupload-staging` on branch `feat/staged-kernel-prototype` (HEAD `6133fed4` at handoff,
pushed). Keep going without asking: the owner is not reachable until morning. Make design calls as a senior
engineer would (minimal, fail closed, consistent with the recorded owner decisions) and record each one in
`driver/MVP-PLAN.md` with its reasoning.

## Read first, in order
1. `driver/MVP-PLAN.md`, from the top through "MVP gate (orchestrator decision, 2026-10-07)". This covers
   scope, owner decisions, current state, and the MVP gate you implement.
2. `driver/evidence/2026-10-05/phase4-suite-design-v2.txt`: case contracts (APPROVE, BLOCK, H, D) and the rows.
3. `driver/scripts/Test-StagedInvariantSuite.ps1`, `StagedInvariantCases.psd1`, and
   `Invoke-StagedInvariantQualification.py` (`case_gate`, `MODES`).
4. `/home/victor/.claude/projects/-home-victor-Work-safeupload-staging/memory/safeupload-debuggee-lessons.md`:
   debuggee facts that each cost hours (a bugcheck looks like a hang, dump recipe, WinRE recovery, clock jump).

## State at handoff
- Driver: build `mvp4-b10` from `326eb512`, unchanged since (artifacts in `/tmp/claude-1000/exact-mvp4-b10/`).
- Agent: `agent-mvp4-b17` from `12ad8e96` (353/353 tests; matrix PASS). Artifacts in `/tmp/claude-1000/exact-agent-agent-mvp4-b17/`.
- Policy SHA-256: `29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731`.
- Runtime-Verifier results so far:
  - C01-approve-absent `c01o`: 0 FAIL.
  - C01-block-absent `c01b3`: 131 PASS, 0 FAIL, 21 INCONCLUSIVE; hand-back verified; restoration clean.
  - Every remaining INCONCLUSIVE is on the MVP-gate allowlist except `C01BlockedStageRetained`: the admin
    harness gets "Access is denied" opening `C:\ProgramData\SafeUpload\staging\<id>.txt`.
- A01: run `a01r1` stopped because the harness never armed runtime Verifier on the activation path (fixed
  in `7d8f4c49`, not yet rerun). A02 and A03 have never run.
- C02-C05 (7 Ready variants) are merged and pass Windows PowerShell 5.1 checks, but have never run on the VM.
- NotReady MVP rows: A04, A05, B01, B02, R01, R02, R03, X01. The P rows and RV4 are deferred: do not touch them.
- The debuggee was BaselineClean=True before a01r1, and a01r1 reported RestorationClean=true. Verify again
  before your first run.

## Work, in priority order
Run VM cases in the background, one at a time (a run takes about 20-25 minutes). Implement host-side work
in a separate git worktree (`git worktree add ../safeupload-wt-sol <new-branch>`), never in the checkout a
run is using. Merge between runs, after validation.

1. **MVP gate in the runner.** Add a per-run `MvpGatePassed` plus an `MvpDeferred` list, exactly as
   MVP-PLAN defines them. Leave `GatePassed`, `Phase4Suite` and the case contracts unchanged.
   - Add an `MvpSuite` summary line covering MVP rows × modes.
   - Add Python tests: each allowlisted INCONCLUSIVE is tolerated, any other INCONCLUSIVE fails, any FAIL fails.
   - Recompute it for the existing results `c01o` and `c01b3` from their saved case JSON, if the runner keeps it.
2. **Fix `C01BlockedStageRetained`.** Find out why the admin harness is denied the stage file. Check whether
   `SUProofFile.Open` requests backup semantics, and whether the driver deliberately refuses non-service opens
   of stage streams. If the refusal is intended product behavior, do not weaken the product. Read the bytes
   another trusted way instead: the existing raw-volume reader, or the SYSTEM Inspector path.
3. **Runtime-Verifier pass over every Ready row:**
   - A01, A02, A03
   - C02-approve-absent, C02-block-absent, C03-approve-existing, C03-block-existing, C04-approve, C04-block,
     C05-denied-external-rename
   - S00, S01, S02
   - C01 approve and block again after items 1 and 2.

   Triage every non-PASS:
   - **Harness bug:** fix it, validate it (see "Gates"), rerun the case.
   - **Product bug:** fix it minimally (see "Product changes").
   - **The same failure twice with no new information:** record it in MVP-PLAN and move on to the next case.
4. **`LiveTaintFlags`: replace it with live evidence.**
   - The Inspector already prints `TaintsRecorded`, `TaintLookups`, `TaintHits` and `RenamesFromTainted`,
     and a diagnostic carries `testDisableTaint` (`driver/SafeUpload.Inspector/main.c` around lines 441 and 1826).
   - Prove that no taint decision participated: take counter deltas across the observation window, plus the
     live flag.
   - If that needs a driver change, record why and leave the item on the allowlist.
5. **Latency run.** For each MVP write path (cached write, mapped, overwrite, replacement save), run 100 unheld
   repetitions plus a cold sample, using the budget in `case_gate`. This is what lets `*UnheldLatency` be
   tolerated in the functional runs.
6. **Implement the NotReady MVP rows** from the design rows: A04, A05, B01, B02, R01-R03, X01.
   - Reuse the C01/A01 framework; do not copy whole functions.
   - Make each row Ready with a concrete ExpectedTimeline and StatusClasses, then run it in runtime-Verifier mode.
   - Implement the C01-C05 umbrella-row variants that are still NotReady if they are cheap; otherwise record
     them in MVP-PLAN as deferred, with the reason.
7. **Ordinary and boot-Verifier modes** for every MVP row, after runtime Verifier is green.
8. **Phase 5 review packet.**
   - Write `driver/evidence/<date>/phase5-review-brief.md`. It lists what the MVP claims, the evidence paths
     per row and mode, the allowlist, and known limitations.
   - If you can run `codex exec`, launch an independent adversarial review with Luna. Use
     `codex exec -m gpt-6-luna -c model_reasoning_effort=max -s workspace-write -C <worktree> -o <final.txt> - < brief.md`
     against a read-only worktree, and record its findings. Otherwise leave the brief for the morning.

## Environment
- **Builder** (Windows, WDK, .NET, Windows PowerShell 5.1): `192.168.122.210`, user `vika`.
  **Debuggee:** libvirt domain `win10-debug` (`virsh -c qemu:///system`) at `192.168.122.51`.
- **Remote PowerShell:** `python3 driver/scripts/remote_ps.py <ip> < script.ps1`.
  - A script with a `param` block cannot be piped. `scp` it to `C:\Users\vika\Documents\` and invoke it with `& '<path>'`.
  - The scp options the repo uses are
    `-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes`.
- **Debuggee baseline:**
  `echo "& 'C:\Users\vika\Documents\Get-StagedBaseline.ps1'" | python3 driver/scripts/remote_ps.py 192.168.122.51`
  must print `BaselineClean=True` before every run.
- **One case run:**
  `python3 driver/scripts/Invoke-StagedInvariantQualification.py <tag> mvp4-b10 326eb512 agent-mvp4-b17 29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731 --cases <CaseId> --modes runtime-verifier --agent-source-commit 12ad8e96`
  - Use a fresh, unique tag every time.
  - The summary is in `driver/evidence/<date>/phase4-suite-<tag>-index.txt`.
  - Assertions are in `.../boot-start-invariant-<case>-<mode>-<tag>-artifacts/trial.clixml`.
  - A `...-recovery-required.txt` marker means the guest must be rolled back.
- **Serial batch with automatic rollback:**
  `driver/scripts/Invoke-StagedSuiteBatch.sh mvp4-b10 326eb512 agent-mvp4-b17 12ad8e96 runtime-verifier <prefix> <CaseId>...`.
  It is untested: watch its first rollback closely, and fix it if needed.
- **Agent build:** `driver/scripts/Invoke-ExactAgentBuild.sh <fresh-label> <commit>`. It is good only when the
  log prints `ExactAgentGate=PASS;tests=N`. One build ended without that line (a test host hang); rerun it with
  a new label.
  **Before pushing an agent change:**
  `python3 driver/scripts/Invoke-ExactAgentMatrixBuild.py <label> --reviewed-untracked driver/handoff/empty-allowlist.json`
  must print `ExactAgentMatrixGate=PASS`.
- **Driver build:**
  `SAFEUPLOAD_SIGNING_THUMBPRINT=A6D6CE1AA28835D509160A80ADB7894869AADF38 SAFEUPLOAD_SIGNING_STORE_LOCATION=LocalMachine driver/scripts/Invoke-ExactSourceBuild.sh <fresh-label> <commit>`.
  The exit code is not the verdict: read `driver/evidence/<date>/exact-<label>-summary.txt`. All four
  configurations must be at 0 errors and 0 warnings, with PREfast and ApiValidator clean.

## Gates (nothing is pushed without its gate)
- **PowerShell change:** `scp` the suite files to the builder's Documents folder. Then
  `[System.Management.Automation.Language.Parser]::ParseFile` must report 0 errors, and
  `StagedInvariantProofAdapters.SelfCheck.ps1` must PASS, on Windows PowerShell 5.1. Also run
  `python3 driver/scripts/test_staged_invariant_proof_adapters.py`.
- **Agent change:** a new exact build, then the matrix PASS.
- **Driver change:**
  - four clean builds;
  - a fresh independent adversarial review by Luna before the build runs on the VM;
  - then a runtime-Verifier VM run.
- **Commits:** one coherent increment per commit, then `git push origin feat/staged-kernel-prototype`.
  - Never force-push, never push `main`, never rewrite published history.
  - Never touch `wip/owner-prototype-20261006`.
- **Evidence:** commit run evidence after each run. Skip files over 20 MB; their hashes are in provenance.

## Product rules (owner decisions; do not reopen them)
- The adversary is a standard user. Admins and SYSTEM are trusted.
- MVP platform: Windows 10 19045 only, one local fixed-NTFS folder.
- Process taint is never a protection mechanism. No file-system scans and no timers in the product.
- A scope with a pre-existing writer stays Activating and is never reported Ready.
- The hand-back is bound to the requestor SID. Sessions matter only for UI delivery and justification.
- Never weaken the product, a case contract or the strict gate to make a run pass. If a contract is wrong,
  write the reasoning into MVP-PLAN before changing it.

## Windows PowerShell 5.1 and harness rules (each one already cost a VM run)
- No `[ulong]`, `?:`, `??` or `-Parallel`.
- `-band` on byte-backed enums (AceFlags) needs `[int]` casts.
- `Measure-Object -Property` fails on hashtables: sum explicitly.
- An `if` statement assigned to a variable unrolls a single-element array: wrap the whole `if` in `@()`.
- Deadlines use `[Diagnostics.Stopwatch]::GetTimestamp()` ticks only. Never use `DateTime.UtcNow`: the guest
  clock jumps about +4 h after each boot.
- `state.clixml` is shared by the observation and AfterBoot: use only `Save-State` and `Load-State`.
- Take a time window's start before the capture it covers.
- Missing evidence is INCONCLUSIVE with an exact reason, never a silent PASS.
- Restoration leaves the guest clean: product files are restored in place, policy before product state.

## Debuggee safety (hard stops)
- Only one VM run at a time. Never `scp` to the guest while a run is in flight.
- **Rollback** (only after a run left `recovery-required`, or the baseline is unclean): use the guarded
  pattern of `driver/evidence/2026-10-07/c01b1-state-race-rollback.sh`, or the batch script's `rollback`.
  - It runs only when the failed run's overlay is the domain's top disk.
  - It creates one new overlay on that overlay's parent.
  - It never deletes or modifies an existing image, never uses blockcommit or snapshot-delete, and never
    touches another domain.
- **After a rollback**, do a clean restart and confirm `BaselineClean=True`.
- **WinRE screen** ("Choose your keyboard layout"): `virsh send-key win10-debug KEY_ENTER`, then `KEY_DOWN`
  plus `KEY_ENTER` ("Turn off your PC"), then `virsh start`.
- **A frozen guest is usually a bugcheck.** If a driver bug is suspected, capture the memory dump first
  (lessons file) and read `nt!KiBugCheckData` before restarting anything.
- If the guest cannot be brought back to `BaselineClean=True` by these steps, stop all VM work. Record exactly
  what happened in MVP-PLAN, then continue with host-only items (gate code, case implementation, review packet).

## Reporting
- Keep a "2026-10-07 overnight (Sol)" section in `driver/MVP-PLAN.md`. Update it after every increment.
  Use a checkbox tree (done / in progress / pending), with a commit hash or evidence path for every done item.
- When you finish, or when only owner decisions remain, write `driver/handoff/sol-overnight-2026-10-07-report.md`.
  It needs:
  - an MVP gate table (row × mode → `MvpGatePassed` plus run tag);
  - the product fixes, with their commits;
  - the design decisions taken;
  - the open items;
  - the decisions only the owner can make.
