# T4 checkpoint — 2026-10-20

Pair under test: kernel `d1068cc3` (signed `3547377A…`, Debug feature build `t4pagefix1`: WDK/PREfast/ApiValidator 0/0, imports PASS)
+ agent `586ae7cb` (matrix `m2t4refund2`, 2,801 passed per feature configuration, package `1EA4A2E1…`). Lab: win10-debug3 only,
both builder locks held, builders off, separate restoration after every row. Component and dev evidence, not a milestone claim.

## What was wrong (all attempts kept)

| Row | Result | Finding |
|---|---|---|
| `m2t4smoke1020a` | stopped before any product step | my launcher edit mid-run (bash reads scripts incrementally); lab only |
| `m2t4smoke1020b` | stopped at baseline | guest clock gate (29.5 s skew); lab only |
| `m2t4smoke1020c` | 7/256, stop at 10 | saves to new names refused (Win32 32) with no deny-ring entry |
| `m2t4smoke1020d`/`f` (logging-only driver `t4/sharediag`) | 3/256, 5/256 | every failure site `0x84`/`0x91`: the **allocation exchange** answered "no allocation committed" ([d ring](m2t4smoke1020d-after.txt), [f ring](m2t4smoke1020f-after.txt)); READMIT conversion (`0x83`) never fired |
| `m2t4smoke1020e` | no cycles | boot-time sticky Unknown (rename failure), receipt kept |
| `m2t4smoke1020g` | 0/256 (sequential reopens) | saves succeeded; original owner's reopen PASS; second process's read/write open Win32 32 ~20 ms after the owner closed ([receipts](m2t4smoke1020g-reopens.jsonl)) |
| `m2t4smoke1020h` | 174 healthy cycles, then bugcheck `0x7F` (8) | dump: `StageMvpNamespacePre` (pageable) called for a paging read; its code page trimmed by Verifier; the in-page read re-entered the filter and recursed until the kernel stack was exhausted ([excerpt](t4-1020h-bugcheck-excerpt.txt)) |
| `m2t4bv10k1` (10k boot Verifier, budget on) | 325 healthy cycles, then a 5.8 s allocation reply (Win32 121) and refusals of every later save | see "10k findings" below; [verdict](m2t4bv10k1-verdict.txt), [ring](m2t4bv10k1-after.txt), [timings](m2t4bv10k1-service-events.txt) |
| `m2t4smoke1020j` | 256/256 with 64-cycle sampling, all required lines PASS | smoke gate passed |
| `m2t4smoke1020i` | 256/256, versions 256/256, stage files 0, worker idle, registry bounded, no cap refusal | only `T4PoolEndpoint` failed: my invocation used the default 500-cycle sampling; rerun with `sample_every=64` |

## Fixes

- `586ae7cb` (agent): the capacity grant covers the user's whole remaining allowance and is refunded only when the publisher records
  the previous save's stage as deleted, a moment after its bytes appear; a back-to-back save was refused. The allocation now retries
  the same reservation for at most 1.5 s with a full refund pass between attempts; genuine exhaustion still fails the same way.
  Budgets, floor and caps unchanged. Four focused tests; matrix `m2t4refund1` first leg failed one unrelated journal wall-clock
  assertion (1,144 vs 1,000 ms, receipt kept, not touched), `m2t4refund2` PASS.
- `d1068cc3` (kernel): `StageMvpNamespaceOperation` runs in resident code before the pageable router and skips paging I/O and every
  operation except CREATE/SET_INFORMATION. No behavior change for routed operations. No independent review (owner: avoid over-review).
- `c0c812d7` (harness): the raw-cell runner no longer requires the retired staging-out profile rows; offline input validation of the
  pair passes.

## Scope decision (default, owner may veto)

The optional immediate-reopen control (`T4_IMMEDIATE_REOPEN`, added 2026-10-16) is not an owner 2026-10-12 T4 gate. In sequential
mode the original owner's reopen passes and the second process's read/write open fails: that is the Word reopen defect tracked in
T8 (`word-readonly-gate-analysis-sol-high.md`, review REVISE). T4 closes on the unchanged owner gates; the control and its evidence
move to T8. Worker 1's READMIT repair (bundle `t4/readmit`) targets a different race and stays unintegrated.

## Rows in flight / next

Smoke with `sample_every=64`, 10k boot-Verifier, 10k runtime-Verifier, 10k ordinary, then C01–C04/B01/B02/X01 raw-volume cells in
ordinary/runtime-/boot-Verifier, each with separate restoration. The lost-reply fault row (worker 2 bundle `t4/fault-row`) follows.

## 10k findings (boot Verifier, `m2t4bv10k1`) — T9 accounting, not kernel lifetime

1. **Allocation latency grows and has fat tails.** Slow-request log: per-allocation `journal-scan` 0.3–0.7 s early, 1.2 s near request 4,200;
   flushes 0.3–1.4 s on this guest; one allocation took 5.8 s, past the driver's reply timeout (Win32 121). My refund-grace loop
   (`586ae7cb`) runs full reconcile passes in that path and overshot its own 1.5 s bound; it must use bounded same-SID passes.
2. **A lost allocation reply wedges later saves.** The driver kept opening the stranded allocation's private stage files from the
   requester's context and its own private-namespace guard denied every attempt (ring 8–19); each later save was refused (error 32).
   This is the V20 lost-reply recovery scenario; it does not self-heal in this build.
3. **Completed saves keep a 1 MiB charge forever.** `RetireCompletedMetadata` retires only never-exposed discard kinds, and
   `CompletedArchiveShape` is false for bound allocations; UX-LARGE.md lists automatic metadata retirement as separate work. With the
   default budget on, the per-user allowance on this guest is exhausted after a few hundred completed saves, whatever the latency.

None of these is a kernel context, pool or cap result. Owner decision 2026-10-20 ("I approved the change"): T4's kernel lifetime
rows may run with `T4_STAGE_SPACE=off` (the configuration of the 2026-10-12 T4 rows), recorded in each receipt and verdict, as an
isolation result only. The three accounting defects block M2 with the default configuration and are tracked as T9 work.

## Isolation rows (budget disabled, owner-approved) — results to 2026-10-21 03:30 BRT

Pair: kernel `d1068cc3` (`t4pagefix1`), agent `586ae7cb` (`m2t4refund2`), `T4_STAGE_SPACE=off`; every receipt carries `stage-space.txt` and a
`T4StageSpaceConfig INFO` verdict line. Isolation results, not a product-configuration qualification.

| Row | Mode | Result |
|---|---|---|
| `m2t4ordoff1` | ordinary 10k | **PASS**, 10,000/10,000, 11,000 s ([verdict](m2t4ordoff1-verdict.txt)) |
| `m2t4bvoff1` | boot Verifier 10k | all functional gates PASS; `T4PoolFlat` FAIL: slope 0.971 B/cycle (limit 4) but after-idle endpoint +75,200 B vs the 64 KiB band ([verdict](m2t4bvoff1-verdict.txt), [samples](m2t4bvoff1-samples.jsonl)) |
| `m2t4bvoff2` | boot Verifier 10k rerun | same: slope -0.414 B/cycle, cycle 1000 6,606,824 -> cycle 10000 6,606,872, after idle 6,679,504 (+72,680 B) ([verdict](m2t4bvoff2-verdict.txt), [samples](m2t4bvoff2-samples.jsonl)) |
| `m2t4rvoff1`, `m2t4rvoff1r` | runtime Verifier | never Ready (rc=19), identical instance Unknown (reason TRUST, site 6488): the old runtime mode loaded the driver late ([ready](m2t4rvoff1-ready.txt)) |
| `m2t4rvoff2` | runtime Verifier 10k, arm after Ready | stopped at cycle 21: the driver entered sticky instance Unknown (reason IDENTITY, site `StageWriters.c:5939`, alias/scope classification of an activating writer failed) about 2.5 min in; every later protected create, including the agent's own publication, was refused by the legacy create gate (fail-closed by design) |
| `m2t4rvoff3` | runtime Verifier 10k repeat | **PASS**, 10,000/10,000, 10,999 s, `T4PoolFlat` PASS: slope 0.587 B/cycle, 134,240 -> 131,936 at cycle 10000, after idle 143,200 ([verdict](../2026-10-21/m2t4rvoff3-verdict.txt)); the first failure was a chance sticky-Unknown event |

**Pool endpoint.** The settled pool is identical across both boot-Verifier rows (6,620,768 / 6,622,232 B) and flat across 9,000 cycles; the
writer-registry tag (`SwUr`) then steps up by about 58-60 KB in the idle window after the actor exits, in both rows. Hypothesis (not proven):
about 24 registry entries from the agent's idle archive housekeeping (packs are bounded at 32, about 77 KB worst case), which the 64 KiB band
(set before the archive existed) cannot accommodate. Gate untouched; owner decision requested: accept, widen to 128 KiB, or change the
kernel/agent so the service's own private-journal writes leave no registry entries.

**Runtime mode.** The cycles launcher's runtime mode (hold at demand start, arm unloaded, late `fltmc load`) can never report Ready; it passed
on 2026-10-10 only before the Ready gate existed. It now matches the invariant suite: boot-start pair to Ready, then
`verifier /volatile /flags 0x13B /adddriver SafeUpload.sys` on the running driver, read back exactly (`e329048f`, PowerShell 5.1 gate
[`m2t4rvmode1`](../2026-10-21/harness-windows-gate-m2t4rvmode1.txt) PASS).

## Raw-volume cells (C01-C04, B01, B02, X01 x ordinary/runtime/boot = 33 runs)

First rows (`m2t4o1`, `m2t4r1`, `m2t4b1`: [index](phase4-suite-m2t4o1-index.txt)) were INCONCLUSIVE at C01-approve-absent with eight blockers.
Offline triage (worker 3, [result](t4-cells-triage-worker-result.md)): the cell harness's journal reader expected a flat directory of per-transfer JSON,
but the staged agent also writes `driver-epoch.state`, packs completed receipts into `completed/*.pack` segments and records `SealPending` (10).
Taint was not the cause; no kernel/agent regression is established; all 33 runs share the mismatch. Fixes: reader patch (`e7a6990a`, 44 offline checks,
PS 5.1 gate green) and host validation of physical journal files plus archived payload frames (`ArchivePayload` self-check, 19 controls including a replay of
the real pack). Rerun `m2t4q1` ([index](../2026-10-21/phase4-suite-m2t4q1-index.txt)): C01-approve-absent ordinary completes, ForbiddenByteCount 0,
restoration clean, public listing / independent reader / seal-after-close / journal order / sealed digest / released image and raw extent / metadata
and security assertions PASS. Remaining MVP blockers: dedicated unheld-latency evidence (approve cases only, separate `--dedicated-unheld-latency` runs),
and `LiveTaintFlags` (the taint-era check the owner directed to delete on 2026-10-15; the removal branch `wt/taint-removal` was never merged and the
driver still has the test flag). Coverage items are the cell's own documented deferrals. Owner scope decision requested (see plan).

## Update 2026-10-21 (to 07:45 BRT)

**All three 10k modes now have a result:** ordinary PASS, runtime Verifier PASS (`m2t4rvoff3`), boot Verifier functional PASS twice with the pool endpoint over the band.

**Pool endpoint is a constant, not a leak.** Driver nonpaged bytes after idle (Verifier pool tracking, boot Verifier): 256-cycle smokes 6,681,608 and 6,654,224;
10k rows 6,682,024 and 6,679,504. The idle level does not depend on the number of cycles; the gate's baseline (the cycle-1000 sample, 6,606,824 B) sits about
72 KB below it. The hypothesis "archive packs" is not supported (the step is the same with one pack and with about two dozen). Owner decision still requested:
accept, widen the band (recommended 128 KiB), or change the kernel/agent.

**Sticky Unknown family.** 3 of about 15 boots/rows today ended in sticky `WriterStateUnknown` with a different reason and site each time (rename 2069, trust 6488,
identity 5939). Fail-closed by design, driven by background writers; the T1/T18 area, tracked separately from T4's lifetime gates.

**Raw-volume cells, ordinary-mode survey** (`m2t4s*`; each completed with ForbiddenByteCount 0 and clean restoration where it ran to the end):

| Cell | Result | Remaining blockers |
|---|---|---|
| C01-approve-absent (`m2t4q1`) | completes; product assertions PASS | dedicated unheld latency, `LiveTaintFlags` (receipts incomplete: the Inspector cannot read live policy while the agent is up), deferred coverage items |
| C01-block-absent | INCONCLUSIVE | ActualServiceTimelines, C01Execution, C01HandBackWindowClosureAndRestart |
| C02-block-absent | INCONCLUSIVE | + Missing C02HandBackSafeRelativeCreation / SecondUserAccess |
| C03-block-existing | INCONCLUSIVE | C03Execution, hand-back window closure and restart |
| C04-block | INCONCLUSIVE | C04Execution, hand-back window closure and restart, LiveTaintFlags |
| B01, B02 | wrapper failed at the lab level in about 3 minutes | evidence retained under `boot-start-invariant-B0*-ordinary-m2t4s[56]1` |
| X01 | INCONCLUSIVE | X01Execution |

The cell harness needs a staged-agent modernization per family (BLOCK hand-back evidence, B01/B02 wrapper, X01 execution, live-taint receipts) before 33 runs can pass.
That is an M2 qualification work item, not a T4 kernel-lifetime result. Owner scope decision requested.

## Closed for now — 2026-10-21

Owner: "Record, push, and close T4 for now." T4 is closed provisionally on the evidence above. Nothing was waived and no gate, threshold or
assertion changed. Carried to the final M2 pair:

- [ ] Boot-Verifier 10k on the final M2 pair under the 128 KiB endpoint band (owner chose option 2 below; future rows only).
- [ ] 10k rows with the default staging budget, after the T9 fixes (metadata retirement, bounded allocation latency, lost-reply self-heal).
- [ ] Raw-volume cells to MVP-gate PASS in three modes (BLOCK hand-back evidence, B01/B02 wrapper, X01 execution, dedicated latency, live-taint receipts).
- [ ] Lost-reply fault row (harness held on `t4/fault-row`).
- [ ] Sticky `WriterStateUnknown` family (3 of about 15 boots), T1/T18 area.
- [ ] Immediate-reopen control under T8 (second process's read/write open, Win32 32).

Held, unintegrated branches: `t4/readmit` (worker 1 READMIT repair; the smoke failures it targeted had other causes), `t4/fault-row`
(worker 2), `t4/sharediag` (logging-only diagnostic driver).

## Endpoint decision — 2026-10-21

**What the check measures.** `T4PoolFlat` (10k) has two parts: slope <4 B/cycle from cycle 1,000 (catches per-save retention; pre-T4 each
save kept ~4.5 KB) and an endpoint: the after-idle sample must be at most the band above the cycle-1000 sample. `T4PoolEndpoint` (smoke)
uses the same band against its first warm sample.

| Row | Saves | Baseline sample | Baseline B | After idle B | Rise | Verdict (64 KiB) |
|---|---|---|---|---|---|---|
| `m2t4smoke1020j` (boot) | 256 | cycle 64 | 6,662,776 | 6,681,608 | +18,832 | PASS |
| `m2t4bvoff1` (boot) | 10,000 | cycle 1000 | 6,606,824 | 6,682,024 | +75,200 | FAIL (+9,664 over) |
| `m2t4bvoff2` (boot) | 10,000 | cycle 1000 | 6,606,824 | 6,679,504 | +72,680 | FAIL (+7,144 over) |
| `m2t4rvoff3` (runtime) | 10,000 | cycle 1000 | 134,240 | 143,200 | +8,960 | PASS |

Runtime Verifier counts only allocations made after it is armed, hence its small absolute numbers. Findings from the retained samples:

- The after-idle level is the same in every boot-Verifier row (6.65–6.68 MB) at 256 and at 10,000 saves. The smoke passed only because its
  baseline fell on a busy sample; during a run the level swings about 25 KB between samples, so the baseline sample decides much of the margin.
- About 96% of the rise is the writer-registry tag `SwUr` (`m2t4bvoff2`: +70,064 of +72,680). The driver's own `registryEntries` stays
  220–233 during the run and steps to 249–253 after the actor exits, about 2–3 KB per entry; the entries remain after the memory purge.
- In the runtime-Verifier row the step is absent (`registryEntries` 232 -> 238).
- Not established: which files the extra entries belong to (no harness listing by name), why the step depends on the Verifier mode, and whether
  it repeats per idle period (each row has one idle window). If it repeated, the registry would fill toward its 4,096 capacity and the driver
  would go sticky Unknown (protected saves refused until reboot); if it is one-time, users see nothing (~75 KB of ~100 MB guest nonpaged pool).

Options offered: (1) accept as recorded exception, (2) widen the band to 128 KiB, (3) widen plus a second-idle repeat check (recommended).
**Owner: "Ok I choose 2, but only to future rows."** The launcher band is 128 KiB from this commit on (`Invoke-StageCycles.sh`, both
`T4PoolFlat` and `T4PoolEndpoint`; the limit is now printed in the `T4PoolFlat` line); slope limit unchanged. `verdict-selfcheck.py` adds
`T4PoolBandControl` (first+131,072 PASS, +131,073 FAIL, slope 4 B/cycle FAIL). The receipts above are not re-judged and keep their verdicts.
