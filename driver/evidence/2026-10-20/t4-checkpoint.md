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
