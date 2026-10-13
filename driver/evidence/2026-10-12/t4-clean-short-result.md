# T4 clean short qualification — m2t4clean256b1

**Result: FAIL.** The unchanged pair completed 256/256 saves and every cleanup, cap and idle assertion passed, but the
nonpaged module-pool slope was **461.600 B/cycle**, above the unchanged limit of 4. The diagnostic PASS did not reproduce
in qualification without debugger/control overhead. The same memory gate has failed repeatedly; further VM tests are
stopped under the owner's `/goal` condition. The 10,000-cycle run has not started. Separate restoration passed.

## Run and original verdict

Kernel `60fecdbc` / `m2-driver5-t11`, SHA256
`EBDFCE549EA1DC271498A5F6A38D151AC952ADE9105D476B073A313EB271C851`; agent `6198eee7`, protocol 18, archive SHA256
`21F725DD4995603979CF173C43499477B45E2CC5085404AFC594C5B04CD5293F`. These are the pair from the
[prior diagnostic](t4-memory-attribution-result.md), with its cited four-profile build/test evidence; no new product code.

The row launched at `1d488a3f`: win10-debug3 only, boot Verifier `0x13B`, 256 mixed saves, samples every 64, no optional
memory debugger or controls. [Host output](m2t4clean256b1-host.txt), [original verdict](m2t4clean256b1-verdict.txt),
[cycle outcomes](m2t4clean256b1-cycles.jsonl), [samples](m2t4clean256b1-samples.jsonl),
[final state](m2t4clean256b1-after.txt), [stop receipt](m2t4clean256b1-stop.txt).

- All four save patterns: 192 approved, 64 blocked; zero outcome failures or sampled blocked-byte publications.
- Zero final versions, views, tombstones and private stages; all 256 created versions/views released.
- Zero cap refusals and idle stage-worker passes/timer fires. Verifier remained active, guest alive, driver loaded.
- Median cycle 1,174 ms, p95 1,620 ms, maximum 4,553 ms. This row does not replace the required raw-volume regressions.

## Memory evidence

| Cycle / sample | Module nonpaged bytes | SwUr bytes / live tagged allocations | SUfl bytes | Listed registry entries |
| --- | ---: | ---: | ---: | ---: |
| 64 | 6,361,800 | 6,328,064 / 233 | 130,744 | 230 |
| 128 | 6,401,064 | 6,366,464 / 249 | 165,240 | 241 |
| 192 | 6,426,920 | 6,388,064 / 258 | 297,176 | 248 |
| 256 | 6,451,656 | 6,421,664 / 272 | 405,368 | 237 |
| After idle | 6,380,680 | 6,349,664 / 242 | 398,648 | 241 |

Original module slope: 461.600 B/cycle. Additional tag regressions over the same four points: SwUr 472.500,
SUfl 1,493.450 B/cycle. These are attribution, not replacement verdicts.

Module bytes drop 70,976 from cycle 256 to idle. Idle is 18,880 above cycle 64 and 8,352 above the start, within the
original 65,536-byte endpoint band. The failing assertion is the slope; this drop does not excuse it.
The SwUr live-allocation increase from 233 to 272 is 39 × 2,400 = 93,600 bytes, matching the named-shell size identified by
the previous debugger run. It then drops to 242. The SUfl increases again match 224-byte increments. These observations
are consistent with working-set variation and retained contexts, but do not establish correct ownership or bounded growth.

Tag, module and registry queries are not atomic. In particular, 272 tagged allocations and 237 listed entries at cycle 256
cannot be subtracted to claim 35 leaked or retired entries. Exact owner/reference accounting is still missing.

## Coverage and next action

The [service events](m2t4clean256b1-service-events.txt) contain 12 coverage-query retry warnings and corresponding degraded
notices, plus pending coverage/promotion notices. No stage-reply or journal persistence failures occurred in this export.
One generic operation-1 request took 2,751.5 ms and its reply was Delivered; it does not exercise NO_WAITER cleanup or prove
that a stage allocation caused the historical delay. The [source explanation](t4-coverage-retry-analysis.md) remains valid;
individual degraded durations are unmeasured.

The added post-idle current-Ready assertion is in `3856c943`, passes PowerShell 5.1/self-check validation, and is guarded by
the original row's success. It was not reached after this FAIL, and has no real-row PASS yet.

Prepare exact retained-owner accounting using existing read-only diagnostics first, with bounded test instrumentation only
if necessary. It must add no owning references, cleanup authority or protocol states. Identify the release edge before a
targeted repair; any kernel lifetime/lock/retirement change needs the required Luna review and four WDK gates before boot.
Do not force-delete contexts, clear uncertainty, preallocate merely to hide growth, or change warm-up/thresholds to pass.
Owner authorization is required before another VM attempt because the same gate failed again.

## Independent restoration

[Initial baseline](m2t4clean256b1-baseline.txt) clean; [initial start](m2t4clean256b1-checkpoint.txt) reset EFI.
The [run restoration](m2t4clean256b1-final-restored-state.txt) deleted its disk and verified the base/XML unchanged.
The separate [fresh verification start](m2t4clean256b1restore-start.txt) reset EFI again, and
[independent baseline/restoration](m2t4clean256b1-independent-restoration.txt) passed and deleted the second disk.
Both debug VMs and the validation builder are off. No host-wide configuration changed.
