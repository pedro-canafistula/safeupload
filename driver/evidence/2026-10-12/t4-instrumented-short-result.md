# T4 instrumented short run — 2026-10-12

**FAIL: memory gate only.** `m2t4reject256a1`, win10-debug3, service `6198eee7` on `fix/t4-journal-recovery-v18`,
unchanged kernel `60fecdbc` / `m2-driver5-t11`, Verifier 0x13B from first load. No further test or 10,000-cycle run is launched:
the same memory-growth gate also failed in `m2t4recover256a1`, so the owner's repeated-failure stop rule applies.

## Results

The [verdict](m2t4reject256a1-verdict.txt) and [cycle outcomes](m2t4reject256a1-cycles.jsonl) record all 256 saves passing:
192 approved and 64 blocked across resave/new/replace/mapped patterns. No cap refusal or Verifier stop, all 256 versions/views
released, no tombstones, zero stage files after idle. The [raw final Verifier query](m2t4reject256a1-verifier/verifier-256-idle.txt)
still verifies SafeUpload.sys with 0x13B. The worker made zero idle passes/timer fires. Median cycle 1,188 ms,
p95 1,773 ms, maximum 3,213 ms. The [stop record](m2t4reject256a1-stop.txt) records completed cycles and exit 1 for the failed gate.

[Service events](m2t4reject256a1-service-events.txt) contain no reply or journal-write failures. One ordinary operation-1 request
completed in 1,146.9 ms and delivered its reply; it has no stage transfer. Therefore neither the historical 5.8-second denial nor
the new NO_WAITER cleanup branch was exercised in this run. The exact-cleanup fault cases pass in the
[Windows agent matrix](exact-agent-matrix-t4-rejected-allocation1-summary.txt), not in this protected workload. Do not claim the
historical delay's cause is resolved.

The cycle row's sampled destination checks pass. They do not replace the separate raw-volume invariant rows, which remain pending.

## Remaining memory failure

The unchanged limit is 4 bytes/cycle. [Samples](m2t4reject256a1-samples.jsonl) give 318.863 bytes/cycle:

| Measurement | Verifier module nonpaged bytes | SwUr bytes | SpUs bytes | Registry entries |
| --- | ---: | ---: | ---: | ---: |
| Cycle 64 | 6,354,504 | 6,320,864 | 3,872 | 223 |
| Cycle 128 | 6,388,776 | 6,354,464 | 3,872 | 238 |
| Cycle 192 | 6,423,000 | 6,388,064 | 3,872 | 251 |
| Cycle 256 | 6,411,120 | 6,378,464 | 3,872 | 253 |
| After idle | 6,375,640 | 6,344,864 | 0 | 239 |

`SpUs` returns to zero and all owned versions/views release. Most module-byte movement follows `SwUr`, the writer-registry tag;
this is distinct from a demonstrated unreleased upper stage. Aggregate counts do not identify the remaining objects or references,
and do not establish whether retention is bounded. The next focused investigation must identify those registry entries and their
owners/references before changing kernel reclamation. No threshold, warm-up window, sample selection or assertion is changed.

## Restoration

The [test disk was deleted](m2t4reject256a1-final-restored-state.txt), base disk untouched and domain XML unchanged.
The [separate baseline/restoration](m2t4reject256a1-independent-restoration.txt) reports `BaselineClean=True` and
`IndependentRestoration=PASS` from a fresh verification overlay, which was also deleted. Both
[test start](m2t4reject256a1-checkpoint.txt) and [verification start](m2t4reject256a1restore-start.txt) record EFI reset.
The test VM is off again; win10-debug2 stayed off. No host-wide configuration changed.
