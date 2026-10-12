# T4 memory investigation and recommended direction — 2026-10-12

**Recommendation:** identify the owners of retained allocations in one bounded diagnostic before changing reclamation.
Current evidence establishes a failed gate, not a new kernel leak. No code, assertion, threshold, sample window or VM state
is changed by this analysis. Further VM runs remain stopped under the owner's repeated-failure rule.

**Execution update:** the owner subsequently approved this diagnostic ("Great, do it"). The optional local-KD harness uses the
unchanged `60fecdbc` kernel and `6198eee7` agent, with their retained hashes verified. The exact driver's PDB GUID/age matches.
It enables local debugging only on the throwaway disk, retains context/pool/Verifier output, checks full identities for fixed
and disjoint corpora, and observes voluntary unload only after the original row's results are exported. It is attribution,
not milestone qualification. No kernel change or host-wide configuration is involved.
The [Windows PowerShell 5.1 gate](harness-windows-gate-t4-memory-attribution1.txt) passes all 19 self-checks; the
[final helper check](harness-t4-memory-final-helper.txt) additionally validates the final output checks and real NTFS identity controls.
The [completed diagnostic and separate restoration](t4-memory-attribution-result.md) now provide context-type and unload accounting.
Both investigated tags return to zero at unload; bounded retention while loaded remains open. This supersedes the pending-execution
status above, without changing the qualification gates or authorizing speculative reclamation.

## What the evidence separates

The latest [short result](t4-instrumented-short-result.md) has 256/256 successful outcomes, zero private stage files,
versions/views/tombstones after cleanup, and an idle stage worker. It fails the module-pool slope. The preceding
[short failure](t4-allocation-reply-diagnosis.md) also had reply errors; that failure path did not recur in the latest run,
so the original delay's cause and protected fault-path qualification remain open.

All three runs below use kernel `60fecdbc` (`m2-driver5-t11`). Slopes are ordinary least squares over the existing gate's
samples: cycles 64–256 for the shorts and 1,000–10,000 for the long run. Tag slopes are additional analysis, not new verdicts.

| Run | Module slope, B/cycle | SwUr slope | SUfl slope | Overall outcome |
| --- | ---: | ---: | ---: | --- |
| [recover256a1](m2t4recover256a1-samples.jsonl) | 192.225 | 187.500 | 1,735.650 | 255/256; one leftover stage |
| [reject256a1](m2t4reject256a1-samples.jsonl) | 318.863 | 322.500 | 1,428.000 | 256/256; memory gate failed |
| [boot10k1011a2](../2026-10-11/m2t4boot10k1011a2-samples.jsonl) | 1.501 | 0.160 | 296.479 | 8,740/10,000; journal/cleanup failures |

The older [10k module-pool PASS](../2026-10-11/m2t4boot10k1011a2-verdict.txt) is neither an overall pass nor proof that all
driver-related pool returned to its baseline. In that run SUfl grew from 651,320 bytes at cycle 1,000 to 3,361,272 at cycle
10,000, with 3,360,824 after idle. The present gate evaluates only Verifier's module bytes
(`driver/scripts/Invoke-StageCycles.sh:375–387`), although samples retain the other tags.

**SwUr: changing live registry occupancy is the leading explanation, not yet a proved bound.** In the latest run its live
tagged allocations go from 225 to 240 after idle, while listed entries go from 223 to 239. Across those samples,
`SwUr bytes = 5,768,864 + 2,400 × live tagged allocations`. Named-shell allocation and the fixed compact pool are in
`60fecdbc:driver/SafeUpload.Minifilter/StageWriters.c:735–748,6721–6734`. The non-simultaneous tag/status queries cannot identify
which remaining reference owns which entry. They provide no evidence of an accumulating retired-entry cache.

The short gate has only four points. A single 2,400-byte allocation appearing only at the last point contributes
11.25 B/cycle to that regression, already above the 4 B/cycle limit. This explains sensitivity; it does not excuse either
failed verdict or authorize a wider threshold. Latest idle module bytes are only 21,136 above cycle 64, within the unchanged
65,536-byte endpoint band; the slope is the failing part.

**SUfl: an unresolved retention category that must be attributed.** Across all three runs, almost all changes in its live
allocation count correspond to 224 bytes per allocation (the residual varies by only 80 bytes). The general tag covers
multiple context types and direct driver allocations. `60fecdbc:driver/SafeUpload.Minifilter/Context.c:103–150` registers
instance, stream, handle and transaction contexts under it; `:600–651` allocates/attaches a nonpaged stream context and
`:158–196` supplies its cleanup. Type, stack and reference ownership are absent from the recorded aggregates.

Windows contexts can remain attached until the underlying object is torn down; driver-acquired references must still be
balanced. See Microsoft's [reference rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/referencing-contexts)
and [context deletion rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/deleting-contexts).
Filesystem retention is therefore a plausible explanation, not an exemption or a demonstrated cause here. The workload adds
journals, hand-backs and new public identities; repeatedly saving the same pathname does **not** hold that identity set fixed.

## Alternatives and minimum useful next step

| Approach | Assessment |
| --- | --- |
| Repeat short runs or increase limits | Does not identify ownership; risks accepting unexplained growth. |
| Add periodic trimming, force-delete contexts or clear uncertainty | Adds lifetime races and can discard writer evidence needed for privacy. |
| Rewrite the registry or journal now | Broad change without evidence that it addresses this memory failure. |
| Attribute retained objects, then repair only a demonstrated owner/reference defect | Recommended: smallest causal experiment and narrowest eventual fix. |

1. Obtain allocation-type/stack/reference attribution using existing kernel debugging facilities if available. The retained
   `verifier /query` output contains aggregate statistics, not allocation records. If existing facilities cannot supply the
   missing information, prepare temporary feature/debug instrumentation: context creates/attachments/cleanup by type;
   registry allocation/free, retired-but-live and cache-reference balances; a bounded sample of unresolved owners.
   Diagnostics must introduce no owning references, new lock ordering, per-save disk logging, protocol states or cleanup authority.
2. In a separately approved diagnostic, measure idle activity, repeat opens/closes on a fixed set of **physical identities**,
   compare a disjoint corpus, and capture close/settle plus teardown accounting where supported. Then attribute the actual
   staged workload, including its new journal and public identities. These controls supplement the existing mixed-save row;
   they do not replace it, alter its corpus or subtract background activity from its verdict.
3. Use the result to choose the fix. A driver reference surviving its documented release edge requires a targeted lifetime
   repair. Attached contexts require proof of their owners and release/bounded-retention behavior; close alone does not prove
   that the filesystem destroyed a stream. If growth is bounded working-set variation, document that result before proposing
   any change to the short gate's interpretation. Such a gate change needs the owner's decision and is not approved here.
4. After the cause is demonstrated and any fix is reviewed/built, rerun the unchanged qualification: short gate, 10k,
   required raw-volume regression rows, Verifier and separate restoration. T4 remains open until all assertions pass.

Keep allocation-reply latency as a separate obligation. The existing phase timings can identify journal wait, scan, write or
reply delay if it recurs. Historical-directory scans are a performance candidate, not an established cause of this pool failure.
The NO_WAITER cleanup branch still needs protected fault-path qualification; a clean short run did not exercise it.

## Independent lifetime review

Luna 6, max effort, independently inspected the tested kernel and evidence on 2026-10-12. It agreed with attribution first and
found no evidence justifying an additional reclamation path. The existing cache release requires exact quiescence and a
successful locked prune, clears only the matching cache under WriterLock, and drops the reference after unlocking
(`60fecdbc:StageWriters.c:2428–2455,6581–6597`); context teardown separately releases writer/cache ownership (`:2776–2816`).
Luna identified the same SUfl accounting gap and recommended bounded diagnostics with no additional owning references or
lock-order change. This is a review of the direction, not approval or runtime qualification of an unimplemented patch.
