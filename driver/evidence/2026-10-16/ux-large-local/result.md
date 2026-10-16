# T9 local implementation receipt

2026-10-16, `ux/large`, base `62fd1673`. **Opt-in unbound MVP prototype; T9 remains open.**
No Windows builder/VM was contacted. Claude owns Windows execution as standard user `t5actor`.
Original Git refs/index and `.ai-memory.toml` were not edited; source commits are delivered in `.scratch/ux/large.bundle`.
The bundle delivery receipt identifies the resulting commit/hash. Local builds used the modified worktree before that source commit;
Windows exact-source gates must use the bundle commit.

The [design](../../../UX-LARGE.md) describes configurable per-SID/total/floor reservations, exact identity-bound capacity grants,
durable content/metadata accounting, restart/orphan holds, failed-prefix refusal, owner notifications, parser processes and streaming ZIP text.
The [Windows list](../../../UX-LARGE-VM.md) gives T9L01–T9L21 and pre-boot/native/matched-pair/restoration conditions.

## Local verification

- Feature agent Tests/Core/Network/Minifilter/Service Debug and Release builds: **0 warnings / 0 errors**; tray Release cross-build also **0/0**.
  SDK `/home/victor/Work/safeupload-tools/dotnet/dotnet` 10.0.400, cached packages, single MSBuild node, artifacts under `.scratch/t9`.
- **248/248 actual focused test/data rows passed**, zero skipped selected rows, nine actual classes. This is an in-process reflection diagnostic,
  not standard VSTest discovery/execution. VSTest's first attempt aborted because the sandbox denies its TCP listener; that failed receipt is retained.
  Archive integrity methods reside in the partial `ArchiveInspectionTests` class. Focus includes budgets/restart/isolation/metadata/failure seals,
  archive integrity/coverage, strict text decoding, streaming Word/scanner, work budgets, snapshot copies, replacement retries and inspection failures.
- Three new `StagedLargeFileNativeTests` rows compile but **were not executed on Linux**: manifest-before-grant large-seed replay and unknown-create
  refusal/retry after restart. They require native Windows execution plus protected VM observations.
- Actual production grant validator compiled/executed with **cc and clang**, strict warnings and UBSan: >2 GiB, exact IDs/GUID, boundaries,
  signed overflow, alignment/padding and a required failing mutation. T5 namespace/allocation/manifest/reconcile shims/self-checks pass.
- T4 verdict self-check, exact-agent-matrix 21 controls, driver import self-check, UX outside/activating self-checks pass.
  T4/import self-check logs deliberately contain failing fixture verdicts. They do not turn the known T4 row or a new driver binary green.
- [Kernel source API audit](api-audit.txt): no new external DDI call names. **No WDK, PREfast, ApiValidator, final `.sys` import check,
  Windows agent four-leg matrix, Job Object/native controls, product VM or Verifier result is claimed.**
- Existing tests/assertions/thresholds were preserved. The first diagnostic exposed one real exact-expansion ZIP timeout caused by repeated strict
  decompression; a bounded four-MiB text replay fixed it. Fifty other first-run errors were runner fixture construction. All first receipts are retained
  with a [concise failure record](first-failure-summary.json); no failed receipt was overwritten.

[Verification/hashes](verification.json) records exact local DLL/probe hashes and raw log paths/hashes. Raw inputs/logs/builds and all attempts remain
under `.scratch/t9`, per the session's scratch instruction. These Linux artifacts are not Windows delivery packages or a qualified pair.

## Measurements

AMD Ryzen 9 3900X (12 cores/24 logical CPUs), 33,546,350,592 bytes physical RAM, Linux x86-64, .NET 10.0.11.
Fresh process per input; 256 MiB managed GC heap ceiling; file/host cache and other local workload uncontrolled. Probe policy is 4 GiB/ten minutes,
all categories, complete streaming parser/scanner passes. Product defaults remain 20 MiB/five seconds.

Synthetic decoded payloads are neutral text; DOCX has one very large text node and ZIP32 stores one plaintext member without compression.
Every case completed with zero findings/no failure. Files include tiny container overhead. Throughput uses actual container bytes.
Peak is process peak working set sampled before the post-timing SHA pass; cumulative managed allocation is separately preserved in JSON.
These steady peaks support bounded streaming on this corpus; they do not prove hostile parser bounds or Windows Job Object behavior.

| Payload MiB | Format | Seconds | MiB/s | Peak working set MiB |
|---|---|---:|---:|---:|
| 64 | .txt | 3.371 | 18.99 | 53.50 |
| 64 | .docx | 7.157 | 8.94 | 70.00 |
| 64 | .zip | 4.985 | 12.84 | 69.25 |
| 512 | .txt | 24.017 | 21.32 | 54.14 |
| 512 | .docx | 51.388 | 9.96 | 70.04 |
| 512 | .zip | 34.194 | 14.97 | 70.24 |
| 2048 | .txt | 96.656 | 21.19 | 54.76 |
| 2048 | .docx | 246.406 | 8.31 | 69.66 |
| 2048 | .zip | 153.927 | 13.31 | 67.26 |

[All nine measurement rows](measurements.json) include input SHA-256, byte length, elapsed time, cumulative managed allocations and Core assembly hash.
Scope excludes staging/seed/snapshot/publication/hand-back, and therefore cannot decide whole-operation UX or budget defaults.
The earlier complete nine-case run remains in `.scratch/t9/measure`; the table uses the final Core run in `.scratch/t9/measure-final`.

Reproduce with the committed `driver/scripts/LargeFileMeasure` Release probe (feature flag) and `driver/scripts/ux/measure-large.py`
using `--dotnet /home/victor/Work/safeupload-tools/dotnet/dotnet --probe <probe.dll> --scratch .scratch/<fresh-label>`.
Build with `--artifacts-path .scratch/<fresh-build> -p:RestorePackagesPath=/home/victor/Work/safeupload-tools/nuget-cache -m:1 -p:BuildInParallel=false`.
Do not reuse receipt labels or count these probes as product qualification.

## Review and remaining work

Sol 6.1 xhigh: [design acceptance with conditions](design-review-sol61.md), [initial implementation REVISE](implementation-review-sol61.md),
[source corrections accepted](implementation-final-sol61.md), [final integration accepted with conditions](integration-review-sol61.md).
Review and component results remain separate from Windows qualification and final adversarial review of the working pair.

The mode is disabled unless explicit storage/parser settings are supplied. Proposed resource defaults remain an owner decision:
**total min(32 GiB, 10% available); per-SID min(8 GiB, total/4); floor max(1 GiB, 5% volume); parser 256 MiB; seed deadline 120 s.**
Four-copy charging leaves about one quarter as content; a 2 GiB protected save needs more than 8 GiB per SID including metadata and a suitable
inspection size/deadline. This is a conservative trial recommendation, not approval or automatic activation.

Substantial limits remain: one whole-remaining-SID content lease can refuse concurrent same-SID/temp saves; linear synchronous MVP seeding can
hit the foreground RPC deadline/delay other creates; legacy metadata migration/retirement and old-service downgrade are not implemented;
metadata charges remain; ZIP64/7z and nested seek members over 8 MiB explicitly refuse. Job Objects are resource containers, not token sandboxes.
Legacy mode retains 16 MiB until cutover. Required clean large/seed/concurrent UX failures leave T9 open even with zero forbidden bytes.
