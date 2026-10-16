# Unbound journal scaling: component result

2026-10-16. Base `2a2a2b8973bcb30dadbea7a0ec4b669448bbed78`, branch `ux/journal`.
Commits are delivered in `.scratch/ux/journal.bundle`; original Git is read-only.
[Design and limits](../../T11-UNBOUND-JOURNAL-SCALING.md).

Completed unbound transfers leave the active directory and polling scans, with full
exact receipts packed into bounded segments. Selected generation claims include
rename ties and cancellation's separate newer generation. Obligations, required
ancestry and live-epoch receipts remain. Archive recovery/compaction preserves the
committed frontier, latches uncertain authority and retries only metadata. Driver
last close is polled until exact disposal, without another public mutation. Runtime
capability/readiness gates and bound destination-head validation are preserved.

## Measurements

.NET SDK 10.0.400 / runtime 10.0.11, Linux, local filesystem; single observations,
not Windows timing qualification. Setup is outside operation measurements. Baseline
was built from a read-only `git archive` of the unchanged base. The scaling controls
retain 10,000 real records; both distinct destinations and repeated generations are
measured after actual production archival and restart. Bounds are <1 second and
<1 MiB allocation per allocate/seal; pending/discard scans have <512 KiB combined
allocation. The old warm scans alone allocated ~10 MiB each and fail these bounds.

| Operation | Unchanged 10k hot history, warm | Packed archive, distinct destinations | Packed archive, repeated destination |
|---|---:|---:|---:|
| Allocate | 43.861 ms / 9,852,016 B | 1.356 ms / 20,984 B | 6.440 ms / 20,936 B |
| Seal | 90.601 ms / 19,722,632 B | 6.577 ms / 63,736 B | 2.875 ms / 62,440 B |
| Pending scan | 43.043 ms / 10,569,984 B | five pending + discard scans: 1.310 ms / 18,560 B | five: 0.190 ms / 13,560 B |

Normal Debug migration (10k fixture writes plus real packed archival): 2,473.796 /
1,531.149 ms. Archive startup: 359.116 / 256.200 ms. Retained bytes: 21,881,184 /
21,831,298 in six <=4 MiB segments, zero terminal hot manifests. One subsequent
active save remains hot. Feature Release allocate: 1.422 / 1.287 ms; seal: 7.013 /
2.510 ms. Full measurements, per-case outcomes and assembly hashes are in
[component-results.json](ux-journal/component-results.json).

The code confirms repeated whole-directory work and global-gate contention as
history-dependent costs. Redundant metadata write-through is removed while explicit
Flush(true) remains. New serialization/flush/replace timing distinguishes individual
write stalls. The supplied Windows incident's second-scale disk/flush component
cannot be isolated from Linux measurements; the `uxk5t4ord2-*` raw prefix was absent
from the referenced staging evidence directory when inspected. No substitute VM run
was started and no driver timeout, test assertion or workload was relaxed.

## Verification

- Normal Debug focused controls: **63/63 pass**, no skipped cases, build 0 warnings /
  0 errors. Includes 34 archive cases and three retry cases: two 10k controls, exact
  receipts, closure/ties/cancellation/live epoch, corruption/missing/truncated frames,
  committed frontiers, interrupted append/compaction, reparse refusal, held→released
  last-close disposal and persistent-I/O worker backoff.
- Feature Release: build 0/0; **63 pass, five Windows-only bound-index cases fail on
  Linux** (Windows filename comparator / `kernel32.dll`). All 37 new cases pass.
  These failures are retained, not converted to skips or green results.
- Broader diagnostic against existing classes: base and modified source both execute
  243 cases, **135 pass / 108 fail**, identical outcome sets. Failures require Windows
  NTFS, path/share/ACL or native APIs. This is an unsupported-platform diagnostic,
  never the required matrix. Existing tests were not edited.
- Standard `dotnet test` aborts because the sandbox denies its local socket. A serial
  in-process runner invokes the same actual xUnit methods and data, with xUnit
  assertions unchanged. Raw logs, runner, initial failures and interrupted exploratory
  runs remain under `.scratch/ux-journal/`; focused controls are diagnostic subsets.
- `git diff --check` clean. Source-review closure: **ACCEPT WITH CONDITIONS**;
  [design review](ux-journal/design-review.md), [implementation review](ux-journal/implementation-review.md),
  [closure](ux-journal/implementation-review-closure.md). Reviewer ran no tests.

## Remaining limits

This does not qualify a protected driver/agent pair or close T4/T11. The Windows
feature Debug/Release user+SYSTEM legs, real protected 10k replies, native private
archive security and crash/power-loss rows remain. Startup/full compaction are
O(retained receipts); cold storage/index memory grows with necessary live-epoch
receipts and distinct barriers. Segments are bounded; total mandatory history has
no arbitrary refusal cap. Retention deletes only the eligible history defined in
the design. A damaged committed frontier holds for diagnostics/validated restart;
it is never repaired from a digest or silently cleared. Coherent rollback of the
whole private store is outside these local integrity checks.
