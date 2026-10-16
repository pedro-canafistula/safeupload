# T11 / T4: unbound transfer journal scaling

2026-10-16, `ux/journal`, base `2a2a2b8973bcb30dadbea7a0ec4b669448bbed78`.
Scope is the MVP unbound staging line. No bound V30 storage/provider, activation,
capability, driver, destination-head validation or qualification change.

## Problem and observed cost

Allocation and seal destination checks enumerated every retained transfer manifest
under the global journal gate. Publisher/discard polling repeated that enumeration.
Even a warm parsed-entry cache allocated one directory entry/claim projection per
historical save. Every journal replacement evicted its cache entry, and publication
competed for the same gate. This is a demonstrated O(history) cost and convoy source.
The owner's `uxk5t4ord2-*` Windows report records second-scale journal wait/scan/write
and a missed reply at cycle 532; those raw files were not present in this checkout.
The Linux measurements below do not identify the Windows disk's individual flush
latency or qualify the driver's five-second reply budget.

Temporary metadata files also used `WriteThrough` AND explicit `Flush(true)` before
rename. Keep the explicit durability barrier; remove redundant write-through on
these private temporary files and archive append handles. Public byte writes and
finite metadata-rename retries are unchanged. Request timing now separates
`journal-serialize`, `journal-flush`, and `journal-replace`, as well as wait/scan/write.

## Active set and durable receipts

Only exact completed unbound records leave the hot `*.json` set. Eligibility requires
no pending rename/cleanup, confirmed stage absence, and one of:

- Released with disposal recorded, or justified/blocked with verified hand-back,
  closed justification window and the matching exact deletion receipt.
- Discarded, or an acknowledged discard with every exact cleanup prerequisite done.
- Cancelled with the exact cancellation receipt and stage absence recorded.

Unresolved transfers and all bound/security/provenance records stay on their existing
paths. Caller completion supplies the complete expected snapshot and is checked again
under the journal gate. Terminal recovery uses its validated snapshot without per-entry
I/O; the separate maintenance pass performs fresh checks before archival. Bound ACK
recovery stays independent of this terminal no-op. Publisher maintenance skips
outstanding native-success/outcome and journal-progress work. Notification delivery remains in its independent durable
notification store; archival never deletes that store or replays public mutations.
Released last close is polled while hot so a formerly driver-held stage can eventually
finish disposal. Private archive I/O failures use monotonic 250 ms to 8 s backoff;
integrity failure disables staging readiness and retains an actionable diagnostic.

`completed/` is private and no-follow, with the same owner/DACL/single-link checks as
the hot journal. Packed segments are at most 4 MiB; payloads at most 128 KiB. A
checksummed 4 KiB control page selects the committed end. Each versioned frame binds
length, transfer GUID and SHA-256 to a complete validated manifest. Append frames,
write the new frontier, then `Flush(true)` BEFORE publishing the index/removing hot
copies. New segments also enter a tiny atomically replaced inventory frontier before
hot deletion; missing whole segments cannot become an empty generation index.
Startup validates the inventory, every selected frontier and every committed frame
before staging can reconcile/admit work. Bytes past a valid older frontier are
uncommitted; ambiguous/corrupt committed bytes are held. Exact duplicate hot/archive
records must agree and are flushed again before consolidation, including recovery
from a failed flush whose bytes were visible. Conflicting duplicates refuse startup.

The in-memory ID/offset/digest and per-path maximum-claim indexes are published only
after complete validation. Every selected receipt is freshly checked against its
expected location/digest and committed frontier. Rename tombstones, maximum ties and
the cancellation receipt's separate newer generation participate in the index.
An idle slice validates up to 16 retained frames per publisher pass. Unrelated archive
corruption is detected at startup, full compaction, exact/selected reads or that idle
sweep; active and bound-head validation retain their existing paths. An integrity
error latches the journal gate until validated restart, including when the ordinary
startup compaction caller logs/catches an exception. An uncertain metadata append
must fully reload/revalidate before another authoritative access.

## Retention and restart

The archive is segmented, not globally capped: necessary receipts/barriers never
cause a new arbitrary capacity refusal. The existing retention cutoff is one day
before the current boot. Complete obsolete records older than that cutoff may be
deleted, keeping maximum-generation ties, all exact parent/delete/allocation/seed
reference closure and external pending-head/receipt owners over hot + archived
records. Known current-epoch archived receipts are pinned independently of wall time
until exact durable drain; absent epoch proof also pins them. Required generation
barriers remain even after receipt-history deletion. Startup is O(retained receipts);
foreground scans are O(active), with indexed selected archive-claim reads. Memory
still accounts for retained receipt IDs and distinct generation barriers.

Compaction flushes a retained replacement segment and atomically replaces that one
segment. Every protected record survives either image. Offsets are invalidated even
if replacement returned before an error. Partial compaction is safe: already-removed
obsolete history is not authority for any surviving entry. Existing hot-manifest
compaction behavior and the bound path are preserved.

## Component evidence and remaining gates

Focused Linux controls and measurements: [result](evidence/2026-10-16/ux-journal-result.md).
The [terminal-recovery follow-up](evidence/2026-10-16/ux-journal2-result.md) restores
read-free terminal dispatch while maintenance retains exact archival validation.
The [outcome-scaling follow-up](evidence/2026-10-16/ux-journal3-result.md) removes a
separate full-history audit read from legacy notification work reached by public
file observation. Positive recent-event requests read complete UTF-8 lines from
the tail without rewriting history. The same audit lock guards publication's
outcome append, so this also removes that source of contention. Full-history
requests and legacy UTF-16/32 queue compatibility keep their existing full scans;
no transfer archive, exact receipt, barrier or retention contract changes.
Independent design/implementation reviews and closure are linked there. Existing
assertions and thresholds remain unchanged. These are component results, not a
Windows user/SYSTEM matrix, a matched protected-pair T4 10k verdict, or T11 closure.
Windows four-leg checks, the protected 10k row and crash/power-loss qualification
remain required. Unsupported-platform diagnostic failures are retained and compared
with the unchanged base; no test is skipped or weakened to turn those green.
