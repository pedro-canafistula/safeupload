# T4/T11 unbound terminal archive — independent implementation review

2026-10-16. Requested reviewer: Sol 6.1, xhigh. Reviewed the working tree over `2a2a2b8973bcb30dadbea7a0ec4b669448bbed78`, including the final committed-end control page and recovery reflush change in `StagedTerminalArchive.cs`, journal/compaction/security/timing changes, publisher/recovery/worker integrations and `StagedTerminalArchiveTests.cs`. Read-only review; no tests, source changes, Git writes or VM actions by the reviewer.

**Verdict: REVISE one worker-recovery issue below.** No remaining byte-authorization or generation-retention blocker was found in the inspected archive mechanism. This is source review, not a test result or protected-pair qualification.

## Required correction

**Recoverable archive maintenance I/O can permanently stop the live workers.** `MinifilterInterceptor.cs:1440`–`1442` invokes released disposal, archive migration and the audit outside the per-transfer catch; `:1507` similarly invokes discarded archival before the cleanup loop's catches. `ArchiveCompletedBatchAsync` resets its index-load state and rethrows append/flush/hot-deletion failures. A transient cold-segment sharing error or hot-manifest deletion failure therefore faults the publication or cleanup task. Those task failures are observed only when the receive/port loop finally ends (`:624`–`:652`); receive/admission can continue while no worker makes further progress, even after the original transient error disappears.

Handle maintenance failures at the live-loop boundary: cancellation exits normally; integrity failure preserves the journal's latched hold and reports an actionable diagnostic promptly; recoverable I/O retries unfinished metadata work with bounded backoff without terminating publication/discard progress. Revalidation must finish before further authority is used. Do not replay a public save. A focused control should inject one archive I/O failure and then remove it, proving the worker reaches a later unrelated save/cleanup and completes the exact original archive once.

## Findings resolved by the implementation

- The 4 KiB control page checksums the committed end and refuses control loss, frame-boundary truncation and damaged committed frames. Bytes beyond a valid old frontier remain uncommitted. Frames/data/frontier are flushed before inventory selection and hot removal; recovery reflushing exact duplicates covers a prior failed flush whose complete bytes remained visible.
- Startup validates before handshake. Selected reads check the retained payload digest, GUID/length, schema and committed range. Runtime detected damage latches the journal gate; index reconstruction cannot silently use partial membership. Sixteen-frame slices add bounded live auditing.
- Full snapshot comparison and the immutable replacement boundary preserve exact receipts. Archive claims and compaction include cancellation generation, rename barriers and ties; reference closure spans hot/archive rows and head obligations. Current accepted-epoch archive receipts are pinned independently of timestamps. Existing hot compaction semantics remain separate.
- Private-directory and segment checks reuse trusted-owner/DACL, no-follow, single-link and byte bounds. Explicit `Flush(true)` remains at every private-temporary caller, including the unchanged bound allocation/security/head paths, after removing temporary `WriteThrough`.
- In the concrete unbound call routes inspected, confirmed publication audit/notification precedes disposal/archive; blocked recovery notification precedes cleanup. Maintenance skips confirmed/pending caller progress. I found no demonstrated interleaving where the new direct terminal archive calls outrun those obligations. The independent notification store is retained.

## Remaining focused validation conditions

- Exercise live released-stage polling with a gate returning held, then released after last close: one public mutation/outcome, stage absence acknowledged, eventual archive, no repeated inspection. Existing startup-disposal assertions alone do not prove this new live route.
- Exercise a failed archive flush and an exact hot/archive duplicate in an already registered segment; prove recovery reflushing precedes hot deletion. Also cover segment rollover/inventory failure and post-compaction cancellation with subsequent fresh-index use.
- Keep the strict committed-truncation, conflicting-duplicate, selected coherent-rewrite, current-epoch, cancellation, mixed ancestry and 10k real-record controls. The Linux symlink control explicitly returns on Windows, so it does not establish Windows reparse/ACL/owner admission; cover those in the Windows user/SYSTEM checkpoint.
- Update `design.md` to the implemented control-page/inventory/reflush/idle-audit contract; its original incomplete-tail paragraph is stale.

No V30 activation/import, bound-head shortcut, VM authorization, capacity threshold change or final milestone acceptance is implied.
