# Phase 5 final pair review — 5ebe139a

**Verdict: ACCEPT WITH CONDITIONS.** Static review of the requested driver and agent diff against 9578f937. No source changes, build, VM, or tests.

**No P0/P1 found.** I found no path where the standard-user adversary can get unapproved bytes into a protected local-NTFS destination while coverage is Ready, no receipt consumer that can clear a newer alias/policy probe, and no promotion of a replaced base-stream incarnation while its own or a sibling incarnation has writer state. Rename churn remains gated and queued for retry. Retirement waits for no stage handles, file objects, or sections; it checks DeletePending before retiring, and a retired current view is detached. Sealed prior versions and tombstone metadata remain allocated through unload, so I found no dangling view/tombstone reference; unload’s drain and null-safe backing close cover retired streams. Journal scan hits cannot be changed by a standard user under the protected journal ACL, and class writes invalidate the corresponding cache entry.

## P2 findings

- **Privileged stale projection — accepted trust boundary.** [StagedTransferJournal.cs:219](/home/victor/Work/safeupload-wt-gen4/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:219). If trusted SYSTEM/admin replaces a manifest with different valid state (or invalid content) while preserving length, creation time, last-write time, and attributes, a cache hit skips the direct open, ACL, link-count, reparse, and parse checks. DestinationVersionsAsync can then use the old generation, tombstone, or reservation projection for a new create/publication decision until that entry is written again or the process restarts. This is outside the stated standard-user threat model and is the accepted freshness trade-off.

- **Cache clear can restore O(history) reads.** [StagedTransferJournal.cs:231](/home/victor/Work/safeupload-wt-gen4/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:231). With more than 50,000 retained manifests and a stable enumeration order, the clear-at-cap can recur during each scan; a 50,001-entry history can therefore cause near-full disk/ACL/JSON rereads per scan. ReadPendingAsync holds _gate for each miss, so large histories can delay stage-state operations. Memory remains bounded; this is a performance and liveness-cost condition.

- **Sealed-stage query context.** [StageStream.c:1391](/home/victor/Work/safeupload-wt-gen4/driver/SafeUpload.Minifilter/StageStream.c:1391). A sealed reopen synchronously calls FltQueryInformationFile while holding StageNamespaceResource, without checking IoGetTopLevelIrp(). If a recursive create reaches this branch with a non-null top-level IRP, the query can deadlock and hold the namespace lock. I found no ordinary standard-user direct-open path establishing that context, so this is conditional, not a reproduced P1. The query’s successful result is also the admission point: a create that passes it before File.Delete may complete afterward and counts as a pre-delete open.

- **Per-boot stage-version cap.** [StageStream.c:26](/home/victor/Work/safeupload-wt-gen4/driver/SafeUpload.Minifilter/StageStream.c:26), [StageStream.c:1399](/home/victor/Work/safeupload-wt-gen4/driver/SafeUpload.Minifilter/StageStream.c:1399), [StageStream.c:2342](/home/victor/Work/safeupload-wt-gen4/driver/SafeUpload.Minifilter/StageStream.c:2342). Retired versions stay on StageStreams through unload and do not return a StageStreamCount slot. After 128 successful stage versions in one driver lifetime, the next version is refused with insufficient resources, even if prior BLOCK stages were deleted. This is bounded fail-closed over-gating, not unbounded growth.

- **Generation rollover.** [StageWriters.c:5295](/home/victor/Work/safeupload-wt-gen4/driver/SafeUpload.Minifilter/StageWriters.c:5295). After 2^31 policy commits, signed LONG ordering can stop advancing the activation stamp; the promotion generation check then keeps entries gated. This is the known P2 rollover condition.

## Release-note conditions

- Qualify only Windows 10 build 19045.2965, local fixed NTFS; installation needs reboot.
- Keep the accepted freshness boundary explicit: only trusted SYSTEM/admin preserving all four manifest stamp fields can retain a stale scan projection.
- State the 128 stage-version per-driver-lifetime cap and that retirement does not reclaim the slot before unload.
- State the MVP evidence limit: NoUnapprovedByte is based on sampled fresh/uncached raw-volume reads and the final image, not a continuous proof; keep staging off any build real users can receive.
- Document fail-closed behavior: scopes with pre-scope writers remain Activating and never Ready; sticky Unknown remains until reboot.
- Carry forward the known conditions: reclaim-worker rescan CPU churn under unresolved probes; C05DenialLedger deferred; lower mutation ledger and continuous coverage proofs deferred; taint-on read-classification stall risk; signed-LONG generation rollover.
