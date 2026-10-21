# T9 failed-allocation and notification recovery

2026-10-16, `ux/large`, follow-up to dev `45102e57`. This fixes the reported regression in source; Windows/VM qualification remains open. Delivery is `.scratch/ux-large4.bundle`, head `ux/large`; original repository Git remains read-only. See the [local receipt](../../../evidence/2026-10-16/ux-large4-local/result.md).

## Cause and behavior

The regressed allocator persisted every definitive refusal, including requests replayed after the application had already received a failed CREATE. A quarter-MiB global receipt envelope never reclaimed those files. Reboot reconstructed the same population, so later attempts hit `RequireNegativeReceiptSpace`. This contradicted the existing 2026-10-14 owner decision: refusals create nothing and are stateless. The reported sharing-violation CREATEs alone do not establish which underlying policy/requester check returned refusal; new diagnostics identify that reason before backing creation.

New definitive refusals write no metadata. Committed successes still replay the exact object/generation and grant. A late success for an already-failed CREATE goes through the existing exact kind-5 cleanup. Its acknowledged never-attached `None`/validated `Aborted` claim no longer supersedes an earlier save. Its generation remains allocation high-water. Both hot/packed lookup and compaction retain independent effective and high-water frontiers, preventing stale saves from reviving after pruning.

Startup recovery and background batches (16 items) share allocator serialization. A legacy refusal file retires only after held full request/nonce validation, no manifest, exact recorded unissued seed deletion or confirmed absence, and no capacity companion. Its exact metadata identity/length controls deletion. Partial, malformed, inaccessible or conflicting metadata holds that nonce and preserves bytes; it does not consume a global refusal-file quota. Existing refusal storage is inventoried once, charging rounded bytes plus a metadata unit per file (including an empty file); only confirmed exact deletion refunds it. No new refusal files means this population cannot grow through normal saves.

Never-granted/no-manifest records retire their exact ledger only after backing/grant absence and no snapshot/reader obligation. Deletion precedes the in-memory refund; restart/retry cannot refund twice. Unknown or replacement backing remains charged. Completed exact kind-5/private retirement metadata moves from the per-user 1-MiB ledger to the existing conservative shared hot/packed storage envelope before ledger deletion. Exact journal ACKs, replay evidence and generation frontiers remain. Startup reconstructs the shared inventory/debit. Ordinary completed-record policy and integrity holds on unsafe/corrupt accounting authority remain as designed.

Background recovery is bounded by item count. Startup reconstruction and existing hot journal admission scans still scale with retained records; no constant-latency claim is made. Real per-user/total/physical exhaustion still refuses with `not_enough_staging_space`; a refusal-file count is no longer a storage-budget failure. Cleanup uncertainty stays with its transfer, never grants deletion/publication, and is retried.

The notification failure was separate: the allocator emits `Retained + NotEnoughStagingSpace`, but recorder validation accepted inspection-failure metadata only on `Blocked`. Its catch then permanently failed the recorder even for that input error. The closed flag was in memory: each new service instance could fail again on its first retained-space alert; the receipt backlog was the restart-persistent fault. Validation now accepts this exact retained alert without publication/override/handback authority, and invalid input leaves the writer usable. Owner SID/session are required for hub delivery. Actual storage faults suppress delivery, retain the original cause and retry strict recovery on later append/heartbeat with monotonic backoff. Damaged history is preserved unchanged; a reset rotates InstanceId and begins `Start`, sequence 1, zero previous hash. Online empty history also resets explicitly. ACL/link/unexpected-directory failures are never normalized. A failed emission is never queued retrospectively; a disposed recorder stays closed.

All kernel files remain byte-identical to `45102e57`, including its security descriptor/SAL and MSVC `alloc_text` fixes. The grant shim now finds the function definition past its forward declaration and asserts the pragma precedes it; its boundaries, mutation controls and compiler warning gates are unchanged.

## Proved resource refusal — 2026-10-19

The [T4 smoke diagnosis](../../../evidence/2026-10-19/t4-smoke-diagnosis.md) found resource exceptions bypassing the existing
no-allocation proof and leaving requests retryable. The narrow agent repair has an independent
[design review](../../../evidence/2026-10-19/t4-resource-refusal-design-review-sol-high.md), ACCEPT WITH CONDITIONS.
Only a direct `StagedSpaceException` from serialized preparation with a real budget enters the proof. It rereads the exact
manifest, requires healthy accounting and the existing exact unissued cleanup, then confirms both backing and grant absence.
Only successful proof creates the internal marker classified as the existing exact `NoAllocationCommitted` reply.
Post-commit, unknown/locked/replacement, issued/snapshot, faulted-ledger and failed-proof cases remain held/retryable.
Both outcomes preserve the original space-notification cause; no public mutation or negative receipt is introduced.
The legacy null-preparation route retains its cleanup contract and additionally refuses an orphan companion.

This does not change whole-SID capacity allocation, concurrent sharing, limits or product assertions. Component execution
and protected-pair qualification remain separate requirements; the original smoke is still failed and 10k has not started.

## Test contract changes

No tests were removed or skipped and no threshold was loosened. The owner-approved stateless contract replaces these obsolete expectations; exact request/reply mutation, uncertain custody and publication assertions remain.

| Existing expectation | Replacement control |
|---|---|
| Definitive refusal leaves a durable exact file across restart | Refusal/replay creates no metadata, manifest or public bytes; exited/reused owner still refuses |
| A second request can never allocate after a refusal | Serialization remains required; late positive receives exact kind-5 cleanup, no public bytes |
| Altered request cannot reuse a negative receipt | Same assertions against an explicitly constructed legacy compatibility receipt |
| Failed unissued seed retains one MiB forever | Exact ledger removal, equal restored capacity, repeat removal no-op and no double refund |
| Negative file count eventually vetoes all further metadata | Existing storage charged; same/other SID admission succeeds without a count veto |
| Partial/corrupt old negative file refuses whole startup | Exact bytes retained, own nonce held, unrelated admission remains possible |
| Upgrade grants only a fixed extra population of negative files | Large historical population starts and is accounted; normal source creates none |

Added controls cover 200 old failed ledgers at restart, 256 new failed seeds, bounded background recovery with unknown bytes retained, 48 exact kind-5 aborts each in hot/packed modes, predecessor currentness after actual PREPARE/ABORT, high-water preservation, A/B/C compaction/restart barriers, and notification validation/storage/empty-history recovery. The native Windows control reconstructs 96 historical refusals plus partial metadata, then requires normal allocation and an independent SID share.

## Exact Windows/VM retest list

Claude runs the existing lab workflow on `SAFEUPLOAD_DEBUGGEE=win10-debug3` only, applications as standard user **t5actor**. Keep win10-debug2 off; disposable overlay/EFI reset/no TPM/test-signing/Secure Boot/restoration rules remain. Each VM row below runs ordinary, runtime-Verifier and boot-Verifier, fresh label per attempt, independent public-byte observations, ForbiddenByteCount=0 and no Verifier failure. Preserve first failure; stop under the existing lab rules.

Before boot, run feature WDK Debug/Release + PREfast/ApiValidator/import gates (0 warnings/errors), and the complete feature agent Debug/Release × user/SYSTEM matrix with all tests discovered/executed, no skips. Include full `StagedAllocationResolutionTests`, `StagedAllocationRecoveryTests`, `StagedLargeFileNativeTests` (now four rows), `StagedLargeFileTests`, `StagedLargeDefaultsTests`, `NotificationRecordTests`, `NotificationHubTests`, `StagedTransferJournalTests`, `StagedJournalCompactionIndexTests`, `StagedTerminalArchiveTests` and `StagedAttachmentV20AllocationFaultTests`. Windows PowerShell 5.1/native-signature gates apply to the existing harnesses used. No new VM harness is introduced here.

| Row | Steps and required result |
|---|---|
| T9R01 | Preserve the original 42-failure boot's private journal/ledger/negative files as evidence. On a disposable copy start the new service, then make 64 sequential clean new saves in `C:\Protected` using Notepad and Explorer under t5actor. Repeat service restart and full reboot. Valid absent old refusals retire, failed unissued charges disappear exactly once, each clean save publishes exact bytes, no sharing-violation cascade/global Unknown/negative growth. |
| T9R02 | Through existing allocation/attachment failure controls, exercise 64 failures before backing, seed sharing/access failures, and lost PREPARE/explicit ABORT followed by exact kind-5 ACK. After each class, t5actor and a second standard SID save normally while total/headroom permit. Unknown identity, live lease, locked/replacement file stays held and charged only to its owner; no identity adoption, partial publication or second refund. Record request, SID, stage ID, generation, grant and ledger before/after. |
| T9R03 | More than 64 valid historical negatives, one truncated/corrupt canonical file and one partial `.tmp`. Startup and 16-item background passes remove only validated exact objects. Both malformed files remain unchanged and hold their own nonce. Normal new t5actor/second-SID saves succeed. Inject sharing/replacement during receipt/ledger deletion, then release the lock; only exact original objects may retire on retry. |
| T9R04 | A sealed/pending earlier save; late ordinary allocation; PREPARE→ABORT; kind-5 deletion ACK. A becomes current again only after the ACK. Repeat hot and packed/restarted. Separately A old blocked, B later published/disposed, C late kind-5 ACK: drain eligible epoch, compact, restart; B remains the effective barrier, A cannot publish, next allocation exceeds C's generation. |
| T9R05 | Exhaust t5actor's configured SID budget while total/headroom remain available. Require owner-only “not enough staging space” alert and no override; second SID saves successfully. Then release/recover exact obligations and save again. Repeat after service restart/reboot. Tray release/status/heartbeat notifications continue after the resource alert; no “record is closed” cascade. |
| T9R06 | Hold notification checkpoint against replacement long enough to cause storage failure; failed emission remains undelivered. Release the lock and require background/next-emission recovery. For interrupted tail/head and empty history, preserve damaged evidence and require new InstanceId/Start/valid chain. Wrong ACL, hard link, reparse and unexpected directory stay unmodified and suppress delivery until repaired. Restart validates the resulting chain and later owner-only alerts work. |

Also rerun affected [T9L08–T9L11, T9L15–T9L17, T9L19–T9L21 and the full existing large-file list](UX-LARGE-VM.md), existing T5 CREATE/sharing/abort/replay/rename/delete/blocked notification rows, then the required matched-pair milestone and restoration gates. This source review and local diagnostics are not Windows qualification or a readiness/cutover approval.
