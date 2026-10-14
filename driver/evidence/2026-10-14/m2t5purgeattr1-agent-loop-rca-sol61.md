**RCA: the idle loop repeatedly selects completed BLOCK records. The restart failure is separate: driver disposal has no durable per-version completion receipt, and the agent’s fallback rejects an already-absent stage.**

Verified at `7ae168804698`, clean checkout; agent/kernel subtree comparisons match the stated commits. No edits, builds, tests or VM actions.

**(1) Idle retries — confirmed, with an evidence correction.**

I decoded event-12 records in the retained [idle ETL](driver/evidence/2026-10-14/m2t5purgeattr1-purge-attribution/purge-attribution/idle.etl), reproducing 26,718 agent creates and 91 paths:

| Path group | Verified count |
|---|---:|
| **64** journal manifests | 141 each = **9,024** |
| 16 `~tmp-N.txt` names | 282 each = **4,512** |
| `Protected\t4` and `Protected\` | **4,512 each** |

Thus **all 64 blocked entries are reread**; only the 16 replace blocks generate public-name probes. The reported “16 manifests; 48 other blocks untouched” is refuted.

The source chain is:

- [StagedTransferJournal.cs:2545](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:2545) includes every `Blocked` record, even after `StageDeleted=true`.
- [MinifilterInterceptor.cs:1445](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1445) dispatches those records directly to cleanup; the loop delays only 250 ms at line 1522.
- [StagedTransferPublisher.cs:733](agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:733) rereads the manifest **before** returning for `StageDeleted`. This explains one manifest open per pass, no warning, and no backoff. The backoff in [StagedTransferRecovery.cs:88](agente/SafeUpload.Agent.Service/Interception/StagedTransferRecovery.cs:88) does not gate this direct branch.

**Probable durable state:** `State=Blocked`, `HandbackState=Verified`, `JustificationWindowClosed=true`, **`StageDeleted=true`**, `StageCleanupStarted=false`, `PendingRename=null`, with the matching blocked-deletion receipt. These records already completed cleanup; the pending-work projection never stops selecting them. This state is inferred from the single-read early-return signature and successful cleanup evidence; the row exported no journal snapshots.

For each replace block, the committed rename stores the old `~tmp-N.txt` source in both `LastRenameReceiptV20.SourcePath` and `NamespaceTombstones`; the transfer names the final target. See [StagedTransferJournal.cs:2467](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:2467). Validation normalizes both historical names at lines **1726 and 1745**, through `RequireManifestPath`’s `Path.GetFullPath` at **1940**.

Windows .NET attempts `GetLongPathNameW` expansion whenever the normalized path contains `~`, including probing partially missing paths. This is verified in the [.NET implementation](https://github.com/dotnet/runtime/blob/v10.0.11/src/libraries/System.Private.CoreLib/src/System/IO/PathHelper.Windows.cs#L23). **Two historical-name validations × 141 passes = 282 temporary-name probes**, with matching directory probes. The observed 2.35 passes/s fits work time plus the 250 ms delay. Approved records are excluded from ordinary pending work.

Harness correction: [cycles-actor.ps1:64](driver/scripts/t4/cycles-actor.ps1:64) performs a held-handle `FileRenameInfo` replacement through `SetFileInformationByHandle`, rather than calling `ReplaceFileW`.

**(2) Released-stage restart bookkeeping — confirmed.**

[StagedTransferPublisher.cs:502](agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:502) returns when disposal reports `Held=true`, leaving `StageDeleted=false`. Ordinary Released entries receive no subsequent live-loop disposal attempt.

The driver later checks the exact volume/file identity, marks deletion, closes its backing and frees the stream: [StageStream.c:5818](driver/SafeUpload.Minifilter/StageStream.c:5818), **5884**, **1496**. It records aggregate counters, without persisting a per-transfer delete receipt.

Startup retries disposal at [MinifilterInterceptor.cs:1652](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1652). `RequirePrivateStagePath` then calls `GetAttributes` on the absent leaf at **Publisher:1010**, before the absence-capable cleanup helper. All **192 distinct warning events** have that stack; completion at **Publisher:512** is never reached.

`Held=0` is insufficient deletion evidence: [StageStream.c:6958](driver/SafeUpload.Minifilter/StageStream.c:6958) means no matching listed stream, potentially before teardown finishes. The [8-byte reply](agente/SafeUpload.Agent.Minifilter/Protocol.cs:1069) carries only size and Held. Counters, missing paths and digests cannot reconstruct exact deletion authority.

**Minimal correct fixes and controls:**

- Exclude completed blocked cleanup from pending dispatch while retaining manifests, receipts and generation tombstones. Validate historical names lexically without filesystem short-name expansion; retain exact live-object checks at authorization/mutation boundaries.
- Make released cleanup absence-tolerant, but finish exact bookkeeping only from a durable receipt binding **driver epoch, transfer, destination generation, full stage identity, rename count and successful disposition/lifetime completion**. Persist/replay that receipt until acknowledged. Missing or conflicting evidence remains a named hold.
- Route genuinely unfinished bookkeeping through monotonic bounded backoff; park evidence-dependent holds. Neither timers nor retries authorize progress or repeat publication/deletion.

Required new regression controls, expected to fail before these fixes:

- **All eight `resave/new/replace/mapped × approve/block` patterns:** after cleanup, repeated publisher passes perform no per-entry work; rename receipts/tombstones remain usable. Include occupied targets, name reuse and BLOCK→resave.
- **Released cleanup:** driver-held publication → exact driver deletion → service restart; matching receipt completes bookkeeping once, with no extra public mutation. Inject receipt/completion persistence failures and lost replies.
- **Negative recovery:** wrong epoch/generation/identity/rename count, replacement/reparse objects, access errors and absent stage without receipt remain held. Pending work backs off; terminal work stops.

Extend the existing [publisher disposal tests:554](agente/SafeUpload.Agent.Tests/StagedTransferPublisherTests.cs:554), [hand-back recovery tests:185](agente/SafeUpload.Agent.Tests/StagedHandbackTests.cs:185) and [scan controls:1094](agente/SafeUpload.Agent.Tests/StagedTransferJournalTests.cs:1094).

**Kernel/wire impact:** defect (1) is agent-only. Exact driver-delete recovery for (2) needs kernel receipt retention and a negotiated wire extension; an agent-only missing-file catch cannot supply that evidence. Batch its accounting, replay and unload obligations with `T5-RECOVERY-HOLDS.md` and `T5-VOLUNTARY-UNLOAD.md`. Historical entries lacking receipts cannot be retroactively certified from this row’s aggregate counters.