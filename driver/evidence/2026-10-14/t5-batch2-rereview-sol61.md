**REVISE.** Sol 6.1 xhigh independent review at `ae2d0b3c`. Checkout unchanged; no edits, builds, tests or VM actions. This verdict concerns the scoped design delta.

Previous findings:

| Finding | Status and evidence |
|---|---|
| Original 1: seal request persistence | **Resolved in design:** atomic intent plus `SealPending`, exact resumption and all entry points. [§3](driver/T5-RECOVERY-HOLDS.md:101) |
| Original 2: exposure/lifetime transitions | **Resolved in design:** explicit attestations, flag/pin transitions and cancellation-CLOSE hold. [§4](driver/T5-RECOVERY-HOLDS.md:142) |
| Original 3: retained residue/unload conflict | **Resolved conservatively:** residue still vetoes unload; custody exception remains unapproved. [Default](driver/T5-RECOVERY-HOLDS.md:187) |
| Original 4: permanent retirement/quarantine conflict | **No longer applicable after deferral:** existing V20/EPOCH_DRAINED and post-ACK progress remain. [Unload contract](driver/T5-RECOVERY-HOLDS.md:360) |
| Original 5: live-owner sealing requirement | **Resolved in design:** historical-owner sealing; live authority remains required for fresh op15. [Authority table](driver/T5-RECOVERY-HOLDS.md:71) |
| Re-review 1: retirement storage CREATE | **No longer applicable:** retirement writes deferred; bookkeeping CREATE preserved. |
| Re-review 2: retirement-only bootstrap | **No longer applicable:** normal authentication/op11 preserved. |
| Re-review 3: permanent refusal policy | **No longer applicable:** permanent-refusal mode excluded. All three remain deferred, rather than fixed. [Deferrals](driver/T5-RECOVERY-HOLDS.md:375) |

1. **High — Accepted Release has no cancellation transition for a legitimate rename.**  
   The immutable binding and [state progression](driver/T5-RECOVERY-HOLDS.md:249) omit cancellation. Yet committed rename changes generation/count and clears disposal in the [driver](driver/SafeUpload.Minifilter/StageStream.c:4704), while the [journal](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:2479) returns the transfer to Sealed. Rename after Release but before DeleteClaimed can strand the old record, consume capacity and prevent unload.  
   **Required:** define exact pre-disposition revocation, old-request replay behavior, ownership drain and subsequent release of the newly approved tuple. Freeze conflicting transitions after DeleteClaimed. Recommend preserving normal rename behavior; refusing these renames would require an owner decision.

2. **Medium — Retirement before Release lacks an exact ownership handoff.**  
   [Owner exit](driver/SafeUpload.Minifilter/StageStream.c:6537) or supersession can lead to [stream retirement without Disposed](driver/SafeUpload.Minifilter/StageStream.c:5905). [Teardown](driver/SafeUpload.Minifilter/StageStream.c:5884) then leaves the backing on disk. Control 35 subsequently returns [ReceiptUnavailable](driver/T5-RECOVERY-HOLDS.md:251), with no specified cleanup route.  
   **Required:** explicitly retain bounded exact shell/ticket ownership until Release/CleanedUp resolves it, or define an exact drained handoff and deletion route. Cover exited-owner and follow-up saves.

Before implementation, complete control 35’s per-phase result/ReceiptId/action matrix, including denial, capacity, NotReady and lost Release/Query. Also make saved op24 completion lookup precede fresh filesystem observation: [line 325](driver/T5-RECOVERY-HOLDS.md:325) must agree with the historical replay guarantee at line 331.

Wire sizes, offsets, identifiers and `0x1FBF` arithmetic are consistent. Op24 specifies negative/lost/stale reply handling, bounded nonpaged retention and unload obligations.

Budget activation and the custody exception remain [owner decisions](driver/POST-MVP-PLAN.md:697). Recommend measured approved limits, named exhaustion diagnostics and the conservative residue veto until the exception is approved. The explicit cold-driver evidence-loss hold is a scoped limitation.