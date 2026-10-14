**REVISE — Sol 6.1 xhigh, at `d683c59f`.** One resolving transition remains undefined. Read-only review; checkout unchanged. No builds, tests or VM actions.

Prior findings’ status:

| Prior finding | Status |
|---|---|
| Original 1 — Seal-request persistence | **Resolved in design:** atomic intent plus `SealPending`, exact resumption, all entry points. |
| Original 2 — Exposure/lifetime transitions | **Resolved in design:** explicit attestations, ownership transitions and cancellation-CLOSE hold. |
| Original 3 — Retained residue/unload conflict | **Resolved by the accepted custody exception**, replacing the conservative veto. |
| Original 4 — Permanent retirement/quarantine conflict | **Deferred, not fixed:** retirement mode excluded from batch 2. |
| Re-review 1 — Retirement storage CREATE | **Deferred, not fixed:** existing bookkeeping route preserved. |
| Re-review 2 — Retirement-only bootstrap | **Deferred, not fixed:** normal authentication/op11 preserved. |
| Re-review 3 — Permanent-refusal policy | **Deferred, not fixed:** that mode remains excluded. |
| Original 5 — Live-owner sealing requirement | **Resolved in design:** historical-owner sealing; fresh permission retains live authority. |
| Batch-2 1 — Accepted Release followed by rename | **Resolved in design:** suspension, exact revocation and drained ownership. The preacceptance boundary remains below. |
| Batch-2 2 — Retirement before Release | **Resolved in design:** bounded, counted `AwaitingDisposal` shell. |
| Batch-2 comment — Control-35 phase matrix | **Specified:** phase/result/ReceiptId and loss handling. |
| Batch-2 comment — Saved op24 lookup first | **Specified:** historical completion lookup precedes filesystem observation. |

1. **Medium — Rename before Release acceptance can strand an obsolete intent.**  
   The agent [persists Release intent before sending](driver/T5-RECOVERY-HOLDS.md:389). Rename can then advance generation/count before driver acceptance. The old Release becomes `TupleRefused`; [Query’s `ReceiptUnavailable` explicitly cannot prove nonacceptance of another in-flight copy](driver/T5-RECOVERY-HOLDS.md:419). Revocation covers accepted records with ReceiptIds, but supplies no terminal route for this unaccepted intent. Its unfinished bookkeeping remains an [unload obligation](driver/T5-RECOVERY-HOLDS.md:613). The underlying rename transition is confirmed in [StageStream.c](driver/SafeUpload.Minifilter/StageStream.c:4704).  
   **Required:** define exact closure of an unaccepted Release intent after rename, serialized against accepted records, factories and in-flight controls. Prove no older call can subsequently accept; persist the historical outcome and specify replay/drain handling. Cover delayed sends, lost replies, crashes and multiple renames. Do not mark the stage deleted or retarget the intent. **User effect:** supported rename should complete without leaving a permanent recovery/unload hold. Preserve that behavior; no new owner decision is needed.

No additional blocker identified in custody proof and separate agent/driver validation, qualifying-record-only `EPOCH_DRAINED`, time-local result 20, positive-first replay, candidate ordering, exact withdrawal/NO_WAITER cleanup, legacy refusal metadata, or **`0xFBF`** arithmetic and negotiation.

The scope is proportionate; deferred retirement infrastructure stays excluded. Measured positive/custody storage limits remain an owner activation choice: approve explicit limits and named exhaustion holds before enabling them. Design resolution does not establish implementation acceptance or protected-pair qualification.