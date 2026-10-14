# m2t5boot13 replace-onto-existing root-cause analysis — Sol 6.1 xhigh (2026-10-14)

Analyst: `gpt-6.1-sol`, `reasoning_effort=xhigh`, read-only, web search enabled (Codex session `01a13aba-707f-7ba0-a25e-a2ec270186b6`), on `2e77a633`. Verbatim final report; checkout paths shortened.

**Root cause: the driver sends the renamed destination with its old allocation generation. High confidence.** The agent’s refusal is correct. Sol 6.1/xhigh independently confirmed this analysis.

The journal assigns the destination’s `max + 1` generation in [StagedTransferJournal.cs:2359](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:2359). The agent returns only Allow ([MinifilterInterceptor.cs:682](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:682)); the kernel clears the rename exchange without updating `DestinationGeneration` ([StageStream.c:4549](driver/SafeUpload.Minifilter/StageStream.c:4549)).

The reconstructed op19 tuple is:

| Field | Driver versus journal after rename |
|---|---|
| Destination name | Both `rep-3.txt` / `rep-7.txt`; kernel name changed at line 4916 |
| Destination generation | **Driver 1; journal 2 for cycles 11/15, 3 for cycle 19** |
| Transfer and stage identity | Same exact transfer/object; rename changes neither |
| Owner | Same PID 5108 |
| View generation | Kernel-local ACK revalidation; **not transmitted** |
| Driver epoch | Unchanged |
| Parent identity | Same `t4` directory; allocation parent remains valid here |

[Op19 collection/send:6025](driver/SafeUpload.Minifilter/StageStream.c:6025) snapshots the stale generation. [Journal validation:813](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:813) rejects it before recording HandleObserved. Boot13 journals corroborate committed generations 2/3, `CompletionPermitted`, no HandleObserved, and State 0; service events report this exact validation failure. No raw op19 payload dump is present, so the transmitted generation is reconstructed from the matching source tree.

Cycles 3/7 passed because both fresh names had generation 1. **Absence alone does not guarantee a match:** a previously used absent name can retain a higher watermark.

**Secondary cause: the exchange backoff resets during each attempt. High confidence.** [StageProcessStream:5788](driver/SafeUpload.Minifilter/StageStream.c:5788) changes pending op19 to `SERVICE`; collection marks it in-flight without restoring `EXCHANGE`. The pre-RPC timer update at line 6417 therefore sees zero waiters and resets `StageRetryMs` ([line 6324](driver/SafeUpload.Minifilter/StageStream.c:6324)). The refusal restores `EXCHANGE` at line 6087 and rearms 250 ms. All three requests have a **258 ms median refusal interval**, consistent with the counters.

Confirmed denials are also retried as exchanges, contrary to the [timer rule:146](driver/T4-STAGE-LIFETIME.md:146).

**Proposed fix: both agent and kernel; retain strict op19 validation.**

1. **Return and adopt an exact rename-commit receipt.** At `CompleteRenameAsync:2342–2398`, persist the transaction’s source tuple and resulting destination tuple with the path/generation/tombstone update. Return that typed receipt through `RetargetStage:664`, the mirrored protocol definitions, and FilterPort. In `StagePerformRenameRpcs:6227` / `StageApplyRenameReply:4549`, validate transaction, object, epoch, owner/view and destination, then adopt the returned generation **before clearing the rename fence**. Do not infer it locally or require `newGeneration > oldGeneration` across different names.

2. **Preserve replay and authority.** Resolve an exact stored commit receipt before comparing its old source tuple with the now-retargeted manifest. Lost replies replay the same bookkeeping result without another increment; abort retains the original tuple. Unresolved crash recovery stays held. T5 requires the current destination generation ([T5-DELETES.md:306](driver/T5-DELETES.md:306)); using allocation-time op19 authority would also leave the subsequent seal mismatched ([MinifilterInterceptor.cs:1210](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1210)). The prior published bytes remain until clean publication; BLOCK preserves them and follows the ordinary authorized hand-back path. Pending/BLOCK successors do not cancel deletes.

3. **Repair retry accounting and classification.** Keep an unfinished eligible exchange counted through pending → in-flight → reply. Reset backoff only when that obligation actually ends. Distinguish permanent tuple refusal from retryable journal failure—currently all exceptions become Deny. Park permanent refusals until reconnect/reconciliation; back off unanswered/transient exchanges to 8 s. Collectors must respect that wait cause, including unrelated wakes. Preserve `KeReadStateTimer` arming and idle cancellation.

Boot13 is **unbound and same-parent**. Cross-parent handling still carries the allocation parent; bound seed checks still compare immutable allocation evidence with mutable generation ([StageStream.c:2065](driver/SafeUpload.Minifilter/StageStream.c:2065), [StagedSeedProvenance.cs:104](agente/SafeUpload.Agent.Service/Interception/StagedSeedProvenance.cs:104)). Refuse those cases before mutation until explicit rebinding is implemented; never rewrite seed evidence to manufacture readiness.

Required controls:

- **Agent:** extend `StagedAttachmentV20Tests.cs:94` and replacement tests at `StagedTransferJournalTests.cs:584` with occupied generations 1→2→3, op19→seal, clean/BLOCK outcomes, altered-tuple rejection, abort, lost reply/restart, and lower-generation target moves.
- **Kernel:** source controls for receipt adoption before fence release, exact ACK rejection, unchanged abort generation, and persistent exchange accounting; extend `reconcile-retry-selfcheck.py` for 250/500/1000/2000/4000/8000 ms progression, refusal parking, and zero idle polling.

No files changed; no builds, tests, or VM actions performed.