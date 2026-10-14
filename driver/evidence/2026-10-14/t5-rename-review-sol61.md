# Review of the rename-commit receipt 2e0cd707 (REJECT) — Sol 6.1 xhigh (2026-10-14)

Reviewer: `gpt-6.1-sol`, `reasoning_effort=xhigh`, read-only, web search enabled (Codex session `01a13ae8-4069-7441-99a9-0b59bd8fbe39`). Verbatim final report; checkout paths shortened.

**REJECT for inclusion as-is in the next dormant Verifier boot.**

The receipt binding, atomic manifest update, replay ordering and adoption before fence release appear coherent. Three issues remain:

1. **Medium — structural refusals become transient retries.** [StagedTransferJournal.cs:3597](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:3597) treats untagged `IOException` as transient. However, stage single-link/reparse violations and parent reparse rejection use that exception ([StagedStageFile.cs:88](agente/SafeUpload.Agent.Service/Interception/StagedStageFile.cs:88), [108](agente/SafeUpload.Agent.Service/Interception/StagedStageFile.cs:108)). The new op19 handler returns result 19, causing continued timer retries of a semantic refusal. **Required:** classify these structural failures as permanent and add handler-level refusal-versus-storage-failure controls.

2. **Medium — disconnect during backoff leaves timer polling active; inherited gap.** [StageStream.c:6922](driver/SafeUpload.Minifilter/StageStream.c:6922) parks reconciliation but leaves pending receipt waits as EXCHANGE. The [timer census:6497](driver/SafeUpload.Minifilter/StageStream.c:6497) continues counting them, while [generation-first reconciliation:6794](driver/SafeUpload.Minifilter/StageStream.c:6794) prevents the stream pass from parking them. This can rearm indefinitely while disconnected. **Required:** remove disconnected receipt exchanges from timer eligibility while retaining their bookkeeping and genuine drain waits. Test transient failure → disconnect → idle cancellation → reconnect/unpark.

3. **Medium — the new clean replacement control deterministically fails at generation 3.** [StagedAttachmentV20Tests.cs:164](agente/SafeUpload.Agent.Tests/StagedAttachmentV20Tests.cs:164) compares against `previousPublic`, captured before the loop. Generation 2 has already published different clean bytes. **Required:** advance the expected public baseline after successful publication; retain the unchanged-by-rename assertion. Prefer distinct replacement bytes per generation.

After corrections, require the complete agent matrix, four WDK/PREfast/ApiValidator builds and Windows transport verification before boot.

Read-only review; no edits, tests, builds or VMs performed.