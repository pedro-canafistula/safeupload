# Review of the reconcile retry fix a211847c (REJECT) — Sol 6.1 xhigh (2026-10-14)

Reviewer: `gpt-6.1-sol`, `reasoning_effort=xhigh`, read-only, web search enabled (Codex session `01a13a85-812e-7380-b1a8-1f95076fff8b`). Verbatim final report; checkout paths shortened.

**REJECT** `a211847c` for the next dormant Verifier boot. Sol 6.1, xhigh review:

1. **P2 — retained fire can clear the armed flag for a new timer.** At [StageStream.c:6592](driver/SafeUpload.Minifilter/StageStream.c:6592): timer A fires → Busy reconciliation arms B → unrelated wake arrives before B expires → A’s retained `StageRetryFired` clears B’s armed flag. If reconciliation succeeds or enters SERVICE with no other waits, [6325](driver/SafeUpload.Minifilter/StageStream.c:6325) skips cancellation. B subsequently fires while idle, violating the owner’s rule. Re-setting B can also postpone its deadline ([KeSetTimer contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesettimer)).
   
   **Required:** consume each expiry once, preserve owed stream retries separately, and cancel the actual timer when nothing waits. Extend [reconcile-retry-selfcheck.py:43](driver/scripts/t5/reconcile-retry-selfcheck.py:43) to cover this interleaving; its current assertions enforce the flawed bookkeeping.

2. **P2, pre-existing — accepted drain-only Busy can strand an owed pass.** [StageStream.c:6620](driver/SafeUpload.Minifilter/StageStream.c:6620) clears reconciliation, but schedules a follow-up pass only for `NT_SUCCESS`. With no timer-backed waits, retained fire/exit-ring work can remain until another event. An unload attempt explicitly wakes it.
   
   **Required:** guarantee a maintenance pass for owed local work after drain-only acceptance, without granting ordinary protocol authority. Track this separately from the new regression.

3. **Informational — the original retry stall is repaired, subject to finding 1.** [StageWaitFor:4504](driver/SafeUpload.Minifilter/StageStream.c:4504) keeps Busy, timeouts and malformed replies on EXCHANGE retries; disconnect, stale-channel failures and access refusals wait on SERVICE/reconnect. Result handling calls timer maintenance at [6639](driver/SafeUpload.Minifilter/StageStream.c:6639). The retained flag alone creates no autonomous busy loop. An owed exit sweep still overrides backoff and remains deferred while reconciliation skips the pass.

4. **Informational — no additional permanent stall from unload preparation, or new teardown lifetime defect found.** Rollback [7111](driver/SafeUpload.Minifilter/StageStream.c:7111) and quarantined veto [7465](driver/SafeUpload.Minifilter/StageStream.c:7465) explicitly resume and wake work. Teardown joins the worker, then unconditionally cancels and flushes at [6944](driver/SafeUpload.Minifilter/StageStream.c:6944), covering already queued DPCs ([flush contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keflushqueueddpcs)). **Required change:** none here.

5. **Informational — agent completion wake is optional.** [StagedNativeStartupRecovery.cs:153](agente/SafeUpload.Agent.Service/Interception/StagedNativeStartupRecovery.cs:153) completes preparation without waking the driver. Correct timer bookkeeping suffices for eventual negotiation. Eight seconds caps the retry delay, not total startup or exchange latency. **Required agent change:** none.

Read-only review; no edits, builds, tests or VMs. This verdict is not qualification.