# T5 re-review of the exact attachment replay (bdab1f51) — Sol 6.1 xhigh (2026-10-14)

Reviewer: `gpt-6.1-sol`, `reasoning_effort=xhigh`, read-only, web search enabled (Codex session `01a13abd-0202-7633-8776-92592db81d04`). Verbatim final report; checkout paths shortened.

**ACCEPT WITH CONDITIONS** for including `bdab1f51` in a dormant Verifier boot. Sol 6.1 xhigh review found no new boot-blocking defect. Prior findings 2, 3 and 5 are resolved.

1. **Medium, resolved — cached permission and unload recovery.** Live validation now precedes cached-permit acceptance ([StageStream.c:3512](driver/SafeUpload.Minifilter/StageStream.c:3512)). Unresolved attachments veto unload before cleanup classification or quarantine (**:7344**); Veto releases NamespaceResource before restoring admission (**:7561**, **:7195**). Kind-5 guards independently exclude ambiguous op15. **Required change: none.**

2. **Informational — exact replay and lifetime accounting are sound.** Replay preserves RequestId and compares the entire reconstructed request before sending the saved bytes ([StageProtocol.c:1522](driver/SafeUpload.Minifilter/StageProtocol.c:1522), **:1554**, **:1614**). The owner gate retains process/view/generation/allocation authority ([StageStream.c:1738](driver/SafeUpload.Minifilter/StageStream.c:1738)). The lifecycle claim clears after completion, before the sole transaction-pin release (**:4228–4236**). PASSIVE scratch allocation under NamespaceResource introduces no spin-lock I/O; sends remain outside namespace/spin locks. Mandatory teardown adds no service exchange or result wait. **Required change: none.**

3. **Informational — timer/reconcile interaction preserves the resolving route.** Maintenance retains SERVICE and DrainStatus ([StageStream.c:5855](driver/SafeUpload.Minifilter/StageStream.c:5855)); SERVICE is excluded from timer accounting and timer-only sweeps (**:6391**, **:6468**). Owner CREATE still drives replay. Generation-first reconciliation preserves newer disconnect state (**:6700**). No additional stranded-owner path found. **Required change: none.**

4. **Informational, resolved — controls cover the previously missed regressions.** Replay **16/16**, including 29 rejected mutations; pin **9/9**, including 11 rejected mutations. Missing handoff, missing pin, initial-validation removal, double release and lost requeue are covered ([replay controls:148](driver/scripts/t5/attachment-replay-selfcheck.py:148), [pin controls:53](driver/scripts/t5/attach-pin-selfcheck.py:53)). **Required qualification:** reconnect, cancellation, concurrent retries, changed-parent cached acceptance, reversible unload and service-absent teardown with independent byte observations.

5. **Medium, recovery limitation — owner exit/never retry and late fences remain indefinite holds.** V20 has no typed durable op15 refusal ([StageProtocol.c:1473](driver/SafeUpload.Minifilter/StageProtocol.c:1473)). **Required before recovery qualification:** approved exact recovery/lifetime evidence; generic DENY must remain held.

6. **Medium, pre-existing — lost seal ACK remains unresolved.** The handler requires exactly `Sealed` ([MinifilterInterceptor.cs:1216](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1216)), while journal replay can return a progressed measured state or refuse after cleanup starts. **Required:** exact durable acknowledgement recovery without repeating publication.

Before boot, obtain fresh four-profile WDK/PREfast/ApiValidator/import gates at **0 warnings/errors**, exact-commit artifact hashes, and preserve dormant capability gates. Acceptance does not establish runtime or recovery qualification.

Read-only review and source controls only; no edits, builds or VMs. Checkout unchanged.