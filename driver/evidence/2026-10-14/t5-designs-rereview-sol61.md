**T5-RECOVERY-HOLDS.md — REVISE.**  
**T5-VOLUNTARY-UNLOAD.md — REVISE.**

Reviewed at `bbd806c5`; checkout unchanged. Findings are source-derived, with no builds, tests or VM actions.

Previous findings:

- **1 — Resolved in the design.** Atomic intent plus `SealPending`, identical-request resumption and all entry points are specified in [Recovery:94](driver/T5-RECOVERY-HOLDS.md:94). This addresses the unchanged source’s requestless persistence/startup paths at [Journal:2143](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:2143) and [Journal:3120](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:3120).
- **2 — Resolved in the design.** Explicit attestations, flag/pin transitions and the cancellation-CLOSE named hold appear at [Recovery:144](driver/T5-RECOVERY-HOLDS.md:144) and [Recovery:170](driver/T5-RECOVERY-HOLDS.md:170). They address [StageStream:5448](driver/SafeUpload.Minifilter/StageStream.c:5448), the op19 gate at [6285](driver/SafeUpload.Minifilter/StageStream.c:6285), and the genuine receipt transition at [Journal:1011](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:1011).
- **3 — Resolved conservatively.** [Recovery:192](driver/T5-RECOVERY-HOLDS.md:192) and [Unload:94](driver/T5-VOLUNTARY-UNLOAD.md:94) preserve the existing [terminal-and-absent predicate](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:114). The custody exception and budgets remain owner decisions.
- **4 — Partially resolved.** The shared tables agree, enumerate sender/continuation closure, and prohibit the existing [post-ACK reopen](driver/SafeUpload.Minifilter/StageStream.c:7757). However, retirement storage and reconnect remain incomplete; see new findings 1–2.
- **5 — Resolved in the design.** [Recovery:64](driver/T5-RECOVERY-HOLDS.md:64) preserves historical-owner sealing, consistent with [Journal:2115](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:2115) and [owner-exit scheduling](driver/SafeUpload.Minifilter/StageStream.c:6542); fresh op15 retains the [live-owner requirement](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:962).

New findings:

1. **High — Closing bookkeeping CREATE before R prevents op17 from completing.**  
   [Unload:131](driver/T5-VOLUNTARY-UNLOAD.md:131) closes that route, while [Recovery:247](driver/T5-RECOVERY-HOLDS.md:247) requires subsequent durable `Retiring`/`EpochRetired` writes and auditing. Current epoch persistence [creates a temporary](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:162), and receipt reads [open the journal](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:131); the existing CREATE gate explicitly [exempts the authenticated service](driver/SafeUpload.Minifilter/StageStream.c:9391). Removing that exemption without a replacement strands even idle retirement, including receipt recovery after reconnect.  
   **Required:** specify a bounded, exact retirement-storage route, or a complete pre-opened storage construction. Count and drain its ownership; permit no ordinary recovery/publication.

2. **High — Retirement-only reconnect lacks an authentication/bootstrap contract.**  
   [Recovery:263](driver/T5-RECOVERY-HOLDS.md:263) permits only final op17 traffic and forbids op11. Existing authentication requires [SET_POLICY followed by authentication commit](driver/SafeUpload.Minifilter/Communication.c:2992); the agent [pushes policy first](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:225). Drain replay additionally depends on [reconciliation-installed authority](driver/SafeUpload.Minifilter/StageProtocol.c:1857), and the agent requires an [established driver binding](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:948). Neither note defines their replacement.  
   **Required:** define the narrow bootstrap messages, identity/cookie/epoch/revision validation, capability check and reply adoption. Establish retirement mode before starting ordinary recovery tasks; never authenticate by reactivating ordinary authority.

3. **Medium — Permanent refusal needs an explicit owner rescope.**  
   [Recovery:261](driver/T5-RECOVERY-HOLDS.md:261) retains R even for `Held`/EpochBusy with unexpected unresolved obligations, while ordinary resolving traffic is forbidden. This departs from [approved §7](driver/T5-DELETES.md:470), whose veto preserves usable recovery routes, and the [current retry path](driver/SafeUpload.Minifilter/StageStream.c:7798). Users can receive unload failure while saving and service-assisted resolution remain permanently fenced.  
   **Required:** record this failure-policy decision and remedy explicitly. Recommend completing recoverable prerequisites in P/Q and preserving monotonic R/E fences; obtain owner approval for any remaining restart-only failure outcome.

No additional delta defect identified in identity/generation authority, mutation replay, sticky Unknown, or the stated lock/IRQL/timer constraints. Implementation review and qualification remain required.