# Phase 5 whole-MVP review

**Commit:** `51ba5873` vs `9578f937`  
**Verdict: ACCEPT WITH CONDITIONS**  
**Scope:** requested driver, inspector, writer fixture and agent diff. Static source review only; no VM or build.

## P0 / P1

**None found.** I found no path in this diff where a standard user can publish an unapproved byte into a protected local-NTFS folder while coverage is Ready, nor a lost wakeup, deadlock, use-after-free, new unbounded cache growth, or trust/ACL regression.

The driver pieces compose conservatively: alias-scan results carry rename, transaction, policy-generation, activation-generation, probe-serial and scope-publication identity; successful consumers validate them under RegistryLock → policy-cache lock → StateLock. A stale result leaves the gate for a later pass. Rename churn remains pending and is rescanned. Promotion rechecks writer/transaction/rename/unknown/section state and scope generation; the replaced-incarnation path is limited to base streams, samples the live SOP, and checks sibling incarnations. The added inspector/protocol rows are diagnostic and do not feed readiness or admission.

## P2

1. **Privileged stale scan projection is in the destination authorization path** — [StagedTransferJournal.cs](/home/victor/Work/safeupload-wt-gen3/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:216), [destination scan](/home/victor/Work/safeupload-wt-gen3/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:796), [destination check](/home/victor/Work/safeupload-wt-gen3/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:824), [publication transition](/home/victor/Work/safeupload-wt-gen3/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:380).

   If an administrator or SYSTEM replaces/edits a historical manifest while preserving length, creation time, last-write time and attributes, a scan can reuse its old generation/tombstone/reservation projection and permit a publication that a fresh disk scan would refuse. Cache hits also skip the direct open’s ACL, reparse-point and single-link checks. This is the stated accepted trade-off: standard users cannot mutate the protected journal; class writes invalidate the relevant entry; current state changes start with a direct disk read; restart starts with an empty cache. Record the privileged freshness boundary in release notes.

   The shallow-record concern does not create another publication path: `StateHistory` is a mutable list behind an `IReadOnlyList`, but destination claims do not consult it, and current service consumers do not mutate it. The fields used for destination claims are immutable record properties/strings. `_gate` is acquired before the cache lock; there is no inverse acquisition or await while holding the cache lock.

2. **The 50,000-entry all-clear can restore full journal-read cost** — [cache limit](/home/victor/Work/safeupload-wt-gen3/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:30), [all-clear](/home/victor/Work/safeupload-wt-gen3/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:231), [per-entry scan gate](/home/victor/Work/safeupload-wt-gen3/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:610).

   Once the cache is full, the first uncached manifest clears the entire dictionary. With a stable enumeration order and more than 50,000 retained manifests, repeated scans can evict the cached tail and re-open, ACL-check and parse the history again. The publish loop scans every 250 ms and holds `_gate` per entry, so this can raise CPU use and stage-operation latency at that history size. It does not change authorization for standard users or grow the cache without bound. Carry the 50,000-manifest performance limit; journal retention/pruning remains unqualified.

## Release-note conditions

- Qualified target is local fixed NTFS on Windows 10 build 19045.2965 only. The driver is boot-start and installation requires a reboot; admins and SYSTEM are trusted.
- A scope with a pre-scope writer remains Activating and is never Ready. Sticky Unknown remains until reboot.
- Unresolved probes can make the reclaim worker rescan and consume CPU under endless churn; this is the recorded liveness-cost issue.
- C05DenialLedger, the lower mutation ledger and continuous coverage proofs are deferred. State the sampled-evidence limitation for NoUnapprovedByte.
- Read classification can stall the service while taint is on; the MVP proof runs with taint off.
- The signed LONG policy-generation comparison rolls over after 2^31 commits.
- At more than 50,000 retained manifests, scans can repeatedly re-read history. State that this scale is not performance-qualified.
