# Phase 5 review (final pair): whole MVP diff (driver + agent), commit 5ebe139a

Independent adversarial reviewer. Modify nothing except your output. No VM, no build.
Worktree `/home/victor/Work/safeupload-wt-gen4`, branch `feat/mvp-gen4`, driver/agent final commit `5ebe139a` (main line for comparison: `9578f937`; the agent is unchanged since `51ba5873`).
Scope: `git diff 9578f937 5ebe139a -- driver/SafeUpload.Minifilter driver/SafeUpload.Inspector driver/SafeUpload.WriterFixture agente`
(about 670 added lines; StageWriters.c is most of it). This is the MVP release review required by driver/MVP-PLAN.md Phase 5:
the question is whether this diff, as the final MVP driver + agent, contains a P0/P1 (fail-open: an unapproved byte reaching a protected
local-NTFS folder when coverage is reported Ready; a lost wakeup that leaves a file gated/Activating forever; deadlock; use after
free; IRQL/SAL violations; unbounded growth; a trust or ACL regression).

Product rules (do not propose otherwise): local fixed NTFS on Windows 10 build 19045.2965 only; boot-start driver, install needs a
reboot; admins and SYSTEM are trusted, standard users are the adversary; fail closed; no timers or scans as fixes; no process taint
(read classification only while taint is on); a scope whose files still have a pre-scope writer stays Activating and is never Ready;
a sticky Unknown is never cleared (until reboot).

## What the diff contains (each part already reviewed in isolation; re-judge the combination)
1. gen2 `cfee5a33`: runtime activations carried policy generation 0; monotone `ActivationGeneration` stamp in
   `StageRegistryBeginAliasProbe`, live generation re-read under the entry lock at the promotion CAS. Your earlier verdict: ACCEPT WITH
   CONDITIONS (P2: signed LONG comparison after 2^31 policy commits).
2. replaced-incarnation promotion (`c1086343`..`91da9534`), snapshot-churn fix `817c1420`, names-by-id `9b964be9` (all ACCEPT/ACCEPT WITH
   CONDITIONS earlier).
3. hard-link ADDITION begins an alias probe instead of poisoning the volume with Unknown(RENAME) (`c56ead4f`, ACCEPT WITH CONDITIONS).
4. classification receipt (rename/transaction version, policy generation, activation stamp, scope-publication sequence) validated by
   every successful consumer under RegistryLock -> policy-cache lock -> StateLock (`f6c8e00b`), plus the per-entry `AliasProbeSerial`
   (`b4ff2a84`).
5. rename churn is parked and retried instead of becoming sticky Unknown(IDENTITY): `94334034`, `f550666b` (`STATUS_RETRY` from
   `StageRegistryOpenIdentity`), `840e6479` (catch-all at `Exit:` of `StageRegistryClassifyAllLinkNames`). Your last verdict on this
   chain: ACCEPT WITH CONDITIONS at `840e6479` (condition: parked scans keep the reclaim worker rescanning under endless churn;
   recorded as a known issue).
6. Agent `StagedTransferJournal` scan cache (`51ba5873`): `ReadPendingAsync` (publish loop, every 250 ms) and
   `DestinationVersionsAsync` (every stage create/rename/commit) reused to open, ACL-check and JSON-parse EVERY historical manifest; the
   journal never shrinks, so every stage operation was O(journal age) (C04 rename-ex 30 -> 340 ms over 100 rounds on both gen2 and gen3
   drivers). Now a parsed entry is reused while the directory enumeration reports the same Length, CreationTime, LastWriteTime and
   Attributes (never for a reparse point); Create/Replace drop the entry; `ReadAsync`/`ReadCoreAsync` (the start of every state change) always
   read and validate the disk. Attack this one hard: stale-cache decisions (publication of a manifest an attacker replaced; a hard link /
   symlink swapped in with a preserved stamp; a replace within one timestamp tick; `with`-copies of shared immutable records mutated by
   a caller; the 50 000-entry clear), lock/threading (`_scanCache` lock vs `_gate`, `ReadPendingAsync` taking `_gate` per entry),
   restart semantics, and whether any scan result can authorize a publication that a direct disk read would refuse. The accepted trade-off
   is that only an administrator/SYSTEM who preserves size, creation time, last-write time and attributes could keep a stale projection for
   scans until the next write to that manifest.
7. Inspector/protocol additions (diagnostics only, feature build).
8. NEW since your last Phase 5 (ACCEPT WITH CONDITIONS at 51ba5873): `StageStream.c` `b085d577` + `5ebe139a` (about 55 lines): a sealed stage stream's read-only
   backing is opened with FILE_SHARE_DELETE, the 250 ms stage worker retires a sealed stream (no handle/file object/section, backing DeletePending: rundown barrier, close backing, mark
   Retired, detach view) and `StageCreate` refuses opens of a delete-pending sealed stream with STATUS_DELETE_PENDING; `SafeUploadProcessHasMappings` ignores retired detached views.
   Reason: no BLOCK stage could ever be deleted by the service (sharing violation on every try). Your delta reviews are committed: `driver/evidence/2026-10-08/luna-gen4a-review.md` (REJECT P1, fixed)
   and `driver/evidence/2026-10-08/luna-gen4b-review.md` (ACCEPT WITH CONDITIONS: top-level-IRP guard on the new FltQueryInformationFile under the namespace lock; create admitted before the delete is a pre-delete open).

## Reasoning already accepted (do not reopen unless you can break it)
A mutating create (name or ID based) holds the admission epoch token from pre-operation through post-create writer registration; a
policy publication can make the pending union visible while it is held but the apply drains the old epoch before reconciling, so the
old-epoch writer is an existing entry when probed, becomes Activating, is never promoted while H/S/C/T/W is live, and coverage is never
Ready while it exists. (`review-gen3b-report.md`: "P1 not reproduced".)

## Known issues the release notes will list (record, do not re-find): reclaim-worker rescan CPU churn under unresolved probes (existing
liveness rule); C05DenialLedger deferred by the owner; lower mutation ledger / continuous coverage proofs deferred; taint-on read
classification stall risk; signed-LONG generation rollover after 2^31 commits; Windows 10 19045.2965 only.

Review the combination of everything including item 8 (stage-stream lifetime with the rest of the staging path: sealed-then-written-again views, rename of a sealed view, tombstones, unload). Verdict ACCEPT / ACCEPT WITH CONDITIONS / REJECT. REJECT only for a P0/P1, an actual fail-open, deadlock, memory-safety or trust
regression; over-gating, performance and liveness-cost findings are conditions. P0/P1/P2 with file:line and a concrete scenario each, then the
list of conditions the release notes must carry. Under 1500 words.
Output: /home/victor/Work/safeupload-tools/workers/phase5-final-report.md
