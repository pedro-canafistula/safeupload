# Independent T9 upgrade/default design review

2026-10-16. Sol 6.1, xhigh. Read-only source review against base `a2b67984` and `.scratch/ux-large3/design.md`; only this review receipt was written. No code, build, Windows, VM or Git mutation. Owner-selected defaults are accepted inputs, not reopened decisions. This review is not component verification or protected-pair qualification.

**Disposition: REVISE before implementation acceptance.** The proposed architecture is sound, but the two gaps below need explicit handling. Review the final coherent implementation once after fixes.

## Findings

### F1 — P1: An unreserved manifest does not establish legacy 16 MiB capacity

The import design assigns every pending unreserved journal entry a 16 MiB `LegacyGuard` debit. It does not say to reject an existing `.space` companion or evidence that the version already exceeded that guard. An installation with a lost large-mode reservation and its surviving manifest/companion would therefore be reclassified as a legacy version. Base inventory accepts `stage + ".space"` whenever it recognizes the stage reservation (`StagedSpaceBudget.cs:175–180`). The driver reads that companion and caches its larger immutable `SpaceCapacity` (`StageStream.c:1698`, `1739–1744`); recording a smaller ledger capacity cannot lower the driver's authority. Outstanding growth can exceed the imported debit and compete with newly admitted users.

Require the migration to distinguish the old no-grant population from inconsistent modern accounting. At minimum, before persisting a legacy import, require confirmed companion absence (access errors are not absence), reject durable sealed/seed length evidence above the guard, and keep a preexisting companion/oversized object held without deleting or replacing it. Do not shrink an already-issued grant by overwriting its accounting. Keep partially migrated replay equally strict. Where an exact held stage can be inspected without changing its lifetime/sharing contract, reject length above the claimed capacity as well; an unavailable object is not permission to invent identity or cleanup authority.

Controls: pending unreserved manifest plus a valid identity-bound larger companion; oversized sealed length; an exact stage larger than the guard; inaccessible companion; restart after one import commits. All inconsistent cases remain held and retain their evidence, and none produce a `.space` grant.

### F2 — P2: Existing negative allocation receipts can still prevent upgrade startup

The legacy journal envelope counts hot/cold journal storage, but valid `.allocation-refused` receipts live in the stage root. Base `VerifyInventory` calls `RequireNegativeReceiptSpace(creating:false)`, whose fixed existing-data limit is `_metadataBytes / 4` (`StagedSpaceBudget.cs:183–186`, `249–263`). Pre-large operation does not impose that bound. A valid old installation with more retained negative receipts than the new allowance still refuses initialization, contrary to the requested upgrade behavior. For ordinary 4 KiB allocation units this is 64 receipts; at 64 KiB it is only four.

Include validated preexisting negative-receipt storage in a conservative global migration debit and compatible existing-data allowance, while retaining a finite bound on additional growth. Charge existing bytes and recovery overlap against total/free space before admitting new versions; over-budget history must inhibit new admission rather than prevent recovery. Corrupt, partial, unexpected, or untrusted receipts must continue to hold. This compatibility accounting grants no allocation-replay authority: the allocator still validates the exact full tuple.

Controls: old receipt population above the former threshold survives startup/restart unchanged; its debit reduces fresh capacity; new growth stops at the accounted allowance; malformed/partial residues still refuse unsafe admission.

## Conditions for implementation acceptance

- Validate imported manifests through the existing trusted held-handle path and `ValidateEntry`, and packed entries through the complete checksum/frontier/shape machinery. Do not use raw JSON/filenames as authority.
- Terminal exemption requires the existing completed shape, confirmed stage absence and no unaccounted companion/snapshot. It affects inventory only, never `Reserve`, `Bind`, snapshot ownership, publication, deletion, generation or replay authority. Rebuild it every start.
- Persist legacy status before publishing admission readiness; disallow grant issuance, new-capacity reuse and failed-allocation retirement for a legacy record, including null identity/SID cases. Missing SID is global debt, not fabricated per-user ownership.
- Install archive growth hooks before `EnsureArchiveLoadedCoreAsync` can repair/control-write. Compute the rounded existing-storage envelope first. Preserve journal-to-budget lock order and never read the journal while holding the budget lock.
- Recovery must work with valid existing debt above configured budget and with tiny/zero limits. New reservations fail with the resource reason. Checked arithmetic and invalid negative settings remain explicit failures.
- The current large path is unbound-only. Do not widen completed shapes or silently import bound/security-store dependencies as ordinary unbound authority. If those records are included in the supported upgrade population, enumerate/account their auxiliary GUID-named objects explicitly; base `VerifyJournalInventory` otherwise interprets every GUID prefix as a transfer ID. Preserve existing bound recovery restrictions.
- Explicit policy/resource settings remain authoritative; capability/runtime readiness gates stay in force. Native Windows storage, ACL, driver-capacity and protected large-file evidence remain separate required work.

The proposed four-copy legacy debt, metadata envelope, terminal inventory exemptions, journal-lock callback direction and recovery-with-no-new-admission approach are appropriate once these conditions are implemented. No independent product-default decision is needed for these fixes.
