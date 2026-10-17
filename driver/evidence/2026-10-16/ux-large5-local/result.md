# ux-large5 matrix regression repair

2026-10-16, source commit `c2982f6bd358520d8191cf02cb53db5089c4f4c1`, based on `e329a7a2` (includes dev `45102e57` and large4 recovery). Delivery is `.scratch/ux-large5.bundle`, head `ux/large`; the final documentation commit/head/hash receipt is `.scratch/ux-large5/delivery.json`. Original repository Git HEAD/index remain unchanged; commits and refs use `.scratch/ux-large5/bundle.git` only.

**42 of the supplied 56 failures have large-code fixes here. The other 14 are retained, separately attributed below. The Windows matrix is not claimed green.** Both supplied user TRX files have 2,721 executed, 2,665 passed, 56 failed, no skipped/not-executed tests, and identical failure names. [Input hashes, counters and all 56 classifications](failure-classification.json) preserve the mapping; original full TRX/failures.txt remain under `.scratch/ux-m6-diag/`. The owner-reported 25/25 SYSTEM legs were not supplied as TRX here.

## Failure groups and fixes

| Cases per user profile | Root cause | Fix / disposition |
|---|---|---|
| 35 ACL failures + 3 expected IOException / actual UnauthorizedAccess | Large budget preflight correctly reaches the journal's old untrusted-writer check, but fresh fixture roots and one partial ledger inherited the ordinary test user's parent/logon ACL. Grant creation also lacked an explicit descriptor. | Create fresh private storage with the journal's protected owner/SYSTEM/Administrators ACL supplied at CREATE. Budget supports a missing private root and creates its ledger/grants privately. Fixtures use a fresh private child and the product factory. No check, expected exception or corruption assertion is weakened. |
| 3 legacy defaults (RN-012, RN-013, audit reason) | Global 4096 MiB / 900 s defaults replaced legacy 20 MiB / 5 s behavior. | Omitted policy fields map to legacy 20/5 through `LoadAsync`/`CreateDefault`, staged 4096/900 through `LoadCurrentAsync`/`CreateStagedDefault`. Original legacy assertions are unchanged. |
| 1 native snapshot type | Large accounting wrapped even an unbudgeted native reader in `ReadLease`, breaking the original exact `FileStream` contract. | Unbudgeted snapshots return the original restricted native `FileStream` duplicate. Budgeted snapshots retain the wrapper/reference through actual last reader close; immutable mode selection prevents disposal races. Original native type/rights/lifetime assertions are unchanged. |
| 9 Active / Rejected | T11 first-use epoch guard, `d89f9f7c`: fixtures create retained driver receipts before first registering their epoch. | Other-branch setup issue; unchanged here. Register the fresh epoch before the first receipt/allocation. Never relax missing-epoch/lost-drain-proof rejection. |
| 4 metadata_source_open_failed + 1 publication reason mismatch | meta2 strict native observation, `2bd77f46`: Windows ERROR_PATH_NOT_FOUND (3) is not missing-leaf ERROR_FILE_NOT_FOUND (2). Four fixtures omit the destination parent; publisher fixture deliberately deletes it. | Other-branch fixture/fault-trigger issue; unchanged here. Establish the valid parent in four allocation/handback setups. Publisher owner should preserve the strict missing-parent control and exercise its generic publication-failure assertion using a fault after successful metadata lookup, e.g. an IOException from the publication gate. Do not accept error 3 as absence or merely change the expected reason. |

Windows creation passes security in the create operation, avoiding an inherited writable interval. Existing unsafe objects are validated and rejected unchanged; this helper does not repair evidence or create missing ancestor chains. Startup's protected-parent/SYSTEM gates and preflight-before-allocator order remain unchanged. The ordinary `TestWorkspace` ACL is unchanged. Native controls add broad parent inheritance, exact SID/owner/protection/inheritance checks, unchanged unsafe descriptors and parent, CreateNew collision without replacement, ledger/grant restart, READ_CONTROL while an exclusive data handle is open, and denied second data open. READ_CONTROL is metadata access; it does not bypass the original data-sharing contract.

New JSON provisioning omits the two inspection overrides so neither mode pins defaults into the other. Either explicit field still overrides both modes; null/invalid values retain rejection. Effective limits remain fingerprinted. A successful staged read caches a separately mapped legacy last-good view; later ACL rejection cannot enlarge legacy fallback, and staged current reads still never fall back. Existing persisted explicit values, accepted stage-space formulas and 256 MiB parser memory are unchanged. [Updated default contract and original measurements](../../../UX-LARGE.md).

## Other-branch cases remaining

All names below have namespace `SafeUpload.Agent.Tests.`; each bullet is one failed TRX case. These production guards and tests are untouched in this delta.

T11 (9):

- `StagedTransferAllocatorTests.Direct_released_successor_requires_gate_confirmed_disposal_before_parent_ack`
- `StagedTransferAllocatorTests.Direct_emptyheld_parent_cleanup_requires_terminal_child_ack_and_survives_restart_compaction(childDisposition: UnattachedAllocation)`
- `StagedTransferAllocatorTests.Direct_emptyheld_parent_cleanup_requires_terminal_child_ack_and_survives_restart_compaction(childDisposition: PrivateVersion)`
- `StagedTransferAllocatorTests.Direct_emptyheld_successor_must_be_exactly_retired_before_its_parent(childCleanupKind: DriverUnloadEmpty)`
- `StagedTransferAllocatorTests.Direct_emptyheld_successor_must_be_exactly_retired_before_its_parent(childCleanupKind: OwnerExitEmpty)`
- `StagedTransferAllocatorTests.Direct_emptyheld_cleanup_rejects_mismatched_child_writer_or_epoch(mutation: "driver-epoch")`
- `StagedTransferAllocatorTests.Direct_emptyheld_cleanup_rejects_mismatched_child_writer_or_epoch(mutation: "process-creation")`
- `StagedTransferAllocatorTests.Direct_emptyheld_cleanup_rejects_mismatched_child_writer_or_epoch(mutation: "sid")`
- `StagedTransferAllocatorTests.Direct_released_successor_replacement_blocks_parent_cleanup_without_deleting_replacement`

meta2 (5):

- `StagedTransferAllocatorTests.Later_open_copies_the_sealed_version_without_changing_it`
- `StagedTransferAllocatorTests.Allocation_is_journaled_before_the_stage_name_is_returned`
- `StagedTransferAllocatorTests.Allocation_persists_requestor_sid_and_process_creation_time`
- `StagedHandbackTests.Completed_BLOCK_after_requester_exit_remains_idle_across_reconnect_and_name_reuse`
- `StagedTransferPublisherTests.Failed_publication_is_retained_and_never_audited_as_sent`

## Local verification

- Feature Debug and Release agent/test compilation, SDK `/home/victor/Work/safeupload-tools/dotnet/dotnet` 10.0.400, warnings as errors: **0 warnings, 0 errors**. [Build settings, raw log hashes and assembly hashes](verification.json).
- **310 unique controls pass in both Debug and Release** as Linux in-process diagnostics of actual Fact/Theory methods/rows. Includes restored RN-012/RN-013/audit behavior, all mode-default controls, budget/default/upgrade/recovery/integration classes, archive/text and notification controls. [Exact selectors/outcomes](controls.json). This is not VSTest or a Windows matrix.
- The first broader run had three Windows-path/environment assumption failures. Expanded Debug had 310 passes and one Windows sharing assumption failure (`NotificationRecordTests.A_second_writer_is_refused_until_the_first_closes`); Release selected the 310 locally supported controls. All four original controls remain unchanged and required on Windows. [Preserved failed attempts and dispositions](prior-attempts.json), raw logs in `.scratch/ux-large5`.
- Production grant shims **cc + clang PASS**, warnings-as-errors/UBSan and negative mutation; exact agent matrix runner 21, feature defaults 2, allocation retry 7, T11 SOP 3, metadata-security 2, import-gate and T4 verdict offline self-checks PASS. Synthetic import refusal output is an intended negative control, not a new product import result. [Log hashes](verification.json).
- [Source/API audit](api-audit.json): all 45 tracked kernel files byte-identical to `e329a7a2`; no new managed native imports; MSVC alloc_text precedes the three relevant definitions. Journal source differs only by private-rule-builder visibility. Source discovery retains all 1,182 base methods and all 43 required feature methods, adding seven methods; no removed/renamed tests. This is not binary ApiValidator/WDK qualification.
- Independent **Sol 6.1 xhigh ACCEPT WITH CONDITIONS**: [design review](design-review-sol61.md), [coherent source review](review-sol61.md). Default documentation is now corrected and native assertions additionally cover the review's suggested exact SID/inheritance/collision controls. Windows native and matrix conditions remain pending.

No builder, product VM, Windows PowerShell, WDK or native Windows test was run. The first-free-builder wrapper's shared lock/log files are outside this session's writable roots; coordination was not bypassed. No parser implementation or accepted resource value changed, so prior throughput/memory measurements remain the justification; they were not remeasured here.

## Exact Windows / VM retest list

Run the complete **feature Debug/Release × user/SYSTEM matrix**, committed combined dev + large5 source, fresh label, complete discovery/execution, no skips. The 14 other-branch cases must be resolved by their owners and rerun; the combined-line goal remains open until all four legs pass. Specifically require:

1. Full `StagedPrivateStorageNativeTests` (two new controls); all `StagedLargeFileTests`, `StagedLargeFileNativeTests`, `StagedLargeDefaultsTests`, `StagedLargeIntegrationTests`, `StagedAllocationRecoveryTests`.
2. Full `StagedInspectionSnapshotTests`, including unchanged `Read_lease_has_no_write_or_delete_rights_and_survives_the_owner_until_its_last_close`, new `Budgeted_snapshot_keeps_its_slot_until_the_read_lease_closes_without_changing_native_rights`, independent offsets, cancelled capture and timed-out parser lifetime.
3. Full `InspectionModeDefaultsTests`, `PolicyTests`, `HttpPolicyStoreTests`, `InspectionServiceTests`, `AuditTrailTests`, `ArchiveInspectionTests`, `PlainTextDecodingTests`, `NotificationRecordTests`; explicitly RN-012, RN-013, `Motivo_de_nao_inspecao_e_registrado` and the second-writer sharing control.
4. Full allocator/handback/publisher/attachment/journal/compaction/archive suites, including every other-branch case named above and the existing lost-epoch and strict metadata missing-parent adversarial controls. Preserve their custody/retention/ForbiddenByteCount assertions.

Protected VM work remains Claude's existing workflow on **`SAFEUPLOAD_DEBUGGEE=win10-debug3` only**, standard user **t5actor**, win10-debug2 off. After the four-leg matrix and required matched-artifact gates, run existing [T9R01–T9R06](../../../UX-LARGE-RECOVERY.md#exact-windowsvm-retest-list) and [T9 large-file rows](../../../UX-LARGE-VM.md), including default-budget refusal/other-SID save, repeated failed CREATE → normal saves, restart/reboot and no notification closure. Observe fresh private-root ACL creation and normal clean/sensitive 64 MiB/512 MiB saves; 2 GiB rows require explicit adequate budgets as already documented. Keep ordinary/runtime-Verifier/boot-Verifier, independent public bytes and separate restoration under the approved lab rules. No new activation/cutover or qualification claim is made.
