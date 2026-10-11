# T5 cancelled CREATE lifetime design

Date: 2026-10-11. Reviewer: Luna 6, max effort. Scope: cancellation around the native CREATE post callback;
the initial uncommitted native-record draft on `6ee1112e`. This is a product-security design finding, not the
integrated kernel lifetime review or runtime qualification. No VM was changed.

**Verdict: feasible with corrections; the original reference-owning draft must not activate its CREATE producer.**

- `STATUS_REPARSE` is a successful NTSTATUS without a successful open. Exclude it from accepted CREATEs.
- A lower filter can call `FltCancelFileOpen` after NTFS accepted deletion. SafeUpload above it sees failed CREATE;
  cancellation does not undo modifications. `FO_FILE_OPEN_CANCELLED` plus no `FO_HANDLE_CREATED` proves the
  special no-application-handle case, not a harmless failure or physical deletion. Preserve `AcceptedUnresolved`,
  remove the file-object lookup, and automatically reconcile the exact parent/full original ID or absence.
  Do not wait for a CLOSE that the contract does not promise will be observed above the canceler.
- A higher filter can cancel after SafeUpload saw successful CREATE. Holding an object reference can prevent the
  only guaranteed CLOSE; CLEANUP is not guaranteed before any handle is created. Use a non-owning exact
  instance/file-object key. For this altitude, capture the canceled/no-created-handle facts before forwarding CLOSE,
  remove the lookup before object-address reuse, and record its actual completion. Ordinary app handles use CLEANUP.
- `FO_CLEANUP_COMPLETE` is useful when observed but is not guaranteed by cancellation. Never infer that it was set.
- Clear non-owning lookup keys on callback-coverage loss. Retain immutable metadata and callback/map references;
  neither context destruction nor forced instance teardown is a terminal lifetime receipt.
- These are provenance/lifetime facts within the existing accepted/unresolved intent, not new journal states or permits.
  Exact anchored observation remains required before automatic hold release; undecidable parent/identity evidence stays
  held and diagnosed. No new restart exception is approved for cancellation. If automatic reconciliation cannot meet
  owner rule 1(a), return to the owner before activating that path.

Primary contracts: [FltCancelFileOpen](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcancelfileopen),
[FILE_OBJECT flags](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object),
[CLEANUP](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup),
[pre-operation callback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_pre_operation_callback).

Required runtime rows include cancellation above and below SafeUpload, no fabricated no-effect receipt, automatic
parent/identity reconciliation, duplicate/inherited ordinary handles, pointer reuse after close, coverage loss and unload veto.
Keep the independent byte observer, Verifier and separate VM restoration. CREATE producer, authenticated replay/export and
service startup/close recovery wiring remain open; a static build alone cannot qualify these rows.
