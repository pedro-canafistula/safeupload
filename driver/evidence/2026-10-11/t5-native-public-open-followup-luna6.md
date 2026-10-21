# T5 native public-open follow-up — Luna 6 max

Date: 2026-10-11. Reviewer: `/root/t5_public_proxy_routing_design_luna`, `gpt-6-luna`, max effort.
Scope: focused follow-up to the NOT READY routing review at `c82deb6f`; source/design only. No code, build or VM qualification.
This records the reviewer's returned findings, including the correction to the earlier suggested second-open/on-close fallback.

## Verdict: NOT READY

- Forward the original non-writing CREATE once with its original desired/share access and bind the resulting native FILE_OBJECT.
  A second independent backend open conflicts with ShareAccess=0. Duplicate handles share the same native object.
  Native DeleteAccess and original caller/full identity must remain bound; an object reference does not preserve the open after cleanup.
- Reject DELETE|FILE_DISPOSITION_ON_CLOSE as an equivalent to FILE_DELETE_ON_CLOSE. MS-FSA requires the link already be deleted or
  returns STATUS_NOT_SUPPORTED; the native builder control returned Win32 50. Classic FileDispositionInformation uses a currently
  open file object at PASSIVE_LEVEL. Do not fabricate support for Ex flags.
- Stripping native delete-on-close and applying ordinary disposition at cleanup loses intent at mandatory filter unregister unless
  another supported mechanism owns it. Cleanup cannot fail, and deferred work must account for TopLevelIrp restrictions.
- Keeping native delete-on-close unchanged preserves NTFS scheduling and filter-unload behavior. It does not solve post-CREATE binding
  failure: FltCancelFileOpen does not undo mutations. Preallocating contexts alone does not prove identity mismatch or connection loss
  impossible. Specify non-silent accepted/ambiguous reconciliation or prove namespace serialization eliminates the relevant failure.
- Both native and emulated routes block newer clean publication for an arbitrary reader lifetime if the durable destination reservation
  lasts until cleanup. Either that user-visible latency needs owner approval, or the design must release/relax the reservation after
  exact binding and define ordering of a newer clean publication against old-object cleanup. Native open timing alone proves neither.

The reviewer did not approve routing implementation. The later root correction in T5-NATIVE-PUBLIC-OPENS.md remains a proposal;
the scheduled-delete ordering and failure-policy choice require resolution before product code.

## Evidence and primary contracts

- [Accepted transaction note](../../docs/design/publication-and-namespace/T5-DELETES.md), sections 3 and 4.1–4.2.
- [Native disposition control](t5-ntfs-disposition-control-1011.txt): native CREATE delete-on-close opens succeed before creator close
  and fail with Win32 5 afterward; Ex on-close returns Win32 50.
- Checked backend factory: `driver/SafeUpload.Minifilter/StagePublic.c:357`, source `3be0fe71`.
- [NtCreateFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile).
- [Object lifetime](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/life-cycle-of-an-object) and
  [IRP_MJ_CLEANUP](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup).
- [FltSetInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsetinformationfile) and
  [MS-FSA FileDispositionInformationEx](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4c26c8cb-5a8f-4339-a372-b315c4974131).
- [FltCancelFileOpen](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcancelfileopen) and
  [FltQueueDeferredIoWorkItem](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltqueuedeferredioworkitem).
