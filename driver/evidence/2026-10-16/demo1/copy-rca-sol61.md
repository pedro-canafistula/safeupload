**The evidence shows two separate failures. It does not establish that the service denies every other publication.** I found a concrete kernel CREATE lifetime defect, plus a separate fail-closed publication refusal. No files were changed.

**Publication failure — confirmed rejecting path**

The agent registers the permit, then calls `CreateUnbuffered` at [StagedTransferPublisher.cs:419](/home/victor/Work/safeupload-mvp/agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:419). The driver’s service-permit path falls through to legacy CREATE processing at [StageStream.c:8264](/home/victor/Work/safeupload-mvp/driver/SafeUpload.Minifilter/StageStream.c:8264).

That legacy path independently rejects protected writes when authentication, trust or destination admission is unavailable: [Filter.c:1467](/home/victor/Work/safeupload-mvp/driver/SafeUpload.Minifilter/Filter.c:1467). Admission requires the fixed-NTFS/canary checks and **no instance/global tracking loss**: [Context.c:505](/home/victor/Work/safeupload-mvp/driver/SafeUpload.Minifilter/Context.c:505).

Two important corrections to the interpretation:

- `legacyCreateGate` deliberately records **the instance’s volume name**, not the CREATE’s actual target: [Filter.c:1521](/home/victor/Work/safeupload-mvp/driver/SafeUpload.Minifilter/Filter.c:1521). Thus records 202/209 do **not** prove the service opened the raw volume.
- The subsequent `.pending` CREATE denials are cleanup fallout. The permit’s scope ends before the catch executes `File.Delete`: [StagedTransferPublisher.cs:452](/home/victor/Work/safeupload-mvp/agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:452). They are not the original publication failure.

The ring does **not** record which readiness condition failed. Therefore neither “stale permit” nor a particular Unknown/canary cause is established. Permits are individually keyed by transfer and temporary name; there is no alternating permit toggle.

After publication fails, the agent records `Retained`. Its publication loop selects only `Sealed`, explaining why waiting 60 seconds does not repair it: [MinifilterInterceptor.cs:1451](/home/victor/Work/safeupload-mvp/agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1451).

**Alternating copies — concrete source defect, runtime attribution still conditional**

The attach lookup rejects a CREATE when its `CallbackData` address equals an existing transaction’s address: [StageStream.c:3207](/home/victor/Work/safeupload-mvp/driver/SafeUpload.Minifilter/StageStream.c:3207).

But `StageAttachComplete` returns that callback data to Filter Manager **before clearing its lookup key**. The transaction remains searchable while subsequent stream/resource cleanup runs, until [StageStream.c:4284](/home/victor/Work/safeupload-mvp/driver/SafeUpload.Minifilter/StageStream.c:4284). Filter Manager resumes processing at completion; a reused callback-data address can consequently look like a duplicate CREATE. [Microsoft’s completion contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcompletependedpreoperation).

This is a real stale-key race compatible with rapid CopyFileEx retries. However, the ring’s missing site offsets prevent declaring it the proven source of these particular refusals. Another synchronous `STATUS_INVALID_DEVICE_STATE` exists for an unsuitable related directory object at [StagePublic.c:472](/home/victor/Work/safeupload-mvp/driver/SafeUpload.Minifilter/StagePublic.c:472).

The chronology also matters: copy 2’s metadata operations precede the first service publication failure; copy 4 precedes the second. **Copies 2/4 appearing immediately could be the writer’s private staged view.** The driver explicitly overlays that process’s directory enumeration: [StageStream.c:9628](/home/victor/Work/safeupload-mvp/driver/SafeUpload.Minifilter/StageStream.c:9628). Appearance there does not establish public publication.

**Smallest safe code correction**

**Kernel-only:** retire the callback-data lookup key immediately before handing the operation back, while retaining the transaction’s teardown ownership.

Add a helper immediately before `StageAttachComplete`, then replace its four `FltCompletePendedPreOperation` calls with this helper:

```c
static VOID StageAttachFinishCallback(
    PSTAGE_ATTACH_TRANSACTION tx,
    FLT_PREOP_CALLBACK_STATUS result,
    PVOID context)
{
    PFLT_CALLBACK_DATA data;
    KIRQL irql;

    NT_ASSERT(!tx->CancelRegistered);
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    data = tx->CallbackData;
    tx->CallbackData = NULL;
    StageStreamReleaseSpinLock(&StageAttachLock, irql);

    NT_ASSERT(data != NULL);
    FltCompletePendedPreOperation(data, result, context);
}
```

Exact replacement sites in this checkout: **StageStream.c:4158, 4177, 4182, 4229**. On installed source **b97d263e**, they are **4135, 4154, 4159, 4206**.

Keep the lookup entry, active count, references and existing final removal intact. Keep the duplicate check intact.

This removes false duplicate matching and stale cancellation lookup without granting additional access, changing inspection or bypassing any authority gate. **It would not fix the separate publication readiness refusal, Word compatibility, or already-Retained transfers.** It is a kernel lifetime change requiring cancellation/teardown/address-reuse verification and the repository’s pre-boot review/build gates.

I cannot recommend a safe publication availability hotfix from these artifacts alone: the failed readiness condition must first be identified. Exempting SYSTEM/the service, clearing Unknown or bypassing the legacy gate would violate the requested invariants.

**Why the clean `.docx` does not publish**

There is no demonstrated DOCX extraction failure here. For any transfer producing the supplied `CreateUnbuffered` exception, inspection and current approval checks have already succeeded before publication: [StagedTransferPublisher.cs:376](/home/victor/Work/safeupload-mvp/agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:376).

The DOCX also has initial CREATE refusals, records 207/208. The ring alone cannot bind service transfer `…d840` to that DOCX rather than copy 4; that needs the transfer journal. Its failure therefore cannot honestly be attributed to DOCX parsing or fixed by relaxing format inspection.

**Minimum Word support work**

- Correct CREATE/reopen handling for temporary and owner files, including the lifetime defect above.
- Virtualize `FileBasicInformation` timestamps/attributes and answer `FileRemoteProtocolInformation` (`0x37`) appropriately.
- Support or safely classify `FSCTL_CREATE_OR_GET_OBJECT_ID` (`0x900C0`) on the directory.
- Support staged `FSCTL_SET_COMPRESSION` (`0x9C040`) with defined publication metadata behavior.
- Preserve Word’s temp/backup rename, replacement and deletion sequence, including legitimate sharing/delete-pending behavior and reopening after publication.

These require kernel/common-application support; a publication-only agent patch would not make Word SaveAs2 reliable.