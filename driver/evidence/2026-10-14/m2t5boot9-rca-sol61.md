# m2t5boot9 root-cause analysis — Sol 6.1 xhigh (2026-10-14)

Analyst: `gpt-6.1-sol`, `reasoning_effort=xhigh`, read-only (Codex session `01a139ba-2042-7730-9ef3-7d5f72d430d4`), run independently of the fix `426c7dcd` on `44ad8a57`. Verbatim final report; checkout paths shortened.

**Root cause: successful CREATE links the stream but never sets `stream->Listed = TRUE`. High confidence.** This causes the driver to reject its own successful op19 receipt. The worker stops **before `StageDrain`**, so the proposed `FileObjects != 0` explanation identifies a downstream symptom.

1. **Successful v20 path.** `StageCreateStreamShell` allocates a zeroed stream, leaving `Listed=FALSE` ([StageStream.c:1822](driver/SafeUpload.Minifilter/StageStream.c:1822); [WDK allocation contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2)). Successful CREATE inserts it into `StageStreams` without setting that flag at [StageStream.c:2608](driver/SafeUpload.Minifilter/StageStream.c:2608). The retained failed-allocation path **does** set it at [StageStream.c:1925](driver/SafeUpload.Minifilter/StageStream.c:1925).

2. **The exact blocking condition.** After PREPARE/COMMIT/COMPLETION_PERMITTED, attachment completion clears `AttachCompletionPending` and `AllocationReceiptPending` at [StageStream.c:3991](driver/SafeUpload.Minifilter/StageStream.c:3991), then clears the completion fence and allocation-only delete reservation at [StageStream.c:4112](driver/SafeUpload.Minifilter/StageStream.c:4112). CLEANUP sets `AnyHandleCleanupObserved` and `HandleReceiptPending`, removes sharing and uninitializes the private cache map ([StageStream.c:5203](driver/SafeUpload.Minifilter/StageStream.c:5203)). The collector sends op19 without checking `Listed`; the service durably records `HandleObserved`. But reply application requires `stream->Listed` at [StageStream.c:6061](driver/SafeUpload.Minifilter/StageStream.c:6061). Because it is false, the handler takes the fallback at **6083**, leaving `HandleReceiptPending=TRUE`, `HandleReceiptAcknowledged=FALSE`, and `Wait=STAGE_WAIT_SERVICE`. [StageProcessStream:5779](driver/SafeUpload.Minifilter/StageStream.c:5779) then returns before drain/seal.

   This explains the durable op19 receipts with no seal, and `waitingVersions=0`: that counter includes drain/exchange waits, not service waits ([StageStream.c:6295](driver/SafeUpload.Minifilter/StageStream.c:6295)). `RpcReferences` is decremented after reply handling; it is not the first blocker.

3. **Missing CLOSE is not an established attachment-reference leak.** The explicit upper-object reference taken at **3084** is released at **2889**, through successful transaction teardown at **4157**. CLOSE accounting itself has no `Listed` or attachment-ACK condition ([StageStream.c:5261](driver/SafeUpload.Minifilter/StageStream.c:5261)). Cached writes initialize the upper cache at **4392**; the worker never reaches its purge at **5430**. Cache/MM retention is therefore a plausible downstream explanation for the five remaining objects, but the supplied logs cannot identify their exact final reference holder. No additional dereference is justified.

4. **Why the contrasts differ.** Boot7’s `wakeClose=5` comes from attachment rollback: it explicitly decrements both counters and queues `WakeClose` ([StageStream.c:3670](driver/SafeUpload.Minifilter/StageStream.c:3670)). It does **not** prove five Windows CLOSE callbacks. At `60fecdbc`, `StageProcessStream` (**historical StageStream.c:2736**) had no op19 acknowledgement barrier and reached cache drain directly.

**Minimal fix proposal:** immediately after the successful insertion at **2608**, before releasing `StageListLock`, add:

```c
stream->Listed = TRUE;
```

Keep the op19 membership and exact-tuple checks. For consistent membership bookkeeping, clear `Listed` when unlinking at **5747** and final teardown at **7506**. Preserve actual CLEANUP/CLOSE accounting and every cache, paging, inspection and publication gate.

**Controls and tests:**

- Extend [teardown-participation-selfcheck.py](driver/scripts/t5/teardown-participation-selfcheck.py:321) to check both insertion paths publish `Listed` before unlocking; mutation removal must fail. My read-only audit caught the current omission and passed the proposed assignment **in memory**.
- Exercise successful CREATE → CLEANUP → exact op19 ACK through the kernel worker: require acknowledgement, pending cleared and drain queued. Changed identity/generation and lost-reply replay must remain fail closed.
- Recheck resave/new/replace/mapped, plus empty files and duplicate/retained-section lifetimes: no premature seal; eventual real CLOSE, seal and inspected outcome after lifetime release. Existing [agent test:95](agente/SafeUpload.Agent.Tests/StagedAttachmentV20Tests.cs:95) calls `SealAsync` directly, so it cannot catch this kernel defect.

No files changed, builds performed or VMs booted. The fix remains unqualified until the required review/build/runtime gates pass.