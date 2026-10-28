# T9 kernel pair-context fix (4f1d69d3): narrow independent review (Sol 6.1 high)

Reviewer: fresh read-only Codex session `01a184b6-8bfd-7223-985d-4f7afcf630f8`, `gpt-6.1-sol`, effort high, standard tier, 2026-10-28. Verbatim report follows.

**ACCEPT** `4f1d69d3` for the next authorized N-U5-01 component-overlay load, after the required fresh kernel build/static gates. No blocking source finding. This accepts the fix; N-U5-01 and protected-pair qualification remain outstanding.

1. **ConnectionContext is captured memory on this user-mode connection path.** `FilterConnectCommunicationPort` transports the context through the FltMgr message-device CREATE EA. The I/O manager captures user-mode EA data into system memory; ConnectNotify receives the context within that captured data, rather than the agent’s original stack address. A user issuing the native CREATE directly still goes through EA capture.

   The exact-size check followed by `RtlCopyMemory` into a local structure is appropriate. It neither retains the callback buffer nor follows embedded pointers. Removing `__try` is safe under this callback contract.

   **Do not assume eight-byte alignment:** the inline context can be less aligned, and a byte copy handles that. Also, this repository declares the pair under `#pragma pack(push, 4)`, so the removed probe required **four-byte**, not eight-byte, alignment. Merely being less than eight-byte aligned would not explain its failure. See [pair layout](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.h:128), Microsoft’s [ConnectNotify reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_connect_notify), and the locally available [FltMgr port analysis](/home/victor/Work/kbdvc-verify/_kb/vx-underground/text/papers-windows-internals-and-analysis-2023-01-04-investigating-filter.txt:280).

   **Uncertainty:** the EA implementation is more specific than the public callback parameter description. I did not independently disassemble the target’s FltMgr/I/O manager or observe its callback pointer. My conclusion covers the supported Windows user-mode connection path, not arbitrary kernel code violating that contract.

2. **`0x800703E6` matches the removed probe’s failure.** `ProbeForRead` rejects a nonempty kernel-address range with `STATUS_ACCESS_VIOLATION` (`0xC0000005`); insufficient requested alignment can raise `STATUS_DATATYPE_MISALIGNMENT` (`0x80000002`). Both map to Win32 `ERROR_NOACCESS` (`998`, `0x3E6`), producing HRESULT `0x800703E6`. A caught exception returned as NTSTATUS also explains the absence of a bugcheck. See Microsoft’s [ProbeForRead contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread).

   The [receipt](../../../driver/evidence/2026-10-28/t9-nu501-nu501c2/collected/result/receipt.json) is consistent with that explanation, but contains neither raw NTSTATUS nor callback address/alignment. It cannot distinguish the exceptions or conclusively establish their origin.

3. **The remaining pair validations are sufficient for these untrusted bytes.** In [SafeUploadMetadataPair](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:507):

   - NULL/exact-size checks bound the single copy to 24 bytes.
   - Cookie checks reject zero, out-of-range and nonrepresentable values. The cookie is compared as a numeric serial, never dereferenced.
   - `MetadataPin` finds the live group and acquires rundown under the lock.
   - `MetadataAuthenticate` binds the caller to the original process/token, service SID and authenticated main connection.
   - The GUID comparison binds the driver instance.
   - Locked `Revoked`/`Paired` checks serialize acceptance against revocation and duplicate pairing.

   I found no other instance of this buffer-category mistake in the two requested files. The remaining probes operate on **MessageNotify user buffers**, where probes and exception protection belong; they must remain. The metadata control path captures input and checks the captured header against its first snapshot. Native SET_INFORMATION reads use I/O-manager-buffered input; READ/WRITE buffer addresses are checked and forwarded without dereferencing their contents. See [metadata controls](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:1375), [main message dispatch](../../../driver/SafeUpload.Minifilter/Communication.c:2124), and Microsoft’s [MessageNotify contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_message_notify).

4. **Loading verdict: ACCEPT within the existing component authorization.** Use the fresh disposable `win10-debug3` component overlay, runtime Verifier `0x13B`, no protected folders/actor, existing stop rules and separate restoration check. A successful rerun must establish the remaining N-U5-01 assertions.

Review remained offline and read-only. HEAD advanced concurrently to `052f883b`; the reviewed kernel files remained identical to `4f1d69d3`. Microsoft links are reference pointers, not pages fetched during this review.