# T5 read-only recovery observation transport review

Date: 2026-10-11. Reviewer: Luna 6, maximum effort. Reviewed the proposal against `674e0bc7` before product implementation.
**Driver-side observation is feasible with the corrections below; the serial/root-ID-only proposal was NOT READY.** No VM or host
configuration changed. This is a product-security design review, not the integrated pre-boot kernel lifetime review.

- Return checked directory metadata directly instead of exporting directory handles. The response grants no child access, DELETE
  permit, physical deletion ACK or manual hold release. The service still requires exact lifetime proof and a reconciliation turn.
- Bind the original Mount Manager volume GUID into the native binding and durable destination identity. Volume serial/root/parent
  IDs alone can match a clone when the original is absent. Require that exact GUID plus full root/parent IDs and serial; missing,
  changed or ambiguous provenance remains held. Legacy records are retained without inventing their original GUID.
- Instance enumeration is mutable. Balance all returned instance/volume references, reject incomplete enumeration, bracket I/O with
  the existing topology generation/in-flight checks, and recheck per-instance retirement and admission before/after I/O. Pin the
  exact authenticated service connection/process through the callback; check replay revision and binding before returning.
- NTFS parent-by-ID selection may use its eight-byte ID only for a recorded zero high half; compare the resulting full 128-bit ID
  and serial. Never use the saved pathname as a substitute. Recheck non-reparse directory type, case mode and both anchors around
  two complete scans. These scans report a momentary name mapping, never a durable unlink receipt.
- Copy bounded input and output under local exception guards in the caller's callback context. Release local handles/references on
  every path. No cross-process handle ownership/revocation protocol is needed.

Scope correction: `Context.c` classifies fixed media using only `FILE_REMOVABLE_MEDIA`; `StageAdmission.c`, native reserve and
public-backend admission have no separate portable-device test. USB hardware can report fixed media. Before native admission is
enabled, capture exact successful `FileFsDeviceInformation` at PASSIVE_LEVEL and exclude portable/removable/remote or unknown
devices from M2 admission/coverage. Require the complete returned structure. This keeps unqualified USB disabled; it does not
implement T21. No additional owner decision is needed for either correction.

Primary sources: [volume serial definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/bf691378-c34e-4a13-976e-404ea1a87738),
[FltGetVolumeGuidName](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetvolumeguidname),
[FltEnumerateInstances](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltenumerateinstances),
[ZwCreateFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile),
[FltQueryDirectoryFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltquerydirectoryfile),
[message callback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_message_notify),
[device characteristics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/616b66d5-b335-4e1c-8f87-b4a55e8d3e4a),
[FltQueryVolumeInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltqueryvolumeinformation).

Implementation must still pass four WDK/PREfast/ApiValidator 0/0 builds, the agent matrix, the single integrated kernel lifetime/lock/
retirement review before first revised boot, protected Verifier/fault rows and separate restoration. No runtime completion is claimed.
