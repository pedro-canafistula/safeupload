**ACCEPT WITH CONDITIONS — design proposal only.** Reviewed by Sol 6.1, xhigh at `35f057ce`. The main identity, caller-authority, seeding, replacement and recovery gaps are honestly gated. Owner recommendations are reasonable; the qualification plan requires independent byte evidence. SMB remains disabled.

1. **High — forced teardown lacks an explicit coverage-loss gate.** [T22:127](driver/T22-SMB-UNC-DESIGN.md:127) proposes synthetic remote uppers; [T22:314](driver/T22-SMB-UNC-DESIGN.md:314) requires a permanent publisher fence. [T22:385](driver/T22-SMB-UNC-DESIGN.md:385) acknowledges callback loss but establishes only local draining. Microsoft confirms [new callbacks stop at teardown start](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_teardown_callback); [T5:311](driver/T5-NATIVE-PUBLIC-OPENS.md:311) distinguishes forced cutoff from orderly draining.

   **Required change:** add a blocking feasibility condition proving that live synthetic handles/mappings cannot reach redirector code with SafeUpload-owned contexts, and surviving publisher/duplicate handles cannot admit mutations outside the fence. Extend N02/N09 with forced teardown before/during upload, after fencing and after rename, including service absence and reconnect. Journal holds alone cannot enforce this. Previously authorized in-flight bytes require no retroactive recall.

2. **Medium — the cross-volume retargeting claim is incorrect.** [T22:129](driver/T22-SMB-UNC-DESIGN.md:129) states a same-volume restriction. [Microsoft’s contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_io_parameter_block) permits another-volume `TargetInstance` for the same minifilter/altitude with adequate stack size; the replacement `TargetFileObject` must belong to that selected instance’s volume.

   **Required change:** correct the rationale. Keep separate generated I/O and N02 as the proposed architecture and feasibility gate.

3. **Low — enumerate the finite diagnostic candidates.** [T22:285](driver/T22-SMB-UNC-DESIGN.md:285) and [T22:427](driver/T22-SMB-UNC-DESIGN.md:427) leave reservation candidates and rename variants unspecified. [M29’s explicit replay branches](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ae543f57-d993-4905-bce0-3cfc446c1fbb) depend on connection configuration.

   **Required change:** before diagnostic authorization, enumerate candidate access/share masks, rename classes/flags and decisive stop outcomes. Separate admitted single-channel ordinary durable reconnect from excluded multichannel/persistent replay controls.

No files changed; no tests or VM actions performed.