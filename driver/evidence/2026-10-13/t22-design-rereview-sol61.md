**REVISE — one remaining security-contract gap.** Sol 6.1, xhigh review of `0953036a`.

1. **High — outbound ranges lack atomic ordering against destination-head changes.** [T22:305](driver/T22-SMB-UNC-DESIGN.md:305) checks generation/delete eligibility before the first write; [T22:331](driver/T22-SMB-UNC-DESIGN.md:331) requires subsequent fencing, but [T22:408](driver/T22-SMB-UNC-DESIGN.md:408) specifies only an attempt/epoch submission gate.

   A newer allocation, cancellation or delete hold could become durable while another range is admitted under stale generation authority. Final rename validation is too late because temporary bytes already reached the destination. This concerns authorization of inspected bytes, not an observed uninspected-byte leak.

   **Required change:** reuse the common [T21 exposure/head transition protocol](driver/T21-USB-REMOVABLE-DESIGN.md:167), or specify an equivalent construction. Check current head/policy eligibility atomically at every write/EOF reservation; fence the old attempt before a competing head transition commits or native mutation forwards. Preserve previously admitted range receipts and fences through recovery. Add deterministic controls for both race orders, including failed tracking ACKs and service restart. Hold no kernel/global journal lock across SMB I/O.

2. **Low — stale checkout-relative provenance.** [T22:10](driver/T22-SMB-UNC-DESIGN.md:10) says the retained review receipt is absent from this checkout; it exists at this HEAD.

   **Required change:** correct that statement and distinguish historical draft provenance from the current review snapshot.

The earlier findings are **closed at design level**: F1 now has explicit C1/C2 coverage-loss gates and cutoff controls; F2 matches [Microsoft’s cross-volume retargeting contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_io_parameter_block); F3 enumerates finite reservation/rename candidates and separates the [configuration-specific replay branches](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ae543f57-d993-4905-bce0-3cfc446c1fbb).

D1–D13 describe user effects candidly; their recommendations are reasonable. Repository behavior claims checked against source are accurate. Qualification appropriately requires validated continuous server observation, independent bytes, matched artifacts, three-mode gates and separate restoration.

C1/C2, identity/authentication, seeding, metadata, replacement/recovery and P0 enforcement remain unproved blocking conditions. SMB stays disabled. No files changed; no builds, tests or VM actions performed.