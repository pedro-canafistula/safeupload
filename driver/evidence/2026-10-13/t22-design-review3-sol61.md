**REVISE — Sol 6.1, xhigh review of `e6f1990b`.** All earlier findings are closed at design level; one additional cutoff contract gap remains.

1. **High — native application mutation handles lack a cutoff contract.** [T22:433](driver/T22-SMB-UNC-DESIGN.md:433) preserves native delete opens; [T5:87](driver/T5-NATIVE-PUBLIC-OPENS.md:87) passes their original CREATE to the filesystem. [C1/C2](driver/T22-SMB-UNC-DESIGN.md:457) cover synthetic uppers and kernel publisher handles.

   Counterexample: open A with DELETE but no deletion intent, lose callback coverage, then issue TRUE/FALSE disposition through that application handle. Microsoft confirms [new callbacks stop at teardown start](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_teardown_callback), so this operation bypasses the required [BeginHeadChange ordering](driver/T22-SMB-UNC-DESIGN.md:402).

   **Required change:** explicitly select the native application route. Provide independent mediation, or require coverage-loss barriers for every native mutation-capable open—including ordinary opens without pending intents—until exact remote lifetime and authenticated reconciliation permit release. Extend N09 to native DELETE/security handles, duplicates, post-cutoff mutations, reattachment and reconnect. Distinguish continuing native operations from broker operations that can actually be fenced. This is a head/lifetime gap, **not an observed byte leak**.

2. **Medium — intervening same-object edits have no defined conflict outcome.** [T22:269](driver/T22-SMB-UNC-DESIGN.md:269) establishes coherence during seeding; [T22:289](driver/T22-SMB-UNC-DESIGN.md:289) reserves the target during final validation/rename. Another client can modify the same object between those intervals without changing its identity. [FILE_SHARE_WRITE permits competing write opens](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), yet line 270 promises no silent overwrite conflict.

   **Required change:** define the outcome and add deterministic N04/N06 controls changing same-ID bytes/EOF after seeding. If last-publisher-wins is intended, disclose that limitation and narrow the promise. If conflicts must be detected or preserved, specify the enforceable mechanism and owner choice. Identity and digest checks alone do not establish it.

3. **Low — the shared-protocol link targets a nonexistent anchor.** [T22:377](driver/T22-SMB-UNC-DESIGN.md:377) includes `--finding-2`, absent from the [actual T21 heading](driver/T21-USB-REMOVABLE-DESIGN.md:162).

   **Required change:** use `#53-per-range-exposure-and-shared-head-transitions`.

Earlier closure verified: first-review F1 has C1/C2 gates and cutoff controls; F2 matches Microsoft’s [cross-volume contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_io_parameter_block); F3 enumerates finite reservation/rename candidates and separate replay profiles. Re-review F1 is addressed by §7.4/N13’s atomic WRITE/EOF ordering and closed recovery; F2’s provenance is corrected.

The checked source claims are accurate. D1–D13 are candid and their recommendations reasonable, subject to finding 2. Qualification appropriately requires continuous independent server mutation/payload evidence, matched artifacts, three verification modes and separate restoration. Identity, authority, seeding, metadata, replacement and recovery mechanisms remain explicitly unproved gates.

No files changed or tests/VM actions performed. SMB remains disabled; T4’s runtime stop remains.