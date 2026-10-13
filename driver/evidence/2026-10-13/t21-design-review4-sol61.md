**ACCEPT WITH CONDITIONS** — independent **Sol 6.1, xhigh** review of `0674a37b`.

**No new blocking or unsafe design findings.** Every earlier finding is closed **at design level**:

1. Surviving routing ownership and public-delete transport are concretely selected in [StageFs](driver/T21-USB-REMOVABLE-DESIGN.md:266) and the [cross-volume relay](driver/T21-USB-REMOVABLE-DESIGN.md:344).
2. [Per-range exposure](driver/T21-USB-REMOVABLE-DESIGN.md:164) now follows shared-head transitions, with irreversible fencing and explicit bounded nonretroactivity.
3. [Pre-attachment ownership](driver/T21-USB-REMOVABLE-DESIGN.md:392) supplies atomic handoff and close-once recovery when no app handle or CLEANUP exists.
4. [Ordinary remount recovery](driver/T21-USB-REMOVABLE-DESIGN.md:482) preserves accepted native results and generation floors while ending only the proved dead-incarnation hold. It covers FALSE recovery and all affected consumers.
5. [Review provenance](driver/T21-USB-REMOVABLE-DESIGN.md:10) accurately records the retained REVISE verdicts.

Microsoft’s [retargeting](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_io_parameter_block), [surprise-removal](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/handling-an-irp-mn-surprise-removal-request) and [canceled-open](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcancelfileopen) contracts support the proposed mechanisms. Exact device association, stale-handle isolation and integrated cleanup remain explicit native proof obligations.

D1–D8 adequately explain user-visible consequences, and their recommendations are reasonable. The controls are finite and decisive; qualification requires validated continuous byte capture alongside independent medium readback.

Existing conditions remain: owner decisions and numerical budgets before dependent implementation; T5 authority/security/seed prerequisites; C1–C11 exits; pre-boot lifetime review; final matched-pair Q1–Q8 qualification, Verifier, restoration and adversarial review.

No files changed, builds or VM runs performed. USB remains disabled; T4’s product VM stop remains in force.