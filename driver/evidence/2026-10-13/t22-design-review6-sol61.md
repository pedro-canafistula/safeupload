**ACCEPT WITH CONDITIONS — architectural decision proposal only.** Sol 6.1, xhigh review at `869c20fe`.

No new blocking design defects. All ten earlier findings are accounted for: nine remain closed at design level; review 5’s fresh-open gap is honestly converted into architectural failure and pending D16. It remains unsolved.

Remaining implementation-blocking conditions:

1. **High — the endpoint-only architecture cannot satisfy all-state privacy.** [T22:606](driver/T22-SMB-UNC-DESIGN.md:606) correctly identifies fresh uninspected writes during callback loss. Microsoft’s [teardown contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_teardown_callback) supports the counterexample. **Required:** resolve D16 before dependent implementation. The recommended D16 B needs a separately reviewed enforcement architecture covering direct writes, aliases, reconnect and enforcement outages. C1–C3 or passing ordinary rows cannot enable this design.

2. **High — owner choices and mechanism proofs remain prerequisites.** [T22:642](driver/T22-SMB-UNC-DESIGN.md:642) and [T22:878](driver/T22-SMB-UNC-DESIGN.md:878) preserve these conditions. **Required:** record applicable D1–D15 decisions before dependent implementation; prove identity, original caller/SMB authority, coherent seeding, metadata, exact-target commit and recovery before admission. Complete the T5 integration and qualification gates.

The owner tables candidly explain user effects; recommendations are reasonable. Native controls are finite and decisive, and replacement qualification appropriately requires continuous independent server data/EA-byte evidence. Material source and Windows claims check out.

SMB remains disabled. No files changed; no builds, tests or VM actions performed.