**REVISE — Sol 6.1, xhigh review at `0674a37b`.**

1. **High — native EA handles can transmit uninspected payloads after callback cutoff.** [T22:509](driver/T22-SMB-UNC-DESIGN.md:509) includes `FILE_WRITE_EA` in the native route. [T22:529](driver/T22-SMB-UNC-DESIGN.md:529) permits native operations to continue after cutoff while C3 holds publication and head advancement.

   Counterexample: open an existing protected object with `FILE_WRITE_EA`, without `FILE_WRITE_DATA`; lose callback coverage; submit a forbidden marker through `NtSetEaFile`. SMB authorizes this mutation using the separate EA grant and stores the supplied values, which are arbitrary byte arrays. C3 can hold every subsequent save while those uninspected bytes reach the server. This is a **documented design counterexample, not an observed leak**. ([Microsoft SET_INFO contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/43cf22fe-84cb-49cf-b3e7-e3d7d766a7b7), [EA format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989))

   **Required change:** keep payload-bearing EA authority on a private/refused path unless inspection enforcement survives cutoff independently. State the approved T8 EA content boundary explicitly. Extend N09 with forbidden-marker attempts before/after cutoff, duplicates and reconnect; extend N11/qualification with independent server EA-byte observation. Current [native admission excludes `FILE_WRITE_EA`](driver/SafeUpload.Minifilter/StageStream.c:3570); the proposed route must preserve that protection.

All eight earlier findings are otherwise **closed at design level**: C1/C2 coverage-loss gates; corrected cross-volume contract; finite reservation/rename/replay candidates; §7.4/N13 range/head ordering; corrected provenance; §8.2 native lifetime and population barriers; §6.1/D14 concurrent-edit outcome; repaired T21 anchor.

The remaining source claims match the cited implementation. Owner recommendations are reasonable, including D14’s explicitly pending lost-update limitation. Native controls and qualification are adequate subject to the EA correction and existing feasibility gates.

No files changed; no builds, tests or VM actions performed. SMB remains disabled; T4’s runtime stop remains.