# T9 N-U4-06 on the target OS (win10-debug3, Windows 10 19045.2965): PASS

Non-qualifying planned component row: native mechanism evidence **without the new metadata kernel**. The installed original `SafeUpload.sys` (SHA-256 `ADA9D05A…`) was stopped and unloaded before, during and after each subject. This is not protected-pair qualification.

| Attempt | Source / control SHA-256 | Result |
|---|---|---|
| `nu406t1` | `b7877339` / `9338320A…` | **FAIL (harness)**: the actor control exceeded the runner's arbitrary 5-minute task bound on a first-logon profile, and the control buffered all events, leaving no trace. Restoration passed (BaselineClean=True, overlays deleted, base untouched). Kept locally under `t9-target-nu406t1/` |
| PS 5.1 gate `m2t9nu406h3`, builder `nu406b4` | `77c78918` / `93EFE2C6…` | PASS: per-case progress trace and a 15-minute liveness bound added; no assertion change |
| **`nu406t2`** | **`77c78918` / `93EFE2C6…`** | **PASS** for both subjects |

`nu406t2`, each subject on its own fresh disposable overlay (EFI reset, no TPM), serially, with both builders idle and `win10-debug2` off:

- **Actor:** standard `t5actor` (Medium integrity, not elevated, interactive session 1, one-boot autologon). **Admin:** elevated `vika` (High).
- Both report OS `10.0.19045.2965` (TargetBaselineMatches=True) and native A=U=4096. Each has Verdict PASS: 52 comparisons PASS, 12 record-only (unpreallocated chunked allocation, measured only), and the complete 32 replacement / 48 allocation / 7 fault / 8 retention / 1 release rows. Host validation passed for both.
- The builder-measured facts reproduced on the target. Held-target replacement works only with class 65/flags 3 plus predecessor SHARE_DELETE; class 10 and class 65/flags 1 are refused. The old object ends Links=0, DeletePending=True, still readable through the held handle. Preallocated rows stay within Q. Every fault stage is refused with exactly `0xC0000022` (rename without SHARE_DELETE: `0xC0000043`) and is Held, with R_phys never decreasing, including the real 3xQ overrun. A held, unlinked predecessor reopens by FileId (`0x00000000`, same identity); after the last close it returns `0xC000000D`. The release row stays NativeDestroyedChargeHeld (no native refund; the persisted release record is agent-side evidence).
- Elapsed time: the actor took 130 s and the admin 3.4 s, both well within the liveness bound. The actor's time is spread over many cases (12–18 s steps), consistent with first-logon background load rather than a stall.
- Restoration was checked separately after each subject on another fresh overlay: BaselineClean=True, audit settings unchanged, RunDiskBaseUntouched / XmlUnchanged / OverlayDeleted=True.

Curated receipts: [t9-nu406-target/](t9-nu406-target/) (verdicts, progress traces, runner inputs, SHA-256 of the raw JSONL). Raw evidence (ignored by git): `t9-target-nu406t{1,2}/`. Builder discovery: [t9-nu406-builder-discovery.md](t9-nu406-builder-discovery.md).

This closes the re-review's N-U4-06 before-first-boot condition ([re-review](t9-inc3-preboot-rereview-sol-high.md), finding 2). The protected first boot still needs N-U5-01 on the authorized component host.
