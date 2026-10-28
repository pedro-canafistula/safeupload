# T9 N-U5-01 component-host attempts (win10-debug3 component overlay, owner-authorized 2026-10-28)

Inputs: the signed pass-4 driver from gate `m2t9i3k1028a8` (`a2e5d428`, `SafeUpload-stage-prototype.sys` SHA-256 `B30457ED…`), and the feature-release agent package from gate `m2t9nu501a3` (`7c3ab3e5`; zip `F8849FEB…`, service `F6E1BD84…`). The component runs with an inert zero-destination policy, no actor and runtime Verifier `/volatile /flags 0x13B`, and is not a protected boot. Each attempt used a fresh disposable overlay, followed by a separate restoration overlay.

| Attempt | Scripts | Result |
|---|---|---|
| `nu501c1` | `1a3e3553` | **STOP before install (harness).** `Confirm-SecureBootUEFI` threw `0xC0000100` (variable not found) on the EFI-reset overlay instead of returning false. Nothing installed or loaded; no minidump. Restoration PASS. Fixed in `7339e4cf` (only `$false` or that exact status counts as off) and gated by the PS 5.1 gate `m2t9nu501h3`. |
| `nu501c2` | `dc420a9d` | **First load of the reviewed substrate.** The driver demand-loaded, the service bound the component evidence endpoint, and runtime Verifier `0x13B` was armed with `/query` readback (1,384 pool allocations, 0 failed). Steps Idle and Probe passed (real main bootstrap, zero grants). **Pair FAILED: HRESULT `0x800703E6` (ERROR_NOACCESS)**, so the control stopped there; Commit/hold/registration steps did not run. No bugcheck, Verifier report or minidump. Restoration PASS. |

**Kernel finding from `nu501c2`:** `SafeUploadMetadataPair` called `ProbeForRead` on Filter Manager's ConnectNotify `ConnectionContext`. That context is the create EA buffer already captured into kernel memory, not a user address, so the probe raises and every real pair failed closed. No authority was granted. Fixed in `4f1d69d3` (exact-size copy, all field validation unchanged). It needs the kernel static gate and a narrow independent check before the next component load.

Raw evidence (ignored by git): `t9-nu501-nu501c1/`, `t9-nu501-nu501c2/` (receipt `collected/result/receipt.json`).
