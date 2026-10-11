# R24 bounded gate failure and custody review

**Failure capture: ACCEPTED as an accurate bounded failure record. R24 full-gate outcome: NO-GO. Remote process custody: NOT PROVEN.** The earlier R24 source review accepted the correction and approved a bounded diagnostic attempt; this actual run failed in the lifecycle fixture before either barrier case or the main diagnostic. It did not qualify runtime or product behavior.

## Pinned evidence

The 34-file checkpoint is bound by `driver/evidence/2026-10-11/m2-t5-harness-r24-full-gate-a1-root-checkpoint-manifest.json`, SHA-256 `37bb1c52d9e514a0a6a71db01bce39a27887df4aaaaebc06610d71b57a88c274`. Its `FilesSHA256` map pins 33 files plus the checkpoint manifest itself; all 33 listed hashes match. The separate failure disposition, `m2-t5-harness-r24-full-gate-a1-root-failure-disposition.json`, matches SHA-256 `89a8a4d049bb4410d083e95495ccc0007cc97333f4ea033ff4af2c18f3a7a68a`; all 32 hashes in its evidence map match. The R24 source review capture remains `e4cfa1e2e9ab63214b4fae771583e8a990ac269ac6f932c0cebdec4e7834577e`; all 121 captured source, context, and author files match that capture, including all 63 frozen source pins.

## What failed

The prepared command ran once at 2026-10-11 15:04:42.375068 UTC and ended at 15:05:08.680606 UTC with exit code 4. The root observer binds it to shell PID 1567073 and the reviewed report hash. Local manifest, client, and finish self-checks passed; preflight reported the exact builder/user/PowerShell identity; upload reported 40 files. The lifecycle fixture then failed. The gate's own evidence says “Exact keeper-publication and pre-resume barrier diagnostics failed; main diagnostic was not started,” and its post-fixture local source-pin verification passed.

The fixture stdout is empty. Its captured stderr is 84 bytes and contains `HarnessWindowsGateLifecycleFixtureError=Could not find item C:\Users\vika\AppData.` The fixture client rejected the result because it did not receive two case records and a final sentinel. This is an early setup error, not an assertion failure at either keeper barrier.

The source location agrees with that boundary. `Invoke-R18BarrierCase` calls `Get-HarnessGateStateRoot` at `HarnessWindowsGateLifecycleFixture.ps1:264-270`, before it creates the fixture job at line 313 or starts the suspended RUN child at lines 320-322. `Get-HarnessGateStateRoot` probes fixed ancestors with `Get-Item -LiteralPath ... -ErrorAction Stop` at `HarnessWindowsGateProtocol.psm1:1415-1425`; the failing ancestor is `C:\Users\vika\AppData`. Therefore neither barrier case reached RUN/keeper creation, negative control, or cancellation. The failure is in the fixed state-root ancestor lookup; it does not invalidate the prior source-level cancellation review, but it prevents the fixture and main diagnostic from passing.

## Custody boundary

The captured local transport record identifies PID 1567487 with start ticks 7974292, exit code 1, `originalLocalIdentityTerminal=true`, `localTreeTerminal=true`, and no unexpected local descendants. The local wrapper also reached terminal state. Those facts prove local transport termination only; the client marks `localTransportCompleted=false` for this failed remote-fixture phase. They do not prove that the original Windows-side PowerShell/remote command or any remote descendants became terminal.

The postquery at 15:07:24.830146 UTC was read-only and explicitly records `FixtureRerun=false`, `ProductInvoked=false`, and `OriginalRemoteProcessTerminalProof=false`. I independently matched its 40 observed remote file hashes and paths to the R24 manifest: 33 execution sources, six support files, and the manifest all match. It also observed AppData as `Hidden, Directory`, a directory and not a reparse point. This later observation does not establish the exact cause of the earlier `Get-Item` failure, and the query's own terminal state is not proof about the original remote process. The disposition correctly leaves `RemoteCustodyQualified=false` and `FullRemoteCustodyQualified=false`.

No main self-check diagnostic or success-only cleanup ran; the remote source tree was retained. The captured outcome remains NO-GO, with runtime, pair, cutover, and product qualification false. The source author is working on R25 with existing checks unchanged; this review does not assess that candidate. No additional Windows, remote, host, VM, network, or Git action was performed for this review, and no rerun is recommended from this failure evidence alone.
