# Independent SDK V3 review record

Review date: 2026-10-06. Reviewer: Luna6. This note supplements the frozen V3 review package; it does not modify that package or authorize MSI execution/extraction.

## Exact source pins

- V3 script `winfsp-builder-sdk-extraction-plan-v3/extract-sdk-v3.ps1`: SHA-256 `0e0b17a56c528834c91745fbf0e54661561ae7e62c0acde113982f16e5df41cf`.
- Frozen V3 plan `winfsp-builder-sdk-extraction-plan-v3/plan.txt`: SHA-256 `184a645f42bac6db9a233d3f4758d3de364e098b368b9a074be0d135ee103417`.
- V3 source manifest: SHA-256 `4d36485dabfc88c9b22fd8b7604df144a45c4041c363df696b3f6ccb46829211`; all 24 listed rows pass `sha256sum -c`.
- Historical V2 parameter-binding failure readout: SHA-256 `e89a643c89549ff1ec701e72bb4948a93232ded25d2b97736d8596e6f5cf2f7c`. It records the `Split-Path -LiteralPath ... -Parent` `AmbiguousParameterSet` failure and no extraction attempt.

## Actual parse/compile evidence

The exact V3 source was checked on the pinned builder in Windows PowerShell 5.1. The root readout (`winfsp-sdk-v3-ps51-parse/root-readout.json`) SHA-256 is `11d6893a432581ece9af4f2631a34267de8ad3a1660491cdd28c19542ca0f8d8`; it binds the exact V3 source SHA and reports remote exit 0. The captured stdout JSON SHA-256 is `a68433d36f7f5325fcb9edb6973c40c5dbf721525857762403e42e5c51235588`; it records `ParseErrors=0`, `NativeCSharpCompilePassed=true`, and `DirectoryBindingPassed=true`. Stderr SHA-256 is `5fac1e349309e76e42f64381996245ccfa5a50f54c11a4f1c7d0b5617b426a34` and contains only the retained PowerShell module-initialization progress record. The readout records `ProductScriptExecuted=false`, `NativeFilesystemCallsExecuted=false`, `BuildStarted=false`, and `TrustChanged=false`. MSI extraction was not attempted.

The frozen plan's opening line says “not executed or PowerShell-parsed.” That statement describes the package when the plan was authored and remains unchanged as historical text. The later, separately pinned parse/compile evidence above records the completed parse-only check; it does not indicate execution of the product script.

## Review result and scope

Independent static result: **PASS**, with no concrete blocker found in the frozen V3 script or its pinned inputs. V3 fixes the actual V2 PowerShell 5.1 parameter-binding failure by using `[IO.Path]::GetDirectoryName($msiPath)`. The source pins the MSI bytes and Authenticode identity before and after; opens the MSI database read-only; verifies the exact reviewed administrative execution sequence; guards source/output paths and file identities; creates a fresh quarantine target and retained log; checks before/after installed WinFsp inventory and build actors; and inventories/hashes the extracted tree without executing extracted binaries. This is a static/readiness review, not an MSI extraction, installation, build, trust, or runtime qualification.

The MSI table receipt pins both `AdminExecuteSequence` and `AdminUISequence`. Microsoft documents that administrative installation uses these sequence tables and that `AdminExecuteSequence` lists the actions in the administrative execution sequence: [Administrative Installation](https://learn.microsoft.com/en-us/windows/win32/msi/administrative-installation), [AdminExecuteSequence Table](https://learn.microsoft.com/en-us/windows/win32/msi/adminexecutesequence-table). The frozen MSI hash and the table receipt are the basis for the reviewed action set.

The script calls `FileStream.Flush(true)` on a read-only log stream. The .NET Framework reference source flushes OS buffers only when `flushToDisk && CanWrite`, so that call does not attempt a write through the read-only handle: [Microsoft .NET Framework reference source](https://github.com/microsoft/referencesource/blob/main/mscorlib/system/io/filestream.cs).
