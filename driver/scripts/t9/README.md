# N-U4-06 native-store mechanism control

Self-contained x64 Windows PowerShell 5.1 plus its built-in C# compiler. No SDK,
test host, driver installation, registry writes or system configuration changes.
Run separately as the interactive actor and the admin remote-shell subject on
**Windows 10 19045.2965**, **without the new metadata kernel loaded**. Record the
installed driver identity/hash separately; the script does not establish which
kernel is loaded. These are native mechanism results, not protected-pair qualification.
This directory does not authorize a VM/builder run.

The embedded expectations come from
[builder results](../../evidence/2026-10-28/t9-inc3-native-results-2.md),
[replacement tests](../../../agente/SafeUpload.Agent.Tests/StagedMetadataStoreReplacementNativeTests.cs)
and [allocation tests](../../../agente/SafeUpload.Agent.Tests/StagedMetadataStoreAllocationNativeTests.cs).
The target prerequisite is in
[the growth design](../../docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md)
and [pre-boot review finding 4](../../evidence/2026-10-28/t9-inc3-preboot-review-sol-high.md).

## Run

Copy the two `.ps1` files together to an operator-selected directory on the
already prepared target. Use a **fresh evidence filename for each attempt**.
Example commands below assume `C:\T9` and a fixed NTFS `C:\` volume. The script
creates a unique private directory underneath `-TempParent` and removes only
that directory in `finally`. Use an existing writable local directory for
`-TempParent`; the default is the invoking subject's normal temp directory.
The actor must have permission to create its private temp directory.

Offline self-check, usable before runtime under either subject:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\T9\native-store-mechanism-control.SelfCheck.ps1 -SelfCheck
```

From the actor's ordinary, unelevated Windows PowerShell shell:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\T9\native-store-mechanism-control.ps1 |
    Set-Content -LiteralPath C:\T9\actor-01.jsonl -Encoding UTF8
$code = $LASTEXITCODE
"ExitCode=$code"
```

From the admin remote Windows PowerShell shell, separately:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\T9\native-store-mechanism-control.ps1 |
    Set-Content -LiteralPath C:\T9\admin-01.jsonl -Encoding UTF8
$code = $LASTEXITCODE
"ExitCode=$code"
```

If `C:\T9` is not writable to the actor, choose another evidence destination.
These commands launch the native Windows PowerShell executable explicitly;
`Set-Content -Encoding UTF8` prevents Windows PowerShell's default UTF-16 file
redirection. Do not use `Join-Path` with `COM`, device names or an assumed
PowerShell drive. The control uses `System.IO.Path` for its Windows paths.
If transport wraps output as CLIXML, decode it using the existing remote
transport's CLIXML handling before evaluating JSON/summary lines; never treat
an SSH/process exit alone or a substring `PASS` as a verdict.

The control writes JSON records followed by exactly one runtime summary:

```text
NativeStoreMechanism=PASS
```

PASS requires the exact target OS revision and measured builder geometry
(native A=4096, cluster U=4096), 32 matching replacement rows, and all 36
single/preallocated rows within Q at every measured step. There are also 12
unpreallocated Chunked rows, for **48 allocation rows total**. Exit is zero.
The self-check ends with:

```text
NativeStoreMechanismSelfCheck=PASS
NativeStoreMechanismHarnessSelfCheck=PASS
```

A native failure, baseline/geometry difference, replacement difference,
deterministic allocation overrun, incomplete coverage or cleanup failure emits
a JSON error/first difference, `NativeStoreMechanism=DIFFERS` and exit **1**.
**STOP the lab sequence and preserve this first receipt.** Revise the design
before relying on a changed mechanism. No retry, rename fallback, learned table
or threshold adjustment is implemented. `FirstDifference` is in the JSON verdict;
raw native receipts remain available even if a case cannot finish.

`-ExpectBuilderTable` defaults on. For observation-only use from a PowerShell
script (not a PS 5.1 `powershell.exe -File` Boolean argument):

```powershell
& C:\T9\native-store-mechanism-control.ps1 -ExpectBuilderTable:$false
```

This disables only replacement comparison and reports `RECORDED`, never PASS.
Baseline checks, native-operation validity, deterministic allocation checks and
cleanup still apply. It does not close N-U4-06.

## Coverage and receipts

- 32 replacement vectors: class 10, class 65/flags 1, class 65/flags 3 and
  released-predecessor/class 10, crossed with requested hold, SHARE_DELETE and
  predecessor DELETE access. Exactly one rename attempt per vector. Writable
  target seed closes before the configured predecessor opens. Source access
  `0x130083`/share 7, anchor `0x120081`/share 3, predecessor `0x120081` or
  `0x130081`/share 3 or 7, native child options `0x20006A`.
- FileStandardInformation and full volume/file identity before/after, old held
  bytes, new links/DeletePending, and an independent read-only target open.
  Unheld old objects are explicitly unavailable; no identity is inferred from
  a path or recreated handle. The comparison includes every observation field.
- Allocation: Single, PreallocatedSingle, PreallocatedChunked and observational
  Chunked; L=64,192,1192,8192,65537,131072 and A=4096,65536. These use the
  builder's Segment access `0x120083`/share 7 with the same child options.
  U is measured independently. P=AlignUp(L,A), Q=AlignUp(P,U). Real native
  pointers, write sizes and offsets obey A. Preallocation sets P, not L.
- Every write, F1, EOF normalization, F2, allocation normalization and final flush
  has a status receipt and allocation observation. The initial create and
  preallocation are measured too. Peak is retained across normalization.
  As in the builder discovery, extension stops at the first observed overrun;
  EOF normalizes to min(L, written), allocation to P. Chunked overshoot is
  recorded only, with no expected magnitude or presence assertion.
- Token user/SID, elevation/type, integrity RID, true OS build plus read-only
  UBR, volume/sector/cluster/alignment geometry, script SHA-256 and PS version.
  All explicit NT calls record returned status, IO_STATUS_BLOCK status and
  Information, including expected rename refusals. No power-loss durability
  guarantee is inferred from flush success.

The self-check parses both files with the current engine (the Windows gate
must use the real PS 5.1 parser), checks P/Invoke types/out parameters, x64
rename/allocation/standard and supporting layouts, encoded rename bytes and
leaf rejection, status and observation mutations for all 32 rows, missing and
duplicate rows, allocation-overrun/lost-peak mutants, record-only behavior, and
the PowerShell-to-CLR verdict boundary. `-SelfCheck` invokes no Windows APIs.
Linux PowerShell parsing/C# compilation cannot establish Windows PS 5.1 or
NTFS execution. Those gates and both target subject runs remain required.

The Windows gate's parse/check lists include both scripts. Its remote staging
command currently creates only `t4`, `t5`, `t6` and `t10`; it also needs a `t9`
directory before SCP can copy these files. That command was left unchanged
because this task authorizes only the gate's file-list edits. The standalone
commands above do not depend on the gate's staging directory.
