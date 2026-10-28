# N-U4-06 native-store mechanism control

Windows PowerShell **5.1**, x64, built-in Add-Type C# 5 only; no SDK, test host,
driver/agent install or protected-pair qualification. This directory authorizes
no VM/builder run. The control uses a unique private fixed-NTFS temp directory
and removes only that tree. Record the installed driver separately; run without
the new metadata kernel loaded.

## Runners

Both runners take **committed** control bytes with `git show <commit>:path`,
record the commit/SHA-256, require a fresh evidence and guest directory, verify
the hash and PS 5.1 parser in the guest, collect JSONL/stderr/child exits, and
validate structured receipts on the host. Transport success cannot pass a row.
A mismatch is a STOP; preserve the first receipt, resolve its cause before a
new label/run, and never loosen an assertion to accept discovery.

From the repository root (replace `<commit>`; labels are 3–30 alphanumerics):

```bash
SAFEUPLOAD_DEBUGGEE=win10-debug3 bash driver/scripts/t9/Invoke-TargetNativeControl.sh nu406target01 <commit> --dry-run
bash driver/scripts/t9/Invoke-BuilderNativeControl.sh nu406builder01 <commit> --dry-run
```

Dry runs validate arguments/commit/committed input/unused evidence destination
and print the plan/hash. They create no evidence or locks and contact no guest,
builder or libvirt. Remove `--dry-run` only in an authorized orchestrator run.

**Target:** `Invoke-TargetNativeControl.sh` requires `win10-debug3` explicitly,
with debug2 off and both builders idle. It holds both existing builder-run flock
locks nonblocking through restoration. Work bypassing those locks must also be
stopped. Evidence: `driver/evidence/<date>/t9-target-<label>/`.

Each subject gets a fresh disposable overlay: interactive standard `t5actor`,
then elevated `vika` remote-shell admin. After the actor overlay's clean baseline
and OS/driver inventory, the runner creates `t5actor` in Users
(`S-1-5-32-545`) only. A random password is generated **inside the guest** and is
never printed/exported. One-boot Winlogon autologon (`AutoLogonCount=1`), OOBE
privacy and first-logon-animation suppression follow StageNotepad's pattern.
It requests a reboot, waits up to 300 monotonic seconds for a **changed boot
ID**, rechecks OS and stopped/unloaded original driver, then waits up to 180
monotonic seconds for exactly one `t5actor` Explorer in a session >0. A limited
Interactive scheduled task runs the actor control. No manual sign-in pause or
product installation is involved. The one-boot secret stays on that discarded
actor disk. Before/control/after boot IDs must match the post-reboot inventory;
the initial actor boot must differ. Admin must not reboot during its row.

The existing image-store/run-disk helpers enforce EFI reset on overlay starts,
no TPM, original base/XML preservation and run-disk deletion. On success or
failure the runner captures diagnostics, discards the run disk, boots a separate
fresh restoration overlay, requires `BaselineClean=True`, pinned UUID and
unchanged process-audit values, then discards that overlay. Successful target
execution uses four overlays and leaves the original base/XML off. Unprovable
cleanup stops with state retained; never delete an unknown chain. OS must be
**19045.2965**, original driver hash must match, and SafeUpload must stay stopped
and unloaded before and after the control. Subject token/SID/integrity/session,
script hash, child/task exit and boot receipts are mandatory.

**Builder discovery:** `Invoke-BuilderNativeControl.sh` takes **no locks**.
The orchestrator must run it under `~/Work/safeupload-tools/builder-run.sh`,
which selects the first free approved builder and exports `SAFEUPLOAD_BUILDER`.
It uses `approved_builders.py --role gate` and its identity-checked remote-shell
transport. Exactly one elevated admin control runs from a fresh guest directory;
no actor or VM lifecycle is involved. Evidence:
`driver/evidence/<date>/t9-builder-native-<label>/`. `-ExpectedOS 19045.6466`
requires that exact builder OS and records **MechanismDiscovery=True,
ProductQualification=False, TargetEvidence=False** in environment/verdict JSON.
An OS-matching builder run does not become DIFFERS merely for being non-target.
Its `TargetBaselineMatches` remains false; `ExpectedBaselineMatches` is true.
Discovery must pass before independent target reproduction; it never closes
the target gate.

## Coverage and proof boundary

Existing assertions are unchanged:

- **32 replacement rows:** class 10, class 65/flags 1, class 65/flags 3 and
  released-predecessor/class 10, crossed with hold, SHARE_DELETE and DELETE
  access. Full status/identity/link/DeletePending/readability comparison.
- **48 allocation rows:** Single, PreallocatedSingle, PreallocatedChunked and
  observational Chunked; L=64,192,1192,8192,65537,131072; A=4096,65536; measured
  native A=U=4096. All 36 single/preallocated vectors stay within Q at every
  sample. The 12 unpreallocated Chunked vectors assert no overshoot magnitude
  or occurrence. No threshold was added.

New receipts:

- **7 FaultResult rows:** Allocation, Write, F1, EOF, F2, Rename, F3. Each uses
  a real native refusal and is classified **Held**, including F3 after one
  successful rename (never replayed). Allocation/write/EOF/barriers use a
  production current-role data-read handle (Read|DELETE) lacking write access; Rename uses the
  selected class 65/flags 3 against a predecessor without SHARE_DELETE.
- Every fault fixture precharges Q=4096 for three distinct objects: new output,
  current/predecessor and residue. New/current after replacement is one identity,
  never a second charge. It natively sets new AllocationSize=12288 (>Q), observes
  it before the fault, then samples immediately after refusal and after each
  admitted EOF/F2/allocation/final-barrier normalization. The final allocation
  is 4096; retained new charge stays 12288, total 20480, through last output
  handle close. The normal prefix is also sampled after every native call.
  These deliberately negative fixtures issue their fault even after an
  injected overrun; production itself stops admission when it observes an
  overrun. Test-controlled normalization is not an automatic product retry or
  a newly Committed result.
- **8 RetentionResult receipts:** one for each fault plus Release, **81 frames**
  total. At every frame, per-object retained debit is exactly
  `max(Q, Round(each allocation ever observed,U))`, then summed across distinct
  current/new/predecessor/residue identities. Fault, normalization, Links=0,
  DeletePending and final close never refund it. The model mirrors
  `StagedMetadataStorePlan.cs`; it does not execute that production class.
- **1 ReleaseResult:** positive class-65/flags-3 replacement, held predecessor
  identity/allocation/EOF, Links=0/DeletePending=True, then close the last
  predecessor handle. Reopen the captured `FileInternalInformation` ID through
  native FILE_OPEN_BY_FILE_ID, using the same anchor as volume hint: first
  while linked (setup validation), while unlinked/held, and after last close.
  Every call records exact NTSTATUS, IO_STATUS status/Information and identity.
  The charge remains through Linked → UnlinkedHeld → UnlinkedDrained.
- Volume free-cluster values before replacement/while held/after close are
  **observation only**. Other volume activity and deferred frees prevent exact
  attribution; there is no invented tolerance.

**Native destruction is not persisted accounting release.** A passing identity
probe establishes that this file object is no longer reopenable after last
close and its former allocation is no longer attributable to a live object.
It does not prove exact volume-wide reclaimed clusters or the agent's durable
identity-bound `MetadataStorageTransition`. Receipts explicitly set
`PersistedReleaseVerified=False`, `AccountingReleased=False` and classify
`NativeDestroyedChargeHeld`. Released/reduced accounting requires the separate
agent-side persisted transition, drained operations and required barrier proof;
this native control never applies a refund. PASS must not be reported as full
N-U4-06 accounting closure without that complementary evidence, or as protected
pair/crash/power-loss qualification.

## Exact expectations and provenance

The same strict new comparisons run on builder and target:

| Operation | Expected NTSTATUS | Source / confidence |
|---|---|---|
| Current role (no write data): allocation/write/F1/EOF/F2/F3 | `0xC0000022` ACCESS_DENIED | Microsoft NtWriteFile/NtFlushBuffersFile/NtSetInformationFile access contracts; citation comments in C#; native behavior still to execute |
| Rename, held predecessor without SHARE_DELETE | `0xC0000043` SHARING_VIOLATION | Measured class-65/flags-3 table in results below |
| Positive rename; linked FileId reopen | `0x00000000` SUCCESS | Selected replacement table; linked reopen validates FileId/anchor mechanism before using negatives |
| FileId reopen while unlinked/held | `0xC0000056` DELETE_PENDING | **Unmeasured discovery hypothesis**, MS-ERREF status name; this POSIX-unlink combination is not guaranteed by the cited docs |
| FileId reopen after last close | `0xC000000F` NO_SUCH_FILE | **Unmeasured discovery hypothesis**, MS-ERREF status name; exact NTFS result must be established on builder, then target |

There is no status-family acceptance or fallback. In particular, a different
FileId/anchor behavior must fail discovery and be resolved from its evidence
before target use. Failure IO_STATUS fields are retained raw; their undefined
completion values are not assigned invented expected values.

Sources: [growth design §8.4 / N-U4-01..06, N-U8-01 / predetermined faults](../../docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md),
[measured replacement/allocation results](../../evidence/2026-10-28/t9-inc3-native-results-2.md),
[first findings](../../evidence/2026-10-28/t9-inc3-native-findings.md),
[production accounting](../../../agente/SafeUpload.Agent.Service/Interception/StagedMetadataStorePlan.cs)
and [native adapter](../../../agente/SafeUpload.Agent.Service/Interception/StagedMetadataStoreNative.cs).
Source/segment/read masks remain `0x130083`/`0x120083`/`0x120081`, child share 7,
anchor access `0x120081`/share 3, child options `0x20006A`, and the existing
private security descriptor. The current-role fault handle uses `0x130081` (Read|DELETE); the rename
negative removes predecessor SHARE_DELETE; only identity probes add FILE_OPEN_BY_FILE_ID.

## Offline and standalone checks

```bash
bash -n driver/scripts/t9/Invoke-TargetNativeControl.sh
bash -n driver/scripts/t9/Invoke-BuilderNativeControl.sh
python3 driver/scripts/t9/native_control_verdict.SelfCheck.py
python3 driver/scripts/check-doc-links.py
```

The Python self-check extracts the **actual embedded runner verdicts**, accepts
synthetic target/builder PASS receipts and rejects missing/duplicate rows, wrong
ExpectedOS/status/classification, changed refused state, reduced R_phys at fault,
normalization or close, a reopenable destroyed object, premature accounting
release and a free-cluster assertion. It makes no Windows or network calls.

Copy the two PowerShell files together for Windows's managed-only check:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\T9\native-store-mechanism-control.SelfCheck.ps1 -SelfCheck
```

The existing Windows harness gate already parses/self-checks both files with
PS 5.1. Embedded mutants cover each fault status/state/geometry/classification,
row/frame/charge coverage, every retained-charge sample (including consistent
total/debit reductions), identity/lifetime and release-proof boundaries, plus
the unchanged 32/48 comparison/layout/signature tests. `-SelfCheck` calls no
Windows APIs. Actual Windows compilation and execution remain required.

For standalone native execution, use the control's default
`-ExpectedOS 19045.2965` on target, or explicitly select `19045.6466` for builder
mechanism discovery. Use fresh UTF-8 evidence and capture the child exit. The
control emits JSON followed by exactly one `NativeStoreMechanism=PASS` or
`DIFFERS` (exit 1); `-ExpectBuilderTable:$false` still yields only `RECORDED`,
never PASS. Host runners require strict table mode, exact host expectation and
**32/48/7/8/1** counts; incomplete receipts fail.
