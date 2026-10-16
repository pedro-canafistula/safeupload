# T5 descriptor measurements

These are opt-in, unprotected NTFS mechanism measurements under SYSTEM. They do not approve a descriptor exception, change
the exact stored-security contract, enable publication, qualify the protected pair, or cover non-SYSTEM subjects. Explorer display
is out of scope. The decision context is the [2026-10-15 memo](../../evidence/2026-10-15/t5-descriptor-decision-sol61.md) and
[native publication security control](../../T5-NATIVE-PUBLIC-OPENS.md#native-publication-security-control-2026-10-13).

Use a fresh label for every invocation and run serially on an authorized Windows machine. The wrapper runs Windows PowerShell
as SYSTEM with the existing scheduled-task/worker cleanup and 180-second Stopwatch deadline. Do not run the rejected
`-CompareAutoInheritanceRequests` candidate again. None of the new switches implicitly enables it.

```powershell
# First: Windows PowerShell 5.1 parse/signature/self-check gate, through the existing harness gate runner.
# From the repository on the host: bash driver/scripts/Invoke-HarnessWindowsGate.sh <fresh-label> .
# Or the focused self-check in Windows PowerShell 5.1 (no native calls):
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\driver\scripts\t5\security-roundtrip-native-control.ps1 -SelfCheckOnly

# Run each separately with a new label; retain its .txt, .exit and .pid receipts.
.\driver\scripts\t5\Invoke-SecurityRoundTripNativeControl.ps1 -Label t5-inherit-new1 -CompareNativeInheritance
.\driver\scripts\t5\Invoke-SecurityRoundTripNativeControl.ps1 -Label t5-convert-new1 -CompareAutoInheritConversion
.\driver\scripts\t5\Invoke-SecurityRoundTripNativeControl.ps1 -Label t5-marker-new1 -CompareMarkerBehavior
```

The example labels must be replaced if previously used. Switches can be combined in one serial invocation. Do not increase the
deadline to hide a failed run. Preserve the first failure and diagnose it before another run. No product VM is started by these
scripts; builder observations remain separate from target 19045.2965 and protected-pair qualification.

## Reading the results

The original seven stored-descriptor replay rows still run. Every native CREATE uses the existing parent-relative helper:
`FILE_CREATE`, access `0x00110082`, share zero, options `0x0020006A`; its granted access, regular-file status and `0x2A` I/O mode
are checked. Metadata observers check full object identities and query the same `0x1F` security-information classes as the original
reference (owner, group, DACL, SACL and label). Raw descriptors are compared without normalization or masked bits. The old compact
comparison is retained as an additional diagnostic; use `Result`, `Differences` and `RawStoredMismatches` for full byte equality.

| Switch | Expected output and interpretation |
|---|---|
| `-CompareNativeInheritance` | Seven `Construction=native-inheritance` rows, each `EXACT` or `DIFFERENT`, with full input/result bytes and differing offsets/fields. The inherited NULL-input case may match; protected/explicit cases are expected mismatches. The moved-from-another-parent case must differ; an exact result there stops the run as a changed baseline. An exact row establishes only that fixture's SYSTEM assignment in that parent. It does not establish ordinary/restricted caller authority, ownership defaults or labels: **non-SYSTEM subjects not covered**. |
| `-CompareAutoInheritConversion` | Seven `Control=AutoInheritConversion` rows. The full output of conversion with the current parent, expected descriptor, NULL object type, `FALSE` directory flag and file generic mapping is compared with the stored replay input. `CLOSED`, `CreateAttempted=False` means byte-identical input and no conversion CREATE. `DISTINCT` is followed by a normal publication CREATE and full `EXACT`/`DIFFERENT` comparison. Changed ACLs, protection, SACL or other fields remain visible in the conversion delta; a distinct output or successful CREATE does not relax their equality requirement. |
| `-CompareMarkerBehavior` | Ten fresh pairs: each counterexample shape gets separate parent-ACE, tree/keep, tree/remove, icacls and backup experiments. Each baseline must differ by exactly the expected-set/actual-clear `0x0400` bit. Thirty `MarkerBehavior` rows cover baselines, parent ACE add/change/remove, both tree resets, icacls save/pre-restore/restore, backup sources and restored copies. Each reports `EQUIVALENT` only if complete descriptors **and** access matrices match, otherwise `DIFFERENT`, retaining both hex descriptors and all byte deltas. A raw marker-only difference can coexist with `AccessMatrixEqual=True`. Neither result proves universal behavioral equivalence or approves a metadata exception. |

Parent ACE changes use `SetNamedSecurityInfoW(SE_FILE_OBJECT, DACL_SECURITY_INFORMATION)` and add/change/remove a Builtin Users
inheritable allow ACE (`FR`, then `FW`, then absent). Tree reset uses the same DACL-only information mask, `KeepExplicit=TRUE` and
`FALSE` on separate fresh pairs, and requires successful callbacks for both files. `icacls` saves each file's own DACL, records
the saved bytes, applies a temporary DACL-only change, then restores that file's save. No continue-on-error flags are used.

The AccessCheck matrix has five restricting SIDs (`SYSTEM`, Everyone, Authenticated Users, Builtin Users, Anonymous) and fourteen
rights: read/write/append data, execute, read/write attributes, DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, file generic
read/write/full mappings and MAXIMUM_ALLOWED. Tokens are SYSTEM-derived impersonation copies with maximum privileges disabled
and one restricting SID. These are restricted-SID probes, **not logons as those accounts**; both the normal SYSTEM and restricting
SID checks constrain results. They do not establish non-SYSTEM native file-open, integrity, sharing or application behavior.
[Restricted-token contract](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).

Backup uses synchronous buffered handles and `BackupRead`/`BackupWrite` with security processing enabled. Only a private thread
token enables backup/restore/security privileges; its previous thread token is restored, and the process privilege inventory must
remain unchanged. Destination handles include WRITE_DAC, WRITE_OWNER and ACCESS_SYSTEM_SECURITY. The bounded backup stream
must contain BACKUP_SECURITY_DATA; the security payload, source/restored descriptors and deltas are retained. Sources are checked
unchanged and copies retain their pre-recorded identities. This measures this backup API path, not third-party backup software.
[BackupWrite contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupwrite).

## Checks and restoration

`security-roundtrip-native-control.SelfCheck.ps1` is a portable managed-only check: all 17 new P/Invoke signatures, BOOL/BOOLEAN,
callback and structure packing; backup-stream decoding; all 64 byte offsets of a synthetic complete descriptor; and all 16 switch
combinations. The main `-SelfCheckOnly` also checks the existing Windows helpers. The native generic-mask assertions previously
called from the writer self-check now run on the real measurement path, preserving those assertions without native self-check calls.

Every created fixture is registered by full file identity. Cleanup checks the entire registered inventory, refuses unexpected
objects or identity changes, resets DACLs only, rechecks identities and removes children before directories. Uncertain cleanup
fails and retains evidence; it must not be reported as restored. A forced worker termination can interrupt fixture cleanup: inspect
`FixtureRemoved=True` separately from `NativeControlTaskRestored=PASS`, and independently verify no retained fixture/task/worker
before calling restoration complete. A measurement `PASS` describes completed measurements, never exact construction success.

Local Linux verification: pwsh parsing and the portable self-check pass; shell syntax and diff checks pass. Full self-check execution
on Linux is unavailable because the existing writer helper uses .NET Framework `WindowsImpersonationContext`. Windows PowerShell
5.1 parsing/full self-checks and real native measurements remain required; no such run is claimed by this change.
