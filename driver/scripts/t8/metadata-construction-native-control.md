# T8 native security construction feasibility control

Standalone increment-1 mechanism experiment for [the integration proposal](../../T8-METADATA-INTEGRATION.md).
It changes only fresh unprotected NTFS fixtures, not product driver/agent behavior.
The integration proposal remains REVISE for implementation; this control does not
establish commit exclusion, metadata operation classification or MOTW support.

Run from an owned first-free approved builder slot with a fresh label and committed source:

```bash
/home/victor/Work/safeupload-tools/builder-run.sh gate <label> -- \
  bash driver/scripts/t8/Invoke-MetadataConstructionNativeControl.sh <label> <commit>
```

The runner pins source hashes, checks Windows PowerShell 5.1 parsing and runs managed
packing/import/mask checks before the native job. The wrapper retains its live caller
process while an ephemeral SYSTEM scheduled task executes (180-second Stopwatch limit,
existing task/worker cleanup pattern). SYSTEM copies the exact PID/start/SID-bound
non-SYSTEM caller token, then creates a LUA/disabled-maximum-privilege copy. This is
an actual user's restricted token, not a SYSTEM-derived restricting-SID probe; it is
still not target `t5actor`, an application trace or arbitrary token qualification.

The original restricted caller gets exactly `0x00100002` (write-data/synchronize)
on protected/inherited fixtures owned by SYSTEM, group Administrators, with auditing
and a low mandatory label. It must fail parent CREATE and opens requesting WRITE_DAC,
WRITE_OWNER or ACCESS_SYSTEM_SECURITY. The original native write/flush actually runs.
Separate fixtures cover native caller new-file assignment and an actual caller-created
temporary followed by native replacement rename; the latter's metadata is measured
after rename, never inferred from initial CREATE. NULL and empty DACLs add restoration
counterexamples. This does not cover ReplaceFile, Office's actual operation sequence,
explicit original CREATE descriptors, every label or every security control/RM bit.

Under a private SYSTEM impersonation-token copy, only service execution enables
SeRestore/SeSecurity/SeBackup. The original process token must remain byte-identical.
The service creates and exclusively holds one output with exact finite internal grant
`0x011F01FF` (FILE_ALL_ACCESS plus ACCESS_SYSTEM_SECURITY), writes known nonsecret
approved fixture bytes, with explicit FILE_OPEN_FOR_BACKUP_INTENT on service-only
opens (never caller checks), applies exact current-native security via
`NtSetSecurityObject(BACKUP_SECURITY_INFORMATION)` and queries all parts via the same
information class. It compares raw full descriptor bytes before and after native
rename, without masking even `0x0400`. This broad internal handle is never exported
or projected into a caller grant; the caller's write grant is reopened and checked
after publication. Its existence is an experiment, not an approved product capability.

The experiment deliberately separates caller authority from service execution.
[BACKUP_SECURITY_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information)
requires READ_CONTROL/ACCESS_SYSTEM_SECURITY for query and WRITE_DAC/WRITE_OWNER/
ACCESS_SYSTEM_SECURITY for set. [NtSetSecurityObject](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetsecurityobject)
does not grant the original caller those rights. A successful experiment would support
evaluating exact restore as a tightly bound internal publication step, replacing the
proposal's blanket rejection of privileged post-setting. It would not justify generic
SYSTEM metadata repair or new caller authority.

The unprotected experiment has no filter-enforced private-name/object mutation fence.
It therefore proves neither adversarial temporary isolation nor protection against
concurrent WRITE_DAC/owner/label changes through metadata-only opens. Exclusive data
sharing is not that fence. Exact output/state/policy capability, before-first-visibility
exclusion and lifetime/commit integration still require a concrete reviewed design.

Expected success: 24 structured rows, including six complete before/after descriptor
pairs; all exact, denied caller operations unchanged, granted masks exact. Any mismatch
is a failed feasibility assertion, preserved with full hex rather than normalized into
PASS. Native progress/descriptor lines are emitted before later assertions so a failed
attempt retains earlier measurements. Runtime exceptions also fail the control.

Cleanup verifies each registered full file identity, rejects reparses, resets DACLs
only, removes known children before directories and leaves uncertain objects intact.
Separate runner restoration checks verify task/worker absence and fixture absence.
Raw source, hashes, outputs, .exit/.pid and failures live under the dated evidence
convention. A transport zero or text containing PASS is not the structured verdict.
All results are builder mechanism evidence, never target 19045.2965 qualification.
