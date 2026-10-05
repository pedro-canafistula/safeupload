The notification adapter has two independent routes for negative expectations.
The existing authenticated durable record route is unchanged. If it lacks
coverage, the new route requires both whole-window non-execution evidence and
an authenticated unchanged notification location. Supported negative
expectations then report exactly `agent did not run in window`. An unsupported
expectation still stays INCONCLUSIVE.

The window is the complete writer release/completion fence, bounded by the
service snapshots' QPC receipts, frequency and boot identity. No claim is made
about execution elsewhere in the boot or outside this case window. Collectors
retain facts; evaluators establish coverage rather than trusting an empty
provider query or a stopped-service flag alone.

The non-execution route relies on:

- Native OpenSCManager/OpenService queries of SafeUploadAgent at both edges.
  Only ERROR_SERVICE_DOES_NOT_EXIST (1060) authenticates absence. Absence at
  both edges with continuous System evidence and no 7045 installation in the
  window satisfies the SCM premise independently of installed Stopped/PID 0.
  Installed services require stopped, PID zero and stable service/display/image
  identity. The installed SCM image (when present) and the hash-pinned seed
  package image are checked; service SID identity is derived even when absent.
- Complete native process inventories at both edges, including each process's
  full image and primary-token user, group and restricted SIDs. Disabled group
  SIDs also count. PID 0/4 are kernel processes; every other unreadable or
  disappearing process leaves an explicit inventory failure.
- System and Security anchors collected before the first inventory and after
  the last inventory, enclosing the entire QPC window. All-provider raw XML is
  re-read for every intervening record ID, including both exact anchors.
  Missing/duplicate IDs, tail loss, wrap/clear, changed XML or oversized windows
  defeat the proof. The host binds the transferred XML artifacts by SHA256,
  length and exact XML-array equality.
- No SafeUploadAgent SCM events in that range, including 7036/7045/7040 and
  other events naming its service/display identity. Unknown SCM identity data
  also defeats the proof. System clear 104, Security clear 1102, audit loss/full/
  error/shutdown, EventLog restart/shutdown, audit-policy changes and primary
  token reassignment 4696 all defeat coverage. The separate AgentAbsenceScm
  assertion reports FAIL for authenticated agent state-change/install events
  or running/PID-positive installed edges. State-change detection uses event
  IDs rather than localized state text. Coverage loss stays INCONCLUSIVE;
  evidence of service execution alone does not fabricate a notification.
- Prepare records native Process Creation success/failure flags and per-user
  override count durably before using auditpol with the subcategory GUID to
  enable success, retaining the failure setting. Per-user overrides prevent
  setup and are checked again at both edges. Independent restoration steps
  restore the exact recorded flags via auditpol and require native readback;
  rollback, Finalize residue checks and independent pre/post baselines all
  retain/check audit policy. The wrapper compares baseline flags/count and the
  host binds the guest restoration receipts to those independent values.
  Success auditing must be enabled at both edges, with continuous Security
  evidence and no policy-change/loss events across the window.
  **Every 4688 creation between the inventories defeats this
  conservative route**, even for a benign image. 4688 exposes image/user
  identity but does not include token group or restricted SIDs, so it cannot
  exclude a transient process carrying the service SID. There is deliberately
  no assumption that a PID that has already exited had a harmless token.

The location route authenticates and pins the existing ancestors with the
same native file reader as the durable record. It neither initializes nor
repairs the notification writer. The location must be absent at both edges,
or have the same complete child inventory and byte-identical same-handle
reads (including the empty writer lock). Raw stale or malformed bytes can
support this location comparison without supplying current-boot heartbeats.
Changed bytes, newly created/deleted location, ACL/reparse/link failures,
missing bytes, or missing boot/QPC receipts remain INCONCLUSIVE. Retained
location bytes are compared again against transferred artifacts by the host.
Current-window authenticated writer entries contradict non-execution and
cannot be hidden by this fallback.

This is an OS evidence proof under the existing privileged-local-actor trust
boundary, not independent cryptographic attestation of Windows. It trusts
kernel enumeration, SCM, audit generation/transport and the protected evidence
collection/transfer. It cannot exclude renamed/copied or injected emitters,
thread impersonation, privileged tampering, unreported audit transport failure,
off-window notifications, or intermediate notification-file create/delete
activity that leaves identical edges. In particular, absence at two filesystem
edges alone never proves non-emission.

The notify5 collector failure was a cascade from treating a zero-result SCM
query as an exception. All three cases recorded only
`SCM SafeUploadAgent service missing/ambiguous.` in their execution errors,
and native audit flags were zero with no per-user overrides. Their System and
Security **begin** anchors were OK and contained first/last record IDs and raw
XML. The exception skipped service SID/package-image initialization, the
entire process inventory (including its collector), InventoryEndQpc, and both
end anchors. Thus the empty `before=; after=` diagnostic came from an OK begin
anchor without a failure reason plus a missing end anchor, not an observed
permission, channel-name or Get-WinEvent compatibility error. The notify5
artifacts examined reside in the sibling `/home/victor/Work/safeupload-staging`
worktree; they were not copied, rewritten or promoted here.

The collector now treats native service absence as data, isolates SCM and
audit read errors, initializes package image/SID independently of installation,
and always attempts end anchors in finally. First/last IDs are checked before
publishing an anchor. Missing anchors name the channel and edge; failed reads
retain error chains. Continuous all-provider windows still reject System 104
and Security 1102 clears, missing/changed anchors, wrap, gaps and audit loss.
Synthetic checks exercise both absence and SCM query failures through the
actual collector functions with mocked OS calls, in addition to proof-level
absent-service, start/install, disabled-audit and clear-event cases.

The original `2026-10-04/*ordinary-notify4-artifacts/case.json` files were not
modified or promoted. They predate the execution snapshots and log windows,
and have no whole-window process/SID evidence. A future collection can also
stay INCONCLUSIVE because auditing is disabled, processes are unreadable,
logs wrap/clear, agent SCM activity occurs, or a transient process lacks token
SID evidence. The seed harness starts child processes between its service
snapshots; the strict 4688 rule may therefore require richer authenticated
process-lifetime/token evidence to close those actual trials. It never waives
this gap because the child looks like the expected test writer.

Other existing case limits remain: live TEST_DISABLE_TAINT readback and the
lower admission/completion mutation ledger are unavailable; S01/S02 also have
unaccounted cadence intervals and incomplete external cadence coverage. This
change provides no driver qualification or Windows PowerShell 5.1 execution
verification. The self-checks are synthetic authoring checks; use Windows
PowerShell 5.1 to exercise the collectors on newly collected case evidence.

Microsoft's [4688 event schema](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
explains the authenticated image/user fields and their limits. The audit policy
reader uses [AuditQuerySystemPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)
and [AuditEnumeratePerUserPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditenumerateperuserpolicy).
