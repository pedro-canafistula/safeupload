# T5 native public opens and delete lifetime

Date: 2026-10-11. **NOT READY: no implementation or VM boot approved by this note.**
This replaces the synthetic public-FCB proposal at `05ad4df9`, rejected by the
[Luna review](evidence/2026-10-11/t5-public-proxy-routing-design-review-luna6.md).
The [focused follow-up](evidence/2026-10-11/t5-native-public-open-followup-luna6.md) also rejects its suggested second-open and
on-close emulation. The accepted empty/public-delete design in [T5-DELETES.md](T5-DELETES.md) remains in force; the corrections and
pending failure-policy choice below must be resolved before changing section 4.1 or writing the routing implementation.

## Supported correction

For a known non-writing DELETE-capable open of an existing public name with no owner-private view, pass the **original CREATE once**
to NTFS with its original desired access, share access, effective security subject and supported flags. Attach per-open Filter Manager
state to the resulting native FILE_OBJECT. Do not open a separate native backend first: two independently opened objects conflict
when the caller requests ShareAccess=0. Duplicate/inherited application handles retain the same native FILE_OBJECT and grant.

NTFS owns this object's FCB, cache, section pointers, position and byte locks. Reads, queries, read/image mappings and paging continue
on that native object. No synthetic FCB borrows NTFS section pointers, no TargetFileObject retarget is needed for those operations,
and the private 16 MiB read bound is not applied to public reads. Preserve native mapped-file and share-mode delete restrictions.

Content writers, mutating create dispositions and requests whose rights cannot be proven non-writing before opening (including
MAXIMUM_ALLOWED/generic-all requests) continue through the private-stage path. Their checked public deletion capability stays separate
from private data. No writable app handle, writable file mapping or paging write is exposed on the public branch. This classification
must preserve the supported request surface rather than reject broad-access requests to avoid staging them.

Before forwarding, anchor the parent/canonical leaf and preallocate local context/rundown storage. A scheduled-delete CREATE also
needs its durable delete generation/intent before forwarding; an ordinary DELETE-capable open does not itself delete or tombstone a name.
Use a short logical destination reservation to exclude competing physical publication while CREATE and exact binding finish;
hold no StageNamespaceResource across RPC, file I/O or callback completion. After native success, bind the actual volume/full 128-bit
file ID and read-only native DeleteAccess grant to the original caller and any scheduled intent. An ordinary delete allocates its own
generation when the caller requests disposition. Windows remains the authority for DELETE
or parent DELETE_CHILD; there is no SYSTEM reopen, share widening, added privilege or path-based replacement capability.

An ordinary disposition uses the same currently open native FILE_OBJECT and the one-use, exact-object service transaction under the
destination journal turn. The exported service handle is ephemeral and cannot prevent last-handle cleanup. Return NTFS's actual
result. Ordinary TRUE/FALSE cancellation and accepted-disposition reservations remain as specified in T5-DELETES section 4.2.

## Native scheduled delete: preserve timing without holding all future saves

Do not emulate FILE_DELETE_ON_CLOSE with DELETE|FILE_DISPOSITION_ON_CLOSE. The
[MS-FSA contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4c26c8cb-5a8f-4339-a372-b315c4974131)
requires an already deleted link for that Ex operation; the [native control](evidence/2026-10-11/t5-ntfs-disposition-control-1011.txt)
returned Win32 50. Stripping the CREATE flag and remembering it only in filter state would also lose the scheduled delete at mandatory
unload. Pass a supported native FILE_DELETE_ON_CLOSE unchanged only after its durable intent exists. NTFS then owns scheduled deletion
and duplicate-handle/last-close behavior, including during filter unload. Preserve actual unsupported extended-flag results.

The original native control allowed sharing-compatible opens before the creator closed, and became delete-pending afterward.
A long-lived scheduled-delete handle must not create an additional SafeUpload wait for every newer clean publication. The proposed
ordering therefore releases the short CREATE/binding reservation after exact durable binding; it does not retain an exclusive
publication reservation for the handle's whole lifetime. Keep a separate exact-object scheduled intent and provisional generation floor.
Newer clean generations may take their normal commit turn; only a **durably Published** newer generation suppresses removal of the
current public name. Allocated, unsealed, inspecting or blocked successors do not cancel the scheduled delete. Older generations
cannot publish through that intent. Native cleanup may remove only the originally checked old link/object, never a replacement.

This is a design requirement, not a proved implementation. The corrected review must establish how the native cleanup, atomic rename,
durable Published receipt and exact last-close reconciliation serialize, including crash between rename and receipt. A pathname's
absence or a later object's existence alone is insufficient. Do not hold a destination lock through an arbitrary reader lifetime,
silently change latency, or turn Publishing into Published to make the race pass. If this ordering cannot be implemented while
preserving the owner's rules, ask the owner before adopting a different timing policy.

## Pending owner decision: failure after NTFS accepts scheduled deletion

T5-DELETES section 4.2 currently requires failed proxy construction to leave an unchanged backend. That cannot be promised for the
unchanged native delete-on-close CREATE: NTFS may already have accepted the scheduled mutation before post-CREATE identity/context
binding fails. Microsoft's [FltCancelFileOpen contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcancelfileopen)
says cancellation does not undo changes. Preallocation reduces failures but does not prove an exact identity mismatch, I/O failure or
lost service connection is impossible. Reporting a harmless failed open would conceal a deletion that can still occur at close.

**Proposed policy, not approved:**

1. Before native CREATE is forwarded, a failure leaves the public file untouched and returns failure. No durable intent means no forward.
2. After NTFS accepts scheduled deletion, preserve that accepted Windows result; do not claim cancellation undid it or report a
   no-effect failure. If exact binding/recording cannot complete, keep the pre-CREATE intent and destination reservation in an explicit
   accepted-but-unresolved recovery state. Never fabricate an exact acknowledgement or reopen a changed path as SYSTEM.
3. Prevent further physical commits to the affected destination while the accepted mutation is unresolved; keep later edits private.
   Expose the reason through product status/diagnostics. Reconciliation needs the exact anchored object/link and durable intent.
   Existing global Unknown/reboot rules remain unchanged; this proposal grants no new automatic Unknown clearance.
4. Unbound native handles must not bypass tracked disposition/namespace mutation checks. Mandatory unload still drains only local work
   and never waits for the service; it cannot undo NTFS's already accepted scheduled delete. Retain durable recovery state on disk.

**What users notice if approved:** normal empty saves, Explorer New Text Document, empty copy/move and clear-and-save keep their
ordinary publication behavior. Normal delete-on-close uses Windows timing. In the exceptional tracking-failure case, Windows' accepted
delete may still finish; SafeUpload reports recovery needed and holds further saves to that name private until exact recovery is proved.
It does not tell the application that an already accepted delete had no effect.

**If not approved:** leave this failure-policy change unimplemented and revise the design. M2 public-delete qualification remains open;
there is no approval to drop delete-on-close support, weaken existing rows or narrow the MVP to DeleteFileW-only behavior.

## Local lifetime and required verification

Object references preserve allocation, not the native open after last-handle cleanup. Disposition must use a still-open object at
PASSIVE_LEVEL. Drop the driver's own handle holds before waiting for exact last-close completion; do not keep the app's own open alive
with a service/kernel handle. Context ownership must not create a FILE_OBJECT/context reference cycle. Nonpaged completion bookkeeping
can release operation holds at elevated IRQL; final handle/context destruction runs at PASSIVE_LEVEL after local rundown.

Voluntary unload vetoes outstanding private stages, RPCs, native operations and cleanup. Mandatory unload drains actual local
references, stops new work and retains durable recovery without service waits or path reopen. Native NTFS read sections remain native;
private stages retain their separate paging/section rundown. No timeout permits freeing a live FCB or operation.

- Resolve the owner failure-policy choice and the corrected security-design review before routing code.
- Review the integrated kernel lifetime/lock-order/retirement change once before its first revised VM boot.
- Four WDK/PREfast/ApiValidator configurations at 0/0 and the agent matrix after service changes.
- Native ShareAccess=0, duplicate/inherited handles, real public identity/size/security/name, reads beyond 16 MiB and implicit position.
- Native byte-lock conflicts/cancellation, read/image mappings past app cleanup and rejection of public writable sections/paging writes.
- Deterministic native deletes before seal and after independent publication observation; native scheduled-delete/publication races.
- Inject pre/post-CREATE tracking failures, identity replacement, service disconnect and mandatory unload without hiding accepted mutations.
- Existing private disposition assertions, real Notepad clean/CPF rows in all three modes, independent byte observers and separate restoration.
