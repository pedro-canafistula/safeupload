# Outside-scope application compatibility (2026-10-16)

Scope: `ux/outside`, originally based on `demo/apps` `8925d1cf`, integrated onto
`fde7f89f` with `ux/kernel` and `ux/dirs`. This is a source/local-control
checkpoint for the unbound MVP demo profile. It does not enable staging, change
readiness or qualify a driver/agent pair. Native empty child folders and idle
directory rename/delete follow [UX-DIRECTORIES.md](UX-DIRECTORIES.md).

## Findings and changes

1. **Edge, hard-linked DLLs, FileBasicInformation.** The direct-mutation gate
   treated timestamps/attributes as content mutations and required complete alias
   classification. After resolving and checking current/pending protected names,
   this one information class now passes to Windows without alias enumeration.
   An outside alias does not gain content, size, EA, delete, rename or link
   authority. Unresolved names on a possibly scoped volume still fail closed.

   The object classifier also reopened the already-owned source `FILE_OBJECT` by
   file ID before enumerating links. It now queries that exact object directly;
   no pathname or replacement object supplies identity. Link-count, 64-link and
   64-KiB limits, complete enumeration and parent-ID/name checks remain.

   **Historical failing substep is not proved.** `aliasCheckFailed` plus
   `auxStatus=ACCESS_DENIED` collapses source standard/internal queries, source-ID
   reopen, hard-link query, parent-ID open and parent-name query. `kernelMode`
   describes the outer request's mode, not whether its thread is impersonating
   or using a restricted/AppContainer token. `OBJ_KERNEL_HANDLE` restricts handle
   visibility; it does not replace that subject. NTFS by-ID traversal/name
   restrictions are a plausible mechanism, not a demonstrated attribution of
   those 33 records. No impersonation or privilege change is introduced.
   The remaining native query/open failures now preserve their precise callsite
   through the existing deny-ring site hint, alongside the unchanged status.
   Hints are best effort under the ring's existing slot contention rules.

2. **Existing directory ancestor probes.** `StageDirectoryCreateCanMutate`
   included every `FILE_CREATE`, and ancestor matching then refused both the
   volume root and the existing scope root before NTFS could report a collision.
   For ordinary case-insensitive, non-transacted, by-name `FILE_CREATE` of an
   existing non-reparse directory on fixed NTFS, a read-attributes `FILE_OPEN`
   proves existence. Its handle omits share-delete and is held through the
   original CREATE's lower completion. Existing DELETE handles conflict; sharing
   is never bypassed. Ancestor rename/reparse operations retain the protected
   namespace gates. The original CREATE and NTFS result are unchanged.

   The existing admission epoch owns the handle through post-CREATE, including
   lower failure/drain; closure precedes epoch release. The internal token flag
   does not change wire/persisted layout. There are at most 16 reserved/live
   collision probe handles and no new pool allocation or worker. At capacity,
   a missing scope root/ancestor, reparse target, failed/short metadata query,
   case-sensitive/by-ID/delete-on-close request or absent epoch retains
   the collision-path refusal. Native child-directory CREATE/OPEN_IF/OPEN keeps
   the `ux/dirs` route, including creation of new empty folders. EA, stream/index
   selectors and unsupported attributes cannot use the collision exception.
   The collision-only directory pass skips legacy create and writer
   tracking because it can only collide. It supplies no application handle.

3. **WebCache/qmgr writable sections.** The retained `denyring2.json` and
   `denyring3.json` report two identical outside-name section refusals as
   `policyScope`. The decision used that same label for both a literal protected
   name and a conservative `SafeUploadStageWritersSopMatchesPolicy` result after
   the existing bounded classification wait. The latter includes pending alias
   probes, Protected/scoped entries, Unknown, rename/identity uncertainty and
   scope-transition/churn failures. The records contain none of that entry state,
   so they cannot establish which subcondition applied or a prefix-matching bug.

   The name recheck now retains `policyScope`, while the conservative registry or
   policy-sequence recheck reports `registryScope` (new diagnostic value 14;
   same ABI). Its auxiliary `0xE5000000 | SOP_OUTSIDE_*` is a subsequent state
   snapshot, not an atomic receipt of the deciding predicate. The agent decodes
   it by name. Classification/Unknown behavior is unchanged. `activatingName`
   comes from a name-based search of retained Activating/Unknown/alias-pending
   entries; a name outside policy alone cannot rule out a protected hard link or
   a different retained entry with that name. The supplied two rings contain no
   activatingName record. No outside-name bypass of that uncertainty is added.

## Kernel API and lifetime audit

- New alias/directory pageable helpers have preceding declarations, PASSIVE SAL,
  `PAGED_CODE` and `alloc_text(PAGE, ...)`. The directory caller checks PASSIVE
  and a null top-level IRP before name/probe I/O. Alias public helpers retain
  their top-level guard and now advertise the pre-existing PASSIVE requirement.
- No new spin-lock region, lock edge, wait, worker, security-token change or content read
  is introduced. New work uses existing kernel APIs; source-call delta is checked
  locally. This does not substitute for a built-binary import gate.
- `FltClose` requires PASSIVE, as does the dedicated directory close helper.
  Its only completion caller is the CREATE-only epoch-token branch, with an
  assertion and the documented post-CREATE PASSIVE guarantee (including context
  cleanup); generic draining callbacks are not presumed PASSIVE.
- The collision handle prevents the target's rename/delete between existence
  proof and lower CREATE. The epoch and existing ancestor namespace gates are
  essential to that proof. This requires native race/draining qualification.

DDI references: [FltQueryInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltqueryinformationfile),
[FltCreateFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatefile),
[by-ID traversal restrictions](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/checking-for-other-special-cases--on-irp-mj-create),
[name-query ACCESS_DENIED](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetfilenameinformation),
[postoperation IRQL/draining contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_post_operation_callback),
[FltClose](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltclose).

## Integrated local result (2026-10-16)

The merge base of `bb2280aa` and `fde7f89f` is `8925d1cf`. Both typed and
metadata-proved directory CREATEs return their retained collision handle through
the admission epoch. The slot keeps `DirectorySequence`, `DirectoryMutation`
and `DirectoryCollision`; mutation completion and uncertain-drain behavior remain
unchanged. No new resource, wait or lock edge is introduced by the integration.

The directory fixture passes 2/2 controls with GCC and Clang, warnings as errors
and UBSan; the outside suite passes 2/2. All 13 lowercase T5 self-check suites
pass 103/103 tests, and the Notepad verdict self-check passes. The namespace
self-check now verifies the dedicated completion tag from `7172c017`, its
interlocked fence release and both PASSIVE-guarded dispatch call sites; its
initial stale-pointer failure is retained. The two other kernel fixtures, T4
verdict, exact-agent-matrix, exact-source-build, feature defaults and driver-import
self-checks also pass: 23 scripts total. Raw receipts, the initial failure and
the corrected rerun are local in `.scratch/ux-outside2-checks` of the delivery
workspace, beside the scratch integration checkout.

Source API comparison against `fde7f89f`: **zero new external calls**; all 78
host-stub declarations pass the existing audit. The full audit, loaded unchanged
with its header inventory from the `ux/dirs` local receipt, still fails only at
`Taint.c:356: InsertHeadList`, identically on `fde7f89f` and this integration.
That baseline inventory omission is not waived or counted as a full audit pass.
No WDK/PREfast/ApiValidator build, new binary import gate, independent integration
review, agent matrix or VM run is claimed.

## Original checkpoint verification and remaining gates

`python3 driver/scripts/ux/outside-selfcheck.py` compiles and executes the production
alias classifier, physical-mutation, directory and section gate bodies with
deterministic DDI shims, GCC warnings as errors and Windows-width WCHAR. Controls
exercise exact-object queries, protected aliases, failed opens/name/link queries,
malformed/over-limit enumeration, metadata versus content, unknown names,
retained directory handles, capacity exhaustion/recovery, rejected directory
variants and section decision attribution. Source contracts also bind the token
handoff/close ordering, alias calls on rename/FSCTL and pageable declarations.
These are host controls, not Windows security, IRQL or native race evidence.

Local results: outside shim/source suite 2/2; all eleven lowercase T5
`*selfcheck.py` suites 99/99; exact-agent-matrix runner 21/21; exact-source-build
runner 2/2; feature defaults 2/2; T4 verdict replay and driver-import self-check
PASS. The latter validates its controls/retained artifacts, not a newly built
driver. Source API audit: zero new external calls (only two private helper
names). The local `dotnet` host has no SDK, so the added C# diagnostic mapping
case was source-checked, not executed. No PowerShell harness changed.

Independent Sol 6.1 xhigh design review: ACCEPT WITH CONDITIONS for the exact-object
query, metadata exception, retained collision pin and diagnostic separation;
final coherent implementation review: **ACCEPT for this local source checkpoint**.
The addressed conditions include no-share-delete, non-reparse proof, case/by-ID/
transaction exclusions, bounded handles, close-before-epoch-release and the
CREATE-specific PASSIVE guarantee. Review acceptance is not pair qualification.

No builder or VM is contacted by this task. Required before delivery/boot: feature
Debug/Release WDK/PREfast/ApiValidator at 0/0, binary import gates, agent diagnostic
control/matrix, applicable pre-boot review and the authorized native rows on
`win10-debug3` only, with required Verifier modes and separate restoration.

Native controls must include Edge/installer outside saves; the affected system
DLLs as the standard user and restricted/impersonating subjects; a remaining
parent-probe failure with its exact site; metadata outside versus protected;
hard-linked protected content/EOF/allocation/delete/rename/link refusals; existing
volume/scope-root CREATE collisions; native empty child-directory creates and
missing-anchor refusal; held-DELETE and
delete/rename/case/reparse races; completion/draining cleanup; and section
classification before/during policy apply with entry diagnostics. Parent ID/name
access failures remain fail closed for content operations until proved/resolved;
this checkpoint does not claim all restricted-token alias probes are repaired.
