# Independent kernel integration review

2026-10-17. Reviewer: independent `native_kernel_fix_review`, `gpt-6.1-sol`, **high**, following the owner's current override.
Reviewed candidate `311c393efd77f8fdad7d15b14205f9dca9573a4d` (including `23b7cbcf`) over integrated `412f05ad`.

**ACCEPT WITH CONDITIONS.** No remaining P0/P1 found in this delta. This is source review acceptance, not Windows qualification.

- DOC retains original mutation intent across readmission. Uncertain identity refuses; the final dispatch guard prevents unowned
  protected DOC from reaching legacy CREATE (`StageStream.c`, NativeMutationRequired/Readmit/native pre).
- Exact bound objects supply security descriptors. Original caller target DELETE or parent DELETE_CHILD authorizes cancellation;
  original I/O-manager parent lookup carries traversal/create-child evidence, without requiring bypass-traverse privilege.
- Review reproduced an additional no-replace relative rename that cancelled a pending source before parent ADD_FILE denial.
  `311c393e` checks every rename with cancellation obligations, rejects occupied different targets without replacement and preserves
  exact case-sensitive same-name/same-ID no-op grants. Raw reviewer repro: `/tmp/review-no-replace-yib3n2xc` (local).
- No resource spans descriptor I/O/RPC. Registry ownership, synchronized completion, fence release/draining and association-lease
  retirement show no additional blocker. The preceding review of `412f05ad` found no additional P0/P1 in lease/retirement but
  required the DOC fallback and native replacement grant corrections above.

Independent offline tests passed: namespace 5, native-security 1, directory 2, namespace-contract 2, context-lookup 3 and retirement 5;
relevant fixtures execute production bodies under GCC/Clang with fatal UBSan. Host controls do not settle native NTFS semantics.

Conditions: fresh feature Debug/Release WDK + PREfast/ApiValidator 0/0 and imports PASS; matched win10-debug3 ordinary/runtime-/boot-
Verifier rows; independent bytes and separate restoration. Native controls retain granted/denied parent ADD_FILE, target DELETE/
parent DELETE_CHILD, impersonated/restricted subjects, exact no-op/case-only/hardlink distinctions, DOC identity uncertainty,
cancellation faults/restarts and draining. Real Word immediate reopen and unchanged T4 10k gates remain required.

The later `f8e99d25` change inherits the existing query declaration's SAL annotations after WDK C28251; it changes no authority or lifetime.
The build, agent matrix and runtime gates remain distinct from this review.

Primary references: [SET processing](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/set-file-information-processing),
[replacement access checks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-information3),
[FileRenameInformation algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/87f86c9b-6c2a-4803-84b7-131a74a434fa).
