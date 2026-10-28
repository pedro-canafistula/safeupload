# T9 increment 3: native discovery results — focused diagnostic `m2t9fdiag1028a2`, 2026-10-28

Source `633f3ffb` (agent identical to `fda55c13`), builder2 `SU-BUILDER2` Windows 19045.6466, feature Debug/user, `Invoke-FocusedAgentDiagnostic.sh`: **97 executed, 94 passed, 3 failed**
(the 80 discovery cases pass by recording; the three strict gates fail). **Mechanism evidence on the builder OS only; not target 19045.2965 qualification, not a delivery gate.** Raw TRX: `t9-diagnostic-m2t9fdiag1028a2/` (local).

## Held-target replacement (32 discovery cases) — N-U4-05 mechanism table

| Mechanism | Predecessor not held | Held, SHARE_DELETE | Held, no SHARE_DELETE | Predecessor DELETE access |
|---|---|---|---|---|
| Class 10 `FileRenameInformation`, replace | success | **ACCESS_DENIED `0xC0000022`** | `0xC0000022` | no effect |
| Class 65 `FileRenameInformationEx`, flags `1` (REPLACE_IF_EXISTS) | success | `0xC0000022` | `0xC0000022` | no effect |
| Class 65, flags `3` (REPLACE_IF_EXISTS \| POSIX_SEMANTICS) | success | **success** | **`0xC0000043` sharing violation** | no effect |
| Release predecessor first, then class 10 | success (all mask/share combinations) | n/a | n/a | n/a |

With class 65/flags 3 over a held SHARE_DELETE predecessor: rename status 0, `SuccessfulRenames` +1, old object afterwards **`Links=0, DeletePending=True`** (unlinked, still held), its bytes readable through the held handle, successor independently openable with `Links=1`.
**Reading:** held-target replacement is only available via class 65 with POSIX semantics and a predecessor handle opened FILE_SHARE_DELETE. The design's class-10 selection is contradicted; the old "deletion-pending predecessor" wording is right for this mechanism (`Links=0` and `DeletePending=True`), wrong for any other.

## Allocation behaviour (48 discovery cases) — N-U8-01

| Mechanism | Result vs nominal Q=AlignUp(P,U) |
|---|---|
| Single padded write, with or without preallocation | within Q in all 12 + 12 cases |
| Preallocate P (FileAllocationInformation) then chunked writes | within Q in all 12 cases |
| **Unpreallocated chunked writes** | **OVER in 3 of 12**: L=65537 peak 131072 vs Q 69632; L=131072 peak 196608 vs Q 131072 (+50%), also with the 64 KiB quantum; the excess persists through EOF normalization and the second flush and falls only after the later allocation normalization (`FileAllocationInformation`), ending at Q |

**Reading:** NTFS over-allocates transiently while a file is extended by successive writes; preallocating P (now in production) or writing the padded extent in one call keeps allocation within Q. The strict N-U8-01 now commits its initial append (allocation held at 8192 throughout) and fails only at its later class-10 held-target replacement step.

## The three strict failures after round 3

| Case | Cause | Fix class |
|---|---|---|
| N-U4-01 | line 109 `Assert.Throws<IOException>` on opening a junction as a child: production throws `MetadataNativeException` status `0xC00000BA` (STATUS_FILE_IS_A_DIRECTORY), a correct typed refusal | test expectation (assert the typed exception and status) |
| N-U4-05 | class-10 replace over a held target: `0xC0000022` | adopt class 65/flags 3 + SHARE_DELETE predecessor (one-line selection + test expectation `Links==0 && DeletePending`) |
| N-U8-01 | line 284/286: same class-10 replacement; also asserts `DeletePending==False` for the unlinked predecessor | same adoption; expect `Links==0, DeletePending==True` |
