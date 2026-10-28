# T9 kernel Windows-ancestor predicate change (a01ac212): narrow independent review (Sol 6.1 high)

Reviewer: fresh read-only Codex session `01a184bf-15e4-7b10-a5ee-ec4ad5aeb3f8`, `gpt-6.1-sol`, effort high, standard tier, 2026-10-28. Kernel static gate for this commit: `m2t9i3k1028b2` PASS (signed `26ABC39A…`). Verbatim report follows.

**ACCEPT for loading on the authorized dormant component overlay.** The changed parent mask matches §8.7.1, and all seven supplied descriptors pass the security predicates. I found no replacement or authorization bypass introduced by this narrowing. The complete predicate still has pre-existing conformance gaps described below.

Reviewed HEAD `a01ac212cc9058912a6ae6c906d58f3bd2ad19e8`, read-only and offline; wrote nothing and ran no builds or Windows controls. Microsoft links below identify the documented contracts relied upon; I did not fetch them during this review.

1. **The narrowing matches the parent rule; it does not remove authority needed to protect the held child.**

   [§8.7.1](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1632) expressly rejects untrusted `DELETE`, `FILE_DELETE_CHILD`, `WRITE_DAC` and `WRITE_OWNER` on the ancestor itself. [The changed code](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:644) implements that set, preserves the wider inheritance check, and leaves PrivateRoot unchanged.

   - **Rename/delete/replace SafeUpload:** ProgramData’s `WD`/`AD` authorize creation, not removal of an existing child. Removal requires child `DELETE` or parent `FILE_DELETE_CHILD`; the supplied descriptors grant neither to Users. Independently, the retained SafeUpload handle excludes `FILE_SHARE_DELETE`. An existing incompatible DELETE-access handle also prevents capture from succeeding. POSIX replacement flags do not waive this exclusion. These are the relevant [file access](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights) and [sharing contracts](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile).
   - **Reparse conversion:** ordinary NTFS junction/symlink installation requires an empty directory. ProgramData contains the retained SafeUpload child, which Users cannot remove. Existing reparses are opened without following them and rejected by [MetadataQueryDirectory](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:702). **No-share-delete alone does not prevent reparse metadata changes**; the argument also depends on NTFS reparse restrictions. Nonempty-directory tags exist, so “nonempty forbids every reparse tag” would be too broad. I found no ordinary stock-NTFS name-redirection route here; third-party reparse providers are outside the supplied evidence. See [reparse restrictions](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-restrictions) and [tag semantics](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags).
   - **ADS/EAs:** permitted writes affect ProgramData’s streams or EAs, not the held SafeUpload directory’s identity, DACL or contents. The driver derives no authority from those values. Storage exhaustion remains possible through already-permitted creation; this change does not promise availability.
   - **Attributes:** `WRITE_ATTRIBUTES` does not grant deletion, DACL changes, ownership changes or arbitrary reparse installation. Basic attributes cannot themselves turn the directory into a junction. They can cause cosmetic or availability effects. See [SetFileAttributes restrictions](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw).
   - **Lookalike siblings, short names and case:** creation elsewhere does not replace the held component. Capture uses fixed single-component names relative to held parents, then checks identities and security. An attacker-created alternative cannot satisfy the SYSTEM/Admin private-root ownership contract merely by resembling its name. Changing a held object’s short name requires DELETE access. I have not exercised adversarial case-mode/short-name operations on 19045.2965; that remains native-verification uncertainty, not an established bypass.

2. **All seven nodes pass the supplied descriptor walk.**

   | Node | Predicate result |
   |---|---|
   | `C:\` | PASS: exact TrustedInstaller owner is accepted for this Windows ancestor. |
   | `ProgramData` | PASS: SYSTEM owner; Users’ effective `WD/AD/WEA/WA` contains none of the four refused parent rights. |
   | `SafeUpload` | PASS: SYSTEM owner, protected SYSTEM/Admin FullControl DACL; both installation-parent calls pass. |
   | `staging` | PASS: PrivateRoot owner, protection and mutation-principal requirements satisfied. |
   | `.space-reservations` | PASS: same. |
   | `staging-journal` | PASS: same. |
   | `completed` | PASS: same. |

   Specifically:

   - `C:\`’s AU `OICIIO;SDGXGWGR` expands to mutation rights, including DELETE. `IO` makes it ineffective on `C:\` itself. ProgramData’s captured `D:P…` blocks inheritance, so the code correctly does not invent a grant across that edge.
   - `(A;;LC;;;AU)` is acceptable. SDDL `LC` is bit `0x4`, which means **FILE_ADD_SUBDIRECTORY** under directory access mapping—not directory listing. It authorizes creation in other names and has no inheritance flags.
   - SYSTEM/Admin FullControl ACEs are trusted. BU `0x1200a9` contains none of the mutation rights being refused.
   - ProgramData’s `CO;OICIIO;GA` is ineffective on ProgramData and cannot propagate into protected SafeUpload. Its Users CI grant is likewise blocked there.

   These are **security-predicate results**, not proof that every open, volume check or alignment query succeeds. The [nu501c3 receipt](../../../driver/evidence/2026-10-28/t9-nu501-nu501c3/collected/result/receipt.json) records Root1 failure without identifying its internal predicate. The old mask’s rejection of ProgramData follows directly from the supplied ACL.

3. **The complete implementation is not an exact implementation of §8.7.1. The remaining issues predate this change.**

   - **OWNER_RIGHTS is unresolved.** At [lines 683 onward](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:683), its SID is treated as untrusted instead of resolving to the captured owner. An ordinary effective OWNER_RIGHTS WRITE_DAC Allow on a trusted-owned Windows ancestor therefore falsely refuses. Neither supplied stock descriptor contains one.
   - **CREATOR_OWNER handling is incomplete.** The exception only runs for certain inheritable destructive Allows reaching an unprotected child. Non-inherit-only CREATOR_OWNER with, for example, only `FILE_ADD_SUBDIRECTORY` can pass, although the design explicitly requires refusal. Unsupported substitution principals can also escape rejection when their masks miss the checked sets or inheritance is blocked. This accepts design-prohibited descriptors; I found no resulting untrusted mutation authority over these prepared roots.
   - **NO_PROPAGATE is recognized but not explicitly modeled.** It does not prevent inheritance to the immediate child, so it cannot excuse a dangerous immediate-child grant. Actual captured child DACLs constrain later propagation. The broader inheritance mask can nevertheless reject safe nonstock layouts, including WEA/WA inherited into an unprotected Windows ancestor with protected private descendants.
   - **Deny ACEs:** validating then ignoring them for Allow cancellation is correctly conservative. They cannot rescue an unsafe Allow or untrusted owner. However, the early Deny skip also bypasses the design’s blanket rejection of unsupported substitution forms.
   - **InstallationParent trust is correct at the effective owner/grant checks:** only SYSTEM/Admin qualify. The CREATOR_OWNER exception’s `MetadataTrustedSid(childOwner, TRUE)` is overly broad for private children, but each private child subsequently undergoes PrivateRoot validation and rejects TrustedInstaller ownership. It does not make this seven-node capture accept a TI-owned private root.
   - **Final recapture is incomplete:** registration rechecks the requested original root’s identity/security, rather than repeating all seven anchor checks immediately before RootId publication. Later native paths have `MetadataCheckAnchors`. This falls short of the design’s explicit pre-publication wording; retained handles and the supplied ACLs prevent the stated untrusted replacement/security mutations.

   None of these gaps refuses the exact supplied installation. I would require their resolution before claiming general §8.7.1 conformance.

4. **Verdict: ACCEPT for the authorized component overlay.**

   No source revision is required for this narrow mask correction before that load. Existing build/static gates remain required. This review is neither an N-U5-01 PASS nor protected driver/agent qualification.