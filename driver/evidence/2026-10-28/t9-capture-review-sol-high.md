# T9 kernel installation capture (05842976, b90e8b5b): narrow independent review and re-check (Sol 6.1 high)

Reviewer: fresh read-only Codex session `01a184c7-129d-79a3-aaa3-c0cbf404b178`, `gpt-6.1-sol`, effort high, standard tier, 2026-10-28; the re-check resumed the same session, forced read-only. Kernel gate for `05842976`: `m2t9i3k1028b3` PASS.

## Round 1 (05842976): REVISE

**REVISE before the next component load.** The one-hop fix in `05842976` is sound for the measured Windows namespace. I found one additional likely stock-Windows blocker in `MetadataCaptureAlignment`: querying `FileAlignmentInformation` through `FltQueryInformationFile`.

Reviewed HEAD `0584297627b9f0ee35a2d75a4f6af533174c546a`, read-only and offline. No files changed, builds started, or VMs contacted.

1. **Required fix: obtain alignment from volume properties. High confidence.**

   [StageResourceMetadata.c:1679](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:1679) sends `FileAlignmentInformation` through Filter Manager. This information normally comes from the I/O manager’s device-object state; it is not an NTFS query that can safely be assumed to work when sent directly below the filter. Stock NTFS can refuse that request. The failure propagates from installation capture and becomes the same typed RegisterRoot refusal.

   The passing agent controls do not establish this kernel call: [the agent uses `NtQueryInformationFile`](../../../agente/SafeUpload.Agent.Service/Interception/StagedMetadataStoreNative.cs:68), which goes through the I/O manager.

   **Exact recommended change:** pass the already-pinned `PFLT_VOLUME` into `MetadataCaptureAlignment`, query `FLT_VOLUME_PROPERTIES` with `FltGetVolumeProperties`, and use `properties.AlignmentRequirement`. Accept the ordinary `STATUS_BUFFER_OVERFLOW` result when the fixed properties are returned—the existing classifier already handles this correctly. Preserve the alignment-mask, power-of-two, geometry and upper-bound checks.

   Update both callers:

   - Installation capture: use `Capture->Volume`.
   - Root-query post-validation: use `Context->Group->Volume`.

   Keep the sector-size and allocation-unit queries. Do not substitute an assumed 4096 alignment after query failure.

   This is a source/API-contract finding, **not an observed status from the 19045.2965 target**.

2. **The one-hop resolution is correct within the approved namespace trust boundary.**

   At [lines 812–855](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:812):

   - `\Device\BootDevice\Windows` yields the counted component `\Device\BootDevice`; querying it returns the measured canonical volume name.
   - A direct `\Device\HarddiskVolumeN\Windows` layout can take the `STATUS_OBJECT_TYPE_MISMATCH` fallback. That status does not itself prove “device object,” but subsequent equality and Filter Manager volume checks prevent treating an arbitrary mismatched object as the accepted volume.
   - The 1024-byte system buffer bounds the scan to 512 WCHARs. The index, multiplication and subsequent `USHORT` casts cannot overflow at those limits.
   - Missing separators and an empty suffix refuse. The short-circuit conditions protect the indexed reads.
   - The drive buffer reserves one WCHAR before appending `\`; the append remains within its allocation.
   - Counted names need no terminating NUL. Failed or oversized link queries return before their buffers are consumed.
   - A second **final-link target** is not recursively resolved; it fails canonical equality in the normal namespace.

   **Qualification:** this trusts the global `\SystemRoot` link as the installation locator. It does not independently prove the running Windows installation against malicious SYSTEM-level namespace modification. It also accepts a nonempty suffix without validating that suffix as an actual Windows directory. That preserves the existing design’s trusted SYSTEM/administrator boundary; it is not a tamper-resistant boot-volume attestation. Confidence: **high**.

3. **RegisterRoot environment-assumption sweep**

   The prepared descriptors are recorded in [prepare.txt](../../../driver/evidence/2026-10-28/t9-nu501-nu501c4/prepare.txt). I found no other confident, unconditional refusal for those roots.

   | Check | Concrete Windows fact and assessment | Confidence |
   |---|---|---|
   | Volume-name format | `FltGetVolumeName` returns the NT volume device name, conventionally `\Device\HarddiskVolumeN`, without the root-directory trailing slash. That matches the measured global C: target. Comparison ignores case; the directory slash is appended afterward. | High |
   | Instance `VolumeKind` | [Context.c](../../../driver/SafeUpload.Minifilter/Context.c:205) classifies a normal nonremovable local disk as Fixed. Boot-start/readiness trust state is separate and does not turn the system volume into another `VolumeKind`. Portable/removable media deliberately refuse. | High |
   | NTFS requirement | A stock local NTFS Windows installation satisfies `FLT_FSTYPE_NTFS`. No additional readiness/canary requirement appears in this capture. | High |
   | Volume-root open | `\Device\HarddiskVolumeN\` names the filesystem root directory, rather than the raw volume open obtained without the slash. `FILE_DIRECTORY_FILE`, synchronous access and `FILE_OPEN_REPARSE_POINT` are compatible with that directory. | High |
   | Relative descendant opens | Each suffix is one fixed component relative to a retained parent handle, on the selected instance. No stock requirement for absolute names or a trailing slash on these suffixes is missing. Reparse points deliberately refuse. | High |
   | Sharing | The agent and kernel both request read/list access and share Read/Write, so their handles are compatible. Omitting ShareDelete does **not** conflict merely because another handle permits delete sharing; it conflicts when that handle actually has DELETE access. Explorer/notification handles need not cause refusal, but a backup/administrative handle requesting DELETE can legitimately do so. Preserve the exclusion. | High |
   | Root directory information | NTFS supports `FileStandardInformation`, `FileAttributeTagInformation` and `FileIdInformation` for its root directory. The expected x64 sizes are 24, 8 and 24 bytes. A normal root is a directory, is not delete-pending, and has a stable file identity. | High |
   | `ReparseTag` | For a non-reparse object, the tag is not an independent authority signal. Stock NTFS normally returns zero, but requiring zero adds reliance beyond the attributes check. Zero-initialize the query structures and preferably reject based on `FILE_ATTRIBUTE_REPARSE_POINT`; I would not diagnose this as the demonstrated refusal. | Medium |
   | ProgramData registry | Stock Windows uses `%SystemDrive%\ProgramData` or its expanded C: form, both accepted here. The native kernel registry open avoids a caller’s WOW64 view. Relocated or differently spelled equivalent locators can intentionally refuse. | High |
   | Security sizes | The recorded ordinary descriptors are far below 64 KiB. The two-query bounded capture is conventional; growth between queries fails closed. No stock descriptor-size blocker is apparent. | High |
   | Owner and group | The captured security information requests **Owner + DACL**, not Group. The domain-users primary-group SID therefore cannot fail this predicate or the kernel’s subsequent comparison. SYSTEM ownership and protected SYSTEM/Admin FullControl private DACLs pass. | High |
   | Ancestor ACLs | The recorded TrustedInstaller-owned C: root and SYSTEM-owned ProgramData fit the trusted ancestor set. The corrected ancestor mask permits the recorded Users create/write-attribute grants. The protected captured children block the relevant inheritance. | High |
   | Different FILE_OBJECTs | File identity and owner/DACL belong to the underlying NTFS object. Two opens do not inherently produce different identities or descriptors. Both kernel security queries request the same information flags; the agent’s separate Owner/Group/DACL serialization is not compared against these bytes. Concurrent security changes can correctly refuse. | High |
   | Security byte comparison | Unchanged NTFS security queried with identical flags should serialize consistently. Nevertheless, [line 987](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:984) should also require `bytes == node->SecurityBytes` before comparing. This strengthens the capture check; it is not a demonstrated stock-install blocker. | High |
   | Sector/allocation geometry | Windows 10 supports the two volume classes used. The recorded target native controls report A=U=4096, consistent with these bounds. They do not prove the separate kernel alignment-query mechanism identified above. | High |
   | Original-handle access | Agent `AnchorAccess=0x120081` exactly equals `READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY`, matching [ObReferenceObjectByHandle](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:926). `OpenAnchor` does not omit a required grant. | High |

4. **PREfast/build result: verified from existing receipts.**

   The exact-commit [b3 summary](../../../driver/evidence/2026-10-28/exact-m2t9i3k1028b3-summary.txt) and raw Debug/Release logs record both feature builds with PREfast and ApiValidator enabled, **0 warnings / 0 errors**. No C6385, C6386 or C28182 diagnostic appears. The [import report](../../../driver/evidence/2026-10-28/exact-m2t9i3k1028b3-imports.txt) reports PASS for both artifacts.

   Thus `05842976` has a clean recorded static gate. The earlier [nu501c4 receipt](../../../driver/evidence/2026-10-28/t9-nu501-nu501c4/collected/result/receipt.json) identifies only Root1’s refusal, not its native cause. Neither result establishes successful installation capture or qualification of the corrected pair.

## Round 2 (b90e8b5b): ACCEPT

**ACCEPT for the authorized component load**, subject to the normal exact-commit build/static/import gates. `b90e8b5b` correctly addresses the previous findings; I found no additional required source change.

Reviewed HEAD `b90e8b5b9b1738d885d7b3101ef669ba4ba12681`, read-only and offline.

- **Alignment change is correct and complete.** [MetadataCaptureAlignment](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:1659) now reads the volume’s `AlignmentRequirement`. Accepting `STATUS_BUFFER_OVERFLOW` is correct: the fixed properties are available even when the buffer cannot accommodate the appended names. No name fields are consumed. The declaration, definition and both callers were updated; no old alignment-query call remains.

- **`Group->Volume` remains referenced throughout `MetadataRootIoPost`.** Installation capture acquires the volume reference and [transfers ownership into the group](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:1010) before publishing the registered root, under the same lock. Pre-operation admission acquires group rundown protection; its completion context increments `PostOwners`. [Reaping](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:246) refuses to proceed while post owners remain, and releases the volume only after rundown drains. Revocation and forced key withdrawal do not prematurely release it. An additional per-query volume reference is unnecessary.

- **PASSIVE and lock requirements are respected.** Installation capture executes outside `MetadataLock`. [The post-operation path](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:2683) diverts draining or non-PASSIVE completions before reaching `MetadataRootIoPost`. At the call, no metadata spin lock is held. Metadata routing also precedes generic epoch dispatch, so this adds no generic epoch-lock dependency. Holding rundown protection and a completion owner is appropriate lifetime protection, not a lock violation.

- **Bounds remain intact.** The alignment mask is checked below 65536 before adding one, so that addition cannot overflow. Power-of-two checks remain; the effective alignment retains its 4096 minimum and 65536 maximum. Allocation-unit multiplication remains 64-bit, with its bound checked before narrowing. Sector consistency, native result-size checks and zeroed failure outputs remain. `ReturnedLength` need not equal `sizeof(properties)` because it can describe the larger buffer required for names.

- **Security comparison is strengthened correctly.** [The new size equality](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:988) short-circuits before comparing when lengths differ. The supplied buffer remains bounded by the previously validated descriptor size and capture scratch capacity. Query failure still refuses; a successful length/content mismatch refuses and revokes.

- **Directory initialization is correct.** Zeroing all three query structures removes uninitialized contents without replacing any status, exact-size, directory, delete-pending or identity check.

- **Dropping `ReparseTag != 0` does not admit reparse children.** [MetadataInspectChild](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:1737) still rejects every object reporting `FILE_ATTRIBUTE_REPARSE_POINT`, regardless of tag value. The same applies to directory capture. Tags without that attribute are undefined and supply no additional rejection authority. Child CREATE still requires `FILE_OPEN_REPARSE_POINT`; the existing identity/name/security checks remain, and metadata operations grant no reparse-setting FSCTL route. The directory, sparse, compressed and encrypted attribute refusals also remain.

`git diff --check` passed. I did not execute Windows checks or observe completed build/static/import receipts for this commit; this is source-review acceptance for the scoped component experiment, not runtime success or protected-pair qualification.