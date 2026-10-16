<!-- Read-only Sol 6.1 xhigh memo on 304d078c, 2026-10-16; owner decisions of 2026-10-16 in POST-MVP-PLAN.md supersede its open questions (ADS: Zone.Identifier carried with its file). -->
# T8 decision memo: metadata published through staging

**Recommendation:** use the result of the **original operation requested by the same caller and application on unprotected NTFS** as the metadata reference. Preserve that result unless the owner explicitly accepts a difference. The approved copy-and-inspect fallback for moves must not redefine the reference or waive the original move’s security semantics.

Preserve the existing complete-descriptor decision, including only the accepted moved-file `SE_DACL_AUTO_INHERITED` difference. Preserve native timestamp and ordinary-attribute semantics, with an explicit publication-time rule for `ChangeTime`. Hold unsupported ADS/EAs, EFS/offline cases, reparse points and multiple hard-link aliases. Successful browser qualification requires inspected MOTW to be effective **before the downloaded file becomes publicly visible**.

This memo describes source at **304d078c** and uses the newer staging checkout for current decisions. No files were edited; no builds, tests or VM rows were run. The required independent **Sol 6.1 xhigh** design review accepted these recommendations with conditions incorporated below. That is neither implementation acceptance nor qualification.

## Evidence boundary and current publication behavior

The current T8 plan still requires agreed metadata and nine real application workflows in ordinary, runtime-Verifier and boot-Verifier modes. Those results remain incomplete. [Current T8 scope](/home/victor/Work/safeupload-staging/driver/POST-MVP-PLAN.md:1042)

Three implementation facts apply to every item in this memo:

1. **Bound publication refuses today.** Production readiness always includes four native holds; the kernel descriptor-construction check returns `STATUS_NOT_SUPPORTED`. A bound allocation cannot fall through to legacy publication. Consequently, the dormant code does not establish a working metadata result. [Fixed holds](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedBoundReadiness.cs:47), [readiness calculation](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedBoundReadiness.cs:157), [kernel refusal](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StagePublic.c:1877), [no legacy fallthrough](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:391)
2. **The dormant bound path creates a new temporary**, supplies a construction descriptor and `FILE_ATTRIBUTE_NORMAL`, copies the inspected snapshot, then performs a POSIX replacement rename. It contains no general metadata-replay step. [Creation](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedBoundPublicationNative.cs:119), [copy and commit](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedBoundPublicationDispatcher.cs:50)
3. **The separate legacy path also creates a fresh temporary**, with `NORMAL`, no supplied descriptor and no template; it writes one inspected stream and renames the temporary. It does not restore the original metadata. This is existing code, not a product fallback for bound allocations. [Legacy sequence](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:427), [CREATE](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedDestinationFile.cs:51), [write/EOF/flush](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedDestinationFile.cs:67), [rename](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedDestinationFile.cs:108)

`NORMAL` is a creation input. It does **not** prove that the resulting file is uncompressed, unencrypted or assigned entirely new creation/short-name information: parent inheritance and NTFS tunneling can affect the result. [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)

The current publication capability is also insufficient for the proposed contract. Its grant, `0x00110082`, includes write-data, read-attributes, delete and synchronize, but **not write-attributes**. CREATE requires `NORMAL` and no EAs; the fence rejects other mutations. Timestamp/attribute restoration therefore needs a separately designed and reviewed capability, bound to the exact object, generation, original authority and current policy, with corresponding recovery rules. It cannot become a general SYSTEM post-processing step. [Permit](/home/victor/Work/safeupload-design/driver/T5-BOUND-PUBLICATION.md:50), [authority restrictions](/home/victor/Work/safeupload-design/driver/T5-BOUND-PUBLICATION.md:71), [mutation fence](/home/victor/Work/safeupload-design/driver/T5-BOUND-PUBLICATION.md:84), [enforced CREATE restrictions](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageBoundPublication.c:988)

## What the unprotected reference establishes—and what remains unmeasured

Below, **source fact** means verified implementation; **documented** means an API/filesystem guarantee; **unmeasured** means the actual application/build still needs a target control. API documentation cannot establish which API an unspecified Office, Notepad, Explorer, PowerShell or browser build uses.

| Native operation | Documented reference applicable to the item-specific recommendations |
|---|---|
| New file / absent-name Save As | Native creation uses the effective caller’s token, supplied inputs and parent inheritance. |
| Existing object opened and written | Opening does not itself assign a fresh descriptor; subsequent app operations determine the result. |
| Temporary followed by ordinary replacement rename | Do not assume metadata-merging behavior merely because the final name replaces an old file. |
| `ReplaceFileW` | Preserves selected old-target metadata: creation time, short name, optional object ID, DACL, resource-security attributes, encryption/compression and old named streams absent from the replacement. The resulting file ID is the replacement’s. This does not promise complete owner/SACL/MIC equality. |
| Copy | `CopyFileEx` documents preservation of attributes, ADS and EAs, with separate EFS rules. Optional object IDs are not simply cloned. |
| Same-volume move | A native rename retains the existing object rather than assigning new-create defaults. |
| Cross-volume move | Copy/delete behavior differs from same-volume rename; native failure and source-retention behavior must be recorded. |

These are API-level distinctions, not observations of the requested applications. [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew), [CopyFileEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfileexw), [MoveFileEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexa), [object identifiers](https://learn.microsoft.com/en-us/windows/win32/fileio/distributed-link-tracking-and-object-identifiers)

The following native controls are required for **every applicable metadata item**:

| Application/workflow | Direct-save behavior to establish on 19045.2965 |
|---|---|
| **Notepad** | First Save, existing Save, Save As absent/existing name, dialog probes and reopen. Its exact in-place/replacement behavior is **unmeasured**. |
| **Word** | First Save, existing Save and Save As; trace temporary/owner/backup files and rename/delete ordering. **Unmeasured.** |
| **Excel** | Same controls. Microsoft documents temp-write → delete-original → rename for **Excel 2010**, not the unspecified installed build. [Historical mechanism](https://support.microsoft.com/en-us/excel/description-of-the-way-that-excel-saves-files) |
| **PowerPoint** | Independently trace first/existing Save and Save As, intermediates, replacement and reopen. **Unmeasured**; Word/Excel results cannot substitute. |
| **Explorer** | Fresh copy, replace-existing, original same-volume move and cross-volume move. Record the protected copy fallback separately. Exact shell behavior is **unmeasured**. |
| **PowerShell** | `Copy-Item`/`Move-Item`, absent/existing destinations and relevant `-Force` cases. Record Windows PowerShell/PowerShell version and provider; cmdlet names do not establish a complete metadata contract. [Filesystem provider](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_filesystem_provider) |
| **Browser download** | Partial-file creation, close, rename, attachment/MOTW writes, retries and replacement downloads. Completion ordering is **unmeasured**. |

The approved T6 `STATUS_NOT_SAME_DEVICE` fallback permits copy-and-inspect. It does **not** approve replacing an original same-volume move’s security with destination-parent copy defaults. Preserve the original move’s descriptor or hold the operation. File-ID recreation is already inherent in the staged mechanism; optional `OBJECT_ID` and 8.3 fidelity remain separate choices. [Approved fallback](/home/victor/Work/safeupload-staging/driver/POST-MVP-PLAN.md:1024), [Office staged rename](/home/victor/Work/safeupload-design/driver/T5-DELETES.md:304), [new publication object](/home/victor/Work/safeupload-design/driver/T5-BOUND-PUBLICATION.md:20)

The requested Notepad and PowerShell controls supplement the existing nine-app T8 matrix: **Word, Excel, PowerPoint, Paint, WordPad, Explorer replace, browser download, robocopy and 7-Zip**, all three modes.

## Common qualification and concurrency rules

Every row below uses:

- An ordinary **unprotected native reference** on Windows 10 **19045.2965**, with the same caller/token, application build, operation, format and relevant NTFS settings.
- Protected runs in **O/R/B: ordinary, runtime-Verifier and boot-Verifier**, using the matched driver/agent pair.
- Independent native observation outside the private staging view: public bytes, volume/file identity, complete binary descriptor, timestamps, flags and the relevant streams/metadata. Observe during the hold and after publication/reopen; SafeUpload logs alone are insufficient.
- Denied, unsupported, interrupted and racing cases. Verify original caller grants/shares, duplicate-handle and last-cleanup behavior, required source/old-public retention, current-policy binding and no transient uninspected publication.

**Publication must not replay stale metadata over a later authorized change.** Public security setters intentionally reach the real object, and the current plan records an admin ACE lost during later publication. Revalidate identity and all metadata inputs needed for the expected result at physical commit. Changed inputs must hold publication or enter a specifically authorized reconstruction/reinspection path. Every applicable row includes owner/DACL/SACL/MIC, attribute, ADS and EA changes between capture, inspection, commit and recovery. [Public security setters](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:10048), [recorded lost ACE](/home/victor/Work/safeupload-staging/driver/POST-MVP-PLAN.md:1368)

A safe refusal demonstrates containment. It does not count as successful saving where T8 requires clean publication. These are proposed rows; current stops remain in force.

## Security descriptor

The owner already accepted only the moved-file `0x0400` set→clear difference, with every other security byte equal; construction uses native inheritance or stored replay, whichever is exact. This decision needs implementation, not reapproval. [Owner decision](/home/victor/Work/safeupload-staging/driver/POST-MVP-PLAN.md:147)

The controls establish useful mechanisms, but used SYSTEM on builder **19045.6466** and excluded Explorer/non-SYSTEM coverage. They do not qualify target **19045.2965**. The checkout still refuses construction and still compares stored security using raw equality; simply weakening one comparison would not implement the decision. [Control scope](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-15/t5-descriptor-t5-marker-new1-summary.json:2), [results](/home/victor/Work/safeupload-staging/driver/T5-NATIVE-PUBLIC-OPENS.md:744), [stored comparison](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageBoundPublication.c:489)

### Owner SID

**Today:** bound publication is held; its design requires full owner/group fidelity. Legacy publication supplies no original descriptor. Thus source proves absence of owner replay, while the precise resulting default owner requires Windows observation. [Required security](/home/victor/Work/safeupload-design/driver/T5-BOUND-PUBLICATION.md:59), [legacy CREATE](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedDestinationFile.cs:56)

**Native reference:** a new owner comes from the effective token’s default owner, potentially a group SID; an existing-object edit or same-object move does not automatically become caller-owned. Application replacement behavior remains unmeasured. [Owner assignment](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object)

**Options and consequence:** service ownership, blanket source ownership or native ownership. The first two can change permission-management authority and backup/security-tool output.

**Recommend:** exact native owner and primary group, without takeover or SYSTEM repair.

**T8-OWNER — O/R/B:** A owns a target writable by B without B having `WRITE_OWNER`/`WRITE_DAC`; also use a token with a group default owner. Exercise Save, replacement Save As, copy and move. Independently compare owner/group, identity, operation status and subsequent owner-sensitive access.

### DACL and inheritance

**Today:** the bound contract requires complete DACL/control fidelity but is held. Legacy publication does not replay it. Checked writer lookup instead preserves original-subject authority. [Descriptor contract](/home/victor/Work/safeupload-design/driver/T5-BOUND-PUBLICATION.md:59), [original-subject lookup](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StagePublic.c:1537)

**Native reference:** new assignment, same-object preservation and replacement are different cases. A native same-volume move retains its security rather than automatically inheriting the new parent’s defaults. [File security](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)

**Options and consequence:** always inherit, always replay source/target, or reproduce the original operation. Wrong selection can lose explicit DENYs/protection, broaden access, break saves or alter future inheritance and descriptor-aware backups.

**Recommend:** complete native equality—ACE order, flags and controls—with only the accepted moved-shape `0x0400` direction. No SACL-marker or broad `0x0C00` exception.

**T8-DACL — O/R/B:** inherited, moved-inherited, protected, defaulted, empty and NULL DACLs; distinct parents and deny/creator-owner ACEs. Compare binary security and real-token read/write/delete results, inheritance propagation and backup/restore. Negative controls change one unapproved byte/control at a time.

### SACL

**Today:** complete SACL is required by the bound design. Legacy stage-security capture requests owner/group/DACL only; its publication CREATE supplies no descriptor. Captured DACL authorization is not SACL preservation. [Bound requirement](/home/victor/Work/safeupload-design/driver/T5-BOUND-PUBLICATION.md:59), [legacy capture](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageSecurity.c:77)

**Native reference:** inherited versus retained audit security depends on the operation. Complete SACL access has separate rights/privilege requirements; a DACL-preservation guarantee cannot establish full SACL preservation. [SACL access](https://learn.microsoft.com/en-us/windows/win32/secauthz/sacl-access-right)

**Options and consequence:** omit audits, universally inherit or reproduce native SACL. Omission loses auditing; privileged replay can fabricate caller authority.

**Recommend:** exact native audit ACEs/order/inheritance/protection/control, including `0x0800`; otherwise hold. Observer privilege supplies evidence, never caller authorization.

**T8-SACL — O/R/B:** inherited and protected success/failure audit ACEs, varied flags/order, callers with/without relevant privilege. Independently compare full SACL and native statuses; collect audit events where baseline policy enables them.

### Mandatory integrity label

**Today:** complete bound security includes the label; legacy owner/group/DACL capture does not. Bound publication remains held. [Required label](/home/victor/Work/safeupload-design/driver/T5-BOUND-PUBLICATION.md:59), [legacy capture](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageSecurity.c:77)

**Native reference:** MIC is evaluated before DACL access; the label and mandatory-policy mask affect authority. Unlabeled objects are treated as medium integrity. [MIC](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)

**Options and consequence:** native label, service defaults or stripping. Incorrect defaults can remove isolation or prevent application reopen.

**Recommend:** exact native integrity SID/policy/ACE semantics and original-token enforcement; otherwise hold.

**T8-MIC — O/R/B:** low/medium/high objects and callers with permissive DACLs; vary no-write/read/execute-up where supported. Independently query labels and attempt allowed/denied operations using those tokens. SYSTEM readability must not authorize seed export or hand-back.

## Timestamps

**Current source fact for all four fields:** basic metadata is captured and hashed, private queries expose backing metadata, and publication performs no timestamp replay. Hashing is not preservation. [Captured basic metadata](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StagePublic.c:1929), [private query](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:5006), [publication sequence](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedBoundPublicationDispatcher.cs:50)

For each field, the choices are old/source-value replay, service-generated values or native semantics. Exact application tuples remain unmeasured. Newly generated times require event/ordering assertions, not identical wall-clock values across separate runs. [File times](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times), [basic information](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info)

| Item | Native behavior, difference and recommendation | Concrete row |
|---|---|---|
| **Creation** | Retained-object operations differ from new creation; replacement/tunneling can preserve earlier creation information. Wrong values disrupt provenance and backup comparisons. **Recommend the original operation’s semantic creation value**, excluding private-stage allocation time. | **T8-CREATION, O/R/B:** distinct source/target/temp sentinels; first Save, existing Save, Save As, copy/move and rapid/delayed delete-recreate. Independently query by identity after relevant closes and reopen. |
| **Last-write** | Data writes and explicit app setters determine the result; close timing matters. Publication-copy time can cause repeated backup work; stale replay can hide edits. **Recommend native final semantics**, excluding service-copy effects. | **T8-WRITE-TIME, O/R/B:** sentinel values, natural edits, authorized setters before/after writes and overlapping handles. Observe bytes, final times and close ordering. |
| **Last-access** | NTFS updates can be disabled/deferred; scanner reads are additional activity. **Recommend native configured semantics and authorized setters**, excluding private scanner accesses. Do not promise immediate “last read” updates. | **T8-ACCESS-TIME, O/R/B:** record unchanged target settings; sentinel time, caller-read/no-read controls and delayed observations. Compare independently without altering the baseline. |
| **Change** | Tracks metadata mutation, while authorized callers can explicitly set it or control automatic updates. **Recommend actual public-mutation time by default**, explicitly accepting staging-delay divergence; honor authorized setter/suppression ordering or hold unsupported cases. Never mechanically restore an allocation snapshot. | **T8-CHANGE-TIME, O/R/B:** rename, attributes-only changes, delayed approval/restart, explicit values and zero/`-1`/`-2` controls; include absent write-attributes rights. Observe time ordering and suppression lifetime across duplicate/last-close handles. |

Creation-time tunneling must be included rather than assuming every temporary means a new creation timestamp. Last-access assertions must follow the target’s recorded settings. Timestamp control values are operations, not literal dates. [Tunneling](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), [last-access configuration](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior), [native timestamp setters](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_basic_information)

## File attributes

**Current source fact for every attribute below:** original CREATE attributes are captured, but capture does not apply them. Checked writer validation accepts only `NORMAL|ARCHIVE`; publication requests `NORMAL`. The owned dispatch has no general basic-information or metadata-FSCTL replay. [Capture](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:2959), [checked restrictions](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StagePublic.c:1605), [publication input](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedBoundPublicationNative.cs:125), [owned dispatch](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:5684)

For the ordinary bits, choose among source replay, target replay, publication defaults or native final-state fidelity. **Recommend native final state and native refusal behavior**, including authorized app setters in their proper order. [Attribute API](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw)

| Attribute | Native reference and consequence | Recommendation and test |
|---|---|---|
| **Readonly** | Native write/replacement can fail, or the caller can explicitly clear the bit where authorized. SYSTEM clearing could make an otherwise denied save succeed. | Preserve native state/refusal. **T8-READONLY, O/R/B:** readonly source and target, with/without authorized clearing; observe status, raw bit, old bytes and reopen. |
| **Hidden** | Affects visibility and some create/overwrite outcomes. Generic replacement can expose a previously hidden file. | Preserve native final bit and failures. **T8-HIDDEN, O/R/B:** hidden source/target, absent/existing destination and replacement; query bit and Explorer visibility independently. |
| **System** | Can affect visibility/tool behavior and native overwrite outcomes. | Preserve native state without privileged clearing. **T8-SYSTEM, O/R/B:** source/target bit alone and with hidden/readonly; compare status, flags and bytes. |
| **Archive** | Backup signal; restoring a stale clear bit after editing can hide a change from archive-bit backup. | Preserve native write/setter ordering. **T8-ARCHIVE, O/R/B:** initially clear/set, edit/copy/move, explicit clear after write; inspect raw bit and representative backup selection. |
| **Not-content-indexed** | Changes requested content-indexing treatment; the bit alone does not prove an existing index entry disappeared. | Preserve native final bit; qualify Search separately. **T8-INDEX, O/R/B:** differing source/target states, Save As/copy/move; inspect bit and controlled asynchronous Search results. |
| **Temporary** | Cache hint, distinct from delete-on-close. Office’s intermediate temporary need not imply a temporary final document. | Preserve native **final** bit and cleanup lifetimes separately. **T8-TEMPORARY, O/R/B:** temp intermediates, final clearing, duplicate handles and delete-on-close; observe bit, survival and deletion timing. |

### Sparse

**Today:** publication writes one linear inspected stream; sparse mutators are guarded/refused and no sparse reconstruction is implemented. [Writer](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedDestinationFile.cs:67), [FSCTL classification](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:9454)

**Native reference:** sparse state and logical holes require filesystem semantics, not merely copying a flag. **Options:** densify, preserve native sparse semantics or refuse. Densification can exhaust storage; skipping logical holes can weaken inspection accounting.

**Recommend:** qualified native sparse state and complete logical-byte semantics; hold unsupported cases. Do not promise identical physical allocation layouts.

**T8-SPARSE — O/R/B:** large EOF, holes and separated payload sentinels; independently inspect all logical bytes, EOF, sparse state, ranges and storage consumption. Add zero-range changes, late writes and quota/disk/inspection-limit failures. Allocated ranges are not proof that every byte within them is nonzero. [Allocated-range semantics](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_query_allocated_ranges)

### Compressed

**Today:** no compression replay; destination-parent inheritance can still compress a `NORMAL` temporary. [Creation](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedBoundPublicationNative.cs:125), [guarded controls](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:9454)

**Options:** normalize storage, preserve native compression or refuse. Differences affect space/performance/backup; raw compressed-byte copying is not logical-content inspection.

**Recommend:** native compression state/format after complete decompressed-byte inspection and qualification; hold unsupported combinations. No physical-layout parity promise.

**T8-COMPRESSED — O/R/B:** source compression × parent compression × existing-target combinations, across Save/Save As/copy/move. Independently query compression state/format, logical bytes and storage consumption, including failures/reopen. [Compression controls](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw)

### Encrypted/EFS

**Today:** no recipient/certificate replay or original-caller key proof exists in publication; parent EFS inheritance remains possible. [Current CREATE](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedDestinationFile.cs:56)

**Native reference:** EFS copying has key/recipient rules separate from DACL grants. **Options:** exact EFS support, plaintext normalization or refusal. Plaintext normalization loses confidentiality; SYSTEM/default-key encryption can change recipients and prevent caller reopen. [Copy/EFS behavior](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfileexw)

**Recommend:** explicit M2 refusal of EFS source, target and inherited-destination cases until caller plaintext authority, private-storage treatment, full inspection and exact recipient semantics are qualified. No decrypted fallback.

**T8-EFS — O/R/B:** A’s encrypted source; B with filesystem rights but no key; A with key; encrypted parent/existing target. Observe recipients, encryption state and decryptability by each identity; verify no plaintext publication or SYSTEM-created authority.

### Offline

**Today:** no recall/provider contract or metadata replay exists; offline-related controls are guarded. [Control classification](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:9454)

**Options:** qualified recall, flag normalization or refusal. Preserving a stub can later introduce uninspected bytes; clearing the bit can misrepresent availability.

**Recommend:** explicit M2 refusal of offline/recall-dependent cases. Do not clear or hydrate them as SYSTEM to force success.

**T8-OFFLINE — O/R/B:** distinguish bit-only files from genuine recall-backed stubs using available mechanisms. Observe refusal, state, recall attempts and all bytes; retain source/old-public state without baseline/provider changes. [Offline attribute semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw)

## ADS, EAs and identity/alias metadata

### Alternate data streams, including `Zone.Identifier`

**Today: named ADS are not inspected by the staged content pipeline.** The stage opens one base stream; snapshot copy copies that stream; inspection receives that snapshot. Publication copies the same stream. Named staged CREATEs refuse; writer-registry stream enumeration is classification, not content inspection. Basic/security capture is not a complete ADS inventory. [Stage open](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedStageFile.cs:315), [snapshot copy](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedSnapshotCopy.cs:6), [inspection](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:219), [named-stream refusal](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:2421), [tracking enumeration](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageWriters.c:4460), [captured information](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StagePublic.c:1288)

**Native reference:** streams contain independent bytes. Native copying/replacement can retain them, including streams from the old target. Attachment processing can add trust evidence after the local data file exists; actual browser ordering remains unmeasured. [Streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), [attachment save](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iattachmentexecute-save)

**Consequence:** silently dropping MOTW can change Office Protected View/macro treatment. Blind preservation can publish arbitrary uninspected data—including on an otherwise empty file. Office UI additionally depends on trust settings and policy. [Protected View](https://support.microsoft.com/en-us/office/collab-files/what-is-protected-view), [Internet-origin macro policy](https://learn.microsoft.com/en-us/DeployOffice/security/internet-macros-blocked)

**Options:** strip streams, blindly replay them or inspect and bind the complete resulting stream set.

**Recommend:** hold every unsupported ADS-bearing operation, including MOTW today. Successful browser support needs bounded `Zone.Identifier` inspection and a **nonheuristic completion witness for the complete save/rename/attachment/provenance transaction**, with final MOTW effective before public visibility.

Main-stream last close followed by denial of late ADS writers is insufficient: the file could already be opened without native provenance. Neither idle time nor an empty current writer set proves no future MOTW write. Likewise, `ReplaceFileW` cannot serve as an unchecked metadata-repair shortcut.

**T8-ADS — O/R/B:** forbidden payload in ADS; empty unnamed stream plus nonempty ADS; old-target-only streams; different source/target sets; delayed post-close ZoneId/URL writes; malformed/oversized streams; interrupted finalization and mutation races. Independently enumerate/read every stream and attempt Office reopen throughout publication. Require no uninspected bytes and no public interval missing required MOTW. **Refusal cannot count as browser success.**

### Extended attributes

**Today:** CREATE EAs are captured but not thereby applied; the checked writer rejects nonzero EAs. Owned staging lacks complete EA mutation/inspection/replay. Existing-source/target EA inventory is not established by this pipeline. [Capture](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:2966), [checked refusal](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StagePublic.c:1610), [public mutation gate](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:10054)

**Native reference:** EAs carry names, flags and opaque values; native copy can preserve them. **Options:** discard, blind replay or inspected support. Loss breaks consumers; replay can carry uninspected payload.

**Recommend:** hold operations whose native result requires unsupported EAs, including existing EAs—not just CREATE buffers. Require bounded enumeration, complete content/schema treatment, authorization and generation binding before preservation.

**T8-EA — O/R/B:** CREATE/post-create EAs, forbidden values, required-EA flags, malformed lengths and late changes. Independently query full names/flags/values and native open/copy results; require no silent loss or replay. [Native EA semantics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d2a2b53e-bf78-4ef3-90c7-21b918fab304)

### Optional object ID

**Today:** no optional-ID transfer exists; object-ID mutators are guarded. This ID is distinct from volume/file IDs used for authorization. [Guard](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:9458), [authorization identity](/home/victor/Work/safeupload-design/driver/T5-DELETES.md:23)

**Native reference:** optional IDs support link tracking; copy and move/replacement semantics differ. **Options:** drop, clone or preserve native semantics. Loss can break tracking/OLE references; cloning conflicts with uniqueness and can import opaque extended data.

**Recommend:** no clone on a new copy; preserve where the original operation requires it only through a qualified transfer. Otherwise hold. Do not remove an ID from a retained source/target before approval to free it for publication. Validate and bind extended/birth data under content policy. This imposes no new file-ID parity requirement.

**T8-OBJECT-ID — O/R/B:** distinct source/target IDs and extended data; copy, original same-volume move and replacement; collisions, interruption and recovery. Independently query optional IDs and separate file IDs, uniqueness and shortcut/OLE behavior; ensure retained metadata is unchanged before approval. [Uniqueness/set requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/63dff554-eabf-4c95-88ac-112523b04c06)

### Short 8.3 name

**Today:** private alternate-name queries return name-not-found; publication has no alias replay. Native generation/tunneling can nevertheless create an alias. [Private query](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:5000), [publication CREATE](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedBoundPublicationNative.cs:119)

**Native reference:** outcome depends on existing policy, collisions and replacement. **Options:** discard, blindly set or reproduce native semantics. Loss breaks legacy references; stale aliases can address the wrong object.

**Recommend:** native generation/preservation under unchanged policy; hold required preservation that is unsupported. Any manual setter must meet its actual Windows authority requirements; no SYSTEM repair.

**T8-8DOT3 — O/R/B:** custom aliases, collisions, current enabled/disabled configurations and rapid recreate. Query aliases and open long/short names to verify identity through publication/restart; include denied setters. [Short-name API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfileshortnamew)

### Reparse points

**Today:** checked walks reject reparse components; stage opening rejects reparse objects. This does not qualify every source/ancestor race. [Anchor check](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StagePublic.c:1271), [walk](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StagePublic.c:1395), [stage check](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedStageFile.cs:338)

**Native reference:** APIs can follow or copy different reparse tags. **Options:** follow, preserve opaque data or refuse. Following/replaying can redirect to uninspected objects or escape scope.

**Recommend:** M2 refusal of participating source/destination/ancestor reparses and swaps, including cleanup/recovery.

**T8-REPARSE — O/R/B:** file symlinks, directory junctions and unsupported tags at each component; swap during capture/inspection/commit/recovery. Independently observe tags, identities and candidate targets’ bytes; require no unintended traversal/publication. [Reparse semantics](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)

### Hard links

**Today:** private stages require one link; physical links into protected scope refuse. The checked by-ID path rejects multiple links, but that is **not blanket by-name rejection**. [Stage check](/home/victor/Work/safeupload-design/agente/SafeUpload.Agent.Service/Interception/StagedStageFile.cs:338), [link refusal](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StageStream.c:9297), [by-ID restriction](/home/victor/Work/safeupload-design/driver/SafeUpload.Minifilter/StagePublic.c:1441)

**Native reference:** aliases share one object’s data/security/sharing. **Options:** alias-wide support, silently break links or refuse. Replacing one name breaks alias relationships; retaining them creates mutation/publication paths through other names.

**Recommend:** M2 refusal of multi-link source/target workflows and link creation until alias-wide tracking/publication is qualified. Close by-name and concurrent-link gaps.

**T8-HARDLINK — O/R/B:** inside/outside aliases, by-name/by-ID access, concurrent writers/mappings and link addition between checks. Independently inspect link counts, all identities and bytes through each alias; retain required source/old-public state on refusal. [Hard-link semantics](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createhardlinkw)

## One-screen summary

| Metadata | Recommended answer |
|---|---|
| Owner SID/group | Original native operation; no service ownership substitution |
| DACL/inheritance | Exact native result; only accepted moved-file `0x0400` exception |
| SACL / mandatory label | Complete native semantics and original-token authority |
| Creation / last-write / last-access | Native semantic result, excluding service side effects |
| Change time | Actual publication by default; authorized setters/suppression honored or held |
| Readonly / hidden / system | Native final bits **and native refusals** |
| Archive / no-index / temporary | Native final ordering/state; cleanup preserved separately |
| Sparse / compressed | Qualified semantic state and all logical bytes; otherwise hold |
| EFS / offline | Explicit M2 refusal pending separate support |
| ADS / MOTW | Inspect/bind whole transaction before visibility; otherwise hold |
| EAs | Hold until complete inspected preservation exists |
| Optional object ID | Native uniqueness/transfer; no cloning or preparatory public mutation |
| 8.3 name | Native policy/generation/preservation; hold unsupported requirements |
| Reparse points / hard links | Refuse unqualified participation and races |
| Every field | Revalidate current state; no stale replay or generic SYSTEM repair |

The owner must decide:

1. **Metadata reference — recommend:** the original caller-requested native operation. The approved protected fallback supplies no metadata/security waiver.
2. **Timestamps — recommend:** native creation/write/access semantics; accept publication-time `ChangeTime` by default, with authorized explicit setters/suppression supported correctly or held.
3. **Ordinary attributes — recommend:** native final bits, setter ordering and refusal behavior; no privileged clearing.
4. **Sparse/compression — recommend:** semantic fidelity with complete logical inspection; hold unsupported cases, without requiring identical physical allocation.
5. **EFS/offline scope — recommend:** explicitly exclude successful M2 publication until their authority, data and recovery contracts qualify.
6. **ADS/MOTW — recommend:** fail closed now; successful browser T8 requires inspected final streams and a proven complete transaction boundary before visibility.
7. **EAs — recommend:** fail closed until bounded, inspected and generation-bound preservation exists.
8. **Optional object ID/8.3 — recommend:** native semantics, holding operations requiring unavailable preservation; no broad metadata-reset exception.
9. **Reparse/hard-link scope — recommend:** explicit M2 refusal until full participating-path/alias support qualifies.