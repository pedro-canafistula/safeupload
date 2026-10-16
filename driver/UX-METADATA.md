# T8 metadata on the unbound MVP line

2026-10-16, `ux/meta`, base `62fd1673`. The owner's native metadata and MOTW
decision in [POST-MVP-PLAN.md](POST-MVP-PLAN.md#owner-decisions) is the contract.
This is a bounded implementation increment, **not completion of T8**.
The [round-2 prerequisite checkpoint](UX-METADATA-ROUND2.md) records the
remaining completion-signal/native-construction/fence blockers and exact VM rows.

The demo FileBasicInformation handler silently dropped attributes and ignored
lower errors. The publisher copied only unnamed bytes to a new SYSTEM-created
file. Scanner reads, backing flush/close and publication writes could replace
the writer's dates. The increment retains explicit positive dates and ordinary
attributes as private version state, overlays private queries, captures the
exact drained backing outside locks, and applies the sealed metadata to the
held publication object after copying. ChangeTime is left to publication.
App attribute changes travel in the exact measured seal, rather than making
the private backing readonly. Existing-source ordinary flags can also be
seeded on the backing; readonly source writes are refused. Timestamp suppression (`-1`/`-2`) is
refused until it can be represented per original upper FILE_OBJECT.

No caller security is taken from a service-owned backing. Native descriptor
construction and commit serialization against a later authorized public
metadata change still require the existing bound producer/capability work.
Its readiness gates stay closed. This increment must not be represented as
fixing the lost-admin-ACE finding or native owner/DACL/SACL/MIC fidelity.

MOTW needs a whole-version stream set and a transaction completion witness
covering late browser attachment writes. Main-stream close, an idle delay or
absence of a stream is not that witness. Zone.Identifier remains explicitly
held on this line; other ADS and EAs are refused. Refusal is not browser success
and does not establish that the existing main-stream publication timing is
MOTW-safe. Do not qualify browser downloads until that producer is implemented.

Existing-source and actual temporary metadata are checked with no-follow
handles, bounded enumeration and exact identities. EFS, offline, compressed,
sparse, reparse, hard-linked and EA-bearing versions stay unsupported. These
checks prevent silent loss; they are not a source/public metadata race fence.
No new kernel imports, timers, waits under locks, activation or V30 cutover are
part of this increment. All runtime metadata/application rows remain open.

Deterministic allocation metadata refusals park with the typed permanent
classification and the reason in the service log; no staged version exists to
hand back. A publisher refusal retains its existing stage and tells its owner
the metadata reason. Linux controls are limited to the compiled kernel shims,
wire/parser/journal methods and source/API checks; they do not exercise the
Windows publisher. Native metadata methods belong to the Windows matrix user
partition; its SYSTEM partitions retain their existing routing.

## Windows handoff to Claude

Use **win10-debug3 / 19045.2965**, standard user **t5actor**, a matched committed
driver/agent pair and the unbound profile. No VM was contacted by this task.
Before boot: independent orchestrator Sol 6.1 xhigh review, feature Debug and
Release WDK/PREfast/ApiValidator at 0 warnings/errors, both actual binary import
gates, then the four-leg agent matrix. Native metadata tests added here execute
in its user partition. Run the following protected rows separately in ordinary,
runtime-Verifier and boot-Verifier modes, with an unprotected same-caller native
reference, independent destination/raw observations and separate restoration.

| Row | Exact operation and required observations |
|---|---|
| T8-M01 Explorer dates | Copy clean TXT and DOCX into an absent name and replace an existing name. Set distinguishable creation/write/access dates first. Repeat Hidden, Archive clear/set, NoIndex and readonly source combinations. Compare dates/bits after all copy/publisher handles close to what the native copy actually set; inspect public bytes throughout. |
| T8-M02 Word Created | Give a published clean DOCX a known old Created date. Word open, edit, Save, close/reopen; repeat Save As and temp/backup replacement. Created must match the native reference; LastWrite must reflect Word's final setter and ChangeTime the publication. Repeat a blocked CPF save, preserving old public bytes and metadata. Include the previously refused negative timestamp setters in the trace: they remain explicitly unsupported in this increment. |
| T8-M03 browser MOTW | Edge download clean and blocked TXT/DOCX, new and replacement downloads. Capture partial-file rename and attachment writes, including deliberately delayed post-main-close Zone.Identifier, URLs containing CPF, malformed/oversized MOTW and service interruption. Enumerate/read streams independently and attempt Office reopen throughout. Require inspected MOTW effective at the first public visibility and Protected View retained. **Required full-T8 row; cannot pass this increment's missing transaction producer. Do not count refusal as success.** |
| T8-M04 other ADS/EAs | Write `file:payload` containing CPF against new, pending and published files; copy a source with such a stream; repeat empty base plus nonempty ADS and CREATE/post-create EAs. Require native refusal, specific diagnostic, unchanged old destination and no alternate bytes. Zone.Identifier currently has a separate explicit unsupported reason. |
| T8-M05 grants/readonly | Compare denied FILE_WRITE_ATTRIBUTES, metadata-only reopen to clear readonly, already-granted writer after readonly setter, ordinary delete and replacement of a private readonly target, and explicit disposition ignore-readonly flags. Verify caller grants, sharing and old destination; readonly publication failure must remove only its exact uncommitted temporary. |
| T8-M06 version inheritance | FILE_OPEN/OPEN_IF with no write, then write; FILE_OVERWRITE/OVERWRITE_IF truncate to zero and close without WriteFile; FILE_SUPERSEDE with hidden/no-index CREATE attrs. Repeat before and after prior publication and with a sealed predecessor. Check Created, LastWrite and Archive, including explicit setter followed by write/EOF/allocation and writable-map/native controls. |
| T8-M07 unsupported storage | EFS, offline, compression and sparse on source, existing target, staging parent and publication parent. Include truncating opens (no byte seed) and inherited output flags. Require explicit hold/refusal, no normalization/decryption, retained source/old public bytes and bounded allocation. |
| T8-M08 aliases | Existing/by-name/by-ID hard-linked source/target, new hard link, file symlink/junction and ancestor reparse swap at capture/inspection/commit/recovery. Require refusal and no unintended traversal/publication; inspect every alias independently. |
| T8-M09 native descriptor | Native owner/group, binary DACL (only accepted moved-file 0x0400 marker difference), SACL and mandatory label for new/save/copy/replace, including restricted/impersonating users and creator grants. **Requires the unfinished native construction producer; this increment is not a descriptor fix.** |
| T8-M10 commit races | Change public ACL (including the previously lost admin ACE), dates, flags, stream set and EAs between allocation, seal, inspection and rename; replace the public/parent object. Require hold or the authorized native result, never stale replay. **The public metadata fence is unfinished; no success claim from pre-rename inventory alone.** |
| T8-M11 restart/failure | Fail metadata query/application, rename, journal persistence and cleanup; disconnect/restart around metadata application and native rename acceptance. Exact tuple and metadata survive seal replay; accepted rename is never repeated. Uncertain publication stays held; no private readonly residue is stranded. |

Native component filter: `FullyQualifiedName~StagedFileMetadata` (all new pure
and native cases), plus existing publisher, allocator, journal, rename, seed,
notification and cleanup controls. The full feature matrix remains required.
No existing test/assertion/threshold was weakened or removed.

## Local checkpoint

Feature Debug/Release offline Tests (including Service/Core/Minifilter) and App
builds pass with SDK 10.0.400, warnings as errors, 0 warnings/errors. The unchanged
focused methods and InlineData rows execute directly: **50 passed, 0 failed**
(28 metadata and 22 existing rename-wire controls). VSTest itself aborted because
the sandbox denied its TCP listener; direct execution is a diagnostic subset,
not Windows matrix/discovery or publisher integration coverage. The native
metadata cases remain unexecuted here, with no skip annotations introduced.

All 25 selected kernel/runner Python scripts pass, including the T5, directory,
outside, activation, existing kernel fixtures, T4 verdict, exact matrix/source
runner, feature default and import self-checks. The added metadata suite has
three controls and compiles actual setter, seal-capture and seal-wire bodies,
including their real forward declarations, with GCC and Clang, warnings as
errors and UBSan. They cover grants, ordinary flags, readonly state, dates,
truncation/supersede, malformed/failed/pending lower queries, exact wire tuples,
zero tails, immutable seal replay and no lower I/O while a resource is held.

The source API delta has **zero new external kernel calls** and all 86 audited
host stub declarations are supported. The full borrowed API audit fails at the
same pre-existing `Taint.c:356: InsertHeadList` header-inventory omission on both
`62fd1673` and this change. That failure is retained, not suppressed or called a
full audit pass. No newly built driver import, WDK, PREfast or ApiValidator pass
is claimed. No PowerShell harness was changed.

Independent Sol 6.1 xhigh advisory design/implementation review accepted this
bounded increment with conditions. Readonly metadata reopens/delete/replacement,
initial/supersede flags, inherited truncation dates and deterministic allocation
refusal classification were corrected. The fresh orchestrator qualifying review
and Windows gates remain outstanding. Failed attempts and raw local receipts
are retained in `.scratch/verification` of the delivery workspace; initial
VSTest/default-MSBuild and diagnostic-runner failures are separate from the
passing corrected runs. Git delivery is a scratch-repository commit bundle;
the source checkout's Git metadata is not changed.

API references: [FILE_BASIC_INFORMATION and handle-local suppression](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_basic_information),
[GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex),
[FileDispositionInfoEx flags](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex),
[mapped-write timestamp behavior](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile).
