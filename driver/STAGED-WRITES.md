# Staged writes to protected destinations

## User-visible behavior

An ordinary Save or Copy to a protected USB drive, network share, or sync
folder keeps the application's write in private local storage. The tray shows
`Analyzing` after the final writer closes. A fully inspected clean version is
copied to the destination; sensitive or uninspectable versions stay local.
No sensitive byte may be created at the destination before approval. A timeout,
service disconnect, parser error, size limit, unknown format, or journal error
must retain the local version and report that it was not sent.

## Enforcement invariants

1. Every writable open of a protected destination is redirected before the
   underlying filesystem handles the create. Direct writes, paging writes,
   truncation, rename, hard link, and file-ID opens cannot bypass this gate.
2. The private staging file is on a local fixed volume. Its path is never inside
   a protected sync folder. The service records the destination and originating
   user in a durable journal before returning the staging path to the driver.
3. The driver tracks all writable handles on a staged stream. Only the final
   cleanup seals the version. The service acquires a read handle that excludes
   writers for the entire scan and copy. A later open starts a new version.
4. The service releases only `Approved` after actual content inspection under
   the current policy. `AllowedWithoutInspection` is **not** approval for a
   staged transfer. A transfer also stays local if the destination is no longer
   in policy scope when publication is attempted.
5. The service writes an approved version to a temporary file at the target,
   flushes it, and renames it into place. Only the service's authenticated
   publication path may bypass the destination gate. The published bytes must
   be the same locked version that was inspected.
6. Stage creation, sealing, approval, publication, and retention have durable
   states. On restart, the service reconciles each state. It must not treat an
   interrupted inspection as an approval, and it must not lose a user file.
7. A user can justify a blocked transfer only against its exact transfer ID
   and inspected version. A justification may release that version; it must
   never grant a general process or destination bypass.

## Required Windows coverage before deployment

- Explorer `CopyFile` and `MoveFile`, PowerShell and .NET streams, Office
  save-via-temporary-file-and-rename, append, overwrite, multiple open handles,
  and memory-mapped writes.
- Short names, relative opens, reparse points, directory enumeration, metadata
  queries, open-by-ID, alternate data streams, rename and hard-link operations.
- USB, mapped and UNC network shares, and local cloud-sync folders.
- Service crash, driver unload/reload, machine restart, removal of a USB drive,
  full staging disk, timeout, changed policy, and concurrent writers.
- A negative test must watch the actual destination bytes and sync client during
  every blocked case. Checking only the final path after deletion is not enough.

The service-side `StagedTransferPublisher` and `StagedTransferJournal` now
implement sealed-file inspection, durable state transitions, digest-based
publication recovery, and outcome auditing. A classification result is not
audited as a successful send before the destination publication succeeds.
The publisher rechecks the policy version and destination scope before
publication; a policy change during analysis retains the file. The test-only
cross-volume minifilter path is wired to the journal, final-writer seal signal,
and publisher. It remains disabled in ordinary builds and is not a complete
transparent namespace or private-storage implementation.

Microsoft's SimRep sample demonstrates pre-create reparsing, but explicitly
does not virtualize the namespace for higher filters. Its rename, name-provider,
and network-query handling are relevant starting points, not a drop-in DLP
solution: https://learn.microsoft.com/en-us/samples/microsoft/windows-driver-samples/simrep-file-system-minifilter-driver/

Memory-mapped writes require paging-I/O coverage in a filter that monitors
changes: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/memory-mapped-files-in-a-file-system-filter-driver

## Reparse feasibility probe (debuggee VM)

An experimental pre-create callback on `feat/staged-kernel-prototype` used
`IoReplaceFileObjectName` and `STATUS_REPARSE` to map a single top-level test
file from `C:\SafeUpload\Escopo Monitorado` into `C:\SafeUpload\_staging`.
The WDK build succeeded. With the signed prototype loaded on the debuggee,
`File.WriteAllText` succeeded, the stage contained the bytes, and the original
destination path did not exist. The original driver was restored afterward
(SHA-256 `ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE`).

That first probe proved the write redirection primitive, not application
transparency. Immediately after its save, a metadata lookup of the original
path saw no file. An application that reopens its save or enumerates its
folder needs process-aware name virtualization. Cloud sync and other
processes must not see the staged bytes before approval. The prototype is
disabled by default with `SAFEUPLOAD_STAGING_PROTOTYPE=0` and must not ship.

The later test-only namespace map redirects subsequent opens by the writer's
process to its stage file. On the debuggee, the writer could reopen and read
the staged bytes; another process could not see the new destination path.
The map is dropped on process exit so PID reuse does not inherit visibility.
The earlier probe used driver load time and a sequence number in stage names.
The current probe instead obtains a unique GUID basename from the service,
which durably records the transfer before answering the kernel. A recycled
PID cannot claim a previous writer's in-memory view.
An explicit `SafeUploadStagingPrototype=true` WDK build property is required
to include this code; ordinary builds still compile it out.

The same test exposed two missing filesystem operations. The writer's folder
enumeration did not include its staged file. A rename from a staged temporary
file into the protected folder initially made bytes visible before approval.
The prototype now denies renames and hard links into that test folder; the
debuggee confirmed the destination stayed absent. This safety gate breaks
rename-based saves and must become transactional rename virtualization.
The original driver was restored after each test. The reproducible test is
`driver/scripts/Test-StagedNamespacePrototype.ps1`.

## Cross-volume, service-owned allocation probe (30 September 2026)

On the isolated debuggee VM, `Test-StagedCrossVolumePrototype.ps1` created a
disposable NTFS VHDX at `S:` and used the prototype build with protocol 12.
The driver now resolves the local `C:` volume independently, asks the agent
for a unique stage basename, and only reparses the create after the agent
has flushed an `Allocated` journal manifest. With no agent connected, the
protected create returned access denied and left no destination file. With
the self-contained agent running, the writer reopened `S:\SafeUpload\Escopo
Monitorado\...txt`, read its staged bytes from `C:\SafeUpload\_staging`, and
another process saw no file at the destination. The journal contained one
matching transfer, and the stage held the expected bytes. The test unloaded
the prototype, restored the original installed driver, and detached `S:`.
It also stopped and restarted the agent while the driver remained loaded:
the unsealed `Allocated` entry was held locally, with no destination file.
The rename and hard-link safety gates still denied both operations.

The current probe attaches a kernel-created ECP to each redirected create.
The same app can reopen the original name, but a direct open of the private
stage filename without that marker is denied while the filter is loaded.
The VM test confirmed `DirectStageReadDenied=True`. Microsoft documents that
ECPs added during a create survive reparse retries:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltallocateextracreateparameter

The agent also holds interrupted `Allocated` entries unsealed and retains
interrupted `Inspecting` and `Approved` entries on restart, then reconciles
`Publishing` entries against the actual
destination digest. The staged-transfer tests pass. This is a feasibility
probe only: unloading the filter exposes the stage to the same user (also
confirmed by the test).
Other aliases need independent coverage. Only the two hardcoded test
directories are handled. Protocol 14 requires
the matching agent; the ordinary installed driver remains the previous
protocol 11 binary. The prototype is compiled out by default and must not
be placed in a production package.

## Recovery and journal hardening (30 September 2026)

Recovery now puts an interrupted `Allocated` transfer in a distinct `Unsealed`
state. It cannot enter inspection or publication. The journal records whether
the transfer was ever sealed, so an older `Retained` manifest without seal
provenance also cannot be published. This closes a recovery path where an
unfinished writer's bytes could otherwise become eligible for inspection.

The prototype journal moved to `%ProgramData%\SafeUpload\staging-journal`.
On Windows, its directory and manifests get explicit service, SYSTEM, and
Administrators ACLs. Prototype startup rejects a parent that grants ordinary
users child-deletion rights; a LocalSystem service also rejects existing
journal objects owned by other identities. The debugger VM passed 22 focused
tests and the complete 192-test agent suite. The cross-volume debuggee test
passed after the move, including `Unsealed` recovery and restoration of the
original driver hash.

This does not secure the stage file. The debuggee test still reads its exact
unapproved bytes as the writer after the prototype filter unloads. The
current reparse opens that file using the writer's token, so the file's NTFS
ACL must grant that user access. That same access remains after driver unload
or crash. An ACL on the journal cannot close this gap. A protected stage
requires a different data path that gives the app a usable handle without
granting it independent access to the stored file. The probe still denies
rename-based saves and omits folder-listing virtualization. Staging remains
disabled in ordinary builds.

## Final writer and later version probe (30 September 2026)

Protocol 14 uses a kernel-issued `STAGE_SEAL` message after the last writable
handle cleans up. The driver counts staged writers and blocks another writer
while a seal request is in flight. A writable memory-mapped view delays sealing
after its file handle closes; a prototype worker checks the section's writable
references and seals after the view disappears. The agent journals `Sealed`,
notifies `Analyzing`, inspects that version, and publishes a clean version with
its connected-port process identity. A blocked or uninspectable version remains
local. A service restart changes interrupted `Allocated` to `Unsealed` and
requires the real driver seal signal before inspection.

After a sealed version, the same writer's next writable open allocates a new
transfer ID. `FILE_OPEN` and `FILE_OPEN_IF` copy the prior stage into the new
local stage; truncating dispositions start empty. A sensitive append did not
change the already published `alphabeta` destination bytes, and a later clean
overwrite published only `clean replacement`. The debuggee test also passed
two concurrent handles, a mapped write without an extra file reopen, and a
service crash with a handle held open. The WDK prototype build passed; 25
focused and 195 full Windows agent tests passed. A separate
`Test-StagedFileIdAlias.ps1` probe read a fixture by file ID before filter load
and received access denied while the prototype filter was loaded. Each test
restored the installed original driver; its independent SHA-256 check remained
`ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE`.

This path is still a test-specific prototype. It does not synthesize the
writer's directory listing or virtualize rename-based saves, so Explorer and
Office save workflows are incomplete. The stage is readable by its writer
after driver unload. Other aliases, USB hardware, UNC shares, sync clients,
and Driver Verifier have not passed the required matrix. The worker and
version handoff have only the disposable-VHDX test coverage described above.

## Private backing storage and exact-version approval (30 September 2026)

The protocol-15 feature build now stores backing files in
`C:\ProgramData\SafeUpload\staging` under a protected, SYSTEM-owned DACL.
The runtime allocator requires LocalSystem. Before redirecting a create, the
driver checks the original user's access against the destination descriptor
or the parent and inherited descriptor for a new file. Its kernel-only ECP
carries those granted rights into the redirected access state. It never
substitutes the user's token and never grants permission to change the private
backing ACL. This replaces the earlier unload exposure described above.

`Test-StagedPrivateStorage.ps1` and the cross-volume harness confirmed that
the writer could read its virtual destination while direct backing reads
remained denied **after filter unload**. The cross-volume harness also passed
concurrent handles, append and overwrite versions, mapped-view final closure,
service restart with an open writer, and clean publication after final close.
The agent now authenticates its filter-port identity before recovering existing
private files. Every experiment restored the original installed driver, with
the expected SHA-256 independently checked afterward.

The publisher inspects a separate service-only snapshot and copies that same
snapshot to the destination. It checks the backing digest before publication.
A blocked version's justification is bound to its transfer ID, digest, policy
version, originating session and a one-use time-limited callback. Changed bytes,
policy changes, other sessions and replay do not authorize that version.
The callback reinspects and rechecks policy; it never creates a process grant.
The application now displays staged findings and submits this transfer ID.
The 199-test Windows agent suite and application build passed at this point;
the later UNC translation suite brought the total to 206 passing tests.

The feature build also uses configured destination prefixes and volume kinds
for allocation, resolves normalized names, and supports nested file paths.
The disposable `S:` test classification and bootstrap test-folder gate remain.
Unresolved writable names and writable file-ID opens fail closed in this
experimental build. Ordinary builds continue to compile staging out.

Protocol 16 adds a journaled virtual rename transaction, query-open fallback
into virtual creates, and final-extension inspection of temporary files.
Its 31 focused agent tests and WDK build pass. The VM rename test passed an
ordinary `.NET File.Move` from a private `.tmp` stage to the final `.txt`
name: a clean version was inspected and released, a sensitive version remained
private, the writer read the renamed bytes and the old virtual name disappeared.
The failure found and fixed in that test was redirecting a rename's
`SL_OPEN_TARGET_DIRECTORY` parent open as though it were a file write.
Protocol 17 now verifies native final-path names on the local destination,
writer-only directory entries and sizes, old-name removal after rename, and
ordinary clean and sensitive saves. Directory handles keep a private union
snapshot with wildcard matching and a cursor; eight standard information
classes, restart and single-entry queries are implemented, with unsafe-context
queries deferred to PASSIVE_LEVEL. Small-buffer and cancellation probes still
need dedicated VM coverage.

The authenticated LocalSystem port owner now needs a per-transfer publication
permit: an exact pending path and final destination, transfer ID, inspected
digest, one create, one rename and a 30-second expiry. Disconnect revokes all
permits. There is no blanket service write/rename bypass in protected scope.
The VM passed both local rename and cross-volume clean publication through
these permits. A dedicated completion event for each overlapped receive fixes
a discovered shared-port wakeup that previously canceled publication when a
control message was sent alongside the receive.

The full Windows agent suite now passes 212 tests. That includes a new
regression for changed content with identical size and timestamp: inspection
cache reuse now hashes the same in-memory bytes that are scanned. The staged
publisher continues to avoid the legacy inspection cache entirely.

`Test-StagedDuplicatedHandle.ps1` also passed an owner process exit with its
writable file object duplicated into another process: the transfer stayed
unsealed while the duplicate remained open, and final cleanup in the second
process published the exact `basetail` bytes. Both normal (staging disabled)
and experimental WDK builds passed at this checkpoint.

The cross-volume VM test passed writer-only listings, virtual rename,
concurrent writers, append/overwrite versions, mapped-view final closure,
service restart, and destination-byte observers. Each harness restored the
known original driver and detached its disposable VHDX. Rename replacement of
an existing staged target, hard-link aliases, full USB, UNC and sync-client
coverage, crash/reboot recovery and Driver Verifier remain required before
claiming the full design complete.

## Implementation sequence

### Pause checkpoint (1 October 2026)

The latest experimental WDK build and signed VM rename test passed. Each
staged handle now retains a reference to its version's virtual name, independent
of the mutable namespace mapping. A held read handle followed a temporary-file
rename and kept the final virtual path after a later version was allocated;
its original bytes remained unchanged. Native `FileAllInformation` also returned
the virtual path. Backing DOS aliases are not returned as destination aliases.
Directory snapshots now record the requestor identity and rebuild when a shared
directory handle is queried by another process. Allocation failure cleanup no
longer walks an uninitialized directory-entry list.

Private-stage file-ID probes after unload passed with and without backup
semantics under a token with elevated privileges removed. The initial elevated
SSH test could read by ID because its `SeBackupPrivilege` was enabled, which
Windows deliberately allows to override read ACLs. This is a trusted host-admin
boundary, not protection against a privileged backup operator. Backing files
now also receive explicit protected service/SYSTEM ACLs before their paths are
issued; recovery replaces extra file grants. The ACL regression brought the
full Windows agent suite to 213 passing tests. A nullable warning in that test
was corrected locally after this run; no additional test run was started at
the user's pause request.

Latest signed experimental driver SHA-256:
`3751294725B4B677C00CCFFFDB39DAE18D5F680D14691B154E2C7019D9D23D38`.
The final VM test restored the original installed driver. Staging remains
disabled in normal builds and process taint remains in place. The feature is
not complete. Resume with the latest private-storage and cross-volume harnesses,
then native directory pagination/cancellation, transactional replacement and
hard-link/alias support. Per-process destination version ordering, directory
notifications, cross-volume native volume identity, actual Explorer/Office,
USB/UNC/sync, user justification UI/pipe, crash/reboot and Verifier coverage
remain unverified or unfinished. The current rename journal retarget is still
single phase and needs timeout/crash-safe commit handling.

1. Add a service-owned transfer journal and per-user staging directory. The
   driver requests a stage mapping for a specific destination, process, and
   create disposition. A missing service or stage allocation error denies the
   protected create before it reaches the destination.
2. Track all handles for a staged version in kernel. Seal only after the final
   writable cleanup, including mapped writes and rename-based saves. The
   journal survives a service restart and retains an unapproved file.
3. Virtualize names for the writing app: open, query, enumeration, rename,
   hard link, and change notification. Do not expose staged content to the
   sync client or another process. Apply the same rule to USB and UNC paths.
4. Integrate the publisher with the journal. Audit the actual publication
   outcome separately from content classification, and bind justification to
   the exact staged version. Reconcile incomplete publication after restart.
5. Run the coverage matrix above on the debuggee with a byte-level observer
   on each destination, Driver Verifier, and measured save latency. Only then
   replace the process-taint rule and enable the feature in policy.
