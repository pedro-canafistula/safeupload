# T22 — staged protection for SMB / UNC destinations

2026-10-13. Design proposal against `wt/designs`, source `6128a892b30c`.
**Not implemented, not qualified, and not permission to enable SMB or run a VM.**
Independent **Sol 6.1 xhigh** review (`t22_review`, 2026-10-13): **ACCEPT WITH CONDITIONS — design proposal only**.
Credential binding, temporary mutation exclusion and extra publication-grant findings are incorporated.
Owner choices and native feasibility gates remain open; review acceptance is not implementation or runtime qualification.
Recommendations and experiments below require the indicated owner decisions; none is recorded as accepted here.

## 1. Authority, scope and acceptance boundary

The binding sequence is M2 → M3 → T21 → **T22** → T23 → combined M4, then owner-approved taint removal.
Design work may proceed now; implementation, infrastructure changes and destination activation may not.
Authority: `driver/POST-MVP-PLAN.md:9`, `:61`, `:66`, `:850`, `:871`.
The 2026-10-13 review-model decision supersedes older Luna references (`driver/POST-MVP-PLAN.md:26`).
The T4 loaded-context stop remains, with only the specifically authorized hand-back attribution diagnostic excepted
(`driver/POST-MVP-PLAN.md:36`, `:184`). Nothing in this note uses that exception.

T22 must prevent unapproved nonempty bytes produced by the protected endpoint from reaching the remote share.
The boundary includes temporary names, alternate names, server caches, server storage, snapshots and backup input;
another SMB client need not cooperate, know SafeUpload's names, or use the protected endpoint.
An ACL-denied or hidden remote file already contains destination bytes and is therefore not a private preinspection stage.
Approved transfer fragments may exist in a publication temporary only after complete inspection authorized their exact source.
The final name must expose the previous complete version or the next complete approved version, never an incremental overwrite.
Empty versions follow ordinary stable seal/inspect/publish; there is no EmptyHeld branch.
CPF-blocked new saves leave no public file; blocked replacements retain prior bytes unless a separate authorized delete happened
(`driver/POST-MVP-PLAN.md:73`; `driver/T5-DELETES.md:378`).

The threat boundary remains trusted product service/kernel and administrators, with standard users potentially adversarial
(`driver/MVP-PLAN.md:9`). A trusted SMB server must enforce its documented security and storage contract.
This endpoint cannot prevent an unrelated unprotected client from uploading its own sensitive bytes.
It must withstand that client's competing opens, changes and namespace races without misusing this endpoint's authority.
Qualification uses unique payloads and attributed operations to distinguish those obligations.

Recommended initial candidate: Windows SMB client on the qualified Windows 10 **19045.2965**, one owner-selected
Windows Server build, NTFS-backed disk shares, SMB **3.1.1**, authenticated Kerberos and signed traffic, direct UNC and
equivalent user-session mappings; local fixed-NTFS staging, no DFS, CSC, cluster failover or offloaded mutation.
This is a proposed support profile, not an approved narrowing of T22 or a claim that these conditions suffice.
Server identity, write-only seeding and cross-client replacement remain blocking mechanism questions (§§5–7).

## 2. Current repository behavior and the actual gap

| Source at this checkout | Current behavior / implication |
|---|---|
| `agente/SafeUpload.Agent.Core/Infrastructure/PolicyDocument.cs:188`, `:200` | `destinationPaths` is a string list; **`networkPaths` is a Boolean**, default true, not a list of UNC roots. |
| `agente/SafeUpload.Agent.Service/Interception/MinifilterPolicyFactory.cs:30`, `:45` | Destination prefixes and broad network/removable flags are transmitted separately. |
| `agente/SafeUpload.Agent.Minifilter/PolicyBuilder.cs:73`, `:195` | Network flag covers volume kind; `ToNtPath` returns UNC strings unchanged and otherwise translates a drive using `QueryDosDeviceW`. This is not remote canonicalization. |
| `driver/SafeUpload.Minifilter/Policy.c:1781` | Recognizes UNC/MUP/Lanman/DFS/WebDAV-shaped prefixes conservatively; recognizing network syntax does not establish an SMB object. |
| `driver/SafeUpload.Minifilter/Context.c:514` | Positive staging admission requires fixed local disk, NTFS, GUID, canary and known writer coverage; remote is excluded. |
| `driver/SafeUpload.Minifilter/StageStream.c:2152` | Owned staging explicitly rejects non-NTFS / network original instances. |
| `driver/SafeUpload.Minifilter/StageStream.c:1545`, `:1574` | Backing is opened on C: through a separate NTFS instance; sector and device-stack-size conditions are checked. |
| `driver/SafeUpload.Minifilter/Filter.c:146` | Feature dispatcher registers data, paging-related, section, namespace, security, FSCTL and Fast I/O callbacks. Registration is not proof of remote coverage. |
| `agente/SafeUpload.Agent.Service/Interception/StagedDestinationCommitJournal.cs:13` | Head identity uses volume-root/parent full IDs, case mode, leaf and optional Mount Manager GUID; equality includes those fields. |
| `agente/SafeUpload.Agent.Service/Interception/MinifilterBoundAllocation.cs:14`; `agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:83` | Bound admission is false and the legacy publisher rejects bound entries. T22 cannot build on an assumed completed T5 path. |

`driver/STAGED-WRITES.md:32`, `:43`, `:76` describes the owned upper stream and local-only contract; its old caps/worker
description is historical, not permission to undo T4. `driver/ARQUITETURA.md:8`, `:69`, `:301` records earlier prototypes
and taint architecture, not qualified network staging. `driver/MVP-PLAN.md:3` explicitly defers current status to the plan.
`driver/M2-COMPLETION-PLAN.md:13`, `:29` requires a connected authority/inspection/head/cleanup transaction.
T22 extends that transaction with a destination backend; it does not introduce a competing publisher or bypass legacy taint.

## 3. Attachment, visibility and a genuinely local private stage

### 3.1 Attachment contract

Use Filter Manager instances on the remote filesystem stack represented by `\Device\Mup`, plus the existing local NTFS
backing instance. Microsoft's Vista redirector model routes remote filesystem I/O through MUP; redirector device names
can be links to MUP. Remote FILE_OBJECT contents remain redirector-owned. Legacy providers have different routing. [M01]
Do not attach a second bespoke filter to `mrxsmb`/`mrxsmb20` or patch RDBSS internals.
RDBSS supplies redirector infrastructure and caching; Microsoft's SMB mini-redirector uses it. [M02]
The precise loaded modules, instance count, filesystem type and callback paths on 19045.2965 are **unverified: N01**.

InstanceSetup supplies device/filesystem type, but one MUP instance is not one server/share/security principal. [M03]
Keep share/session-specific admission beneath that instance; an admitted share cannot make unrelated providers Ready.
Use documented provider queries on actual remote file objects and a validated `FILE_REMOTE_PROTOCOL_INFO` result to identify
SMB, negotiated version, offline use, persistent-handle and security flags. [M04][M05]
Do not assume either query works on an unopened or synthetic owned FILE_OBJECT; N01 must determine the safe query point.
Before that point, conservatively intercept potentially protected creates and perform only nonmutating authority/identity probes.
Unknown provider, short query, unsupported version or changed binding cannot become “outside policy.”
WebDAV, NFS, loopback shares and legacy redirectors require separate qualification; do not reinterpret all UNC traffic as SMB.

### 3.2 Which operations must be mediated

| Surface | Required treatment and visibility claim |
|---|---|
| CREATE, overwrite, supersede, append | Capture effective subject/disposition/sharing before any destructive forwarding; expose only an owned private data object. N01/N04 compare native outcomes. |
| READ/WRITE, cached/noncached/paging | All writer data belongs to the local owned stream; no application data is forwarded to a remote public open. Trace every route in N02. |
| Section acquire/release, modified writer, cache flush | Maintain owned section/rundown evidence; a map outliving its handle can still change private bytes. N02 reruns both mapping-leak repros. |
| Fast I/O, network query-open, MDL read/write | Refuse unsafe fast routes or provide an explicitly covered owned implementation; only IRP operations may be pended. [M06] |
| EOF/allocation, rename/link, disposition, security, EA, reparse | Route supported operations through private views or checked public metadata/delete capabilities. Unknown mutators fail closed. |
| FSCTL/IOCTL | Explicitly deny COPYCHUNK/WRITE, ODX offload-write, clone/extent and other unmediated mutations into protection; never rely on missing ordinary WRITE callbacks. [M14][M15] |
| Directory/query/notify/locks | Merge only the requesting owner's private namespace; preserve native public information and supported lock/share behavior. Remote users see public versions only. N02/N04. |
| CLEANUP/CLOSE/cancel/teardown | Drain local references independently of remote acknowledgements; never equate local cleanup with server deletion or durable-open retirement. N07/N09. |

These are coverage requirements, not a claim of one filesystem callback per SMB packet.
The filter sees I/O delivered at its altitude; redirector caching, coalescing and retransmission occur below that boundary.
SMB leases permit read/write/handle caching, while directory leasing reduces metadata round trips. [M07][M08]
An oplock/lease break is a cache-coherency event, not inspection approval, exclusive namespace ownership or a durable commit receipt.
RDBSS write-behind must never acquire the private version: a lease break or reconnect must have no unapproved remote data to flush.
Publication uses separate approved-only handles; test leases granted, refused and broken by a second client, including cached negatives.
Do not claim two matching client directory reads alone prove current server identity or absence.

CSC/Offline Files can cache network data locally and synchronize changes later. [M09]
Consequently a private upper stream above a CSC path is not automatically safe: cached lower writes may upload after inspection
failure, service loss or scope change. Recommend refusing CSC-enabled protected scopes until a separate replay design is qualified.
An OFFLINE flag is positive evidence of cached use, not proof that its absence excludes future offline transitions. [M05]
N08 must validate configuration plus actual transition detection; no automatic machine-wide CSC reconfiguration is proposed.
Transparent failover can reconnect clients to another cluster node; persistent handles deliberately complicate lifetime. [M08][M18]
Recommend excluding CA/failover initially, with explicit refusal controls; durable ordinary reconnect still needs N07.

### 3.3 Stage-location alternatives

| Candidate | Destination privacy, including snapshots / other clients | Conclusion |
|---|---|---|
| Local fixed-NTFS private stage; inspect; transfer approved snapshot to remote temporary | No unapproved file data is sent to server storage. Private backing remains protected by local ACL and owned access. | **Recommend**, subject to remote authority/commit controls. |
| Hidden sibling or hidden share for mutable staging | Hidden names do not remove remote bytes; server-local readers, snapshots and backups can retain them. | Violates the stated destination boundary. |
| Remote service-only ACL stage | Other ordinary clients may be denied, but bytes have already reached the server and can enter backup/snapshots. | Violates the boundary even with correct ACLs. |
| COPYCHUNK/ODX from mutable remote source | Server/storage moves bytes without sending ordinary content through the endpoint scanner. | No preinspection route; deny. |
| COPYCHUNK from a fully approved remote temporary | Could optimize a later approved transfer but needs exact source, range, rights, immutability and outcome proofs. | Defer; no benefit to initial local-to-server upload. |

COPYCHUNK uses an opaque source key and destination open; SMB enforces source read and destination write rights. [M14]
ODX is explicitly a filter-visible FSCTL concern; Microsoft says filters must actively allow/refuse it. [M15]
VSS backs up shadow copies: deleting a leaked remote temporary later does not retract snapshot exposure. [M16]
Encryption on the SMB transport does not make server-resident preinspection content private from the destination.
Uploading ciphertext for later remote decryption would change the product/storage contract and is not this proposal.

Retain the app-facing upper on its original remote stack, with exclusively owned FCB/cache/section state and separately generated
I/O to the local backing. Never borrow redirector FsContext/SOPs, transplant them to NTFS or retarget an outer request across volumes.
`FLT_IO_PARAMETER_BLOCK` restricts target-instance/file-object retargeting to the same volume. [M10]
Current backing generation is in `driver/SafeUpload.Minifilter/StageStream.c:4573`; its existence proves no remote compatibility.
**N02 is a hard feasibility gate** for synthetic remote upper objects, stack size, alignment, cache callbacks and paging completion.
If unsupported, retain network refusal and return a revised architecture for review; do not delete the local guard and hope.
Local stage roots must be fixed NTFS, private, non-reparse, outside network/CSC/cloud-sync roots and covered by T9 accounting.
Charge mutable stage, seed/snapshot, security records, hand-back, journal and any remote publication residue at overlapping lifetimes.
No numeric quota is selected here; existing caps stay until their replacement budgets and failure behavior are approved.

## 4. Policy names, aliases and routing

`networkPaths=true` continues to mean all network destinations are in policy; support enrollment is not an allowlist exemption.
In staged mode, an in-scope unsupported/unbound destination is refused with a support reason, not passed through uninspected.
`networkPaths=false` plus UNC `destinationPaths` requires explicit root binding and component-boundary matching.
Do not silently reinterpret the Boolean, or treat an unconvertible UNC prefix as a successful empty policy.
Boot policy, pending scope and active scope must preserve conservative network interception before user opens.
Normal builds and legacy taint retain their current semantics; a negotiated feature-only capability selects the new backend.

| Input / alias | Resolution rule |
|---|---|
| `\\server\share\dir` and `\\?\UNC\server\share\dir` | Parse the actual namespace and components; preserve original lookup semantics, then bind real remote handles. Extended syntax is documented, not permission to strip arbitrary prefixes. [M11] |
| `X:\dir` | Resolve in the original caller's logon/device namespace at create capture; retain that remote binding. SYSTEM's X: is not the user's mapping. [M12] |
| Short hostname, FQDN, CNAME, IP literal | Treat as locators until server authentication and root identity prove equivalence; DNS equality/IP equality is insufficient. |
| Two share names / overlapping shares | Preserve each share's access route but unify the physical namespace key when checked server/store/parent/leaf identity agrees; do not create independent generations. |
| Case / short names / trailing dots or spaces | Use server-qualified lookup and canonical leaf equality, not culture-dependent lowercase or a blanket Windows/Samba assumption. Refuse ambiguous names. [M11] |
| DFS domain root / referral / target UNC | Keep logical policy scope and resolved target separately. A new referral target requires its own binding, policy coverage and generation/conflict handling. [M13] |
| Junction, symlink, mount point, reparse in any ancestor | Detect each hop and refuse initial-profile traversal; final-component OPEN_REPARSE_POINT alone is not an ancestor guarantee. N03. |

Mapped drive support means ordinary drive-letter access and UNC reach the same checked head; remapping X: does not redirect a queued save.
Do not create/manage mappings or cache user passwords in the service. Microsoft recommends UNC with client impersonation. [M12]
`FltGetFileNameInformation` normalized remote names depend on SMB/Windows support and may require expensive component queries. [M17]
Cache names as locators only; query failure, truncation, reparse, referral change or incomplete enumeration preserves a hold.
Never parse undocumented provider adornments by deleting semicolon-delimited fragments or assuming a fixed `LanmanRedirector` string.
N03 records opened, normalized, provider and actual server-local names for every accepted spelling.

For prefix-only policy, an alias reaching the same enrolled remote root must remain protected.
If pre-create identity cannot distinguish an alias from an unrelated scope without data mutation, keep the candidate in scope until
resolved. A configured root's disappearance does not remove protection from its prior outstanding versions.
Hard-link aliases and overlapping exports require object-to-scope coverage, not only parent text; initial support must either prove
that coverage or refuse the affected aliasing configuration. N03 includes a link outside the configured prefix into the same object.
DFS is recommended out initially because a namespace can lead to multiple servers. [M13]
Reject logical and direct-target bypasses according to enrolled scope; simply denying the `\\domain` spelling is insufficient.

## 5. Remote identity and durable destination heads

Keep three distinct concepts: **policy route**, **physical destination identity**, and **ephemeral execution authority**.
Suggested fields below describe a new tagged network binding, not an allocated wire layout or implemented type.

| Binding | Proposed evidence |
|---|---|
| Policy route | Policy revision, configured logical root, approved aliases, actual authenticated server principal, share/export enrollment and configuration revision. |
| Physical destination | Enrolled server/storage incarnation, verified remote root and parent object IDs, qualified case mode, canonical leaf; unify overlapping exports. |
| Existing public object | Full supported file-ID query with identity kind/length, storage identity and exact live open; expected presence or positively proven absence. |
| Execution authority | Original local effective subject/logon context **and** checked SMB authentication context/principal, provider, live remote object/grants/sharing, connection generation, operation nonce and one-use permit. |
| Private content | Local NTFS stage volume/full ID, transfer, generation, stable length/digest, seed provenance and current-policy inspection receipt. |

`FILE_ID_INFO` combines a volume serial and 128-bit file identifier to distinguish files on one computer. [M19]
That pair is not globally unique across servers, clones, restores or export reconfiguration.
The SMB2 wire `SMB2_FILEID` identifies an **open**: its persistent and volatile halves have reconnect semantics. [M20]
It must not be stuffed into `FILE_ID_128`, used as a permanent file ID or treated as proof that a reboot ended the open.
ServerGuid is server-generated protocol identity, not by itself a trusted storage incarnation or immutable share identifier. [M21]
Tree/session IDs and drive letters are connection/locator data, not durable head keys.

No cited API establishes a universally stable SMB server+share+backing-volume identity across arbitrary servers and reboots.
**Unverified N03/N07:** determine what the approved server exposes through supported handle queries and administrative enrollment,
and whether original remote objects can be matched after reconnect without collision, synthetic IDs or stale cached observations.
Enrollment must authenticate the server principal, bind export root/store identity and detect share retarget/restore/clone changes.
A marker file, matching digest, ServerGuid or matching root numeric ID alone is insufficient evidence of this binding.
Do not depend on reading private RDBSS structures to obtain missing identity fields.
If supported interfaces cannot establish the required incarnation, a server companion is a separate owner choice (D8), not assumed.

At reconnect, compare the full authenticated route and remote object evidence before resuming any operation.
A server reboot is not an identity refresh authorization. A recreated share, changed root, clone/rollback, ID reuse or unprovable
incarnation quarantines its old heads and versions; a newly enrolled destination cannot inherit their permits or replay their saves.
Credential sessions stay separate for authority while aliases to the same physical parent/name serialize through one head.
Two different authenticated users therefore share generation ordering without sharing grants or private views.
This client head does not serialize another endpoint's independent head: cross-client mutation exclusion remains §7's requirement.

Preserve T5 `maxAllocated`, latest Published, committed-delete floor, unresolved intents, alias conflict checks and receipt retention
(`driver/T5-DELETES.md:258`, `:323`; `driver/T5-BOUND-PUBLICATION.md:229`).
Add an explicit destination-kind/schema discriminator; never fabricate a Mount Manager GUID for MUP or reinterpret V23/V26 records.
Old agents must refuse unknown network records/capabilities; normal builds omit the new transport.
Missing network identity in a legacy manifest means held/unqualified, not a pathname migration or successful empty recovery.
Compaction must retain network incarnation/alias barriers, security/seed provenance and unresolved remote operation/cleanup receipts.

## 6. Caller authority, remote security and seeding

LocalSystem normally presents the machine account on a domain-member machine; that account's rights differ from the writer's. [M22]
A successful SYSTEM share open, machine-account membership or service-held administrative credential grants no caller authority.
Capture the original CREATE's effective security subject, including thread impersonation, restricted state, logon authentication ID,
rights, shares, disposition and options before queueing; preserve the captured token by reference, not PID/SID reconstruction.
This follows `driver/T5-NATIVE-PUBLIC-OPENS.md:456`, `:516`; current capture is not proof of SMB authentication equivalence.

Publish with that exact original local subject and verified original remote authority, with scoped restoration of worker identity.
Explicit network-connection credentials can select a different remote account from the local token's default account. [M31]
Thus impersonation alone is insufficient: bind the original checked SMB authentication context/principal and prove that each
publication handle uses equivalent authority, including qualified reconnect continuity. Numeric SessionId equality is not required,
but same local SID/token or same remote account name alone is not proof. Never require remote principal = local UserSid.
The supported production mechanism for obtaining and preserving this binding is **unverified N04**; missing proof holds the save.
Never allow an asynchronous continuation to perform remote I/O accidentally as SYSTEM; keep token/operation ownership explicit.
Use native server checks for share plus filesystem rights, traversal, create/overwrite/supersede, DELETE/parent delete-child and sharing.
Native CREATE dispositions and sharing are distinct constraints; preserving write permission does not imply replacement authority. [M23]
Capture the actual accepted handle's rights and keep the original-share reservation for its required lifetime, without broadening it.
Separate temporary/internal grants from the app grant and verify native errors; no backup/restore privilege or share-bypass fallback.
Native write/append access to an existing object does not imply permission to create/delete a sibling or replace that object. [M23]
The proposed upload/rename path needs those internal operations, so N04 must prove an authority-preserving mechanism separately.
Do not label an extra-rights refusal a native access denial or silently narrow the supported edit contract to make publication work.
If no mechanism preserves original native grants, keep that route disabled pending D13; a SYSTEM-created replacement is not a fix.

Impersonation levels constrain local versus remote use; identification tokens cannot perform impersonated operations. [M24]
Do not assume that changing a token's impersonation level supplies outbound credentials or delegation.
Interactive first-hop credentials, network-logon impersonation/double-hop, explicit Kerberos connection credentials and restricted
users need separate N04 controls; change connection credentials while queued and compare same-SID/different-logon sessions.
Record the actual server-authenticated account and granted access; do not infer them from the client's token dump.
Recommend Kerberos mutual authentication and signing; do not weaken SPN/delegation/domain configuration to make a control pass.
IP-literal names normally fall back from Kerberos unless explicitly configured, so IP aliases are not automatically admitted. [M25]
NTLM/workgroup support, if chosen, needs its own server-identity and credential-binding contract; no guest/anonymous fallback.
Logoff, expired/revoked credentials, token loss or changed authentication context holds publication. Same SID is not recovered authority.
Persist provenance and nonsecret identifiers only; no tokens/passwords/tickets in journals. Reauthentication is a fresh checked action,
not permission to replay an already forwarded mutation or silently assign another user's pending version.

Remote temporary creation must reproduce the approved native metadata result for the requested operation and exact target:
owner/group, DACL/SACL/label, ACE ordering, inheritance/control, attributes, times and supported streams/EAs.
New files, overwrite and supersede need differential server controls; a new sibling's inherited ACL is not necessarily overwrite ACL.
Do not apply the private stage ACL to the public file or repair a mismatch under elevated service/server rights.
`driver/T5-NATIVE-PUBLIC-OPENS.md:698` already records unresolved local descriptor counterexamples; SMB does not settle them.
N05 must prove which metadata is representable and queryable under the qualified server. Missing evidence blocks that route.
If native server behavior lacks required labels/metadata, obtain a precise T8/T22 contract choice (D10), rather than dropping fields.

**Seeding is a separate blocking problem.** Whole-file inspection of a partial edit needs a coherent copy of the old remote bytes.
SMB READ requires `FILE_READ_DATA` on the server open. Local KernelMode does not override that check. [M26]
The NTFS proposal to seed via the original write-only FILE_OBJECT is therefore not automatically a usable SMB mechanism
(`driver/T5-NATIVE-PUBLIC-OPENS.md:609`). Adding READ_DATA can change admission and sharing, even for a read-authorized user.
N04 tests a distinct read lease under the original subject against share-zero, byte locks, lease breaks and concurrent remote writers.
Hold a proved coherence boundary over the entire copy/EOF; equal IDs, timestamps or before/after digests alone do not create one.
A remote writer changing the source in place must not produce an inspection-approved torn seed or overwrite conflict silently.

The owner already selected native write-only editing with private retention of unreadable blocked seeds
(`driver/POST-MVP-PLAN.md:49`; `driver/T5-NATIVE-PUBLIC-OPENS.md:638`). Do not silently choose its rejected read-required alternative.
If SMB cannot furnish that private seed without new authority, D9 must decide the remote limitation or a server-side mechanism.
Fresh/truncating content avoids old-byte seeding but still requires original disposition rights and full publication semantics.
Hand-back and justification require affirmative original-source read/export and recipient authority carried through predecessors.
Read-denied or uncertain seeded versions stay service-private with the approved named reason; clean approval never grants export.

## 7. Publication, atomicity and uncertainty

### 7.1 The remote replacement gap

SMB2 SET_INFO carries rename/disposition information. [M33]
Its standard FileRenameInformation replaces by **name** when requested;
the network RootDirectory field is zero and the request has no expected-target-file-ID field. [M27]
Do not copy T5's parent-relative local POSIX rename assumptions into SMB or assume FILE_RENAME_INFORMATION_EX works on every server.
The client's directory handle and local destination turn cannot exclude another SMB client's target/parent replacement.
Post-rename comparison detects an error too late to authorize the object that was actually replaced.

Before permitting replacement, prove a supported server-enforced reservation that covers parent route and exact target from
identity/security validation through rename completion without widening rights or changing required native sharing.
Test finite candidates: retained checked target/ancestor handles with native share reservations, and any documented qualified
server rename behavior; include a rival client and server-local actor at a deterministic pause (N06).
A share-deny-delete handle may prevent our rename too; releasing it before rename creates a gap. Byte locks and breakable leases
are not a compare-and-replace primitive. The candidate fails if it needs an unprotected release/recheck/rename interval.
For an absent target, no-replace rename can reject a racing create, but parent/export binding and outcome recovery still need proof.
No-clobber-only support would exclude ordinary replacement workflows and requires D8; it cannot be called full T22 completion.
If native primitives cannot meet the contract, require an owner-approved server commit component or keep the capability disabled.
Such a component needs its own reviewed caller-authority, server namespace serialization and durable operation-receipt design.
A user-mode server service or lock file alone cannot fence arbitrary SMB clients; it must mediate every conflicting mutation.

### 7.2 Proposed transaction, conditional on those gates

1. Bind route/object/subject and allocate under the shared head; persist private allocation before app-visible success.
   Preserve native absent/existing/disposition outcomes without truncating the real public object as a permission probe.
2. Drain all owned writers/mappings and local paging I/O; seal exact local stage, EOF and content under T4 lifetime rules.
   Inspect the complete immutable snapshot under current policy; unsupported, timeout or incomplete extraction cannot approve.
3. Before the **first remote content write**, validate current policy, generation/delete floor, approved destination and original
   caller authority, then persist a unique publication-attempt/create intent and issue an exact approved-only create permit.
   Create a unique remote sibling with collision refusal and qualified security/share semantics; record its actual object identity.
4. Copy only the inspected snapshot using explicit-offset bounded ordinary writes, never CopyFile's implicit offload route.
   Bind every write/EOF operation to this temporary, attempt, subject and content; capture partial completion and actual status.
   No caller-mutable buffers, stage rewrites, mappings or writes via duplicate handles may enter the remote temporary.
5. Fence temporary data irreversibly, drain admitted writes, verify actual EOF/identity, and finish the qualified lower flush.
   SMB FLUSH requests persistence of cached file information; it is not a journal/rename transaction or power-loss proof. [M28]
   A flush error, unknown partial write or inability to fence keeps the final name unchanged and the attempt noncommittable.
6. Enter the T5 physical commit turn; revalidate current policy, head, exact public identity/absence and the remote reservation.
   Persist exact rename intent, consume a one-use permit, then forward **one** original remote rename on the checked temporary.
   Keep all names/parents/incarnation and expected identities bound through the qualified server mutation boundary.
7. Record actual native success and exact Published receipt in the shared head before Released and releasing the commit turn.
   Fence remains permanent after rename; outstanding temporary handles cannot modify the now-public object.
   Failed final manifest recording retries that recording only (`driver/POST-MVP-PLAN.md:121`).
8. Retire local stage, remote temporary residue and native records only through exact receipts/acknowledgements.
   Preserve generation floors and uncertainty across service crash, client restart and server restart; no path-based scavenging.

The remote temporary needs **server-enforced exclusive mutation ownership from CREATE through rename**, independently of the
local data fence. Test other clients and server-local standard users attempting data/EOF, delete, rename, link, security and offload
changes, cached/mapped writes and handle replay. Native share exclusion is a candidate, not proof that every mutator is excluded. [M32]
N06 pauses during copy, after fence/flush and on reconnect. No digest recheck can replace uninterrupted exclusion through commit.
Lost or unprovable exclusion permanently bars that attempt: retain exact residue, reconcile old I/O and cleanup, then create a fresh
attempt only when those obligations permit it. Restoring connectivity or reopening the same pathname cannot renew ownership.

Approval is needed at the first outbound data write, not just final rename: remote temporary bytes are already destination bytes.
Policy/generation change during upload fences additional writes and forbids commit; cancel/drain existing I/O, then reconcile residue.
Bytes sent under a valid prior approval cannot be recalled from backup. A policy update must order against in-flight egress permits;
it cannot be acknowledged as fully effective while old-permit writes can still be newly admitted.
If product policy instead requires retroactive removal of previously approved destination bytes, that is a new owner decision.
A remote temporary contains approved data but is not user-visible save completion; ACL/share denial is defense in depth.
Partial publication preparation never truncates the final target, and empty publication uses the same transaction with zero data writes.

### 7.3 Failures, retries and recovery proof

SMB durable reconnect can retain an open; persistent handles support stronger failover behavior. [M18][M20]
The redirector can replay protocol requests when connections fail. [M29]
Its internal replay is part of one native operation; SafeUpload must not issue another CREATE/rename/disposition after an ambiguous result.
Service timeout/cancellation, TCP disconnect, local CLOSE or a new session does not prove that the server did nothing.
Do not promise exactly-once remote mutation from a local journal alone.

| Known state | Action and visible outcome |
|---|---|
| No remote mutation forwarded | May resume local preparation after current policy/authority checks; allocate a new attempt only when prior no-forward is affirmative. |
| Approved temporary partly copied; definitely no rename sent | Hold final name unchanged; resume only a proven unwritten range on the same still-writable bound attempt, or clean that exact temporary and begin a fresh attempt. Never reopen a data fence or blindly rewrite after an unknown write. |
| Native rename success retained; journal failed | Record existing success/Published once. “Saved to the share; finishing recovery bookkeeping.” Never re-upload or rename again. |
| Rename may have reached server; response lost | Retain PendingCommit and name hold. “Save result on \\server\share\file is unconfirmed; newer saves remain private. Reconnect to verify.” |
| Authentication lost / server unavailable before publication | Keep private stage charged; reject new uncheckable remote opens. “File is kept on this PC; the share is unavailable. Reconnect and sign in.” |
| Changed server/share/object identity | No rebind/replay. “The share or file changed; this version remains private. Contact your administrator with diagnostic ID ….” |
| Remote cleanup uncertain | Keep exact cleanup obligation and storage charge; no wildcard delete or deletion of a same-name replacement. |

Recovery collects the durable intent, original operation's actual completion facts, a qualified remote lifetime/reservation proof,
and fresh authenticated server/object/name evidence under the reconciliation turn.
Known completed mutation → finish bookkeeping; affirmative never-forwarded/definitive native refusal → release only that attempt;
otherwise hold until those facts can distinguish outcomes. Matching content or the final path's absence alone cannot decide.
Service restart may read facts but cannot recreate lost user credentials or issue mutations under the machine account.
Reconnect wakeups trigger bounded work; retries use monotonic deadlines and release worker slots/global locks while waiting.
Do not introduce a timer that clears Unknown or treats a guessed durable timeout as server-side handle death.

For a lost scheduled-delete/rename result, exact remote open retirement may require an authenticated close/reconnect result or
a server-side operation receipt. A simple observer used by the lab is not a trusted production receipt mechanism.
N07 must identify a supported production proof; if none survives the chosen failures, uncertainty remains held and D7/D8 applies.
A Windows client Restart cannot extinguish arbitrary server durable/persistent state by assertion.
The fixed-NTFS forced-teardown exception is local-only (`driver/POST-MVP-PLAN.md:88`); it does not authorize SMB recovery-by-reboot.
The USB remount requirement is likewise not an SMB lifetime proof. Sticky Unknown still clears only under its existing reboot rule;
even after that reboot, an unresolved remote operation retains its separate destination hold.

## 8. Deletes, lifetime and integration with T4/T5

Publication, public delete, ordinary disposition clear, scheduled delete and private cancellation use the same tagged destination head.
Only a durably Published successor suppresses an older delete; allocated, approved, uploading or blocked saves do not
(`driver/T5-DELETES.md:223`; `driver/T5-NATIVE-PUBLIC-OPENS.md:123`).
Remote non-writing delete opens preserve the original native request, caller grant and sharing; combined staged writers retain
a separate checked remote delete capability. Neither gives the application writable public data access.
Pass supported native on-close timing rather than emulate it with an unproved extended disposition.
Keep accepted/unresolved results truthful after post-CREATE tracking failure; exact close/startup recovery must be established for SMB.
Do not claim local CLEANUP means physical unlink: server leases, other clients and durable opens may retain relevant state. N07/N09.
Another client's externally changed/deleted/recreated object cannot be labeled this client's Published or deleted using an old grant.
N06/N09 must prove old-handle deletion never removes a replacement and unauthorized clear cannot cancel another object's intent.

T4 local stage retirement remains flush/purge/section/rundown based; remote connectivity does not release a local reference.
Account separately for owned upper objects, backing objects, checked remote opens, pending native callbacks, subjects and RPCs.
No cross-volume lock chain may hold the namespace resource, paging/spin lock or journal global gate while waiting on SMB/service I/O.
Keep FilterPort receive/cancel/reconciliation traffic available during a slow share or a last-close wait.
FltMgr teardown stops new callback coverage; an instance reference does not restore it. [M30]
Voluntary unregister retains existing vetoes for live/unresolved native/private work; mandatory teardown drains local lifetimes
without a remote/service ACK dependency and retains durable uncertainty (`driver/T5-DELETES.md:333`).
No forced context deletion, periodic scan, lower timeout or digest match substitutes for missing lifetime evidence.
A share-specific unreachable hold is distinct from machine-wide writer Unknown; neither may be reported Ready through the other.

## 9. Owner decisions required before dependent implementation

All decisions are **PENDING**. Options describe actual user effects; recommendations do not alter current guards or owner policy.

| ID / choice | Options and what users notice | Risks / concrete recommendation |
|---|---|---|
| D1 — dialect/server | A: one named Windows Server build/NTFS, SMB 3.1.1; other servers receive unsupported notices. B: add SMB 2.1/3.0/3.0.2 or named Samba builds now. | B multiplies identity/security/rename contracts. **Recommend A**, record exact build/configuration; add each Samba/dialect profile only after its own evidence. |
| D2 — DFS | A: refuse DFS protected routes. B: support an enrolled set of referral targets with automatic target-change reconciliation. | B can cross servers/replicas with different content. **Recommend A initially**; show the unsupported route, never silently protect only one referral. |
| D3 — Offline Files | A: require CSC disabled for enrolled scopes and refuse detected transitions. B: build CSC-aware ownership and replay control. | B risks delayed upload of rejected bytes. **Recommend A**, with verified detection; users cannot use Windows Work Offline for those scopes. |
| D4 — UNC/mappings/aliases | A: direct enrolled UNC plus caller-session mappings that resolve to it. B: UNC syntax only. C: arbitrary aliases/providers. | B surprises Explorer users and does not eliminate alias bypass. **Recommend A**, refuse unresolved remaps/aliases; prove equivalence, do not trust the drive letter. |
| D5 — stage location | A: private local fixed NTFS. B: remote hidden/ACL-only stage. | A consumes PC disk and uploads after inspection; B already exposes preinspection bytes to server storage. **Recommend A**; B requires changing the invariant and is unsuitable here. |
| D6 — authentication | A: Kerberos mutual authentication plus signing, enrolled server principal. B: also NTLM/workgroup credentials with a separately reviewed identity scheme. | A refuses unsupported IP/SPN/credential routes; B broadens credential/session cases. **Recommend A**; never fix failure by using SYSTEM/machine credentials. |
| D7 — unreachable server | A: deny new uncheckable remote opens; retain already admitted local versions, resume only proven unexecuted work. B: accept offline new saves with deferred authorization. | B can report success without permission/existence proof and needs new conflicts/quotas. **Recommend A**; no automatic discard, no claim that the share contains the save. |
| D8 — remote commit/receipt mechanism | A: client-only, enable only after N03/N06/N07 prove identity, race exclusion and recovery. B: deploy a server commit component with those guarantees. C: owner-limited no-clobber/new-file pilot. | A may be infeasible; B adds server software/operations; C breaks replacement workflows and is not full T22. **Recommend finite A controls first; if they fail, choose B for full support**, keeping SMB off pending that design. |
| D9 — write-only remote seed | A: implement an approved server-private inspection/seed capability preserving native rights and no export. B: explicitly exclude edits needing unreadable old bytes from SMB support. | A expands trusted server work and conflicts with a pure endpoint design; B blocks clean appends that native SMB allows. **Recommend A for full parity**, conditional on a separate design; if unacceptable, request explicit B scope approval. Existing option 1 is not revoked. |
| D10 — metadata fidelity | A: retain native-equivalent owner/ACL/SACL/label and agreed T8 fields for each supported operation. B: accept enumerated server-specific differences. | B may alter who can read/write and app behavior. **Recommend A**; decide B only from N05's exact mismatches, never “best effort ACL.” |
| D11 — failover / transport extras | A: ordinary durable reconnect only; reject CA/persistent/DFS, RDMA and unqualified multichannel configurations. B: qualify cluster/transport combinations now. | B needs more endpoints and longer-lived authority proofs. **Recommend A**; loss of connectivity can delay saving but cannot weaken holds. |
| D12 — retention / budgets | A: carry T9 per-user/total charging into pending remote saves and exact remote cleanup. B: set separate offline retention/eviction defaults. | B can discard unsent work or hide storage exhaustion. **Recommend A**, measure first; propose numeric defaults separately before removing caps. |
| D13 — native edit lacks sibling/replace grants | A: prove an internal commit mechanism that preserves the caller's exact native write/append authority without granting extra app rights. B: explicitly exclude these remote edits. | A may require D8's server component; B rejects edits native SMB permits. **Recommend A for full parity**; if infeasible, obtain explicit B approval and disclose the limitation, separately from unreadable seeding. |

D7's indefinite **uncertain mutation** hold is the existing no-replay safety rule, not automatic recovery proved by this design.
If users require automatic resolution after every supported outage, D8 must supply durable server evidence; do not substitute a
manual journal-unlock button. Diagnostics can guide reconnection, credential restoration and evidence collection without granting access.

## 10. Finite native controls — all UNVERIFIED

Run only after explicit lab/run authorization. Each control has a finite set of cases and a recorded native reference;
failure stops the dependent feature, not an open-ended search through flags. Builder observations are mechanism evidence only.

| Control | Experiment and decisive result |
|---|---|
| N01 — stack/provider visibility | On 19045.2965, one direct UNC, mapped alias, DFS fixture, CSC fixture and non-SMB provider: enumerate instances/modules; trace CREATE/data/metadata/FSCTL/cancel to server operations. Identify exact safe provider/protocol-query points. Missing or double-accounted coverage fails. |
| N02 — owned remote upper | Cached/noncached/asynchronous writes, Fast I/O/MDL fallback, both mapping repros, duplicate/inherited handles, read/image sections, EOF/flush and last cleanup; with leases granted/denied/broken. Server sees no unapproved bytes; all local references and data paths are accounted. |
| N03 — names/identity | UNC, extended UNC, mapped/remapped letter, FQDN/short/CNAME/IP, case/short-name, overlapping exports, hard link, ancestor reparse, share retarget and same-ID clone/restore. Equivalent objects share a head; different incarnations never inherit one. Record all identity-query status/lengths and server-local IDs. |
| N04 — original authority/seed | Pair native/candidate opens for ordinary, impersonated, restricted, read-denied/write-only, read-authorized/write-request-only, DELETE_CHILD-only and machine-only grants; append/overwrite without sibling-create/delete rights; share 0/7 and concurrent seed/range-lock cases. Include first/double-hop, distinct explicit Kerberos credentials, credential change while queued and same-SID/different-logon sessions. Compare actual SMB authority, exact grants/status/sharing and coherent seed; no privileged rescue. |
| N05 — metadata | New/overwrite/supersede under inherited/protected/empty/NULL DACLs, explicit owner/group, SACL/label where supported, supplied descriptors, attributes/times/ADS/EAs and security changes while queued. Compare native versus candidate binary results, including control bits; enumerate unsupported differences. |
| N06 — commit race/atomicity | Existing/absent targets: pause after final check, then rival client/server-local actor replaces target, parent or export. Also attack the temporary during copy, after fence/flush and reconnect with write/EOF/delete/rename/link/security/offload, cached/mapped and durable-handle mutations. Exercise the finite reservation candidates and native rename variants; require exclusive temporary mutation, exact-target authorization and old-or-new complete final bytes. Any gap fails. |
| N07 — disconnect/replay | Inject loss before send, after server acceptance before reply, after reply before journal, and after journal before ACK for CREATE/write/flush/rename/delete. Repeat with TCP loss, service crash, client Restart and server restart; distinguish actual durable reconnect from fresh open. Require no duplicate public mutation and exact recovery/held uncertainty. |
| N08 — CSC/DFS/failover refusal | Online→offline→online, cached dirty preactivation data, referral swap and attempted CA/persistent connection. Prove unsupported paths stay nonadmitted and cannot later flush forbidden data through replay. If those features are approved, replace refusal rows with complete privacy/recovery rows, not skips. |
| N09 — deletes/lifetime | Ordinary TRUE/FALSE, scheduled on-close, duplicate handles, another client's reader, newer blocked versus Published successor, instance teardown and service-absent shutdown. Prove native result/timing, separate local/server lifetime and automatic resolution wherever promised. |
| N10 — offload bypass | COPYCHUNK and COPYCHUNK_WRITE, ODX read/write and clone/extent attempts from sensitive remote sources into protected names, including direct native FSCTL callers. Require refusal before server mutation; ordinary inspected copy fallback may then succeed separately. |
| N11 — observers | Deliberate forbidden-marker writes in a sacrificial unprotected fixture, including short-lived temporary, ADS, write then delete and snapshot. Each observer must detect its claimed surface; sequence gaps/lost events invalidate continuous proof. |
| N12 — resource/UX | Server and local disk full, quota boundary, low memory, bounded parallel transfers, stale policy, credential expiry, interrupted hand-back and prolonged outage. Require charged retained state, complete-or-refuse inspection and accurate per-user notices, without unbounded worker growth. |

Native correctness is a prerequisite, not destination qualification. Record OS/server build, dialect, provider, auth, lease/cache
configuration, exact inputs/results, source commit and artifact hashes. Do not infer behavior on Samba from Windows Server controls.

## 11. Qualification lab, byte observation and restoration

**No additional lab infrastructure is assumed to exist.** Obtain owner approval for a separate SMB server VM and its exact baseline,
isolated test share/data disk, second independent SMB client, and any AD/DNS/Kerberos test realm required by D6.
Server choice may be Windows Server or Samba; record server build, backing filesystem and configuration as qualification inputs.
Recommend Windows Server/NTFS first to permit server-local raw-volume evidence plus native ACL comparisons.
A later Samba target needs its own observer/backend/metadata controls; Microsoft's protocol documents are not Samba qualification.
Approve capacity, addresses, credentials, fault-injection topology and server snapshot/backup fixtures before creating them.
Do not install a domain controller, modify host routing/firewall/libvirt/polkit or alter the qualified client baseline under this note.

The protected client remains **win10-debug3 only**, `SAFEUPLOAD_DEBUGGEE=win10-debug3`; keep win10-debug2 off.
Builder 19045.6466 is separate from target 19045.2965 (`driver/POST-MVP-PLAN.md:104`, `:132`).
No loopback share, host-mounted directory or mocked transport substitutes for the real SMB server.
The second client runs ordinary SMB readers/racing actors without trusting the protected client's service or cache.
Each server-side observer executes independently of the publishing service and writes evidence outside the observed share.

Use three complementary observations, retaining their distinct proof limits:

1. Server-local raw/uncached volume reads and final disk image detect forbidden markers in destination objects, temporaries, ADS
   and relevant deleted allocation/snapshot state; map offsets to objects and retain capture coverage. Sampling can miss transients.
2. An independently validated server filesystem mutation observer records actual data/namespace operations, object IDs, ranges,
   results and sequence continuity, including cache/paging/offload paths; pair it with bytes or independent payload capture.
   SMB/server ETW can correlate acceptance, sessions and loss but must not be assumed to contain every payload byte.
3. A second SMB client polls old/new final-name bytes and known temporary names with fresh opens; test server-local snapshot/backup
   reads during BLOCK and publication. Client caching cannot be the sole privacy oracle. [M08][M16]

N11 proves observer sensitivity before product rows. **ForbiddenByteCount=0** with complete continuous mutation coverage is required;
missing payload coverage, dropped events or observer downtime is incomplete evidence, never a PASS.
For approved replacement, independently record complete old/new versions and prove no torn final image; for BLOCK, search the whole
test share surface for its unique forbidden markers, not only the final pathname. Distinguish prior authorized fixture bytes.
Synchronize fault windows on authenticated operation receipts and observer events, not wall-clock sleeps.

| Qualification family | Required rows on the final matched pair |
|---|---|
| Core data / apps | Empty/clean/CPF create, replace, append, clear-save, Notepad and required T8 workflows; blocked hand-back with read-authorized and unreadable seed cases. |
| Mapping / names | Both memory-mapping repros, sections past cleanup, UNC/mapped-drive equivalence, remap while queued, aliases/case/overlapping shares and qualified prefix boundaries. |
| Permissions / metadata | N04/N05 successful and denied controls under protection; machine account granted while caller denied; share and filesystem denial independently. |
| Commit / delete | Both forced publication/delete orders, remote competing writer/parent swap, scheduled delete and only-Published suppression, flush/fence and post-rename write refusal. |
| Recovery | Every N07 durable boundary, ordinary reconnect, changed share identity, partial copy, service restart, client/server crash, exact cleanup/ACK and named uncertainty holds. |
| Unsupported / activation | CSC/DFS/CA/provider/dialect/offload refusal; pre-scope cached writers, startup before edits, policy activation/change, service absent, old/new protocol pairs. |
| Stress / coexistence | Approved T4 occupancy/context gates, multi-user outage storage pressure, server quotas, AV/indexer/backup/VSS and required M4 coexistence; no threshold relaxation. |

Run required families in ordinary, runtime-Verifier and boot-Verifier modes on committed matched driver/agent artifacts.
All four normal/feature × Debug/Release WDK builds, PREfast/ApiValidator and agent matrix remain required at 0 warnings/errors.
Harness changes first pass Windows PowerShell **5.1** parse/native-signature checks and relevant offline self-checks.
Any server kernel observer/component also needs its applicable static/lifetime/Verifier checks before its authorized boot.
No skipped required tests, relaxed assertions or diagnostic subset may stand in for the gate (`driver/POST-MVP-PLAN.md:140`).

Run BLOCK windows and mutable builder/target jobs serially, using monotonic deadlines. Stop at required failures, changed baseline
or repeated identical failures; retain the first receipt and identify a hypothesis before proposing a rerun.
Use existing disposable qcow2 overlays, reset EFI variables at each start, no TPM, test signing and Secure Boot off for the client.
Approve a corresponding disposable server/second-client baseline and restore each involved machine separately from the product verdict.
Verify run-disk deletion, untouched base and unchanged XML independently; retain original base/XML and raw evidence before cleanup
(`driver/POST-MVP-PLAN.md:96`; `driver/evidence/README.md:3`). No production share is a test fixture.
Track a concise cited result with commit/artifact hashes, coverage and separate product/restoration verdicts; no new freeze framework.

## 12. Implementation increments and review exits

1. **T22 decisions/design:** record D1–D13 outcomes, resolve contradictions with T5/T8, obtain independent Sol 6.1 xhigh review.
   Keep all capability gates closed. An accepted proposal with mechanism conditions is not an implementation/activation verdict.
2. **T22 native feasibility:** after lab authorization, implement only finite diagnostic controls N01–N11 in their approved scope.
   Settle identity, synthetic upper, authority/seed, metadata, replacement and lost-result recovery before a product backend.
   If N03/N06/N07 require a server component, return that concrete design/owner choice for security review; do not widen client trust.
3. **T22 protocol/head:** introduce negotiated tagged network identity and immutable attempt facts; extend existing allocation,
   head/permit/recovery/compaction with bounded accounting and negative controls. Local fixed-NTFS behavior remains regression-gated.
4. **T22 integrated backend:** connect original-subject checks, local stage, current-policy approved-only transfer, one-use commit,
   native deletes, exact recovery and cleanup together; admission remains off until all selected profile prerequisites hold.
   Obtain one coherent Sol 6.1 xhigh kernel lifetime/lock-order/retirement review before its first authorized changed-driver boot.
5. **T22 destination qualification:** run §11 against the final pair and approved server; complete failures/uncertainties explicitly.
   A first passing save, transport exit or server/client hash match is not completion.
6. **T22 delivery → M4:** independent adversarial review of the working milestone pair and server contract; retain separate review,
   component-test, destination-runtime and restoration results. Carry the approved scope into combined M4, then request cutover
   only through the existing owner process. Taint and normal-build staging exclusion stay in force throughout.

## Microsoft reference index

References support the specific Windows/protocol behavior cited above; proposed SafeUpload mechanisms remain subject to controls.
Pages were consulted 2026-10-13. No documentation statement here is claimed as a 19045.2965 native run result.

[M01]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/mup-changes-in-microsoft-windows-vista
[M02]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/the-redirected-drive-buffering-subsystem
[M03]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_setup_callback
[M04]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlmupgetproviderinfofromfileobject
[M05]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_remote_protocol_info
[M06]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_pre_operation_callback
[M07]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a64e55aa-1152-48e4-8206-edd96444e7f7
[M08]: https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-feature-descriptions
[M09]: https://learn.microsoft.com/en-us/windows-server/storage/folder-redirection/enable-always-offline
[M10]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_io_parameter_block
[M11]: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
[M12]: https://learn.microsoft.com/en-us/windows/win32/services/services-and-redirected-drives
[M13]: https://learn.microsoft.com/en-us/windows-server/storage/dfs-namespaces/dfs-overview
[M14]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/cd0162e4-7650-4293-8a2a-d696923203ef
[M15]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/offloaded-data-transfers
[M16]: https://learn.microsoft.com/en-us/windows/win32/vss/overview-of-processing-a-backup-under-vss
[M17]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetfilenameinformation
[M18]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3309c3d1-3daf-4448-9faa-81d2d6aa3315
[M19]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info
[M20]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f1d9b40d-e335-45fc-9d0b-199a31ede4c3
[M21]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a1df6781-a507-48a7-bcdb-be9ef0c09c97
[M22]: https://learn.microsoft.com/en-us/windows/win32/ad/the-localsystem-account
[M23]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile
[M24]: https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels
[M25]: https://learn.microsoft.com/en-us/windows-server/security/kerberos/configuring-kerberos-over-ip
[M26]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/21e8b343-34e9-4fca-8d93-03dd2d3e961e
[M27]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52aa0b70-8094-4971-862d-79793f41e6a8
[M28]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e494678b-b1fc-44a0-b86e-8195acf74ad7
[M29]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ae543f57-d993-4905-bce0-3cfc446c1fbb
[M30]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_teardown_callback
[M31]: https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w
[M32]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
[M33]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4
