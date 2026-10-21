# T8 metadata round 2 — blocked prerequisite checkpoint

2026-10-16, `ux/meta2`, base `demo/apps` **2ed2b20b**. This branch does **not**
finish the owner's T8 contract. It must not be merged or described as a native
security, publication-race or browser-download fix. The original scope and
owner decisions remain in [POST-MVP-PLAN.md](../../../POST-MVP-PLAN.md#owner-decisions)
and [UX-METADATA.md](UX-METADATA.md). The evening priority is successful real
user workflows; a fail-closed refusal does not count as browser success.

## Delivered changes

- T8: allocation/publication observations use a native no-follow open. Only
  `ERROR_FILE_NOT_FOUND` proves a missing leaf. A missing parent, access denial,
  sharing failure or malformed/unsupported object remains an error. This fixes
  `File.Exists` treating a failed observation as an absent destination; it does
  not pin the object or close the subsequent race window.
- T8: the existing kernel O/G/DACL query requires an exact successful native
  `FILE_OPENED`, a 20–65,536-byte allocation and a complete structurally valid
  returned descriptor. Optional absent/NULL/empty ACLs remain distinct and valid;
  validation does not demand their presence. All six security entry points and
  the local query repeat PASSIVE SAL on declarations/definitions and retain
  `PAGED_CODE`/PAGE placement. Existing assignment and grants are unchanged.
- T8: `StagedPublicationSecurity` compares canonical binary descriptors without
  erasing owner/group, SACL, label, DACL, ordered opaque ACEs, RM or control bits.
  Its optional exception requires separate moved-file-save proof and accepts
  only expected `0x0400` set → actual clear. It is a dormant comparator, not a
  constructor, proof producer, capability or live publication gate.
- T8: `StagedMotwSnapshot` bounds capture before allocation, requires exact length
  plus EOF, keeps immutable bytes/read leases and inspects every field through
  the ordinary strict `.txt` inspector. Invalid UTF-8/16/32 blocks. Unknown
  fields, HostUrl and ReferrerUrl are scanned too. Out-of-scope or unmonitored
  text results throw instead of supplying approval. Its 64-KiB bound is a
  dormant capture guard, not an approved new product resource default. It is
  not connected to stream admission, sealing, publication or hand-back.

No existing test was modified, weakened or removed. No kernel import, timer,
worker, wait, lock edge, activation, capability or readiness change was added.
The unbound publisher still has the original native-security/race defects;
`Zone.Identifier` is still refused with `metadata_zone_transaction_unavailable`.
Other ADS, EAs and unsupported storage retain their existing refusal paths.

## Why the requested browser guarantee is still blocked

At main-stream cleanup these histories are identical:

1. A clean ordinary file has no MOTW and will never receive it.
2. A clean download has no MOTW yet; its producer writes it later, after any
   chosen delay or final rename.

No finite file-operation observation distinguishes them. Publishing case 1 now
also publishes case 2 without its MOTW. Waiting on absence forever breaks the
ordinary clean-save workflow. A timer, process-name list, first ADS close,
synthetic ZoneId or rename heuristic does not establish the requested guarantee.
Microsoft's [IAttachmentExecute::Save contract](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iattachmentexecute-save)
explicitly permits attachment processing after the local file is copied and
permits it to modify the file/add ADS evidence.

The owner was asked whether to add an explicit whole-version completion
contract with a real producer, holding affected versions until it arrives.
No answer or product-contract change is assumed. Even approving that API would
not make existing browsers supply its witness. A browser/OS integration and its
qualification are still necessary for successful downloads.

## Remaining implementation

- T8: natively create a new publication object in the anchored destination
  parent under the **original captured effective subject** and original security
  inputs; reproduce creator grants and query its actual full stored descriptor.
  PID/SID/process-token lookup and SYSTEM defaults cannot replace that subject.
  For replacement, preserve the exact current existing descriptor. The current
  legacy query is intentionally O/G/DACL only; it is not SACL/label evidence.
- T8: add one connection/attempt/object-bound admission fence. Admit only the
  exact publication CREATE object and permitted phases; capture identities,
  full SD/basic/stream/EA/link/storage state while all competing admitted public
  mutations have actually drained. No lock spans native I/O. Account for old
  handles, ancestors, by-ID opens, EA/FSCTL changes, pending attachment/native
  disposition owners, writes, mapped/paging writes and delayed cleanup metadata.
  A blanket authenticated-service exemption still permits a concurrent worker
  to change the old target/parent. Expiry, disconnect or draining cannot silently
  erase uncertain ownership. A final inventory followed by a separate rename
  is not a fence.
- T8: bind a bounded whole-version stream manifest and actual completion witness
  to exact stage identity, transfer, generation and policy. Inspect the base and
  MOTW snapshots under the current policy; a `.docx`-only policy must not imply
  approval for uninspected text. Materialize both streams on the same exact held
  output before its single atomic base rename. Later writes create successor
  versions. Keep unfinished bookkeeping separate from accepted public mutation.

The independent **Sol 6.1 xhigh** design review returned **REVISE for full T8**.
The corrected prerequisite diff received **ACCEPT for the partial bundle**,
without qualification. Review caught an attempted live all-parts query/SACL
inheritance change without its needed observer rights and absent-SACL native
controls; that attempt was removed. Review also required exact `FILE_OPENED`
checking and the `.docx`-only policy refusal control, both now included.

## Exact Windows handoff

Claude runs the VM; this task contacted no VM or builder. Use **win10-debug3,
19045.2965, standard user t5actor**, bound capability 0x40 off and readiness false,
matched committed feature driver/agent packages, fresh labels, independent public
and raw-byte observations, and the existing disposable-overlay/restoration rules.
Before a boot: independent kernel lifetime review of the final connected change;
Debug/Release WDK + PREfast + ApiValidator, all 0 warnings/errors, both actual
binary import gates; full Debug/Release × user/SYSTEM agent matrix. Run component
filter `FullyQualifiedName~StagedMetadataRound2|FullyQualifiedName~StagedFileMetadata`
plus existing allocation, publisher, journal, rename, seed, notification and
cleanup controls. Native tests have no platform skip.

The following rows are **requirements for the completed implementation**, not
passing claims for this partial branch. Run each in ordinary, runtime-Verifier
and boot-Verifier modes, serially, against a same-caller native reference.
Keep the first failure and restore/verify the baseline separately.

| Row | Exact operations and required evidence |
|---|---|
| T8-R2-01 browser MOTW | Edge download clean TXT/DOCX into an absent name and an occupied name. Record partial-name rename, base close and every Zone.Identifier open/write/close. Delay the attachment write past main cleanup and final rename. Independent observers must never see the new base without its exact inspected MOTW; Office reopen retains Protected View. Repeat interruption before/after witness, stream copy and native rename. **Blocked on missing producer; current refusal is not a pass.** |
| T8-R2-02 MOTW content/refusal | Repeat with known policy-blocked CPF in base, HostUrl, ReferrerUrl and an unknown text field; valid UTF-8/16/32 BOMs, invalid encodings, exact capture boundary and one byte over, truncated/growing stream, `.docx`-only policy, policy change and lost service connection. No partial/unsupported/out-of-scope result authorizes either stream. Old destination remains intact; clear owner-scoped reason/retained state. |
| T8-R2-03 Explorer copy | Copy clean TXT and DOCX with distinct creation/access/write dates, Hidden/Archive/NoIndex/readonly combinations and downloaded-source MOTW. New destination inherits destination-parent ACL/owner/group/SACL/label as native copy does; source ACL is not carried. Compare after every handle closes; MOTW is inspected and present at first base visibility. Repeat replacement and blocked CPF source. |
| T8-R2-04 Word replacement | Seed a published DOCX with an explicit admin ACE, non-default owner, audit SACL, mandatory label and old creation date. Word open/edit/Save/close/reopen, Save As and WRL/WRD backup/temp swap. Final bytes are inspected; original security is preserved under the chosen native replacement contract. Allow only proven moved-save directional 0x0400 difference, with all other binary bytes exact. Repeat denied writer, restricted/impersonating caller, write-only creator grant, clean/CPF and readonly/share conflicts. |
| T8-R2-05 public races | Pause separately at allocation, seal, inspection, before/after fence capture and immediately before rename. Through pre-opened and new handles change target/parent DACL (add/remove admin ACE), owner, SACL/label, dates/bits; replace parent/target or retarget private name. Race a second authenticated service worker too. Require authorized native result or explicit hold, never stale replay. Capture exact full IDs/descriptors/generation and both competing operation completions. |
| T8-R2-06 other ADS/EAs | Write CPF to `file:payload` on new, pending, published and empty-base files; copy files carrying that ADS. Repeat CREATE EAs and post-create SET_EA; directory ADS/EAs. Each unsupported operation is refused with a clear reason; no alternate bytes/public base escape, old destination unchanged. Ordinary Zone.Identifier remains a distinct transaction surface. |
| T8-R2-07 unsupported identities/storage | Existing and newly introduced EFS, offline, reparse file/ancestor, hard-link/by-ID/alias, compressed and sparse source/target/stage/publication parents; include truncating opens without seed and inherited flags. Require supported logical semantics with complete inspection or explicit hold; never silent normalization. Uncertain native lookup/access-denied is not absent. |
| T8-R2-08 faults/recovery | Inject metadata query/allocation/apply, stream capture/copy, rename, journal and exact cleanup failures; disconnect/restart/lose reply at each acceptance boundary; pending/draining callbacks and cleanup-delayed timestamps. No accepted public mutation is replayed. Unknown fence/publication state stays held with actionable diagnostics; no uncommitted readonly/ADS residue stranded. |

Continue the unchanged T8-M01–M11 rows in [UX-METADATA.md](UX-METADATA.md),
including version inheritance, empty files, original grants/sharing and all eight
application workflows. The rows above add round-2 detail; they replace no prior
assertion, required gate or test.

## Local verification

Final counts and delivery identity are recorded below after the local checks.
All raw attempts are retained under `.scratch/verification`, including initial
MSBuild/shim failures, the VSTest socket denial and Linux-only SID API failures.
These are component diagnostics, not Windows discovery, native security parity,
a connected stream-publication test or a qualified protected pair.

- T8: SDK **10.0.400**, feature Debug and Release Tests builds (including
  Service/Core/Minifilter/Network) succeed with warnings as errors, **0 warnings,
  0 errors**. Build output and intermediates stay in `.scratch/artifacts`.
- T8: direct invocation of unchanged actual methods/InlineData: **85 passed,
  0 failed in each configuration** — 35 new portable round-2 cases, 28 existing
  metadata cases and 22 existing rename-wire cases. This is a deliberately named
  diagnostic subset. The one new Windows native case and all existing native
  cases remain unexecuted here. VSTest aborted on denied TCP listener creation.
  An earlier broader direct selection recorded **87 passed / 2 failed** because
  an existing SID fixture calls Windows Principal APIs on Linux; that receipt is
  retained and is not described as a passing broader suite. Initial scratch
  runner argument-conversion errors and an incorrect empty-stream policy fixture
  are also retained; the corrected fixture uses actual nonempty MOTW text.
- T8: all **28 selected Python self-check scripts pass**: four kernel fixture
  scripts, fourteen T5 scripts, four UX scripts, T4 verdict, exact agent/source/
  source-worktree runner, feature defaults and import self-checks. The new
  security suite compiles the actual production query with GCC and Clang,
  `-Wall -Wextra -Werror` and UBSan, and checks min/max/short/invalid/pending/native
  result/allocator failures and balanced cleanup. Its final review-corrected
  rerun also passes. These shims do not model NTFS access checks or native SAL.
- T8: source-call delta **zero new external identifiers**; all **47 inventoried
  Python host-stub declarations** are supported. The borrowed full API audit
  still fails identically on base and changed source at the pre-existing
  `Taint.c:356: InsertHeadList` header-inventory omission. No assertion or header
  exception was weakened to hide it. No newly built `.sys`, import availability,
  WDK/PREfast/ApiValidator or Windows PowerShell pass is claimed. No PowerShell
  harness changed.
- T8: `git diff --check` passes. Original checkout Git is read-only; the delivered
  incremental bundle is constructed in a scratch Git repository, with
  `refs/heads/ux/meta2` as its head and `2ed2b20b` as its prerequisite. It contains
  this prerequisite checkpoint, not a completed or qualified T8 pair.
