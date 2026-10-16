# M2 review conditions — final adversarial checklist

2026-10-16, `ux/t11`, base `demo/apps` `2ed2b20b`. This is a disposition of
review conditions, not M2 acceptance. Checked items below mean **local source
closure only**; all Windows rows are **UNRUN by this task**. A named row makes a
condition executable; it does not make it pass. Record final source commit,
matched package hashes and receipts against each row before checking it off.

The evening owner decision in the main checkout's status plan controls: real
apps as standard user **t5actor**, on the unbound UX pair, plus T4 and T6–T11.
The base's plan predates that paragraph. Parked batch-3/V30 and T6 identity-census
work is listed separately, without claiming its conditions have been satisfied.
This task changes no capability/readiness/activation gate. Historical reports
mention four kernel profiles, normal agent legs, Luna, taint and Paint; current
owner decisions replace those with two feature kernel profiles, four feature
agent legs, Sol 6.1 xhigh, staging protection and image refusal respectively.
Historical reports and failed receipts remain unchanged.

## T11 changes and component closure

- [x] T11-C01 — startup SOP lifetime: the old by-name reopen followed delete-on-close.
  The revised [startup proof](T11-SOP-LIFETIME.md) checks simultaneous opens, then
  closes all explicit file handles/references with exact successful close results,
  retains a writable section alone, and reopens the same full volume/file ID/SOP.
  No old SOP token is dereferenced. Failed close/reopen/identity proof fails trust.
  `scripts/t11/sop-lifetime-selfcheck.py` executes production bodies under GCC and
  Clang/UBSan, including failed shared/original closes and negative mutations.
  Windows lifetime and cleanup remain **T11-S01/S02**, not component closure.
- [x] T11-C02 — changed/recycled SOP registry retirement: retain existing immutable
  witness + natural Ended retirement. New controls execute the actual prune body
  and its nineteen successful/blocked scenarios. Changed address, failed reopen,
  H/W/T=0 or the replacement stream's MM result is never retirement authority.
  Existing bind/detach/counter-violation controls remain unchanged. **T11-S03/S04**.
- [x] T11-C03 — hot live-epoch receipts now have the same retention pin as archive
  receipts. Missing epoch state cannot be recreated over hot or archived driver
  receipts by either reconciliation entry point, including after unlocked recovery.
  Exact drain and the existing authenticated full-Restart exception remain distinct.
  `Hot_current_epoch_receipts_*`, `Missing_epoch_cannot_be_rebootstrapped_*` and all
  `StagedDriverEpochStartupTests` exercise these boundaries. **T11-J01/J03**.
- [x] T11-C04 — unresolved cleanup/receipt obligations stay hot and in compaction:
  StageCleanupStarted, unacknowledged discard and unbound V20 Released without
  StageDeleted are ineligible even with a missing leaf/old timestamp. Legacy
  journal-only release semantics are preserved. `Superseded_hot_receipts_*` covers
  four valid manifest shapes with an overtaking generation. **T11-J01**.
- [x] T11-C05 — retained delete -> exact CREATE_AFTER successor was missing from
  reference closure. Added CreateAfterReservationId alongside parent/delete,
  allocation, seed predecessor and source-binding edges. Queue deduplication
  handles the cycle back to the delete. New disk hot/archive/restart and index
  transitive controls prevent removal of an overtaken successor. **T11-J01**.
- [x] T11-C06 — audited `ux/journal` (`83bceea2`/`2121f24e`) barriers: full-identity
  bound claims remain separate from legacy paths; rename tombstones, every maximum
  tie, cancellation's separate newer generation and external head/receipt owners
  remain roots. Compaction sees hot + archive rows. Existing controls are retained.
  Added registered-segment failed-flush/reflush-before-hot-delete, second-segment
  inventory failures and pre/post-replace cancellation with fresh same-instance
  index use. All fourteen new agent cases pass in Debug and Release. **T11-J02/J04**.
- [ ] T11-C07 — final coherent independent review, Windows component/static gates,
  protected rows and final adversarial pair review are still required. The local
  worker-launched Sol 6.1 xhigh review is advisory under the provenance rule;
  [its report](evidence/2026-10-16/ux-t11/review-sol61.md) is not orchestrator approval.

## T4–T11 open conditions, mapped to exact rows

Each item below remains open until the named receipt exists for the final pair.
Sources are linked here and indexed individually at the end. Old source findings
that later reports resolve are not re-labelled as open code defects; their native
verification conditions carry forward.

| Checklist | Open condition / source | Closure row |
|---|---|---|
| [ ] T4-R01 | [Witness review](evidence/2026-10-15/t5-witness-detach-rereview-sol61.md), [MVP delta](T5-MVP-PAIR-REVIEW-DELTA.md): CAS-winner bind / retirement-only decrement, skipped-allocation retry, detach references outside locks; native CREATE/reclaim contention and spin hold time; direct SwUl allocation/free/byte slope attribution, pre-purge idle endpoint, 64 KiB band. Host O(1) proof is insufficient. | T11-S03/S04; T4-Q01/Q02 |
| [ ] T4-R02 | [allocfault acceptance](evidence/2026-10-16/ux-allocfault/review-sol61.md): exact None/Prepared Abort with dead owner/negative policy, no-op15 and local-drain guards, kind-5 exact deletion/absence ACK, stale channel/tuple refusal, no premature reservation release. | T4-F01 (all §12.1 variants) |
| [ ] T4-R03 | Context ceiling, flat pool, resource/cap, complete success counts, Ready and idle; historical near-pass/failure receipts do not qualify updated pair. | T4-Q01/Q02; unchanged C01–C04/B01/B02/X01 raw cells |
| [ ] T5-R01 | [T5 deletes §8](T5-DELETES.md#8-required-qualification): ordinary empty publication, real Notepad clean/CPF Save As, clear/save zero bytes, Explorer New Text Document then rename and second-process open; empty copy/move. | T5-N01 |
| [ ] T5-R02 | Exact native delete-before-seal and delete-after-independent-publication ordering; both file DELETE and parent DELETE_CHILD denied fixture; newer pending/blocked save cannot cancel prior accepted delete, only published successor can. | T5-N02/N03 |
| [ ] T5-R03 | [UX namespace](T5-UX-NAMESPACE-GAP.md): original same-object/duplicate-handle rename sharing; native non-writing READ/ATTRIBUTES/DELETE opens without private allocation; native rename/disposition legacy/Ex flags, on-close/POSIX/clear, replacement/readonly/image conflicts, occupied target, same-scope cross-parent and unmonitored-to-monitored fallback. | T5-N02/N04; full original D1–D6 list |
| [ ] T5-R04 | Immediate private retarget before/after close/op19/seal/inspection/final rename, multiple retained owners/generations; pending publisher cancellation is durable under one gate; no obsolete inspection or cancelled generation publishes; Word WRL/WRD backup cleanup and placeholder states. | T5-N03/N05 |
| [ ] T5-R05 | [Replay review](evidence/2026-10-14/t5-replay2-review-sol61.md), [pin review](evidence/2026-10-14/t5-pin-review-sol61.md), [Listed review](evidence/2026-10-14/t5-fix7-review-sol61.md): lost op15, op19 and progressed seal-ACK; owner exit/no retry, failed/ambiguous resume, cached permission after parent change, reconnect and late fences. Exact durable ACK recovery cannot repeat public mutation. MVP restart-time holds remain a limitation, not a pass of automatic recovery. | T5-F01/F02; parked P-T5-01 for negotiated V29 recovery |
| [ ] T5-R06 | [Reconcile/rename review](evidence/2026-10-14/t5-rename3-review-sol61.md): paused authentication -> disconnect -> resume -> reconnect, cookie/generation ordering, local progress and idle cancellation; exact 1,192-byte Windows transport. | T5-F02 |
| [ ] T5-R07 | [Timer review](evidence/2026-10-14/t5-timer3-review-sol61.md): no arm for SERVICE, no lost timer wake or timer-only work after idle; monotonic deadlines and cancellation; bounded retry does not bound total filesystem/storage latency. | T5-F02; T4-Q01 |
| [ ] T5-R08 | [Unload contract](T5-VOLUNTARY-UNLOAD.md#deferred-work-and-required-verification): reversible idle/C01 unload with ordinary history, actual stage/native/callback vetoes, Q cleanup/reconnect and post-ACK failure; no loss of resolving route. Mandatory teardown uses no service exchange, joins producers, closes backends/anchors before waits and leaves no work in an unloaded image. | T5-U01/U02 |
| [ ] T5-R09 | [Callback-source contract review](evidence/2026-10-11/luna-t5-v20-r18-callback-unregister-contract-review.md): use its later disposition rather than reasserting R18's superseded NO-GO; source/callback rundown and code-image ordering still need runtime controls. Failed DriverEntry unwind and admission/capture accounting from [preboot review](evidence/2026-10-13/t5-preboot-review-sol61.md) need failure-path evidence. | T5-U02; G01/G02 |
| [ ] T5-R10 | [Native startup/boot/automatic-delete reviews](evidence/2026-10-11/t5-native-startup-epoch-design-review-luna6.md): authenticated exact boot/epoch/replay evidence, owner-bound original native disposition result, last-close receipt, no reset of unknown, wrong file/parent/volume and lost reply held; full Restart is not ordinary service restart. | T5-F01/F02; P-T5-02 |
| [ ] T5-R11 | [Proxy routing](T5-PUBLIC-PROXY-ROUTING.md#required-verification): >16 MiB reads, original length/ID/name/streams/security/volume, implicit positioning/All, bidirectional byte locks/cancel, duplicate owner changes, read/image sections surviving cleanup; deny writable sections/paging mutators. Unbound native route still needs real-app native controls; dormant proxy activation is parked. | T7-A01; P-T5-02 |
| [ ] T6-R01 | [ux-dirs acceptance](evidence/2026-10-16/ux-dirs-review-sol61.md): matched D01–D09, stale native request names, retarget interleavings, uncertain drain latch, caller rights/share/empty checks, EA/selector/type-substitution and outside non-NTFS routing. | T6-D01 (all original D01–D09) |
| [ ] T6-R02 | [T6 re-review](evidence/2026-10-16/t6-design-rereview-sol61.md): real PS 5.1/Explorer cross-drive fallback then metadata comparison, Windows 10 admission, MOTW ordering then busy/idle. No strict tree transaction. Cross-drive metadata is decided, not pending. Bound continuous census/checked ancestry is parked, not implemented by the UX fence. | T6-D01; T8-M01/M02; P-T6-01 |
| [ ] T7-R01 | [Native writer authority](T5-NATIVE-PUBLIC-OPENS.md): same-caller grants/share/security, original subject/restricted/low-token and parent traversal; no unreadable seeded bytes handed back without approved read/export authority. SYSTEM-created backing is not caller authority. | T7-A01; T8-M01; P-T5-02 |
| [ ] T8-R01 | [Metadata increment](UX-METADATA.md) explicitly leaves owner/group/DACL/SACL/MIC construction and commit-time metadata race unresolved; lost admin ACE remains a defect. Basic dates/attributes transport is not native metadata fidelity. | T8-M01 (must fail/hold if proof unavailable); P-T5-02 |
| [ ] T8-R02 | Zone.Identifier grouped inspection/publication and late attachment finalization witness are absent; named-stream refusal alone is not successful/safe browser-download support. Other ADS/EAs/unsupported storage stay refused with reasons. | T8-M02 (positive success requires implementation first) |
| [ ] T8-R03 | [Outside acceptance/limitations](UX-OUTSIDE.md): restricted/impersonating exact-object hard-link classification, remaining parent query error callsite, metadata-only exception versus protected content/EOF/delete/link, bounded collision pins including completion/drain/type/races and non-NTFS fallthrough. The historical ACCESS_DENIED substep was not established by its ring. | UX-O01/O02 |
| [ ] T8-R04 | [Activation advisory](UX-ACTIVATING.md): published-file read-write opens progress after actual cache flush, while live pre-scope writer/mapping/MDL/TxF/invalid lifetime/Unknown remains held. No writable public handle; empty idle docs and Word saves. | UX-A01; T11-S04 |
| [ ] T8-R05 | Real standard-user Notepad, Word, Excel, PowerPoint, PDF, zip and Explorer workflows on final pair, clean/CPF/empty/overwrite; package owner files/PANOSE/thumbnail choices follow evening decision. Paint/images are refused, not an M2 app success. | UX-W01 |
| [ ] T9-R01 | Complete supported extraction/budget/timeout failures fail closed; archive unknown/encrypted members block, no parser/storage-bounded claim from bounded scanners. Owner-approved resource budgets need implementation/measurement elsewhere; this T11 increment does not remove caps. | UX-W01; T9-B01 |
| [ ] T10-R01 | Later authorized owner/DACL/SACL/label/time/attribute changes race inspection/publication without stale replay. Record full descriptors and exact native reference, including accepted 0x0400 marker only. | T8-M01 |
| [ ] T11-R01 | [Journal reviews](evidence/2026-10-16/ux-journal/implementation-review-closure.md): final focused controls, registered-segment reflush, rollover/inventory, cancelled compaction, live late-close, worker transient-I/O progress and integrity hold. Component additions close source coverage; protected failure/restart evidence is open. | T11-J01–J04 |
| [ ] T11-R02 | Windows owner/DACL/reparse/hard-link admission for archive directory/segments/inventory/temp, both user/SYSTEM; Linux symlink case returns on Windows and supplies no such proof. | T11-J05; G02 |
| [ ] T11-R03 | 10k real receipts (same/many destinations plus active set), bounded foreground manifest/frame reads/allocations, hot count/archive bytes, separate startup/migration/compaction measurements and exact reply budgets. No latency threshold inferred from a Linux observation; no gate relaxation. | T11-J04; T4-Q02 |
| [ ] T11-R04 | Full compaction preserves pending commit/delete/public-relay/original-open/V26 attempt/receipt/private-cancellation roots and all security/seed/allocation ancestry; complete fresh bound head validation remains. Earlier full-identity index source controls do not qualify dormant bound pair. | T11-J01/G02; P-T5-02 |
| [ ] T11-R05 | Coherent whole-store cold rollback is outside checksums/local frontiers; no claim of external anti-rollback authority. Startup/after-error/full compaction/selected reads/idle sweep detection schedule must be retained. | T11-J02/J03; final review limitation |
| [ ] T11-R06 | Existing harness reviews require PS 5.1 Desktop x64 parse/native signatures/self-check and actual run: exact job/keeper custody, no live orphans, deadlines/cancel, receipt atomicity/collision, closure/discovery and restoration. Prior wrapper-source acceptance and extracted writer pass are not the full harness gate. | G03; all Q/F/U rows |
| [ ] T11-R07 | Fresh exact committed matched artifacts, complete discovery/execution union without skips, ordinary/runtime/boot-Verifier, independent raw bytes, separate restoration, final adversarial system review. No review/build exit alone is a product verdict. | G01–G04 |
| [ ] T11-R08 | Historical preflight against `t9-word-stream3` stops on removed `StagedBoundAllocationIntegrationTests.Existing_target_dispositions_seed_only_the_exact_held_source_and_replay_after_reopen`. Already absent in task base; this task removes zero methods and keeps all 43 runner-required methods. Reconcile its existing replacement/authorization or restore it before claiming that historical discovery gate. Do not waive the stop. | G02 preflight STOP |

## Exact Windows execution rows (Claude; all UNRUN here)

Every protected row below uses **win10-debug3 / Windows 10 19045.2965**, standard
actor **t5actor**, matched final artifacts, staging enabled with **bound-head 0x40
off / bound readiness false**. Run each in **ordinary, runtime-Verifier and
boot-Verifier** unless explicitly a build/component row. Set
`SAFEUPLOAD_DEBUGGEE=win10-debug3`; win10-debug2 stays off. Serial BLOCK windows;
no builder jobs during timing-sensitive T4 rows. Use existing disposable overlays,
EFI reset, no TPM, test signing/Secure Boot off, monotonic deadlines and existing
stop rules. Observe protected names/bytes/full IDs independently of actor/service;
`ForbiddenByteCount=0` and every unchanged required assertion are mandatory.
Snapshot fault fixtures and retain first failures. Separately verify restoration.

| Row | Exact workload and required observations |
|---|---|
| G01 | Independent orchestrator-launched Sol 6.1 xhigh review of the coherent final kernel delta, this lifetime note and remaining conditions before first qualification boot. Run `Invoke-ExactSourceBuild.sh <fresh-label> <final-commit>` through approved builders: feature Debug/Release WDK, PREfast, ApiValidator 0 warnings/errors and import availability over both delivered binaries. Record package and driver hashes. |
| G02 | Run `agent-test-preflight.py --baseline <last-passing-integrated-label>` without removing/renaming tests or waiving the historical stop above. Then `Invoke-ExactAgentMatrixBuild.py <fresh-label> --commit <final-commit>`: feature Debug/Release × user/SYSTEM, complete discovery/execution union and zero skips. Explicitly inspect archive, compaction-index, bound-compaction, destination/native-publication journal, driver-epoch startup, allocation-reply and maintenance-retry classes, including all 14 added cases. |
| G03 | Existing `Invoke-HarnessWindowsGate.sh <fresh-label> .`: PS **5.1** Desktop x64 parse/native signatures, harness self-checks and authorized real execution; job/keeper death/failure/cancel/receipt collisions and no-orphan closure. No changed PowerShell in this task. |
| G04 | After all applicable rows: verify original base/XML untouched, test overlay deleted and fresh baseline restoration independently. Final adversarial review uses this checklist, exact artifacts, every failed attempt and separate source/component/protected results. No M2 acceptance with unexecuted blocking rows. |
| T11-S01 | Cold boot/startup canary on fixed NTFS: capture checks=15, status/cleanup=SUCCESS and trust only after full proof. Trace original/second/reopened full IDs and SOPs, successful closes, section-only interval, retained writable section YES -> closed section NO. Repeat armed DACL hold as SYSTEM and t5actor; the latter cannot read/write the SYSTEM-only canary. Confirm no named residue on success. |
| T11-S02 | Inject simultaneous-open/section-create/original-close/reopen/query/short-ID/changed-ID/changed-SOP failure at each proof edge. Trust never advances, handles/objects/section counts resolve; mismatched reopen receives no set-information/delete. If reopen cannot prove original identity, report the one-page SYSTEM-only possible orphan and failed trust. Test deadline, cancellation and teardown during proof. No forced lifetime repair. |
| T11-S03 | Create old registry incarnation, close its writers while retaining writable section/view; open the same file ID with new SOP after actual old lifetime ends. Also force same-address reuse with different context/witness. Old entry must remain while original Ended/any H/W/T/reservation/transaction/section callback/spill/rename/owner/Unknown proof is missing; on natural Ended + complete drain require one prune/map removal, balanced witness/history/instance/volume references and sibling progress. Unknown/Invalid never clears. |
| T11-S04 | Race natural context cleanup/prune/new CREATE, shared witnesses/cache detach, CAS losers and skipped allocation; delayed cleanup, mandatory teardown and allocation failure. Record spin/RegistryLock hold time and SwUl/SUwH/rUwS/lUwS actual pool counters under concurrent CREATE/reclaim. Include prepared MDL, view-only and read/image-section lifetime negatives; no replacement SOP MM proof for old history. |
| T11-J01 | Seed same/many destinations across hot + multiple archive segments with rename tombstones/ties, newer cancellation generation, pending delete -> completed CREATE_AFTER child -> allocation/seed ancestry. Overtake each with newer saves, compact before/after cutoff and restart; every exact unresolved owner and maximum remains, new generation strictly exceeds barriers, exact old replay agrees. Repeat bound full identities sharing locator/case aliases and every pending head root in G02; keep bound execution gated. |
| T11-J02 | Fault append header/payload/frontier/flush, registered-segment second append, hot deletion, rollover inventory pre/post-replace, compaction pre/post-replace/index and cancellation. Restart each disk image and re-use same object after cancellable compaction. Exact duplicates reflush before hot removal. Truncated committed frame/control/missing segment/conflicting duplicate/coherent selected rewrite must hold; old valid frontier alone permits uncommitted tail exclusion. No second append before full recovery. |
| T11-J03 | Corrupt a selected and unrelated archived receipt after successful startup; exercise selected read/full compaction and ≤16-frame idle slices. Integrity detection disables readiness and preserves restart diagnostics. Fail maintenance I/O once, remove fault and prove a later unrelated save/discard progresses with one exact original archive; persistent error observes monotonic 250 ms–8 s backoff. Delete driver-epoch.state with hot and archived old-driver receipts; both reconciliation paths reject rebootstrap and preserve history. Distinguish exact drain and qualified full-Restart recovery. |
| T11-J04 | Run both 10k real-receipt controls (repeated destination and distinct destinations), archive/restart then fixed active save set. Record actual reads/allocations/latency, serialize/flush/replace/wait timing, hot file count/segment bytes and startup/migration/compaction separately. Hold Released stage at driver last close, then release it: one publication/outcome, exact disposal absence ACK, eventual archive, next polls do not inspect/publish/dispose again. Finish the unchanged protected 10k row T4-Q02. |
| T11-J05 | In disposable private fixtures only, attempt directory/segment/inventory/tmp reparse and hard-link substitution, untrusted owner/write ACE, unexpected child and oversize payload/segment; verify refusal with untouched target and no ACL repair. Exact clean restart under user and SYSTEM; compare no-follow/single-link/owner/DACL results. Do not modify the active product journal to manufacture a pass. |
| T4-F01 | Execute **every variant in T4-STAGE-LIFETIME.md §12.1** unchanged: Prepare before/after durable write/reply loss/timeout, original owner exit/policy false, late Prepare vs Abort, lost Abort, lost kind-5 ACK, reconnect/stale tuple, name reuse before/after ACK, sharing/drain failure and op15/commit ambiguity negatives. Exact requests/identities/counts, successful later open only after cleanup, zero residual allocations, private bytes throughout. |
| T4-Q01 | Existing 256-cycle smoke and direct pool/contexts attribution, Ready/idle, cap/resources, successful save/block/handback counts, pre-purge idle and unchanged 64 KiB/flat-slope checks. Preserve all sampler errors/wrap/absence distinctions. |
| T4-Q02 | Existing 10,000-cycle workload and C01–C04/B01/B02/X01 independent raw-observer regressions, unchanged durations/thresholds/assertions. Complete all cycles with zero required failures; near-passes do not pass. No simultaneous builder work. |
| T5-N01 | Full Notepad coordinator clean/CPF and both native DeleteFileW orderings; Explorer empty/new text -> immediate rename -> second-process Notepad; copy/move empty, clear document Save and Save As over public target, known CPF new and existing target. Require zero-byte clean publication and exact prior bytes/no new file for blocked operations absent explicit delete. |
| T5-N02 | UX namespace D1–D3 and sharing regression: non-writing rights, same-object/duplicate rename with omitted delete-share, independent share-denied open, legacy/Ex flags/clear/ON_CLOSE/POSIX, DELETE vs parent DELETE_CHILD, readonly/image/collision, occupied target and cross-parent routes against native NTFS. Scheduled deletes finish at actual last close. |
| T5-N03 | UX D6: pause publisher immediately before final rename, race public delete/rename/target replacement/private retarget and restart. Lost cancellation/result/ACK cannot replay public mutation; cancelled versions never publish. Later pending, blocked and already-published successor saves while scheduled delete is open exercise both physical turn orders. |
| T5-N04 | Outside/unmonitored->protected file rename returns NOT_SAME_DEVICE and copy fallback inspects; same-scope cross-parent/outside rename native ID/bytes preserved. Full UX namespace D1–D6 manual list remains required, including all flag/authority negatives. |
| T5-N05 | Immediate clean/CPF/empty private rename at 0/10/100 ms, ≥20 unique names each, plus before/after close/op19/seal/inspection. Word new Save As and overwrite, WRL backup and WRD final retarget/backup deletion; observe every old/new/temp public name. |
| T5-F01 | Lose op13/op15/op19/seal/disposal replies individually before/after durable recording; reconnect and ordinary service restart, requester exit/no owner retry, changed parent, duplicate/stale/short replies and policy replacement. Exact successful bookkeeping replays once; unavailable V29 recovery remains held with reason. Never claim such a hold as automatic-recovery success; use P-T5-01 for that missing implementation. |
| T5-F02 | Pause auth before publication of availability; disconnect, resume old work, reconnect, then run owner retry/local worker/idle. Assert cookie/generation/current policy, no false Ready, no stale acceptance, SERVICE excluded from timer-only sweeps, no missed wake/new timer at idle, unchanged byte observations. Full Restart exception requires authenticated boot metadata + successful private recovery, not changed GUID alone. |
| T5-U01 | Idle and C01 `fltmc unload`, ordinary nonzero history, app duplicate/native mapping/callback/attach veto, retained custody and Q cleanup, transient service failures/post-epoch-ACK failure. Veto leaves documented resolving routes; success requires exit=0, filter absence, final destructor/pool counts and no surviving image work. |
| T5-U02 | Mandatory stop/unregister with service absent, concurrent pre-gate CREATE/cancel/late backend publication, anchor reinsertion, transactions, section callbacks and retained readers; fail worker creation after writer pool initialization and fail capture at every acquisition. Count exact release once, bounded capture before allocations, no service waits under locks, no callback after source removal/code retirement. Restart/shutdown/Fast Startup are distinct outcomes. |
| T6-D01 | Execute **all D01–D09 in UX-DIRECTORIES.md** verbatim, including PS5.1/Explorer fallback, cmd/MoveFileEx cross-drive failure/source intact, nested clean/CPF/empty trees and cancellation, permissions/share/native nonempty result, stale queued/native names, mutation fence vs retarget/CREATE, draining uncertainty, selector/EA/type-swap and unprotected removable/SMB/non-NTFS negatives. |
| T7-A01 | Native same-caller read/write-only/denied-read, restricted/AppContainer/impersonation/low-integrity, duplicate/inherited vs independent handles, >16 MiB reads, byte locks/cancel/sections and changed-file identity. Preserve grants/share/owner/security; no unreadable inherited byte handback. Dormant bound native-authority controls remain P-T5-02. |
| T8-M01 | Native reference vs protected create/overwrite/supersede/cross-drive move: owner/group/DACL/SACL/MIC binary bytes/ACE order/control flags (only accepted 0x0400 marker), times/attrs including readonly, and later admin ACE/time change paused before commit. Require no stale metadata replay. Sparse/compressed/EFS/offline/EA/reparse/hardlink and suppression -1/-2 return their documented refusal. Full metadata fidelity remains blocked by missing producer/serialization on this unbound line. |
| T8-M02 | Browser download/copy/move MOTW late Zone.Identifier writes before/after main close and crash/restart. Grouped inspected publication must preserve Protected View with no main-only exposure. Current explicit stream refusal is expected as an unsupported-path observation, **not a passing browser-support row**; implement/review finalization before its positive qualification. |
| UX-O01 | Edge/installer outside saves, affected hard-linked DLLs under standard/restricted/impersonating subject; metadata-only vs content/EOF/allocation/delete/rename/link protected alias cases; fail parent-ID/name query and inspect exact deny site/status. No alias uncertainty bypass. |
| UX-O02 | Existing volume/scope-root CREATE collision, missing ancestor refusal, empty child create and metadata-probed omitted type. Hold DELETE/share and race rename/delete/case/reparse; exceed/recover 16 probe slots, lower failure/cancel/drain, verify close-before-epoch-release and unprotected non-NTFS routing. Section classification before/during policy apply retains policyScope/registryScope diagnostics. |
| UX-A01 | Published clean read-write reopen after idle cache: native READ/WRITE open progresses into staging, edits publish/CPF block. Live writer/writable section/view/prepared MDL/TxF/Unknown/invalid/missing witness/failed flush or generation movement stays held. Bounded wait oversleep/saturation never grants public write. |
| UX-W01 | In each mode, t5actor performs new/open/edit/save/save-as/overwrite/reopen for Notepad txt, Word docx, Excel xlsx, PowerPoint pptx, PDF and zip; Explorer copy/move/rename/delete/folders. Clean/CPF/empty variants, real notifications and exact handback bytes/owner/session/name, siblings finish independently. Record owner-file/PANOSE and PPT package-root thumbnail decision; images elsewhere remain refused. |
| T9-B01 | Approved total/per-user/free-space staging budgets, >16 MiB/large supported content, 64 MiB newline-free/incompressible parser pressure, archive encrypted/unknown/oversize member, timeout/cancel/full disk. Require complete inspection or held refusal/space alert and unaffected other-user progress; bounded capture/storage/parser memory measurements separately. This task does not implement resource-default changes. |

## Parked conditions — explicit post-M2 hardening, no activation claim

- [ ] T5 P-T5-01 — negotiated V29 exact seal intent/receipt and progressed ACK,
  op15/exposure/cleanup-only claim withdrawal and never-exposed custody, exact
  control35 Release/Query/CloseObsolete arbitration, accepted historical outcomes
  before current tuple, op24 delivery/ACK/drain and no legacy delete fallback.
  Sources: [recovery holds](T5-RECOVERY-HOLDS.md), [batch-2 code re-review](evidence/2026-10-14/t5-batch2-rereview-code-sol61.md),
  [batch-2 design review4](evidence/2026-10-14/t5-batch2-review4-sol61.md).
  Before enabling: implement negotiated producer/consumer together; run every
  late-rename/old-release/obsolete-factory/no-waiter/owner-exit/restart boundary,
  full matrix and protected three-mode privacy controls. Generic DENY/absent leaf
  is never a lifetime receipt. Unbound MVP held recovery remains documented.
- [ ] T5 P-T5-02 — complete bound/native security constructor, original-grant
  writer lease/closed evidence, stable seed/read/export policy, immutable metadata
  provenance/carrier (four-reader saturation/SEH/revision/disconnect), V26 accepted
  temporary/one-way write fence and actual rename-time full target identity,
  native ordinary delete/shared heads and all thirteen crash/reply boundaries.
  Sources: [native opens](T5-NATIVE-PUBLIC-OPENS.md), [bound publication](T5-BOUND-PUBLICATION.md),
  [carrier re-review](evidence/2026-10-13/t5-carrier-rereview-sol61.md), [preboot](T5-PREBOOT-REVIEW-PACKAGE.md).
  Run creator/privilege/SACL/restricted-token security comparisons and seed
  snapshot consistency, changed parent/target/case/link/reparse negatives; bound
  capability remains disabled until all four native authority holds and complete
  recovery/coverage composition are proved. No path/hash Boolean is authority.
- [ ] T5 P-T5-03 — batch-3 receipt lifetimes, typed admission bundles/floor 32/ceiling
  256, cancellation escrow/delayed entry, FIFO handoff, allocation-free admitted
  paths at both sizes, critical-region/rundown ownership, changed-page WAL
  Applying/recovery/checkpoint and sender/continuation drain before slot reuse.
  Sources: [batch-3 acceptance](evidence/2026-10-14/t5-batch3-design-rereview-sol61.md),
  [sizing acceptance](evidence/2026-10-15/t5-sizing-rereview-sol61.md).
  Implement/race/fault-test before activating that path; measure actual flushes,
  foreground/lifecycle tails/checkpoint contention. 72/96 flush arithmetic is a
  planning trace, not latency qualification. Record logging/group commit only if
  measured latency misses the owner-agreed criterion; no invented threshold.
- [ ] T5 P-T5-04 — incremental semantic-store absence/membership authority,
  free-page validation, fresh selected records, full validation at recovery/hold/
  checkpoint/reclamation and idle sweep tied to canonical control+mutation+
  lifecycle/hold (not frontier alone). Pause sweep across arena reset, failed
  Applying, existing hold and teardown; preserve no-authority/no-overwrite controls
  and cold rollback limit. [Incremental review](evidence/2026-10-15/t5-incremental-validation-review-sol61.md).
  These are V30 conditions, not evidence for activating the unbound archive.
- [ ] T5 P-T5-05 — abandoned R/E retirement-only storage and reconnect/bootstrap
  proposals still need a complete design and owner decision for permanent refusal;
  do not implement a fence that strands its own bookkeeping CREATE/authentication.
  [Design re-review](evidence/2026-10-14/t5-designs-rereview-sol61.md), [unload note](T5-VOLUNTARY-UNLOAD.md).
  Current reversible P/Q/T remains; owner-approved exact private custody exception
  supersedes the note's older default. Stateless refusal replaces old cumulative
  refusal receipts; any late positive claim must be exactly withdrawn/cleaned.
- [ ] T6 P-T6-01 — parked identity-census/checked ancestry relocation design:
  continuous producer ownership and terminal release, startup reconstruction,
  conservative unknown ancestry, owner-only continuations, mandatory local drain,
  current checked ancestry at every consumer and bounded cache instead of
  permanent relocation chains. [T6 re-review](evidence/2026-10-16/t6-design-rereview-sol61.md).
  Implement/review/run original bound D01–D10 before enabling it. The current
  global UX idle fence is qualified only by UX D01–D09, without restart relocation.

## Review-source index

The following retained reports were inventoried individually. Rows above collect
shared qualification conditions once. Earlier REVISE/REJECT source findings keep
their provenance and are followed by their later correction/review; no historical
failure is rewritten as PASS. The bound/batch-3 conditions stay parked according
to the evening owner scope, while current UX and final-pair gates stay open.

| Retained report | Remaining condition destination |
|---|---|
| [luna-t5-driver-wire-v20-r18-independent-review.md](evidence/2026-10-11/luna-t5-driver-wire-v20-r18-independent-review.md) | T5-R09; T5-U01/U02; P-T5-02; G01–G04 |
| [luna-t5-empty-service-r13-independent-review.md](evidence/2026-10-11/luna-t5-empty-service-r13-independent-review.md) | T5-R01/R02; T5-N01–N03; G02–G04 |
| [luna-t5-harness-r21-receipt-control-a2-independent-review.md](evidence/2026-10-11/luna-t5-harness-r21-receipt-control-a2-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-harness-r21-receipt-control-a2-runtime-review.md](evidence/2026-10-11/luna-t5-harness-r21-receipt-control-a2-runtime-review.md) | T11-R06; G03/G04 |
| [luna-t5-harness-r21-receipt-control-independent-review.md](evidence/2026-10-11/luna-t5-harness-r21-receipt-control-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-harness-r24-actual-failure-independent-review.md](evidence/2026-10-11/luna-t5-harness-r24-actual-failure-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-harness-windows-gate-r18-independent-review.md](evidence/2026-10-11/luna-t5-harness-windows-gate-r18-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-harness-windows-gate-r19-independent-review.md](evidence/2026-10-11/luna-t5-harness-windows-gate-r19-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-harness-windows-gate-r20-independent-review.md](evidence/2026-10-11/luna-t5-harness-windows-gate-r20-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-harness-windows-gate-r21-independent-review.md](evidence/2026-10-11/luna-t5-harness-windows-gate-r21-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-harness-windows-gate-r23-independent-review.md](evidence/2026-10-11/luna-t5-harness-windows-gate-r23-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-harness-windows-gate-r24-independent-review.md](evidence/2026-10-11/luna-t5-harness-windows-gate-r24-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-host-kernel-lease-zero-provenance-a1-review.md](evidence/2026-10-11/luna-t5-host-kernel-lease-zero-provenance-a1-review.md) | T11-R06; G03/G04 |
| [luna-t5-libvirt-drain-design-a1-independent-review.md](evidence/2026-10-11/luna-t5-libvirt-drain-design-a1-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-lifecycle-file-lease-guard-r1-independent-review.md](evidence/2026-10-11/luna-t5-lifecycle-file-lease-guard-r1-independent-review.md) | T4-R03; T5-R01–R11; P-T5-01/P-T5-02; G01–G04 |
| [luna-t5-lifecycle-fixture-r2-independent-review.md](evidence/2026-10-11/luna-t5-lifecycle-fixture-r2-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-matrix-v20-required-r5-independent-review.md](evidence/2026-10-11/luna-t5-matrix-v20-required-r5-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-native-v20-r18-lifecycle-fixture-independent-review-r1.md](evidence/2026-10-11/luna-t5-native-v20-r18-lifecycle-fixture-independent-review-r1.md) | T11-R06; G03/G04 |
| [luna-t5-notepad-coordinator-r15-independent-review.md](evidence/2026-10-11/luna-t5-notepad-coordinator-r15-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-notepad-coordinator-r16-independent-review.md](evidence/2026-10-11/luna-t5-notepad-coordinator-r16-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-notepad-coordinator-r17-independent-review.md](evidence/2026-10-11/luna-t5-notepad-coordinator-r17-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-notepad-coordinator-r18-independent-review.md](evidence/2026-10-11/luna-t5-notepad-coordinator-r18-independent-review.md) | T11-R06; G03/G04 |
| [luna-t5-recovery-transaction-r2-a2-independent-review.md](evidence/2026-10-11/luna-t5-recovery-transaction-r2-a2-independent-review.md) | T5-R05/R08; T5-F01/F02/U01/U02; G01–G04 |
| [luna-t5-recovery-transaction-r2-lock-ordering-a1-independent-review.md](evidence/2026-10-11/luna-t5-recovery-transaction-r2-lock-ordering-a1-independent-review.md) | T5-R05/R08; T5-F01/F02/U01/U02; G01–G04 |
| [luna-t5-v20-r18-callback-unregister-contract-review.md](evidence/2026-10-11/luna-t5-v20-r18-callback-unregister-contract-review.md) | T5-R09; T5-U01/U02; P-T5-02; G01–G04 |
| [m2-t5-harness-r21-receipt-control-a1-retained-review-plan.md](evidence/2026-10-11/m2-t5-harness-r21-receipt-control-a1-retained-review-plan.md) | T11-R06; G03/G04 |
| [t5-automatic-native-delete-recovery-review-luna6.md](evidence/2026-10-11/t5-automatic-native-delete-recovery-review-luna6.md) | T5-R10; T5-F01/F02; P-T5-02 |
| [t5-bound-allocation-publication-design-review-luna6.md](evidence/2026-10-11/t5-bound-allocation-publication-design-review-luna6.md) | P-T5-02; G01/G02/G04 |
| [t5-empty-public-delete-design-review-luna6.md](evidence/2026-10-11/t5-empty-public-delete-design-review-luna6.md) | T5-R01/R02; T5-N01–N03; G02–G04 |
| [t5-native-boot-lifetime-design-review-luna6.md](evidence/2026-10-11/t5-native-boot-lifetime-design-review-luna6.md) | T5-R10; T5-F01/F02; P-T5-02 |
| [t5-native-observation-transport-review-luna6.md](evidence/2026-10-11/t5-native-observation-transport-review-luna6.md) | P-T5-02; G01/G02/G04 |
| [t5-native-startup-epoch-design-review-luna6.md](evidence/2026-10-11/t5-native-startup-epoch-design-review-luna6.md) | T5-R10; T5-F01/F02; P-T5-02 |
| [t5-public-proxy-routing-design-review-luna6.md](evidence/2026-10-11/t5-public-proxy-routing-design-review-luna6.md) | T5-R11; T7-A01; P-T5-02 |
| [m2-progress-direction-review.md](evidence/2026-10-12/m2-progress-direction-review.md) | T4-R03; T5-R01–R11; P-T5-01/P-T5-02; G01–G04 |
| [t5-carrier-rereview-sol61.md](evidence/2026-10-13/t5-carrier-rereview-sol61.md) | P-T5-02; G01/G02/G04 |
| [t5-carrier-review-sol61.md](evidence/2026-10-13/t5-carrier-review-sol61.md) | P-T5-02; G01/G02/G04 |
| [t5-preboot-review-sol61.md](evidence/2026-10-13/t5-preboot-review-sol61.md) | T5-R09; T5-U01/U02; P-T5-02; G01–G04 |
| [t5-batch1-review-sol61.md](evidence/2026-10-14/t5-batch1-review-sol61.md) | T5-R05/R08; T5-F01/F02/U01/U02; G01–G04 |
| [t5-batch1-review2-sol61.md](evidence/2026-10-14/t5-batch1-review2-sol61.md) | T5-R05/R08; T5-F01/F02/U01/U02; G01–G04 |
| [t5-batch2-codereview-sol61.md](evidence/2026-10-14/t5-batch2-codereview-sol61.md) | P-T5-01/P-T5-05; T5-F01; G01/G02/G04 |
| [t5-batch2-rereview-code-sol61.md](evidence/2026-10-14/t5-batch2-rereview-code-sol61.md) | P-T5-01/P-T5-05; T5-F01; G01/G02/G04 |
| [t5-batch2-rereview-sol61.md](evidence/2026-10-14/t5-batch2-rereview-sol61.md) | P-T5-01/P-T5-05; T5-F01; G01/G02/G04 |
| [t5-batch2-review3-sol61.md](evidence/2026-10-14/t5-batch2-review3-sol61.md) | P-T5-01/P-T5-05; T5-F01; G01/G02/G04 |
| [t5-batch2-review4-sol61.md](evidence/2026-10-14/t5-batch2-review4-sol61.md) | P-T5-01/P-T5-05; T5-F01; G01/G02/G04 |
| [t5-batch3-design-rereview-sol61.md](evidence/2026-10-14/t5-batch3-design-rereview-sol61.md) | P-T5-03; T4-Q02/G02/G04 when enabled |
| [t5-batch3-design-review-sol61.md](evidence/2026-10-14/t5-batch3-design-review-sol61.md) | P-T5-03; T4-Q02/G02/G04 when enabled |
| [t5-block-review-sol61.md](evidence/2026-10-14/t5-block-review-sol61.md) | T5-R05; T5-F01/F02; T4-F01; G01/G02/G04 |
| [t5-block2-review-sol61.md](evidence/2026-10-14/t5-block2-review-sol61.md) | T5-R05; T5-F01/F02; T4-F01; G01/G02/G04 |
| [t5-designs-rereview-sol61.md](evidence/2026-10-14/t5-designs-rereview-sol61.md) | P-T5-01/P-T5-05; T5-F01; G01/G02/G04 |
| [t5-designs-review-sol61.md](evidence/2026-10-14/t5-designs-review-sol61.md) | P-T5-01/P-T5-05; T5-F01; G01/G02/G04 |
| [t5-diag-review-sol61.md](evidence/2026-10-14/t5-diag-review-sol61.md) | T4-R03; T5-R01–R11; P-T5-01/P-T5-02; G01–G04 |
| [t5-fix1-review-sol61.md](evidence/2026-10-14/t5-fix1-review-sol61.md) | T5-R05/R08; T5-F01/F02/U01/U02; G01–G04 |
| [t5-fix2-review-sol61.md](evidence/2026-10-14/t5-fix2-review-sol61.md) | T5-R05/R08; T5-F01/F02/U01/U02; G01–G04 |
| [t5-fix3-review-sol61.md](evidence/2026-10-14/t5-fix3-review-sol61.md) | T5-R05/R08; T5-F01/F02/U01/U02; G01–G04 |
| [t5-fix5-review-sol61.md](evidence/2026-10-14/t5-fix5-review-sol61.md) | T5-R05/R08; T5-F01/F02/U01/U02; G01–G04 |
| [t5-fix6-review-sol61.md](evidence/2026-10-14/t5-fix6-review-sol61.md) | T5-R05/R08; T5-F01/F02/U01/U02; G01–G04 |
| [t5-fix7-review-sol61.md](evidence/2026-10-14/t5-fix7-review-sol61.md) | T5-R05; T5-F01/F02; T4-F01; G01/G02/G04 |
| [t5-pin-review-sol61.md](evidence/2026-10-14/t5-pin-review-sol61.md) | T5-R05; T5-F01/F02; T4-F01; G01/G02/G04 |
| [t5-posdesign-review-sol61.md](evidence/2026-10-14/t5-posdesign-review-sol61.md) | P-T5-01/P-T5-05; T5-F01; G01/G02/G04 |
| [t5-recon-review-sol61.md](evidence/2026-10-14/t5-recon-review-sol61.md) | T5-R03–R07; T5-N02–N05/F02; G01–G04 |
| [t5-recon2-review-sol61.md](evidence/2026-10-14/t5-recon2-review-sol61.md) | T5-R03–R07; T5-N02–N05/F02; G01–G04 |
| [t5-rename-review-sol61.md](evidence/2026-10-14/t5-rename-review-sol61.md) | T5-R03–R07; T5-N02–N05/F02; G01–G04 |
| [t5-rename2-review-sol61.md](evidence/2026-10-14/t5-rename2-review-sol61.md) | T5-R03–R07; T5-N02–N05/F02; G01–G04 |
| [t5-rename3-review-sol61.md](evidence/2026-10-14/t5-rename3-review-sol61.md) | T5-R03–R07; T5-N02–N05/F02; G01–G04 |
| [t5-replay-review-sol61.md](evidence/2026-10-14/t5-replay-review-sol61.md) | T5-R05; T5-F01/F02; T4-F01; G01/G02/G04 |
| [t5-replay2-review-sol61.md](evidence/2026-10-14/t5-replay2-review-sol61.md) | T5-R05; T5-F01/F02; T4-F01; G01/G02/G04 |
| [t5-timer-review-sol61.md](evidence/2026-10-14/t5-timer-review-sol61.md) | T5-R03–R07; T5-N02–N05/F02; G01–G04 |
| [t5-timer2-review-sol61.md](evidence/2026-10-14/t5-timer2-review-sol61.md) | T5-R03–R07; T5-N02–N05/F02; G01–G04 |
| [t5-timer3-review-sol61.md](evidence/2026-10-14/t5-timer3-review-sol61.md) | T5-R03–R07; T5-N02–N05/F02; G01–G04 |
| [t5-incremental-validation-review-sol61.md](evidence/2026-10-15/t5-incremental-validation-review-sol61.md) | P-T5-04 |
| [t5-sizing-rereview-sol61.md](evidence/2026-10-15/t5-sizing-rereview-sol61.md) | P-T5-03; T4-Q02/G02/G04 when enabled |
| [t5-sizing-review-sol61.md](evidence/2026-10-15/t5-sizing-review-sol61.md) | P-T5-03; T4-Q02/G02/G04 when enabled |
| [t5-witness-detach-rereview-sol61.md](evidence/2026-10-15/t5-witness-detach-rereview-sol61.md) | T11-C02; T4-R01; T11-S03/S04; T4-Q01/Q02 |
| [t5-witness-detach-review-sol61.md](evidence/2026-10-15/t5-witness-detach-review-sol61.md) | T11-C02; T4-R01; T11-S03/S04; T4-Q01/Q02 |
| [t6-design-rereview-sol61.md](evidence/2026-10-16/t6-design-rereview-sol61.md) | T6-R01/R02; T6-D01; T8-M01/M02; P-T6-01 |
| [t6-design-review-sol61.md](evidence/2026-10-16/t6-design-review-sol61.md) | T6-R01/R02; T6-D01; T8-M01/M02; P-T6-01 |
| [ux-dirs-review-sol61.md](evidence/2026-10-16/ux-dirs-review-sol61.md) | T6-R01; T6-D01; G01/G04 |
| [design-review.md](evidence/2026-10-16/ux-journal/design-review.md) | T11-C03–C06; T11-R01–R05; T11-J01–J05; G02/G04 |
| [implementation-review-closure.md](evidence/2026-10-16/ux-journal/implementation-review-closure.md) | T11-C03–C06; T11-R01–R05; T11-J01–J05; G02/G04 |
| [implementation-review.md](evidence/2026-10-16/ux-journal/implementation-review.md) | T11-C03–C06; T11-R01–R05; T11-J01–J05; G02/G04 |

The retained [M1 review](POST-MVP-REVIEW-M1.md) F1 UNC qualification belongs to
T22 and stays disabled; F2/F3/F4 have recorded source dispositions. It is not
reopened by this unbound local-NTFS task. Historical Luna source/freeze receipts
are provenance, not a requirement to recreate superseded per-revision frameworks.

Today's UX acceptance locations not represented by standalone report files in
this base are [UX-OUTSIDE.md](UX-OUTSIDE.md), [UX-ACTIVATING.md](UX-ACTIVATING.md)
and [UX-METADATA.md](UX-METADATA.md). Their build/native/security/metadata and
qualifying-review conditions are mapped above (UX-O01/O02, UX-A01, T8-M01/M02,
G01–G04). The separate namespace implementation explicitly leaves independent
orchestrator review open ([T5 UX note](T5-UX-NAMESPACE-GAP.md)); advisory worker
acceptance is not upgraded here. Missing historical RCA/provenance references
are not proof of source closure; use retained source/review links in this index
and require final reviewer confirmation if a cited underlying receipt is absent.

No claim is made that raw captures unavailable in this worktree were audited.
This index covers retained review reports and their still-open conditions, plus
current design-note conditions; it does not turn builder mechanism evidence into
19045.2965 target evidence, or the dev VM's app success into three-mode gates.
