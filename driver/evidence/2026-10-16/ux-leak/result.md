# T4 UX leak investigation and repair

Base `54e0efd7`, branch `ux/leak`. Source Git is read-only in this session;
delivery is `.scratch/ux-leak.bundle`, with a new `ux/leak` head constructed
in an isolated scratch repository. No VM or builder was contacted. This is
component/source evidence, not a flat-pool protected 10k verdict.

## Findings

The supplied [sample projection](samples-summary.json) binds the original raw
JSONL by SHA-256. From 0 to 5,000 saves SUfl live allocations rise 453 -> 8,427,
bytes 125,792 -> 1,911,168 (223.900 bytes/net allocation). The 1,000–5,000 byte
slope is 267.016 B/save. Writer entries stay 237–262; stage versions/views,
tombstones, stage files and waiting versions are zero in every sample. At
5,000, created/released versions both equal 5,000, cap refusals/deletion
failures are zero, hot journals are 3,752, and kept hand-backs are 1,248.

**Definite service defect:** the driver's disposal can delete the stage before
the service's next pass. `RequirePrivateStagePath` then calls
`File.GetAttributes` on the absent leaf and throws. `DisposeReleasedStageAsync`
catches/logs it without setting StageDeleted, so archival cannot happen.
`PublishSealedLoopAsync` calls `DisposeReleasedStagesAsync` every maintenance
pass; `ReadReleasedAsync` enumerates hot `*.json` manifests. Every ordinary
release still lacking StageDeleted sends another DISPOSE. This is the growing
work set. The kernel handler scans **StageStreams**, not the registry/receipt
history, and increments DisposeNotHeld **once per unmatched call**, not per
entry visited. It has no persistent not-held list. A history-sized hot set
explains cumulative quadratic calls (224,043 at 500; 10,107,036 at 5,000).

**Kernel retention gap:** successful ordinary prune releases the large registry
entry/cache and last SOP witness binding, but leaves the empty Filter Manager
stream context attached. Such an attachment can follow NTFS cache lifetime for
unique hand-backs, manifests and replaced streams. Static context references
balance: successful allocation/Set ownership transfers to the caller; losing
allocations/Get/winner references and reclaim pins are released. No leaked
FILE_OBJECT/context reference was proven. The aggregates and historical
224-byte context attribution are consistent with attached-context retention;
they do not identify every original live object or its final filesystem owner.

## Allocation and list audit

[Full inventory](sufl-inventory.json): 45 SUfl allocation sites, including the
five context allocation sites and their four registered context types.

| Family | Tag and owner/retirement |
|---|---|
| Stream context | SUfl; attached to the exact NTFS stream. The repaired path detaches only an inert context after successful ordinary prune and all witness/cache bindings are gone. Old users keep normal reference lifetime. |
| Instance context | SUfl; one per attachment, freed by Filter Manager at instance teardown. Teardown-token allocation has separate `SAUt` tag. No per-save insertion. |
| Stream-handle context (ordinary marker and directory enumeration) | SUfl; owned by a live FILE_OBJECT/handle context, freed after its natural context lifetime. Directory cleanup frees the view. No per-save historical table. |
| Transaction context | SUfl; per live transaction/Filter Manager lifetime. Associations use `SwUt`; no transaction-per-publication history. |
| Policy and admission epochs/tokens | SUfl; current/pending policy snapshots, draining epochs and live callback tokens. Snapshot replacement releases predecessors; tokens release epoch references at completion. Not one per published file. |
| Protocol/filter exchange and rename reply | SUfl; per in-flight call; common exit frees the exchange and rename reply is freed/reset after each send. Retained stream rename exchange uses `SpUs`, released with its exact outcome. |
| Directory snapshot/census/overlay | Paged SUfl entries/view/buffer/overlay; bounded directory-view bytes, freed on rebuild/failure/handle cleanup. One temporary nonpaged related-object copy per deferred query is freed by worker/unwind. These are not the observed nonpaged growing population. |
| Coverage/security/identity/path scratch and policy-message capture | SUfl (mostly paged); freed at common handler/operation exits. Samples show paged SUfl usage zero. |
| Legacy taint buckets | SUfl per tainted process, refreshes existing entries; exit/expiry/unload frees. Product disables process taint on this line; not per save and not changed here. |
| Writer registry, reservations, name/ADS history, directory-rename records and identity anchors | `SwUr`; history retires through exact ordinary/Ended proofs, reservations/rename/anchors through their existing owners. Compact pool is fixed/reused. Samples show bounded entries and roughly flat bytes. |
| Writer nodes / incarnation witnesses / TxF associations | `SUwH` / `SwUl` / `SwUt`; exact cleanup node, context+entry witness refs, transaction owner. Witness has no back-reference/object pin. No missing-lifetime expiry added. |
| Native namespace/publication/backend receipts | `SpUn` / `SpUb` / `SpUp` (wire/observation have separate tags); map/callback/operation/lease owners, exact terminal ACK and local destructor. These cannot explain SUfl. Uncertain receipts remain held; their zero count is not inferred from stage-version counters. |
| Versions/views/tombstones/attach/recovery objects | `SpUs`; existing event-driven stream/RPC/owner retirement. Supplied live counts and tag bytes are zero at samples. No extra retirement list was introduced. |
| Alias proofs, deny ring, activation recheck | Alias scratch `SpUa`, proof embedded in reservation; deny ring/hints are fixed image arrays; recheck is coalesced queued/rescan state plus existing bounded work/anchor owners under `SwUr`. None is an SUfl per-save list. |

## Change and lifetime argument

The service still validates every ancestor and refuses reparse points, access
errors and missing ancestors. Only a missing leaf is permitted at this
precheck. The existing no-follow exact-ID delete/absence helper, second
journal read, committed-rename count, version/state checks and final durable
absence receipt remain required before archival. No publication is replayed.

The kernel consumes **only successful existing ordinary-prune authority**.
After cache/witness release, RegistryLock -> WriterLock rechecks the pruned
cache receipt, null cache/witness, empty writer list, no invalid/untracked or
entry/global Unknown state, ACTIVE token and no mandatory teardown. It fences
the context permanently, invalidates the old zero-census receipt and advances
coverage/change sequences. Only after dropping locks does its sole worker
delete the pinned exact context and signal the initialized per-context event.
No current/nonretired binding can lose its witness. No Ended is fabricated.

Bind and every writer/unknown-marker insertion reject the fence. A CREATE
whose lookup preceded fencing retries the full Get+Bind pair with its original
reservation; a successful bind blocks fencing. An old snapshot returns Unknown,
not a stale zero. Lookup waits at PASSIVE outside caller locks for the sole
delete owner, then drops its old pin and relooks up; it never deletes a newer
context or issues a second delete. The diagnostic removal also claims its
delete under WriterLock: invalidation winning vetoes ordinary detach; fencing
winning refuses diagnostic deletion. Explicitly retired cleanup cannot publish
natural Ended, and contradictory owned state records sticky loss.

The extra event adds resident bytes per live context; WDK size/pool-bucket
measurement is still required. No new DDI import is introduced (all used DDIs
already occur in this driver), but both actual binary import gates remain due.
SAL is repeated on new declarations/definitions; pageable Get+Bind is declared
before alloc_text and definition. Spin-lock helpers remain resident. There is
no wait/I/O/allocation/Filter Manager call under either retirement lock, no new
timer, no history list and no change to policy/capability/Ready/Unknown gates.

Design/interleavings: [UX-LEAK](../../../docs/design/lifetime/UX-LEAK.md).
Fresh Sol 6.1 xhigh [advisory review](review-sol61-advisory.md) found no remaining
source blocker after single-deleter/diagnostic races were repaired. Repository
policy's formal Claude-launched pre-boot review and native conditions remain.

## Verification

- The new real-journal control fails at its first kernel-deleted release with
  the original precheck call restored; its hot-manifest assertion fails. The
  failure receipt is `.scratch/ux-leak/agent-before.log`.
- Fixed 10k disposal/generation control: **PASS**; 10,000 archived receipts,
  zero hot manifests, exactly 20,000 disposal calls and a clean archive restart.
  It drives real Create/Seal/Inspect/Approve/Publish/
  Release journal transitions over four names, driver-held disposal followed
  by simulated exact kernel deletion, durable absence and archive restart.
- 50 other archive/recovery cases PASS, no skips, through the serial in-process
  Linux runner in feature Debug and Release. Both unchanged existing 10k
  archive/generation scaling controls also PASS in Debug (allocation 1.265–7.902
  ms, seal 2.520–7.320 ms). Identity replacement, pending cleanup/rename, invalid receipt,
  corruption, failed flush/restart and generation-barrier cases stay required.
- Four new C controls PASS with GCC and Clang, warnings as errors and UBSan:
  10,000 contexts under a deliberately never-releasing filesystem attachment
  model, stale Get+Bind retry, allocation failure, sibling binding, ten final
  vetoes, diagnostic ownership and repeated worker visit. Removing detachment
  or the bind fence compiles and fails execution. Existing ordinary-prune
  controls retain the H/W/T/owner/reservation/section/transaction vetoes.
- All 20 existing/selected T5, kernel-host, T11 lifetime and T4 verdict scripts
  PASS (114 unittest cases plus verdict controls); final context/witness controls
  rerun after final source edits. Import self-check and matrix runner's 21
  offline controls PASS. Source diff whitespace check PASS.
- Local normal/feature Debug/Release Service/App/Tests builds PASS, all 0/0.
  Focused feature Debug/Release test builds also PASS 0/0. These Linux builds/controls
  are diagnostic, not the Windows user/SYSTEM matrix or WDK verification.

Raw local outputs and runner are under `.scratch/ux-leak/`; initial shim-only
fixture failures were corrected (fixture ownership accounting/source matching
and per-test runner isolation),
not product assertions or T4 thresholds. No existing test was renamed, removed,
skipped, weakened or given a new threshold.

## Remaining qualification and risks

No claim of actual flat nonpaged pool or protected-pair completion is made.
Before boot, run feature Debug/Release WDK + PREfast + ApiValidator at 0/0,
both binary import gates, the formal independent review and matched Windows
agent matrix. Then unchanged T4 smoke/10k ordinary/runtime-/boot-Verifier,
allocation-reply/native identity/namespace regressions and independent bytes,
zero residual stage/version/view/tombstone, idle worker and restoration on
`win10-debug3` only under current lab/stop rules.

Explicit native races: pause after fence before delete/signal (including
concurrent teardown); new CREATE/cleanup/diagnostic in both orders; stale old
reader versus fresh writer; live read-only section/view; late section slot after
prune; sibling/incarnation/address reuse; allocation failure and global/instance
Unknown. No host shim proves Filter Manager/MM/IRQL scheduling or the wait's
native progress. Existing unresolved/unsupported/seeded receipts may correctly
stay hot; distinct retained managed archive receipts/storage remain charged and
are not a claim of bounded total agent memory. The fix bounds finished work,
not unresolved security obligations.
