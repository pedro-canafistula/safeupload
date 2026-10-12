# T4 memory attribution — m2t4memdiag1, 2026-10-12

**Result:** the approved bounded diagnostic completed. All 256 save outcomes and the original short-row assertions passed;
voluntary unload released both investigated pool tags and all Verifier-tracked allocations. Separate restoration passed.
This establishes release at unload, **not** bounded retention while the driver remains loaded. It does not qualify T4 or
justify another kernel reclamation path. No product code, gate, threshold or failure policy changed.

## Pair and execution

- Kernel `60fecdbc` / `m2-driver5-t11`, SHA256
  `EBDFCE549EA1DC271498A5F6A38D151AC952ADE9105D476B073A313EB271C851`.
- Protocol-18 agent `6198eee7`; archive SHA256
  `21F725DD4995603979CF173C43499477B45E2CC5085404AFC594C5B04CD5293F`.
- Existing matching private PDB: GUID `8ad16830-ebf1-485d-be1b-7ec477193b97`, age 1. Existing Windows SDK local debugger;
  no kernel instrumentation or host debugger installation.
- Harness launched at `83eae7e6`: 256 mixed saves, sample every 64, boot Verifier `0x13B`, VM `win10-debug3` only.
  [Host output](m2t4memdiag1-host.txt), [original verdict](m2t4memdiag1-verdict.txt),
  [samples](m2t4memdiag1-samples.jsonl), [final row state](m2t4memdiag1-after.txt).
- The diagnostic deliberately adds file opens, debugger I/O and pauses. Its results are attribution evidence, not an
  uninstrumented qualification or latency result. The prior [four WDK builds](../2026-10-10/exact-m2-driver5-t11-summary.txt)
  and [four-profile agent matrix](exact-agent-matrix-t4-rejected-allocation1-summary.txt) apply to this unchanged pair.

## What the run established

| Observation | Result |
| --- | --- |
| Fixed and disjoint physical-file controls | 1,536 opens with unchanged full volume/file identities |
| Save outcomes | 256/256: 192 clean publications, 64 blocked hand-backs; all four patterns |
| Original module-pool slope | −23.175 B/cycle, unchanged limit 4; endpoint band also passed |
| Versions / views / tombstones / stage files after settling | All zero; 256 versions and views released |
| Idle stage worker | Zero passes and timer fires in the original 60-second interval |
| SUfl pool, cycle 64 → idle | 387,288 → 473,224 bytes: retention remains visible despite module-pool PASS |
| Registry entries during cycles | 240, 241, 239, 240 at cycles 64, 128, 192, 256; 261 after idle |
| SUfl immediately before → after unload | 475,608 bytes / 2,029 allocations → zero |
| SwUr immediately before → after unload | 6,411,392 bytes / 268 allocations → zero |
| Verifier after unload | SafeUpload.sys unloaded; zero current paged and nonpaged allocations/bytes |

The identity corpus is retained in [raw control output](m2t4memdiag1-memory/output/corpus-identities.json).
Pool and unload observations are in the [before](m2t4memdiag1-memory/output/teardown-before.stdout.txt) and
[after](m2t4memdiag1-memory/output/teardown-after.stdout.txt) debugger output; the
[teardown result](m2t4memdiag1-memory-teardown.txt) completed after the original verdict had already been recorded.

**Context attribution:** Filter Manager's stream-context allocator requests 200 bytes per object, consistent with the
previously observed 224-byte pool increments after allocation overhead/alignment. Its outstanding allocation count was
1,652 in the [during-cycle snapshot](m2t4memdiag1-memory/output/context-counts-during-cycles.stdout.txt), then 1,943 in the
[final ownership snapshot](m2t4memdiag1-memory/output/final-owners-corrected.stdout.txt). Instance contexts were four in both;
handle contexts were 26 and 41. A separate [reference snapshot](m2t4memdiag1-memory/output/context-allocation-detail.stdout.txt)
reported zero driver-held FLT_CONTEXT references at that instant. These are live, non-atomic observations; they do not prove
every retained context's attachment or its individual release edge. Successful unload proves that this run's retained
allocations were reclaimable at teardown, not that an ever-growing loaded working set is acceptable.

**Registry attribution:** Verifier identifies 2,400-byte named-shell allocations at `StageRegistryAllocateNamedShell`, plus
the fixed registry pool. The final bounded listing contains 256 entries: all listed, none retired, no W/T or UnknownReasons;
245 have H=1, one H=2, ten H=0. All have LastSState=0 (Unknown), which must not be cleared merely to reclaim memory.
This is evidence of live ownership rather than an accumulated list of retired entries, but the walk reached its 256-entry
bound and names could not be read reliably. It is neither a complete inventory nor proof that each H reference is justified.

**Control limitation:** repeatedly opening the fixed corpus preserved physical identity, but the debugger and background
activity also open files. Aggregate pool changes cannot be assigned solely to those 1,536 opens. Do not infer a per-open
leak or subtract this activity from the original verdict. The stable registry occupancy and negative module slope support
working-set variation as an explanation for earlier short-run slopes; they do not establish causation or a long-run bound.

## Remaining obligations and next step

Keep the tested kernel's guarded retirement logic. There is no demonstrated release-edge defect to fix from this run,
and no basis for force-deleting contexts or clearing uncertain writer state. Record loaded context/registry ownership as
an open resource question. The next qualification remains an unchanged short row without debugger/control overhead,
then the unchanged 10,000-cycle row; the raw-volume regression cells and final M2 pair rerun remain required. A proposal to
change warm-up, sampling, thresholds or acceptance would require a separate owner decision.

The [service events](m2t4memdiag1-service-events.txt) contain 21 coverage-query failures (`0x800704D5`), with 21 corresponding
degraded-state notices, plus pending coverage/promotion notices. Similar warnings exist in the prior short runs. There are
no stage-reply or journal-failure events in this export, but it is **not** an error-free service run. The coverage-query
behavior remains an availability qualification item. The tested kernel deliberately returns `STATUS_RETRY` when the registry
changes during its coverage snapshot (`60fecdbc:StageWriters.c:7799`, propagated by `StageAdmission.c:687–691`); the service
reports an unsuccessful query as degraded and polls again after 500 ms (`6198eee7:MinifilterInterceptor.cs:809–868`). That is
consistent with these warnings, but the run did not capture the precise native return edge or duration of each degraded
interval. Do not suppress them or change readiness semantics to claim a pass. The approved NO_WAITER cleanup fault path was
not exercised.

## Restoration and harness corrections

The [run start](m2t4memdiag1-checkpoint.txt) reset EFI variables. The initial baseline passed. Run cleanup
[deleted the overlay and verified the base/XML](m2t4memdiag1-final-restored-state.txt). A separate
[fresh-overlay start](m2t4memdiag1restore-start.txt) reset EFI again; the
[independent baseline/restoration](m2t4memdiag1-independent-restoration.txt) passed and deleted that second overlay.
Both debug3 and debug2 are now off. `run-disk.sh` refuses a test domain containing a TPM.

The initial debugger setup unnecessarily changed NET transport to LOCAL, causing Windows to select another network adapter.
The VM identity/SSH key were verified and its expected address restored only on the disposable disk. Commit `10a54e09`
preserves the existing transport. Optional unload now has finite service/unload waits; its
[PowerShell 5.1 parse and identity self-check](harness-t4-memory-bounded-teardown.txt) passed, then the real unload passed.
One verbose extra debugger listing was stopped; an overlapping attempt could not attach, and a loop expression was corrected.
The corrected final listing completed; the original coordinator snapshots all completed. All exploratory attempts remain
local alongside the raw run output. No host-wide configuration changed.
