# T4 failed-run diagnosis — 2026-10-11

Status: read-only diagnosis; no product fix or retry. The owner reply requested after repeated identical failures is pending.
Run `m2t4boot10k1011a2` used `m2-driver5-t11` (`60fecdbc`) and agent `t4-af1`
(`970239a328b11878a5131ee022d7e671644aae5c`). It remains **FAILED**, with 8,740 of 10,000 attempts passing.

## What the retained output establishes

The [raw service events](m2t4boot10k1011a2-service-events.txt) contain exactly four failed **private journal manifest** replacements,
all `StagedDestinationFile.CommitHandle` / native Win32 error 5. These stacks identify the destination as a journal manifest,
even though the generic exception text says “destination entry.” They are not failures of the public-file rename at that stack frame.
Sort events by `RecordId`; guest wall time is not a reliable host-duration measure.

| RecordId (raw line) | Transfer | Failed update | Subsequent observed symptom |
| --- | --- | --- | --- |
| 33983 (2451) | `26140ba0-d0ae-455a-9fa3-363ea2279fdd` | Publishing → Released | 845 allocation errors, “Publication or rename currently holds this destination,” first RecordId 33988 |
| 34686 (1750) | `c734c4a6-b77f-4e02-a1cc-8104d9f5a71d` | BeginHandbackAttempt | First of two missing blocked-file hand-backs |
| 34991 (1449) | `266cb9c7-bcb4-4bcf-afa8-c5ed0938c4ef` | Publishing → Released | 413 “The rename destination is busy” errors, first RecordId 34994 |
| 36115 (327) | `026eb05c-c524-46a8-b0af-a9e03e339a6f` | BeginHandbackAttempt | Second missing blocked-file hand-back |

The [10,000 cycle records](m2t4boot10k1011a2-cycles.jsonl) independently report:

- 845 same-name access denials, cycles 3245–9997, all `resave`, naming `C:\Protected\t4\same-5.txt`.
- 413 rename sharing violations (`Win32=32`), cycles 6699–9995, all `replace`.
- Missing hand-backs at cycle 5632 (`mapped`, blocked) and 9310 (`new`, blocked), each after its 120-second wait.

The counts and event order support the journal-reservation cascade. The failed manifests were not exported before the throwaway
disk was deleted, so exact transfer-to-destination associations and the identities of the four residual stage files are unproven.
Do not present those associations as directly observed.

## Why the reservation persists in the tested source

All line numbers below refer to agent commit `970239a328b11878a5131ee022d7e671644aae5c`, not the newer working tree.
Sources are under `agente/SafeUpload.Agent.Service/Interception/`:

- `StagedTransferPublisher.cs:309–310` commits the native public rename before `:344–346` records Released. Both publication
  failures reached the latter call. The public commit therefore completed before the private bookkeeping error.
- `StagedTransferJournal.cs:941–966` atomically replaces the manifest. A failed replacement leaves the preceding durable Publishing
  state. `:818–841` classifies that state as a destination reservation; `:133–136` refuses new allocation and `:522–524` refuses
  rename into a reserved destination.
- `MinifilterInterceptor.cs:566` skips every non-Sealed entry except its preceding cleanup branches. Its exception path at
  `:581–600` only retains Sealed/Inspecting/Approved. It neither completes nor reconciles the failed Publishing entry on later iterations.
- `StagedTransferJournal.cs:863–905` already has publishing reconciliation, but `MinifilterInterceptor.cs:628–629` invokes it only
  at subsystem initialization. Restarting was not part of this one-boot gate and would not satisfy it.
- `StagedTransferJournal.cs:647–664` must durably begin hand-back before `StagedTransferPublisher.cs:627–629` copies it to the owner.
  The two failures occurred before that copy; they are distinct from the two publication reservations.

The current working tree still has the same Publishing skip/final-transition structure, at
`MinifilterInterceptor.cs:1180`, `StagedTransferPublisher.cs:390–392`, and `StagedTransferJournal.cs:2853–2879`.
The later T5 destination-head component is not yet connected to this live path.

## Limits and next diagnostic work

The underlying reason for native error 5 is **not established**. The service's journal readers already share DELETE
(`StagedJournalFile.cs:29–30`), and Windows private temporaries request FullControl (`StagedTransferJournal.cs:975–977`),
so neither a missing DELETE share on those readers nor a missing DELETE request on those temporaries explains these logs.
Do not loosen ACLs, share modes, or checks on that assumption.

After the owner's reply, a focused reproduction must capture the failed manifest and temporary identities, attributes/ACLs,
requested access, native rename result, relevant driver denials, and transfer/destination binding before restoration.
It must also prove recovery of a successful public commit whose durable final update fails, without republishing older bytes or
reporting release/cleanup without durable evidence. Any security or failure-policy change requires the stipulated design review
and owner decision. The harness must stop promptly on repeated identical failures and retain the reason.

The [original verdict](m2t4boot10k1011a2-verdict.txt), zero-residual assertions, raw-observer regressions and final-pair rerun remain
unchanged. The [separate restoration check](m2t4boot10k1011a2-independent-restoration.txt) passed; no VM is running for this diagnosis.
