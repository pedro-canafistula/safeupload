**REVISE**

Reviewed independently with Sol 6.1 xhigh at `d97b0ccd`. The settled copy and idle-rename semantics are respected. The main blocker is compatibility with the newer T8 metadata decision. No files were edited; no builds, tests or VM rows were run.

1. **High — Incoming fallback lacks the approved original-move metadata binding.**

   **Evidence:** The design delegates directory metadata to native CREATE inheritance ([T6:25](/home/victor/Work/safeupload-review-t6/driver/T6-DIRECTORY-MOVES.md:25)) and promises ordinary per-file staging after fallback ([T6:46](/home/victor/Work/safeupload-review-t6/driver/T6-DIRECTORY-MOVES.md:46)). But the current owner decision requires the metadata produced by the same caller’s original operation without SafeUpload ([plan:28](/home/victor/Work/safeupload-staging/driver/POST-MVP-PLAN.md:28)). Its adopted memo explicitly says forced copy fallback cannot substitute destination-parent defaults for an original same-volume move’s security ([memo:52](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-16/t8-metadata-contract-sol61.md:52)).

   A restrictive source tree moved under a permissive parent can retain its descriptors natively but inherit broader access through recursive CREATE/copy. Existing allocation binds destination-writer metadata; it carries no original folder-move/source-child provenance ([allocator:12](/home/victor/Work/safeupload-review-t6/agente/SafeUpload.Agent.Service/Interception/StagedBoundTransferAllocator.cs:12), [binding:5](/home/victor/Work/safeupload-review-t6/agente/SafeUpload.Agent.Service/Interception/StagedAllocationBindingV23.cs:5)).

   **Required change:** Specify the exact source-object, original-operation and caller-authority binding needed to preserve the approved metadata result, or hold affected publication when that proof is unavailable. Tracing inheritance differences is insufficient. This requires neither a tree transaction nor a source-retention promise.

2. **High — The pre-forward directory classification algorithm remains unresolved.**

   **Evidence:** The design requires actual base-object classification despite omitted or contrary directory flags ([T6:36](/home/victor/Work/safeupload-review-t6/driver/T6-DIRECTORY-MOVES.md:36)), but refers to post-CREATE classification without defining the safe sequence ([T6:94](/home/victor/Work/safeupload-review-t6/driver/T6-DIRECTORY-MOVES.md:94)). Existing admission branches on `FILE_DIRECTORY_FILE` ([StageStream.c:8859](/home/victor/Work/safeupload-review-t6/driver/SafeUpload.Minifilter/StageStream.c:8859)); actual directory checking occurs after CREATE ([StageWriters.c:2811](/home/victor/Work/safeupload-review-t6/driver/SafeUpload.Minifilter/StageWriters.c:2811)).

   [FltIsDirectory requires an already-opened object](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltisdirectory). Also, [NtCreateFile documents](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile) that NTFS began honoring `FILE_NON_DIRECTORY_FILE` for `$INDEX_ALLOCATION` only in Windows 11 24H2. The qualified Windows 10 target cannot rely on that flag.

   **Required change:** Define what is rejected before forwarding, how an unflagged target is proved to be the same plain directory, and how that proof survives namespace changes. Cover original attribute/stream selectors, EA-bearing CREATEs, reparse traversal and scheduled deletion. Post-CREATE verification may confirm a safe admission; cancellation cannot retract prior filesystem effects. This is an unresolved proof, not a demonstrated implemented T6 exploit.

3. **Medium — Incoming success must explicitly depend on T8’s grouped `Zone.Identifier` publication.**

   **Evidence:** The owner requires inspected MOTW to become public together with its file ([plan:33](/home/victor/Work/safeupload-staging/driver/POST-MVP-PLAN.md:33)). T6 references T8 generally, while D01 says “all EA/ADS…” attempts are refused ([T6:123](/home/victor/Work/safeupload-review-t6/driver/T6-DIRECTORY-MOVES.md:123)). Current staging rejects every named stream ([StageStream.c:2421](/home/victor/Work/safeupload-review-t6/driver/SafeUpload.Minifilter/StageStream.c:2421)).

   **Required change:** Distinguish refused **directory streams** from eligible **file `Zone.Identifier`**. Make successful downloaded-file/folder moves depend explicitly on the reviewed T8 transaction. Add late/post-close MOTW writes, interruption and restart controls proving no public interval without required provenance. Dropping or refusing MOTW cannot satisfy a successful move row.

4. **Low — A smaller current-locator design appears sufficient.**

   **Evidence:** Descendant heads key on **volume root**, immediate parent identity, case mode and leaf ([journal:13](/home/victor/Work/safeupload-review-t6/agente/SafeUpload.Agent.Service/Interception/StagedDestinationCommitJournal.cs:13)). Those keys survive subtree rename. The source already derives a diagnostic locator from an identity-checked parent handle ([StagedDestinationDirectory.cs:21](/home/victor/Work/safeupload-review-t6/agente/SafeUpload.Agent.Service/Interception/StagedDestinationDirectory.cs:21)).

   Consequently, retaining relocation mappings while any terminal history depends on them ([T6:88](/home/victor/Work/safeupload-review-t6/driver/T6-DIRECTORY-MOVES.md:88)) is not established as necessary.

   **Recommended change:** Evaluate checked current-parent ancestry plus a namespace-revision cache, preserving immutable history and exact durable rename intent/result records. Ambiguous path-only records remain held. This could remove permanent relocation-chain dependencies without changing owner semantics.

**Conditions**

- **Close findings 1–3 before implementation acceptance.** Preserve the settled per-file inspection and ordinary caller source-removal behavior.

- **Prove the idle census and fence coverage in the coherent implementation.** The categories at [T6:56](/home/victor/Work/safeupload-review-t6/driver/T6-DIRECTORY-MOVES.md:56) are appropriately broad: custody-private bytes, borrowers, writer/SOP/mapping lifetime, factories, queued work, permits, delete reservations, receipts and unfinished historical recovery all count. The fence-before-count sequence is coherent. Supply a producer/transition map proving reservation before admission, terminal release once, complete startup reconstruction, and conservative unknown ancestry. Existing writer accounting explicitly skips directories ([StageWriters.c:1591](/home/victor/Work/safeupload-review-t6/driver/SafeUpload.Minifilter/StageWriters.c:1591)); security mutation currently returns directly ([StageStream.c:10048](/home/victor/Work/safeupload-review-t6/driver/SafeUpload.Minifilter/StageStream.c:10048)). These require explicit integration, including aliases/by-ID, mappings, delayed cleanup and ancestor mutations.

- **Preserve the proposed lifetime and lock rules.** I found no additional structural lock-order or exactly-once contradiction in [T6:69](/home/victor/Work/safeupload-review-t6/driver/T6-DIRECTORY-MOVES.md:69) and [T6:96](/home/victor/Work/safeupload-review-t6/driver/T6-DIRECTORY-MOVES.md:96). Implementation review must verify no locks across RPC/native waits, continuation progress through its own exclusion, draining-post uncertainty, mandatory local rundown, and no replay of a completed rename. Existing registry rename bookkeeping is cache maintenance, not this authority.

- **Keep T5 identity and history separate.** Preserving descendant head keys/floors is correct. Raw receipt paths must remain immutable: validation compares them with stored transfer paths ([journal:1841](/home/victor/Work/safeupload-review-t6/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:1841)). Every live path consumer must use checked current ancestry; the existing path-based claim scan ([journal:3136](/home/victor/Work/safeupload-review-t6/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:3136)) cannot remain authoritative after relocation.

- **Run native traces first, in this order:** installed PS 5.1 and real Explorer fallback against same-volume, real cross-volume and induced `NOT_SAME_DEVICE` controls; original-move versus fallback security/metadata; Windows 10 directory/selector/EA/reparse admission; downloaded-file MOTW ordering; then busy-status translation and idle-rename behavior. Record actual operations and results. Stop a fallback claim if the caller does not perform it.

- **Keep acceptance gates distinct.** Component/static verification, the coherent pre-boot lifetime review, and matched-pair D-row qualification remain separate requirements. This review establishes none of those runtime results.