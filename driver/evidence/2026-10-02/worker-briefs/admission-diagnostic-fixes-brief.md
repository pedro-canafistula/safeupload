You are a Codex worker on the SafeUpload repo at /home/victor/Work/safeupload-staging (branch feat/staged-kernel-prototype, HEAD 0999edb, with UNCOMMITTED changes in the working tree). You fix review findings in kernel and Inspector code. You CANNOT build (the WDK is on a builder VM) and must not run any VM/virsh/ssh/scp/network command; the orchestrator builds and tests. Be extremely careful about compile correctness (warnings-as-errors, PREfast, DriverRecommendedRules, API validation; previous failures: wrong WDK identifier names, a 1.1 KB struct on the kernel stack).

## 1. Objective
Resolve the findings of the adversarial review driver/evidence/2026-10-02/admission-diagnostic-review.txt for the observe-only admission trace slice, applying EXACTLY the orchestrator decisions in section 3. Keep the slice strictly observe-only, feature-build-only and default-OFF.

## 2. Read
- driver/evidence/2026-10-02/admission-diagnostic-review.txt (all 28 lines).
- driver/evidence/2026-10-02/worker-briefs/admission-diagnostic-kernel-brief.md (the original spec) and admission-diagnostic-worker-notes.txt (what exists now).
- The working-tree diff: `git diff HEAD -- driver/SafeUpload.Minifilter driver/SafeUpload.Inspector`. Then StageStream.c around lines 280-520 (ring, ReadBatch, probe helpers), 1900-2010 (the two probe sites in StageAdmit), 2090-2200 (paging-write and section-sync observation); Communication.c ~574-660; Inspector main.c lines 30-45, 510-760; SafeUpload.Minifilter.vcxproj lines 50-62 (how the minifilter defines the feature macro) and SafeUpload.Inspector.vcxproj.
- Use grep -n and sed -n; never cat whole large files.

## 3. Decisions (implement exactly; do not re-litigate)
D1 [review BLOCKER, StageStream.c:439] KEEP the inline probe, with these mitigations: (a) probe only when the diagnostic is enabled AND the create is not by file ID AND the disposition is not FILE_CREATE AND the request does not set FILE_DIRECTORY_FILE AND the instance volume kind is local NTFS (reuse the existing volume-kind classification; skip network, removable-unsupported and unknown kinds; record a skip event/counter with a reason code instead); (b) keep FILE_READ_ATTRIBUTES-only access (attribute-only opens do not cause oplock breaks per MS-FSA 2.1.5.1.1) and add FILE_OPEN_REPARSE_POINT so the probed object is the request's own target; keep FILE_NON_DIRECTORY_FILE; (c) do NOT hold the diagnostic rundown reference across the lower FltCreateFileEx2 call: acquire it only to record the result afterwards (drop the record if the trace was disabled/shut down meanwhile), so Disable/Clear/unload never wait on a probe that is blocked; (d) the probe handle and file object must still be released on every path; (e) update the code comment to state plainly that the probe is the only extra I/O, runs only when explicitly enabled on the disposable test VM, and can wait like any lower create.
D2 [MAJOR 1983, 450, 1927] Covered by D1(a)/(b): skip rather than guess for file-ID opens, FILE_CREATE, directory opens and unsupported volume kinds. Record skips in counters.
D3 [MAJOR StageStream.c:385] REMOVE the synchronous FltGetStreamContext/FltGetInstanceContext calls from the paging-write and section-sync hooks. Report stream-context presence as a new sentinel meaning "not queried" (add a clearly named constant; update Inspector output to print "not_queried"). Do not add any lookup that could take a lock in those hooks. If the instance volume kind is needed in those hooks, take it from a source that needs no context lookup, or report it as unknown.
D4 [MAJOR StageStream.c:375] NO code change: slice 1 has no admission-record table, so AdmissionRecordState stays "not_tracked". Mention this in the new notes file as a revised slice contract.
D5 [MAJOR Inspector main.c:38] Remove the unconditional `#define SAFEUPLOAD_STAGING_PROTOTYPE 1` default. Make the Inspector's feature commands/structs compile only when the build defines SAFEUPLOAD_STAGING_PROTOTYPE=1, by adding to SafeUpload.Inspector.vcxproj the same conditional ClCompile PreprocessorDefinitions entry the minifilter project uses for the MSBuild property SafeUploadStagingPrototype=true (copy the pattern at SafeUpload.Minifilter.vcxproj:55-56; keep every other definition). A normal Inspector build (property unset) must be identical to the pre-slice behavior: no admission-trace commands, no feature structs from Protocol.h.
D6 [MINOR StageStream.c:310] Fix ReadBatch so the cursor never advances past a slot whose sequence is reserved but not yet published: stop the batch at the first uncommitted sequence (leave the cursor there) or account for it explicitly in a counter; add a short comment on the commit ordering you rely on.
D7 Keep everything the review VERIFIED intact (guards, MmDoes only in the PASSIVE_LEVEL probe, hooks returning existing results, size/buffer validation, rundown/unload order, scratch-buffer reply path in Communication.c).

## 4. May edit
driver/SafeUpload.Minifilter/{StageStream.c, Stage.h, Filter.h, Filter.c, Protocol.h, Communication.c}, driver/SafeUpload.Inspector/main.c, driver/SafeUpload.Inspector/SafeUpload.Inspector.vcxproj, and the NEW file driver/evidence/2026-10-02/admission-diagnostic-fix-notes.txt (at most 60 lines: per decision what you changed with file:line, the revised slice contract, anything unresolved, where a second reviewer should look hardest). Do not rewrite admission-diagnostic-worker-notes.txt or any other evidence file.

## 5. Forbidden
Editing any other file; git commit/push/reset/clean/checkout/stash; deleting anything; VM/virsh/ssh/scp/network; disabling any warning/validation/optimization; adding behavior beyond the decisions; changing normal-build code paths.

## 6. Steps
1. Read, then apply D1-D7. Keep C and style identical to the surroundings (comment density, naming, SAL, PAGED_CODE/alloc_text, error handling). No private APIs or internal offsets.
2. Self-review: IRQL at every changed hook, reference counting of the probe handle/file object on every path including the new early skips, unsigned/signed comparisons, SAL and PAGED annotations matching between declaration and definition, size/offset C_ASSERTs still valid after any struct change (update them if you add a field), no new stack buffers over a few hundred bytes (PREfast C6262 fails the build), every new symbol declared and defined under the same guard, normal Inspector build unchanged.
3. Write the notes file.

## 7. Done when
D1-D7 are applied; `git diff --stat HEAD` shows only allowed files; the notes file exists.

## 8. Final message (at most 150 words)
Per decision: done or not and where; compile-risk spots you are least sure of; anything you could not do; open questions. No pasted code.
