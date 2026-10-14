# Review of the Unknown first-origin diagnostics af95f33f — Sol 6.1 xhigh (2026-10-14)

Reviewer: `gpt-6.1-sol`, `reasoning_effort=xhigh`, read-only, web search enabled (Codex session `01a13a96-ff93-7700-aa49-bb3981753648`). Verbatim final report; checkout paths shortened.

**ACCEPT WITH CONDITIONS** for inclusion of af95f33f in the next dormant Verifier boot. No blocking source defect found.

1. **Medium — delivery verification remains pending.** The worker report leaves WDK and agent gates outstanding. **Required:** fresh normal/feature × Debug/Release WDK builds, PREfast/ApiValidator at 0 warnings/errors, complete agent matrix, and matched artifact hashes before boot. The recorded readiness stop still applies.

2. **Low — controls miss conditional Unknown transitions.** [unknown-origin-selfcheck.py:145](driver/scripts/t5/unknown-origin-selfcheck.py:145) inventories literal state writes, missing `PrepareActivation(..., TRUE)` at [StageWriters.c:5552](driver/SafeUpload.Minifilter/StageWriters.c:5552). Removing the preceding instrumented setter at line 2071 would escape these checks. **Change:** add a mutation control for that dependency. Nonblocking: every current TRUE call has an instrumented predecessor. Layout, unsigned JSON, 64-bit counters and proxy-bound tests cover the main regressions.

3. **Informational — behavior and allocation checks are sound.** [StageWriters.c:870](driver/SafeUpload.Minifilter/StageWriters.c:870) adds resident CAS operations on nonpaged state; Unknown decisions, coverage sequencing and scheduling remain unchanged. Changed DISPATCH paths add no lock, wait or allocation. The status query adds an existing chunked SectionLock scan at APC-or-lower. The [padding assertion:197](driver/SafeUpload.Minifilter/StageWriters.c:197) preserves named allocations and compact-pool stride. **Required change:** none.

4. **Informational — origins are complete, with attribution limits.** Both global setters, direct entry mutations and SOP marker mutations record origins; [deferred forwarding:6441](driver/SafeUpload.Minifilter/StageWriters.c:6441) and [census fallback:7928](driver/SafeUpload.Minifilter/StageWriters.c:7928) preserve attribution. Sites identify mutations, sometimes propagation rather than the initiating failure; they contain no object/volume identity. **Required capture:** retain agent counters alongside full admission/per-instance receipts and delivered source to investigate another boot10/12 failure.

5. **Informational — feature ABI matches and rejects mismatches.** Appended offsets 288–300 and size 304 match; driver buffer checks, agent returned-length/StructSize checks, proxy bounds and JSON types are correct. Builds are **not literally layout-identical**: the normal driver retains its unused 136-byte prefix and omits command 12; both agent builds use the feature mirror. This is existing gating, not a new regression. **Required change:** none.

Read-only review; no edits, builds, tests or VMs run.