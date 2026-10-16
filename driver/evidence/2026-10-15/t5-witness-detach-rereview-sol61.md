**Verdict: ACCEPT WITH CONDITIONS — design acceptance only.**

Reviewed clean `77fc029f`, limited to the delta and previous findings. The counter and detach remain unimplemented.

1. **Informational — previous medium finding resolved at design level.**  
   **Verified:** binding has one publication site; [prune](driver/SafeUpload.Minifilter/StageWriters.c:4250) and [instance retirement](driver/SafeUpload.Minifilter/StageWriters.c:3983) are the only live-entry `Retired = TRUE` writes. [Listed history owns a reference](driver/SafeUpload.Minifilter/StageWriters.c:1348); shell destruction and compact-pool reset do not bypass retirement of bound history. No live unretire path found.  
   **Assessment:** CAS-winner-only increment and guarded retirement-only decrement cover the audited paths exactly once. Failure, Unknown, cleanup and cache replacement correctly contribute zero.  
   **Required:** implement those rules and production fail-closed violation handling: invalidate the witness, publish sticky tracking loss, refuse detach, never clamp. These are specified, not yet verified in code.

2. **Informational — no new lock-order or IRQL defect found; contention remains unmeasured.**  
   **Verified:** `RegistryLock → WriterLock` already occurs during [writer insertion](driver/SafeUpload.Minifilter/StageWriters.c:2812). The binder caller holds neither lock; no reverse acquisition was found. The proposed resident, allocation-free spin region is compatible with the [push-lock APC_LEVEL limit](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltacquirepushlockexclusive).  
   **Required:** retain the specified hold-time qualification and include concurrent CREATE/reclaim pressure. Another exclusive registry acquisition can increase CREATE contention; O(1) work alone does not establish the [25 μs spin-lock guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-spin-locks).

3. **Informational — reference ownership is consistent.**  
   The design transfers exactly one context reference, retains entry-owned references through retirement, and requires detach’s context/cache drops after both locks. Fresh-allocation losers release once. **Caveat:** the existing [tentative CAS-reference undo](driver/SafeUpload.Minifilter/StageWriters.c:2658) occurs inside `WriterLock`; it cannot be the final release while the context reference remains attached.  
   **Required:** verify these paths and skipped-allocation retry against the implementation; no ownership redesign is needed.

4. **Low — prior provenance-link finding is only partly closed.**  
   The teardown link is fixed. The [RCA link](driver/T5-SOP-WITNESS-DETACH.md:9) still targets an absent file in this checkout. Retention on `feat/driver-m2` is verified, including commit `7c960b47`.  
   **Required:** provide a resolving reference or include the retained RCA before delivery.

5. **Informational — verification plan is sufficient; resource success remains unproved.**  
   **Verified:** the sampler accepts `SwUl`; existing idle sampling precedes purge. The revised plan covers allocation/free/byte observations, wrap handling, errors versus absence, production-linked mutations, implementation review and unchanged qualification gates.  
   **Required:** execute that plan. Neither attribution to `SwUl` nor `<4 B/cycle` follows from design acceptance; the pre-purge idle endpoint and 64 KiB band must remain unchanged.

No edits, builds or VM runs performed.