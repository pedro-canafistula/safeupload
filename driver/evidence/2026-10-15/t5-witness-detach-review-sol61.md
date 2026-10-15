**Verdict: REVISE — the lifetime predicate is sound; the proposed spin-lock walk needs revision or a defensible latency bound.**

Reviewed clean `c001e83a`, read-only. Detach and binder retry are not implemented yet.

**Verified against source:** every live bound entry is registry-listed, and binding to this context’s witness occurs under `WriterLock`. Therefore the complete scan plus clear excludes a live entry needing the binding; a later binder must reread the pointer. The proposed skipped-allocation retry closes the two-check race, provided genuine allocation failure and Invalid remain terminal failures. See [binding](driver/SafeUpload.Minifilter/StageWriters.c:2621).

Reference accounting is consistent: transfer only the context reference, release it and any cache reference after both locks, and retain entry-owned references until destruction. Existing tentative binder decrements occur under `WriterLock` but cannot free the context-owned witness. Detach preserves Unknown/Invalid and publishes no synthetic End; [natural cleanup](driver/SafeUpload.Minifilter/StageWriters.c:2952) remains the End publisher.

No lock cycle found. `RegistryLock → WriterLock` already exists; existing paths also include `WriterLock → StateLock` and `WriterLock → SectionLock`. Releasing `SectionLock` before detach is essential. Contexts, entries and witnesses are nonpaged; the new helper/walk must remain resident. Restricting invocation to successful ordinary prune preserves batch-1 teardown, callback references and activation. No direct conflict found with batch-2/3; this does not accept their implementation or authorize activation.

1. **Medium — full-registry work at DISPATCH_LEVEL lacks an acceptable bound.**  
   [Design lines 20–30](driver/T5-SOP-WITNESS-DETACH.md:20) hold `WriterLock` throughout the walk. [Registry limits](driver/SafeUpload.Minifilter/Protocol.h:586) permit **20,480 entries**: roughly **2.6 million visits** across a 128-prune batch. Bounded storage does not establish short spin-lock holds; Microsoft’s [guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-spin-locks) specifies no longer than 25 μs. Excess latency is inferred, not measured.  
   **Required change:** specify and substantiate worst-case hold time, or move the walk outside `WriterLock` with equivalent serialization. One narrow option is to serialize the binder’s second check under `RegistryLock → WriterLock`, allowing the scan under `RegistryLock` alone and a short final WriterLock recheck/clear. Simply unlocking during the current scan is insufficient.

2. **Low — review provenance links are broken.**  
   The RCA target is absent from this checkout; line 50 resolves to `driver/driver/T5-VOLUNTARY-UNLOAD.md`.  
   **Required change:** provide a retained, resolvable RCA reference and correct the teardown link.

3. **Informational — `<4 B/cycle` remains unproved.**  
   Releasing the context-owned tail is the narrowest supported ownership fix. Attribution of ~34.5 B/cycle to `SwUl` remains inferred; live/Unknown history and other allocations remain.  
   **Required verification:** directly sample `SwUl` and run unchanged matched-pair resource/Verifier/restoration gates. Design acceptance cannot predict `T4PoolFlat` PASS.

No edits, builds or VM runs performed.