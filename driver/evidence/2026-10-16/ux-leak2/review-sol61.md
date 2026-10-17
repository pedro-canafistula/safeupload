# Independent source review

Reviewer: gpt-6.1-sol, xhigh, separate read-only agent, 2026-10-16.

Decision on lifetime/lock candidate: ACCEPT WITH CONDITIONS. Reviewer checked
lookup hit/miss/set loser, active lease versus exclusive prune/fence, last-user
release/recheck cursor reset, bind failure, tracking-loss fallback, diagnostic
invalidation and worker reference releases. No concrete kernel correctness
blocker was found. Worker/entry pins substantiate nonfinal cache/witness drops.

Requested harness corrections: same-owner probes as well as child probes;
PS5.1 decimal uint32 casts; retained child process ownership through join,
abort and kill. Implemented; follow-up disposition recorded in the local raw
review log. New production getter shim added after the initial review. Final follow-up
required publishing corruption GlobalUnknown before releasing WriterLock;
implemented. Process joins after kill are bounded, unconfirmed termination
fails the control and has an explicit receipt.

This review does not establish Word's 40-second cause or that this candidate
fixes it. Native Filter Manager/internal-lock schedules and precise deny-gate
attribution remain open, together with required Windows builds/static/import,
PS5.1 and unchanged 10k qualification gates. Reviewer inspected host receipts;
review acceptance is not independent execution or native qualification.
