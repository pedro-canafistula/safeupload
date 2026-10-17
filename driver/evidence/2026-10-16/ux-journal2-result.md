# Terminal recovery manifest-read regression

Base: `83bceea2496ba61511ccf0dfba07282a7fc1d809`. Delivery branch: `ux/journal`;
commits are in `.scratch/ux-journal2.bundle`, with the source worktree's Git unchanged.

The `ux-m4-diag` Windows result supplied by the owner reports two failures of
`Pending_publication_ACK_does_not_suppress_justified_stage_last_close_cleanup`
(`loseAckReply=false/true`): eight extra manifest reads over eight terminal passes.
The terminal fast path called `ArchiveCompletedAsync`, which freshly rereads the
manifest even when the bound entry is ineligible for archival.

Remove that call from the terminal recovery projection. The maintenance pass still
finds eligible unbound terminal records and performs all fresh exact-state checks
before archival. Bound receipt recovery bypasses this terminal fast path as before;
its pending ACK, retry deadline and durable receipt remain independent. No archive
format, eligibility, retention, generation barrier or receipt-authority check changes.
The failing Windows test and its assertions are byte-for-byte unchanged.

Four added portable cases cover Blocked/justified Released and both recovery overloads:
eight passes cause zero additional manifest reads, archival writes or disposals;
maintenance then archives the record, restart recovers its exact receipt, and the
next allocation advances its generation. All four fail against the original fast
path (expected reads 1, actual 2) and pass after the fix.

Focused Linux feature Debug and Release: **61/61 pass each**, zero skipped cases,
zero build warnings/errors. Includes both original 10k scaling controls, archive
corruption/restart/retention/receipt controls and worker retry controls. Allocate at
10k: 1.30–1.46 ms; seal: 2.40–7.43 ms. Tests use the serial in-process xUnit runner
because the sandbox does not permit the standard host's local socket. Raw before/
after logs and runner remain under `.scratch/ux-journal2/`; counts, unchanged-test
hashes, artifact hashes and timings: [controls](ux-journal2-controls.json).

These are focused component results. The native Windows invariant and full Windows
matrix were not rerun locally; they remain the delivery checkpoint. No VM action or
staging activation was performed.
