# Independent T5 empty-file and public-delete design review

Review verdict: **ready for implementation; no remaining substantive design blockers.** This is a source-only design review. No product code, build, VM, or runtime qualification was performed.

Source pin: `a152474f942928bf1dddc9b3b7c8b1366ac947b5`; the reviewed T5 design and component-classification documents include the current owner clarifications in the worktree. Product source is unchanged from baseline `c8fa2f90be66346cb467a8d025fa4dd12cc92f42`.

The checked public backend and app-facing proxy bind authorization to the original effective subject and exact public identity (`driver/T5-DELETES.md:111–156`). The shared per-destination turn ends after publication plus durable `Published`, or public disposition plus durable `DispositionAccepted`; asynchronous last-close completion holds a durable reservation rather than a lock/thread (`:214–234`). Authorized ordinary `FALSE` cancels all still-provisional barriers and tombstones for the same object, while preserving scheduled per-handle on-close requests (`:177–201`). The component classification agrees on the short-turn/reservation split (`t5-empty-public-delete-component-classification.md:33`).

These disposition rules match the existing source model and control evidence: ordinary disposition is stream-wide while scheduled on-close state is per handle (`driver/SafeUpload.Minifilter/StageStream.c:4688–4701, 5199–5204`); the real NTFS control shows a second DELETE handle can clear ordinary disposition before or after the first handle's cleanup (`driver/evidence/2026-10-11/t5-ntfs-disposition-control-1011.txt:4–5`). The design also preserves the private scheduled-on-close admission assertions, including Win32 303 (`driver/T5-DELETES.md:69–77`).

The design remains unimplemented. The specified WDK/PREfast/ApiValidator checks, exact agent matrix, native delete orderings, Notepad runs, and VM-restoration verification remain qualification gates; the NTFS control does not qualify product behavior.
