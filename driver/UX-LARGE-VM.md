# T9 large-file Windows qualification list

Run only through Claude's existing lab workflow on `SAFEUPLOAD_DEBUGGEE=win10-debug3` (19045.2965), disposable
qcow2/EFI reset/no TPM, test signing/Secure Boot off. Keep win10-debug2 off. Applications and native actors run as
standard user **t5actor**; only the existing observer/service/setup legs use their approved administrative identity.
Use the first free approved builder, no builder work during timing-sensitive T4 rows. Preserve the first failure;
stop on a required failure, changed baseline or repeated identical failure. Do not weaken an assertion or deadline.

Before boot: fresh committed bundle source; two feature WDK Debug/Release builds, PREfast + ApiValidator 0/0,
imports PASS on both artifacts; agent feature Debug/Release × user/SYSTEM four-leg matrix with complete discovery,
execution and no skips; Windows PowerShell 5.1/native-signature gates for any harness used. Source review acceptance
is separate from these gates. Build/package/receipt hashes must identify the matched pair.

The matrix must include `StagedLargeFileNativeTests` (three rows: manifest-before-grant exact replay and both
unknown-create refusal/retry paths) and `StagedLargeFileTests`. The Linux diagnostic does not execute the native class.

Every row below runs in **ordinary, runtime-Verifier, and boot-Verifier** modes. Use a fresh label per mode/attempt.
Observe destination bytes independently throughout, retain original/final hashes, and require ForbiddenByteCount=0,
no Verifier hit, no false Ready/cleared Unknown and no leaked live lease/refund. Record the exact SID, transfer,
stage object, destination generation, policy fingerprint, grant capacity, ledger debits and outcome. A safe refusal
is not success for a row requiring publication. Restore and verify the baseline separately after each run disk.

| Row | Exact scenario and expected result |
|---|---|
| T9L01 | New clean `.txt`, `.docx`, ZIP32 `.zip` containing plaintext, each 64 MiB/512 MiB/2 GiB payload: **nine cases**; publish complete exact bytes under explicit sufficient storage/inspection settings. Record foreground/lifecycle time, seed/capture/scan/copy phases, service + worker peak commit/working set and peak physical private allocation. |
| T9L02 | Same nine cases with the sole CPF at decoded EOF (Word final text node, ZIP final member): block entire version; original destination absent/unchanged; verified named hand-back where export is allowed; owner-only tray reason. |
| T9L03 | Seeded existing-file edit for the same nine format/size combinations using FILE_OPEN and FILE_OPEN_IF: **18 cases**; preserve caller rights/shares/metadata, complete seed and full inspection, publish exact clean final bytes. Measure cold and warm seed cost. No timeout/refusal counts as successful editing. |
| T9L04 | Seed without caller read/export authority: refuse full-file hand-back/justification; preserve exact private custody and original caller grants. SYSTEM must not confer read authority. |
| T9L05 | New plain files at 16 MiB−1, 16 MiB, 16 MiB+1 and 64 MiB with sufficient large-mode capacity: all four clean versions publish; no legacy-cap refusal. |
| T9L06 | Configure per-SID B=4*C+metadata for C=32 MiB; ordinary writes at C−1/C/C+1 (**three cases**). First two succeed. C+1 returns disk-full/resource refusal; its clean/empty prefix is permanently blocked, original destination unchanged, no justification. Repeat append and write-through variants. |
| T9L07 | Set EOF above C; allocate above C; extending section/mapped write above C (**three paths**). Resource refusal without livelock; sticky v31 failure survives cleanup; no prefix publication. Successful ≤C mapping still uses all original lifetime/inspection gates. |
| T9L08 | Two standard-user SIDs: t5actor consumes its SID allowance, second actor saves a small clean file while total/headroom allow. First user's denied growth/seed does not set global Unknown or consume the second user's allowance. Repeat after service restart and reboot; verify exact ledger reconstruction. |
| T9L09 | Total/headroom boundaries: exact reservation, one byte short, floor greater than free bytes, very large configured floor with an outstanding reservation. No arithmetic wrap or over-admission. Record physical allocation-unit rounding; include a large-cluster NTFS fixture if available. |
| T9L10 | Disk-full/quota injection after reservation at each of seed, snapshot, metadata flush/rename, publication temporary, hand-back (**six phases**). Exact failed temp cleanup or explicit retained charge, actionable reason, original destination unchanged. Native ERROR_DISK_QUOTA_EXCEEDED/STATUS_DISK_QUOTA_EXCEEDED must set sticky failure. Free space then retry unfinished bookkeeping only. |
| T9L11 | Kill service/reboot at intent-before-create, create-before-identity, identity-before-seed, seed-before-manifest, manifest-before-grant, GrantIssued-before-companion, companion-before-reply, snapshot-created/bound/copying and publication-after-native-rename-before-bookkeeping (**11 points**). No uncharged orphan, no filename deletion, no replay of completed mutation. Unknown identity remains held; exact unissued failed seed can retire/retry. |
| T9L12 | Parser timeout, crash, native allocation failure, memory limit, ignored cancellation and attempted child process (**six cases**): whole operation incomplete; kill/drain proven, no late approval, source read-only, Core slot/snapshot charge retained until actual process/reader exit. The second SID still obtains bounded parser service. |
| T9L13 | Huge XML attributes/name tables/relationships, ZIP central names/count/expansion, giant PDF page/XMP/resources and corrupt/encrypted tails: fail fully with bounded aggregate service/worker memory. Sensitive prefix plus corrupt tail yields no partial clean result. Retain all original coverage assertions. |
| T9L14 | ZIP32 text >16 MiB succeeds; CRC/length/final-marker/trailing-data faults block. Nested seek member 8 MiB+1, depth >3, metadata >4 MiB, ZIP64 and 7z explicitly refuse; never label those refusals successful supported publication. |
| T9L15 | Snapshot read lease deliberately survives publisher timeout; retry capture while live must refuse. Close publisher only: no refund. Close final reader/process: exact cleanup and content refund, metadata charge retained. Repeat restart with recorded snapshot, replacement-at-path, hard link and reparse injection; never delete replacement/unknown object. |
| T9L16 | Deterministic seed access/sharing/size/deadline failure before manifest, then same stable allocation intent: exact cleanup, no permanent lost SID capacity, no double debit/new authority. Crash uncertainty without an exact identity stays charged. |
| T9L17 | Corrupt/writable/wrong-owner/reparse/multiple-link/oversized reservation record or directory: refuse before parsing/ACL hardening; retain evidence and bytes. Existing unrelated private files and unreserved legacy journals prevent opt-in, with diagnostics. |
| T9L18 | Old driver + large-mode agent; short/oversized/wrong-version capability reply: NotReady, no large allocation/publication. Disable mode with outstanding ledger: refuse downgrade and explain re-enablement/recovery. Old-service downgrade remains an unqualified T14 boundary. |
| T9L19 | Clean-prefix disk-full save including zero bytes: tray explicitly says not enough staging space; returned partial bytes clearly belong to failed save, no override action. Disk-full hand-back shows custody failure, not a false verified copy. Notifications go only to the original SID/session. |
| T9L20 | Concurrent same-SID Word/temp/Explorer saves and two-SID long seeding: record the current conservative admission/queue refusal and latency. This prototype limitation must be resolved before claiming everyday T9 UX. Run Notepad, Explorer copy and a real Word direct save after budget release; byte/privacy/namespace regressions remain required. |
| T9L21 | Repeat many complete/blocked/failed saves, restart, exhaust metadata replacement/negative-receipt headroom and reclaim only exact authorized objects. Content charges return; retained records stay charged; metadata cannot grow beyond its envelope or starve unreserved recovery work. |

After the focused rows pass, run all affected existing T4/T5/T7/T8/T10 namespace, sharing, empty, delete, hand-back,
policy/justification, publication/recovery and raw-byte rows on the matched pair, plus the required milestone matrix.
Keep BLOCK windows serial. Finish with independent adversarial review of the working pair and separate restoration.
Any failed clean large/seed/concurrent UX row leaves T9 open even if its fail-closed privacy observer passes.
