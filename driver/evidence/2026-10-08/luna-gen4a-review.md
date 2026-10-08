# gen4a review — retire deleted sealed stage stream

**Verdict: REJECT** — one P1 fail-open. Review was limited to `git diff 840e6479 b085d577 -- driver/SafeUpload.Minifilter`; no build or VM used, and the worktree was not changed.

## P1 — sealed stage remains readable after service deletion

[`StageStream.c:1382-1387`](</home/victor/Work/safeupload-wt-gen4/driver/SafeUpload.Minifilter/StageStream.c:1382>) reuses the current sealed stream for a non-writer open; it does not reject a delete-pending backing. The worker only checks `DeletePending` when its 250 ms scan finds zero opens/file objects ([`StageStream.c:2320-2334`](</home/victor/Work/safeupload-wt-gen4/driver/SafeUpload.Minifilter/StageStream.c:2320>)). Scenario: after the owner closes its last handle, service `File.Delete` succeeds; before the next scan, the owner reopens the logical name. `StageCreate` hands out the still-open backing object and can serve the blocked bytes. The worker then sees the new open and leaves the stream available; an owner can keep it open or repeat this race. This defeats the promised end of the hand-back window.

The namespace/resource locks do prevent a new `StageCreate` from incrementing `OpenCount` between the worker’s zero-count check and `StageCloseBacking`; they do not serialize the service’s delete with a reopen before that scan. Fail closed by preventing opens of a sealed stream once its backing is delete-pending, with a design that also handles disposition racing the open.

## P2 — detached retired views still count as “mappings”

Retirement sets `View->Detached` ([`StageStream.c:2333`](</home/victor/Work/safeupload-wt-gen4/driver/SafeUpload.Minifilter/StageStream.c:2333>)), but [`SafeUploadProcessHasMappings`](</home/victor/Work/safeupload-wt-gen4/driver/SafeUpload.Minifilter/StageStream.c:3817>) returns true for any retained view, including detached ones. Scenario: a process stays alive after its only stage is retired; later `QUERY_OPEN`/`NETWORK_QUERY_OPEN` requests keep taking the slow/disallowed fast-I/O path at lines 3384-3389. This is a persistent performance false positive until unload, not a safety blocker.

## Other attack checks

- No post-retirement backing dereference found: retirement holds `NamespaceResource` then `Resource`; `StageCreate` takes the same locks. With zero file objects/open count and null section pointers, no user I/O path remains. Directory overlays skip detached current views; old-name tombstones retain stream pointers, but those paths use the retained name/version metadata, not its backing object.
- Rundown use is consistent with `StageDrain`: wait, close, reinitialize. Unload later drains the retired read-only stream without flushing a null backing, then performs its final rundown wait and null-safe close. Worker runs at PASSIVE_LEVEL and follows the existing namespace-to-stream lock order.
- `FILE_SHARE_DELETE` changes share compatibility, not granted delete access; the stated SYSTEM/service-only stage ACL keeps standard users from deleting it. For ordinary Windows `DeleteFile` semantics, Microsoft documents deletion-on-close and `FILE_STANDARD_INFORMATION.DeletePending` as true when deletion was requested ([DeleteFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deletefile), [FILE_STANDARD_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_standard_information)). This supports the polling check for `File.Delete`; exact NTFS behavior on build 19045 was not runtime-verified here.
