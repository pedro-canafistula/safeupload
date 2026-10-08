# Staged writes: design summary

How the MVP driver stages, seals and publishes writes to protected folders. Status, gate results and known issues are in
[MVP-PLAN.md](MVP-PLAN.md). The full design history (decisions, slices, probes, reviews) is preserved under the git tag
`mvp-history-2026-10-08`.

## Components

- `Filter.c` registers the operation dispatcher; `StageStream.c` owns the upper stream, the namespace registry, the cache, sections and the
  retirement worker; `StageProtocol.c` carries allocation, seal, namespace-transaction and publication-permit messages; `StageSecurity.c`
  keeps the original caller's access checks; `StageDirectory.c` merges private names into directory listings; `StageWriters.c` tracks
  pre-scope writers, aliases and admission (Activating, Free, Protected).
- `SafeUpload.Agent.Service` allocates and journals each transfer, inspects the sealed bytes, publishes approved versions and hands blocked
  versions back.

```mermaid
flowchart LR
    W[Writer at the original destination path] --> U[Owned upper stream and cache]
    U --> B[Private NTFS version, service-chosen GUID name]
    B --> S[Retire sections, close write access]
    S --> I[Journal seal, inspect immutable snapshot]
    I --> P[Authenticated approved publication]
    P --> D[Destination file]
    I --> H[Blocked: hand-back copy to the requestor]
```

## Admission and identities

- A protected create succeeds only after the original token's access checks and a flushed service `Allocated` manifest. The service chooses
  the private basename and ACLs; the kernel opens that backing noncached with exclusive data sharing while it is mutable. A disconnected
  service cannot authorize new protected writes.
- The upper file object stays on the original volume with SafeUpload's own FCB header, resources and section object pointers; fast I/O is
  refused; paging I/O to the backing uses separately allocated callback data and partial MDLs over the original request's pages.
- Identities: destination = normalized path plus a durable, monotonic `DestinationGeneration`; version = service transfer GUID, one upper
  stream, cache and backing per version; open capability = the `FILE_OBJECT` bound to its version, so duplicated or inherited handles keep
  their version. Hard links are alias entries of one destination identity, not separate publication rights.
- **Bounded namespace:** versions and process references are retained until unload, at most 128 stage streams per boot and 16 MiB per
  version; exhaustion fails closed. Supported rename is a two-slot transaction on the same volume (at most 16 moves per version); renames from
  outside into a protected folder are refused.

## Lock order and the retirement gate

**Lock order:** namespace resource, then upper stream resource. Reads, writes and size changes serialize on the stream resource;
cache/modified-writer callbacks use a separate paging resource; generated backing I/O holds rundown until lower completion. The service is
never called from paging completion.

CLEANUP removes share participation and uninitializes the file object's cache map; it never seals. A 250 ms worker retires a version while
holding the namespace then stream locks, and **every condition must succeed, in this order**:

1. No open share participants, and `MmCanFileBeTruncated(Sections, NULL)` reports no user mappings, section references or images.
2. Flush the owned cache and the backing, purge the owned cache, then require all cache, data and image section pointers to be NULL and the
   upper file-object count to be zero.
3. Drain paging rundown references and flush the backing again.
4. Close the last kernel write handle on the backing, mark the version read-only and reopen it read-only (a failed reopen keeps new opens
   blocked and retries).
5. Obtain the durable service seal acknowledgement (idempotent across reconnects); only then is the version `Sealed`.

The all-object condition favors correctness over save latency and must not be replaced by a writer or section counter. Once the service has
deleted a blocked version's stage file, the driver closes the read-only backing within one worker pass when nothing holds the version and
refuses new opens of the delete-pending stage (`STATUS_DELETE_PENDING`).

## Publication and recovery

- Service states: `Allocated -> Sealed -> Inspecting -> Approved -> Publishing -> Released`, with `Blocked`/`Retained` outcomes and
  `Unsealed` after recovery. Only the latest durably allocated generation of a destination may be inspected, approved or published; an older
  justification can never replace a later edit.
- Publication needs an authenticated, expiring kernel permit bound to the transfer ID, digest and exact temporary and destination paths. The
  service writes one exclusive temporary file, flushes it and replaces the destination with a same-handle POSIX rename; existing readers keep
  the old bytes. `AllowedWithoutInspection` never grants publication.
- Service loss: new allocations are denied, existing private writes stay private, and a restart turns `Allocated` into `Unsealed`; a lost
  seal reply leaves the backing read-only and retries. A crash may lose unflushed application bytes but can never produce an automatic
  approval.

## Destination contract

Local NTFS for destination and backing, backing sector size 512-65536, and the checked stack-size relation. Network volumes are rejected.
ReFS/FAT/exFAT, USB surprise removal, SMB/UNC redirectors, cloud-sync clients and third-party filter stacks are not qualified and must not be
enabled by removing these guards.
