# T8 MOTW native feasibility checkpoint — 2026-10-27

**Native diagnostic completed; transparent whole-version witness not established.**
No protected-pair qualification or user-visible product change.

Target: `win10-debug3`, Windows **19045.2965**, preserved Office dev overlay
`demo1`, EFI reset at boot, no TPM/Secure Boot. Standard interactive `t5actor`.
Installed pair unchanged: driver `m2dev1022b` SHA-256
`7BEF3FF2C8C6F5C74DEE9082B5EE0ABD026369D5DB60BC1A461070A53D685465`;
agent remains `Agent-m2dev1022b`. WSearch disabled and WinDefend stopped in the
retained dev configuration; this is not normal-service qualification.

Source `efb4b0f4` (same tree as published `a1877313`; only the unpublished commit
email was corrected). Run **m2motw1027b1**:

- Installed headed Edge **154.0.4258.62**, fresh isolated profile, loopback-only
  synthetic 8-MiB HTTP attachment. Edge completed with `ZoneId=3`; sampled base
  and ADS have the same full volume/128-bit ID as the earlier `.crdownload`.
- Shell `CopyHere`, PowerShell `Copy-Item` and robocopy `/COPY:DAT` preserved the
  explicit tagged source. All three copied hashes match the independently
  generated payload SHA-256
  `A3BAF030390CFD1A07F9BBE48C53D53E91B86E7DC5EA0BC01C9B551F21B7A544`.
- The observer recorded 364 polling passes / 235 events. First sampled final
  Edge name at 7095.115 ms already had the tag; the completed CDP event was
  received at 7098.5865 ms. These are observer/receipt times, not first-visibility
  or causal ordering proof. The source-base hash was checked through copied
  fixtures, not independently asserted at the Edge completion event.
- Later owned-fixture ADS writes succeeded on the same Edge and shell IDs.
  Neither sampled completion nor CDP supplied a mutation cutoff.
- Windows PowerShell **5.1.19041.2673**, source hashes, parse and native signature
  self-check pass. Exact-profile Edge processes and fixture server listener are
  absent afterwards. Fixtures/profile and raw failed attempts remain on the dev
  overlay for retention; this is process closure, not baseline restoration.

The first attempt **m2motw1027a1** failed in the harness: .NET Framework string
paths reject ADS syntax. The native-handle correction has its own commit and
fresh label. The first failure and source/receipts were retained, not overwritten.

Retained audit subset: [result](t8-motw-m2motw1027b1/result.json),
[selected observations](t8-motw-m2motw1027b1/selected-observations.json),
[hashes](t8-motw-m2motw1027b1/source-sha256.json),
[Windows gate](t8-motw-m2motw1027b1/gate.txt),
[process closure](t8-motw-m2motw1027b1/closure.txt), and
[first failed result](t8-motw-m2motw1027a1/result.json).
The selected observations bind the full local raw JSON by SHA-256.

## Independent feasibility review and next experiment

Fresh read-only reviewer `/root/motw_feasibility_review`, **gpt-6.1-sol high**, no
fast tier, independently read the source, raw results and vendor contracts.
Verdict: native carriage demonstrated; more engineering evidence is required
before asking the owner to choose a changed workflow. No basis to declare
transparent support impossible.

Relevant primary evidence:

- [Upstream Chromium download implementation](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/download/internal/common/download_file_impl.cc)
  (observed blob `feac44591dedf93eda2bf2bd7cf64b21a8fabf4b`) renames before
  annotation and explicitly documents an intervening unmarked-name window.
  This is a trace hypothesis, not proof of proprietary installed Edge ordering.
- [IAttachmentExecute::Save](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iattachmentexecute-save)
  expects an already-copied local file and allows trust services to alter/delete
  it. Its entry alone cannot supply pre-creation registration. The upstream
  [quarantine implementation](https://chromium.googlesource.com/chromium/src/+/refs/tags/145.0.7561.4/components/services/quarantine/quarantine_win.cc)
  also has direct ADS annotation paths, so a Save-only hook is insufficient.
- [IFileOperationProgressSink](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ifileoperationprogresssink)
  attaches to a caller-owned operation instance. A helper's own instrumented
  copy is not proof of interception of stock Explorer.

The follow-up **m2motwtrace1027c1**, source `b4620691`, did not complete either operation. Edge CDP
never became ready, and Win+E did not produce a new foreground Explorer window;
the input guard refused navigation, so no actual Explorer paste occurred.
The broad verbose FileIO trace dropped **1,871,347 events** and created a
2,850,029,568-byte ETL. It supplies no ordering proof and is not being retried.
Running that trace alongside the builder was too costly; severe host I/O pressure
was observed. Timing failures alone do not prove its exclusive cause.

The recorder stopped normally. The original Edge PID/start-time-bound process
was closed and owned-profile processes were verified absent. Commit `96423808`
adds that exact-owned-process fallback to the probe; a real Windows PowerShell
5.1 cleanup self-check subsequently passed. The failed Edge and Explorer results,
gate, trace stop and closure receipts remain retained with the
[Edge failure](t8-motw-m2motwtrace1027c1/edge-result.json),
[Explorer failure](t8-motw-m2motwtrace1027c1/explorer-result.json),
[WinPS 5.1 gate, trace stop and closure/ETL hash](t8-motw-m2motwtrace1027c1/retained-summary.json)
tracked here. The curated summary binds unchanged raw CRLF receipts by SHA-256.
Full ETL remains on preserved `demo1` at
`C:\T8\motw-trace-m2motwtrace1027c1\fileio.etl`, SHA-256
`056468CD1E6EA8244838F9A58E43387ECDDDCDBAC550E0F4FB573ECBDCAD735F`.
The target is off, base/inactive XML unchanged; this is not fresh-disk restoration.

Next engineering evidence must use a narrowly bounded operation trace with an
idle host, an interactive-window preflight and a checked verdict before starting
the next case. Then use a deterministic pause around annotation and a concrete
adapter prototype. Further runs are stopped pending owner direction after the
repeated component failures in the [T9 checkpoint](t9-reservation-totals-checkpoint.md).
A positive prototype must register before first mutation,
bind original grants and exact source/destination/stage/generation, and finalize
both immutable streams with an enforced cutoff. Lost/stale completion, late ADS,
producer death and a no-MOTW ordinary-save control remain required. A broker,
extension or replacement command still requires the owner's product choice
before adoption; this experiment selects none.
