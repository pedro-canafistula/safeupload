# T8 native Mark of the Web completion probe

This increment tests the feasibility boundary in
[the metadata integration design](../../docs/design/metadata/T8-METADATA-INTEGRATION.md#whole-version-motw-and-completion-witness).
Run on the preserved Office dev overlay of `win10-debug3`, as interactive standard
user `t5actor`, with a fresh label and committed source. Keep `win10-debug2` off,
reset EFI on start, and retain the unchanged product pair and exact artifact hashes.
This is an unprotected mechanism experiment, not protected-pair qualification.

Before execution, parse both PowerShell/source inputs using Windows PowerShell
5.1 Desktop x64, check source hashes, and run:

```powershell
& .\motw-completion-native-control.ps1 -SelfCheck
& .\motw-completion-native-control.ps1 -Label <fresh-label>
```

The self-check compiles the C# helper and checks the native file-ID query signature,
monotonic clock and CDP JSON decoder without file operations. The real run:

- Starts a loopback-only HTTP attachment server and an isolated, headed instance
  of the installed Edge, with a fresh profile and an ephemeral loopback CDP port.
  It changes no installed policy, existing profile, download security setting,
  service or product gate. The 8-MiB payload is synthetic ASCII, not user data.
- Enables CDP download events before navigating through Edge's actual download
  path. Records the received events, exact base/ADS volume and 128-bit file IDs,
  lengths, tag text and explicit query errors. The observer reopens the base to
  bracket identity; uncertain queries do not imply an absent tag.
- Uses a separately, explicitly tagged source to isolate shell `CopyHere`,
  `Copy-Item` and robocopy `/COPY:DAT` behavior. Records operation-return times
  separately from observed complete file/tag states. `CopyHere` is asynchronous;
  a matching sampled state is not its authoritative completion receipt.
- Attempts an owned-fixture tag write after observed browser/copy completion,
  retaining its exact identity and result. This tests the absence of an existing
  cutoff; it neither proves that a future kernel cutoff is impossible nor supplies
  pre-registration of a stock Explorer/Edge transaction.

`result.json` and `observations.json` remain in `C:\T8\motw-<label>`, together with
the fresh profile/fixtures, for collection before cleanup. The helper closes its
loopback socket and observer and requests `Browser.close`; a failed close or other
error leaves the probe incomplete. Verify no process using that exact fresh profile
remains before removing this run's fixtures. Never remove another profile or a
previous failed attempt.

The probe reports `WholeVersionWitnessEstablished=False` even when all native
operations complete. Polling and CDP receipt timestamps cannot prove first public
visibility, enforce future-write exclusion, authenticate an exact product tuple or
establish a transparent integration for stock producers. Loopback download zoning
is recorded as observed; absent MOTW is not turned into successful Internet-zone
support. A real Internet attachment/Office Protected View leg and a concrete
pre-registration/finalization prototype remain required before a positive verdict.

Primary API references: [IAttachmentExecute::Save](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iattachmentexecute-save)
may attach security evidence to the file's ADS; [CDP Browser](https://chromedevtools.github.io/devtools-protocol/tot/Browser/)
exposes download notifications, not SafeUpload object authority or a filesystem
write cutoff. These references inform the probe, not a product acceptance result.
