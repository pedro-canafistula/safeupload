**ACCEPT WITH CONDITIONS — for implementing RegisterRoot, RegisterChildIntent and the transaction pools as dormant increment-3 infrastructure.** This does not approve a diagnostic actor, first boot, modern admission or qualification.

Reviewed HEAD `44080deb9871645f3d2f5ed1dda6e9fadf56ca32`, the three prior reviews, the kernel worker report and the cited implementation. Offline and read-only; no builds, tests, network, builder or VM access.

Below, **P** means `driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md`; **K** means `driver/SafeUpload.Minifilter/StageResourceMetadata.c`.

1. **Medium — Specify the ancestor-security predicate before coding root admission.**

   **Document:** P:1487–1498.  
   **Code:** `StagedTransferJournal.cs:2083`, `:3544`, `:3581`; K:361.

   The four private roots have a reasonably precise trust rule: owner LocalSystem or Builtin Administrators, protected non-null DACL, and no mutation grants to other principals. The ancestor rule—“untrusted subjects cannot … change its authority”—does not define the corresponding owner/principal treatment.

   **Concrete failure:** reusing `RequireTrustedOwner` indiscriminately on every ancestor can reject a legitimate Windows servicing-owned ancestor. Conversely, checking ancestor Allow ACEs alone can overlook an untrusted owner’s ability to change the DACL. The distinction matters even when the next directory currently appears protected.

   **[before-coding]** Define separate predicates for private roots and Windows ancestors. Include owner-derived security authority, effective/inheritable rights and unsupported ACE forms. Under the proposed private-root rule, TrustedInstaller and a separate service-SID mutation ACE are **not automatically accepted**; Administrators explicitly are. Handle legitimate Windows servicing authority on ancestors explicitly rather than silently broadening private-root trust.

   This is a specification condition, not an identified exploit in current registration: K:387 still refuses it.

2. **Medium — The current dispatch stubs would erase the proposed native Busy result.**

   **Document:** P:1591–1597.  
   **Code:** K:581–592; `FilterPort.ResourceSends.cs:123–134`.

   RegisterRoot currently converts every unsuccessful handler status into a successful transport carrying Refused. Child dispatch unconditionally replaces its validation status with success. Those are acceptable refusal stubs, but cannot remain around working pool admission.

   **Concrete failure:** the ninth Growth registration returns `STATUS_DEVICE_BUSY` internally, but the wrapper turns it into Result=2. The service receives a permanent-looking refusal rather than the specified retryable exhaustion signal. Cleanup or a save can then fail unnecessarily despite preserved reserved capacity.

   **[before-coding]** Define and preserve the distinction between malformed/refused registration and native Busy through handler, dispatcher and agent adapter. Busy must return no successful ID or retained new ownership; it must not invent Result=3. Verify both local send-class Busy and kernel transaction-pool Busy.

3. **Medium — Pool isolation is sound, but its implementation must account separately for pending intents and live children.**

   **Document:** P:1003–1012, P:1575–1589.  
   **Code:** `StageResourceMetadata.h:23–26`; K:390–440; `ResourceControlWireV32.cs:116–139`.

   The arithmetic is **eight Growth + eight NonGrowth transactions**, with up to **64 live child objects** and separately bounded pending-intent ownership. The existing header’s 64-child constant does not itself provide the extra intent storage or prevent a fifth object from being opened.

   **Concrete failure:** four objects remain live while another intent is registered; lower CREATE starts before a child/context credit is reserved, producing a fifth Opening owner. Alternatively, cancellation releases the transaction slot while its completion context still references it.

   **[before-coding]** Specify whether pending intents use separate bounded storage or reserve one of the four child credits. Either representation is acceptable; admission must prevent a fifth Opening/Active/retiring child before lower dispatch.

   Both validators also need the new masked-nonzero and role/tag rules: they currently check only an ordinary nonzero GUID. Test the tag-only GUID, all Growth-disallowed roles, tag-flipped aliases, concurrent first children and release through failed CREATE/revoke/CLOSE.

4. **Medium — Deferring the actor is acceptable; deferring every real `_sendGate` check to increment 6 is avoidable.**

   **Document:** P:1709–1722, P:2398, P:2514.  
   **Code:** `FilterPort.cs:93–126`, `:572–583`; `FilterPort.ResourceSends.cs:152`; `ResourceSendTests.cs:9–49`.

   The document honestly leaves the affected evidence open. However, the existing test uses fabricated handles and a fake native sender. It proves the managed admission distinction, not concurrent Filter Manager callbacks.

   **Concrete failure:** the managed helper bypasses `_sendGate`, but production pairing, a shared native lock or disposal introduces another serialization edge. Discovering that after increments 4–5 means revisiting their dependencies.

   **[before-first-boot]** Prepare an early native gate-independence control using the existing agent-side `HoldLegacySendForTesting` seam with real connected handles and actual RegisterRoot/ChildIntent calls. Execute it after the required source review. This needs no new kernel opcode.

   A stronger early alternative is a bounded diagnostic-agent pause before replying to an existing legacy allocation request:

   - CREATE already owns an epoch at `StageStream.c:11333–11354`.
   - Allocation reaches `SafeUploadStageAllocateV19` at `StageStream.c:2752` and the request exchange at `StageProtocol.c:965`.
   - Pause before the reply at `MinifilterInterceptor.cs:657–662`; concurrently issue normal SetPolicy and raw metadata work; then release independently within existing deadlines.

   That can exercise actual drain dependency without adding kernel authority. It still needs correlation and observation of the blocked transition; it is not automatically equivalent to the proposed actor’s held-old-epoch snapshot or side-port echo.

5. **Low — The scheduling table retains an inconsistent prerequisite statement.**

   **Document:** P:2370 versus P:2371, P:2398 and P:2514.  
   **Code:** `FilterPort.ResourceSends.cs:33–35`, `ResourceSendTests.cs:27–39`.

   Increment 2 still calls native control/reply progress a “prerequisite to increment 3,” while subsequent text permits increment-3 coding and defers selected runtime progress evidence.

   **Concrete failure:** a worker treats fake-send tests as that completed prerequisite, or unnecessarily blocks substrate coding on a runtime test requiring the substrate.

   **[before-coding]** Distinguish accepted progress contracts, implemented source review and subsequent native/protected execution consistently. The existing fake-send suite closes none of the latter execution obligations.

The installed-root proposal is otherwise sufficient **within its explicitly limited trust boundary**:

- The actual roots are `staging`, `staging\.space-reservations`, sibling `staging-journal`, and `staging-journal\completed`. This matches `MinifilterInterceptor.cs:1697–1698`, `StagedSpaceBudget.cs:71` and `StagedTransferJournal.cs:246–247`. `AgentPaths.cs:22–24` uses CommonApplicationData.
- P:1524 explicitly refuses non-C: Windows and relocated ProgramData. That is a modern-startup compatibility limitation, not support for those layouts. The existing kernel already constructs C: paths at `StageStream.c:2164` and `:2889`; `:9247` supplies only a volume-relative classifier.
- Independently opening the fixed installed object and comparing its complete identity, volume/instance and held ancestry with the original UserMode-checked handle closes the **arbitrary SYSTEM-owned directory supplied by the caller** hole. Neither ownership nor the caller’s expected ID alone closes it.
- The TOCTOU protection comes from retained native handles, no-SHARE_DELETE ancestry, relative subsequent operations and final group/security validation. A FILE_OBJECT reference alone is not a substitute for the retained exclusion handles.
- Walking every component without following reparse points covers junctions and mounted-folder ancestors. Final-component `FILE_OPEN_REPARSE_POINT` alone would not.
- Case-insensitive lookup is reasonable when followed by exact object comparison. Short-name or alternative-locator acceptance must not become string-based enrollment. The bootstrap’s stricter refusal of alternative spelling is an availability limitation.
- Child admission must enforce unnamed-stream, regular-file, single-link identity checks for existing opens as well as creates. The dormant native adapter already checks existing-file type/link count at `StagedMetadataStoreNative.cs:99–107`, `:152–158`; that does not replace kernel enforcement.
- Legitimate ACL repair must revoke and drain **before** mutation, then recapture. Existing journal startup can change directory and child DACLs at `StagedTransferJournal.cs:307–325`; integration must preserve that ordering.
- Administrators/SYSTEM already have private-storage mutation authority under the existing ACL model. The proposal does not make them harmless, and does not protect against their erasure/rollback. An attacker controlling the authenticated service also controls transaction-purpose declarations. Those are O2 limits, not newly established isolation guarantees.

A simpler equivalent capture is to hold the fixed installation ancestry once and resolve the signed relative suffixes through it, comparing every supplied handle with the independently reached object. Repeating four absolute opens is not itself extra authority. Supporting relocated ProgramData would require a reviewed authoritative location source—such as protected machine installation configuration—not trusting the service’s environment expansion. Neither alternative supplies an erasure-resistant anchor.

The pool tag is **not intrinsically unforgeable**. Its authority comes from the authenticated original process/token/service-SID/group checks at K:62–110 and `Communication.c:1996–2007`. A non-service caller choosing the bit gains nothing. Full tagged IDs plus live-group identity, rejection of retained tag-flipped aliases and drain-before-reconnect make the proposed transient classification adequate. Fresh-ID discipline after complete retirement remains a trusted-service obligation, not permanent kernel replay protection.

The pools provide occupancy isolation, not scheduler fairness or guaranteed progress through stalled native calls. P:1598–1602 correctly acknowledges the shared eight metadata-send slots. Already-admitted cleanup/completion must require no new registration; otherwise Busy merely conceals a deadlock. Production purpose classification remains an increment-4/5/6 verification obligation.

For the diagnostic actor, **none of A/B/C may leave an enabled actor interface in a product-signed product driver**. A is the smallest acceptable lab-only approach if its deployment boundary is explicitly accepted. B additionally needs the presently missing independent permit authority; it still compiles the actor out of product binaries. C leaves the attack surface present and should remain rejected. Signing a diagnostic binary does not make its interfaces suitable for product delivery.

I found no ABI-size contradiction: the 64-byte header, 96/112 negotiation, 64/40 root, 640/16 child, 8/8 revoke and 24-byte pairing layouts agree with `StageResourceMetadata.h:103–115`. The diagnostic payloads are separate proposed layouts. Sections 8.1/8.6/12–13 otherwise preserve the opaque substrate cut, Commit NotReady and later production gates. Earlier release, CREATE-shell, MDL and padded-peak conditions are not discharged by section 8.7.

The next pass may proceed under these conditions:

| Timing | Required condition |
|---|---|
| **before-coding** | Resolve findings 1–3 and the scheduling wording; retain the corrected peak-accounting prerequisites. Implement authenticated capture, maps, immutable pools and matching pre/post ownership as one coherent dormant substrate. Record actor selection or explicit deferral separately. |
| **before-first-boot** | Independently review both wrappers, native exclusions, authentication, pool conservation, cancellation and rundown; pass exact-role native mechanisms, both WDK/static/import gates and the full agent delivery matrix. If an actor is selected, review its source/lifetimes and prove product parser/symbol absence. Current refusal stubs and their static gate are insufficient. |
| **before-qualification** | Execute root/pool/lifetime controls and retained progress evidence; complete owning archive/custody, CREATE/fence and growth/MM integrations, then matched-pair and Verifier qualification. Keep uncertain charges, sticky Unknown and existing admission/capacity gates. |
| **before-coding dependent increments** | **O2 remains an owner decision before increment 4; O1 remains an owner decision before increment 6.** Neither is decided by this review. Activation and cutover remain separately gated. |