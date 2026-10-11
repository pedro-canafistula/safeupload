# T5 startup epoch security-design review

Reviewer: Luna 6, maximum effort, 2026-10-11. Source inspected: `e97585cb` and the startup prerequisite proposed in
`driver/T5-NATIVE-PUBLIC-OPENS.md`. Result: **FEASIBLE WITH CORRECTIONS**, before implementation; no runtime claim.

The existing journal accepts a changed driver only after an exact drain nonce (`StagedTransferJournal.cs:50`); its epoch record has
no boot metadata (`:171`). Registration reaches that gate before startup recovery (`MinifilterInterceptor.cs:716`, `:390`), so an
unclean full Restart cannot reach the approved hold recovery today. The authenticated, complete, revision-stable native replay is
available (`NativeRecordReplay.cs:143`), but not connected to dispatch.

Required correction:

- Capture optional unsigned OS boot metadata only from the authenticated replay for that exact driver/connection. A same-driver
  reconnect may fill its own missing baseline. A replacement driver must never fill an old epoch's missing baseline.
- Replace an undrained epoch only with a saved original boot value, a different authenticated driver instance, a strictly greater
  current unsigned boot value and a complete reconciled replay. Missing/equal/lower/wrapped/inconsistent evidence fails closed.
- Native records do not cover private staged FILE_OBJECTs or attachment receipts. Full-Restart qualification also depends on the
  approved service-stop prohibition, voluntary unload veto for native/private objects and local drain. Never forge a drain receipt.
- Run existing conservative private startup recovery before readiness: retain uncertain stages and `PendingRename`, preserve old
  manifest driver bindings, and do not rebind/delete unsaved stages. Failure keeps the service degraded. Resolve exceptional native
  holds separately using exact lifetime evidence and anchored-parent observation before allowing physical publication.
- Keep kernel RPC replies responsive while recovery runs. No new protocol state or persisted enum value is necessary.

No additional owner choice is needed for the approved M2 path if legacy missing-metadata epochs remain fail-closed. Their visible
effect is unavailable staging/a retained named-file hold until exact safe recovery. Automatic deletion/rebinding of retained private
state or automatic `PendingRename` resolution would require a new owner decision.

Microsoft describes BootId as increasing on OS-loader boot attempts in
[KUSER_SHARED_DATA](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data).
[System power states](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states) and
[Fast Startup](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation)
explain retained kernel/driver state. The counter alone is therefore insufficient; same-driver resume preserves live records.

The integrated kernel lifetime/lock-order/retirement review remains required once before the revised pair's first VM boot.
