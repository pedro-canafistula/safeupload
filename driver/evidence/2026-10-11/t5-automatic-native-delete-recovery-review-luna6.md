# T5 automatic native-delete recovery — Luna 6 max

Date: 2026-10-11. Reviewer: `/root/t5_public_proxy_routing_design_luna`, `gpt-6-luna`, max effort.
Scope: owner's conditional accepted/unresolved recovery and corrected native-open lifetime design. No product implementation or VM
qualification. This records the reviewer's returned findings; it supersedes the pending-policy verdict in the earlier native follow-up.

**Verdict: READY WITH CORRECTIONS.** Automatic service-start and last-handle recovery is feasible with the existing destination
journal and one appended `AcceptedUnresolved` state. The reviewed construction is [T5-NATIVE-PUBLIC-OPENS.md](../../docs/design/publication-and-namespace/T5-NATIVE-PUBLIC-OPENS.md).

- Persist accepted/unresolved conservatively before forwarding native CREATE. Reconcile destination heads before physical publication
  admission on startup; the current `MinifilterInterceptor.cs:1313` recovery only handles transfer entries and is not sufficient yet.
- Use complete read-only extended enumeration of the anchored parent/canonical leaf and full FILE_ID_128. Pending child opens may
  fail; do not open as SYSTEM, widen sharing or infer identity from absence/PID/driver epoch.
- Original identity or exact absence releases only the exceptional barrier. Downgrade to existing nonblocking scheduled intent
  (Admitted plus native-on-close kind) and retain its generation floor. Do not call it Complete/Canceled or forge a cleanup ACK.
  Different unexplained identity stays held; a newer identity requires exact durable publication reconciliation before Superseded.
- Block accepted/unresolved in physical-turn and publication guards; durable downgrade wakes existing queue waiters. Keep normal
  scheduled intents nonblocking. Native Win32-5 publication refusal may remain while another reader holds the pending object:
  keep the clean stage and retry on directory change plus exact recheck, preserving NTFS's restriction.
- Mandatory unload fences new native opens/mutations, keeps CLEANUP/CLOSE/rundown callbacks active, cancels service requests by closing
  ports, drops driver/service handle holds and drains native app records to last-handle CLEANUP plus local operation references before
  unregister. The existing section-7 local drain may be unbounded; never wait for service ACK or claim a mandatory veto prevents unload.
  Preserve service-stop prohibition/voluntary veto and count the native table in both. No live delete-capable handle crosses detach.
- Native read-only mappings can outlive app cleanup because NTFS owns the section. Private owned sections keep their separate drain.
  Actual OS shutdown does not invoke FilterUnloadCallback; recovery uses trusted OS boot evidence, never a driver-instance change.

Supporting raw control: [publication race](t5-native-delete-publication-control-1011a1.txt), source `b33042cb`. Replacement before
creator cleanup succeeds and survives old close; after creator cleanup with another reader, both child metadata open and POSIX rename
return Win32 5. The proposed after-cleanup zero-result assertion failed and was not waived. The separate
[parent-query control](t5-native-pending-link-control-builder-1011a1.txt) identifies the pending original without opening it, then
observes exact absence after last reader close. Both are unprotected builder controls, not driver/recovery qualification.

Primary contracts: [cleanup](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup),
[extended directory entry](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_extd_dir_info),
[MS-FSA close](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/d142c93a-72bc-4b05-9d96-8e00371c3308),
[MS-FSA directory query](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/fa8194e0-53ec-413b-8315-e8fa85396fd8),
[unload callback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/when-the-filterunloadcallback-routine-is-called),
[unregister](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/unregistering-the-minifilter).

Integrated kernel lifetime/lock-order/retirement review remains required once before its first revised VM boot. Four WDK 0/0 builds,
agent matrix, protected automatic-release fault rows, independent byte observation, runtime Verifier and separate restoration remain open.
