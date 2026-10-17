# Unbound directory UX review

Independent reviewer: **Sol 6.1, xhigh** (`gpt-6.1-sol`, `reasoning_effort=xhigh`),
agent `/root/dirs_review`, 2026-10-16. Base `demo/apps` / `ux/dirs` `8925d1cf`.
Reviewed the working diff in `Filter.h`, `Policy.c`, `StageStream.c` and the
small [F1–F4 design/test list](../../UX-DIRECTORIES.md). No build, VM or network
operation was performed by the reviewer.

**ACCEPT WITH CONDITIONS.** No remaining code blocker in the requested unbound
scope. Concrete findings corrected before acceptance:

- Native directory admission compares the pre-lookup sequence inside the
  namespace resource before scanning; a completed intervening mutation cannot
  make a stale prefix authoritative.
- Private retarget checks the active fence before querying its destination.
- Unprotected directory information operations fall through to existing gates;
  ordinary/extended disposition clears need no idle proof.
- Initial malformed backslash character literals were corrected before host
  compilation.

The scan has namespace ownership without lower I/O. Omitted-type opens pin the
original CREATE to directory type after the metadata probe. Resident atomic
completion handling is safe for draining callbacks. The documentation condition
is now satisfied: known success/failure clears the fence; draining uncertainty
keeps it latched until reboot, and delayed lower I/O can prolong unrelated busy
refusals.

Remaining conditions: WDK/PREfast/import gates, matched Windows ordinary/runtime-
Verifier/boot-Verifier D rows, stale native-request names, retarget interleaving
and unprotected non-NTFS controls. This is design/code acceptance, **not** native
qualification, V30 qualification or service-restart relocation qualification.
