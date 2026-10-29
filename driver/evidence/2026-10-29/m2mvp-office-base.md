# M2 MVP Office base (2026-10-29)

Owner-approved fresh Office base for task B (owner 2026-10-29). Sealed by the orchestrator after the owner's interactive Microsoft 365 sign-in.

- File: `/var/lib/libvirt/images/win10-debug3.office-base-20261029.qcow2`, a qcow2 overlay of `win10-debug3.base-20261014.qcow2` created through the libvirt `default` pool. Never booted again; every row uses a disposable overlay above it (T5_OFFICE_BASE=1).
- Guest: Windows 10 19045.2965, UUID FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3; the original SafeUpload.sys stays installed and stopped, as in the qualified base.
- Office: Microsoft 365 Apps for enterprise (O365ProPlusRetail, Current channel, x64, en-us) via ODT `setup.exe` SHA-256 C883AB32DFFE4A371BB37411DE83EDC5D62FF31D315C5E3B59E830326BB4E322. Installed VersionToReport **16.0.20326.20232**, automatic updates disabled.
- Actor: local standard user `t5actor` (SID S-1-5-21-316478115-1595729549-2803163825-1279), member of Users only, signed in to Microsoft 365 by the owner (licence file present in the profile). Its password is host-only (`~/Work/safeupload-tools/secrets/office-base-20261029-t5actor.txt`, 0600) and must never be reset, because the Office credential is DPAPI-bound.
- Sealed state: no persistent Winlogon autologon values, installer directory removed, clean guest shutdown. The domain is repointed to `win10-debug3.base-20261014.qcow2` afterwards.
- Baseline: `Get-StagedBaseline.ps1 -OfficeBase` accepts exactly this actor profile and the pinned Office installation; all other checks are the default baseline's.
