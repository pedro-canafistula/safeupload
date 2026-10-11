# Independent prerequisite review: zero lease-break timeout on the installed kernel

**Decision:** the static binary evidence verifies the zero-deadline sentinel in the exact `7.2.5-3-omarchy` build identity observed running on this host. In that binary, a nonpositive `lease_break_time` produces a zero lease-break deadline, and `time_out_leases()` skips expiry work for zero deadlines. Thus zero does not mean an immediate forced break: it means the automatic lease-break deadline does not expire. This is a static implementation finding, not live qualification of lease behavior with the host knob set to zero.

## Evidence chain

The root read-only package receipt is `driver/evidence/2026-10-11/m2-t5-host-kernel-provenance-readonly-a1-root.json` (SHA-256 `9a25b4be57083fe449c7f1ac70600017e73d9b12e54f06bec9b6d5a4b95b7c1a`). It records `uname -r` as `7.2.5-3-omarchy`, the installed build-tree `vmlinux`, its 20-byte GNU build ID `240f9ec5a8022b1a7f578b0199033bf067658fbc`, and the cached `linux-omarchy` and headers package paths.

The cached kernel archive SHA-256 is `5782d55cb40b8a0a05b797fa863898fb9589c893b6588b0c776886b7c9379331`; its adjacent signature file SHA-256 is `d7bd87426905a97367386f9ccd170855c666b637ed91f71920540c56e15b879a`. The cached headers archive SHA-256 is `d1ad9cfc2aca78cd44a87ec637d51a90a7dcf0bc486bc5ab84a8612ddda2e2f9`; its signature file SHA-256 is `3972e88facc319e7c7f5d57335c98920ba5426bab442aabd1121f00fabe4b2c7`.

I extracted only package metadata into `/tmp/luna-kernel-lease-review-20261011/`. Both package `.BUILDINFO` records name `pkgbase = linux-omarchy`, `pkgver = 7.2.5-3`, the same `pkgbuild_sha256sum = 2ac6e4ddb90f0afbe7602d274a36389f70b9a11664c256d2aee6cafb1fd4fcbf`, and `builddate = 1789415701`. The headers `.MTREE` records the `build/vmlinux` SHA-256 as `5758c63f60544e682faa9758ad44cf1a4bf5c207bfadc416a21b67e178d9a1a3`. Independently hashing that archive member produced the same digest, as did hashing `/usr/lib/modules/7.2.5-3-omarchy/build/vmlinux`. The installed build artifact is therefore byte-for-byte the vmlinux payload in the cached matching-version headers package.

The separate read-only running-kernel identity receipt is `driver/evidence/2026-10-11/m2-t5-running-kernel-build-identity-readonly-a1-root.json` (SHA-256 `8cf7662f55d2366d1ff114e837335aa11556dae439473a7f9b094309c39fcbe1`). It records that `/sys/kernel/notes` exposes GNU build ID `240f9ec5a8022b1a7f578b0199033bf067658fbc`, matching the installed vmlinux build ID, and reports running release `7.2.5-3-omarchy`. This ties the running kernel to the same build identity for this review; it is an identity observation, not measurement of every in-memory instruction or a behavioral test.

## Static implementation finding

I disassembled only the matching `vmlinux`; no kernel, candidate, lease control, VM, or service was executed. The combined `objdump` output for `time_out_leases` and `__break_lease` is preserved temporarily at `/tmp/luna-kernel-lease-review-20261011/vmlinux-time-out-leases.txt` (SHA-256 `acfee9a904517ef774f949078deb473cc284be393e59264d0e02fc30dd603b9d`). The source file `fs/locks.c` is absent from the installed headers package, so this finding is based on the exact binary rather than a claimed source-to-build match.

In `__break_lease`, address `ffffffff818c277d` initializes the local break deadline to zero. At `ffffffff818c2786` the binary reads `lease_break_time` (`ffffffff83ba5120`); the test at `ffffffff818c278c` branches past deadline calculation when the value is nonpositive (`jle` at `ffffffff818c278e`). The zero local deadline is then copied into the lease deadline field at `ffffffff818c27ec` or `ffffffff818c287a`-`ffffffff818c287f`.

In `time_out_leases`, the deadline fields are tested at `ffffffff818bffd0`-`ffffffff818bffda` and `ffffffff818bfff1`-`ffffffff818bfffb`. A zero first field skips its expiration path; a zero second field skips to the next lease. The timeout/removal call to `lease_modify` is reached only after nonzero deadline checks. Together, these paths establish that zero does not schedule automatic lease expiry in this binary. A writer encountering such a lease can remain blocked until another event releases or changes the lease; the code does not grant writer admission merely because a break was requested.

## Boundaries

- This review did not set `lease-break-time` to zero, perform lease or writer tests, or qualify systemd FDStore behavior, process-loss recovery, filesystem behavior, or production host policy.
- A break notification or `F_GETLEASE` reporting a pending `F_UNLCK` target is not evidence that a writer has acquired the file. This report makes no such inference.
- The package metadata says `Unknown Packager`. I recorded archive and signature hashes but did not independently authenticate the package signature or recover the exact PKGBUILD/source tree. The binary identity chain and matching build ID support the implementation finding without proving vendor source provenance.
- The installed `vmlinux` and running build identity support an exact-build conclusion; they do not replace runtime qualification or the independent whole-VM restore, crash-custody, or API-drain requirements.

No repository `AGENTS.md` or `CLAUDE.md` was present. No tracked source, kernel setting, package, service, VM, or Git state was changed. The only workspace change from this review is this additive report.
