#!/usr/bin/env python3
"""Offline exact-closure controls for the R22 R17-self-check integration."""
from __future__ import annotations

import difflib
import hashlib
import json
import re
from pathlib import Path


REPO = Path('/home/victor/Work/safeupload-staging')
CANDIDATE = REPO / 'output/review-candidates/m2-t5-harness-windows-gate-r22-luna-a1'
SRC = CANDIDATE / 'src'
R21 = REPO / 'output/review-candidates/m2-t5-harness-windows-gate-r21-root-a1/src'
R21_CAPTURE = CANDIDATE / 'context/r21/m2-t5-harness-windows-gate-r21-root-review-capture.json'
R17_CAPTURE = CANDIDATE / 'context/r17/source-capture.json'
R17_RESULT = CANDIDATE / 'context/r17/author-result.json'
R17_ROOT_CAPTURE = CANDIDATE / 'context/r17/m2-t5-notepad-coordinator-r17-root-review-capture.json'
R17_DIAG_RESULT = CANDIDATE / 'context/r17/m2-t5-coordinator-r17-diag-a1-root-result.json'
R17_DIAG_VERIFY = CANDIDATE / 'context/r17/m2-t5-coordinator-r17-diag-a1-root-verification.json'
R17_DIAG_STDOUT = CANDIDATE / 'context/r17/m2-t5-coordinator-r17-diag-a1-controls.stdout.log'
R17_DIAG_STDERR = CANDIDATE / 'context/r17/m2-t5-coordinator-r17-diag-a1-controls.stderr.log'
R17_SELFCHECK = 'be52114a729e2861afccf6c73d900d5b03fc9f476e3664a64f10f959cb33ae47'
OLD_SELFCHECK = 'dbc00a84c456b97f6903cfcb4ccc0ba37c5ff763fc6b67e83aab3e86e807245f'
R21_ROOT_CAPTURE_SHA = '70af109854294f7eca2fb17be997438b225c18ebae6bafeddb75330eb289bbe0'
R21_BOUNDED_DISPOSITION_SHA = 'a182aad74031dac7b4b7df80a33bc59d6819907cbb0804e75b84d89c4abeb63e'
R21_REVIEW_SHA = '345547088c092449fb33c8e9cd6fab8973b42c573180b5cd01efc639db884321'
R17_REVIEW_SHA = 'cde139668abb57964cc394fa84944c9949c05994567a08b559d3abe30b9b1540'
R17_ROOT_CAPTURE_SHA = '7fd178b5560c782cecb655557e17889b1ce6b9739dc54d009191732c89289d79'
R17_DIAG_RESULT_SHA = '334b8794c812cdcd7330104b3f269457185aeef405fb6abfbf1998438bd2edf4'
R17_DIAG_VERIFY_SHA = '5a552d5adc1e3a18c3bbdca55795b31e63aa1a7dc72279679304d353641192bc'
R17_DIAG_STDOUT_SHA = '6af33efaa7bccb8ad8c344d48af1d8bd5029fa4e627cbb31019ab0e6970a27db'
R17_DIAG_STDERR_SHA = '31db57ecf12725856215a7f0a6c4c9e41a5f7828c46d4ee7189057f61ee09b97'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str:
    return sha(path.read_bytes())


def require(ok: bool, message: str) -> None:
    if not ok:
        raise AssertionError(message)


def records(root: Path) -> list[dict[str, object]]:
    paths = sorted((p for p in root.rglob('*') if p.is_file()), key=lambda p: p.relative_to(root).as_posix())
    require(all(not p.is_symlink() for p in paths), 'source closure may not contain symlinks')
    result = []
    for p in paths:
        data = p.read_bytes()
        result.append({'path': p.relative_to(root).as_posix(), 'sha256': sha(data), 'size': len(data)})
    return result


def source_delta(before: dict[str, bytes], after: dict[str, bytes]) -> list[str]:
    require(set(before) == set(after), 'R22 changed the R21 source path inventory')
    return sorted(path for path in before if before[path] != after[path])


def validate_r22(candidate: dict[str, bytes], manifest_obj: dict[str, object], shell: str) -> list[str]:
    errors: list[str] = []
    expected_path = 'driver/scripts/t5/notepad-coordinator.SelfCheck.ps1'
    manifest_records = manifest_obj.get('sourceFiles')
    if not isinstance(manifest_records, list):
        return ['manifest sourceFiles is not a list']
    matches = [r for r in manifest_records if isinstance(r, dict) and r.get('path') == 't5/notepad-coordinator.SelfCheck.ps1']
    if len(matches) != 1 or matches[0].get('sha256') != R17_SELFCHECK:
        errors.append('manifest must pin the exact R17 T5 self-check hash')
    if sha(candidate.get(expected_path, b'')) != R17_SELFCHECK:
        errors.append('execution source is not the exact R17 self-check')
    manifest_bytes = json.dumps(manifest_obj, indent=2, ensure_ascii=False).encode('utf-8') + b'\n'
    pins = dict(re.findall(r"^(expected_[a-z_]+_sha256)='([0-9a-f]{64})'$", shell, re.MULTILINE))
    if pins.get('expected_manifest_sha256') != sha(manifest_bytes):
        errors.append('shell manifest pin does not match the manifest bytes')
    return errors


def main() -> None:
    root_capture_bytes = R21_CAPTURE.read_bytes()
    require(sha(root_capture_bytes) == R21_ROOT_CAPTURE_SHA, 'R21 root capture context pin mismatch')
    root_capture = json.loads(root_capture_bytes)
    expected_baseline = root_capture['Groups']['src']
    baseline_records = records(R21)
    baseline_map = {r['path']: r['sha256'] for r in baseline_records}
    require(set(expected_baseline) == set(baseline_map), 'frozen R21 source paths differ from root capture')
    require(all(expected_baseline[p] == baseline_map[p] for p in baseline_map), 'frozen R21 bytes differ from root capture pins')

    capture17 = json.loads(R17_CAPTURE.read_text(encoding='utf-8'))
    result17 = json.loads(R17_RESULT.read_text(encoding='utf-8'))
    root_capture17 = json.loads(R17_ROOT_CAPTURE.read_text(encoding='utf-8'))
    diag17 = json.loads(R17_DIAG_RESULT.read_text(encoding='utf-8'))
    verify17 = json.loads(R17_DIAG_VERIFY.read_text(encoding='utf-8'))
    require(digest(CANDIDATE / 'context/r21/m2-t5-harness-r21-root-bounded-disposition.json') == R21_BOUNDED_DISPOSITION_SHA,
            'R21 root disposition context pin mismatch')
    require(digest(CANDIDATE / 'context/r21/luna-t5-harness-windows-gate-r21-independent-review.md') == R21_REVIEW_SHA,
            'R21 independent review context pin mismatch')
    require(digest(CANDIDATE / 'context/r17/luna-t5-notepad-coordinator-r17-independent-review.md') == R17_REVIEW_SHA,
            'R17 independent review context pin mismatch')
    require(digest(CANDIDATE / 'context/r17/m2-t5-notepad-coordinator-r17-root-review-capture.json') == R17_ROOT_CAPTURE_SHA,
            'R17 root capture context pin mismatch')
    require(digest(R17_DIAG_RESULT) == R17_DIAG_RESULT_SHA and digest(R17_DIAG_VERIFY) == R17_DIAG_VERIFY_SHA,
            'R17 failed-diagnostic result/verification pins mismatch')
    require(digest(R17_DIAG_STDOUT) == R17_DIAG_STDOUT_SHA, 'R17 raw diagnostic output pin mismatch')
    require(digest(R17_DIAG_STDERR) == R17_DIAG_STDERR_SHA, 'R17 raw diagnostic error pin mismatch')
    r17_rows = [r for r in capture17['sourceFiles'] if r['path'] == 'src/driver/scripts/t5/notepad-coordinator.SelfCheck.ps1']
    require(len(r17_rows) == 1 and r17_rows[0]['sha256'] == R17_SELFCHECK, 'R17 source capture does not pin the imported self-check')
    require(root_capture17['Groups']['src'].get('driver/scripts/t5/notepad-coordinator.SelfCheck.ps1') == R17_SELFCHECK,
            'R17 root review capture does not pin the imported self-check')
    require(result17['changedSource']['sha256'] == R17_SELFCHECK, 'R17 author result does not pin the imported self-check')
    require(result17['qualification']['runtimeQualified'] is False and result17['qualification']['sourceAccepted'] is False,
            'R17 author result must remain unaccepted/unqualified')
    require(diag17['StandaloneWindowsControlsPassed'] is False and diag17['Failure'] == 'controls failed: exit 1',
            'R17 actual standalone diagnostic failure was not preserved')
    require(verify17['SelfCheckOutputHasExactlyOneCompletePASS'] is False and
            verify17['OriginalDiagnosticProcessTerminal'] is True,
            'R17 actual diagnostic verification does not show retained failed/terminal result')
    require('projection retains exact HandleObserved receipt' in R17_DIAG_STDERR.read_text(encoding='utf-8'),
            'R17 exact failed assertion missing from pinned raw diagnostic output')

    current_records = records(SRC)
    require(len(current_records) == 63, 'R22 source closure must remain exactly 63 files')
    current_map = {r['path']: r['sha256'] for r in current_records}
    baseline_bytes = {r['path']: (R21 / r['path']).read_bytes() for r in baseline_records}
    current_bytes = {r['path']: (SRC / r['path']).read_bytes() for r in current_records}
    changed = source_delta(baseline_bytes, current_bytes)
    expected_changed = [
        'driver/scripts/HarnessWindowsGate.manifest.json',
        'driver/scripts/Invoke-HarnessWindowsGate.sh',
        'driver/scripts/t5/notepad-coordinator.SelfCheck.ps1',
    ]
    require(changed == expected_changed, f'R22 changed source set differs: {changed!r}')
    require(current_map['driver/scripts/t5/notepad-coordinator.SelfCheck.ps1'] == R17_SELFCHECK,
            'candidate T5 source pin differs from exact R17 bytes')

    base_manifest_path = R21 / 'driver/scripts/HarnessWindowsGate.manifest.json'
    new_manifest_path = SRC / 'driver/scripts/HarnessWindowsGate.manifest.json'
    base_manifest_bytes = base_manifest_path.read_bytes()
    old_manifest = json.loads(base_manifest_bytes)
    manifest_bytes = new_manifest_path.read_bytes()
    manifest_obj = json.loads(manifest_bytes)
    require(base_manifest_bytes.count(OLD_SELFCHECK.encode()) == 1, 'R21 manifest must contain one old T5 digest')
    require(manifest_bytes == base_manifest_bytes.replace(OLD_SELFCHECK.encode(), R17_SELFCHECK.encode(), 1),
            'R22 manifest must be exactly the old T5 digest replaced by R17 digest')
    for key in ('schema', 'builder', 'powershell', 'mainFiles', 'rootSelfchecks', 't5Selfcheck'):
        require(old_manifest[key] == manifest_obj[key], f'R22 changed frozen manifest identity field {key}')
    old_sources = old_manifest['sourceFiles']
    new_sources = manifest_obj['sourceFiles']
    require([r['path'] for r in old_sources] == [r['path'] for r in new_sources],
            'R22 changed the ordered 33-source manifest inventory')
    differences = [(old['path'], old['sha256'], new['sha256']) for old, new in zip(old_sources, new_sources)
                   if old['sha256'] != new['sha256']]
    require(differences == [('t5/notepad-coordinator.SelfCheck.ps1', OLD_SELFCHECK, R17_SELFCHECK)],
            f'R22 manifest digest delta is not the exact R17 T5 pin: {differences!r}')
    for key in ('gateRunner', 'gateWorker', 'gateKeeper', 'gateFixture', 'gateControl', 'gateProtocol', 'localClient', 'transport'):
        require(old_manifest[key] == manifest_obj[key], f'R22 changed support pin {key}')

    shell_path = SRC / 'driver/scripts/Invoke-HarnessWindowsGate.sh'
    base_shell = (R21 / 'driver/scripts/Invoke-HarnessWindowsGate.sh').read_bytes()
    shell_bytes = shell_path.read_bytes()
    old_manifest_sha = sha(base_manifest_bytes).encode()
    new_manifest_sha = sha(manifest_bytes).encode()
    require(base_shell.count(old_manifest_sha) == 1, 'R21 shell must contain one old manifest digest')
    require(shell_bytes == base_shell.replace(old_manifest_sha, new_manifest_sha, 1),
            'R22 shell must be exactly the old manifest SHA replaced by its R22 SHA')
    shell = shell_bytes.decode('utf-8')
    errors = validate_r22(current_bytes, manifest_obj, shell)
    require(not errors, 'R22 pin validation failed: ' + '; '.join(errors))

    # Source-only negative controls for stale or mismatched exact pins.
    mutant_old_pin = json.loads(manifest_bytes)
    for row in mutant_old_pin['sourceFiles']:
        if row['path'] == 't5/notepad-coordinator.SelfCheck.ps1':
            row['sha256'] = OLD_SELFCHECK
    require(validate_r22(current_bytes, mutant_old_pin, shell), 'stale R21 T5 pin mutant was accepted')
    mutant_shell = shell.replace(sha(manifest_bytes), '0' * 64, 1)
    require(validate_r22(current_bytes, manifest_obj, mutant_shell), 'stale shell-manifest pin mutant was accepted')
    mutant_source = dict(current_bytes)
    mutant_source['driver/scripts/t5/notepad-coordinator.SelfCheck.ps1'] = b'altered R17 source'
    require(source_delta(baseline_bytes, mutant_source) == expected_changed,
            'negative-control setup did not retain the expected three-path integration delta')
    require(validate_r22(mutant_source, manifest_obj, shell), 'altered T5 execution-source mutant was accepted')

    patch_parts: list[str] = []
    for path in changed:
        patch_parts.extend(difflib.unified_diff(
            baseline_bytes[path].decode('utf-8').splitlines(keepends=True),
            current_bytes[path].decode('utf-8').splitlines(keepends=True),
            fromfile='R21/' + path,
            tofile='R22/' + path,
        ))
    patch_path = CANDIDATE / 'author/exact-delta-from-r21.patch'
    patch_path.write_text(''.join(patch_parts), encoding='utf-8')

    inventory_hash = sha(json.dumps(current_records, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
    output = [
        'R22 offline source controls: PASS',
        f'Closed source inventory: {len(current_records)} files; exact R21 path set preserved.',
        f'R21 root capture: {R21_ROOT_CAPTURE_SHA}; all 63 baseline source hashes match frozen R21 snapshot.',
        f'Changed source paths ({len(changed)}): ' + ', '.join(changed),
        f'Canonical R22 source inventory SHA-256: {inventory_hash}',
        f'R17 self-check: exact byte identity and SHA-256 {R17_SELFCHECK}; its bounded source review did not establish runtime success, and the subsequent actual standalone diagnostic failed at “projection retains exact HandleObserved receipt” (root result {R17_DIAG_RESULT_SHA}); no pass is inferred.',
        'Manifest: exact 33 execution paths and identities preserved; only T5 self-check SHA changed to the R17 pin.',
        f'Manifest and shell: SHA-256 {sha(manifest_bytes)} pinned by the exact shell literal; all other support pins unchanged.',
        'Negative controls: stale R21 T5 manifest pin, stale shell manifest pin, and modified T5 source are all rejected.',
        'R21 source and control dispositions retained; atomic receipt publication and job-containment sources are unchanged.',
        'No PowerShell, Windows, gate, service, actor, coordinator, host, VM, network, or Git action performed.',
        'Disposition: source-only integration candidate; R17 failed-diagnostic cause is under review, R22 independent review remains pending, and full gate/runtime are unqualified.',
    ]
    print('\n'.join(output))


if __name__ == '__main__':
    main()
