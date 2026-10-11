#!/usr/bin/env python3
"""Offline closed-source and pin controls for harness R23."""
from __future__ import annotations

import difflib
import hashlib
import json
import re
from pathlib import Path

REPO = Path('/home/victor/Work/safeupload-staging')
CANDIDATE = REPO / 'output/review-candidates/m2-t5-harness-windows-gate-r23-luna-a1'
SRC = CANDIDATE / 'src'
FROZEN_R22 = REPO / 'output/review-candidates/m2-t5-harness-windows-gate-r22-root-a1/src'
R22_CAPTURE = CANDIDATE / 'context/r22/root-review-capture.json'
R22_SOURCE_CAPTURE = CANDIDATE / 'context/r22/author/source-capture.json'
R18_CONTEXT = CANDIDATE / 'context/r18'
R22_ROOT_CAPTURE_SHA = 'd2f7ea5ec8a7205678fb7fd00a3563c6f86ba0ea07e1f1884dc70039c881101e'
R22_SOURCE_CAPTURE_SHA = '11aabe1e028a051a9f735d21ee3584cc979e821f6d23f77612587bdff5bc4816'
R18_SELF_SHA = 'abc6b472a16e772bdd11fea7ab88e8e3de82579fc2691c6ef2436229c88d74bb'
R18_REVIEW_SHA = 'ee454c91457d54d0697bc07cd8f7b83be0d51c83321093ef1b1c47b884a98098'
R18_SOURCE_CAPTURE_SHA = 'e04ea25160c92b94e44a28dc6fa594b01727b6accd2699251eee2cd62ee56544'
R18_AUTHOR_RESULT_SHA = '07a7032d7300997d12b804b353eb4b8fc9b4f9b1a32b31da4ad85ab43329b689'
R18_DIAG_RESULT_SHA = '9d468ba1e5fc1da11a8801cebfc6a37aec5d0ccfc4b656b6594b88ffc7d17126'
R18_DIAG_VERIFY_SHA = '378f374cfd55c6f1e66ebcf89881eb58f2db53ae9cd1cb9c0766e51279cdfde3'
R18_STDOUT_SHA = 'bf0117d2b0c22f26c9baf17530ea6abaa2f5c0c491a9f286573147f910a77225'
R18_STDERR_SHA = 'a3639af5e23464fc391dae127fd5493f02c8178068a35866d9c7fdd35dcd623f'
OLD_T5_SHA = 'be52114a729e2861afccf6c73d900d5b03fc9f476e3664a64f10f959cb33ae47'
R18_COORDINATOR_SHA = 'c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d'
EXPECTED_CHANGED = {
    'driver/scripts/HarnessWindowsGate.manifest.json',
    'driver/scripts/Invoke-HarnessWindowsGate.sh',
    'driver/scripts/t5/notepad-coordinator.SelfCheck.ps1',
}
R18_CONTEXT_PINS = {
    'coordinator-root-review-capture.json': '019ae43c6488accd0b4118b67d165c9aa93eee2863b8d845633efee52ba2b8d4',
    'coordinator-independent-review.md': R18_REVIEW_SHA,
    'coordinator-source-capture.json': R18_SOURCE_CAPTURE_SHA,
    'coordinator-author-result.json': R18_AUTHOR_RESULT_SHA,
    'coordinator-diagnostic-preparation.json': '08c52ada3f2bc835357a8581bd4aadc9b0cd631131d1f99626487d254e1eeeab',
    'coordinator-diagnostic-result.json': R18_DIAG_RESULT_SHA,
    'coordinator-diagnostic-verification.json': R18_DIAG_VERIFY_SHA,
    'coordinator-diagnostic-controls.stdout.log': R18_STDOUT_SHA,
    'coordinator-diagnostic-controls.stderr.log': R18_STDERR_SHA,
    'coordinator-diagnostic-post-check.stdout.log': 'a66fd3fd2faa40e212aeab7cbc75c4a278b792e70e48730316680441ac05ac95',
    'coordinator-diagnostic-post-check.stderr.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'coordinator-diagnostic-prepare.stdout.log': 'b3754f54b7f90e04f1fc836f7d0f65f8ef767b9084ca13465bb1eb4e4d454f67',
    'coordinator-diagnostic-prepare.stderr.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'coordinator-diagnostic-delivery0.stdout.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'coordinator-diagnostic-delivery0.stderr.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'coordinator-diagnostic-delivery1.stdout.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'coordinator-diagnostic-delivery1.stderr.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'notepad-coordinator.SelfCheck.ps1': R18_SELF_SHA,
}
R18_DIAG_ARTIFACTS = {
    'coordinator-diagnostic-prepare.stdout.log': 'b3754f54b7f90e04f1fc836f7d0f65f8ef767b9084ca13465bb1eb4e4d454f67',
    'coordinator-diagnostic-prepare.stderr.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'coordinator-diagnostic-delivery0.stdout.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'coordinator-diagnostic-delivery0.stderr.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'coordinator-diagnostic-delivery1.stdout.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'coordinator-diagnostic-delivery1.stderr.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
}
OLD_R22_MANIFEST_SHA = '1611157ba0be27a2d7f5223eb615e918deefdd7a8e525c1295f45afcb1c1c5ae'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str:
    return sha(path.read_bytes())


def require(ok: bool, message: str) -> None:
    if not ok:
        raise AssertionError(message)


def records(root: Path) -> list[dict[str, object]]:
    paths = sorted((p for p in root.rglob('*') if p.is_file()), key=lambda p: p.relative_to(root).as_posix())
    require(all(not p.is_symlink() for p in paths), 'closed source/context inventory may not contain symlinks')
    return [{'path': p.relative_to(root).as_posix(), 'sha256': digest(p), 'size': p.stat().st_size} for p in paths]


def validate_inputs(source_bytes: dict[str, bytes], manifest_obj: dict[str, object], shell_bytes: bytes) -> bool:
    manifest_records = manifest_obj.get('sourceFiles')
    if not isinstance(manifest_records, list):
        return False
    t5 = [row for row in manifest_records if isinstance(row, dict) and row.get('path') == 't5/notepad-coordinator.SelfCheck.ps1']
    if len(t5) != 1 or t5[0].get('sha256') != R18_SELF_SHA:
        return False
    if sha(source_bytes.get('driver/scripts/t5/notepad-coordinator.SelfCheck.ps1', b'')) != R18_SELF_SHA:
        return False
    try:
        manifest_digest = sha(json.dumps(manifest_obj, indent=2, ensure_ascii=False).encode('utf-8') + b'\n')
    except (TypeError, ValueError):
        return False
    shell = shell_bytes.decode('utf-8')
    pins = re.findall(r"^expected_manifest_sha256='([0-9a-f]{64})'$", shell, re.MULTILINE)
    return pins == [manifest_digest]


def main() -> None:
    require(digest(R22_CAPTURE) == R22_ROOT_CAPTURE_SHA, 'R22 frozen root capture pin mismatch')
    require(digest(R22_SOURCE_CAPTURE) == R22_SOURCE_CAPTURE_SHA, 'R22 source capture pin mismatch')
    root_capture = json.loads(R22_CAPTURE.read_text(encoding='utf-8'))
    expected_baseline = root_capture['Groups']['src']
    baseline_rows = records(FROZEN_R22)
    baseline_map = {r['path']: r['sha256'] for r in baseline_rows}
    require(set(expected_baseline) == set(baseline_map) and len(baseline_map) == 63,
            'frozen R22 root source must be exactly the captured 63-file closure')
    require(all(expected_baseline[p] == baseline_map[p] for p in baseline_map),
            'frozen R22 source bytes differ from root capture')

    # R22 author/context provenance remains in the new candidate under context/r22.
    for name, expected in root_capture['Groups']['author'].items():
        require(digest(CANDIDATE / 'context/r22/author' / name) == expected,
                f'copied R22 author pin mismatch: {name}')
    for name, expected in root_capture['Groups']['context'].items():
        require(digest(CANDIDATE / 'context/r22/context' / name) == expected,
                f'copied R22 context pin mismatch: {name}')
    for name, expected in R18_CONTEXT_PINS.items():
        require(digest(R18_CONTEXT / name) == expected, f'R18 integrated evidence pin mismatch: {name}')
    for name, expected in R18_DIAG_ARTIFACTS.items():
        require(digest(R18_CONTEXT / name) == expected, f'R18 raw diagnostic step pin mismatch: {name}')
    expected_context_paths = {'r22/root-review-capture.json'}
    expected_context_paths.update('r22/author/' + name for name in root_capture['Groups']['author'])
    expected_context_paths.update('r22/context/' + name for name in root_capture['Groups']['context'])
    expected_context_paths.update('r18/' + name for name in R18_CONTEXT_PINS)
    observed_context_paths = {row['path'] for row in records(CANDIDATE / 'context')}
    require(observed_context_paths == expected_context_paths,
            'R23 context closure must contain exactly the pinned R22 and R18 inputs')

    r18_capture = json.loads((R18_CONTEXT / 'coordinator-root-review-capture.json').read_text(encoding='utf-8'))
    require(r18_capture['Groups']['src'].get('driver/scripts/t5/notepad-coordinator.SelfCheck.ps1') == R18_SELF_SHA,
            'R18 root review capture does not pin the integrated self-check')
    r18_result = json.loads((R18_CONTEXT / 'coordinator-diagnostic-result.json').read_text(encoding='utf-8'))
    r18_verify = json.loads((R18_CONTEXT / 'coordinator-diagnostic-verification.json').read_text(encoding='utf-8'))
    require(r18_result['StandaloneWindowsControlsPassed'] is True and r18_result['CoordinatorInvoked'] is False,
            'R18 actual standalone result is not a bounded diagnostic PASS')
    require(r18_verify['Assertions'] == 162 and r18_verify['SelfCheckOutputHasExactlyOneCompletePASS'] is True,
            'R18 postverification does not show exactly one complete 162-assertion PASS')
    require(r18_verify['OriginalDiagnosticProcessTerminal'] is True and
            r18_verify['OriginalControlPID'] == 4048 and
            r18_verify['OriginalControlStartFILETIME'] == 134362021960171127,
            'R18 original diagnostic process identity/terminal proof mismatch')
    require(r18_verify['SourceInputSHA256'].get('notepad-coordinator.SelfCheck.ps1') == R18_SELF_SHA and
            r18_verify['SourceInputSHA256'].get('notepad-coordinator.ps1') == R18_COORDINATOR_SHA and
            r18_verify['LocalPreparedInputsUnchanged'] is True and
            r18_verify['RemoteDirectoryContainsOnlyTwoPinnedRegularInputs'] is True,
            'R18 exact input/pin postverification is incomplete')
    require(r18_verify['RuntimeQualified'] is False and r18_verify['PairQualified'] is False and
            r18_verify['ProductVMStarted'] is False and r18_verify['HostPolicyApplied'] is False,
            'R18 diagnostic must remain unqualified outside its bounded self-check')

    current_rows = records(SRC)
    require(len(current_rows) == 63, 'R23 source closure must remain exactly 63 files')
    current_bytes = {r['path']: (SRC / r['path']).read_bytes() for r in current_rows}
    before_bytes = {r['path']: (FROZEN_R22 / r['path']).read_bytes() for r in baseline_rows}
    changed = sorted(path for path in before_bytes if before_bytes[path] != current_bytes[path])
    require(set(changed) == EXPECTED_CHANGED, f'R23 source delta must be the exact three integration paths: {changed!r}')

    self_path = 'driver/scripts/t5/notepad-coordinator.SelfCheck.ps1'
    self_data = current_bytes[self_path]
    r18_source = (R18_CONTEXT / 'notepad-coordinator.SelfCheck.ps1').read_bytes()
    require(self_data == r18_source and sha(self_data) == R18_SELF_SHA,
            'integrated T5 self-check is not the exact reviewed R18 source')

    base_manifest_path = 'driver/scripts/HarnessWindowsGate.manifest.json'
    manifest_bytes = current_bytes[base_manifest_path]
    base_manifest_bytes = before_bytes[base_manifest_path]
    require(base_manifest_bytes.count(OLD_T5_SHA.encode()) == 1,
            'R22 manifest must contain exactly one old T5 digest')
    require(manifest_bytes == base_manifest_bytes.replace(OLD_T5_SHA.encode(), R18_SELF_SHA.encode(), 1),
            'R23 manifest must change only the T5 source SHA from R22')
    old_manifest = json.loads(base_manifest_bytes)
    manifest_obj = json.loads(manifest_bytes)
    for key in ('schema', 'builder', 'powershell', 'mainFiles', 'rootSelfchecks', 't5Selfcheck'):
        require(old_manifest[key] == manifest_obj[key], f'R23 changed manifest identity/role field {key}')
    old_sources = old_manifest['sourceFiles']
    new_sources = manifest_obj['sourceFiles']
    require(len(old_sources) == len(new_sources) == 33 and
            [row['path'] for row in old_sources] == [row['path'] for row in new_sources],
            'R23 must preserve the exact ordered 33-entry execution source inventory')
    differences = [(old['path'], old['sha256'], new['sha256'])
                   for old, new in zip(old_sources, new_sources) if old['sha256'] != new['sha256']]
    require(differences == [('t5/notepad-coordinator.SelfCheck.ps1', OLD_T5_SHA, R18_SELF_SHA)],
            f'R23 manifest execution-source digest delta is not exact: {differences!r}')
    role_files = manifest_obj['mainFiles'] + manifest_obj['rootSelfchecks'] + [manifest_obj['t5Selfcheck']]
    require(len(manifest_obj['mainFiles']) == 15 and len(manifest_obj['rootSelfchecks']) == 17 and
            len(role_files) == 33 and len(set(role_files)) == 33,
            'R23 execution roles must remain unique 15 + 17 + 1')
    for key in ('gateRunner', 'gateWorker', 'gateKeeper', 'gateFixture', 'gateControl',
                'gateProtocol', 'localClient', 'transport'):
        require(old_manifest[key] == manifest_obj[key], f'R23 changed gate support pin {key}')

    shell_path = 'driver/scripts/Invoke-HarnessWindowsGate.sh'
    base_shell = before_bytes[shell_path]
    shell_bytes = current_bytes[shell_path]
    manifest_sha = sha(manifest_bytes)
    old_literal = ("expected_manifest_sha256='" + OLD_R22_MANIFEST_SHA + "'").encode()
    new_literal = ("expected_manifest_sha256='" + manifest_sha + "'").encode()
    require(base_shell.count(old_literal) == 1 and
            shell_bytes == base_shell.replace(old_literal, new_literal, 1),
            'R23 shell must change only the exact expected manifest digest')
    require(validate_inputs(current_bytes, manifest_obj, shell_bytes),
            'R23 source manifest/T5/shell pins are inconsistent')

    # Fail-closed source-only omission/mismatch controls.
    stale_manifest = json.loads(manifest_bytes)
    for row in stale_manifest['sourceFiles']:
        if row['path'] == 't5/notepad-coordinator.SelfCheck.ps1':
            row['sha256'] = OLD_T5_SHA
    require(not validate_inputs(current_bytes, stale_manifest, shell_bytes),
            'stale R22 T5 manifest pin mutant was accepted')
    stale_shell = shell_bytes.replace(new_literal, old_literal, 1)
    require(not validate_inputs(current_bytes, manifest_obj, stale_shell),
            'stale manifest digest shell mutant was accepted')
    altered_source = dict(current_bytes)
    altered_source[self_path] = b'altered coordinator self-check source'
    require(not validate_inputs(altered_source, manifest_obj, shell_bytes),
            'altered T5 execution source mutant was accepted')
    duplicate_t5 = json.loads(manifest_bytes)
    duplicate_t5['sourceFiles'].append(dict(duplicate_t5['sourceFiles'][-1]))
    require(not validate_inputs(current_bytes, duplicate_t5, shell_bytes),
            'extra execution source manifest entry mutant was accepted')

    patch_parts = []
    for path in sorted(EXPECTED_CHANGED):
        patch_parts.extend(difflib.unified_diff(
            before_bytes[path].decode('utf-8').splitlines(keepends=True),
            current_bytes[path].decode('utf-8').splitlines(keepends=True),
            fromfile='R22/' + path, tofile='R23/' + path))
    patch = ''.join(patch_parts)
    patch_path = CANDIDATE / 'author/exact-delta-from-r22.patch'
    patch_path.write_text(patch, encoding='utf-8')
    require(patch_path.read_text(encoding='utf-8') == patch,
            'R23 exact delta patch did not retain generated source diff')

    inventory_sha = sha(json.dumps(current_rows, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
    print('R23 offline source controls: PASS')
    print('Closed source inventory: 63 files; exact R22 path set preserved; 60 source files byte-identical.')
    print('Changed source paths (3): ' + ', '.join(changed))
    print(f'Canonical R23 source inventory SHA-256: {inventory_sha}')
    print(f'R18 self-check integration: exact reviewed source {R18_SELF_SHA}; 33 execution roles remain 15 + 17 + 1.')
    print(f'Manifest SHA-256 {manifest_sha}; exact shell manifest literal matches; 8 support pins unchanged.')
    print('R18 evidence: source review, exact root capture, standalone result/raw output, and PID/start-time postverification pinned; 162-assertion PASS is diagnostic-only.')
    print('Negative controls: stale T5 manifest pin, stale shell digest, altered self-check, and duplicate execution entry are rejected.')
    print('R21 atomic receipt publication and native job containment sources remain unchanged from R22.')
    print('No full gate, PowerShell, Windows, service, actor, coordinator, host, API, VM, network, or Git action performed.')
    print('Disposition: source-only R23 integration candidate; full harness, service pair, recovery, and product runtime remain unqualified.')


if __name__ == '__main__':
    main()
