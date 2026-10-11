#!/usr/bin/env python3
"""Offline R24 closed-source, pin, and pre-ready CANCEL controls."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
from pathlib import Path

REPO = Path('/home/victor/Work/safeupload-staging')
CANDIDATE = REPO / 'output/review-candidates/m2-t5-harness-windows-gate-r24-luna-a1'
SRC = CANDIDATE / 'src'
R23 = REPO / 'output/review-candidates/m2-t5-harness-windows-gate-r23-root-a1'
R23_SRC = R23 / 'src'
R23_CAPTURE = CANDIDATE / 'context/r23/root-review-capture.json'
R23_REPORT = CANDIDATE / 'context/r23/independent-review.md'
R23_CAPTURE_SHA = '7f4cd75757bddd4e02a2b88142d9773a59b96e9069883976048535c9f253788c'
R23_REPORT_SHA = '975b1d71e9d255585cd8523c95f795ded0a87b869523f578d50298565eeb5c57'
OLD_MANIFEST_SHA = '2494b0411213f07df94d43f501330f2f5d9b27195f26bedc8444709b98d2c71a'
OLD_CONTROL_SHA = '48a16decedec44e7c529ee2df099f9dbde1f2b69ef33d23d95fc58cd2b3b3caa'
OLD_FIXTURE_SHA = '599eb7da9e0177b2443d5edd937a15b29c72b0357e5c4b71a3c2397b62fb1489'
R18_SELF_SHA = 'abc6b472a16e772bdd11fea7ab88e8e3de82579fc2691c6ef2436229c88d74bb'
EXPECTED_CHANGED = {
    'driver/scripts/HarnessWindowsGateRemoteControl.ps1',
    'driver/scripts/HarnessWindowsGateLifecycleFixture.ps1',
    'driver/scripts/HarnessWindowsGate.manifest.json',
    'driver/scripts/Invoke-HarnessWindowsGate.sh',
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str:
    return sha(path.read_bytes())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def records(root: Path) -> list[dict[str, object]]:
    paths = sorted(root.rglob('*'), key=lambda p: p.relative_to(root).as_posix())
    files = [p for p in paths if p.is_file()]
    require(all(not p.is_symlink() for p in paths), f'symlink in closed tree: {root}')
    return [{'path': p.relative_to(root).as_posix(), 'sha256': digest(p), 'size': p.stat().st_size}
            for p in files]


def read_tree(root: Path) -> dict[str, bytes]:
    return {row['path']: (root / row['path']).read_bytes() for row in records(root)}


def extract_function(text: str, name: str) -> str:
    start = text.find('function ' + name + '(')
    if start < 0:
        return ''
    next_function = re.search(r'(?m)^function\s+', text[start + 1:])
    end = len(text) if next_function is None else start + 1 + next_function.start()
    return text[start:end]


def assert_messages(text: str) -> list[str]:
    messages: list[str] = []
    marker = 'Assert-R18Fixture'
    cursor = 0
    while True:
        start = text.find(marker, cursor)
        if start < 0:
            return messages
        index = start + len(marker)
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text) or text[index] != '(':
            cursor = index
            continue
        depth = 0
        in_string = False
        while index < len(text):
            char = text[index]
            if in_string:
                if char == "'":
                    if index + 1 < len(text) and text[index + 1] == "'":
                        index += 2
                        continue
                    in_string = False
            elif char == "'":
                in_string = True
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    index += 1
                    break
            index += 1
        while index < len(text) and text[index].isspace():
            index += 1
        if index < len(text) and text[index] == "'":
            index += 1
            value: list[str] = []
            while index < len(text):
                if text[index] == "'":
                    if index + 1 < len(text) and text[index + 1] == "'":
                        value.append("'")
                        index += 2
                        continue
                    break
                value.append(text[index])
                index += 1
            messages.append(''.join(value))
        cursor = max(index + 1, start + len(marker))


def validate_bundle(source_bytes: dict[str, bytes], manifest_bytes: bytes, shell_bytes: bytes) -> bool:
    try:
        manifest = json.loads(manifest_bytes)
        rows = manifest['sourceFiles']
        if not isinstance(rows, list) or len(rows) != 33:
            return False
        paths = [row['path'] for row in rows]
        if len(paths) != len(set(paths)):
            return False
        for row in rows:
            path = 'driver/scripts/' + row['path']
            data = source_bytes.get(path)
            if data is None or sha(data) != row['sha256']:
                return False
        support = {
            'gateRunner': 'HarnessWindowsGateRemote.ps1',
            'gateWorker': 'HarnessWindowsGateWorker.ps1',
            'gateControl': 'HarnessWindowsGateRemoteControl.ps1',
            'gateProtocol': 'HarnessWindowsGateProtocol.psm1',
            'localClient': 'HarnessWindowsGateClient.py',
            'transport': 'remote_ps.py',
            'gateKeeper': 'HarnessWindowsGateLeaseKeeper.ps1',
            'gateFixture': 'HarnessWindowsGateLifecycleFixture.ps1',
        }
        for key, name in support.items():
            data = source_bytes.get('driver/scripts/' + name)
            if data is None or sha(data) != manifest[key]['sha256']:
                return False
        if (len(manifest['mainFiles']) != 15 or len(manifest['rootSelfchecks']) != 17 or
                manifest['t5Selfcheck'] != 't5/notepad-coordinator.SelfCheck.ps1'):
            return False
        if paths != manifest['mainFiles'] + manifest['rootSelfchecks'] + [manifest['t5Selfcheck']]:
            return False
        if sha(source_bytes['driver/scripts/t5/notepad-coordinator.SelfCheck.ps1']) != R18_SELF_SHA:
            return False
        shell = shell_bytes.decode('utf-8')
        literals = {
            'expected_manifest_sha256': sha(manifest_bytes),
            'expected_fixture_sha256': manifest['gateFixture']['sha256'],
            'expected_control_sha256': manifest['gateControl']['sha256'],
        }
        for key, value in literals.items():
            if re.findall(r"^" + re.escape(key) + r"='([0-9a-f]{64})'$", shell, re.MULTILINE) != [value]:
                return False
        return True
    except (KeyError, TypeError, ValueError, UnicodeDecodeError):
        return False


def pre_ready_eligible(case: dict[str, object]) -> bool:
    original_phase = case.get('original_phase')
    if case.get('mode') != 'CANCEL' or original_phase not in ('JOBS_CREATED', 'KEEPER_IDENTITY_DURABLE'):
        return False
    if case.get('status') != 'RUNNING' or case.get('run_token_ok') is not True:
        return False
    if case.get('ready_hash') != '' or case.get('ready_file') is not False:
        return False
    if case.get('main_job_held_kill_on_close') is not True or case.get('keeper_job_held_kill_on_close') is not True:
        return False
    if case.get('main_ids') != [] or case.get('worker_pid') != 0 or case.get('worker_start') != 0:
        return False
    if original_phase == 'JOBS_CREATED':
        if case.get('original_keeper_pid') != 0 or case.get('original_keeper_start') != 0:
            return False
        if case.get('post_phase') != 'CANCEL_RECOVERED_KEEPER_IDENTITY':
            return False
    else:
        if case.get('original_keeper_pid', 0) <= 0 or case.get('original_keeper_start', 0) <= 0:
            return False
        if case.get('post_phase') != 'KEEPER_IDENTITY_DURABLE':
            return False
        if (case.get('state_keeper_pid') != case.get('original_keeper_pid') or
                case.get('state_keeper_start') != case.get('original_keeper_start')):
            return False
    keeper_pid = case.get('keeper_handle_pid')
    keeper_start = case.get('keeper_handle_start')
    return bool(
        keeper_pid and keeper_start and
        case.get('state_keeper_pid') == keeper_pid and
        case.get('state_keeper_start') == keeper_start and
        case.get('keeper_ids') == [keeper_pid] and
        case.get('keeper_active') == 1 and
        case.get('keeper_handle_live') is True and
        case.get('keeper_handle_in_job') is True and
        case.get('keeper_path_token_match') is True
    )


def base_pre_ready_case(phase: str) -> dict[str, object]:
    case: dict[str, object] = {
        'mode': 'CANCEL', 'status': 'RUNNING', 'run_token_ok': True,
        'ready_hash': '', 'ready_file': False,
        'main_job_held_kill_on_close': True, 'keeper_job_held_kill_on_close': True,
        'main_ids': [], 'worker_pid': 0, 'worker_start': 0,
        'original_phase': phase, 'original_keeper_pid': 0 if phase == 'JOBS_CREATED' else 811,
        'original_keeper_start': 0 if phase == 'JOBS_CREATED' else 9001,
        'post_phase': 'CANCEL_RECOVERED_KEEPER_IDENTITY' if phase == 'JOBS_CREATED' else 'KEEPER_IDENTITY_DURABLE',
        'state_keeper_pid': 811, 'state_keeper_start': 9001,
        'keeper_handle_pid': 811, 'keeper_handle_start': 9001,
        'keeper_ids': [811], 'keeper_active': 1,
        'keeper_handle_live': True, 'keeper_handle_in_job': True,
        'keeper_path_token_match': True,
    }
    return case


def main() -> None:
    require(digest(R23_CAPTURE) == R23_CAPTURE_SHA, 'R23 frozen root capture SHA mismatch')
    require(digest(R23_REPORT) == R23_REPORT_SHA, 'R23 independent review SHA mismatch')
    capture = json.loads(R23_CAPTURE.read_text(encoding='utf-8'))
    require(capture['ClosedInventoryVerified'] is True and capture['TwoFDStableReadsAndPostCopyEquality'] is True,
            'R23 root capture does not assert a complete stable inventory')
    require(capture['SourceAccepted'] is False and capture['RuntimeQualified'] is False and
            capture['ProductVMStarted'] is False and capture['HostPolicyApplied'] is False,
            'R23 must remain source-pending and runtime-unqualified')
    baseline_rows = records(R23_SRC)
    baseline_map = {row['path']: row['sha256'] for row in baseline_rows}
    require(set(capture['Groups']['src']) == set(baseline_map) and len(baseline_map) == 63,
            'R23 source is not exactly the frozen 63-file root capture')
    require(all(capture['Groups']['src'][path] == baseline_map[path] for path in baseline_map),
            'R23 frozen source differs from its exact capture')

    context_root = CANDIDATE / 'context/r23'
    for name, expected in capture['Groups']['author'].items():
        require(digest(context_root / 'author' / name) == expected, f'R23 author context pin mismatch: {name}')
    for name, expected in capture['Groups']['context'].items():
        require(digest(context_root / 'context' / name) == expected, f'R23 prior-context pin mismatch: {name}')
    context_rows = records(CANDIDATE / 'context')
    expected_context = {'r23/root-review-capture.json', 'r23/independent-review.md'}
    expected_context.update('r23/author/' + name for name in capture['Groups']['author'])
    expected_context.update('r23/context/' + name for name in capture['Groups']['context'])
    require({row['path'] for row in context_rows} == expected_context,
            'R24 context is not the exact 49-file R23 source/review/provenance closure')

    current_rows = records(SRC)
    current_map = {row['path']: row['sha256'] for row in current_rows}
    require(len(current_rows) == 63 and set(current_map) == set(baseline_map),
            'R24 source must preserve the exact 63-file R23 path set')
    require(all(capture['Groups']['src'][path] == baseline_map[path] for path in baseline_map),
            'R23 source changed while R24 was authored')
    changed = sorted(path for path in baseline_map if current_map[path] != baseline_map[path])
    require(set(changed) == EXPECTED_CHANGED, f'R24 source delta is not the exact four intended paths: {changed!r}')
    source_bytes = read_tree(SRC)
    baseline_bytes = read_tree(R23_SRC)
    require(sum(source_bytes[path] == baseline_bytes[path] for path in baseline_map) == 59,
            'R24 must preserve 59 of 63 sources byte-for-byte')

    control_rel = 'driver/scripts/HarnessWindowsGateRemoteControl.ps1'
    fixture_rel = 'driver/scripts/HarnessWindowsGateLifecycleFixture.ps1'
    manifest_rel = 'driver/scripts/HarnessWindowsGate.manifest.json'
    shell_rel = 'driver/scripts/Invoke-HarnessWindowsGate.sh'
    control = source_bytes[control_rel].decode('utf-8')
    old_control = baseline_bytes[control_rel].decode('utf-8')
    fixture = source_bytes[fixture_rel].decode('utf-8')
    old_fixture = baseline_bytes[fixture_rel].decode('utf-8')

    receipt_function = extract_function(old_control, 'Assert-KeeperReadyReceipt')
    require(receipt_function and extract_function(control, 'Assert-KeeperReadyReceipt') == receipt_function,
            'R24 altered strict ready-receipt validation')
    open_keeper = extract_function(old_control, 'Open-KeeperProcess')
    require(open_keeper and extract_function(control, 'Open-KeeperProcess') == open_keeper,
            'R24 altered the reviewed exact keeper-recovery primitive')
    verify_tail_start = '        if ($Mode -eq \'VERIFY\') {'
    require(old_control[old_control.index(verify_tail_start):] == control[control.index(verify_tail_start):],
            'R24 changed the existing VERIFY/CANCEL/CLEANUP termination, wait, drain, or terminal-record tail')
    original_capture = control.index('$originalKeeperPhase = [string]$state.phase')
    open_call = control.index('$keeperProcess = Open-KeeperProcess $state')
    require(original_capture < open_call and
            control.index('$originalKeeperPid = [uint32]$state.keeperPid') < open_call and
            control.index('$originalKeeperStartFiletime = [long]$state.keeperStartFiletime') < open_call,
            'original durable phase and keeper identity must be captured before Open-KeeperProcess can recover/rewrite state')
    precheck = control[original_capture:open_call]
    for required in (
        "$Mode -eq 'CANCEL'", "'JOBS_CREATED'", "'KEEPER_IDENTITY_DURABLE'",
        "'RUNNING'", 'keeperReadySha256', '$null -eq $state.keeperReadySha256', 'Test-Path -LiteralPath',
        'workerPid', 'workerStartFiletime', 'mainSnapshot.Active -ne 0',
        '$originalKeeperPid -ne 0', '$originalKeeperStartFiletime -ne 0',
    ):
        require(required in precheck, f'pre-open exact startup eligibility check is missing {required!r}')
    helper = extract_function(control, 'Assert-PreReadyCancelKeeperIdentity')
    for required in (
        "$Mode -cne 'CANCEL'", 'VerifyKillOnCloseJob($MainJobHandle)',
        'VerifyKillOnCloseJob($KeeperJobHandle)', '$State.runToken -cne $RunToken',
        'Get-HarnessGateJobName $RunToken', 'Get-HarnessGateKeeperJobName $RunToken',
        'Assert-LiveScriptIdentity $KeeperProcess $KeeperPath',
        'IsProcessHandleInJob($KeeperProcess.ProcessHandle, $KeeperJobHandle)',
        'WaitHandle($KeeperProcess.ProcessHandle, [uint32]0) -ne 258',
        '$KeeperSnapshot.Active -ne 1', '$KeeperSnapshot.Ids.Length -ne 1',
        '$State.workerPid -ne 0', '$MainSnapshot.Ids.Length -ne 0',
        'keeperReadySha256', '$null -eq $State.keeperReadySha256', 'Test-Path -LiteralPath',
        "'CANCEL_RECOVERED_KEEPER_IDENTITY'", "'KEEPER_IDENTITY_DURABLE'",
        '$OriginalKeeperStartFiletime',
    ):
        require(required in helper, f'pre-ready exact identity gate is missing {required!r}')
    require('Terminate' not in helper, 'identity-admission helper must not itself terminate or mutate a process')
    route = control[control.index('if ($null -ne $keeperProcess -and -not (Test-ProcessHandleTerminal $keeperProcess))'):control.index(verify_tail_start)]
    require("if ($preReadyCancelCandidate)" in route and
            'Assert-PreReadyCancelKeeperIdentity' in route and
            'Assert-KeeperReadyReceipt $state' in route and
            route.index('Assert-PreReadyCancelKeeperIdentity') < route.index('Assert-KeeperReadyReceipt $state'),
            'only the exact pre-ready CANCEL candidate may bypass the receipt assertion')

    cancel_function = extract_function(old_fixture, 'Invoke-R18Cancel')
    require(cancel_function and extract_function(fixture, 'Invoke-R18Cancel') == cancel_function,
            'R24 altered the existing exact successful CANCEL subprocess/receipt verifier')
    old_assertions = assert_messages(old_fixture)
    require(old_assertions and all(assertion in fixture for assertion in old_assertions),
            'R24 removed or rewrote an existing lifecycle assertion message')
    require(fixture.count("Invoke-R18BarrierCase 'BeforeKeeperPublication'") == 1 and
            fixture.count("Invoke-R18BarrierCase 'BeforeKeeperResume'") == 1,
            'both exact startup barrier cases must remain enabled exactly once')
    for required in (
        'both startup barriers have no readiness hash or receipt',
        'VERIFY without readiness fails without rewriting durable state',
        'failed VERIFY does not synthesize keeper readiness',
        'mismatched keeper path is rejected without control-side state rewrite',
        'mismatched durable keeper FILETIME is rejected without control-side state rewrite',
        'identity-negative controls restore the original unpublished barrier state',
        'identity-negative controls restore the original durable barrier identity',
        'ambiguity control holds exactly the real keeper plus one distinct job-listed process',
        'ambiguous keeper identity is rejected without durable state rewrite',
        'ambiguous CANCEL leaves both original held process handles active',
        'exact ambiguity-control process drain restores only the original keeper PID',
        'CANCEL terminates the exact retained keeper process handle',
        'held keeper job reaches exact zero after CANCEL',
        'held main job remains exact zero after keeper termination',
        'CANCEL durable state carries its exact terminal and post-pin proof',
        'CANCEL terminal state retains the exact original keeper PID and FILETIME',
        'successful pre-ready CANCEL records no synthesized readiness receipt',
        'outer fixture job reaches exact zero only after CANCEL and controller termination',
        'ambiguousChildTerminal=',
    ):
        require(required in fixture, f'fixture control or exact terminal assertion is missing {required!r}')
    require("$scriptText = 'while ($true) { [System.Threading.Thread]::Sleep(1000) }'" in fixture,
            'ambiguity fixture child must remain a bounded harmless sleep loop')
    require('Start-Process' not in fixture and 'Invoke-Expression' not in fixture,
            'R24 fixture may not introduce unrestricted process launch or dynamic evaluation')

    baseline_manifest_bytes = baseline_bytes[manifest_rel]
    manifest_bytes = source_bytes[manifest_rel]
    old_manifest_text = baseline_manifest_bytes.decode('utf-8')
    expected_manifest_text = old_manifest_text
    for old, new in ((OLD_CONTROL_SHA, digest(SRC / control_rel)), (OLD_FIXTURE_SHA, digest(SRC / fixture_rel))):
        require(expected_manifest_text.count(old) == 1, f'R23 manifest must contain exactly one support pin {old}')
        expected_manifest_text = expected_manifest_text.replace(old, new, 1)
    require(manifest_bytes.decode('utf-8') == expected_manifest_text,
            'R24 manifest may change only the two derived gateControl/gateFixture support hashes')
    manifest = json.loads(manifest_bytes)
    old_manifest = json.loads(baseline_manifest_bytes)
    require(manifest['mainFiles'] == old_manifest['mainFiles'] and
            manifest['rootSelfchecks'] == old_manifest['rootSelfchecks'] and
            manifest['t5Selfcheck'] == old_manifest['t5Selfcheck'],
            'R24 changed the closed 15 main + 17 root + one T5 execution roles')
    require(len(manifest['sourceFiles']) == 33 and
            [r['path'] for r in manifest['sourceFiles']] ==
            old_manifest['mainFiles'] + old_manifest['rootSelfchecks'] + [old_manifest['t5Selfcheck']] and
            len({r['path'] for r in manifest['sourceFiles']}) == 33,
            'R24 changed the ordered unique 33-role execution input inventory')
    require(manifest['sourceFiles'] == old_manifest['sourceFiles'],
            'R24 must preserve every execution-source hash, including the reviewed R18 T5 self-check')
    for key in ('gateRunner', 'gateWorker', 'gateProtocol', 'localClient', 'transport', 'gateKeeper'):
        require(manifest[key] == old_manifest[key], f'R24 changed unrelated support input {key}')
    require(manifest['gateControl']['sha256'] == digest(SRC / control_rel) and
            manifest['gateFixture']['sha256'] == digest(SRC / fixture_rel),
            'R24 manifest support pins do not bind the exact changed control and fixture')

    shell_bytes = source_bytes[shell_rel]
    old_shell_bytes = baseline_bytes[shell_rel]
    old_shell = old_shell_bytes.decode('utf-8')
    new_shell = old_shell
    replacements = (
        (OLD_MANIFEST_SHA, sha(manifest_bytes)),
        (OLD_FIXTURE_SHA, digest(SRC / fixture_rel)),
        (OLD_CONTROL_SHA, digest(SRC / control_rel)),
    )
    for old, new in replacements:
        literal = ("expected_" + ('manifest_sha256=' if old == OLD_MANIFEST_SHA else
                   'fixture_sha256=' if old == OLD_FIXTURE_SHA else 'control_sha256=') + "'").encode()
        expected_line = literal + old.encode() + b"'"
        replacement_line = literal + new.encode() + b"'"
        require(old_shell_bytes.count(expected_line) == 1, f'R23 shell must contain exactly one derived pin {old}')
        new_shell = new_shell.replace(expected_line.decode(), replacement_line.decode(), 1)
    require(shell_bytes.decode('utf-8') == new_shell,
            'R24 shell may change only manifest, gateControl, and gateFixture expected hash literals')
    require(validate_bundle(source_bytes, manifest_bytes, shell_bytes),
            'R24 source roles/support pins/shell digest are not internally consistent')

    changed_paths = sorted(EXPECTED_CHANGED)
    for path in changed_paths:
        data = source_bytes[path].decode('utf-8')
        require(data.endswith('\n') and not data.endswith('\n\n'), f'changed source final newline is noncanonical: {path}')
        require(all(line.rstrip(' \t') == line for line in data.splitlines()),
                f'changed source contains trailing whitespace: {path}')

    # Pure in-memory admission model: source controls only; it does not invoke PowerShell or native code.
    publication = base_pre_ready_case('JOBS_CREATED')
    resume = base_pre_ready_case('KEEPER_IDENTITY_DURABLE')
    require(pre_ready_eligible(publication), 'valid unpublished exact-recovery case was denied by the model')
    require(pre_ready_eligible(resume), 'valid pre-resume durable identity case was denied by the model')
    mutants: list[tuple[str, dict[str, object]]] = []
    mutant = copy.deepcopy(resume); mutant['mode'] = 'VERIFY'; mutants.append(('VERIFY mode', mutant))
    mutant = copy.deepcopy(resume); mutant['mode'] = 'CLEANUP'; mutants.append(('CLEANUP mode', mutant))
    mutant = copy.deepcopy(publication); mutant['original_phase'] = 'WORKER_RUNNING'; mutants.append(('wrong original phase', mutant))
    mutant = copy.deepcopy(publication); mutant['post_phase'] = 'KEEPER_IDENTITY_DURABLE'; mutants.append(('wrong recovered phase', mutant))
    mutant = copy.deepcopy(publication); mutant['original_keeper_pid'] = 812; mutants.append(('nonempty original unpublished PID', mutant))
    mutant = copy.deepcopy(resume); mutant['state_keeper_start'] = 9002; mutants.append(('durable FILETIME mismatch', mutant))
    mutant = copy.deepcopy(resume); mutant['ready_hash'] = 'a' * 64; mutants.append(('readiness hash present', mutant))
    mutant = copy.deepcopy(resume); mutant['ready_hash'] = None; mutants.append(('null readiness hash', mutant))
    mutant = copy.deepcopy(resume); mutant['ready_file'] = True; mutants.append(('readiness file present', mutant))
    mutant = copy.deepcopy(resume); mutant['main_job_held_kill_on_close'] = False; mutants.append(('missing main job handle', mutant))
    mutant = copy.deepcopy(resume); mutant['keeper_job_held_kill_on_close'] = False; mutants.append(('missing keeper job handle', mutant))
    mutant = copy.deepcopy(resume); mutant['main_ids'] = [912]; mutants.append(('nonempty main job', mutant))
    mutant = copy.deepcopy(resume); mutant['worker_pid'] = 912; mutants.append(('published worker', mutant))
    mutant = copy.deepcopy(resume); mutant['keeper_ids'] = [811, 912]; mutant['keeper_active'] = 2; mutants.append(('ambiguous keeper job PID list', mutant))
    mutant = copy.deepcopy(resume); mutant['keeper_handle_pid'] = 812; mutants.append(('wrong handle PID', mutant))
    mutant = copy.deepcopy(resume); mutant['keeper_handle_start'] = 9002; mutants.append(('wrong handle creation FILETIME', mutant))
    mutant = copy.deepcopy(resume); mutant['keeper_handle_live'] = False; mutants.append(('terminal keeper handle', mutant))
    mutant = copy.deepcopy(resume); mutant['keeper_handle_in_job'] = False; mutants.append(('keeper handle outside job', mutant))
    mutant = copy.deepcopy(resume); mutant['keeper_path_token_match'] = False; mutants.append(('keeper path or token mismatch', mutant))
    mutant = copy.deepcopy(resume); mutant['run_token_ok'] = False; mutants.append(('wrong run token', mutant))
    for label, mutant in mutants:
        require(not pre_ready_eligible(mutant), f'pre-ready synthetic negative accepted: {label}')

    # Source-tree mutation controls prove stale/omitted/altered pin inputs reject.
    stale_control = json.loads(manifest_bytes)
    stale_control['gateControl']['sha256'] = OLD_CONTROL_SHA
    require(not validate_bundle(source_bytes, json.dumps(stale_control, indent=2).encode() + b'\n', shell_bytes),
            'stale gateControl support pin mutant was accepted')
    stale_fixture = json.loads(manifest_bytes)
    stale_fixture['gateFixture']['sha256'] = OLD_FIXTURE_SHA
    require(not validate_bundle(source_bytes, json.dumps(stale_fixture, indent=2).encode() + b'\n', shell_bytes),
            'stale gateFixture support pin mutant was accepted')
    altered = dict(source_bytes); altered[control_rel] += b'\n# altered source\n'
    require(not validate_bundle(altered, manifest_bytes, shell_bytes), 'altered control-source mutant was accepted')
    duplicate = json.loads(manifest_bytes); duplicate['sourceFiles'].append(dict(duplicate['sourceFiles'][-1]))
    require(not validate_bundle(source_bytes, json.dumps(duplicate, indent=2).encode() + b'\n', shell_bytes),
            'duplicate execution entry mutant was accepted')
    missing = json.loads(manifest_bytes); missing['sourceFiles'].pop()
    require(not validate_bundle(source_bytes, json.dumps(missing, indent=2).encode() + b'\n', shell_bytes),
            'missing execution entry mutant was accepted')
    stale_shell = shell_bytes.replace(sha(manifest_bytes).encode(), OLD_MANIFEST_SHA.encode(), 1)
    require(not validate_bundle(source_bytes, manifest_bytes, stale_shell), 'stale shell manifest digest mutant was accepted')

    helper = SRC / 'driver/scripts/HarnessWindowsGateManifest.py'
    self_test = subprocess.run(
        ['python3', '-I', '-B', str(helper), '--self-test'], cwd=SRC,
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    args = [
        'python3', '-I', '-B', str(helper), '--verify',
        '--manifest', str(SRC / 'driver/scripts/HarnessWindowsGate.manifest.json'),
        '--expected-manifest-sha256', sha(manifest_bytes),
    ]
    for key, arg in (
        ('gateRunner', '--expected-runner-sha256'),
        ('gateWorker', '--expected-worker-sha256'),
        ('gateKeeper', '--expected-keeper-sha256'),
        ('gateFixture', '--expected-fixture-sha256'),
        ('gateControl', '--expected-control-sha256'),
        ('gateProtocol', '--expected-protocol-sha256'),
    ):
        args.extend([arg, manifest[key]['sha256']])
    args.extend(['--root', str(SRC / 'driver/scripts'), '--phase', 'R24-source-controls'])
    verify = subprocess.run(args, cwd=SRC, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    shell_check = subprocess.run(
        ['bash', '-n', str(SRC / shell_rel)], cwd=REPO,
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    require(records(SRC) == current_rows and records(CANDIDATE / 'context') == context_rows and
            records(R23_SRC) == baseline_rows, 'R23/R24 source or context bytes changed during offline controls')
    require(digest(R23_CAPTURE) == R23_CAPTURE_SHA and digest(R23_REPORT) == R23_REPORT_SHA,
            'R23 capture or independent report changed during offline controls')

    print('R24 offline source controls: PASS')
    print('R23 frozen root closure: 63 source / 7 author / 40 context inputs; root capture and review pins verified.')
    print('R24 exact source closure: 63 paths; 59 byte-identical; changed paths: ' + ', '.join(changed_paths))
    print(f'Pre-ready routing model: two valid barrier phases accepted; {len(mutants)} wrong-mode/state/receipt/job/identity cases rejected.')
    print('Fixture controls present for both barriers: VERIFY/no-ready, path mismatch, ambiguity, exact cancellation/drains; pre-resume also checks mismatched FILETIME.')
    print('Manifest helper self-check: ' + self_test.stdout.strip())
    print('Manifest exact source/support verification: ' + verify.stdout.strip())
    print('Manifest/shell stale-pin, altered-source, missing-entry, and duplicate-entry mutants rejected.')
    print('Shell syntax: bash -n PASS. No PowerShell parser/runtime, Windows, service, actor, coordinator, host/API, VM, network, or Git action performed.')
    print('R24 remains a source-only candidate pending root capture, independent review, and separately authorized bounded execution.')


if __name__ == '__main__':
    main()
