#!/usr/bin/env python3
"""Linux-only source/structure audit, not a PowerShell parser or VM proof."""
from pathlib import Path
import ast
import importlib.util
import json
import re
import subprocess
import sys
import tempfile

SCRIPTS = Path(__file__).resolve().parent
FORBIDDEN = r'(?i)(?:\.\s*Kill\s*\(|\bStop-Process\b|\bStop-ScheduledTask\b|\btaskkill\b)'


def check(ok, message):
    if not ok:
        raise AssertionError(message)


def code_mask(source):
    """Mask PS strings/comments, preserving offsets/braces for a structural audit.

    Handles single/double quotes, doubled quotes, backtick escapes, here strings,
    line comments and block comments. Does not claim PowerShell AST equivalence.
    """
    chars = list(source); i = 0
    while i < len(source):
        start = i
        if source.startswith('<#', i):
            end = source.find('#>', i + 2)
            check(end != -1, 'Unclosed block comment'); i = end + 2
        elif source[i] == '#':
            end = source.find('\n', i); i = len(source) if end == -1 else end
        elif source.startswith("@'", i) or source.startswith('@"', i):
            quote = source[i + 1]
            end = re.search(r'(?m)^' + re.escape(quote + '@') + r'\s*$', source[i + 2:])
            check(end is not None, 'Unclosed here string'); i = i + 2 + end.end()
        elif source[i] in "'\"":
            quote = source[i]; i += 1
            while i < len(source):
                if source[i] == '`' and quote == '"':
                    i += 2; continue
                if source[i] == quote:
                    if i + 1 < len(source) and source[i + 1] == quote:
                        i += 2; continue
                    i += 1; break
                i += 1
            else:
                raise AssertionError('Unclosed quoted string')
        else:
            i += 1; continue
        for n in range(start, min(i, len(chars))):
            if chars[n] != '\n':
                chars[n] = ' '
    return ''.join(chars)


def closing(mask, opening):
    depth = 0
    for i in range(opening, len(mask)):
        if mask[i] == '{':
            depth += 1
        elif mask[i] == '}':
            depth -= 1
            if depth == 0:
                return i
    raise AssertionError('Unbalanced structural brace')


def function_body(source, name):
    masked = code_mask(source)
    match = re.search(r'(?m)^function\s+' + re.escape(name) + r'\b[^\n{]*\{', masked)
    check(match is not None, 'Missing function: ' + name)
    begin = match.end() - 1; end = closing(masked, begin)
    return source[begin + 1:end], begin, end


def audit_parent(source):
    check(not re.search(FORBIDDEN, source), 'Termination primitive in parent')
    stack = []
    for token in code_mask(source):
        if token in '([{':
            stack.append(token)
        elif token in ')]}':
            check(stack and stack.pop() == {')': '(', ']': '[', '}': '{'}[token], 'Mismatched PS structural delimiters')
    check(not stack, 'Unclosed PS structural delimiters')
    # No custom action may impose a finite task execution limit. Reading the
    # setting to prove PT0S is allowed; every constructor must explicitly use Zero.
    limits = re.findall(r'-ExecutionTimeLimit\s+([^\n]+)', source)
    check(limits and all(v.strip() == '([TimeSpan]::Zero)' for v in limits), 'Finite/implicit task execution limit')
    for forbidden in (r'\?\?', r'&&', r'-AsHashtable\b', r'ForEach-Object\s+-Parallel', r'\[ulong\]', r'\?[^\n]+:'):
        check(not re.search(forbidden, code_mask(source), re.I), 'PS7/unsigned range hazard: ' + forbidden)
    restore, begin, end = function_body(source, 'Restore-TerminalRun')
    guard = "if(-not(Test-TerminalState)){throw 'Restoration refused: terminal predicate false'}"
    frozen = "if($state.Frozen -ne $true){throw 'Restoration refused: evidence not frozen'}"
    effective = re.sub(r'(?m)^\s*#.*$', '', restore).strip()
    check(effective.startswith(guard + '\n    ' + frozen), 'Restoration guard does not dominate all restoration')
    terminal, _, _ = function_body(source, 'Test-TerminalState')
    for item in ("$state.RecoveryRequired -ne $false", "$state.ChildStarted -ne $true", "$task.State -cne 'Ready'",
                 '$done.Exited -ne $true', '$d.RecoveryRequired -ne $false', '$d.WriterExited -ne $true',
                 "Get-Process -Id ([int]$done.Pid)", "Get-Process -Id ([int]$d.WriterPid)",
                 '$status.CurrentHeld -ne 0', '$status.Mode -ne 0', '$status.ArmedFileObject -ne 0', '$status.LowerPosts -ne 1',
                 '$status=$d.LowerDisarmTerminal'):
        check(item in terminal, 'Missing terminal/disconnect invariant: ' + item)
    check('[SafeUploadSectionFaultClient]::new' not in source and 'DisarmWrite(' not in source and 'ReadWriteStatus(' not in source, 'Parent can own/disconnect a pending lower port')
    # All destructive native and registry/file/task operations reside in the
    # guarded restoration function, except one owned state-root deletion in
    # Finalize after the safe-restored + recovery=false + reboot predicate.
    outside = source[:begin + 1] + ' ' * (end - begin - 1) + source[end:]
    for forbidden in (r"Native 'fltmc.exe' @\('unload'", r"Native 'sc.exe' @\('(?:stop|delete)'", r"'/removedriver'", r"'/reset'", r'Unregister-ScheduledTask', r'Remove-ItemProperty'):
        check(not re.search(forbidden, outside), 'Restoration mutation outside guard: ' + forbidden)
    removes = re.findall(r'(?m)^\s*Remove-Item\b[^\n]*', outside)
    check(removes == ['        Remove-Item -LiteralPath $stateDirectory -Recurse -Force'], 'Ungated file/lower removal')
    finalize = source[source.index("}else{\n    $state=[Management.Automation.PSSerializer]"):]
    check(finalize.index('$state.Restored -ne $true') < finalize.index(removes[0].strip()), 'Finalize removal before restored assertion')
    check(finalize.index('$state.RecoveryRequired -ne $false') < finalize.index(removes[0].strip()), 'Finalize removal with RecoveryRequired')
    after = source[source.index("}elseif($Phase -eq 'AfterBoot')"):source.index("}else{\n    $state=[Management.Automation.PSSerializer]")]
    sequence = ["if(-not(Test-TerminalState)){Recovery", 'Freeze-Artifacts', 'Restore-TerminalRun', "'W01_CASE_COMPLETED=True';'W01_RESTORED=True'"]
    offsets = [after.index(item) for item in sequence]
    check(offsets == sorted(offsets), 'Unsafe AfterBoot freeze/restore/sentinel order')
    check(len(re.findall(r'(?m)^\s*Restore-TerminalRun\s*$', source)) == 1, 'Unexpected restoration call site')
    check('finally' not in code_mask(after), 'Restoration reachable through AfterBoot finally')
    check('write.request' not in code_mask(source), 'Parent can publish write request')
    check(not re.search(r"Request\s+['\"]write|Write-\w+.*['\"]write\.request", source), 'Parent owns write trigger')
    params = source[:source.index("$ErrorActionPreference='Stop'")]
    hashes = re.findall(r'\$Expected\w+Sha256', params)
    check(set(hashes) == {'$Expected' + n + 'Sha256' for n in ('InputManifest','Feature','Lower','Inspector','Stimulus','Client','Child','Observer','Suite','ServicePackage','ServiceTree','Bytes','OriginalDriver','OriginalPolicy')}, 'Missing required hash pins')
    for line in params.splitlines():
        if re.search(r'\$Expected\w+Sha256', line):
            check('[Parameter(Mandatory=$true)]' in line and "ValidatePattern('^[A-Fa-f0-9]{64}$')" in line, 'Hash is optional/unvalidated')
    check('[IO.FileMode]::CreateNew' in source and 'Hardlinks -ne 1' in source and 'Assert-NoReparse' in source, 'Exclusive identity prerequisites missing')


def audit_host(source, module):
    tree = ast.parse(source)
    check(not re.search(FORBIDDEN, source), 'Termination primitive in host')
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            check('InvariantQualification' not in ast.unparse(node), 'Host imports S01 host')
        if isinstance(node, (ast.Name, ast.Attribute)):
            check((node.id if isinstance(node, ast.Name) else node.attr) != 'phase_line', 'Host reuses S01 phase_line')
        if isinstance(node, ast.Call):
            check(not any(k.arg == 'timeout' for k in node.keywords), 'Host applies process timeout')
            if isinstance(node.func, ast.Attribute):
                check(node.func.attr not in ('kill', 'terminate'), 'Host terminates a process')
    for phase in ('Prepare', 'AfterBoot', 'Finalize'):
        line = module.transport_phase_line(phase, 'phase.ps1', 'A' * 64, 'boot-start-w01-selfcheck', r'C:\Evidence')
        check(not re.search(FORBIDDEN, line), 'Generated phase contains termination')
        check('WaitForExit' not in line and 'Start-Process' not in line, 'Generated phase applies a process deadline')
        check('-ExecutionTimeLimit ([TimeSpan]::Zero)' in line, 'Generated task limit is finite/default')
        check('Transport wait expired; guest task retained' in line and "State -ne 'Ready'" in line, 'Transport expiry does not fail closed')
        check(line.index("State -ne 'Ready'") < line.index('Unregister-ScheduledTask'), 'Transport can remove pending task')
        check(line.index('Safe phase sentinel missing; retain phase task') < line.index('Unregister-ScheduledTask'), 'Transport can remove phase task while child is pending')
        short = module.wrapper_phase_line('w01-' + 'a' * 32 + '-transport-' + phase + '.ps1', 'A' * 64)
        wrapper_script = "$global:ProgressPreference = 'SilentlyContinue'\n$ErrorActionPreference = 'Continue'\ntry { " + short + "; 'HARNESS_RETURNED' } catch { 'HARNESS_THREW: ' + $_.Exception.Message }\n"
        encoded_length = len(__import__('base64').b64encode(wrapper_script.encode('utf-16le'))) + 128
        check(encoded_length < 7000, 'remote_ps long-script cleanup can run while pending')
    for item in ('require(expected == hashes', 'recovery_markers(evroot)', 'finally:\n        copies = collect_guest', "sha(source) != hashes[key]", 'input-staging-verified.json', "name = 'boot-start-w01-", 'source_transport_gate', 'frozen-manifest.json'):
        check(item in source, 'Missing host invariant: ' + item)
    with tempfile.TemporaryDirectory(prefix='w01-recovery-check-') as tmp:
        root = Path(tmp); check(not module.recovery_markers(root), 'Empty recovery latch fails')
        (root / 'prior-recovery-required.txt').write_text('GUEST_RECOVERY_REQUIRED=True\n')
        check(module.recovery_markers(root), 'Prior recovery latch bypassed')
        marker = root / 'prior-recovery-required.txt'
        digest = module.sha(marker)
        check(not module.recovery_markers(root, {'prior-recovery-required.txt': digest}), 'Exact operator-resolved marker still latches')
        check(module.recovery_markers(root, {'prior-recovery-required.txt': '0' * 64}), 'Hash-mismatched disposition cleared a marker')
        check(module.recovery_markers(root, {'other-recovery-required.txt': digest}), 'Path-mismatched disposition cleared a marker')
        marker.write_text('GUEST_RECOVERY_REQUIRED=True\nmodified\n')
        check(module.recovery_markers(root, {'prior-recovery-required.txt': digest}), 'Modified marker stayed cleared')
        w01 = root / 'boot-start-w01-x-recovery-required.json'
        w01.write_text('{}')
        check(module.recovery_markers(root, {w01.name: module.sha(w01)}), 'W01-family marker was cleared by a disposition')
        lease = root / 'w01-recovery-required-active.json'
        lease.write_text('{}')
        check(lease.name in [Path(x).name for x in module.recovery_markers(root, {lease.name: module.sha(lease)})], 'Active W01 lease was cleared')
        note = root / 'note.json'
        note.write_text(json.dumps({'Schema': 'RecoveryMarkerDisposition/1', 'Resolved': [{'Path': 'x', 'Sha256': '0' * 64}]}))
        check(module.load_disposition(note, '0' * 64) == {}, 'Disposition with the wrong pinned hash was accepted')
        check(module.load_disposition(root / 'missing.json') == {}, 'Missing disposition did not fail closed')
        listed = root / 'listed.json'
        listed.write_text('[1]')
        check(module.load_disposition(listed, module.sha(listed)) == {}, 'Non-object disposition did not fail closed')
        hidden = root / 'hidden'; hidden.mkdir()
        (hidden / 'inner-recovery-required.txt').write_text('x')
        outside = Path(tmp).parent / ('w01-link-target-' + root.name); outside.mkdir()
        (outside / 'late-recovery-required.txt').write_text('x')
        (root / 'linkdir').symlink_to(outside, target_is_directory=True)
        check(any('symlink' in item for item in module.recovery_markers(root, {})), 'Symlinked directory could hide a marker')
        (root / 'linkdir').unlink(); outside.joinpath('late-recovery-required.txt').unlink(); outside.rmdir()
        real = module.load_disposition()
        check(len(real) == 20 and all('w01' not in key.lower() for key in real), 'Pinned operator disposition not loaded exactly')


def rejects(operation, message):
    try:
        operation()
    except AssertionError:
        return
    raise AssertionError('Negative structural control accepted: ' + message)


def main():
    parent = (SCRIPTS / 'Test-StagedW01Parent.ps1').read_text()
    host_path = SCRIPTS / 'Invoke-StagedW01Diagnostic.py'; host = host_path.read_text()
    spec = importlib.util.spec_from_file_location('w01_host', host_path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    audit_parent(parent); audit_host(host, module)
    for leaf in ('Test-StagedW01Diagnostic.ps1', 'StagedSectionFaultClient.cs', 'StagedInvariantObserver.psm1', 'StagedW01Stimulus.cs'):
        source = (SCRIPTS / leaf).read_text()
        check(not re.search(FORBIDDEN, source), 'Pending-path dependency terminates: ' + leaf)
    child = (SCRIPTS / 'Test-StagedW01Diagnostic.ps1').read_text()
    order = [child.index('$terminal=$client.DisarmWrite()'), child.index("throw 'Lower disarm reply is not terminal'"), child.index('$observed.LowerDisarmTerminal=$terminal'), child.index('if($disarmed){$client.Dispose()}'), child.index("Save-Text (Join-Path $EvidenceDirectory 'rv4-w01-diagnostic.json')")]
    check(order == sorted(order), 'Child lower terminal receipt precedes actual disarm/disconnect')
    rejects(lambda: audit_parent(parent.replace("    if(-not(Test-TerminalState)){throw 'Restoration refused: terminal predicate false'}", "    $null=Native 'fltmc.exe' @('unload','SafeUploadSectionFault')\n    if(-not(Test-TerminalState)){throw 'Restoration refused: terminal predicate false'}")), 'lower unload before guard')
    rejects(lambda: audit_parent(parent.replace('        Freeze-Artifacts', '        Restore-TerminalRun\n        Freeze-Artifacts')), 'extra early restore call')
    rejects(lambda: audit_parent(parent.replace('$d.WriterExited -ne $true', '$false')), 'missing writer exit proof')
    rejects(lambda: audit_parent(parent.replace('([TimeSpan]::Zero)', '([TimeSpan]::FromMinutes(15))')), 'automatic task termination')
    rejects(lambda: audit_host(host + '\nimport Invoke_StagedInvariantQualification\n', module), 'S01 import')
    rejects(lambda: audit_host(host + '\np.Kill()\n', module), 'host kill')
    rejects(lambda: audit_host(host + '\nsubprocess.run([], timeout=1)\n', module), 'host process timeout')
    # Compile every Python script in driver/scripts with caches confined to /tmp.
    files = sorted(SCRIPTS.glob('*.py'))
    with tempfile.TemporaryDirectory(prefix='w01-pycompile-') as tmp:
        env = dict(__import__('os').environ, PYTHONPYCACHEPREFIX=tmp)
        subprocess.run([sys.executable, '-m', 'py_compile', *map(str, files)], env=env, check=True)
    print('W01 Linux self-check: structural checks completed (no verdict): pending-path structure, unlimited tasks, required pins, host transport, seven rejection controls; ' + str(len(files)) + ' Python scripts compiled.')
    print('PowerShell 5.1 parse, native compilation and VM execution NOT VERIFIED. W01/A05 INCONCLUSIVE; Phase4=NOT_QUALIFIED')


if __name__ == '__main__':
    main()
