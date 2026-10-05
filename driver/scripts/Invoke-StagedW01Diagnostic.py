#!/usr/bin/env python3
"""One checkpointed W01/A05 diagnostic. Always INCONCLUSIVE / NOT_QUALIFIED.

Create/review pins without contacting a guest:
  ... TAG --stimulus-exe /path/StagedW01Stimulus.exe --write-current-pins /tmp/w01-pins.json
Then use the same artifact paths with --pins /tmp/w01-pins.json. No S01 launcher.
A prior recovery marker blocks every new run; only an operator can resolve it.
"""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'driver/scripts'
DOCS = r'C:\Users\vika\Documents'
UPPER_COMMIT = '6f312cd64df889ec59e25d2c463cbc6f4426c33b'
LOWER_COMMIT = '6efd9cf3f7a0100e3e02ad3415b13562e82da04f'
AGENT_COMMIT = 'fd8ce62f646daaee8059a754dbce47fa7b8292b6'
UPPER_SHA = '3A338D2046226507EB890F0EA9ADC01C28B8F167E67C484993C7BC30F3BDE6E1'
LOWER_SHA = 'C58433FB3431566BB545173FB7F4772DAA2C6B9E20CF057C0A985595EE93E386'
SIGNER = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
ORIGINAL_DRIVER = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
ORIGINAL_POLICY = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
EXPECTED_BYTES = (b'W01-OLD-EXPECTED-' * 768)[:12288]
SSH = ['-F', '/dev/null', '-i', '/home/victor/.ssh/id_ed25519', '-o', 'BatchMode=yes',
       '-o', 'ConnectTimeout=10', '-o', 'LogLevel=ERROR', '-o', 'StrictHostKeyChecking=accept-new']
SENTINELS = {'PREPARED': 'W01_PREPARED=True', 'CASE': 'W01_CASE_COMPLETED=True',
             'RESTORED': 'W01_RESTORED=True', 'FINAL': 'W01_FINAL_STATE=True'}
SOURCE_INPUTS = {
    'Suite': 'Test-StagedW01Parent.ps1', 'Child': 'Test-StagedW01Diagnostic.ps1',
    'Client': 'StagedSectionFaultClient.cs', 'SectionController': 'Invoke-StagedSectionFault.ps1',
    'StimulusSource': 'StagedW01Stimulus.cs', 'Observer': 'StagedInvariantObserver.psm1',
    'Baseline': 'Get-StagedBaseline.ps1', 'Wrapper': 'Invoke-DebuggeeExperiment.sh',
    'Transport': 'remote_ps.py', 'Parser': 'Validate-StagedWTrace.py',
    'Host': 'Invoke-StagedW01Diagnostic.py', 'SelfCheck': 'Invoke-StagedW01Diagnostic.SelfCheck.py',
}


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def durable(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())


def ps(value):
    return "'" + str(value).replace("'", "''") + "'"


def read(path):
    raw = path.read_bytes()
    return raw.decode('utf-16') if raw[:2] in (b'\xff\xfe', b'\xfe\xff') else raw.decode('utf-8-sig')


def digest_field(summary, field):
    rows = re.findall(r'^' + re.escape(field) + r'=([a-fA-F0-9]{64})\s*$', summary, re.M)
    require(len(rows) == 1, 'Missing/ambiguous build digest: ' + field)
    return rows[0].upper()


def exact_archive(work, commit, subtrees):
    summary = read(work / 'summary.txt')
    for leaf, key in [('src.zip', 'ARCHIVE_SHA256'), ('src.manifest', 'MANIFEST_SHA256')]:
        require(sha(work / leaf) == digest_field(summary, key), 'Exact build digest mismatch: ' + leaf)
    records = [line.split('  ', 1) for line in read(work / 'src.manifest').splitlines()]
    paths = [path for _, path in records]
    expected = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', commit, '--', *subtrees], cwd=ROOT).decode().splitlines()
    require(set(paths) == set(expected) and len(paths) == len(expected), 'Exact source inventory mismatch')
    with zipfile.ZipFile(work / 'src.zip') as archive:
        leaves = [i.filename for i in archive.infolist() if not i.is_dir()]
        require(set(leaves) == set(paths) and len(leaves) == len(paths), 'Exact ZIP inventory mismatch')
        for digest, path in records:
            original = subprocess.check_output(['git', 'show', commit + ':' + path], cwd=ROOT)
            require(hashlib.sha256(original).hexdigest().upper() == digest.upper() and archive.read(path) == original,
                    'Source archive differs from pinned commit: ' + path)
    # This diagnostic intentionally uses the authorized signed b38 snapshot (b34 plus the directory-cleanup Unknown fix).
    # Current product sources have later edits; prove the archived build against
    # its own commit and report the working-tree difference in provenance.
    return summary


def checked_inputs(args):
    upper, lower, agent = args.upper_dir.resolve(), args.lower_dir.resolve(), args.agent_dir.resolve()
    us = exact_archive(upper, UPPER_COMMIT, ['driver/SafeUpload.Minifilter', 'driver/SafeUpload.Inspector', 'driver/SafeUpload.WriterFixture'])
    ls = exact_archive(lower, LOWER_COMMIT, ['driver/SafeUpload.SectionFault'])
    require(us == read(ROOT / 'driver/evidence/2026-10-05/exact-mvp3-b38-summary.txt'), 'Upper summary differs from repository b38 evidence')
    require(ls == read(ROOT / 'driver/evidence/2026-10-05/section-fault-mvp3-b36-summary.txt'), 'Lower summary differs from repository b36 evidence')
    for suffix in ('normal', 'owned-feature', 'normal-release', 'owned-feature-release'):
        pattern = r'^driver:' + suffix + r' : .*exit=0 succeeded=True warnings=0 errors=0 apivalidator=True prefast=True '
        require(len(re.findall(pattern, us, re.M)) == 1, 'Missing exact product WDK gate: ' + suffix)
        require('DriverRecommendedRules.ruleset' in read(upper / (suffix + '-wdk.txt')), 'Missing actual WDK log: ' + suffix)
    require('signed_sha256=' + UPPER_SHA + ' signer=' + SIGNER in us, 'Upper sign gate mismatch')
    require(sha(upper / 'owned-feature.sys') in us, 'Unsigned upper hash mismatch')
    for config in ('Debug', 'Release'):
        require(config + ' : exit=0 warnings=0 errors=0 prefast=True apivalidator=True' in ls, 'Lower build gate missing')
        require('DriverRecommendedRules.ruleset' in read(lower / (config + '-wdk.txt')), 'Missing actual lower WDK log')
    require('SignExit=0' in ls and digest_field(ls, 'SignedSHA256') == LOWER_SHA and 'SignerThumbprint=' + SIGNER in ls, 'Lower sign gate mismatch')
    inspector = upper / 'inspector-feature-release.exe'
    require(re.search(r'^inspector-feature-release : exit=0 succeeded=True warnings=0 errors=0 artifact_sha256=' + sha(inspector) + r'\s*$', us, re.M), 'Inspector gate mismatch')
    require(sha(upper / 'SafeUpload-stage-prototype.sys') == UPPER_SHA and sha(lower / 'SafeUploadSectionFault.sys') == LOWER_SHA, 'Exact signed b38/b36 artifact hash mismatch')
    asummary = exact_archive(agent, AGENT_COMMIT, ['agente'])
    require('tests: exit=0 warnings=0' in asummary and 'publish: exit=0 warnings=0' in asummary, 'Agent tests/publish gate missing')
    package = agent / 'stage-service-publish.zip'
    require(sha(package) == digest_field(asummary, 'package_sha256'), 'Agent package digest mismatch')
    with zipfile.ZipFile(package) as archive:
        leaves = [i.filename for i in archive.infolist() if not i.is_dir()]
        require(len(leaves) == len(set(p.lower() for p in leaves)), 'Duplicate agent package path')
        require(all(not p.startswith(('/', '\\')) and '..' not in p.split('/') and '\\' not in p and ':' not in p for p in leaves), 'Unsafe agent package path')
        require(hashlib.sha256(archive.read('SafeUpload.Agent.Service.exe')).hexdigest().upper() == digest_field(asummary, 'exe_sha256'), 'Agent executable mismatch')
        tree = sorted(hashlib.sha256(archive.read(p)).hexdigest().upper() + '  ' + p for p in leaves)
        tree_sha = hashlib.sha256(('\n'.join(tree) + '\n').encode()).hexdigest().upper()
    files = {key: SCRIPTS / leaf for key, leaf in SOURCE_INPUTS.items()}
    files.update(Upper=upper / 'SafeUpload-stage-prototype.sys', Lower=lower / 'SafeUploadSectionFault.sys',
                 Inspector=inspector, Stimulus=args.stimulus_exe.resolve(), AgentPackage=package)
    for path in files.values():
        require(path.is_file() and not path.is_symlink(), 'Missing/unsafe input: ' + str(path))
    require(files['Stimulus'].read_bytes()[:2] == b'MZ', 'Stimulus must be a builder-produced Windows PE executable')
    build_pins = {str(p): sha(p) for directory in (upper, lower, agent) for p in directory.iterdir() if p.is_file()}
    hashes = {key: sha(path) for key, path in files.items()}
    hashes.update(ExpectedBytes=hashlib.sha256(EXPECTED_BYTES).hexdigest().upper(),
                  OriginalDriver=ORIGINAL_DRIVER, OriginalPolicy=ORIGINAL_POLICY, ServiceTree=tree_sha)
    provenance = {'Schema': 'Rv4W01Provenance/1', 'UpperSource': UPPER_COMMIT, 'LowerSource': LOWER_COMMIT,
                  'AgentSource': AGENT_COMMIT,
                  'UpperSummarySha256': sha(upper / 'summary.txt'), 'LowerSummarySha256': sha(lower / 'summary.txt'),
                  'UpperArchiveSha256': sha(upper / 'src.zip'), 'LowerArchiveSha256': sha(lower / 'src.zip'),
                  'UpperManifestSha256': sha(upper / 'src.manifest'), 'LowerManifestSha256': sha(lower / 'src.manifest'),
                  'AgentSummarySha256': sha(agent / 'summary.txt'), 'Signer': SIGNER,
                  'BuildEvidencePins': build_pins,
                  'CurrentProductDiffersFromB34': subprocess.check_output(['git', 'diff', '--name-only', UPPER_COMMIT, '--',
                       'driver/SafeUpload.Minifilter', 'driver/SafeUpload.Inspector', 'driver/SafeUpload.WriterFixture'], cwd=ROOT).decode().splitlines(),
                  'LowerBuilderTrust': 'UnknownError; guest Valid signature REQUIRED', 'Pins': hashes,
                  'SourceMode': 'current-checkout-SHA256-pinned-harness', 'Verdict': 'W01/A05 INCONCLUSIVE', 'Phase4': 'NOT_QUALIFIED'}
    return files, hashes, provenance


DISPOSITION = ROOT / 'driver/evidence/2026-10-05/recovery-marker-disposition-20261005.json'
DISPOSITION_SHA256 = 'ABF1CFC284CFF588CC8CE871185F045A492EB71BAE0A749FF3A3142A796F53B2'


def load_disposition(path=DISPOSITION, pinned=DISPOSITION_SHA256):
    """Operator-resolved historical markers as {relative path: SHA-256}. Fails closed to {}."""
    try:
        if not path.is_file() or path.is_symlink() or sha(path) != pinned:
            return {}
        note = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(note, dict) or note.get('Schema') != 'RecoveryMarkerDisposition/1':
            return {}
        return {item['Path']: item['Sha256'].upper() for item in note['Resolved']
                if 'w01' not in item['Path'].lower()}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def recovery_markers(evidence, resolved=None):
    """Every recovery marker that still latches. Resolution is never inferred from a later
    baseline: a marker is cleared only by an exact (relative path, SHA-256) operator entry, and a
    W01-family marker or the active W01 lease can never be cleared."""
    resolved = load_disposition() if resolved is None else resolved
    found = []
    for path in evidence.rglob('*'):
        if path.is_symlink():
            # rglob does not enter symlinked directories, so a marker could hide behind one: latch.
            found.append(str(path) + ' (symlink under the evidence root)')
            continue
        if path.is_file() and ('recovery-required' in path.name.lower() or 'recoveryrequired' in path.name.lower()):
            relative = str(path.relative_to(evidence))
            if 'w01' not in relative.lower() and resolved.get(relative) == sha(path):
                continue
            found.append(str(path))
    return found


def transport_phase_line(phase, launcher, launcher_hash, name, evidence, seconds=1200):
    """Wait only for a scheduled task's durable receipt. Expiry leaves it alive.

    No guest Process.WaitForExit, no local timeout around a guest process, no
    S01 phase_line import. Wrapper missing-sentinel path then blocks reboot 2.
    """
    task = 'SafeUpload-W01Phase-' + name + '-' + phase
    prefix = DOCS + '\\' + name + '-' + phase.lower()
    command = "$ErrorActionPreference='Stop';$l=" + ps(DOCS + '\\' + launcher) + ';'
    command += "if((Get-FileHash -LiteralPath $l).Hash -cne " + ps(launcher_hash) + "){throw 'Phase launcher pin mismatch'};"
    command += '$t=' + ps(task) + ";if(Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue){throw 'Phase task collision'};"
    command += "$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"'+$l+'\"');"
    command += "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
    command += '$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero);'
    command += 'Register-ScheduledTask -TaskName $t -Action $a -Principal $p -Settings $s|Out-Null;Start-ScheduledTask -TaskName $t;'
    command += '$deadline=[DateTime]::UtcNow.AddSeconds(' + str(seconds) + ');$done=' + ps(prefix + '.done.json') + ';$r=$null;'
    command += "do{if(Test-Path -LiteralPath $done){try{$r=Get-Content -LiteralPath $done -Raw|ConvertFrom-Json}catch{}};"
    command += "if($null -ne $r -and (Get-ScheduledTask -TaskName $t).State -eq 'Ready'){break};Start-Sleep -Milliseconds 250}while([DateTime]::UtcNow -lt $deadline);"
    command += "if($null -eq $r -or (Get-ScheduledTask -TaskName $t).State -ne 'Ready'){"
    command += '$m=@{RecoveryRequired=$true;Phase=' + ps(phase) + ';Task=$t;Reason=\'Transport wait expired; guest task retained\';'
    command += 'Pids=@(Get-CimInstance Win32_Process|Where-Object {$_.CommandLine -like ' + ps('*' + name[-32:] + '*') + '}|Select-Object ProcessId,ParentProcessId,CreationDate,CommandLine);'
    command += "ArmGeneration='Unknown';LowerStatus='Unknown: child may own sole port';CheckpointReceipt=" + ps(name + '-checkpoint.txt') + '}|ConvertTo-Json -Depth 16;'
    command += '$m|Set-Content -LiteralPath ' + ps(evidence + '\\Transport-RecoveryRequired.json') + " -Encoding UTF8;throw 'Phase transport pending; preserve guest'};"
    command += '$output=@(Get-Content -LiteralPath ' + ps(prefix + '.out') + ');$output;Get-Content -LiteralPath ' + ps(prefix + '.err') + ';'
    required = {'Prepare': SENTINELS['PREPARED'], 'AfterBoot': SENTINELS['RESTORED'], 'Finalize': SENTINELS['FINAL']}[phase]
    command += 'if(@($output|Where-Object {$_ -ceq ' + ps(required) + "}).Count -ne 1){throw 'Safe phase sentinel missing; retain phase task'};"
    command += 'if($r.Phase -cne ' + ps(phase) + ' -or $r.RunName -cne ' + ps(name) + " -or $r.ExitCode -ne 0){throw 'Phase failed; retain task'};"
    command += 'Unregister-ScheduledTask -TaskName $t -Confirm:$false'
    return command


def phase_launcher(phase, params, suite_leaf, name):
    prefix = DOCS + '\\' + name + '-' + phase.lower()
    command = '& ' + ps(DOCS + '\\' + suite_leaf) + ' -Phase ' + ps(phase)
    command += ''.join(' -' + key + ' ' + ps(value) for key, value in params.items())
    # Receipt follows the return of the parent in this SAME SYSTEM process.
    return ("$ErrorActionPreference='Stop';$exitCode=0;try{\n" + command + ' 1> ' + ps(prefix + '.out') + ' 2> ' + ps(prefix + '.err') +
            "\n}catch{$exitCode=1;$_|Out-String|Add-Content -LiteralPath " + ps(prefix + '.err') + "}\n" +
            '$r=@{RunName=' + ps(name) + ';Phase=' + ps(phase) + ';ExitCode=$exitCode;Pid=$PID};' +
            '$b=[Text.UTF8Encoding]::new($false).GetBytes(($r|ConvertTo-Json));$s=[IO.FileStream]::new(' + ps(prefix + '.done.json') +
            ',[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough);' +
            'try{$s.Write($b,0,$b.Length);$s.Flush($true)}finally{$s.Dispose()};exit $exitCode\n')


def wrapper_phase_line(leaf, digest):
    # Keep remote_ps.py below its 7000-character encoded-command threshold.
    # Its long-command fallback deletes a guest temp script on return, which
    # cannot be used when our transport returns with a pending W01 child.
    path = DOCS + '\\' + leaf
    return ('$tp=' + ps(path) + ';if((Get-FileHash -LiteralPath $tp).Hash -cne ' + ps(digest) +
            "){throw 'Transport script pin mismatch'};& $tp")


def clean_baseline(path):
    return path.exists() and read(path).splitlines().count('BaselineClean=True') == 1


def collect_guest(ev, name, run_guid):
    outcomes = {}
    for leaf in (name + '-artifacts', 'SafeUpload-w01-state-' + run_guid, 'SafeUpload-rv4-w01-control-' + run_guid):
        target = ev / (name + '-guest')
        target.mkdir(exist_ok=True)
        guest_root = 'C:/' if leaf.startswith('SafeUpload-rv4-w01-control-') else 'C:/Users/vika/Documents/'
        with (ev / (name + '-copy-' + leaf + '.txt')).open('w') as log:
            outcomes[leaf] = subprocess.call(['scp', *SSH, '-r', 'vika@192.168.122.51:' + guest_root + leaf, str(target)], stdout=log, stderr=subprocess.STDOUT)
    # Phase streams survive the wrapper's CLIXML cleaner, including failure.
    for phase in ('prepare', 'afterboot', 'finalize'):
        for suffix in ('out', 'err', 'done.json'):
            leaf = name + '-' + phase + '.' + suffix
            with (ev / (name + '-copy-phase.txt')).open('a') as log:
                outcomes[leaf] = subprocess.call(['scp', *SSH, 'vika@192.168.122.51:C:/Users/vika/Documents/' + leaf, str(ev / (name + '-guest'))], stdout=log, stderr=subprocess.STDOUT)
    return outcomes


def source_transport_gate(ev, name, hashes, copies):
    artifact = ev / (name + '-guest') / (name + '-artifacts')
    require(copies.get(name + '-artifacts') == 0, 'Guest evidence copy failed/incomplete')
    staged = json.loads(read(artifact / 'input-staging-verified.json'))
    require(staged['RunName'] == name, 'Staging receipt foreign')
    for key in SOURCE_INPUTS.keys() | {'Upper', 'Lower', 'Inspector', 'Stimulus', 'AgentPackage', 'ExpectedBytes'}:
        require(staged['Hashes'][key] == hashes[key], 'Guest staging digest mismatch: ' + key)
    for phase, sentinels in [('prepare', [SENTINELS['PREPARED']]), ('after-boot', [SENTINELS['CASE'], SENTINELS['RESTORED']]), ('finalize', [SENTINELS['FINAL']])]:
        lines = read(ev / (name + '-' + phase + '.txt')).splitlines()
        require(all(lines.count(s) == 1 for s in sentinels + ['HARNESS_RETURNED']), 'Phase sentinels missing/duplicate: ' + phase)
        require(not any(l.startswith('HARNESS_THREW') for l in lines), 'Wrapper phase threw: ' + phase)
    require(clean_baseline(ev / (name + '-baseline.txt')) and clean_baseline(ev / (name + '-final-restored-state.txt')), 'Independent wrapper baseline failed')
    for phase in ('reboot-1', 'reboot-restore'):
        require(read(ev / (name + '-' + phase + '-changed.txt')).startswith('BootIdentityChanged=True;'), 'Boot identity unchanged')
    frozen = artifact / 'frozen'
    records = json.loads(read(artifact / 'frozen-manifest.json'))
    require(len(records) == len({r['Path'] for r in records}), 'Duplicate frozen artifact')
    actual = {p.relative_to(frozen).as_posix() for p in frozen.rglob('*') if p.is_file()}
    require(actual == {r['Path'].replace('\\', '/') for r in records}, 'Incomplete frozen inventory')
    for record in records:
        rel = record['Path'].replace('\\', '/')
        require('..' not in rel.split('/') and not rel.startswith('/') and ':' not in rel, 'Unsafe frozen path')
        p = frozen / rel
        require(p.stat().st_size == record['Length'] and sha(p) == record['Sha256'], 'Frozen artifact transport mismatch: ' + rel)
    result = json.loads(read(artifact / 'case.json'))
    require(result['Verdict'] == 'W01/A05 INCONCLUSIVE' and result['Phase4'] == 'NOT_QUALIFIED' and result['GuestRestorationVerified'] is True, 'Guest disposition/restoration missing')
    return artifact


def join_observations(artifact):
    """Narrow parser plus explicit lower/cleanup/IOCP/raw joins; never qualification."""
    terminal = json.loads(read(artifact / 'terminal-state.json'))
    child = terminal['Child']
    identity = json.loads(read(artifact / 'fixture-identities.json'))['Target']
    opened, completed = terminal['Opened'], terminal['Completed']
    events = child['Events']
    def event(name):
        rows = [r for r in events if r['Name'] == name]
        require(len(rows) == 1, 'Missing/duplicate child event: ' + name)
        return rows[0]
    armed, held, post = event('armed'), event('held'), event('lower-post')
    overlap = event('cleanup-overlap')
    lower = terminal['Lower']
    require(terminal['RecoveryRequired'] is False and terminal['DiagnosticExited'] is True and terminal['WriterExited'] is True and terminal['LowerPostDisarmTerminal'] is True, 'Terminal receipt incomplete')
    require(str(armed['Generation']) == str(held['Generation']) == str(lower['ArmGeneration']) and str(armed['FileObject']) == str(held['FileObject']), 'Lower arm/hold identity mismatch')
    require(held['Offset'] == '0' and held['Length'] == 4096 and held['IrpFlags'] & 1 and not held['IrpFlags'] & 2 and overlap['H'] == 0 and overlap['W'] > 0, 'Hold/cleanup overlap missing')
    require(post['Status'] == 0 and post['Information'] == '4096' and post['PostFlags'] & 1 == 0 and int(post['CallbackData']) != 0, 'Genuine lower post missing')
    require(completed['CompletionSource'] == 'IOCP' and completed['Success'] == 'True' and completed['Bytes'] == '4096' and completed['NativeError'] == '0' and completed['DeadlineExceeded'] == 'False', 'IOCP mismatch')
    trace = artifact / 'frozen/child/upper-trace.jsonl'
    parser = subprocess.run(['python3', str(SCRIPTS / 'Validate-StagedWTrace.py'), str(trace), '--file-id', identity['FileIdHex'],
                             '--volume-serial', '0x' + int.from_bytes(bytes.fromhex(identity['VolumeSerialHex']), 'little').to_bytes(8, 'big').hex().upper(),
                             '--pid', opened['ProcessId'], '--offset', '0', '--length', '4096', '--irp-flags', '0x' + format(held['IrpFlags'], '08X'),
                             '--alignment', '4096', '--target-file-object', '0x' + format(int(armed['FileObject']), '016X')], capture_output=True, text=True)
    durable(artifact / 'host-upper-parser.json', {'ExitCode': parser.returncode, 'Stdout': parser.stdout, 'Stderr': parser.stderr})
    final_trace = artifact / 'frozen/parent-unfiltered-upper-trace.jsonl'
    final_args = list(parser.args); final_args[2] = str(final_trace)
    final_parser = subprocess.run(final_args, capture_output=True, text=True)
    durable(artifact / 'host-final-upper-parser.json', {'ExitCode': final_parser.returncode, 'Stdout': final_parser.stdout, 'Stderr': final_parser.stderr})
    accounting = {}
    for label, path in [('held', artifact / 'frozen/child/held-upper-trace.jsonl'), ('child-final', trace), ('parent-final', final_trace)]:
        full_rows = [json.loads(line) for line in read(path).splitlines() if line.strip()]
        counts = {}
        for row in full_rows:
            key = 'summary' if row.get('summary') is True else row.get('event', 'UNKNOWN')
            counts[key] = counts.get(key, 0) + 1
        accounting[label] = {'Rows': len(full_rows), 'Counts': counts, 'Sha256': sha(path)}
    durable(artifact / 'host-unfiltered-trace-accounting.json', accounting)
    require(parser.returncode == 0, 'Unfiltered upper W parser INCONCLUSIVE (includes foreign W)')
    require(final_parser.returncode == 0, 'Final unfiltered parent trace INCONCLUSIVE (includes foreign W)')
    rows = [json.loads(line) for line in read(trace).splitlines() if line.strip()]
    cleanups = [r for r in rows if r.get('event') == 'file_cleanup' and r.get('targetFileObject') == '0x' + format(int(armed['FileObject']), '016X')]
    require(len(cleanups) == 1, 'Exact unfiltered upper cleanup row missing/ambiguous')
    begin = [r for r in rows if r.get('event') == 'w_begin']
    end = [r for r in rows if r.get('event') == 'w_end']
    require(len(begin) == len(end) == 1 and begin[0]['sequence'] < cleanups[0]['sequence'] < end[0]['sequence'], 'Upper cleanup is outside the pending W ticket')
    held_rows = [json.loads(line) for line in read(artifact / 'frozen/child/held-upper-trace.jsonl').splitlines() if line.strip()]
    require(any(r == cleanups[0] for r in held_rows) and not any(r.get('event') == 'w_end' for r in held_rows), 'Cleanup was not captured before release')
    require(lower['CurrentHeld'] == lower['Mode'] == lower['ArmedFileObject'] == 0 and lower['LowerPosts'] == 1 and lower['Canceled'] == lower['TimedOut'] == lower['SyntheticFailures'] == 0 and lower['LowerStatus'] == 0 and lower['LowerInformation'] == 4096 and int(post['CallbackData']) == lower['LowerCallbackData'], 'Terminal lower post/disarm mismatch')
    raw_dir = artifact / 'frozen/child/raw'
    guest_raw = DOCS + '\\' + artifact.name + '\\child\\raw\\'
    def raw_bytes(record):
        require(record['Path'].startswith(guest_raw), 'Foreign raw artifact path')
        rel = record['Path'][len(guest_raw):].replace('\\', '/')
        require(rel and '/' not in rel and ':' not in rel and rel not in ('.', '..'), 'Unsafe raw artifact leaf')
        path = raw_dir / rel
        require(path.stat().st_size == record['Length'] and sha(path) == record['Sha256'], 'Raw artifact hash/length differs')
        return path.read_bytes()
    manifest = [json.loads(line) for line in read(raw_dir / 'manifest.ndjson').splitlines() if line.strip()]
    require(len(manifest) == len({r['Path'] for r in manifest}), 'Raw manifest duplicate')
    for record in manifest:
        raw_bytes(record)
    require({p.name for p in raw_dir.iterdir() if p.is_file()} == {'manifest.ndjson'} | {r['Path'].split('\\')[-1] for r in manifest}, 'Unaccounted raw artifact')
    issued = dict(line.split('=', 1) for line in read(artifact / 'frozen/receipts/issued.receipt').splitlines() if line)
    require(issued['RunGuid'] == child['RunGuid'] and issued['WriteCall'] == 'PENDING' and issued['WriteCallError'] == '997', 'Issued receipt mismatch')
    serial = int.from_bytes(bytes.fromhex(identity['VolumeSerialHex']), 'little')
    for leaf in ('raw-baseline-decoded.json', 'raw-before-decoded.json', 'raw-held-decoded.json', 'raw-after-decoded.json'):
        sample = json.loads(read(artifact / 'frozen/child' / leaf))
        require(sample['Status'] == 'OK', 'Raw observer sample incomplete: ' + leaf)
        images = [i for i in sample['Images'] if i['Role'] == 'Current' and i['Path'] == identity['CanonicalPath']]
        require(len(images) == 1 and images[0]['Identity']['FileId'] == identity['FileIdHex'], 'Raw target identity missing')
        image = images[0]
        require(image['Identity']['VolumeSerial'] == serial and not image['CrossCheckErrors'], 'Raw volume identity/cross-check mismatch')
        logical = raw_bytes(image['LogicalArtifact'])
        require(len(logical) == image['Length'] and hashlib.sha256(logical).hexdigest().upper() == image['Sha256'], 'Raw logical image mismatch')
        for container in image['Containers']:
            raw_bytes(container['Artifact'])
        if leaf != 'raw-after-decoded.json':
            require(logical == EXPECTED_BYTES, 'Before/held raw target changed')
        else:
            require(len(logical) == len(EXPECTED_BYTES) and logical[4096:] == EXPECTED_BYTES[4096:] and hashlib.sha256(logical[:4096]).hexdigest().upper() == issued['PayloadSha256'], 'After raw bytes do not match submitted payload/range')
    before = json.loads(read(artifact / 'frozen/child/control-before-entry.json'))
    after = json.loads(read(artifact / 'frozen/child/control-after-entry.json'))
    require(before == after and before['state'] == 'Protected' and before['unknownReasons'] == '0x00000000' and before['H'] == before['W'] == 0, 'Protected control changed')
    return {'UpperParser': 'PAIRED_W01_SUCCESS_STATUS', 'LowerArmPostIocpRawJoin': 'NARROW_DIAGNOSTIC_ONLY',
            'RawAfterPayloadJoin': 'MATCHED: retained observer logical bytes and containers; not an independent NTFS decoder',
            'PromotionBoundary': 'UNAVAILABLE: retained promotion trace is not a coherent status tuple',
            'Verdict': 'W01/A05 INCONCLUSIVE', 'Phase4': 'NOT_QUALIFIED'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('tag')
    ap.add_argument('--upper-dir', type=Path, default=Path('/tmp/claude-1000/exact-mvp3-b38'))
    ap.add_argument('--lower-dir', type=Path, default=Path('/tmp/claude-1000/exact-section-fault-mvp3-b36'))
    ap.add_argument('--agent-dir', type=Path, default=Path('/tmp/claude-1000/exact-agent-agent-mvp4-notify1'))
    ap.add_argument('--stimulus-exe', type=Path, required=True)
    pins = ap.add_mutually_exclusive_group(required=True)
    pins.add_argument('--pins', type=Path, help='Reviewed JSON with every expected input SHA-256; required to run')
    pins.add_argument('--write-current-pins', type=Path, help='Write draft host pins only; no VM/SSH calls')
    args = ap.parse_args()
    require(re.fullmatch(r'[A-Za-z0-9-]{1,48}', args.tag), 'Unsafe tag')
    files, hashes, provenance = checked_inputs(args)
    if args.write_current_pins:
        durable(args.write_current_pins, hashes)
        print('Host draft pins written; no guest contacted. W01/A05 INCONCLUSIVE; Phase4=NOT_QUALIFIED')
        return 0
    expected = json.loads(read(args.pins))
    require(expected == hashes, 'Expected pin inventory/digests differ; every hash is mandatory')
    evroot = ROOT / 'driver/evidence'
    markers = recovery_markers(evroot)
    require(not markers, 'Prior RecoveryRequired marker; operator disposition required: ' + '; '.join(markers))
    now = datetime.datetime.now().astimezone()
    ev = evroot / now.strftime('%Y-%m-%d'); ev.mkdir(exist_ok=True)
    run_guid = uuid.uuid4().hex
    name = 'boot-start-w01-' + args.tag + '-' + run_guid
    provenance.update(RunName=name, RunGuid=run_guid, Utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    # Exclusive durable lease also survives host interruption. A healthy restored
    # case alone removes it; pending/failed cases retain this recovery latch.
    lease = evroot / 'w01-recovery-required-active.json'
    durable(lease, {'RecoveryRequired': True, 'RunName': name, 'RunGuid': run_guid,
                    'Reason': 'Run active or interrupted; do not start another VM case',
                    'CheckpointReceipt': str(ev / (name + '-checkpoint.txt'))})
    retained = ev / (name + '-inputs'); retained.mkdir()
    # Retain immutable per-run inputs, not another mutable /tmp sibling checkout.
    transfers, manifest = [], {}
    for key, source in files.items():
        dest = retained / source.name
        with source.open('rb') as inp, dest.open('xb') as out:
            shutil.copyfileobj(inp, out); out.flush(); os.fsync(out.fileno())
        require(sha(dest) == hashes[key], 'Retained input digest mismatch')
        leaf = 'w01-' + run_guid + '-' + source.name
        transfers.append((dest, leaf)); manifest[key] = {'Leaf': leaf, 'Hash': hashes[key]}
    image = retained / 'expected-old.bin'; image.write_bytes(EXPECTED_BYTES)
    transfers.append((image, 'w01-' + run_guid + '-expected-old.bin'))
    manifest['ExpectedBytes'] = {'Leaf': transfers[-1][1], 'Hash': hashes['ExpectedBytes']}
    manifest_path = retained / 'inputs.json'; durable(manifest_path, manifest)
    manifest_leaf = 'w01-' + run_guid + '-inputs.json'; transfers.append((manifest_path, manifest_leaf))
    params = {'RunName': name, 'RunGuid': run_guid, 'InputManifestFile': manifest_leaf, 'ExpectedInputManifestSha256': sha(manifest_path),
              'CheckpointName': 'safeupload-pre-' + name + '-' + now.strftime('%Y%m%d'),
              'CheckpointOverlay': '/var/lib/libvirt/images/win10-debug.safeupload-pre-' + name + '-' + now.strftime('%Y%m%d')}
    bindings = {'Feature': 'Upper', 'Lower': 'Lower', 'Inspector': 'Inspector', 'Stimulus': 'Stimulus', 'Client': 'Client',
                'Child': 'Child', 'Observer': 'Observer', 'Suite': 'Suite', 'ServicePackage': 'AgentPackage',
                'ServiceTree': 'ServiceTree', 'Bytes': 'ExpectedBytes', 'OriginalDriver': 'OriginalDriver', 'OriginalPolicy': 'OriginalPolicy'}
    params.update({'Expected' + k + 'Sha256': hashes[v] for k, v in bindings.items()})
    suite_leaf = manifest['Suite']['Leaf']
    # Wrapper stages harness under basename; give it an identical uniquely named file.
    harness = retained / suite_leaf; harness.write_bytes(files['Suite'].read_bytes())
    transfers = [(p, leaf) for p, leaf in transfers if leaf != suite_leaf]
    # Created by the wrapper BEFORE its EXTRA_FILES loop. If a date boundary
    # changes the wrapper output directory, staging fails closed before Prepare.
    checkpoint_leaf = 'w01-' + run_guid + '-checkpoint.txt'
    transfers.append((ev / (name + '-checkpoint.txt'), checkpoint_leaf))
    params['CheckpointReceiptFile'] = checkpoint_leaf
    lines = {}
    for phase in ('Prepare', 'AfterBoot', 'Finalize'):
        path = retained / ('phase-' + phase + '.ps1')
        path.write_text(phase_launcher(phase, params, suite_leaf, name), encoding='utf-8-sig')
        leaf = 'w01-' + run_guid + '-phase-' + phase + '.ps1'; transfers.append((path, leaf))
        transport = retained / ('transport-' + phase + '.ps1')
        transport.write_text(transport_phase_line(phase, leaf, sha(path), name, DOCS + '\\' + name + '-artifacts'), encoding='utf-8-sig')
        transport_leaf = 'w01-' + run_guid + '-transport-' + phase + '.ps1'; transfers.append((transport, transport_leaf))
        lines[phase] = wrapper_phase_line(transport_leaf, sha(transport))
    provenance.update(Parameters=params, PhaseCommands=lines, Retained={p.name: sha(p) for p in retained.iterdir() if p.is_file()})
    durable(ev / (name + '-provenance.json'), provenance)
    env = os.environ.copy()
    require(all(not re.search(r'[\s=]', str(p)) for p, _ in transfers), 'Wrapper EXTRA_FILES cannot encode spaces/=')
    env['EXTRA_FILES'] = ' '.join(str(p) + '=' + leaf for p, leaf in transfers)
    for key, sentinel in SENTINELS.items():
        env['BOOT_START_' + key + '_SENTINEL'] = sentinel
    env['BOOT_START_AFTER_BOOT_PS'] = lines['AfterBoot']; env['BOOT_START_FINAL_PS'] = lines['Finalize']
    wrapper_status, copies, problems, source_gate, joins = None, {}, [], False, None
    try:
        # No timeout/kill for the wrapper or a guest process. Finite task polling
        # in each transport line fails CLOSED while leaving every guest task alive.
        with (ev / (name + '-wrapper.txt')).open('w') as log:
            wrapper_status = subprocess.call(['bash', str(SCRIPTS / 'Invoke-DebuggeeExperiment.sh'), name, str(harness), lines['Prepare']], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        copies = collect_guest(ev, name, run_guid)
        for key, source in files.items():
            if sha(source) != hashes[key]:
                problems.append('Input changed after staging: ' + key)
        for leaf, digest in provenance['Retained'].items():
            if sha(retained / leaf) != digest:
                problems.append('Retained input changed after staging: ' + leaf)
        for path, digest in provenance['BuildEvidencePins'].items():
            if sha(Path(path)) != digest:
                problems.append('Exact build evidence changed after staging: ' + path)
    try:
        require(wrapper_status == 0 and not problems, 'Wrapper/staging failure: ' + str(wrapper_status))
        artifact = source_transport_gate(ev, name, hashes, copies)
        source_gate = True
        try:
            joins = join_observations(artifact)
        except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
            joins = {'Verdict': 'INCONCLUSIVE', 'Reason': str(error), 'Phase4': 'NOT_QUALIFIED'}
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        problems.append(str(error))
    if not source_gate:
        durable(ev / (name + '-recovery-required.json'), {'RecoveryRequired': True, 'RunName': name, 'Reason': problems,
                 'CheckpointReceipt': str(ev / (name + '-checkpoint.txt')), 'GuestEvidenceCopy': copies,
                 'Action': 'Preserve VM/processes/ports/overlay. No further VM case until operator disposition.'})
    result = {'RunName': name, 'SourceTransportRestorationGate': source_gate, 'WrapperExit': wrapper_status,
              'CopiedEvidence': copies, 'Problems': problems, 'ObservationJoins': joins,
              'Verdict': 'W01/A05 INCONCLUSIVE', 'Phase4': 'NOT_QUALIFIED'}
    durable(ev / (name + '-result.json'), result)
    if source_gate:
        lease.unlink()
    print(json.dumps(result, indent=2))
    print('W01/A05 INCONCLUSIVE\nPhase4=NOT_QUALIFIED')
    return 0 if source_gate else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        print('W01/A05 INCONCLUSIVE\nPhase4=NOT_QUALIFIED\nPreflight/transport error: ' + str(error))
        raise SystemExit(2)
