#!/usr/bin/env python3
"""Finish one boot-start invariant run whose host orchestrator died after the restoration reboot request.

Usage: Resume-StagedInvariantRun.py <run name>

The guest already ran Prepare and AfterBoot (case completed and restored) and was asked to reboot.
This replays, unchanged, only what the dead host processes had left: the wrapper's changed-boot check,
Finalize phase and independent restoration check, then the runner's evidence path (transfer, phase
gate, raw/service/audit validation, case and MVP gates). It never reruns any case step, never
reuses a partially written phase file, and records the resume in <name>-manual-resume.txt.
"""
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'driver/scripts'
HOST = '192.168.122.51'
spec = importlib.util.spec_from_file_location('runner', SCRIPTS / 'Invoke-StagedInvariantQualification.py')
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)


def clean(text):  # same filter as the wrapper's clean()
    text = re.sub(r'<Objs.*?</Objs>', '', text).replace('\r', '')
    return '\n'.join(l for l in text.split('\n') if l and 'CLIXML' not in l) + '\n'


def remote(script, output):
    done = subprocess.run(['python3', str(SCRIPTS / 'remote_ps.py'), HOST], input=script, text=True,
                          capture_output=True, cwd=ROOT)
    text = clean(done.stdout + done.stderr)
    Q.write_new(output, text)
    return done.returncode, text


def main():
    Q.require(len(sys.argv) == 2 and re.fullmatch(r'boot-start-invariant-[A-Za-z0-9-]+', sys.argv[1]), 'Usage: <run name>')
    name = sys.argv[1]
    hits = list((ROOT / 'driver/evidence').glob('*/' + name + '-provenance.txt'))
    Q.require(len(hits) == 1, 'Expected exactly one provenance file')
    ev = hits[0].parent
    provenance = json.loads(hits[0].read_text())
    params = provenance['Parameters']
    case, mode = params['CaseId'], params['Mode']
    for leaf in ('after-boot', 'reboot-restore-before', 'reboot-restore-requested'):
        Q.require((ev / (name + '-' + leaf + '.txt')).exists(), 'Run did not reach the restoration reboot: ' + leaf)
    for leaf in ('reboot-restore-changed.txt', 'finalize.txt', 'final-restored-state.txt', 'recovery-required.txt', 'artifacts', 'artifact-transfer.txt'):
        Q.require(not (ev / (name + '-' + leaf)).exists(), 'Run already progressed past the restoration reboot: ' + leaf)
    after_boot = (ev / (name + '-after-boot.txt')).read_text().splitlines()
    Q.require('INVARIANT_CASE_COMPLETED=True' in after_boot and 'INVARIANT_RESTORED=True' in after_boot, 'AfterBoot did not complete and restore')
    before = re.search(r'^GuestLastBootUpTime=(.+)$', (ev / (name + '-reboot-restore-before.txt')).read_text(), re.M).group(1)
    status, text = remote("$b=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o');'GuestLastBootUpTime='+$b\n",
                          ev / (name + '-reboot-restore-resume-boot.txt'))
    current = re.search(r'^GuestLastBootUpTime=(.+)$', text, re.M)
    Q.require(status == 0 and current and current.group(1) != before, 'Guest boot identity did not change after the restoration reboot')
    Q.write_new(ev / (name + '-reboot-restore-changed.txt'), f'BootIdentityChanged=True;Before={before};After={current.group(1)}\n')
    remote("$ErrorActionPreference = 'Continue'\ntry { " + provenance['FinalInvocation'] + "; 'HARNESS_RETURNED' } catch { 'HARNESS_THREW: ' + $_.Exception.Message }\n",
           ev / (name + '-finalize.txt'))
    Q.require(subprocess.call(['scp', '-F', '/dev/null', '-i', '/home/victor/.ssh/id_ed25519', '-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR',
                               str(SCRIPTS / 'Get-StagedBaseline.ps1'), 'vika@' + HOST + ':C:/Users/vika/Documents/Get-StagedBaseline.ps1']) == 0,
              'Baseline helper copy failed')
    restored = ev / (name + '-final-restored-state.txt')
    remote("& 'C:\\Users\\vika\\Documents\\Get-StagedBaseline.ps1'\n", restored)
    audit_ok = Q.baseline_audit(ev / (name + '-baseline.txt')) == Q.baseline_audit(restored)
    with restored.open('a') as stream:
        stream.write('ProcessCreationAuditRestored=' + str(audit_ok) + '\n')
    Q.write_new(ev / (name + '-manual-resume.txt'),
                'MANUAL_RESUME=True\nReason=Host orchestrator exited while waiting for the restoration reboot; guest phases Prepare/AfterBoot had completed.\n'
                f'Tool=driver/scripts/Resume-StagedInvariantRun.py\nToolSha256={Q.sha(Path(__file__))}\nBootBefore={before}\nBootAfter={current.group(1)}\n')
    destination = ev / (name + '-artifacts')
    scp = ['scp', '-F', '/dev/null', '-i', '/home/victor/.ssh/id_ed25519', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
           '-o', 'StrictHostKeyChecking=accept-new']
    with (ev / (name + '-artifact-transfer.txt')).open('x') as log:
        copied = subprocess.call(scp + ['-r', 'vika@' + HOST + ':C:/Users/vika/Documents/' + name + '-artifacts', str(destination)], stdout=log, stderr=log)
        transport_complete = copied == 0
        if copied == 0:
            transport = destination / 'transport'
            transport.mkdir()
            for phase in ('prepare', 'afterboot', 'finalize'):
                for suffix in ('.out', '.err'):
                    transport_complete &= subprocess.call(scp + ['vika@' + HOST + ':C:/Users/vika/Documents/' + name + '-' + phase + suffix,
                                                                 str(transport / (phase + suffix))], stdout=log, stderr=log) == 0
    Q.phase_gate(ev, name)
    Q.require(copied == 0 and transport_complete, 'Complete guest evidence/raw streams unavailable')
    provisional = destination / 'case.json'
    result = json.loads(provisional.read_text('utf-8-sig'))
    provisional.rename(destination / 'case.guest-export.txt')
    guest_root = 'C:\\Users\\vika\\Documents\\' + name + '-artifacts\\'
    Q.validate_raw_artifacts(destination, guest_root, ('raw', 'raw-external') if case == 'C05-denied-external-rename' else ('raw',))
    Q.validate_service_artifacts(result, destination, guest_root)
    Q.validate_audit_restoration(result, ev / (name + '-baseline.txt'), restored)
    result['AuthoritativeCaseExport'] = True
    result['ManualResume'] = str(ev / (name + '-manual-resume.txt'))
    result['Restoration'].update(Known=True, IndependentBaseline=str(restored), IndependentBaselineSha256=Q.sha(restored))
    result['CheckpointLinks'] = {key: str(ev / (name + '-' + key + '.txt')) for key in ('baseline', 'flush', 'checkpoint', 'prepare', 'after-boot', 'finalize', 'final-restored-state')}
    result['ProvenanceLink'] = str(hits[0])
    result['ArtifactRootMapping'] = {'Guest': guest_root.rstrip('\\'), 'Host': str(destination)}
    Q.attest_external_coverage(result)
    passed = Q.case_gate(result, case, mode, name, params)
    result['GatePassed'] = passed
    assessment = Q.mvp_case_gate(result, None)
    result.update(assessment)
    Q.write_new(provisional, json.dumps(result, indent=2) + '\n')
    print(json.dumps({'CaseId': case, 'Mode': mode, 'RunName': name, 'Verdict': result['Verdict'], 'GatePassed': passed, **assessment,
                      'ForbiddenByteCount': result.get('ForbiddenByteCount'), 'RestorationClean': True, 'Result': str(provisional)}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit('Resume failed: ' + str(error))
