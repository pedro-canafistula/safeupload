#!/usr/bin/env python3
"""Checkpoint one canary-newvolume run (fresh-volume canary, real timeout, real allocation failure).

Usage: <run-name> <main-build-label> <source-commit> <ordinary|verifier> <expected-check-count>
The shared experiment wrapper requires independent clean baselines before and after.
"""
from pathlib import Path
import datetime
import hashlib
import os
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
name, label, revision, mode, expected_checks = sys.argv[1:6]
if sys.argv[6:] or mode not in ('ordinary', 'verifier') or not expected_checks.isdigit():
    raise SystemExit('Unknown arguments')
for value in (name, label):
    if not re.fullmatch(r'[A-Za-z0-9._-]{3,60}', value):
        raise SystemExit('Invalid label')
if not re.fullmatch(r'[A-Za-z0-9_-]{3,60}', label):
    raise SystemExit('Main build label cannot contain dots')
commit = subprocess.check_output(['git', 'rev-parse', '--verify', revision + '^{commit}'], cwd=root, text=True).strip()
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
ev = root / 'driver/evidence' / datetime.date.today().isoformat()
ev.mkdir(parents=True, exist_ok=True)
if (ev / (name + '-provenance.txt')).exists() or (ev / (name + '-gate.txt')).exists():
    raise SystemExit('Refusing to replace experiment evidence')
work = Path('/tmp/claude-1000/exact-' + label)
summary = (work / 'summary.txt').read_text('utf-8-sig')


def unique_row(content, prefix):
    rows = [line for line in content.splitlines() if line.startswith(prefix + ' :')]
    if len(rows) != 1:
        raise SystemExit('Missing or duplicate build gate: ' + prefix)
    fields = re.findall(r'(\w+)=([^\s]+)', rows[0])
    if len({key for key, _ in fields}) != len(fields):
        raise SystemExit('Duplicate build gate fields')
    return dict(fields)


def checked_gate(content, prefix, analysis=False):
    row = unique_row(content, prefix)
    if row.get('exit') != '0' or ('succeeded' in row and row['succeeded'] != 'True'):
        raise SystemExit('Failed build: ' + prefix)
    for key in ('warnings', 'errors'):
        if not re.fullmatch(r'0(?:,0)*', row.get(key, '')):
            raise SystemExit('Build diagnostics: ' + prefix)
    if analysis and (row.get('apivalidator') != 'True' or row.get('prefast') != 'True'):
        raise SystemExit('Missing analysis gate: ' + prefix)
    return row


for gate in ['driver:normal', 'driver:owned-feature', 'driver:normal-release', 'driver:owned-feature-release',
             'inspector-normal-release', 'inspector-feature-release']:
    checked_gate(summary, gate, gate.startswith('driver:'))
checked_gate(summary, 'writer-fixture')
subtrees = ['driver/SafeUpload.Minifilter', 'driver/SafeUpload.Inspector', 'driver/SafeUpload.WriterFixture']
for local, key in [('src.zip', 'ARCHIVE_SHA256'), ('src.manifest', 'MANIFEST_SHA256')]:
    digest = hashlib.sha256((work / local).read_bytes()).hexdigest().upper()
    matches = re.findall(r'^' + key + r'=([0-9A-Fa-f]{64})$', summary, re.MULTILINE)
    if len(matches) != 1 or matches[0].upper() != digest:
        raise SystemExit('Build summary/source hash mismatch: ' + str(work / local))
expected_paths = set(subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', commit, '--'] + subtrees, cwd=root, text=True).splitlines())
manifest_lines = (work / 'src.manifest').read_text().splitlines()
manifest_paths = [line.split('  ', 1)[1] for line in manifest_lines]
if set(manifest_paths) != expected_paths or len(manifest_paths) != len(expected_paths):
    raise SystemExit('Incomplete or duplicate build manifest')
for line in manifest_lines:
    digest, path = line.split('  ', 1)
    content = subprocess.check_output(['git', 'show', commit + ':' + path], cwd=root)
    if hashlib.sha256(content).hexdigest().lower() != digest.lower():
        raise SystemExit('Exact source manifest mismatch: ' + path)
# The build under test must also be the driver source at HEAD, or the run would not test what is committed.
if subprocess.call(['git', 'diff', '--quiet', commit, head, '--'] + subtrees, cwd=root) != 0:
    raise SystemExit('Driver/Inspector/fixture source at HEAD differs from the build commit')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


inputs = [
    ('FeatureDriverFileName', 'ExpectedFeatureSha256', work / 'SafeUpload-stage-prototype.sys', 'SafeUpload-stage-prototype-' + label + '.sys'),
    ('InspectorInputFileName', 'ExpectedInspectorSha256', work / 'inspector-feature-release.exe', 'SafeUpload.Inspector.' + label + '.exe'),
]
helper = root / 'driver/scripts/StagedTestAgent.ps1'
if subprocess.check_output(['git', 'show', head + ':driver/scripts/StagedTestAgent.ps1'], cwd=root) != helper.read_bytes():
    raise SystemExit('Dirty executable harness source: StagedTestAgent.ps1')
inputs.append(('TestAgentHelperFileName', None, helper, helper.stem + '-' + sha(helper)[:16] + helper.suffix))
signing = unique_row(summary, 'sign')
if signing.get('exit') != '0' or signing.get('signer') != '220DD82C37FCF36048D59E4F10113185D81D5DC7':
    raise SystemExit('Main signing gate failed')
if signing.get('signed_sha256') != sha(inputs[0][2]) or signing.get('unsigned_sha256') != sha(work / 'owned-feature.sys'):
    raise SystemExit('Main signed/unsigned artifact mismatch')
if unique_row(summary, 'inspector-feature-release').get('artifact_sha256') != sha(inputs[1][2]):
    raise SystemExit('Inspector artifact hash mismatch')
harness = root / 'driver/scripts/Test-StagedAdmissionDiagnostic.ps1'
harness_hash = sha(harness)
invocation = "$ErrorActionPreference='Stop';$d='C:\\Users\\vika\\Documents';"
invocation += "if((Get-FileHash (Join-Path $d 'Test-StagedAdmissionDiagnostic.ps1') -Algorithm SHA256).Hash -ne '" + harness_hash + "'){throw 'Harness hash mismatch'};"
invocation += "$sig=Get-AuthenticodeSignature (Join-Path $d 'SafeUpload-stage-prototype-" + label + ".sys');if($sig.Status.ToString() -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne '220DD82C37FCF36048D59E4F10113185D81D5DC7'){throw 'Upper signature preflight failed'};"
invocation += "& (Join-Path $d 'Test-StagedAdmissionDiagnostic.ps1') -Variant canary-newvolume -RequireAllVolumeCanaries"
if mode == 'verifier':
    invocation += ' -Verifier'
pre = "$ErrorActionPreference='Stop';$d='C:\\Users\\vika\\Documents';\n"
for param, hash_param, path, guest_leaf in inputs:
    invocation += " -" + param + " '" + guest_leaf + "'"
    if hash_param:
        invocation += " -" + hash_param + " '" + sha(path) + "'"
    pre += "$p=Join-Path $d '" + guest_leaf + "';if((Test-Path $p) -and (Get-FileHash $p -Algorithm SHA256).Hash -ne '" + sha(path) + "'){throw 'Existing input hash mismatch'}\n"
pre += "'PRE_RUN_OK=True'\n"
provenance = ['SourceCommit=' + commit, 'HarnessSourceCommit=' + head, 'MainBuildLabel=' + label,
              'Variant=canary-newvolume', 'Verifier=' + str(mode == 'verifier'), 'ExpectedChecks=' + expected_checks,
              'Invocation=' + invocation]
for leaf in ['Invoke-StagedCanaryNewVolumeQualification.py', 'Test-StagedAdmissionDiagnostic.ps1', 'Get-StagedBaseline.ps1',
             'StagedTestAgent.ps1', 'Invoke-DebuggeeExperiment.sh', 'remote_ps.py']:
    path = root / 'driver/scripts' / leaf
    if subprocess.check_output(['git', 'show', head + ':driver/scripts/' + leaf], cwd=root) != path.read_bytes():
        raise SystemExit('Dirty executable harness source: ' + leaf)
    provenance.append(sha(path) + '  driver/scripts/' + leaf)
for _, _, path, guest_leaf in inputs:
    provenance.append('Input=' + guest_leaf + ';SHA256=' + sha(path))
(ev / (name + '-provenance.txt')).write_text('\n'.join(provenance) + '\n')
env = os.environ.copy()
env['PRE_RUN_PS'] = pre
env['EXTRA_FILES'] = ' '.join(str(path) + '=' + guest_leaf for _, _, path, guest_leaf in inputs)
status = subprocess.call(['driver/scripts/Invoke-DebuggeeExperiment.sh', name, str(harness), invocation], cwd=root, env=env)
if status:
    raise SystemExit(status)
gate = (ev / (name + '-gate.txt')).read_text()
restored = (ev / (name + '-final-restored-state.txt')).read_text()
for required in ['VariantComplete=canary-newvolume', 'RestorationSucceeded=True', 'CN_Summary=passed:' + expected_checks + ';failed:0']:
    if gate.splitlines().count(required) != 1:
        raise SystemExit('Qualification verdict missing or ambiguous: ' + required)
if re.search(r'^(RunError|RestorationError|HARNESS_THREW|InspectorTimeout)=?', gate, re.MULTILINE):
    raise SystemExit('Experiment reported an error')
if re.search(r'^CN_.*;FAIL$', gate, re.MULTILINE):
    raise SystemExit('Canary new-volume run reported a failing check')
if restored.splitlines().count('BaselineClean=True') != 1 or 'BaselineClean=False' in restored:
    raise SystemExit('Independent restoration failed')
print('CheckpointedCanaryNewVolumeQualification=PASS')
