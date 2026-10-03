#!/usr/bin/env python3
"""Checkpoint one real writer-node allocation-failure experiment, using exact-source build evidence.

Usage: <run-name> <main-build-label> <source-commit>
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
name, label, revision = sys.argv[1:4]
if sys.argv[4:]:
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
for directory, build_summary, subtrees in [(work, summary, ['driver/SafeUpload.Minifilter', 'driver/SafeUpload.Inspector', 'driver/SafeUpload.WriterFixture'])]:
    for local, key in [('src.zip', 'ARCHIVE_SHA256'), ('src.manifest', 'MANIFEST_SHA256')]:
        digest = hashlib.sha256((directory / local).read_bytes()).hexdigest().upper()
        matches = re.findall(r'^' + key + r'=([0-9A-Fa-f]{64})$', build_summary, re.MULTILINE)
        if len(matches) != 1 or matches[0].upper() != digest:
            raise SystemExit('Build summary/source hash mismatch: ' + str(directory / local))
    expected_paths = set(subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', commit, '--'] + subtrees, cwd=root, text=True).splitlines())
    manifest_paths = [line.split('  ', 1)[1] for line in (directory / 'src.manifest').read_text().splitlines()]
    if set(manifest_paths) != expected_paths or len(manifest_paths) != len(expected_paths):
        raise SystemExit('Incomplete or duplicate build manifest')
    for line in (directory / 'src.manifest').read_text().splitlines():
        digest, path = line.split('  ', 1)
        content = subprocess.check_output(['git', 'show', commit + ':' + path], cwd=root)
        if hashlib.sha256(content).hexdigest().lower() != digest.lower():
            raise SystemExit('Exact source manifest mismatch: ' + path)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()

inputs = [
    ('FeatureDriverFileName', 'ExpectedFeatureSha256', work / 'SafeUpload-stage-prototype.sys', 'SafeUpload-stage-prototype-' + label + '.sys'),
    ('InspectorInputFileName', 'ExpectedInspectorSha256', work / 'inspector-feature-release.exe', 'SafeUpload.Inspector.' + label + '.exe'),
    ('WriterFaultFileName', 'ExpectedWriterFaultSha256', work / 'writer-fixture.exe', 'SafeUpload.WriterFault-' + label + '.exe'),
]
for param, hash_param, leaf in [
    ('FaultClientFileName', 'ExpectedFaultClientSha256', 'StagedSectionFaultClient.cs'),
    ('WriterFaultExerciseFileName', 'ExpectedWriterFaultExerciseSha256', 'StagedWriterFault.ps1'),
    ('TestAgentHelperFileName', None, 'StagedTestAgent.ps1'),
]:
    path = root / 'driver/scripts' / leaf
    if subprocess.check_output(['git', 'show', head + ':driver/scripts/' + leaf], cwd=root) != path.read_bytes():
        raise SystemExit('Dirty executable harness source: ' + leaf)
    guest_leaf = path.stem + '-' + sha(path)[:16] + path.suffix
    inputs.append((param, hash_param, path, guest_leaf))
signing = unique_row(summary, 'sign')
if signing.get('exit') != '0' or signing.get('signer') != '220DD82C37FCF36048D59E4F10113185D81D5DC7':
    raise SystemExit('Main signing gate failed')
if signing.get('signed_sha256') != sha(inputs[0][2]) or signing.get('unsigned_sha256') != sha(work / 'owned-feature.sys'):
    raise SystemExit('Main signed/unsigned artifact mismatch')
if unique_row(summary, 'inspector-feature-release').get('artifact_sha256') != sha(inputs[1][2]):
    raise SystemExit('Inspector artifact hash mismatch')
if unique_row(summary, 'writer-fixture').get('artifact_sha256') != sha(inputs[2][2]):
    raise SystemExit('Fixture artifact hash mismatch')
harness = root / 'driver/scripts/Test-StagedAdmissionDiagnostic.ps1'
harness_hash = sha(harness)
invocation = "$ErrorActionPreference='Stop';$d='C:\\Users\\vika\\Documents';"
invocation += "if((Get-FileHash (Join-Path $d 'Test-StagedAdmissionDiagnostic.ps1') -Algorithm SHA256).Hash -ne '" + harness_hash + "'){throw 'Harness hash mismatch'};"
invocation += "$sig=Get-AuthenticodeSignature (Join-Path $d 'SafeUpload-stage-prototype-" + label + ".sys');if($sig.Status.ToString() -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne '220DD82C37FCF36048D59E4F10113185D81D5DC7'){throw 'Upper signature preflight failed'};"
invocation += "& (Join-Path $d 'Test-StagedAdmissionDiagnostic.ps1') -Variant writer-fault -RequireAllVolumeCanaries -Verifier"
pre = "$ErrorActionPreference='Stop';$d='C:\\Users\\vika\\Documents';\n"
for param, hash_param, path, guest_leaf in inputs:
    invocation += " -" + param + " '" + guest_leaf + "'"
    if hash_param:
        invocation += " -" + hash_param + " '" + sha(path) + "'"
    pre += "$p=Join-Path $d '" + guest_leaf + "';if((Test-Path $p) -and (Get-FileHash $p -Algorithm SHA256).Hash -ne '" + sha(path) + "'){throw 'Existing input hash mismatch'}\n"
pre += "'PRE_RUN_OK=True'\n"
provenance = ['SourceCommit=' + commit, 'HarnessSourceCommit=' + head, 'MainBuildLabel=' + label,
              'Verifier=True', 'RealLowResourceFault=True', 'Invocation=' + invocation]
for leaf in ['Invoke-StagedWriterQualification.py', 'Test-StagedAdmissionDiagnostic.ps1', 'Get-StagedBaseline.ps1',
             'StagedTestAgent.ps1', 'StagedSectionFaultClient.cs', 'StagedWriterFault.ps1',
             'Invoke-DebuggeeExperiment.sh', 'remote_ps.py']:
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
for required in ['VariantComplete=writer-fault', 'RestorationSucceeded=True', 'WriterFaultRestored=True',
                 'WriterFaultQualification=PASS', 'WriterFaultProcessExitCode=0']:
    if gate.splitlines().count(required) != 1:
        raise SystemExit('Qualification verdict missing or ambiguous: ' + required)
if re.search(r'^(RunError|RestorationError|HARNESS_THREW|InspectorTimeout)=?', gate, re.MULTILINE):
    raise SystemExit('Experiment reported an error')
if restored.splitlines().count('BaselineClean=True') != 1 or 'BaselineClean=False' in restored:
    raise SystemExit('Independent restoration failed')
print('CheckpointedWriterQualification=PASS')
