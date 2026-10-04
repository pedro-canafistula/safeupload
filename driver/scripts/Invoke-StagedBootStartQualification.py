#!/usr/bin/env python3
"""Checkpoint one Phase 2 boot-start run (X4 + E1 with boot Verifier), using exact-source build evidence.

Usage: <run-name starting with boot-start> <main-build-label> <source-commit> <agent-build-label> <original-policy-sha256>
The agent label must pin a package with the SYSTEM-only --seed-boot-policy mode.
This runner and Test-StagedBootStart.ps1 may be uncommitted; their working-tree bytes are pinned in provenance.
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
name, label, revision, agent_label, policy_sha = sys.argv[1:6]
if sys.argv[6:] or not name.startswith('boot-start') or not re.fullmatch(r'[0-9A-Fa-f]{64}', policy_sha) or not re.fullmatch(r'[A-Za-z0-9_-]{3,60}', agent_label):
    raise SystemExit('Unknown arguments')
mode='boot-verifier'; expected_checks='0'
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
    ('InspectorFileName', 'ExpectedInspectorSha256', work / 'inspector-feature-release.exe', 'SafeUpload.Inspector.' + label + '.exe'),
]
agent_work = Path('/tmp/claude-1000/exact-agent-' + agent_label)
agent_summary = (agent_work / 'summary.txt').read_text('utf-8-sig')
agent_pkg = agent_work / 'stage-service-publish.zip'
m = re.search(r'^package_sha256=([0-9A-Fa-f]{64})$', agent_summary, re.MULTILINE)
if not m or m.group(1).upper() != sha(agent_pkg) or 'tests: exit=0' not in agent_summary or 'publish: exit=0' not in agent_summary:
    raise SystemExit('Agent build summary/package mismatch or failing agent gate')
inputs.append((None, 'ExpectedServicePackageSha256', agent_pkg, 'stage-service-publish.zip'))  # fixed guest name, hash only
helper = root / 'driver/scripts/StagedTestAgent.ps1'
if subprocess.check_output(['git', 'show', head + ':driver/scripts/StagedTestAgent.ps1'], cwd=root) != helper.read_bytes():
    raise SystemExit('Dirty executable harness source: StagedTestAgent.ps1')
helper_guest = helper.stem + '-' + sha(helper)[:16] + helper.suffix
inputs.append(('TestAgentHelperFileName', None, helper, helper_guest))
signing = unique_row(summary, 'sign')
if signing.get('exit') != '0' or signing.get('signer') != '220DD82C37FCF36048D59E4F10113185D81D5DC7':
    raise SystemExit('Main signing gate failed')
if signing.get('signed_sha256') != sha(inputs[0][2]) or signing.get('unsigned_sha256') != sha(work / 'owned-feature.sys'):
    raise SystemExit('Main signed/unsigned artifact mismatch')
if unique_row(summary, 'inspector-feature-release').get('artifact_sha256') != sha(inputs[1][2]):
    raise SystemExit('Inspector artifact hash mismatch')
harness = root / 'driver/scripts/Test-StagedBootStart.ps1'
def phase_line(phase):
    line = "$ErrorActionPreference='Stop';$d='C:\\Users\\vika\\Documents';"
    line += "if((Get-FileHash (Join-Path $d 'Test-StagedBootStart.ps1') -Algorithm SHA256).Hash -ne '" + sha(harness) + "'){throw 'Harness hash mismatch'};"
    line += "$sig=Get-AuthenticodeSignature (Join-Path $d 'SafeUpload-stage-prototype-" + label + ".sys');if($sig.Status.ToString() -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne '220DD82C37FCF36048D59E4F10113185D81D5DC7'){throw 'Upper signature preflight failed'};"
    line += "& (Join-Path $d 'Test-StagedBootStart.ps1') -Phase " + phase + " -ExpectedOriginalPolicySha256 '" + policy_sha.upper() + "'"
    for param, hash_param, path, guest_leaf in inputs:
        if param:
            line += " -" + param + " '" + guest_leaf + "'"
        if hash_param:
            line += " -" + hash_param + " '" + sha(path) + "'"
    return line
invocation = phase_line('Prepare')
after_boot_ps = phase_line('AfterBoot')
final_ps = phase_line('Finalize')
pre = "$ErrorActionPreference='Stop';$d='C:\\Users\\vika\\Documents';\n"
for param, hash_param, path, guest_leaf in inputs:
    if param is None:
        # A different package from an earlier run may sit under the fixed name: preserve it under its hash, never overwrite or delete.
        pre += ("$p=Join-Path $d '" + guest_leaf + "';if((Test-Path $p) -and (Get-FileHash $p -Algorithm SHA256).Hash -ne '" + sha(path) + "'){"
                "$old=(Get-FileHash $p -Algorithm SHA256).Hash.Substring(0,16);$keep=$p+'.preserved-'+$old;"
                "if(Test-Path $keep){throw 'Preserved package name already exists'};Move-Item -LiteralPath $p -Destination $keep}\n")
    else:
        pre += "$p=Join-Path $d '" + guest_leaf + "';if((Test-Path $p) -and (Get-FileHash $p -Algorithm SHA256).Hash -ne '" + sha(path) + "'){throw 'Existing input hash mismatch'}\n"
pre += "'PRE_RUN_OK=True'\n"
provenance = ['SourceCommit=' + commit, 'HarnessBaseCommit=' + head, 'HarnessSourceMode=sha256-pinned-working-tree', 'MainBuildLabel=' + label,
              'Variant=boot-start', 'AgentBuildLabel=' + agent_label, 'BootVerifier=True', 'Invocation=' + invocation,
              'AfterBootInvocation=' + after_boot_ps, 'FinalInvocation=' + final_ps]
for leaf in ['Invoke-StagedBootStartQualification.py', 'Test-StagedBootStart.ps1', 'Get-StagedBaseline.ps1',
             'StagedTestAgent.ps1', 'Invoke-DebuggeeExperiment.sh', 'remote_ps.py']:
    path = root / 'driver/scripts' / leaf
    # Allow this harness-only edit without a commit; keep every shared helper's exact-HEAD gate.
    if leaf not in ('Invoke-StagedBootStartQualification.py', 'Test-StagedBootStart.ps1') and \
            subprocess.check_output(['git', 'show', head + ':driver/scripts/' + leaf], cwd=root) != path.read_bytes():
        raise SystemExit('Dirty executable harness source: ' + leaf)
    provenance.append(sha(path) + '  driver/scripts/' + leaf)
for _, _, path, guest_leaf in inputs:
    provenance.append('Input=' + guest_leaf + ';SHA256=' + sha(path))
(ev / (name + '-provenance.txt')).write_text('\n'.join(provenance) + '\n')
env = os.environ.copy()
env['PRE_RUN_PS'] = pre
env['EXTRA_FILES'] = ' '.join(str(path) + '=' + guest_leaf for _, _, path, guest_leaf in inputs)
env['BOOT_START_AFTER_BOOT_PS'] = after_boot_ps
env['BOOT_START_FINAL_PS'] = final_ps
status = subprocess.call(['driver/scripts/Invoke-DebuggeeExperiment.sh', name, str(harness), invocation], cwd=root, env=env)
if status:
    raise SystemExit(status)
restored = (ev / (name + '-final-restored-state.txt')).read_text()
for phase, required in [('prepare', ['BootPolicySeed=product-mode;ExitCode:0;PASS',
                                    'BootPolicyPrebootVerified=ParametersAcl:True;BootPolicyAcl:True;RecordBytes:16656;ExactRecord:True;PendingScopes:Absent;Start:3;PASS',
                                    'BOOT_PREPARED=True', 'BootVerifierConfigured=True', 'HARNESS_RETURNED']),
                        ('after-boot', ['BootStartX4AndE1=True', 'BOOT_RESTORED=True', 'HARNESS_RETURNED']),
                        ('finalize', ['BOOT_FINAL_STATE=True', 'HARNESS_RETURNED'])]:
    text = (ev / (name + '-' + phase + '.txt')).read_text().splitlines()
    for line in required:
        if text.count(line) != 1:
            raise SystemExit('Boot-start verdict missing or ambiguous in ' + phase + ': ' + line)
    if any(re.match(r'^(HARNESS_THREW|PrepareRollbackReason)', l) for l in text):
        raise SystemExit('Boot-start phase reported an error: ' + phase)
if restored.splitlines().count('BaselineClean=True') != 1 or 'BaselineClean=False' in restored:
    raise SystemExit('Independent restoration failed')
print('CheckpointedBootStartQualification=PASS')
