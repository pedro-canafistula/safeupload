#!/usr/bin/env python3
"""Serial WP3 checkpoint adapter. No Windows execution during authoring.

First orchestrator run:
  python3 driver/scripts/Invoke-StagedInvariantQualification.py <unique-tag> \
    <driver-label> <driver-source-commit> <product-seed-agent-label> \
    <original-policy-sha256> --cases S00-observer-control --modes ordinary \
    --agent-source-commit <agent-source-commit>

Omitting --cases/--modes expands the entire immutable table x three modes.
NOT_READY and INCONCLUSIVE fail; subset runs never print Phase4Suite=PASS.
Guest case.json is provisional until the wrapper's separate baseline returns;
its bytes are retained as case.guest-export.txt before the ONE authoritative
host case.json export. Failed overlays/artifacts are never removed.
"""
from pathlib import Path
import argparse
import base64
import datetime
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'driver/scripts'
MODES = ('ordinary', 'runtime-verifier', 'boot-verifier')
SIGNER = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
SENTINELS = {
    'BOOT_START_PREPARED_SENTINEL': 'INVARIANT_PREPARED=True',
    'BOOT_START_CASE_SENTINEL': 'INVARIANT_CASE_COMPLETED=True',
    'BOOT_START_RESTORED_SENTINEL': 'INVARIANT_RESTORED=True',
    'BOOT_START_FINAL_SENTINEL': 'INVARIANT_FINAL_STATE=True',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def read_log(path):
    # WDK/msbuild logs from the builder are UTF-16 LE with a BOM; summaries are UTF-8 with a BOM (S00 attempt 1).
    raw = path.read_bytes()
    return raw.decode('utf-16') if raw[:2] in (b'\xff\xfe', b'\xfe\xff') else raw.decode('utf-8-sig')


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def write_new(path, text):
    with path.open('x', encoding='utf-8') as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())


def unique_hash(summary, key):
    values = re.findall(r'^' + re.escape(key) + r'=([0-9A-Fa-f]{64})$', summary, re.M)
    require(len(values) == 1, 'Missing/duplicate hash: ' + key)
    return values[0].upper()


def unique_row(content, prefix):
    rows = [line for line in content.splitlines() if line.startswith(prefix + ' :')]
    require(len(rows) == 1, 'Missing/duplicate build gate: ' + prefix)
    fields = re.findall(r'(\w+)=([^\s]+)', rows[0])
    require(len({key for key, _ in fields}) == len(fields), 'Duplicate gate fields')
    return dict(fields)


def checked_gate(content, prefix, analysis=False):
    row = unique_row(content, prefix)
    require(row.get('exit') == '0' and row.get('succeeded', 'True') == 'True', 'Failed build: ' + prefix)
    require(all(re.fullmatch(r'0(?:,0)*', row.get(key, '')) for key in ('warnings', 'errors')), 'Build diagnostics: ' + prefix)
    if analysis:
        require(row.get('apivalidator') == 'True' and row.get('prefast') == 'True', 'Missing WDK analysis: ' + prefix)
    return row


def exact_sources(work, summary, commit, subtrees):
    for leaf, key in [('src.zip', 'ARCHIVE_SHA256'), ('src.manifest', 'MANIFEST_SHA256')]:
        require(sha(work / leaf) == unique_hash(summary, key), 'Source artifact summary mismatch: ' + leaf)
    rows = (work / 'src.manifest').read_text('utf-8-sig').splitlines()
    records = [line.split('  ', 1) for line in rows]
    paths = [path for _, path in records]
    expected = git('ls-tree', '-r', '--name-only', commit, '--', *subtrees).decode().splitlines()
    require(set(paths) == set(expected) and len(paths) == len(expected), 'Incomplete/duplicate exact source manifest')
    with zipfile.ZipFile(work / 'src.zip') as archive:
        archive_paths = [item.filename for item in archive.infolist() if not item.is_dir()]
        require(set(archive_paths) == set(paths) and len(archive_paths) == len(paths), 'Source ZIP path inventory mismatch')
        for digest, path in records:
            require(re.fullmatch(r'[0-9A-Fa-f]{64}', digest) is not None, 'Malformed manifest digest')
            original = git('show', commit + ':' + path)
            require(hashlib.sha256(original).hexdigest().upper() == digest.upper() and archive.read(path) == original,
                    'Exact source mismatch: ' + path)
    # Covers HEAD and tracked dirty working-tree source; no test of stale code.
    require(subprocess.call(['git', 'diff', '--quiet', commit, '--', *subtrees], cwd=ROOT) == 0, 'Build source differs from working tree')
    require(not git('ls-files', '--others', '--exclude-standard', '--', *subtrees).strip(), 'Untracked build source')


def table_rows(path):
    # Deliberately restricted data-table grammar: never run/evaluate PowerShell
    # on the host. Guest Import-PowerShellDataFile validates the complete schema.
    source = path.read_text()
    rows = re.findall(r"^\s+CaseId = '([^']+)'; Revision = ([1-9][0-9]*); Status = '(Ready|NotReady)'$", source, re.M)
    require(rows and len({row[0] for row in rows}) == len(rows), 'Missing/duplicate table IDs')
    required = {f'{prefix}{n:02}' for prefix, limit in [('A', 5), ('C', 5), ('B', 2), ('R', 3), ('P', 6), ('X', 1)] for n in range(1, limit + 1)}
    required.update(('S00-observer-control', 'S01-denied-write-after-boot', 'S02-agent-down-open-refused'))
    require(required <= {r[0] for r in rows}, 'Table silently omitted a design family')
    return {case: {'Revision': int(revision), 'Status': status} for case, revision, status in rows}


def build_inputs(args, commit, agent_commit, head):
    work = Path('/tmp/claude-1000/exact-' + args.driver_label)
    summary = (work / 'summary.txt').read_text('utf-8-sig')
    for suffix, log in [('normal', 'normal-wdk.txt'), ('owned-feature', 'owned-feature-wdk.txt'),
                        ('normal-release', 'normal-release-wdk.txt'), ('owned-feature-release', 'owned-feature-release-wdk.txt')]:
        checked_gate(summary, 'driver:' + suffix, True)
        require('DriverRecommendedRules.ruleset' in read_log(work / log), 'WDK rule set evidence absent: ' + log)
    for gate in ('inspector-normal-release', 'inspector-feature-release', 'writer-fixture'):
        checked_gate(summary, gate)
    exact_sources(work, summary, commit, ['driver/SafeUpload.Minifilter', 'driver/SafeUpload.Inspector', 'driver/SafeUpload.WriterFixture'])
    feature = work / 'SafeUpload-stage-prototype.sys'
    inspector = work / 'inspector-feature-release.exe'
    signed = unique_row(summary, 'sign')
    require(signed.get('exit') == '0' and signed.get('signer') == SIGNER and signed.get('signed_sha256') == sha(feature)
            and signed.get('unsigned_sha256') == sha(work / 'owned-feature.sys'), 'Signed/unsigned driver/signer gate')
    require(unique_row(summary, 'inspector-feature-release').get('artifact_sha256') == sha(inspector), 'Inspector artifact mismatch')
    agent_work = Path('/tmp/claude-1000/exact-agent-' + args.agent_label)
    agent_summary = (agent_work / 'summary.txt').read_text('utf-8-sig')
    exact_sources(agent_work, agent_summary, agent_commit, ['agente'])
    for gate in ('tests', 'publish'):
        matches = re.findall(r'^' + gate + r': exit=0 warnings=0$', agent_summary, re.M)
        require(len(matches) == 1, 'Agent tests/publish gate absent/ambiguous: ' + gate)
    counters = ET.parse(agent_work / 'agent-tests.trx').getroot().find('.//{*}Counters')
    require(counters is not None and int(counters.get('total', '0')) > 0 and
            counters.get('total') == counters.get('passed') == counters.get('executed') and
            all(int(counters.get(key, '0')) == 0 for key in ('failed', 'error', 'aborted', 'timeout', 'notExecuted', 'inconclusive', 'notRunnable', 'warning', 'pending', 'inProgress')), 'Current agent tests incomplete')
    package = agent_work / 'stage-service-publish.zip'
    require(sha(package) == unique_hash(agent_summary, 'package_sha256'), 'Agent package summary mismatch')
    tree_lines = []
    with zipfile.ZipFile(package) as archive:
        leaves = [item.filename for item in archive.infolist() if not item.is_dir()]
        require(len(leaves) == len(set(p.lower() for p in leaves)), 'Duplicate package entries')
        require(all(not p.startswith(('/', '\\')) and '..' not in p.split('/') and '\\' not in p for p in leaves), 'Unsafe package path')
        require('SafeUpload.Agent.Service.exe' in leaves, 'Missing seed executable')
        require(hashlib.sha256(archive.read('SafeUpload.Agent.Service.exe')).hexdigest().upper() == unique_hash(agent_summary, 'exe_sha256'), 'Extracted executable mismatch')
        for leaf in leaves:
            tree_lines.append(hashlib.sha256(archive.read(leaf)).hexdigest().upper() + '  ' + leaf)
    tree_hash = hashlib.sha256(('\n'.join(sorted(tree_lines)) + '\n').encode()).hexdigest().upper()
    files = {
        'FeatureDriverFileName': (feature, 'ExpectedFeatureSha256'),
        'InspectorFileName': (inspector, 'ExpectedInspectorSha256'),
        'TableFileName': (SCRIPTS / 'StagedInvariantCases.psd1', 'ExpectedTableSha256'),
        'ObserverFileName': (SCRIPTS / 'StagedInvariantObserver.psm1', 'ExpectedObserverSha256'),
        'HelperFileName': (SCRIPTS / 'StagedTestAgent.ps1', 'ExpectedHelperSha256'),
    }
    provenance = {'SourceCommit': commit, 'AgentSourceCommit': agent_commit, 'HarnessBaseCommit': head,
                  'HarnessSourceMode': 'sha256-pinned-working-tree', 'SignedSha256': sha(feature),
                  'UnsignedSha256': sha(work / 'owned-feature.sys'), 'Signer': SIGNER,
                  'SourceManifests': {str(work): sha(work / 'src.manifest'), str(agent_work): sha(agent_work / 'src.manifest')},
                  'ServiceTreeSha256': tree_hash, 'BuildSummarySha256': sha(work / 'summary.txt'),
                  'AgentSummarySha256': sha(agent_work / 'summary.txt'), 'WriterFixtureSha256': sha(work / 'writer-fixture.exe')}
    pins = {}
    for leaf in ('StagedInvariantCases.psd1', 'StagedInvariantObserver.psm1', 'Test-StagedInvariantSuite.ps1',
                 'Invoke-StagedInvariantQualification.py', 'StagedInvariantProofAdapters.SelfCheck.ps1', 'test_staged_invariant_proof_adapters.py', 'StagedTestAgent.ps1', 'Invoke-DebuggeeExperiment.sh', 'Get-StagedBaseline.ps1', 'remote_ps.py'):
        path = SCRIPTS / leaf
        # Baseline now records the case-owned audit setting; like the suite and
        # wrapper, freeze its authorized working-tree bytes in provenance.
        if leaf in ('StagedInvariantObserver.psm1', 'StagedTestAgent.ps1', 'remote_ps.py'):
            require(git('show', head + ':driver/scripts/' + leaf) == path.read_bytes(), 'Dirty shared executable: ' + leaf)
        pins['driver/scripts/' + leaf] = sha(path)
    provenance['BuildEvidenceDirectories'] = [str(work), str(agent_work)]
    provenance['Pins'] = pins
    provenance['ArtifactPins'] = {str(path): sha(path) for path in (feature, inspector, package, work / 'writer-fixture.exe')}
    return files, package, tree_hash, provenance


def ps_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def phase_line(phase, params, suite_leaf, name):
    docs = 'C:\\Users\\vika\\Documents'
    command = '& ' + ps_literal(docs + '\\' + suite_leaf) + ' -Phase ' + phase
    for key, value in params.items():
        command += ' -' + key + ' ' + ps_literal(value)
    encoded = base64.b64encode(("$ErrorActionPreference='Stop';try{" + command + "}catch{[Console]::Error.WriteLine(($_|Out-String)+$_.Exception.ToString()+$_.ScriptStackTrace);exit 1}").encode('utf-16le')).decode()
    prefix = docs + '\\' + name + '-' + phase.lower()
    # Raw guest process streams survive the wrapper's CLIXML cleaning. All
    # sentinels come from this pinned child; cache Handle before wait on PS 5.1.
    return ("$ErrorActionPreference='Stop';$p=$null;try{"
            "$p=Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encoded + "' -PassThru "
            "-RedirectStandardOutput " + ps_literal(prefix + '.out') + " -RedirectStandardError " + ps_literal(prefix + '.err') + ";"
            "$null=$p.Handle;if(-not $p.WaitForExit(900000)){throw 'Suite child timeout'};$p.WaitForExit();"
            "Get-Content -LiteralPath " + ps_literal(prefix + '.out') + ";"
            "if($null -eq $p.ExitCode -or $p.ExitCode -ne 0){Get-Content -LiteralPath " + ps_literal(prefix + '.err') + ";throw 'Suite child failed'}"
            "}finally{if($null -ne $p){if(-not $p.HasExited){$p.Kill();$p.WaitForExit()};$p.Dispose()}}")


def clean_baseline(path):
    text = path.read_text('utf-8-sig')
    return text.splitlines().count('BaselineClean=True') == 1 and not re.search(r'^BaselineClean=(?!True$)', text, re.M)


def baseline_audit(path):
    text = path.read_text('utf-8-sig')
    values = {}
    for key in ('ProcessCreationAuditFlags', 'ProcessCreationAuditPerUserCount'):
        matches = re.findall(r'^' + key + r'=(\d+)$', text, re.M)
        require(len(matches) == 1, 'Missing/duplicate independent audit value: ' + key)
        values[key] = int(matches[0])
    return values


def validate_audit_restoration(result, before_path, after_path):
    before, after = baseline_audit(before_path), baseline_audit(after_path)
    require(before == after, 'Independent process-creation audit restoration mismatch')
    policy = result.get('Restoration', {}).get('ProcessCreationAudit') or {}
    require(policy.get('Restored') is True, 'Guest audit restoration receipt missing')
    for edge, baseline in (('Original', before), ('Final', after)):
        receipt = policy.get(edge) or {}
        require(receipt.get('CreationFlags') == baseline['ProcessCreationAuditFlags']
                and receipt.get('PerUserPolicyCount') == baseline['ProcessCreationAuditPerUserCount'],
                'Guest audit policy differs from independent baseline: ' + edge)


def phase_gate(ev, name):
    for phase, lines in [('prepare', ['INVARIANT_PREPARED=True', 'CaseStatus=READY', 'BootPolicySeed=product-mode;ExitCode:0;PASS',
                                     'BootPolicyPrebootVerified=ParametersAcl:True;BootPolicyAcl:True;RecordBytes:16656;ExactRecord:True;PendingScopes:Absent;Start:3;PASS']),
                         ('after-boot', ['INVARIANT_CASE_COMPLETED=True', 'INVARIANT_RESTORED=True']),
                         ('finalize', ['INVARIANT_FINAL_STATE=True'])]:
        text = (ev / (name + '-' + phase + '.txt')).read_text('utf-8-sig').splitlines()
        for line in lines + ['HARNESS_RETURNED']:
            require(text.count(line) == 1, 'Missing/duplicate phase sentinel: ' + phase + '/' + line)
        require(not any(re.match(r'^(HARNESS_THREW|PrepareRollback|CaseStatus=NOT_READY)', l) for l in text), 'Phase failure: ' + phase)
    for phase in ('reboot-1', 'reboot-restore'):
        lines = (ev / (name + '-' + phase + '-changed.txt')).read_text().splitlines()
        require(len(lines) == 1 and lines[0].startswith('BootIdentityChanged=True;'), 'Missing changed boot identity')
    require(clean_baseline(ev / (name + '-baseline.txt')) and clean_baseline(ev / (name + '-final-restored-state.txt')), 'Independent baseline failure')
    require(baseline_audit(ev / (name + '-baseline.txt')) == baseline_audit(ev / (name + '-final-restored-state.txt')),
            'Independent process-creation audit restoration mismatch')
    require((ev / (name + '-flush.txt')).read_text().splitlines().count('VolumeCacheWritten=True') == 1, 'Checkpoint flush missing/duplicate')


def actor_cadence_complete(trial):
    """Recompute operation-free intervals; never accept an Accounted/Complete flag."""
    try:
        baseline, fence = trial['Baseline'], trial['WriterFence']
        boot, frequency = baseline['Time']['BootId'], baseline['Time']['QpcFrequency']
        calls, samples = trial['Operations'], trial['Samples']
        if (fence['Complete'] is not True or fence['BootId'] != boot or fence['QpcFrequency'] != frequency
                or frequency <= 0 or fence['ExpectedAttempts'] != 101 or not samples
                or fence['ReleasedQpc'] > fence['CompletedQpc']):
            return False
        windows, count, previous = [], 0, fence['ReleasedQpc']
        for number in range(101):
            attempt = [c for c in calls if c['Trial'] == number]
            classes = [c['Class'] for c in attempt]
            if classes == ['writer-open-deny']:
                if attempt[0]['NativeCode'] == 0:
                    return False
            elif classes == ['writer-open', 'cached-write', 'flush', 'close']:
                if attempt[0]['NativeCode'] != 0:
                    return False
            else:
                return False
            for call in attempt:
                if not previous <= call['StartQpc'] <= call['EndQpc'] <= fence['CompletedQpc']:
                    return False
                previous = call['EndQpc']
            windows.append((attempt[0]['StartQpc'], attempt[-1]['EndQpc']))
            count += len(attempt)
        if count != len(calls):
            return False
        if any(end > samples[-1]['End']['Qpc'] for _, end in windows):
            return False
        if baseline.get('CaseId') != 'S00-observer-control' and any(start < baseline['Time']['Qpc'] for start, _ in windows):
            return False
        previous = baseline['Time']['Qpc']
        for sequence, sample in enumerate(samples, 1):
            start, end = sample['Start'], sample['End']
            if (sample['Status'] != 'OK' or sample['Sequence'] != sequence
                    or start['BootId'] != boot or end['BootId'] != boot
                    or start['QpcFrequency'] != frequency or end['QpcFrequency'] != frequency
                    or not previous <= start['Qpc'] <= end['Qpc']):
                return False
            # Includes capture duration, not just dead time between samples.
            if any(left <= end['Qpc'] and right >= previous for left, right in windows):
                return False
            previous = end['Qpc']
        return True
    except (KeyError, TypeError, ValueError, IndexError):
        return False


def attest_external_coverage(result):
    """Called only after phase_gate and the independent remote baseline."""
    boot, restoration = result['BootIds'], result['Restoration']
    for trial in result['Trials']:
        timeline = trial.setdefault('ExpectedTimeline', {})
        evidence = timeline.setdefault('ExternalEvidence', {})
        evidence['Restoration'] = dict(restoration, FinalBootId=boot['Final'])
        problems = []
        baseline = trial.get('Baseline') or {}
        platform = trial.get('Platform') or {}
        actor = trial.get('Actor') or {}
        provenance = trial.get('ActorProvenance') or {}
        observer = platform.get('ObserverProcess') or {}
        activating_case = result.get('CaseId') in ('A01', 'A02', 'A03')
        if baseline.get('Build') != '19045.2965' or evidence.get('Build') != baseline.get('Build'):
            problems.append('Build 19045.2965 attestation missing.')
        if (len({boot.get(k) for k in ('Prepare', 'Active', 'Final')}) != 3
                or not all(boot.get(k) for k in ('Prepare', 'Active', 'Final'))
                or boot['Active'] != baseline.get('Time', {}).get('BootId')
                or evidence.get('PrepareBootId') != boot['Prepare'] or evidence.get('ActiveBootId') != boot['Active']):
            problems.append('Activation/restoration boot identities incomplete.')
        if (evidence.get('ObserverSid') != 'S-1-5-18' or baseline.get('ObserverSid') != evidence.get('ObserverSid')
                or observer.get('OwnerSid') != evidence.get('ObserverSid')
                or observer.get('Pid', 0) <= 0 or observer.get('Pid') != evidence.get('ObserverPid')
                or baseline.get('ObserverPid') != observer.get('Pid')):
            problems.append('OS SYSTEM observer identity missing.')
        if (actor.get('Elevated') is not False or actor.get('IsAdministrator') is not False
                or not re.fullmatch(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+', actor.get('Sid', ''))
                or actor.get('Sid') == evidence.get('ObserverSid') or actor.get('Pid', 0) <= 0
                or actor.get('Pid') == evidence.get('ObserverPid') or actor.get('BootId') != boot['Active']
                or provenance.get('OwnerSid') != actor.get('Sid') or provenance.get('Pid') != actor.get('Pid')
                or provenance.get('SessionId') != actor.get('SessionId')
                or timeline.get('WriterIdentities') != [actor]):
            problems.append('OS independent standard-user writer/session provenance missing.')
        if activating_case:
            holder = trial.get('HolderSetup') or {}
            if (holder.get('Pid') != actor.get('Pid') or holder.get('Sid') != actor.get('Sid')
                    or holder.get('SessionId') != actor.get('SessionId')
                    or not isinstance(holder.get('CreateQpc'), int) or not isinstance(holder.get('CompleteQpc'), int)
                    or holder['CreateQpc'] > holder['CompleteQpc']):
                problems.append('Activation holder setup is not bound to the standard-user process identity/QPC interval.')
        elif not actor_cadence_complete(trial):
            problems.append('Synchronous actor cadence has unaccounted intervals.')
        if (restoration.get('Known') is not True or restoration.get('GuestChecks') is not True
                or not restoration.get('IndependentBaseline') or not restoration.get('IndependentBaselineSha256')):
            problems.append('Independent restoration evidence missing.')
        assertion = {'Name': 'ExternalCoverage', 'Verdict': 'INCONCLUSIVE' if problems else 'PASS',
                     'Reason': ' '.join(problems) if problems else
                     'Build, boot identities, OS observer/writer SID/PID/session, operation-free QPC intervals and independent BaselineClean=True attested.',
                     'Evidence': evidence}
        for container in (trial, trial.get('Predicate', {})):
            assertions = [a for a in container.get('Assertions', []) if a.get('Name') != 'ExternalCoverage']
            assertions.append(assertion)
            container['Assertions'] = assertions
            container['Verdict'] = ('FAIL' if any(a.get('Verdict') == 'FAIL' for a in assertions) else
                                    'INCONCLUSIVE' if any(a.get('Verdict') != 'PASS' for a in assertions) else 'PASS')
        if trial.get('Errors') or any(l.get('Verdict') != 'PASS' for l in trial.get('Latency', [])):
            trial['Verdict'] = 'FAIL' if any(l.get('Verdict') == 'FAIL' for l in trial.get('Latency', [])) or trial['Verdict'] == 'FAIL' else 'INCONCLUSIVE'
    result['Verdict'] = ('FAIL' if any(t['Verdict'] == 'FAIL' for t in result['Trials']) else
                         'INCONCLUSIVE' if any(t['Verdict'] != 'PASS' for t in result['Trials']) else 'PASS')


def validate_service_artifacts(result, destination, guest_root):
    for trial in result.get('Trials', []):
        for snapshot in (trial.get('ServiceBefore') or {}, trial.get('ServiceAfter') or {}):
            records = list(snapshot.get('Journal', [])) + list((snapshot.get('Notifications') or {}).get('Artifacts', []))
            for record in records:
                path = record['Artifact']
                require(path.startswith(guest_root), 'Service evidence outside owned guest evidence root')
                relative = path[len(guest_root):].replace('\\', '/')
                require('..' not in relative.split('/') and not relative.startswith('/'), 'Invalid service artifact path')
                artifact = destination / relative
                require(artifact.stat().st_size == record['Length'] and sha(artifact) == record['Sha256'],
                        'Copied authenticated service evidence hash/length mismatch')
                if 'Entry' in record:
                    require(json.loads(artifact.read_text('utf-8-sig')) == record['Entry'], 'Journal JSON differs from retained bytes')

            notifications = snapshot.get('Notifications') or {}
            if notifications.get('LocationStatus') == 'OK' and notifications.get('DirectoryExists'):
                for file in notifications.get('LocationFiles', []):
                    if file['Name'] == 'writer.lock':
                        require(file.get('Bytes') == [], 'Notification writer lock bytes mismatch')
                        continue
                    matches = [r for r in notifications.get('Artifacts', []) if r.get('Name') == file['Name']]
                    require(len(matches) == 1, 'Notification location bytes lack unique retained artifact')
                    relative = matches[0]['Artifact'][len(guest_root):].replace('\\', '/')
                    require(list((destination / relative).read_bytes()) == file.get('Bytes'),
                            'Notification location bytes differ from retained artifact')

        absence = (trial.get('ServiceEvidence') or {}).get('AgentAbsenceProof') or {}
        for name in ('SystemLog', 'SecurityLog'):
            record = absence.get(name) or {}
            if not record.get('Artifact'):
                continue
            path = record['Artifact']
            require(path.startswith(guest_root), 'Agent absence evidence outside owned guest evidence root')
            relative = path[len(guest_root):].replace('\\', '/')
            require('..' not in relative.split('/') and not relative.startswith('/'), 'Invalid agent absence artifact path')
            artifact = destination / relative
            require(artifact.stat().st_size == record['Length'] and sha(artifact) == record['Sha256'],
                    'Copied agent absence evidence hash/length mismatch')
            require(json.loads(artifact.read_text('utf-8-sig')) == record['Xmls'],
                    'Agent absence event XML differs from retained bytes')


def case_gate(result, case, mode, name, params):
    require(result.get('Schema') == 'StagedInvariantSuite/2' and result.get('CaseId') == case and result.get('Mode') == mode
            and result.get('RunName') == name, 'Case JSON schema/run identity mismatch')
    for param, field in [('ExpectedTableSha256', 'Table'), ('ExpectedObserverSha256', 'Observer'), ('ExpectedSuiteSha256', 'Suite'),
                         ('ExpectedHelperSha256', 'Helper'), ('ExpectedFeatureSha256', 'Feature'), ('ExpectedInspectorSha256', 'Inspector'),
                         ('ExpectedServicePackageSha256', 'ServicePackage'), ('ExpectedServiceTreeSha256', 'ServiceTree')]:
        require(result.get('InputHashes', {}).get(field) == params[param], 'Result input hash mismatch: ' + field)
    require(len(result.get('Trials', [])) == 1, 'Missing/ambiguous seed trial')
    boot = result.get('BootIds', {})
    require(all(isinstance(boot.get(k), str) and boot[k] for k in ('Prepare', 'Active', 'Final')) and len(set(boot.values())) == 3, 'Case boot identities incomplete')
    if case in ('A01', 'A02', 'A03'):
        required = {
            'RuntimePendingUnionAndAdmissionEpoch', 'ServiceReadinessPendingWhileHolderLives',
            'ExactActivatingWriterEvidence', 'NewWritableOpenDenied', 'NewWritableSectionDenied',
            'NewWritableSectionAdmissionCallback', 'NoObservedReadyWhileHolderLives',
            'OldHolderMutationAllowedAndRecorded', 'OldHolderStillActivatingAfterMutation',
            'OldHolderLowerCompletion', 'FreeAndProtectedAfterLastHolder', 'PromotionTraceForSameFileId',
            'ServiceReadinessReadyAfterPromotion', 'PostPromotionUnapprovedWriteRoutedToOwnedStream',
            'OwnedStreamJournalForExactDestination', 'PostPromotionRawDestinationUnchanged', 'Disposal',
        }
        passed = (result.get('Verdict') == 'PASS' and result.get('CaseStatus') == 'READY'
                  and result.get('ForbiddenByteCount') == 0)
        for trial in result['Trials']:
            assertions = trial.get('Assertions', [])
            names = {item.get('Name') for item in assertions}
            passed &= (trial.get('Verdict') == 'PASS' and trial.get('ForbiddenByteCount') == 0
                       and trial.get('Disposal', {}).get('Status') == 'OK' and not trial.get('Errors')
                       and required <= names and bool(assertions)
                       and all(item.get('Verdict') == 'PASS' for item in assertions))
        return bool(passed)
    passed = (result.get('Verdict') == 'PASS' and result.get('CaseStatus') == 'READY' and result.get('ForbiddenByteCount') == 0)
    for trial in result['Trials']:
        passed &= (trial.get('Verdict') == 'PASS' and trial.get('ForbiddenByteCount') == 0 and
                   trial.get('Predicate', {}).get('Verdict') == 'PASS' and trial.get('Disposal', {}).get('Status') == 'OK' and
                   not trial.get('Errors') and bool(trial.get('Assertions')) and
                   all(a.get('Verdict') == 'PASS' for a in trial['Assertions']))
        classes = trial.get('Latency', [])
        passed &= bool(classes)
        for item in classes:
            samples = item.get('Samples', [])
            durations = [s.get('Ms') for s in samples]
            unheld = sorted(s['Ms'] for s in samples if not s.get('Cold'))
            valid = (len(unheld) >= 100 and all(isinstance(n, (float, int)) and math.isfinite(n) and n >= 0 for n in durations))
            passed &= valid and item.get('Verdict') == 'PASS'
            if valid:
                passed &= sorted(durations)[math.ceil(.95 * len(durations)) - 1] <= 250 and max(durations) <= 1000
    return bool(passed)


def run_case(args, case, mode, ev, files, package, tree_hash, provenance):
    name = f'boot-start-invariant-{case}-{mode}-{args.tag}'
    require(not list(ev.glob(name + '*')), 'Evidence collision: ' + name)
    params = {'CaseId': case, 'Mode': mode, 'RunName': name, 'ExpectedOriginalPolicySha256': args.policy_sha.upper(),
              'ExpectedServicePackageSha256': sha(package), 'ExpectedServiceTreeSha256': tree_hash}
    transfers = []
    for param, (path, hash_param) in files.items():
        leaf = path.stem + '-' + sha(path)[:16] + path.suffix
        params[param] = leaf
        params[hash_param] = sha(path)
        transfers.append((path, leaf))
    suite = SCRIPTS / 'Test-StagedInvariantSuite.ps1'
    params['ExpectedSuiteSha256'] = sha(suite)
    suite_leaf = suite.stem + '-' + sha(suite)[:16] + suite.suffix
    # Wrapper copies its harness argument by basename; supply identical bytes
    # under the hash-qualified name, never weaken the guest collision gate.
    with tempfile.TemporaryDirectory(prefix='invariant-harness-', dir='/tmp') as temporary:
        staged_suite = Path(temporary) / suite_leaf
        staged_suite.write_bytes(suite.read_bytes())
        transfers.extend([(package, 'stage-service-publish.zip')])
        pre = "$ErrorActionPreference='Stop';$d='C:\\Users\\vika\\Documents';\n"
        for path, leaf in transfers + [(staged_suite, suite_leaf)]:
            pre += '$p=Join-Path $d ' + ps_literal(leaf) + ';'
            if leaf == 'stage-service-publish.zip':
                pre += ("if((Test-Path -LiteralPath $p) -and (Get-FileHash $p).Hash -ne " + ps_literal(sha(path)) + "){$old=(Get-FileHash $p).Hash;"
                        "$keep=$p+'.preserved-'+$old;if(Test-Path -LiteralPath $keep){throw 'Preserved package collision'};Move-Item -LiteralPath $p -Destination $keep};\n")
            else:
                pre += 'if((Test-Path -LiteralPath $p) -and (Get-FileHash $p).Hash -ne ' + ps_literal(sha(path)) + "){throw 'Input collision'};\n"
        for leaf in [name + '-artifacts', 'SafeUpload-invariant-state-' + name, *[name + '-' + phase + suffix for phase in ('prepare', 'afterboot', 'finalize') for suffix in ('.out', '.err')]]:
            pre += 'if(Test-Path -LiteralPath (Join-Path $d ' + ps_literal(leaf) + ")){throw 'Run-scoped guest evidence collision'};\n"
        pre += "'PRE_RUN_OK=True'\n"
        env = os.environ.copy()
        env.update(SENTINELS)
        env['PRE_RUN_PS'] = pre
        env['EXTRA_FILES'] = ' '.join(str(path) + '=' + leaf for path, leaf in transfers)
        env['BOOT_START_AFTER_BOOT_PS'] = phase_line('AfterBoot', params, suite_leaf, name)
        env['BOOT_START_FINAL_PS'] = phase_line('Finalize', params, suite_leaf, name)
        prepared = phase_line('Prepare', params, suite_leaf, name)
        write_new(ev / (name + '-provenance.txt'), json.dumps(dict(provenance, RunName=name, Parameters=params, Sentinels=SENTINELS,
                  PrepareInvocation=prepared, AfterBootInvocation=env['BOOT_START_AFTER_BOOT_PS'], FinalInvocation=env['BOOT_START_FINAL_PS']), indent=2) + '\n')
        # Freeze all pins before EACH serial invocation, not just at suite startup.
        for path, digest in provenance['ArtifactPins'].items():
            require(sha(Path(path)) == digest, 'Pinned build artifact changed mid-suite: ' + path)
        for relative, digest in provenance['Pins'].items():
            require(sha(ROOT / relative) == digest, 'Pinned harness changed mid-suite: ' + relative)
        with (ev / (name + '-wrapper-stdout.txt')).open('x') as out, (ev / (name + '-wrapper-stderr.txt')).open('x') as err:
            status = subprocess.call([str(SCRIPTS / 'Invoke-DebuggeeExperiment.sh'), name, str(staged_suite), prepared], cwd=ROOT, env=env, stdout=out, stderr=err)
        # Even failure evidence is retrieved; no following VM run on a failed
        # lifecycle or missing/dirty independent restoration.
        destination = ev / (name + '-artifacts')
        scp = ['scp', '-F', '/dev/null', '-i', '/home/victor/.ssh/id_ed25519', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
               '-o', 'StrictHostKeyChecking=accept-new']
        with (ev / (name + '-artifact-transfer.txt')).open('x') as log:
            copied = subprocess.call(scp + ['-r', 'vika@192.168.122.51:C:/Users/vika/Documents/' + name + '-artifacts', str(destination)], stdout=log, stderr=log)
            transport_complete = copied == 0
            if copied == 0:
                transport = destination / 'transport'
                transport.mkdir()
                for phase in ('prepare', 'afterboot', 'finalize'):
                    for suffix in ('.out', '.err'):
                        transport_complete &= subprocess.call(scp + ['vika@192.168.122.51:C:/Users/vika/Documents/' + name + '-' + phase + suffix,
                                               str(transport / (phase + suffix))], stdout=log, stderr=log) == 0
        require(status == 0, 'Wrapper failed; stop serial runs; retain checkpoint/recovery-required evidence: ' + name)
        phase_gate(ev, name)
        require(copied == 0 and transport_complete, 'Complete guest evidence/raw streams unavailable; stop serial runs')
        provisional = destination / 'case.json'
        result = json.loads(provisional.read_text('utf-8-sig'))
        # Preserve guest bytes; only the host knows the separate remote baseline.
        provisional.rename(destination / 'case.guest-export.txt')
        manifest = destination / 'raw/manifest.ndjson'
        guest_root = 'C:\\Users\\vika\\Documents\\' + name + '-artifacts\\'
        if manifest.exists():
            for line in manifest.read_text('utf-8-sig').splitlines():
                entry = json.loads(line)
                require(entry['Path'].startswith(guest_root), 'Raw artifact outside owned evidence root')
                relative = entry['Path'][len(guest_root):].replace('\\', '/')
                require('..' not in relative.split('/'), 'Invalid artifact path')
                artifact = destination / relative
                require(artifact.stat().st_size == entry['Length'] and sha(artifact) == entry['Sha256'], 'Copied raw artifact hash/length mismatch')
        validate_service_artifacts(result, destination, guest_root)
        validate_audit_restoration(result, ev / (name + '-baseline.txt'), ev / (name + '-final-restored-state.txt'))
        result['AuthoritativeCaseExport'] = True
        result['Restoration'].update(Known=True, IndependentBaseline=str(ev / (name + '-final-restored-state.txt')),
                                     IndependentBaselineSha256=sha(ev / (name + '-final-restored-state.txt')))
        result['CheckpointLinks'] = {key: str(ev / (name + '-' + key + '.txt')) for key in ('baseline', 'flush', 'checkpoint', 'prepare', 'after-boot', 'finalize', 'final-restored-state')}
        result['ProvenanceLink'] = str(ev / (name + '-provenance.txt'))
        result['ArtifactRootMapping'] = {'Guest': 'C:\\Users\\vika\\Documents\\' + name + '-artifacts', 'Host': str(destination)}
        attest_external_coverage(result)
        passed = case_gate(result, case, mode, name, params)
        result['GatePassed'] = passed
        write_new(provisional, json.dumps(result, indent=2) + '\n')
        return {'CaseId': case, 'Mode': mode, 'RunName': name, 'Verdict': result['Verdict'], 'GatePassed': passed,
                'ForbiddenByteCount': result.get('ForbiddenByteCount'), 'RestorationClean': True, 'Result': str(provisional), 'ResultSha256': sha(provisional)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for value in ('tag', 'driver_label', 'source_commit', 'agent_label', 'policy_sha'):
        parser.add_argument(value)
    parser.add_argument('--agent-source-commit', default='HEAD')
    parser.add_argument('--cases', nargs='+')
    parser.add_argument('--modes', nargs='+', choices=MODES)
    args = parser.parse_args()
    require(re.fullmatch(r'[A-Za-z0-9-]{3,16}', args.tag), 'Invalid unique tag')
    for value in (args.driver_label, args.agent_label):
        require(re.fullmatch(r'[A-Za-z0-9_-]{3,60}', value), 'Invalid build label')
    require(re.fullmatch(r'[0-9A-Fa-f]{64}', args.policy_sha), 'Invalid original policy hash')
    # Baseline helper has this default; wrapper calls it with no arguments.
    require(args.policy_sha.upper() == '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731', 'Wrapper baseline currently pins the recorded original policy')
    head = git('rev-parse', 'HEAD').decode().strip()
    commit = git('rev-parse', '--verify', args.source_commit + '^{commit}').decode().strip()
    agent_commit = git('rev-parse', '--verify', args.agent_source_commit + '^{commit}').decode().strip()
    rows = table_rows(SCRIPTS / 'StagedInvariantCases.psd1')
    cases = args.cases or list(rows)
    modes = args.modes or list(MODES)
    require(len(cases) == len(set(cases)) and set(cases) <= rows.keys() and len(modes) == len(set(modes)), 'Unknown/duplicate selection')
    files, package, tree_hash, provenance = build_inputs(args, commit, agent_commit, head)
    ev = ROOT / 'driver/evidence' / datetime.date.today().isoformat()
    ev.mkdir(parents=True, exist_ok=True)
    index = ev / ('phase4-suite-' + args.tag + '-index.txt')
    require(not index.exists(), 'Suite index collision')
    frozen = ev / ('phase4-suite-' + args.tag + '-inputs')
    frozen.mkdir()
    retained = {}
    for directory in [Path(value) for value in provenance['BuildEvidenceDirectories']] + [SCRIPTS]:
        target = frozen / directory.name
        target.mkdir()
        sources = (ROOT / relative for relative in provenance['Pins']) if directory == SCRIPTS else (p for p in directory.iterdir() if p.is_file())
        for source in sources:
            destination = target / source.name
            with source.open('rb') as inp, destination.open('xb') as out:
                shutil.copyfileobj(inp, out)
                out.flush();os.fsync(out.fileno())
            retained[str(destination)] = sha(destination)
    provenance['RetainedInputs'] = retained
    outcomes = []
    aborted = False
    # Append and fsync every outcome so interruption cannot erase failed mappings.
    write_new(index, 'Schema=StagedInvariantSuiteIndex/1\n' + json.dumps(provenance, sort_keys=True) + '\n')
    for case in cases:
        for mode in modes:
            if rows[case]['Status'] != 'Ready':
                print('CaseStatus=NOT_READY;CaseId=' + case + ';Mode=' + mode, flush=True)
                item = {'CaseId': case, 'Mode': mode, 'Verdict': 'NOT_READY', 'GatePassed': False}
            elif aborted:
                item = {'CaseId': case, 'Mode': mode, 'Verdict': 'INCONCLUSIVE', 'Reason': 'Prior lifecycle/restoration failure; not run', 'GatePassed': False}
            else:
                print('Running ' + case + ' / ' + mode, flush=True)
                try:
                    item = run_case(args, case, mode, ev, files, package, tree_hash, provenance)
                except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
                    aborted = True
                    failed_name = f'boot-start-invariant-{case}-{mode}-{args.tag}'
                    known_failure = (ev / (failed_name + '-final-restored-state.txt')).exists() and not clean_baseline(ev / (failed_name + '-final-restored-state.txt'))
                    item = {'CaseId': case, 'Mode': mode, 'RunName': failed_name, 'Verdict': 'FAIL' if known_failure else 'INCONCLUSIVE',
                            'Reason': str(error), 'GatePassed': False, 'RetainedFailurePrefix': str(ev / failed_name)}
            outcomes.append(item)
            with index.open('a') as stream:
                stream.write(json.dumps(item, sort_keys=True) + '\n');stream.flush();os.fsync(stream.fileno())
    complete = set(cases) == rows.keys() and set(modes) == set(MODES)
    selected_pass = bool(outcomes) and all(item['GatePassed'] for item in outcomes)
    phase4_pass = complete and selected_pass
    # WP3 seed-only rows and NotReady families intentionally make full qualification impossible.
    verdict = f'SelectedInvariantGate={"PASS" if selected_pass else "FAIL"}\nPhase4Suite={"PASS" if phase4_pass else "FAIL"}\nCompleteTableAndModes={complete}\n'
    with index.open('a') as stream:
        stream.write(verdict);stream.flush();os.fsync(stream.fileno())
    print(verdict, end='')
    return 0 if phase4_pass else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('Invariant qualification preflight failed: ' + str(error))
