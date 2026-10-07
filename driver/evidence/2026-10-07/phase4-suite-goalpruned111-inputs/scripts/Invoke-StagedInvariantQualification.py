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
    signer = signed.get('signer', '')
    require(signed.get('exit') == '0' and re.fullmatch(r'[A-F0-9]{40}', signer) and signed.get('signed_sha256') == sha(feature)
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
                  'UnsignedSha256': sha(work / 'owned-feature.sys'), 'Signer': signer,
                  'SourceManifests': {str(work): sha(work / 'src.manifest'), str(agent_work): sha(agent_work / 'src.manifest')},
                  'ServiceTreeSha256': tree_hash, 'BuildSummarySha256': sha(work / 'summary.txt'),
                  'AgentSummarySha256': sha(agent_work / 'summary.txt'), 'WriterFixtureSha256': sha(work / 'writer-fixture.exe')}
    pins = {}
    for leaf in ('StagedInvariantCases.psd1', 'StagedInvariantObserver.psm1', 'Test-StagedInvariantSuite.ps1',
                 'Invoke-StagedInvariantQualification.py', 'StagedInvariantProofAdapters.SelfCheck.ps1', 'test_staged_invariant_proof_adapters.py', 'test_staged_a04_gate.py', 'StagedInvariantActivationDuplicate.SelfCheck.ps1', 'StagedTestAgent.ps1', 'Invoke-DebuggeeExperiment.sh', 'Get-StagedBaseline.ps1', 'remote_ps.py'):
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
            "$null=$p.Handle;if(-not $p.WaitForExit(1500000)){throw 'Suite child timeout'};$p.WaitForExit();"
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
        activating_case = result.get('CaseId') in ('A01', 'A02', 'A03', 'A04')
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


def validate_raw_artifacts(destination, guest_root, required=('raw',)):
    # C05 has a second observer for its external physical source. Each module
    # writes its own manifest; pin both, including failed/partial captures.
    for leaf in ('raw', 'raw-external'):
        manifest = destination / leaf / 'manifest.ndjson'
        if not manifest.exists():
            require(leaf not in required, 'Required raw evidence manifest missing: ' + leaf)
            continue
        lines = manifest.read_text('utf-8-sig').splitlines()
        require(bool(lines), 'Raw evidence manifest empty: ' + leaf)
        for line in lines:
            entry = json.loads(line)
            require(entry['Path'].startswith(guest_root), 'Raw artifact outside owned evidence root')
            relative = entry['Path'][len(guest_root):].replace('\\', '/')
            require('..' not in relative.split('/') and not relative.startswith('/'), 'Invalid artifact path')
            artifact = destination / relative
            require(artifact.stat().st_size == entry['Length'] and sha(artifact) == entry['Sha256'],
                    'Copied raw artifact hash/length mismatch')


def validate_service_artifacts(result, destination, guest_root):
    for trial in result.get('Trials', []):
        for snapshot in [trial.get('ServiceBefore') or {}, trial.get('ServiceAfter') or {},
                         *trial.get('JournalSnapshots', []), {'Journal': (trial.get('HandBack') or {}).get('Files', [])},
                         {'Journal': [(trial.get('DuplicateSetup') or {})['PhysicalObjectArtifact']]
                          if (trial.get('DuplicateSetup') or {}).get('PhysicalObjectArtifact') else []},
                         {'Journal': [r['Terminal']['Record'] for r in (trial.get('DedicatedLatency') or {}).get('Rounds', [])
                                      if r.get('Terminal') and r['Terminal'].get('Record')]}]:
            records = list(snapshot.get('Journal', [])) + list((snapshot.get('Notifications') or {}).get('Artifacts', []))
            for record in records:
                path = record['Artifact']
                require(path.startswith(guest_root), 'Service evidence outside owned guest evidence root')
                relative = path[len(guest_root):].replace('\\', '/')
                require('..' not in relative.split('/') and not relative.startswith('/'), 'Invalid service artifact path')
                artifact = destination / relative
                require(artifact.stat().st_size == record['Length'] and sha(artifact) == record['Sha256'],
                        'Copied authenticated service evidence hash/length mismatch')
                if 'Bytes' in record:
                    require(isinstance(record['Bytes'], list) and all(type(b) is int and 0 <= b <= 255 for b in record['Bytes'])
                            and artifact.read_bytes() == bytes(record['Bytes']),
                            'Copied authenticated service artifact bytes differ from retained record')
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


ACTIVATION_REQUIRED_ASSERTIONS = {
    'RuntimePendingUnionAndAdmissionEpoch', 'ServiceReadinessPendingWhileHolderLives',
    'ExactActivatingWriterEvidence', 'NewWritableOpenDenied', 'NewWritableSectionDenied',
    'NewWritableSectionAdmissionCallback', 'NoObservedReadyWhileHolderLives',
    'OldHolderMutationAllowedAndRecorded', 'OldHolderStillActivatingAfterMutation',
    'OldHolderLowerCompletion', 'FreeAndProtectedAfterLastHolder', 'PromotionTraceForSameFileId',
    'ServiceReadinessReadyAfterPromotion', 'PostPromotionUnapprovedWriteRoutedToOwnedStream',
    'OwnedStreamJournalForExactDestination', 'PostPromotionRawDestinationUnchanged', 'Disposal',
    'ObserverCachedReaderClosedBeforeActorRelease', 'ObserverReaderReboundWithStableRawU',
}

A04_REQUIRED_ASSERTIONS = ACTIVATION_REQUIRED_ASSERTIONS | frozenset((
    'CrossProcessSameFileObject', 'ParentCloseKeepsSingleHAndActivating',
    'ChildMutationExactRawU', 'ChildLastCloseExactlyOneCleanup',
    'PromotionStableExactU', 'NoJournalAtChildMutationCheckpoints', 'NoHandBackAtChildMutationCheckpoints',
    'A04PublicationAndTemporalCoverage', 'NeverReadyWholeHolderInterval',
    'PostPromotionHeldOwnedWrite', 'HeldOwnedSaveNoApproval', 'ApprovedFinalRawImageA',
))


def activation_duplicate_provenance(result):
    """Bind both actual OS processes and every native duplicate position receipt."""
    try:
        trial = result['Trials'][0]
        primary, child, setup = trial['Actor'], trial['DuplicateActor'], trial['DuplicateSetup']
        boot = result['BootIds']['Active']
        for actor in (primary, child):
            if (type(actor['Pid']) is not int or actor['Pid'] <= 0
                    or type(actor['SessionId']) is not int or actor['SessionId'] < 0
                    or actor['OwnerSid'] != actor['Sid'] or actor['Elevated'] is not False
                    or actor['IsAdministrator'] is not False):
                return False
        if not primary['CommandLine'].endswith('\\writer.ps1"'):
            return False
        if (primary['Pid'] == child['Pid'] or primary['Sid'] != child['Sid']
                or primary['SessionId'] != child['SessionId'] or primary['BootId'] != boot
                or child['BootId'] != boot or child['OwnerSid'] != child['Sid']
                or child['Elevated'] is not False or child['IsAdministrator'] is not False
                or not re.fullmatch(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+', child['Sid'])
                or not child['CommandLine'].endswith('\\duplicate-writer.ps1"')
                or setup['SameFileObject'] is not True):
            return False
        receipts = [(setup['Duplicate'], primary), (setup['Adopt'], child),
                    (setup['ParentPosition'], primary), (setup['ChildQuery'], child),
                    (setup['ChildPosition'], child), (setup['ParentQuery'], primary)]
        previous = 0
        frequency = setup['Duplicate']['QpcFrequency']
        if type(frequency) is not int or frequency <= 0:
            return False
        for receipt, actor in receipts:
            if (type(receipt['Pid']) is not int or receipt['Pid'] != actor['Pid'] or receipt['BootId'] != boot
                    or type(receipt['QpcFrequency']) is not int or receipt['QpcFrequency'] != frequency
                    or type(receipt['NativeCode']) is not int or receipt['NativeCode'] != 0
                    or type(receipt['StartQpc']) is not int or type(receipt['EndQpc']) is not int
                    or not previous <= receipt['StartQpc'] <= receipt['EndQpc']):
                return False
            previous = receipt['EndQpc']
        physical = setup['PhysicalObjectProof']
        artifact = setup['PhysicalObjectArtifact']
        if (artifact['Entry'] != physical or type(artifact['Length']) is not int or artifact['Length'] <= 0
                or not re.fullmatch(r'[A-F0-9]{64}', artifact['Sha256'])
                or not artifact['Artifact'].endswith('activation-trusted-physical-object.json')):
            return False
        if (physical['Status'] != 'OK' or physical['CollectedBySid'] != 'S-1-5-18'
                or type(physical['CollectedByPid']) is not int or physical['CollectedByPid'] <= 0
                or physical['CollectedByPid'] in (primary['Pid'], child['Pid'])
                or physical['Source'] != 'NtQuerySystemInformation/SystemExtendedHandleInformation'
                or physical['BootId'] != boot or physical['QpcFrequency'] != frequency
                or type(physical['StartQpc']) is not int or type(physical['EndQpc']) is not int
                or not previous <= physical['StartQpc'] <= physical['EndQpc']
                or physical['PrimaryPid'] != primary['Pid'] or physical['ChildPid'] != child['Pid']
                or physical['SourceHandle'] != setup['Duplicate']['SourceHandle']
                or physical['RemoteHandle'] != setup['Duplicate']['RemoteHandle']
                or not re.fullmatch(r'0x[0-9A-Fa-f]{16}', physical['Object'])
                or physical['Object'] == '0x0000000000000000'
                or type(physical['ObjectTypeIndex']) is not int or physical['ObjectTypeIndex'] <= 0
                or type(physical['InventoryCount']) is not int or physical['InventoryCount'] < 2):
            return False
        return (type(setup['Duplicate']['TargetPid']) is int
                and type(setup['Duplicate']['SourceHandle']) is int
                and type(setup['Duplicate']['RemoteHandle']) is int
                and type(setup['Adopt']['RemoteHandle']) is int
                and setup['Duplicate']['TargetPid'] == child['Pid']
                and setup['Duplicate']['SourceHandle'] > 0
                and setup['Duplicate']['RemoteHandle'] > 0
                and setup['Duplicate']['RemoteHandle'] == setup['Adopt']['RemoteHandle']
                and setup['ParentPosition']['Position'] == setup['ChildQuery']['Position'] == 317
                and setup['ChildPosition']['Position'] == setup['ParentQuery']['Position'] == 619)
    except (KeyError, TypeError, ValueError, IndexError):
        return False


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
    if case in ('A01', 'A02', 'A03', 'A04'):
        required = A04_REQUIRED_ASSERTIONS if case == 'A04' else ACTIVATION_REQUIRED_ASSERTIONS
        passed = (result.get('Verdict') == 'PASS' and result.get('CaseStatus') == 'READY'
                  and result.get('ForbiddenByteCount') == 0)
        for trial in result['Trials']:
            assertions = trial.get('Assertions', [])
            names = {item.get('Name') for item in assertions}
            passed &= (trial.get('Verdict') == 'PASS' and trial.get('ForbiddenByteCount') == 0
                       and trial.get('Disposal', {}).get('Status') == 'OK' and not trial.get('Errors')
                       and required <= names and bool(assertions)
                       and all(item.get('Verdict') == 'PASS' for item in assertions))
        if case == 'A04':
            passed &= activation_duplicate_provenance(result)
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


MVP_DEFERRED_EXACT = frozenset((
    'PredicateCoverage', 'NoUnapprovedByte', 'CadenceCoverage', 'CadenceGap',
    'ExternalCoverage', 'NeverReadyWholeHolderInterval',
))
MVP_BUILD_HASHES = ('Feature', 'Inspector', 'ServicePackage', 'ServiceTree')
DEDICATED_LATENCY_CASES = frozenset(('C01-approve-absent', 'C02-approve-absent',
                                  'C03-approve-existing', 'C04-approve', 'C05-denied-external-rename'))


def dedicated_latency_selection_valid(cases, modes, diagnostic_seconds=0, latency_evidence=None):
    return (len(cases) == 1 and set(cases) <= DEDICATED_LATENCY_CASES and len(modes) == 1
            and not diagnostic_seconds and not latency_evidence)


def mvp_write_path(case):
    return {'C01': 'cached-write', 'C02': 'mapped-write', 'C03': 'overwrite',
            'C04': 'replacement-save', 'C05': 'external-rename'}.get(case[:3], case)


def mvp_latency_passed(evidence, result, classes):
    """Recompute dedicated unheld samples; a reported verdict alone is insufficient."""
    if not evidence or evidence.get('Schema') != 'StagedInvariantLatency/1':
        return False
    if (evidence.get('WritePath') != mvp_write_path(result.get('CaseId', ''))
            or evidence.get('Mode') != result.get('Mode')
            or evidence.get('RestorationClean') is not True
            or evidence.get('LiveTaintFlagsPassed') is not True
            or evidence.get('Errors') or not evidence.get('RunName')):
        return False
    if any(not re.fullmatch(r'[A-F0-9]{64}', result.get('InputHashes', {}).get(k, ''))
           or evidence.get('InputHashes', {}).get(k) != result['InputHashes'][k]
           for k in MVP_BUILD_HASHES):
        return False
    records = evidence.get('Latency', [])
    if not classes or len(records) != len(classes) or {c.get('Class') for c in records} != set(classes):
        return False
    for record in records:
        samples = record.get('Samples', [])
        if not samples or record.get('Verdict') != 'PASS':
            return False
        if any(s.get('Held') is not False or type(s.get('Cold')) is not bool
               or type(s.get('Ms')) not in (int, float)
               or not math.isfinite(s['Ms']) or s['Ms'] < 0 for s in samples):
            return False
        warm = sorted(s['Ms'] for s in samples if not s['Cold'])
        if (len(warm) < 100 or not any(s['Cold'] for s in samples)
                or warm[math.ceil(.95 * len(warm)) - 1] > 250
                or max(s['Ms'] for s in samples) > 1000):
            return False
    return True


def retain_partial_latency_samples(result):
    """Retain independently timed attempts even when whole-round proof fails.

    These are partial diagnostics, not accepted latency qualification. Full
    image/terminal/lifecycle proof remains mandatory in export_dedicated_latency.
    """
    trials = result.get('Trials') or []
    if len(trials) != 1:
        return []
    trial = trials[0]
    observation = trial.get('DedicatedLatency') or {}
    actor = trial.get('Actor') or {}
    frequency = observation.get('QpcFrequency')
    if type(frequency) is not int or frequency <= 0:
        return []
    collected = {}
    for round_record in observation.get('Rounds', []):
        receipt = round_record.get('Receipt') or {}
        number = round_record.get('Trial')
        if (type(number) is not int or not 0 <= number <= 100
                or receipt.get('Trial') != number or receipt.get('Held') is not False
                or receipt.get('Pid') != actor.get('Pid') or receipt.get('Sid') != actor.get('Sid')
                or receipt.get('BootId') != actor.get('BootId')):
            continue
        for call in receipt.get('Calls', []):
            start, end = call.get('StartQpc'), call.get('EndQpc')
            if (type(start) is not int or type(end) is not int or not 0 <= start <= end
                    or type(call.get('NativeCode')) is not int or call.get('Trial') != number
                    or type(call.get('Cold')) is not bool or call['Cold'] != (number == 0)
                    or not isinstance(call.get('Class'), str)):
                continue
            collected.setdefault(call['Class'], []).append(dict(Trial=number, Cold=number == 0,
                Held=False, NativeCode=call['NativeCode'], StartQpc=start, EndQpc=end,
                Ms=1000.0 * (end - start) / frequency))
    records = []
    for name, samples in collected.items():
        warm = sorted(s['Ms'] for s in samples if not s['Cold'])
        p95 = warm[math.ceil(.95 * len(warm)) - 1] if len(warm) >= 100 else None
        maximum = max(s['Ms'] for s in samples)
        expected_code = 5 if result.get('CaseId') == 'C05-denied-external-rename' and name == 'rename-ex' else 0
        failed = any(s['NativeCode'] != expected_code for s in samples) or maximum > 1000 or (p95 is not None and p95 > 250)
        records.append(dict(Class=name, Samples=samples, UnheldCount=len(warm), P95Ms=p95,
                            MaxMs=maximum, Verdict='FAIL' if failed else 'INCONCLUSIVE'))
    return records


def export_dedicated_latency(result):
    """After artifact verification and independent restoration, recompute receipts.

    Functional case failure/coverage remains separate; this export cannot make
    DedicatedLatencyOnly qualify. Native or product failure prevents acceptance.
    """
    classes = {
        'C01-approve-absent': ['writer-open', 'cached-write', 'flush', 'close'],
        'C02-approve-absent': ['writer-open', 'create-mapping', 'map-view', 'close-source',
                              'mapped-store', 'flush-view', 'unmap-view', 'close-section'],
        'C03-approve-existing': ['writer-open', 'cached-write', 'flush', 'close'],
        'C04-approve': ['writer-open', 'cached-write', 'flush', 'rename-ex', 'close'],
        'C05-denied-external-rename': ['writer-open', 'rename-ex', 'close'],
    }
    evidence = dict(Schema='StagedInvariantLatency/1', RunName=result.get('RunName'),
                    WritePath=mvp_write_path(result.get('CaseId', '')), Mode=result.get('Mode'),
                    InputHashes=result.get('InputHashes', {}), Latency=[], Errors=[],
                    RestorationClean=result.get('Restoration', {}).get('Known') is True,
                    SourceCaseSha256=None, Verdict='INCONCLUSIVE')
    evidence['Latency'] = retain_partial_latency_samples(result)
    evidence['ObservedRounds'] = ((result.get('Trials') or [{}])[0].get('DedicatedLatency') or {}).get('Rounds', [])
    if any(r['Verdict'] == 'FAIL' for r in evidence['Latency']):
        evidence['Verdict'] = 'FAIL'
    try:
        require(result.get('AuthoritativeCaseExport') is True and evidence['RestorationClean']
                and result['Restoration'].get('GuestChecks') is True
                and result.get('Verdict') in ('INCONCLUSIVE', 'FAIL') and len(result['Trials']) == 1,
                'Dedicated authoritative lifecycle is incomplete or failed')
        trial = result['Trials'][0]
        expected = classes[result['CaseId']]
        observation = trial['DedicatedLatency']
        actor, platform, provenance = trial['Actor'], trial['Platform'], trial['ActorProvenance']
        require(not trial.get('Errors') and trial.get('Disposal', {}).get('Status') == 'OK'
                and observation.get('Complete') is True and observation.get('Held') is False
                and len(observation['Rounds']) == 101
                and platform['Build'] == '19045.2965'
                and actor['BootId'] == result['BootIds']['Active'] == platform['BootId']
                and actor['Elevated'] is False and actor['IsAdministrator'] is False
                and actor['Pid'] == provenance['Pid'] and actor['Sid'] == provenance['OwnerSid']
                and actor['SessionId'] == provenance['SessionId']
                and any(a.get('Name') == 'DedicatedLatencyOnly' and a.get('Verdict') == 'INCONCLUSIVE'
                        for a in trial['Assertions']), 'Dedicated rounds/platform/provenance/disposal incomplete')
        require(not any(a.get('Verdict') == 'FAIL' for a in trial['Assertions']), 'Dedicated assertion failure')
        taint = [a for a in trial['Assertions'] if a.get('Name') == 'LiveTaintFlags']
        require(len(taint) == 1 and taint[0].get('Verdict') == 'PASS',
                'Dedicated live taint disable proof missing, ambiguous or not PASS')
        evidence['LiveTaintFlagsPassed'] = True
        digest = observation['Digest']
        require(re.fullmatch(r'[A-F0-9]{64}', digest) and observation['Length'] > 0
                and trial['ImageA']['Sha256'] == digest and trial['ImageA']['Length'] == observation['Length'],
                'Dedicated independent image pin mismatch')
        frequency = observation['QpcFrequency']
        require(type(frequency) is int and frequency > 0, 'Dedicated QPC frequency missing')
        samples = {name: [] for name in expected}
        previous, transfer_ids, targets, open_paths = 0, set(), set(), set()
        all_calls = []
        for number, round_record in enumerate(observation['Rounds']):
            receipt, private, terminal = (round_record[k] for k in ('Receipt', 'PrivateReceipt', 'Terminal'))
            require(type(round_record['Trial']) is int and round_record['Trial'] == number
                    and receipt['Trial'] == number and receipt['Held'] is False,
                    'Dedicated round ordering or held receipt mismatch')
            for record in (receipt, private):
                require(record['Pid'] == actor['Pid'] and record['Sid'] == actor['Sid']
                        and record['BootId'] == actor['BootId'] and record['PrivateSha256'] == digest
                        and re.fullmatch(r'[a-f0-9]{32}', record['Token']), 'Dedicated actor/image receipt mismatch')
            require(receipt['Token'] == private['Token'], 'Dedicated round token mismatch')
            if number == 0:
                token = receipt['Token']
            require(receipt['Token'] == token, 'Dedicated actor token changed')
            calls = receipt['Calls']
            require([c['Class'] for c in calls] == expected, 'Dedicated native call sequence mismatch')
            for call in calls:
                expected_code = 5 if result['CaseId'] == 'C05-denied-external-rename' and call['Class'] == 'rename-ex' else 0
                require(type(call['Trial']) is int and call['Trial'] == number
                        and type(call['Cold']) is bool and call['Cold'] == (number == 0)
                        and type(call['NativeCode']) is int and call['NativeCode'] == expected_code
                        and type(call['StartQpc']) is int and type(call['EndQpc']) is int
                        and previous <= call['StartQpc'] <= call['EndQpc'] <= receipt['Qpc'],
                        'Dedicated native status/timing/repetition mismatch')
                previous = call['EndQpc']
                samples[call['Class']].append(dict(Trial=number, Cold=number == 0, Held=False,
                        NativeCode=expected_code, StartQpc=call['StartQpc'], EndQpc=call['EndQpc'],
                        Ms=1000.0 * (call['EndQpc'] - call['StartQpc']) / frequency))
            all_calls.extend(calls)
            if result['CaseId'] == 'C02-approve-absent':
                require(private.get('SourceClosed') is True and private.get('ViewLive') is True
                        and private.get('SectionLive') is True, 'Dedicated mapped lifetime incomplete')
            if result['CaseId'] == 'C05-denied-external-rename':
                proof = round_record['JournalProof']
                destination, source = round_record['DestinationSample'], round_record['SourceSample']
                checks = round_record['SampleAssertions']
                require(terminal is None and round_record['ValidationStatus'] == 'Complete'
                        and round_record['Snapshot']['Status'] == 'OK'
                        and proof['Complete'] is True and not proof['NewEntries'] and not proof['Findings']
                        and checks and all(a.get('Verdict') == 'PASS' for a in checks)
                        and all(s.get('Status') == 'OK' and s['Start']['BootId'] == actor['BootId']
                                and s['End']['BootId'] == actor['BootId']
                                and s['Start']['QpcFrequency'] == frequency == s['End']['QpcFrequency']
                                and previous <= s['Start']['Qpc'] <= s['End']['Qpc'] <= round_record['ObservationVerifiedQpc']
                                for s in (destination, source)),
                        'Dedicated denied rename raw/source/private-transfer proof incomplete or contradicted')
                for sample, path, absent in ((destination, receipt['Target'], True),
                                             (source, receipt['OpenPath'], False)):
                    require(sample.get('Captures') and all(
                        any(i.get('Role') == 'Current' and i.get('Path') == path
                            and i.get('Absent', False) is absent for i in capture.get('Images', []))
                        and any(i.get('Role') == 'Parent' for i in capture.get('Images', []))
                        for capture in sample['Captures']),
                        'Dedicated denied rename raw target/source/parent captures missing')
                require(receipt['OpenPath'] != receipt['Target']
                        and receipt['Calls'][0]['StartQpc'] >= round_record['NativeNotBeforeQpc']
                        and round_record['ObservationVerifiedQpc'] <= round_record['IoCompletedQpc']
                        and (not targets or receipt['Target'] in targets)
                        and (not open_paths or receipt['OpenPath'] in open_paths),
                        'Dedicated denied rename paths/barrier ordering changed')
                targets.add(receipt['Target']); open_paths.add(receipt['OpenPath'])
                previous = round_record['IoCompletedQpc']
                continue
            transfer = json.loads(bytes(terminal['Record']['Bytes']).decode('utf-8-sig'))
            require(terminal['StateName'] == 'Released' and terminal['Sha256Hex'] == digest
                    and terminal['SealedOnce'] is True
                    and terminal['History'] == ['Allocated', 'Sealed', 'Inspecting', 'Approved', 'Publishing', 'Released']
                    and transfer['State'] == 5 and transfer['SealedOnce'] is True and transfer['Sha256Hex'] == digest
                    and transfer['Transfer']['ProcessId'] == actor['Pid']
                    and transfer['Transfer']['SessionId'] == actor['SessionId']
                    and transfer['Transfer']['RequestorSid'] == actor['Sid']
                    and [h['State'] for h in transfer['StateHistory']] == list(range(6))
                    and transfer['Transfer']['TransferId'] == terminal['TransferId']
                    and terminal['TransferId'] not in transfer_ids
                    and previous <= terminal['StartQpc'] <= terminal['EndQpc'] <= round_record['PublicationVerifiedQpc'],
                    'Dedicated Released transfer identity/image/history/timing mismatch')
            destinations = {transfer['Transfer'].get('DestinationPath'), transfer.get('LastRenameDestination')}
            require(receipt['Target'] in destinations, 'Dedicated transfer destination mismatch')
            transfer_ids.add(terminal['TransferId'])
            target, open_path = receipt['Target'], receipt['OpenPath']
            if result['CaseId'].startswith(('C01-', 'C02-')):
                require(target not in targets and open_path == target, 'Dedicated absent path reused')
            else:
                require(not targets or target in targets, 'Dedicated existing destination changed')
            if result['CaseId'] == 'C04-approve':
                require(open_path != target and open_path not in open_paths, 'Dedicated replacement temp reused')
            targets.add(target); open_paths.add(open_path)
            previous = round_record['PublicationVerifiedQpc']
        require(all_calls == trial['Operations'], 'Dedicated aggregate calls differ from receipts')
        evidence['Latency'] = []
        for name in expected:
            values = samples[name]
            warm = sorted(s['Ms'] for s in values if not s['Cold'])
            p95, maximum = warm[math.ceil(.95 * len(warm)) - 1], max(s['Ms'] for s in values)
            evidence['Latency'].append(dict(Class=name, Verdict='PASS' if p95 <= 250 and maximum <= 1000 else 'FAIL',
                                           UnheldCount=len(warm), P95Ms=p95, MaxMs=maximum, Samples=values))
        evidence['Verdict'] = 'PASS' if mvp_latency_passed(evidence, result, expected) else 'FAIL'
    except (RuntimeError, KeyError, TypeError, ValueError, IndexError) as error:
        evidence['Errors'].append(str(error))
    return evidence


def mvp_seed_latency_passed(result, trial):
    """Only the seed actors already perform 101 native unheld repetitions."""
    expected = {'S00-observer-control': ('writer-open', 'cached-write', 'flush', 'close'),
                'S01-denied-write-after-boot': ('writer-open-deny',),
                'S02-agent-down-open-refused': ('writer-open-deny',)}
    try:
        classes = expected[result['CaseId']]
        fence = trial['WriterFence']
        frequency = fence['QpcFrequency']
        if (fence['Complete'] is not True or fence['BootId'] != result['BootIds']['Active']
                or type(frequency) is not int or frequency <= 0
                or type(fence['ExpectedAttempts']) is not int or fence['ExpectedAttempts'] != 101
                or trial['Repetitions']['Unheld'] != 100 or trial.get('HeldReceipt')
                or trial.get('DedicatedLatencyOnly') or trial.get('CloseBarrierQpc')):
            return False
        operations = trial['Operations']
        if len(operations) != 101 * len(classes):
            return False
        expected_code = 0 if len(classes) == 4 else 5
        previous = fence['ReleasedQpc']
        if type(previous) is not int or previous < 0 or type(fence['CompletedQpc']) is not int:
            return False
        grouped = {name: [] for name in classes}
        for index, call in enumerate(operations):
            n, name = divmod(index, len(classes))
            name = classes[name]
            if (call['Class'] != name or type(call['Trial']) is not int or call['Trial'] != n
                    or call['Cold'] is not (n == 0) or call.get('Held', False) is not False
                    or type(call['NativeCode']) is not int or call['NativeCode'] != expected_code
                    or type(call['StartQpc']) is not int or type(call['EndQpc']) is not int
                    or not previous <= call['StartQpc'] <= call['EndQpc'] <= fence['CompletedQpc']):
                return False
            grouped[name].append(call)
            previous = call['EndQpc']
        latency = trial['Latency']
        if len(latency) != len(classes) or [item['Class'] for item in latency] != list(classes):
            return False
        for item in latency:
            calls = grouped[item['Class']]
            if item['Verdict'] != 'PASS' or item['UnheldCount'] != 100 or len(item['Samples']) != 101:
                return False
            times = []
            for call, sample in zip(calls, item['Samples']):
                if any(sample[key] != call[key] or type(sample[key]) is not type(call[key])
                       for key in ('Trial', 'Cold', 'NativeCode', 'StartQpc', 'EndQpc')):
                    return False
                ms = 1000 * (call['EndQpc'] - call['StartQpc']) / frequency
                if (type(sample['Ms']) not in (int, float) or not math.isfinite(sample['Ms'])
                        or not math.isclose(sample['Ms'], ms, abs_tol=0.000001)):
                    return False
                times.append(ms)
            p95, maximum = sorted(times[1:])[94], max(times)
            if (p95 > 250 or maximum > 1000
                    or not math.isclose(item['P95Ms'], p95, abs_tol=0.000001)
                    or not math.isclose(item['MaxMs'], maximum, abs_tol=0.000001)):
                return False
        return True
    except (KeyError, TypeError, ValueError, IndexError):
        return False


def mvp_case_gate(result, latency_evidence=None):
    """Separate MVP assessment, after the existing identity/provenance/lifecycle gates."""
    deferred, blockers = set(), set()
    restoration = result.get('Restoration') or {}
    if (result.get('Schema') != 'StagedInvariantSuite/2'
            or result.get('AuthoritativeCaseExport') is not True
            or result.get('CaseStatus') != 'READY'
            or result.get('Verdict') not in ('PASS', 'INCONCLUSIVE')
            or type(result.get('ForbiddenByteCount')) is not int
            or result['ForbiddenByteCount'] != 0 or result.get('Errors')):
        blockers.add('CasePrerequisites')
    if (restoration.get('Known') is not True or restoration.get('GuestChecks') is not True
            or not restoration.get('IndependentBaseline')
            or not re.fullmatch(r'[A-F0-9]{64}', restoration.get('IndependentBaselineSha256', ''))):
        blockers.add('RestorationClean')
    trials = result.get('Trials', [])
    if len(trials) != 1:
        blockers.add('Trials')
    for trial in trials:
        if (trial.get('Verdict') not in ('PASS', 'INCONCLUSIVE')
                or type(trial.get('ForbiddenByteCount')) is not int
                or trial['ForbiddenByteCount'] != 0
                or trial.get('Disposal', {}).get('Status') != 'OK' or trial.get('Errors')):
            blockers.add('TrialPrerequisites')
        predicate = trial.get('Predicate') or {}
        if predicate.get('Verdict', 'PASS') not in ('PASS', 'INCONCLUSIVE') or predicate.get('Errors'):
            blockers.add('PredicatePrerequisites')
        assertions = trial.get('Assertions', [])
        if not assertions:
            blockers.add('Assertions')
        taint = [a for a in assertions if a.get('Name') == 'LiveTaintFlags']
        if len(taint) != 1 or taint[0].get('Verdict') != 'PASS':
            blockers.add('LiveTaintFlags')
        if result.get('CaseId') in ('A01', 'A02', 'A03', 'A04'):
            required = A04_REQUIRED_ASSERTIONS if result['CaseId'] == 'A04' else ACTIVATION_REQUIRED_ASSERTIONS
            missing = required - {a.get('Name') for a in assertions}
            blockers.update('Missing:' + name for name in missing)
            if result['CaseId'] == 'A04' and not activation_duplicate_provenance(result):
                blockers.add('DuplicateActorProvenance')
        assertions = assertions + predicate.get('Assertions', [])
        classes = [c.get('Class') for c in trial.get('Latency', [])]
        latency_ok = (mvp_seed_latency_passed(result, trial)
                      or mvp_latency_passed(latency_evidence, result, classes))
        for assertion in assertions:
            name, verdict = assertion.get('Name', ''), assertion.get('Verdict')
            if verdict == 'PASS':
                continue
            allowed = (name in MVP_DEFERRED_EXACT or
                       bool(name[:-len('PublicationAndTemporalCoverage')]) and name.endswith('PublicationAndTemporalCoverage') or
                       # The product emits no creation receipt; B01 (junction-swapped hand-back folder, same MVP
                       # suite) proves safe relative creation by behavior. Owner decision pending (2026-10-07).
                       bool(name[:-len('HandBackSafeRelativeCreation')]) and name.endswith('HandBackSafeRelativeCreation') or
                       bool(name[:-len('UnheldLatency')]) and name.endswith('UnheldLatency') and latency_ok)
            if verdict == 'INCONCLUSIVE' and allowed:
                deferred.add(name)
            else:
                blockers.add(name or 'UnnamedAssertion')
        for item in trial.get('Latency', []):
            if item.get('Verdict') == 'FAIL':
                blockers.add('Latency:' + str(item.get('Class')))
            elif item.get('Verdict') != 'PASS' and not latency_ok:
                blockers.add('Latency:' + str(item.get('Class')))
        if classes and not latency_ok:
            # Held C-path functional samples cannot replace dedicated write-path runs.
            blockers.add('DedicatedUnheldLatency')
    def failures(value):
        if isinstance(value, dict):
            if value.get('Verdict') == 'FAIL' or value.get('Errors'):
                return True
            return any(failures(v) for v in value.values())
        return isinstance(value, list) and any(failures(v) for v in value)
    if failures(result):
        blockers.add('FailureOrErrorsInEvidence')
    return {'MvpGatePassed': not blockers, 'MvpDeferred': sorted(deferred),
            'MvpBlockers': sorted(blockers)}


def mvp_required_rows(rows):
    required = {'S00-observer-control', 'S01-denied-write-after-boot', 'S02-agent-down-open-refused',
                *('A%02d' % n for n in range(1, 6)), 'B01', 'B02', 'R01', 'R02', 'R03', 'X01'}
    for family in ('C01', 'C02', 'C03', 'C04', 'C05'):
        variants = {case for case in rows if case.startswith(family + '-')}
        required.update(variants or {family})
    return required


def mvp_suite_passed(outcomes, rows):
    expected = {(case, mode) for case in mvp_required_rows(rows) for mode in MODES}
    selected = [(item['CaseId'], item['Mode']) for item in outcomes]
    return (len(selected) == len(set(selected)) and expected <= set(selected)
            and all(item.get('MvpGatePassed') is True for item in outcomes
                    if (item['CaseId'], item['Mode']) in expected))



def run_case(args, case, mode, ev, files, package, tree_hash, provenance):
    name = f'boot-start-invariant-{case}-{mode}-{args.tag}'
    require(not list(ev.glob(name + '*')), 'Evidence collision: ' + name)
    params = {'CaseId': case, 'Mode': mode, 'RunName': name, 'ExpectedOriginalPolicySha256': args.policy_sha.upper(),
              'ExpectedServicePackageSha256': sha(package), 'ExpectedServiceTreeSha256': tree_hash,
              'ExpectedSignerThumbprint': provenance['Signer']}
    if args.dedicated_unheld_latency:
        params['DedicatedUnheldLatency'] = 1
    if args.mapped_stack_diagnostic_seconds:
        params['MappedStackDiagnosticSeconds'] = args.mapped_stack_diagnostic_seconds
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
        guest_root = 'C:\\Users\\vika\\Documents\\' + name + '-artifacts\\'
        required_raw = ('raw', 'raw-external') if case == 'C05-denied-external-rename' else ('raw',)
        validate_raw_artifacts(destination, guest_root, required_raw)
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
        assessment = mvp_case_gate(result, getattr(args, 'mvp_latency_record', None))
        result.update(assessment)
        write_new(provisional, json.dumps(result, indent=2) + '\n')
        if args.dedicated_unheld_latency:
            latency = export_dedicated_latency(result)
            latency['SourceCaseSha256'] = sha(provisional)
            latency['SourceCase'] = str(provisional)
            write_new(destination / 'dedicated-latency.json', json.dumps(latency, indent=2) + '\n')
        return {'CaseId': case, 'Mode': mode, 'RunName': name, 'Verdict': result['Verdict'], 'GatePassed': passed,
                **assessment, 'ForbiddenByteCount': result.get('ForbiddenByteCount'), 'RestorationClean': True, 'Result': str(provisional), 'ResultSha256': sha(provisional)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for value in ('tag', 'driver_label', 'source_commit', 'agent_label', 'policy_sha'):
        parser.add_argument(value)
    parser.add_argument('--agent-source-commit', default='HEAD')
    parser.add_argument('--mvp-latency-evidence', type=Path, help='Dedicated unheld latency JSON; pinned with this run')
    parser.add_argument('--dedicated-unheld-latency', action='store_true',
                        help='Separate 101-round APPROVE C01-C04 or denied C05 latency evidence; cannot qualify a functional case')
    parser.add_argument('--mapped-stack-diagnostic-seconds', type=int, choices=(0, 600), default=0,
                        help='C02 runtime-Verifier only: keep native actor alive for stack capture; never qualifies')
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
    require(not args.mapped_stack_diagnostic_seconds or
            (set(cases) <= {'C02-approve-absent', 'C02-block-absent'} and modes == ['runtime-verifier']),
            'Mapped stack diagnostic requires only C02 cases in runtime-Verifier mode')
    require(not args.dedicated_unheld_latency or
            dedicated_latency_selection_valid(cases, modes, args.mapped_stack_diagnostic_seconds, args.mvp_latency_evidence),
            'Dedicated latency requires one APPROVE C01-C04 or denied C05 case/mode without diagnostic/evidence options')
    files, package, tree_hash, provenance = build_inputs(args, commit, agent_commit, head)
    args.mvp_latency_record = None
    if args.mvp_latency_evidence:
        args.mvp_latency_record = json.loads(args.mvp_latency_evidence.read_text('utf-8-sig'))
        provenance['MvpLatencyEvidence'] = {'Path': str(args.mvp_latency_evidence.resolve()), 'Sha256': sha(args.mvp_latency_evidence)}
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
    if args.mvp_latency_evidence:
        latency_copy = frozen / 'mvp-latency-evidence.json'
        write_new(latency_copy, json.dumps(args.mvp_latency_record, indent=2) + '\n')
        retained[str(latency_copy)] = sha(latency_copy)
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
            item.setdefault('MvpGatePassed', False)
            item.setdefault('MvpDeferred', [])
            outcomes.append(item)
            with index.open('a') as stream:
                stream.write(json.dumps(item, sort_keys=True) + '\n');stream.flush();os.fsync(stream.fileno())
    complete = set(cases) == rows.keys() and set(modes) == set(MODES)
    selected_pass = bool(outcomes) and all(item['GatePassed'] for item in outcomes)
    phase4_pass = complete and selected_pass
    # WP3 seed-only rows and NotReady families intentionally make full qualification impossible.
    verdict = f'SelectedInvariantGate={"PASS" if selected_pass else "FAIL"}\nPhase4Suite={"PASS" if phase4_pass else "FAIL"}\nCompleteTableAndModes={complete}\n'
    verdict += ('SelectedMvpGate=' + ('PASS' if outcomes and all(i['MvpGatePassed'] for i in outcomes) else 'FAIL') + '\n'
                + 'MvpSuite=' + ('PASS' if mvp_suite_passed(outcomes, rows) else 'FAIL') + '\n')
    with index.open('a') as stream:
        stream.write(verdict);stream.flush();os.fsync(stream.fileno())
    print(verdict, end='')
    return 0 if phase4_pass else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('Invariant qualification preflight failed: ' + str(error))
