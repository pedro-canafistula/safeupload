#!/usr/bin/env python3
"""Freeze reviewed worktree inputs, build on the pinned builder, retain evidence.

Never stages/commits Git changes or installs the agent. --prepare-only performs
no network operation. A fresh label is required after any failed capture/build.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    'agent_snapshot', Path(__file__).with_name('Prepare-ExactAgentWorktreeSource.py'))
agent_snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_snapshot)
SSH = ['-F', '/dev/null', '-i', '/home/victor/.ssh/id_ed25519',
       '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'LogLevel=ERROR',
       '-o', 'StrictHostKeyChecking=yes']
HOST = '192.168.122.210'
REMOTE = 'vika@' + HOST + ':C:/Users/vika/Documents/'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_matrix_outputs(out, summary):
    """Validate actual logs, test discovery/counters, and package hashes."""
    tests = {}
    for mode in ('normal', 'feature'):
        for configuration in ('debug', 'release'):
            name = mode + '-' + configuration
            for action in ('build', 'tests'):
                if name + '-' + action + ': exit=0 warnings=0 errors=0' not in summary.splitlines():
                    raise RuntimeError('Nonzero/incomplete gate: ' + name + '-' + action)
            counters = ET.parse(out / (name + '-results/agent-tests.trx')).find(
                './/{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}Counters')
            if counters is None:
                raise RuntimeError('Missing test counters: ' + name)
            c = counters.attrib
            total = int(c['total'])
            if total <= 0 or int(c['passed']) != total or int(c['executed']) != total or any(
                    int(c.get(k, '0')) for k in ('failed', 'error', 'timeout', 'aborted', 'notExecuted', 'inconclusive')):
                raise RuntimeError('Incomplete/unsuccessful test counters: ' + name)
            tests[name] = total
            ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
            discovered = {(method.attrib.get('className', ''), method.attrib.get('name', ''))
                          for method in ET.parse(out / (name + '-results/agent-tests.trx')).findall(
                              './/t:TestDefinitions/t:UnitTest/t:TestMethod', ns)}
            required = {('SafeUpload.Agent.Tests.AdmissionEvidenceEndpointTests',
                         'EvidenceTypesExistOnlyInFeatureBuilds')}
            if mode == 'feature':
                required |= {('SafeUpload.Agent.Tests.AdmissionEvidenceWireTests', method)
                             for method in (
                                 'Managed_status_mirrors_match_driver_sizes_and_offsets',
                                 'Input_allows_only_readonly_status_commands_and_bounded_start_indices',
                                 'Native_failure_keeps_hresult_and_never_exposes_zeroed_reply_buffer',
                                 'Diagnostic_sends_on_one_port_are_serialized',
                                 'Dispose_drains_an_inflight_diagnostic_send_and_rejects_later_sends')}
                required |= {('SafeUpload.Agent.Tests.AdmissionEvidenceEndpointTests', method)
                             for method in (
                                 'RequestParserRequiresExactBoundedCanonicalIdentity',
                                 'PipeAuthorizationRequiresSystemOrAdministratorTokenAndLocalPipePolicy',
                                 'CaptureStreamsStablePagedSnapshotAndRetriesStatusRetryWithoutReadinessClaim',
                                 'BackendGenerationDriftProducesIncompleteEvidenceAndStillNeverReady',
                                 'BindingDrainWaitsForAcceptedSendAndRejectsLaterCalls',
                                 'RawFrameKeepsActualBytesEvenWhenNativeCallFailed',
                                 'RunTargetTombstonesStayUntilBindingClearAndCapacityDoesNotEvictThem',
                                 'StableSnapshotWithAbsentTargetIsCapturedAndAllowsNextHook',
                                 'StableSnapshotWithAmbiguousTargetCarriesNoSelectedEntryFields',
                                 'NonzeroReservedFlagsInNonTargetActivatingEntryPreserveRawPageAndInvalidateCapture',
                                 'BackpressureDeadlineCancelsCaptureAndTerminalizesReservedHook')}
            if not required.issubset(discovered):
                raise RuntimeError('Required admission tests were not discovered: '
                                   + name + ' ' + repr(sorted(required - discovered)))
        if mode + '-release-publish: exit=0 warnings=0 errors=0' not in summary.splitlines():
            raise RuntimeError('Incomplete publish: ' + mode)
        package = out / (mode + '-release-service-publish.zip')
        if mode + '-release: package_sha256=' + sha(package).upper() not in summary.splitlines():
            raise RuntimeError('Package hash mismatch: ' + mode)
    return tests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('label')
    parser.add_argument('--reviewed-untracked', required=True, type=Path)
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch('[A-Za-z0-9._-]{3,60}', args.label):
        parser.error('invalid label')
    approved = json.loads(args.reviewed_untracked.read_text(encoding='utf-8'),
                          object_pairs_hook=agent_snapshot.unique_object)
    if (not isinstance(approved, dict) or any(
            not isinstance(n, str) or not isinstance(h, str)
            or not n.startswith('agente/') or not n.endswith('.cs')
            for n, h in approved.items())):
        parser.error('allowlist must map exact new agente/*.cs names to reviewed SHA-256')
    work = REPO / 'output' / 'exact-agent-matrix' / args.label
    provenance = agent_snapshot.snapshot.capture(
        REPO, work, roots=agent_snapshot.ROOTS, tools=agent_snapshot.TOOLS,
        reviewed_untracked=approved)
    evidence = REPO / 'driver' / 'evidence' / datetime.date.today().isoformat()
    evidence.mkdir(parents=True, exist_ok=True)
    prefix = 'exact-agent-matrix-' + args.label

    def retain(name, data):
        path = evidence / (prefix + '-' + name)
        if path.exists():
            raise FileExistsError('Evidence path already exists: ' + str(path))
        path.write_bytes(data)
        return path

    for name in ('source-provenance.json', 'src.manifest'):
        retain(name, (work / name).read_bytes())
    print('CAPTURED=' + str(work), flush=True)
    if args.prepare_only:
        print('PREPARED_ONLY; network operations=0', flush=True)
        return

    def remote(ps, name):
        result = subprocess.run(['python3', str(work / 'tools' / 'remote_ps.py'), HOST],
                                input=ps.encode('utf-8'), capture_output=True, cwd=REPO)
        retain(name + '.stdout.txt', result.stdout)
        retain(name + '.stderr.txt', result.stderr)
        return result.returncode

    preflight = """$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
   (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or
   -not @(Get-NetAdapter|Where-Object {$_.MacAddress -eq '52-54-00-63-87-7A'}).Count){throw 'Wrong builder; delivery refused.'}
Write-Output ('BUILDER_PREFLIGHT_MATCH UTC='+[DateTime]::UtcNow.ToString('o'))
"""
    for leaf in (prefix, prefix + '.zip', prefix + '.manifest',
                 'Build-ExactAgentMatrix-' + args.label + '.ps1'):
        preflight += "if(Test-Path -LiteralPath 'C:\\Users\\vika\\Documents\\" + leaf + "'){throw 'Remote build destination already exists.'}\n"
    if remote(preflight, 'builder-preflight') != 0:
        raise RuntimeError('Builder preflight failed before source delivery')
    pins = agent_snapshot.snapshot.verify(work, provenance, tools=agent_snapshot.TOOLS)
    archive_sha, manifest_sha = pins.split()
    tool = work / 'tools' / 'Build-ExactAgentMatrix.ps1'
    tool_sha = provenance['BuildToolsSHA256']['driver/scripts/Build-ExactAgentMatrix.ps1']
    for local, target in ((work / 'src.zip', prefix + '.zip'),
                          (work / 'src.manifest', prefix + '.manifest'),
                          (tool, 'Build-ExactAgentMatrix-' + args.label + '.ps1')):
        subprocess.run(['scp', *SSH, str(local), REMOTE + target], check=True)
    print('DELIVERED; builder identity and frozen input pins verified', flush=True)
    remote_tool = 'C:\\Users\\vika\\Documents\\Build-ExactAgentMatrix-' + args.label + '.ps1'
    ps = "$ErrorActionPreference='Stop'\n"
    ps += "if((Get-FileHash -LiteralPath '" + remote_tool + "' -Algorithm SHA256).Hash -ne '" + tool_sha + "'){throw 'Uploaded build tool hash mismatch.'}\n"
    ps += "& '" + remote_tool + "' -Label '" + args.label + "' -ArchiveSha256 '" + archive_sha + "' -ManifestSha256 '" + manifest_sha + "'\n"
    result = remote(ps, 'build')
    print('BUILD_RETURNED=' + str(result) + '; collecting retained evidence', flush=True)
    out = work / 'out'
    out.mkdir()
    names = ['summary.txt', 'dotnet-info.txt']
    for mode in ('normal', 'feature'):
        for configuration in ('debug', 'release'):
            name = mode + '-' + configuration
            names += [name + '-build.txt', name + '-tests.txt',
                      name + '-results/agent-tests.trx']
        names += [mode + '-release-publish.txt', mode + '-release-package-manifest.txt',
                  mode + '-release-service-publish.zip']
    fetched = {}
    for name in names:
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        fetch = subprocess.run(['scp', *SSH, REMOTE + prefix + '/out/' + name, str(path)],
                               capture_output=True)
        if fetch.returncode:
            fetched[name] = {'Fetched': False, 'Exit': fetch.returncode}
            continue
        fetched[name] = {'Fetched': True, 'Bytes': path.stat().st_size, 'SHA256': sha(path)}
        if not name.endswith('.zip'):
            retain(name.replace('/', '-'), path.read_bytes())
    retain('fetch-readout.json', (json.dumps(fetched, indent=2) + '\n').encode())
    if result != 0 or not all(row['Fetched'] for row in fetched.values()):
        raise RuntimeError('Build or evidence retrieval incomplete; inspect retained logs')
    summary = (out / 'summary.txt').read_text(encoding='utf-8-sig')
    if 'AgentMatrixGate=True' not in summary.splitlines():
        raise RuntimeError('Matrix completion sentinel missing')
    tests = verify_matrix_outputs(out, summary)
    agent_snapshot.snapshot.verify(work, provenance, tools=agent_snapshot.TOOLS)
    readout = {'UTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'AgentMatrixGate': 'PASS', 'Tests': tests, 'Provenance': provenance,
               'Fetched': fetched, 'ServiceInstalled': False, 'RuntimeQualification': False,
               'GitMutation': False}
    retain('root-readout.json', (json.dumps(readout, indent=2) + '\n').encode())
    print('ExactAgentMatrixGate=PASS; ' + json.dumps(tests), flush=True)


if __name__ == '__main__':
    main()
