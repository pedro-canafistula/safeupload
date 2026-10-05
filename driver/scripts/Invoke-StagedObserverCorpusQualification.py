#!/usr/bin/env python3
"""Freeze and run the driver-off observer corpus through Invoke-DebuggeeExperiment.sh.

Prepare: python3 driver/scripts/Invoke-StagedObserverCorpusQualification.py TAG --prepare-only
Run:     python3 driver/scripts/Invoke-StagedObserverCorpusQualification.py TAG --run-guid GUID
The prepare output gives GUID. This adapter exports ObserverCorpus only, never Phase4Suite.
"""
import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'driver' / 'scripts'
EVIDENCE = ROOT / 'driver' / 'evidence'
FILES = {
    'coordinator': 'Invoke-StagedObserverCorpus.ps1',
    'corpus': 'Test-StagedInvariantObserverCorpus.ps1',
    'observer': 'StagedInvariantObserver.psm1',
    'wrapper': 'Invoke-DebuggeeExperiment.sh',
    'baseline': 'Get-StagedBaseline.ps1',
}
CASES = {
    'ResidentConversion', 'OneByteAndFourKiB', 'SparseMapping',
    'CompressedMapping', 'FragmentedExtents', 'ReplacementEofSlack',
    'DirectoryIndexGrowth', 'MftFragmentation', 'FailClosedDecoderCopies',
    'OwnedFixtureCleanup',
}
SAMPLES = {
    'ResidentConversion': ('Converted',),
    'SparseMapping': ('ChangedFirst', 'ChangedMiddle', 'ChangedLast'),
    'CompressedMapping': ('ChangedFirst', 'ChangedMiddle', 'ChangedLast'),
    'FragmentedExtents': ('ChangedFirst', 'ChangedMiddle', 'ChangedLast'),
    'ReplacementEofSlack': ('Replaced', 'EofGrown'),
    'DirectoryIndexGrowth': ('NameAndMetadataChanged',),
}
TARGETS = {
    'ResidentConversion': 'convert.bin', 'SparseMapping': 'sparse.bin',
    'CompressedMapping': 'compressed.bin', 'FragmentedExtents': 'fragment-00.bin',
    'ReplacementEofSlack': 'target.bin', 'DirectoryIndexGrowth': 'new-name.bin',
}
IDENTITY_FIELDS = ('VolumeSerial', 'FileId', 'Reference', 'Eof', 'Allocation',
                   'Attributes', 'Links', 'DeletePending', 'Modified', 'Changed')
HOST = '192.168.122.51'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest().upper()


def write_new(path, data):
    with path.open('x', encoding='utf-8') as target:
        json.dump(data, target, sort_keys=True, indent=2)
        target.write('\n')
        target.flush()
        os.fsync(target.fileno())


def unique_line(content, prefix):
    rows = [line for line in content.splitlines() if line.startswith(prefix)]
    need(len(rows) == 1, 'Missing or duplicate ' + prefix)
    return rows[0]


def completion_marker(content, guid):
    matches = re.findall(
        rf'^OBSERVER_CORPUS_COMPLETE={guid};ChildExit=([0-9]+);ArchiveSha256=([0-9A-F]{{64}});'
        rf'ArchiveName=SafeUpload-corpus-{guid}\.zip;Cleanup=True;Status=(PASS|FAIL|INCONCLUSIVE)$',
        content, re.M)
    need(len(matches) == 1 and
         sum(line.startswith('OBSERVER_CORPUS_COMPLETE=') for line in content.splitlines()) == 1 and
         not any(line.startswith('OBSERVER_CORPUS_ERROR=') for line in content.splitlines()),
         'Missing, duplicate, or contradictory completion sentinel')
    return matches[0]


def source_state():
    return {
        'Head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'Status': subprocess.check_output(
            ['git', 'status', '--short', '--', *(str(Path('driver/scripts') / name) for name in FILES.values())],
            cwd=ROOT, text=True).splitlines(),
    }


def frozen_paths(work, manifest):
    result = {}
    for role in ('coordinator', 'corpus', 'observer'):
        record = manifest['Files'][role]
        path = work / record['FrozenLeaf']
        need(path.is_file() and sha(path) == record['Sha256'], 'Frozen input changed: ' + role)
        result[role] = path
    for role in ('wrapper', 'baseline'):
        need(sha(SCRIPTS / FILES[role]) == manifest['Files'][role]['Sha256'],
             'Wrapper or baseline changed since preparation: ' + role)
    return result


def prepare(work, name, guid):
    need(not work.exists(), 'Prepared input directory already exists: ' + str(work))
    work.mkdir(parents=True)
    records = {}
    for role, leaf in FILES.items():
        source = SCRIPTS / leaf
        need(source.is_file(), 'Missing input: ' + str(source))
        digest = sha(source)
        frozen_leaf = None
        if role in ('coordinator', 'corpus', 'observer'):
            stem, suffix = source.stem, source.suffix
            frozen_leaf = f'{stem}-{digest[:16]}{suffix}'
            target = work / frozen_leaf
            with source.open('rb') as inp, target.open('xb') as out:
                shutil.copyfileobj(inp, out)
                out.flush()
                os.fsync(out.fileno())
            need(sha(target) == digest, 'Freezing failed: ' + role)
        records[role] = {'Source': str(source.relative_to(ROOT)), 'Sha256': digest,
                         'FrozenLeaf': frozen_leaf}
    manifest = {'Schema': 'ObserverCorpusPreparation/1', 'Name': name,
                'RunGuid': guid, 'PreparedUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
                'Source': source_state(), 'Files': records,
                'OutcomeScope': 'ObserverCorpus;Phase4Suite=NOT_QUALIFIED'}
    write_new(work / 'provenance.json', manifest)
    return manifest


def safe_zip_name(name):
    need(name and '\x00' not in name and '\\' not in name and
         not name.startswith('/') and not re.match(r'^[A-Za-z]:', name),
         'Unsafe ZIP path: ' + name)
    need(all(part not in ('', '.', '..') for part in name.split('/')), 'Unsafe ZIP path: ' + name)


def validate_pass_evidence(archive, names, entries, guid, manifest, summary, by_case):
    """Require actual retained observer outputs before exporting ObserverCorpus PASS."""
    base = f'observer-corpus-{guid}'
    root = PureWindowsPath(f'C:/Users/vika/Documents/SafeUpload-corpus-evidence-{guid}')

    def load(name):
        need(name in names, 'PASS evidence missing: ' + name)
        return json.loads(archive.read(name))

    def reference(ref, case, where):
        need(isinstance(ref, dict) and isinstance(ref.get('Path'), str),
             'Missing artifact reference: ' + where)
        path = PureWindowsPath(ref['Path'])
        try:
            relative = path.relative_to(root)
        except ValueError as error:
            raise RuntimeError('Artifact outside owned evidence tree: ' + where) from error
        member = str(relative).replace('\\', '/')
        safe_zip_name(member)
        need(member.startswith(f'{base}/{case}/'), 'Artifact outside its case: ' + where)
        need(member in entries, 'Referenced artifact absent from ZIP: ' + where)
        need(isinstance(ref.get('Length'), int) and ref['Length'] >= 0 and
             isinstance(ref.get('Sha256'), str) and
             re.fullmatch('[0-9A-Fa-f]{64}', ref['Sha256']) is not None,
             'Artifact length/hash malformed: ' + where)
        row = entries[member]
        need(row['Length'] == ref['Length'] and row['Sha256'].upper() == ref['Sha256'].upper(),
             'Referenced artifact length/hash mismatch: ' + where)
        return member

    def same_identity(left, right, where):
        need(isinstance(left, dict) and isinstance(right, dict) and
             all(field in left and field in right and left[field] is not None and
                 left[field] == right[field] for field in IDENTITY_FIELDS),
             'Reader/raw full identity mismatch: ' + where)

    def current(capture, leaf, case):
        target_path = PureWindowsPath(
            f'C:/Users/vika/Documents/SafeUpload-corpus-fixtures-{guid}/'
            f'observer-corpus-{guid}/{case}/{leaf}')
        images = [image for image in capture.get('Images', [])
                  if image.get('Role') == 'Current' and
                  isinstance(image.get('Path'), str) and
                  PureWindowsPath(image['Path']) == target_path]
        need(len(images) == 1, 'Target Current image absent/duplicate: ' + case + '/' + leaf)
        return images[0]

    def image_bytes(image, case):
        member = reference(image.get('LogicalArtifact'), case, 'Mutation logical/' + case)
        return archive.read(member)

    def raw_signature(image):
        return tuple((part.get('Offset'), part.get('Length'),
                      (part.get('Artifact') or {}).get('Sha256'))
                     for part in image.get('Containers', []))

    def expected_bytes(length, seed):
        return bytes((seed + 31 * offset + 7 * (offset // 4096)) % 256
                     for offset in range(length))

    def touched_runs(runs, containers, cluster, kind):
        need(isinstance(runs, list) and cluster > 0, 'Run/geometry proof malformed: ' + kind)
        need(all(isinstance(run, dict) and
                 isinstance(run.get('Vcn'), int) and run['Vcn'] >= 0 and
                 isinstance(run.get('Lcn'), int) and run['Lcn'] >= -1 and
                 isinstance(run.get('Clusters'), int) and run['Clusters'] > 0
                 for run in runs), 'Malformed canonical run map: ' + kind)
        allocated = [run for run in runs if run['Lcn'] >= 0]
        need(all(left['Vcn'] + left['Clusters'] <= right['Vcn']
                 for left, right in zip(allocated, allocated[1:])),
             'Overlapping or unordered logical allocated runs: ' + kind)
        physical = sorted(allocated, key=lambda run: run['Lcn'])
        need(all(left['Lcn'] + left['Clusters'] <= right['Lcn']
                 for left, right in zip(physical, physical[1:])),
             'Overlapping physical allocated runs: ' + kind)
        touched = set()
        for part in containers:
            if part.get('Kind') != kind:
                continue
            offset, length = part.get('Offset'), part.get('Length')
            need(isinstance(offset, int) and isinstance(length, int) and
                 offset >= 0 and length > 0, 'Raw container offset/length invalid: ' + kind)
            for index, run in enumerate(allocated):
                start = run['Lcn'] * cluster
                end = start + run['Clusters'] * cluster
                if start <= offset and offset + length <= end:
                    touched.add(index)
        return allocated, touched

    def readers_ok(capture, case):
        readers = capture.get('Readers')
        need(isinstance(readers, list), 'Capture readers missing: ' + case)
        used = set()
        for image in capture.get('Images', []):
            role = image.get('Role', '')
            if role == 'Current' and image.get('Absent') is True:
                continue
            if role != 'Current' and not role.startswith('Retained:'):
                continue
            if role == 'Current':
                matches = [(index, reader) for index, reader in enumerate(readers)
                           if reader.get('Path') == image.get('Path') and
                           reader.get('Role') is None]
                need(len(matches) == 2 and
                     sum(reader.get('Unbuffered') is True for _, reader in matches) == 1 and
                     sum(reader.get('Unbuffered') is False for _, reader in matches) == 1,
                     'Current buffered+uncached reader pair missing: ' + case)
            else:
                file_id = role.split(':', 1)[1]
                need(image.get('Identity', {}).get('FileId') == file_id,
                     'Retained image role/FileId mismatch: ' + case)
                matches = [(index, reader) for index, reader in enumerate(readers)
                           if reader.get('Role') == 'Retained' and
                           reader.get('FileId') == file_id and
                           reader.get('Unbuffered') is False and reader.get('Path') is None]
                need(len(matches) == 1, 'Held retained reader missing: ' + case)
            for index, reader in matches:
                need(index not in used and reader.get('Status') == 'OK' and
                     reader.get('Error') is None and isinstance(reader.get('Result'), dict) and
                     reader['Result'].get('Status') == 'OK',
                     'Reader error/duplicate: ' + case)
                used.add(index)
                result = reader['Result']
                same_identity(result.get('Before'), result.get('After'), case)
                observed = result.get('Before') or {}
                raw = image.get('Identity') or {}
                need(all(key in observed and key in raw and observed[key] == raw[key]
                         for key in ('VolumeSerial', 'FileId', 'Reference')),
                     'Reader/raw volume, FileId, or reference mismatch: ' + case)
                need(result.get('Length') == image.get('Length') and
                     result.get('Digest') == image.get('Sha256') and
                     result.get('Before', {}).get('Eof') == image.get('Length'),
                     'Reader/raw length or digest mismatch: ' + case)
        need(len(used) == len(readers), 'Unexpected or unpaired capture reader: ' + case)

    def mutation_ok(case, captures):
        if case not in TARGETS:
            return
        leaf = TARGETS[case]
        baseline = current(captures[0], leaf, case)
        if case == 'DirectoryIndexGrowth':
            need(baseline.get('Absent') is True, 'Directory new name not absent at baseline')
            after = current(captures[1], leaf, case)
            need(after.get('Absent') is False and len(image_bytes(after, case)) > 0,
                 'Directory new name lacks actual bytes')
            parents_before = [i for i in captures[0]['Images'] if i.get('Role') == 'Parent']
            parents_after = [i for i in captures[1]['Images'] if i.get('Role') == 'Parent']
            parent_path = PureWindowsPath(
                f'C:/Users/vika/Documents/SafeUpload-corpus-fixtures-{guid}/'
                f'observer-corpus-{guid}/{case}')
            need(len(parents_before) == len(parents_after) == 1 and
                 PureWindowsPath(parents_before[0].get('Path', '')) == parent_path and
                 PureWindowsPath(parents_after[0].get('Path', '')) == parent_path and
                 raw_signature(parents_before[0]) != raw_signature(parents_after[0]) and
                 not any(e.get('Name') == leaf for e in parents_before[0].get('DirectoryEntries', [])) and
                 any(e.get('Name') == leaf and e.get('Attributes', 0) & 2
                     for e in parents_after[0].get('DirectoryEntries', [])),
                 'Directory parent raw/index/name/hidden transition absent')
            return
        need(baseline.get('Absent') is False, 'Mutation baseline target absent: ' + case)
        original = image_bytes(baseline, case)
        before_id = baseline.get('Identity', {}).get('FileId')
        offsets = []
        allocated = []
        if case in ('SparseMapping', 'CompressedMapping', 'FragmentedExtents'):
            cluster = captures[0]['Geometry']['Cluster']
            allocated = [run for run in baseline.get('Runs', [])
                         if run.get('Lcn', -1) >= 0 and
                         (case == 'SparseMapping' or run.get('Vcn', -1) * cluster < len(original))]
            need(len(allocated) >= 3 and
                 all(isinstance(run.get('Vcn'), int) and isinstance(run.get('Clusters'), int) and
                     run['Clusters'] > 0 for run in allocated),
                 'Three actual allocated extents missing: ' + case)
        if case == 'ResidentConversion':
            need(original == expected_bytes(80, 11), 'Resident baseline bytes/length mismatch')
        if case == 'ReplacementEofSlack':
            need(original == expected_bytes(8192, 37), 'Replacement old bytes/length mismatch')
        for index, sample in enumerate(captures[1:], 1):
            after = current(sample, leaf, case)
            need(after.get('Absent') is False, 'Mutation target absent: ' + case)
            actual = image_bytes(after, case)
            need(actual != original and raw_signature(baseline) != raw_signature(after),
                 'Target logical/raw bytes unchanged: ' + case + '/' + sample['Phase'])
            if case in ('SparseMapping', 'CompressedMapping', 'FragmentedExtents'):
                need(len(actual) == len(original), 'Extent mutation changed EOF: ' + case)
                differing = [offset for offset, (a, b) in enumerate(zip(original, actual)) if a != b]
                need(len(differing) == 1, 'Extent mutation did not change exactly one byte: ' + case)
                offsets.append(differing[0])
                facts = by_case[case].get('Facts') or {}
                detected = facts.get('Detected') or []
                expected_run = allocated[(0, len(allocated) // 2, len(allocated) - 1)[index - 1]]
                expected_offset = expected_run['Vcn'] * cluster
                need(0 <= expected_offset < len(original) and
                     differing[0] == expected_offset and
                     actual[differing[0]] == (original[differing[0]] + 1) % 256 and
                     len(detected) == 3 and detected[index - 1].get('Offset') == expected_offset,
                     'First/middle/last recorded offset contradicts bytes: ' + case)
                need(after.get('Identity', {}).get('FileId') == before_id,
                     'Extent mutation changed file identity: ' + case)
            elif case == 'ResidentConversion':
                need(actual == expected_bytes(8192, 19) and baseline.get('Resident') is True and
                     after.get('Resident') is False and
                     after.get('Identity', {}).get('FileId') == before_id and
                     any(run.get('Lcn', -1) >= 0 for run in after.get('Runs', [])),
                     'Resident/nonresident transition absent')
            elif case == 'ReplacementEofSlack':
                retained = [image for image in sample.get('Images', [])
                            if image.get('Role') == 'Retained:' + before_id]
                need(len(retained) == 1 and image_bytes(retained[0], case) == original and
                     retained[0].get('Identity', {}).get('FileId') == before_id,
                     'Replacement held old bytes/identity absent')
                if index == 1:
                    need(actual == expected_bytes(6144, 41) and
                         after.get('Identity', {}).get('FileId') != before_id,
                         'Replacement reused old FileId')
                else:
                    replaced = current(captures[1], leaf, case)
                    replaced_bytes = image_bytes(replaced, case)
                    need(after.get('Identity', {}).get('FileId') == replaced.get('Identity', {}).get('FileId') and
                         len(actual) == 12288 and actual == expected_bytes(6144, 41) + bytes(6144) and
                         replaced_bytes == expected_bytes(6144, 41),
                         'EOF growth/new identity/zero extension absent')
        if offsets:
            need(len(set(offsets)) == 3 and offsets[0] < offsets[1] < offsets[2],
                 'First/middle/last physical extent positions not distinct/ordered: ' + case)

    provenance = load(f'{base}/provenance.json')
    need(provenance.get('RunGuid') == guid and provenance.get('Build') == '19045.2965' and
         provenance.get('DriverUnloaded') is True and
         provenance.get('ObserverSha256') == manifest['Files']['observer']['Sha256'] and
         provenance.get('ScriptSha256') == manifest['Files']['corpus']['Sha256'],
         'PASS provenance build/driver/input mismatch')
    need(summary.get('FixturesRemoved') is True, 'Owned fixture cleanup not proven')

    case_captures = {}
    for case in sorted(CASES - {'OwnedFixtureCleanup'}):
        prefix = f'{base}/{case}'
        disposal = load(f'{prefix}/disposal.json')
        need(disposal.get('Status') == 'OK' and not disposal.get('Errors'),
             'PASS disposal not OK: ' + case)
        baseline = load(f'{prefix}/baseline.json')
        geometry = baseline.get('Geometry')
        need(baseline.get('Schema') == 'StagedInvariant/1' and
             baseline.get('Status') == 'OK' and
             baseline.get('CaseId') == f'ObserverCorpus-{case}-{guid}' and
             baseline.get('Build') == '19045.2965' and isinstance(geometry, dict) and
             isinstance(geometry.get('Guid'), str) and geometry['Guid'].startswith('\\\\?\\Volume{') and
             isinstance(geometry.get('Sector'), int) and geometry['Sector'] > 0 and
             isinstance(geometry.get('Cluster'), int) and geometry['Cluster'] >= geometry['Sector'] and
             isinstance(geometry.get('RecordSize'), int) and geometry['RecordSize'] > 0 and
             isinstance(geometry.get('TotalBytes'), int) and geometry['TotalBytes'] > 0,
             'PASS baseline status/case/geometry/build invalid: ' + case)
        captures = [baseline]
        for sequence, phase in enumerate(SAMPLES.get(case, ()), 1):
            sample = load(f'{prefix}/sample-{sequence:03d}-{phase}.json')
            need(sample.get('Schema') == 'StagedInvariant/1' and sample.get('Status') == 'OK' and
                 sample.get('CaseId') == baseline['CaseId'] and sample.get('Phase') == phase and
                 sample.get('OperationSequence') == sequence and sample.get('Sequence') == sequence,
                 'PASS mutation sample status/identity missing: ' + case + '/' + phase)
            captures.append(sample)
        case_captures[case] = captures
        referenced = set()
        raw_count = logical_count = 0
        for capture in captures:
            readers_ok(capture, case)
            for image in capture.get('Images', []):
                if image.get('Role') == 'Historical':
                    member = reference(image.get('Artifact'), case, 'Historical/' + case)
                    need('/raw/' in member and image.get('Length') == image['Artifact']['Length'] and
                         isinstance(image.get('OriginalSha256'), str),
                         'Historical raw artifact invalid: ' + case)
                    referenced.add(member)
                    raw_count += 1
                    continue
                need(image.get('Role') in ('Parent', 'Current') or
                     image.get('Role', '').startswith('Retained:'),
                     'Unexpected image role in PASS: ' + case)
                if image.get('Absent') is True:
                    continue
                need(image.get('CrossCheckErrors') == [], 'Raw/API cross-check errors: ' + case)
                logical = image.get('LogicalArtifact')
                member = reference(logical, case, 'LogicalArtifact/' + case)
                need('/raw/' in member and logical.get('Kind') == 'logical',
                     'Logical artifact not in raw evidence: ' + case)
                referenced.add(member)
                logical_count += 1
                need(image.get('Length') == logical['Length'] and
                     image.get('Sha256', '').upper() == logical['Sha256'].upper(),
                     'Logical image differs from artifact: ' + case)
                for container in image.get('Containers', []):
                    member = reference(container.get('Artifact'), case, 'Container/' + case)
                    need('/raw/' in member and container.get('Length') == container['Artifact']['Length'],
                         'Raw container length/path invalid: ' + case)
                    referenced.add(member)
                    raw_count += 1
        need(logical_count > 0 and raw_count > 0,
             'PASS lacks logical or raw capture artifacts: ' + case)
        raw_manifest_name = f'{prefix}/raw/manifest.ndjson'
        need(raw_manifest_name in names, 'PASS raw artifact manifest missing: ' + case)
        manifest_members = set()
        for line in archive.read(raw_manifest_name).splitlines():
            record = json.loads(line)
            member = reference(record, case, 'raw manifest/' + case)
            need('/raw/' in member and member not in manifest_members,
                 'Duplicate/nonraw manifest artifact: ' + case)
            manifest_members.add(member)
        actual_raw = {name for name in names if name.startswith(f'{prefix}/raw/') and name.endswith('.bin')}
        need(manifest_members == actual_raw and referenced <= manifest_members,
             'Raw manifest/reference/ZIP inventory differs: ' + case)
        mutation_ok(case, captures)

    classification = load(f'{base}/OneByteAndFourKiB/classification.json')
    class_baseline = case_captures['OneByteAndFourKiB'][0]
    one = current(class_baseline, 'one.bin', 'OneByteAndFourKiB')
    four = current(class_baseline, 'four-k.bin', 'OneByteAndFourKiB')
    one_runs = one.get('Runs', [])
    four_runs = four.get('Runs', [])
    one_fact = classification.get('OneByte') or {}
    four_fact = classification.get('FourKiB') or {}
    summary_fact = by_case['OneByteAndFourKiB'].get('Facts') or {}
    need(image_bytes(one, 'OneByteAndFourKiB') == expected_bytes(1, 13) and
         image_bytes(four, 'OneByteAndFourKiB') == expected_bytes(4096, 17) and
         one.get('Resident') is True and one_runs == [] and
         four.get('Resident') is False and
         isinstance(four_runs, list) and any(run.get('Lcn', -1) >= 0 for run in four_runs) and
         one_fact == {'Resident': True, 'Runs': 0, 'FileId': one.get('Identity', {}).get('FileId')} and
         four_fact == {'Resident': False, 'Runs': len(four_runs),
                       'FileId': four.get('Identity', {}).get('FileId')} and
         summary_fact.get('OneByte') == one_fact and summary_fact.get('FourKiB') == four_fact,
         'One-byte/4096-byte representation control missing')
    mft = load(f'{base}/MftFragmentation/mft-runs.json')
    facts = by_case['MftFragmentation'].get('Facts') or {}
    mft_baseline = case_captures['MftFragmentation'][0]
    mft_containers = [part for image in mft_baseline.get('Images', [])
                      for part in image.get('Containers', [])]
    allocated_mft, touched_mft = touched_runs(
        mft, mft_containers, mft_baseline['Geometry']['Cluster'], 'MFT')
    need(len(allocated_mft) >= 2 and len(touched_mft) >= 2 and
         facts.get('MftRuns') == len(allocated_mft) and
         facts.get('RunsActuallyRead') == len(touched_mft),
         'Actual MFT fragmentation/touched-runs proof missing')
    directory = by_case['DirectoryIndexGrowth'].get('Facts') or {}
    index_baseline, index_sample = case_captures['DirectoryIndexGrowth']
    parents = [image for image in index_baseline.get('Images', []) if image.get('Role') == 'Parent']
    after_parents = [image for image in index_sample.get('Images', []) if image.get('Role') == 'Parent']
    need(len(parents) == len(after_parents) == 1, 'Directory index parent capture missing')
    index_attributes = [attribute for attribute in parents[0].get('Attributes', [])
                        if attribute.get('Type') == 160 and attribute.get('Name') == '$I30']
    need(len(index_attributes) == 1, 'Actual $I30 index allocation absent')
    index_containers = after_parents[0].get('Containers', [])
    allocated_index, touched_index = touched_runs(
        index_attributes[0].get('Runs'), index_containers,
        index_baseline['Geometry']['Cluster'], 'INDEX_ALLOCATION')
    need(len(allocated_index) >= 2 and len(touched_index) >= 2 and
         directory.get('IndexAllocatedRuns') == len(allocated_index) and
         directory.get('IndexRunsActuallyRead') == len(touched_index) and
         directory.get('NewNameDetected') is True and
         directory.get('HiddenMetadataDetected') is True,
         'Directory index fragmentation/name/metadata proof missing')
    negative = load(f'{base}/FailClosedDecoderCopies/negative-inputs.json')
    need(negative.get('RawDiskWritten') is False and
         isinstance(negative.get('ExpectedRecord'), int) and
         isinstance(negative.get('RawRecordArtifacts'), list) and
         len(negative['RawRecordArtifacts']) > 0,
         'Negative decoder source proof missing')
    for ref in negative['RawRecordArtifacts']:
        reference(ref, 'FailClosedDecoderCopies', 'RawRecordArtifacts')
    inputs = negative.get('Inputs') or {}
    for key in ('RawUsaCorruption', 'TruncatedRawRecord', 'TruncatedRunMapping'):
        member = reference(inputs.get(key), 'FailClosedDecoderCopies', key)
        need(member.endswith('.bin'), 'Negative input bytes absent: ' + key)
    short = inputs.get('ShortRawRead') or {}
    need(short == {'Start': 0, 'End': 4096, 'Rounded': 4096, 'Transfer': 4096,
                   'Count': 2048, 'EofAllowed': False, 'Eof': 0},
         'Short-read argument proof mismatch')
    rejections = negative.get('Rejections')
    need(isinstance(rejections, list) and
         {row.get('Name') for row in rejections} ==
         {'RawUsaCorruption', 'TruncatedRawRecord', 'TruncatedRunMapping', 'ShortRawRead'} and
         len(rejections) == 4 and all(row.get('Rejected') is True and
                                      row.get('Recognized') is True and
                                      isinstance(row.get('Chain'), list) and
                                      any(entry.get('Type') and entry.get('Message') for entry in row['Chain'])
                                      for row in rejections),
         'Recognized decoder rejection/type/message chain missing')


def inspect_archive(path, guid, manifest):
    need(path.is_file(), 'Guest archive missing')
    with zipfile.ZipFile(path) as archive:
        need(archive.testzip() is None, 'ZIP CRC failed')
        infos = archive.infolist()
        names = [entry.filename for entry in infos]
        need(len(names) == len(set(names)), 'Duplicate ZIP entry')
        for entry in infos:
            safe_zip_name(entry.filename)
            need(not entry.is_dir(), 'Directory ZIP entry')
            mode = (entry.external_attr >> 16) & 0o170000
            need(mode in (0, stat.S_IFREG), 'Non-file ZIP entry')
        need('archive-manifest.json' in names and 'completion.json' in names,
             'Archive omits coordinator manifest or completion')
        listing = json.loads(archive.read('archive-manifest.json'))
        need(listing.get('Schema') == 'ObserverCorpusArchive/1' and listing.get('RunGuid') == guid,
             'Archive manifest identity mismatch')
        rows = listing.get('Entries')
        need(isinstance(rows, list), 'Archive entry manifest malformed')
        expected = {}
        for row in rows:
            name = row['Path']
            safe_zip_name(name)
            need(name not in expected, 'Duplicate manifest entry')
            expected[name] = row
        need(set(expected) == set(names) - {'archive-manifest.json'}, 'Manifest omits or adds ZIP entry')
        for name, row in expected.items():
            digest = hashlib.sha256()
            length = 0
            with archive.open(name) as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    length += len(block)
                    digest.update(block)
            need(length == row['Length'] and digest.hexdigest().upper() == row['Sha256'],
                 'ZIP entry length/hash mismatch: ' + name)
        completion = json.loads(archive.read('completion.json'))
        need(completion.get('Schema') == 'ObserverCorpusCompletion/1' and
             completion.get('RunGuid') == guid, 'Completion identity mismatch')
        for role in ('coordinator', 'corpus', 'observer'):
            need(completion.get(role.title() + 'Sha256') == manifest['Files'][role]['Sha256'],
                 'Completion input hash mismatch: ' + role)
        need('child-stdout.txt' in names and 'child-stderr.txt' in names,
             'Raw child output missing')
        summary_name = f'observer-corpus-{guid}/summary.json'
        need(summary_name in names, 'Corpus summary missing')
        summary = json.loads(archive.read(summary_name))
        need(summary.get('Schema') == 'InvariantObserverCorpus/1' and summary.get('RunGuid') == guid,
             'Corpus summary identity mismatch')
        need(summary.get('AuthoritativeCaseExport') is False and
             summary.get('Phase4Suite') == 'NOT_QUALIFIED', 'Improper Phase4 claim')
        results = summary.get('Results')
        need(isinstance(results, list) and len(results) == len(CASES), 'Corpus omitted a case')
        by_case = {}
        for row in results:
            key = row.get('CaseId')
            need(key not in by_case and key in CASES, 'Duplicate or unexpected corpus case')
            need(row.get('Status') in ('PASS', 'FAIL', 'INCONCLUSIVE'), 'Invalid corpus status')
            by_case[key] = row
        need(set(by_case) == CASES, 'Corpus case inventory incomplete')
        counts = {status: sum(row['Status'] == status for row in results)
                  for status in ('PASS', 'FAIL', 'INCONCLUSIVE')}
        need(summary.get('Counts') == counts, 'Corpus summary counts mismatch')
        stdout = archive.read('child-stdout.txt').decode('utf-8-sig', errors='replace')
        line = unique_line(stdout, 'Corpus_Summary=')
        need(line == (f"Corpus_Summary=pass:{counts['PASS']};fail:{counts['FAIL']};"
                      f"inconclusive:{counts['INCONCLUSIVE']};Phase4Suite:NOT_QUALIFIED"),
             'Raw stdout summary disagrees with JSON')
        for case in CASES:
            line = unique_line(stdout, 'Corpus_' + case + '=')
            need(line.startswith('Corpus_' + case + '=' + by_case[case]['Status'] + ';'),
                 'Raw stdout case disagrees with JSON: ' + case)
        expected_exit = 1 if counts['FAIL'] else (2 if counts['INCONCLUSIVE'] else 0)
        need(completion.get('ChildExit') == expected_exit and completion.get('TimedOut') is False,
             'Child exit/timeout disagrees with case statuses')
        outcome = 'FAIL' if counts['FAIL'] else ('INCONCLUSIVE' if counts['INCONCLUSIVE'] else 'PASS')
        need(completion.get('Status') == outcome, 'Completion status disagrees with case statuses')
        if outcome == 'PASS':
            validate_pass_evidence(archive, set(names), expected, guid, manifest, summary, by_case)
        return {'Status': outcome, 'Counts': counts, 'Completion': completion}


def self_test():
    """Synthetic/NotVM archive controls through the production validator."""
    guid = '0123456789abcdef0123456789abcdef'
    base = f'observer-corpus-{guid}'
    hashes = {role: hashlib.sha256(role.encode()).hexdigest().upper()
              for role in ('coordinator', 'corpus', 'observer')}
    source = {'Files': {role: {'Sha256': value} for role, value in hashes.items()}}

    def encoded(value):
        return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

    def fixture_bytes(length, seed):
        return bytes((seed + 31 * offset + 7 * (offset // 4096)) % 256
                     for offset in range(length))

    def artifact(case, relative, data):
        return {'Path': f'C:\\Users\\vika\\Documents\\SafeUpload-corpus-evidence-{guid}\\'
                        f'{base}\\{case}\\{relative}',
                'Length': len(data), 'Sha256': hashlib.sha256(data).hexdigest().upper(),
                'Kind': 'logical' if relative.endswith('-logical.bin') else 'MFT'}

    def archive_file(path, files):
        rows = [{'Path': name, 'Length': len(data),
                 'Sha256': hashlib.sha256(data).hexdigest().upper()}
                for name, data in sorted(files.items())]
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as target:
            for name, data in files.items():
                target.writestr(name, data)
            target.writestr('archive-manifest.json', encoded({
                'Schema': 'ObserverCorpusArchive/1', 'RunGuid': guid, 'Entries': rows}))

    def fixture(status):
        files = {}
        results = []
        def identity(file_id, length):
            return {'VolumeSerial': 77, 'FileId': file_id, 'Reference': 42,
                    'Eof': length, 'Allocation': max(4096, length), 'Attributes': 0,
                    'Links': 1, 'DeletePending': False, 'Modified': 1, 'Changed': 1}

        def reader(image, uncached=False, retained=False):
            ident = image['Identity']
            result = {'Status': 'OK', 'Before': ident.copy(), 'After': ident.copy(),
                      'Length': image['Length'], 'Digest': image['Sha256']}
            record = {'Path': None if retained else image['Path'],
                      'Unbuffered': uncached, 'Status': 'OK', 'Error': None,
                      'Result': result}
            if retained:
                record.update(Role='Retained', FileId=ident['FileId'])
            return record

        for case in sorted(CASES):
            facts = ({'Detected': [{'Offset': i * 512} for i in range(3)]}
                     if case in ('SparseMapping', 'CompressedMapping', 'FragmentedExtents') else
                     {'MftRuns': 2, 'RunsActuallyRead': 2} if case == 'MftFragmentation' else
                     {'IndexAllocatedRuns': 2, 'IndexRunsActuallyRead': 2,
                      'NewNameDetected': True, 'HiddenMetadataDetected': True}
                     if case == 'DirectoryIndexGrowth' else {})
            results.append({'CaseId': case, 'Status': status, 'Facts': facts})
            if status != 'PASS' or case == 'OwnedFixtureCleanup':
                continue
            prefix = f'{base}/{case}'
            raw_refs = []

            def image(label, role, leaf, data, file_id='file-old', resident=True, names=None):
                raw = ('raw-' + case + '-' + label).encode()
                raw_path = f'raw/{label}-mft.bin'
                logical_path = f'raw/{label}-logical.bin'
                raw_ref = artifact(case, raw_path, raw)
                logical_ref = artifact(case, logical_path, data)
                files[f'{prefix}/{raw_path}'] = raw
                files[f'{prefix}/{logical_path}'] = data
                raw_refs.extend((raw_ref, logical_ref))
                scope = (f'C:\\Users\\vika\\Documents\\SafeUpload-corpus-fixtures-{guid}\\'
                         f'{base}\\{case}')
                return {'Role': role, 'Path': None if role.startswith('Retained:') else
                        scope if role == 'Parent' else scope + '\\' + leaf, 'Absent': False,
                        'Identity': identity(file_id, len(data)), 'Length': len(data),
                        'Sha256': logical_ref['Sha256'], 'LogicalArtifact': logical_ref,
                        'Containers': [{'Kind': 'MFT', 'Offset': 0,
                                        'Length': len(raw), 'Artifact': raw_ref}],
                        'CrossCheckErrors': [], 'Resident': resident,
                        'Runs': ([{'Vcn': i, 'Clusters': 1, 'Lcn': i * 2 + 1}
                                  for i in range(3)]
                                 if case in ('SparseMapping', 'CompressedMapping', 'FragmentedExtents')
                                 else [] if resident else [{'Vcn': 0, 'Clusters': 2, 'Lcn': 1}]),
                        'DirectoryEntries': names or []}

            def extra_container(owner, label, kind, offset):
                data = ('raw-' + case + '-' + label).encode()
                relative = f'raw/{label}.bin'
                ref = artifact(case, relative, data)
                files[f'{prefix}/{relative}'] = data
                raw_refs.append(ref)
                owner['Containers'].append({'Kind': kind, 'Offset': offset,
                                            'Length': len(data), 'Artifact': ref})

            files[f'{prefix}/disposal.json'] = encoded({'Status': 'OK', 'Errors': []})
            target = TARGETS.get(case, 'record.bin')
            old = (fixture_bytes(80, 11) if case == 'ResidentConversion' else
                   bytes(offset % 256 for offset in range(1536))
                   if case in ('SparseMapping', 'CompressedMapping', 'FragmentedExtents') else
                   fixture_bytes(8192, 37) if case == 'ReplacementEofSlack' else b'baseline')
            if case == 'DirectoryIndexGrowth':
                parent = image('baseline-parent', 'Parent', 'folder', b'', 'parent', names=[])
                parent['Attributes'] = [{'Type': 160, 'Name': '$I30', 'Runs': [
                    {'Vcn': 0, 'Lcn': 30, 'Clusters': 1},
                    {'Vcn': 1, 'Lcn': 40, 'Clusters': 1}]}]
                baseline_images = [parent, {'Role': 'Current', 'Path':
                                            f'C:\\Users\\vika\\Documents\\SafeUpload-corpus-fixtures-{guid}\\'
                                            f'{base}\\{case}\\{target}',
                                            'Absent': True}]
                baseline_readers = []
            elif case == 'OneByteAndFourKiB':
                one = image('baseline-one', 'Current', 'one.bin', fixture_bytes(1, 13),
                            file_id='one-id')
                four = image('baseline-four', 'Current', 'four-k.bin',
                             fixture_bytes(4096, 17), file_id='four-id', resident=False)
                baseline_images = [one, four]
                baseline_readers = [reader(one), reader(one, True),
                                    reader(four), reader(four, True)]
                facts = {'OneByte': {'Resident': True, 'Runs': 0, 'FileId': 'one-id'},
                         'FourKiB': {'Resident': False, 'Runs': len(four['Runs']),
                                     'FileId': 'four-id'}}
                results[-1]['Facts'] = facts
            else:
                old_image = image('baseline-current', 'Current', target, old,
                                  resident=case not in ('SparseMapping', 'CompressedMapping',
                                                        'FragmentedExtents', 'ReplacementEofSlack'))
                if case == 'MftFragmentation':
                    old_image['Containers'][0]['Offset'] = 10 * 512
                    parent = image('baseline-parent', 'Parent', 'folder', b'', 'parent')
                    parent['Containers'][0]['Offset'] = 20 * 512
                    baseline_images = [parent, old_image]
                else:
                    baseline_images = [old_image]
                baseline_readers = [reader(old_image), reader(old_image, True)]
            common = {'Schema': 'StagedInvariant/1', 'Status': 'OK',
                      'CaseId': f'ObserverCorpus-{case}-{guid}'}
            baseline = {**common, 'Images': baseline_images, 'Readers': baseline_readers,
                        'Build': '19045.2965', 'Geometry': {
                'Guid': '\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\',
                'Sector': 512, 'Cluster': 512, 'RecordSize': 1024, 'TotalBytes': 1048576}}
            files[f'{prefix}/baseline.json'] = encoded(baseline)
            for sequence, phase in enumerate(SAMPLES.get(case, ()), 1):
                if case in ('SparseMapping', 'CompressedMapping', 'FragmentedExtents'):
                    data = bytearray(old)
                    data[(sequence - 1) * 512] = (data[(sequence - 1) * 512] + 1) % 256
                    new_image = image(f'sample-{sequence}-current', 'Current', target,
                                      bytes(data), resident=False)
                    images = [new_image]
                elif case == 'ResidentConversion':
                    new_image = image('sample-current', 'Current', target,
                                      fixture_bytes(8192, 19),
                                      resident=False)
                    images = [new_image]
                elif case == 'ReplacementEofSlack':
                    data = (fixture_bytes(6144, 41) if sequence == 1 else
                            fixture_bytes(6144, 41) + bytes(6144))
                    new_image = image(f'sample-{sequence}-current', 'Current', target, data,
                                      file_id='file-new', resident=False)
                    retained = image(f'sample-{sequence}-retained', 'Retained:file-old',
                                     target, old)
                    images = [new_image, retained]
                else:
                    parent = image('sample-parent', 'Parent', 'folder', b'', 'parent',
                                   names=[{'Name': target, 'Attributes': 2}])
                    extra_container(parent, 'index-run-first', 'INDEX_ALLOCATION', 30 * 512)
                    extra_container(parent, 'index-run-last', 'INDEX_ALLOCATION', 40 * 512)
                    new_image = image('sample-current', 'Current', target, b'new-name')
                    images = [parent, new_image]
                readers = [reader(new_image), reader(new_image, True)]
                if case == 'ReplacementEofSlack':
                    readers.append(reader(retained, retained=True))
                sample = {**common, 'Images': images, 'Readers': readers,
                          'Phase': phase, 'OperationSequence': sequence, 'Sequence': sequence}
                files[f'{prefix}/sample-{sequence:03d}-{phase}.json'] = encoded(sample)
            files[f'{prefix}/raw/manifest.ndjson'] = b''.join(encoded(ref) for ref in raw_refs)
        if status == 'PASS':
            files[f'{base}/provenance.json'] = encoded({
                'RunGuid': guid, 'Build': '19045.2965', 'DriverUnloaded': True,
                'ObserverSha256': hashes['observer'], 'ScriptSha256': hashes['corpus']})
            class_facts = next(row['Facts'] for row in results
                               if row['CaseId'] == 'OneByteAndFourKiB')
            files[f'{base}/OneByteAndFourKiB/classification.json'] = encoded(class_facts)
            files[f'{base}/MftFragmentation/mft-runs.json'] = encoded([
                {'Vcn': 0, 'Lcn': 10, 'Clusters': 1},
                {'Vcn': 1, 'Lcn': 20, 'Clusters': 1}])
            neg = f'{base}/FailClosedDecoderCopies'
            inputs = {}
            for key in ('RawUsaCorruption', 'TruncatedRawRecord', 'TruncatedRunMapping'):
                data = key.encode()
                files[f'{neg}/{key}.bin'] = data
                inputs[key] = artifact('FailClosedDecoderCopies', key + '.bin', data)
            inputs['ShortRawRead'] = {'Start': 0, 'End': 4096, 'Rounded': 4096,
                                      'Transfer': 4096, 'Count': 2048,
                                      'EofAllowed': False, 'Eof': 0}
            raw_record = artifact('FailClosedDecoderCopies', 'raw/baseline-current-mft.bin',
                                  files[f'{neg}/raw/baseline-current-mft.bin'])
            files[f'{neg}/negative-inputs.json'] = encoded({
                'RawDiskWritten': False, 'ExpectedRecord': 1,
                'RawRecordArtifacts': [raw_record], 'Inputs': inputs,
                'Rejections': [{'Name': key, 'Rejected': True, 'Recognized': True,
                                'Chain': [{'Type': 'StagedInvariant.ObservationException',
                                           'Message': 'synthetic rejection'}]}
                               for key in (*('RawUsaCorruption', 'TruncatedRawRecord',
                                             'TruncatedRunMapping'), 'ShortRawRead')]})
        counts = {'PASS': 10 if status == 'PASS' else 0,
                  'FAIL': 0, 'INCONCLUSIVE': 10 if status == 'INCONCLUSIVE' else 0}
        files[f'{base}/summary.json'] = encoded({
            'Schema': 'InvariantObserverCorpus/1', 'RunGuid': guid, 'Counts': counts,
            'Results': results, 'FixturesRemoved': status == 'PASS',
            'AuthoritativeCaseExport': False, 'Phase4Suite': 'NOT_QUALIFIED'})
        files['completion.json'] = encoded({
            'Schema': 'ObserverCorpusCompletion/1', 'RunGuid': guid,
            'ChildExit': 0 if status == 'PASS' else 2, 'TimedOut': False,
            'Status': status, **{role.title() + 'Sha256': value
                                  for role, value in hashes.items()}})
        files['child-stderr.txt'] = b''
        files['child-stdout.txt'] = ('\n'.join(
            f'Corpus_{case}={status};synthetic' for case in sorted(CASES)) + '\n' +
            f"Corpus_Summary=pass:{counts['PASS']};fail:0;"
            f"inconclusive:{counts['INCONCLUSIVE']};Phase4Suite:NOT_QUALIFIED\n").encode()
        return files

    with tempfile.TemporaryDirectory(prefix='observer-corpus-host-controls-') as directory:
        path = Path(directory) / 'synthetic.zip'
        good = fixture('PASS')
        archive_file(path, good)
        need(inspect_archive(path, guid, source)['Status'] == 'PASS',
             'Synthetic PASS control rejected')
        sparse_order = copy.deepcopy(good)
        mft_name = f'{base}/MftFragmentation/mft-runs.json'
        mft_runs = json.loads(sparse_order[mft_name])
        mft_runs[0]['Lcn'], mft_runs[1]['Lcn'] = mft_runs[1]['Lcn'], mft_runs[0]['Lcn']
        mft_runs[1]['Vcn'] = 2  # logical gap and nonmonotonic physical allocation are valid
        sparse_order[mft_name] = encoded(mft_runs)
        index_name = f'{base}/DirectoryIndexGrowth/baseline.json'
        index_baseline = json.loads(sparse_order[index_name])
        index_parent = next(image for image in index_baseline['Images']
                            if image.get('Role') == 'Parent')
        index_runs = next(attribute for attribute in index_parent['Attributes']
                          if attribute.get('Type') == 160)['Runs']
        index_runs[0]['Lcn'], index_runs[1]['Lcn'] = index_runs[1]['Lcn'], index_runs[0]['Lcn']
        index_runs[1]['Vcn'] = 2
        sparse_order[index_name] = encoded(index_baseline)
        archive_file(path, sparse_order)
        need(inspect_archive(path, guid, source)['Status'] == 'PASS',
             'Valid nonmonotonic physical runs/logical VCN gap rejected')
        controls = {}
        mutations = {
            'missing-raw': lambda files: files.pop(f'{base}/ResidentConversion/raw/baseline-current-mft.bin'),
            'missing-disposal': lambda files: files.pop(f'{base}/ResidentConversion/disposal.json'),
            'missing-mutation-sample': lambda files: files.pop(
                f'{base}/ResidentConversion/sample-001-Converted.json'),
        }
        baseline_name = f'{base}/ResidentConversion/baseline.json'
        sample_name = f'{base}/ResidentConversion/sample-001-Converted.json'

        def edit_json(files, name, edit):
            value = json.loads(files[name])
            edit(value)
            files[name] = encoded(value)

        def reuse_replacement_id(value):
            for entry in value['Images']:
                if entry.get('Role') == 'Current':
                    entry['Identity']['FileId'] = 'file-old'
            for reader_record in value['Readers']:
                if reader_record.get('Role') != 'Retained':
                    reader_record['Result']['Before']['FileId'] = 'file-old'
                    reader_record['Result']['After']['FileId'] = 'file-old'

        def wrong_retained_bytes(files):
            prefix = f'{base}/ReplacementEofSlack'
            name = f'{prefix}/sample-001-Replaced.json'
            sample = json.loads(files[name])
            retained = next(image for image in sample['Images']
                            if image.get('Role') == 'Retained:file-old')
            member = f'{prefix}/raw/sample-1-retained-logical.bin'
            data = b'Z' * retained['Length']
            digest = hashlib.sha256(data).hexdigest().upper()
            files[member] = data
            retained['Sha256'] = digest
            retained['LogicalArtifact']['Sha256'] = digest
            next(reader_record for reader_record in sample['Readers']
                 if reader_record.get('Role') == 'Retained')['Result']['Digest'] = digest
            files[name] = encoded(sample)
            raw_manifest = f'{prefix}/raw/manifest.ndjson'
            records = [json.loads(line) for line in files[raw_manifest].splitlines()]
            for record in records:
                if PureWindowsPath(record['Path']).name == 'sample-1-retained-logical.bin':
                    record['Sha256'] = digest
            files[raw_manifest] = b''.join(encoded(record) for record in records)

        def fake_classification_without_one(files):
            name = f'{base}/OneByteAndFourKiB/baseline.json'
            def edit(value):
                one = next(image for image in value['Images']
                           if PureWindowsPath(image['Path']).name == 'one.bin')
                old_path = one['Path']
                one['Path'] = str(PureWindowsPath(old_path).with_name('record.bin'))
                for reader_record in value['Readers']:
                    if reader_record.get('Path') == old_path:
                        reader_record['Path'] = one['Path']
            edit_json(files, name, edit)

        def fake_mft_touches(files):
            name = f'{base}/MftFragmentation/baseline.json'
            edit_json(files, name, lambda value: [
                part.update(Offset=0)
                for image in value['Images'] for part in image.get('Containers', [])
                if part.get('Kind') == 'MFT'])

        def fake_index_touches(files):
            name = f'{base}/DirectoryIndexGrowth/sample-001-NameAndMetadataChanged.json'
            edit_json(files, name, lambda value: [
                part.update(Offset=0)
                for image in value['Images'] if image.get('Role') == 'Parent'
                for part in image.get('Containers', [])
                if part.get('Kind') == 'INDEX_ALLOCATION'])

        def duplicate_mft_map(files):
            name = f'{base}/MftFragmentation/mft-runs.json'
            runs = json.loads(files[name])
            runs[1]['Lcn'] = runs[0]['Lcn']
            files[name] = encoded(runs)

        def duplicate_index_map(files):
            name = f'{base}/DirectoryIndexGrowth/baseline.json'
            def edit(value):
                parent = next(image for image in value['Images']
                              if image.get('Role') == 'Parent')
                runs = next(attribute for attribute in parent['Attributes']
                            if attribute.get('Type') == 160)['Runs']
                runs[1]['Lcn'] = runs[0]['Lcn']
            edit_json(files, name, edit)

        mutations.update({
            'missing-readers': lambda files: edit_json(
                files, baseline_name, lambda value: value.pop('Readers')),
            'error-reader': lambda files: edit_json(
                files, baseline_name, lambda value: value['Readers'][0].update(Status='ERROR')),
            'reader-digest-mismatch': lambda files: edit_json(
                files, baseline_name, lambda value:
                value['Readers'][0]['Result'].update(Digest='0' * 64)),
            'unstable-identity': lambda files: edit_json(
                files, baseline_name, lambda value:
                value['Readers'][0]['Result']['After'].update(Reference=999)),
            'raw-api-crosscheck-error': lambda files: edit_json(
                files, baseline_name, lambda value:
                value['Images'][0].update(CrossCheckErrors=['Raw/API EOF mismatch'])),
            'unchanged-mutation': lambda files: edit_json(
                files, sample_name, lambda value: value.update(
                    Images=copy.deepcopy(json.loads(files[baseline_name])['Images']),
                    Readers=copy.deepcopy(json.loads(files[baseline_name])['Readers']))),
            'replacement-reused-file-id': lambda files: edit_json(
                files, f'{base}/ReplacementEofSlack/sample-001-Replaced.json',
                reuse_replacement_id),
            'replacement-wrong-retained-bytes': wrong_retained_bytes,
            'classification-without-actual-one-byte': fake_classification_without_one,
            'fake-mft-touched-count': fake_mft_touches,
            'fake-index-touched-count': fake_index_touches,
            'duplicate-overlap-mft-map': duplicate_mft_map,
            'duplicate-overlap-index-map': duplicate_index_map,
        })
        for label, mutation in mutations.items():
            files = copy.deepcopy(good)
            mutation(files)
            archive_file(path, files)
            try:
                inspect_archive(path, guid, source)
            except RuntimeError:
                controls[label] = 'EXPECTED_REJECTION'
            else:
                raise RuntimeError('Synthetic control unexpectedly accepted: ' + label)
        files = copy.deepcopy(good)
        baseline = json.loads(files[baseline_name])
        baseline['Images'][0]['LogicalArtifact']['Sha256'] = '0' * 64
        files[baseline_name] = encoded(baseline)
        archive_file(path, files)
        try:
            inspect_archive(path, guid, source)
        except RuntimeError:
            controls['bad-referenced-hash'] = 'EXPECTED_REJECTION'
        else:
            raise RuntimeError('Synthetic bad referenced hash accepted')
        archive_file(path, fixture('INCONCLUSIVE'))
        need(inspect_archive(path, guid, source)['Status'] == 'INCONCLUSIVE',
             'Synthetic early INCONCLUSIVE archive rejected')
        print(json.dumps({'Schema': 'ObserverCorpusHostControls/1',
                          'Synthetic': True, 'NotVmQualification': True,
                          'PassFixture': 'ACCEPTED', 'EarlyInconclusive': 'ACCEPTED',
                          'NonmonotonicPhysicalAndVcnGap': 'ACCEPTED',
                          'Rejections': controls, 'Result': 'PASS'}, sort_keys=True, indent=2))


def scp_archive(name, guid, destination):
    remote = f'vika@{HOST}:C:/Users/vika/Documents/SafeUpload-corpus-{guid}.zip'
    command = ['scp', '-F', '/dev/null', '-i', '/home/victor/.ssh/id_ed25519',
               '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'LogLevel=ERROR',
               '-o', 'StrictHostKeyChecking=accept-new', remote, str(destination)]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120)
    need(result.returncode == 0, 'Could not collect guest archive: ' + result.stderr.strip())


def run(args, work, name, guid, manifest):
    frozen = frozen_paths(work, manifest)
    day = work.parent
    gate = day / f'{name}-gate.txt'
    baseline = day / f'{name}-baseline.txt'
    restored = day / f'{name}-final-restored-state.txt'
    archive = day / f'{name}-raw.zip'
    verdict_path = day / f'{name}-observer-corpus-verdict.json'
    need(not any(path.exists() for path in (gate, baseline, restored, archive, verdict_path)),
         'This run name already has result evidence')
    leaves = [manifest['Files'][role]['FrozenLeaf'] for role in ('coordinator', 'corpus', 'observer')]
    pre = '; '.join(["$ErrorActionPreference='Stop'", *(
        f"if(Test-Path -LiteralPath 'C:\\Users\\vika\\Documents\\{leaf}'){{throw 'Staged input collision: {leaf}'}}"
        for leaf in leaves), "'PRE_RUN_OK=True'"])
    coord, corpus, observer = leaves
    docs = 'C:\\Users\\vika\\Documents\\'
    invoke = (f"& '{docs}{coord}' -RunGuid '{guid}' "
              f"-CoordinatorSha256 '{manifest['Files']['coordinator']['Sha256']}' "
              f"-CorpusSha256 '{manifest['Files']['corpus']['Sha256']}' "
              f"-ObserverSha256 '{manifest['Files']['observer']['Sha256']}' "
              f"-CorpusLeaf '{corpus}' -ObserverLeaf '{observer}'")
    env = os.environ.copy()
    env['PRE_RUN_PS'] = pre
    env['EXTRA_FILES'] = f'{frozen["corpus"]}={corpus} {frozen["observer"]}={observer}'
    env['HARNESS_TIMEOUT_SECONDS'] = '4200'
    command = ['bash', str(SCRIPTS / FILES['wrapper']), name, str(frozen['coordinator']), invoke]
    verdict = {'Schema': 'ObserverCorpusVerdict/1', 'Name': name, 'RunGuid': guid,
               'ObserverCorpus': 'NOT_QUALIFIED', 'Phase4Suite': 'NOT_QUALIFIED',
               'WrapperExit': None, 'Archive': str(archive), 'Reasons': []}
    with (day / f'{name}-host-wrapper.txt').open('x', encoding='utf-8') as output:
        try:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=5400)
        except subprocess.TimeoutExpired:
            output.write('HOST_WRAPPER_TIMEOUT=True;Seconds=5400;IndependentRestorationUnverified=True\n')
            output.flush()
            os.fsync(output.fileno())
            verdict.update(WrapperTimeout=True, RecoveryRequired=True, BaselineClean=False)
            verdict['Reasons'].append('Generic wrapper timed out; independent restoration is unverified. Stop VM work and use wrapper recovery evidence.')
            # A completed coordinator marker is emitted only after its immutable ZIP
            # was closed and hashed. Without it, copying could race an active writer.
            if gate.is_file():
                try:
                    marker = completion_marker(gate.read_text('utf-8-sig', errors='replace'), guid)
                    scp_archive(name, guid, archive)  # bounded read-only collection
                    need(sha(archive) == marker[1], 'Post-timeout archive SHA-256 mismatch')
                    verdict['RecoveredArchiveSha256Verified'] = True
                    verdict['RecoveredArchiveGuestStatus'] = marker[2]
                    verdict['Reasons'].append('Completed guest ZIP retained; independent restoration remains unverified.')
                except Exception as error:
                    verdict['Reasons'].append('Post-timeout archive collection: ' +
                                              type(error).__name__ + ': ' + str(error))
            else:
                verdict['Reasons'].append('No complete guest gate; skipped potentially in-flight ZIP')
            write_new(verdict_path, verdict)
            print(json.dumps(verdict, sort_keys=True, indent=2))
            return 1
    verdict['WrapperExit'] = result.returncode
    closed_marker = None
    try:
        if gate.exists():
            content = gate.read_text('utf-8-sig', errors='replace')
            marker = completion_marker(content, guid)
            closed_marker = marker
            need(content.splitlines().count('HARNESS_RETURNED') == 1 and
                 'HARNESS_THREW:' not in content and 'HARNESS_TIMEOUT=True' not in content,
                 'Guest harness did not return cleanly')
        else:
            raise RuntimeError('Guest gate missing')
        # Retrieve even if independent restoration failed; the ZIP retains failure evidence.
        scp_archive(name, guid, archive)
        need(sha(archive) == marker[1], 'Archive SHA-256 disagrees with guest completion')
        inspected = inspect_archive(archive, guid, manifest)
        need(str(inspected['Completion']['ChildExit']) == marker[0] and
             inspected['Status'] == marker[2], 'Completion sentinel disagrees with archive')
        verdict.update(inspected)
        need(result.returncode == 0, 'Generic checkpoint wrapper failed')
        for path in (baseline, restored):
            need(path.is_file() and path.read_text('utf-8-sig', errors='replace').splitlines().count('BaselineClean=True') == 1,
                 'Independent baseline not clean: ' + str(path))
        need(restored.read_text('utf-8-sig', errors='replace').splitlines().count('ProcessCreationAuditRestored=True') == 1,
             'Process creation audit restoration missing')
        verdict['BaselineClean'] = True
        verdict['ObserverCorpus'] = inspected['Status']
    except Exception as error:
        verdict['Reasons'].append(type(error).__name__ + ': ' + str(error))
        # Collect only a ZIP whose completed guest marker proves it was closed.
        if not archive.exists() and closed_marker is not None:
            try:
                scp_archive(name, guid, archive)
                need(sha(archive) == closed_marker[1],
                     'Fallback archive SHA-256 disagrees with closed guest marker')
                verdict['RecoveredArchiveSha256Verified'] = True
            except Exception as copy_error:
                verdict['Reasons'].append('Archive collection: ' + str(copy_error))
        elif not archive.exists():
            verdict['Reasons'].append('No unique closed completion marker; skipped potentially in-flight ZIP')
        restored_lines = (restored.read_text('utf-8-sig', errors='replace').splitlines()
                          if restored.is_file() else [])
        if (restored_lines.count('BaselineClean=True') != 1 or
                restored_lines.count('ProcessCreationAuditRestored=True') != 1):
            verdict['RecoveryRequired'] = True
            verdict['BaselineClean'] = False
    finally:
        write_new(verdict_path, verdict)
    print(json.dumps(verdict, sort_keys=True, indent=2))
    return 0 if verdict['ObserverCorpus'] == 'PASS' and verdict.get('BaselineClean') else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag', nargs='?', help='Unique short evidence tag, 2-24 lowercase letters, digits or hyphens')
    parser.add_argument('--run-guid', help='32 hexadecimal digits; required to run prepared inputs')
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--self-test', action='store_true',
                        help='Local synthetic ZIP acceptance/rejection controls; no VM or builder')
    args = parser.parse_args()
    if args.self_test:
        need(args.tag is None and args.run_guid is None and not args.prepare_only,
             '--self-test takes no run arguments')
        self_test()
        return 0
    need(re.fullmatch(r'[a-z][a-z0-9-]{1,23}', args.tag) is not None, 'Invalid tag')
    guid = (args.run_guid or uuid.uuid4().hex).lower()
    need(re.fullmatch('[0-9a-f]{32}', guid) is not None, 'Invalid RunGuid')
    if not args.prepare_only:
        need(args.run_guid is not None, 'Live run requires --run-guid from prepare-only')
    name = f'observer-corpus-{args.tag}-{guid[:12]}'
    day = EVIDENCE / dt.date.today().isoformat()
    work = day / (name + '-inputs')
    if args.prepare_only:
        manifest = prepare(work, name, guid)
        print(json.dumps({'Prepared': str(work), 'RunGuid': guid, 'Name': name,
                          'Files': manifest['Files'], 'VmTouched': False}, indent=2))
        return 0
    need(work.is_dir(), 'Prepared inputs missing: ' + str(work))
    manifest = json.loads((work / 'provenance.json').read_text('utf-8'))
    need(manifest.get('Schema') == 'ObserverCorpusPreparation/1' and
         manifest.get('Name') == name and manifest.get('RunGuid') == guid,
         'Prepared identity mismatch')
    frozen_paths(work, manifest)
    lock_path = Path('/tmp/safeupload-win10-debug.lock')
    with lock_path.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('WIN10-DEBUGGED VM serial lock is held') from error
        return run(args, work, name, guid, manifest)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(f'ObserverCorpus=NOT_QUALIFIED: {type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(2)
