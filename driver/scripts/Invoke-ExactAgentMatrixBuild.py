#!/usr/bin/env python3
"""Build a Git-commit agent matrix on the recorded builder and retain raw evidence.

Never commits changes or installs the agent. --prepare-only performs no network
operation. The commit identifies source; the archive hash verifies delivery.
"""
import argparse
from approved_builders import (SSH, select, receipt, receipt_lines, identity_ps, remote_args)
import datetime
import hashlib
import json
from pathlib import Path
import re
import runpy
import stat
import subprocess
from collections import Counter
from collections import defaultdict
import shutil
import zipfile
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
TRX_NS = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
FAILED_COUNTERS = ('failed', 'error', 'timeout', 'aborted', 'inconclusive',
                   'passedButRunAborted', 'notRunnable', 'notExecuted', 'disconnected',
                   'warning', 'inProgress', 'pending')
SYSTEM_FILTER_MARKERS = ('CertificateAuthorityTests', 'TlsInspectionProxyTests', 'TrafficDiversionTests')
MACHINE_FACT_CLASSES = ('MachineCertificateAuthorityTests', 'TrafficDiversionTests')
VSTEST_DISCOVERY_HEADER = 'The following Tests are available:'
MATRIX_MODES = ('feature',)
MATRIX_PROFILE_ROW = 'AgentMatrixProfiles=feature-debug,feature-release'
STAGED_V20_REQUIRED_TESTS = {
    ('SafeUpload.Agent.Tests.StagedAttachmentV20Tests', method)
    for method in (
        'V20_attachment_order_blocks_seal_until_handle_receipt_and_allows_positive_save',
        'V20_retire_unexposed_uses_exact_background_delete_ack_and_replays_op16',
        'V20_retire_attached_private_requires_measured_zero_and_exact_ack',
        'V20_epoch_drain_replay_is_exact_and_does_not_reauthorize_a_different_tuple',
        'V20_epoch_rejects_unpaired_drain_receipts_without_rewriting_them',
        'Ordinary_empty_profile_rejects_old_capabilities_before_accepting_an_epoch',
        'Legacy_empty_migration_requires_fresh_exact_content_and_reconciled_obligations')
} | {
    ('SafeUpload.Agent.Tests.StagedTransferAllocatorTests', method)
    for method in (
        'V20_typed_allocate_rejects_the_old_v19_profile_marker',
        'V20_typed_allocate_rejects_nonzero_data_after_payload_or_path',
        'V20_marker_on_an_ordinary_operation_is_rejected_before_image_text_decode',
        'V20_create_after_rejects_identityless_or_different_epoch_v1_before_child_intent',
        'V19_create_after_discard_commits_exact_ancestry_before_backing_and_replays_reservation',
        'Legacy_v19_create_after_preserves_all_legacy_chain_and_rejects_mixed_epoch_request',
        'V20_create_after_requires_exact_op19_before_any_journal_mutation',
        'Direct_emptyheld_parent_cleanup_requires_terminal_child_ack_and_survives_restart_compaction',
        'Direct_emptyheld_successor_must_be_exactly_retired_before_its_parent',
        'Direct_emptyheld_cleanup_rejects_mismatched_child_writer_or_epoch',
        'Direct_released_successor_requires_gate_confirmed_disposal_before_parent_ack',
        'Direct_released_successor_replacement_blocks_parent_cleanup_without_deleting_replacement')
} | {
    ('SafeUpload.Agent.Tests.StagedTransferJournalTests',
     'V19_unattached_allocation_cleanup_cannot_discard_a_sealed_version'),
    ('SafeUpload.Agent.Tests.StagedTransferJournalTests',
     'Exact_private_discard_can_finish_after_a_newer_ordinary_allocation_without_touching_it'),
    ('SafeUpload.Agent.Tests.StagedTransferJournalTests',
     'Empty_stage_is_measured_sealed_with_the_empty_digest_and_reserved_state_cannot_be_forged'),
    ('SafeUpload.Agent.Tests.StagedTransferPublisherTests',
     'Measured_empty_content_publishes_normally_without_extraction_or_private_notice'),
    ('SafeUpload.Agent.Tests.StagedTransferPublisherTests',
     'Changed_length_cannot_turn_a_measured_version_into_an_implicit_empty_approval'),
    ('SafeUpload.Agent.Tests.StagedTransferPublisherTests',
     'Empty_publication_still_requires_the_kernel_permit'),
    ('SafeUpload.Agent.Tests.StagedInspectionFailureTests',
     'Trivial_empty_inspection_measures_content_instead_of_trusting_declared_size')
}
STAGED_V20_REQUIRED_CASES = {
    ('SafeUpload.Agent.Tests.StagedTransferAllocatorTests.'
     'V20_create_after_rejects_identityless_or_different_epoch_v1_before_child_intent'):
        ('parentEpochShape: "identityless"', 'parentEpochShape: "different-epoch"'),
    ('SafeUpload.Agent.Tests.StagedTransferAllocatorTests.'
     'Legacy_v19_create_after_preserves_all_legacy_chain_and_rejects_mixed_epoch_request'):
        (None,),
    ('SafeUpload.Agent.Tests.StagedTransferAllocatorTests.'
     'V20_create_after_requires_exact_op19_before_any_journal_mutation'):
        ('receiptShape: "missing"', 'receiptShape: "pending"',
         'receiptShape: "wrong-receipt-tuple"'),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_gate(summary, row):
    matches = [line for line in summary.splitlines() if line == row]
    if len(matches) != 1:
        raise RuntimeError('Missing or ambiguous gate summary row: ' + row)


def read_captured_text(path):
    """Decode PowerShell-captured text from its explicit BOM, or strict UTF-8."""
    data = path.read_bytes()
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        return data.decode('utf-16')
    if data.startswith(b'\xef\xbb\xbf'):
        return data.decode('utf-8-sig')
    return data.decode('utf-8')


def read_public_discovery_cases(path):
    """Read VSTest /ListTests display names without trimming or transcoding them."""
    lines = read_captured_text(path).splitlines()
    if (len(lines) < 4 or not lines[0].startswith('VSTest version ')
            or lines[1] != '' or lines[2] != VSTEST_DISCOVERY_HEADER):
        raise RuntimeError('Malformed public VSTest discovery output: ' + str(path))
    cases = []
    for line in lines[3:]:
        if len(line) <= 4 or not line.startswith('    ') or line[4].isspace():
            raise RuntimeError('Malformed public VSTest discovery case row: ' + str(path))
        cases.append(line[4:])
    if not cases:
        raise RuntimeError('Empty public VSTest discovery inventory: ' + str(path))
    return Counter(cases)


def bind_discovery_cases_to_methods(public_cases, method_inventory, name):
    """Bind each exact public display string to one exact discovered method FQN."""
    methods = set(method_inventory)
    bound = Counter()
    observed_methods = set()
    for case, count in public_cases.items():
        matches = [method for method in methods
                   if case == method or case.startswith(method + '(')]
        if len(matches) != 1:
            raise RuntimeError('Public discovery case does not bind to exactly one fully qualified method: '
                               + name + '/' + repr(case))
        method = matches[0]
        observed_methods.add(method)
        bound[(method, case)] += count
    if observed_methods != methods:
        missing = sorted(methods - observed_methods)
        raise RuntimeError('Public discovery omits methods from the fully qualified inventory: '
                           + name + '/' + repr(missing[:8]))
    return bound


def require_exact_case_multiset(expected, actual, description):
    if expected != actual:
        missing = expected - actual
        extra = actual - expected
        raise RuntimeError(description + ': missing=' + repr(list(missing.items())[:8])
                           + ' extra=' + repr(list(extra.items())[:8]))


def require_required_passed_result_ids(discovered_cases, executed_cases,
                                       results_by_fqn, fqn, name):
    """Bind every required admission result ID to its exact discovered case."""
    expected = Counter({case: count for (case_fqn, case), count in discovered_cases.items()
                        if case_fqn == fqn})
    if not expected:
        raise RuntimeError('Required admission test has no exact discovered cases: '
                           + name + '/' + fqn)
    actual = Counter({case: count for (case_fqn, case), count in executed_cases.items()
                      if case_fqn == fqn})
    require_exact_case_multiset(
        expected, actual, 'Required admission cases differ from exact public discovery: '
        + name + '/' + fqn)

    result_ids = list(results_by_fqn.get(fqn, []))
    expected_count = sum(expected.values())
    if (len(result_ids) != expected_count
            or len(set(result_ids)) != expected_count
            or any(not isinstance(result_id, str) or not result_id for result_id in result_ids)):
        raise RuntimeError('Required admission result-ID cardinality/uniqueness differs from exact '
                           'discovered cases: ' + name + '/' + fqn)
    return result_ids


def read_trx(path):
    root = ET.parse(path).getroot()
    counters = root.find('.//t:ResultSummary/t:Counters', TRX_NS)
    if counters is None:
        raise RuntimeError('Missing TRX counters: ' + str(path))
    try:
        total = int(counters.attrib['total'])
        executed = int(counters.attrib['executed'])
        passed = int(counters.attrib['passed'])
        unsuccessful = {key: int(counters.attrib.get(key, '0')) for key in FAILED_COUNTERS}
    except (KeyError, ValueError) as exc:
        raise RuntimeError('Malformed TRX counters: ' + str(path)) from exc
    if total <= 0 or executed != total or passed != total or any(unsuccessful.values()):
        raise RuntimeError('Empty, incomplete, skipped, warning, or failed TRX leg: ' + str(path))

    definitions = {}
    for unit in root.findall('.//t:TestDefinitions/t:UnitTest', TRX_NS):
        test_id = unit.attrib.get('id', '')
        method = unit.find('t:TestMethod', TRX_NS)
        if not test_id or method is None:
            raise RuntimeError('Malformed TRX test definition: ' + str(path))
        class_name = method.attrib.get('className', '')
        method_name = method.attrib.get('name', '')
        if not class_name or not method_name:
            raise RuntimeError('TRX definition lacks a fully qualified method: ' + str(path))
        fqn = class_name + '.' + method_name
        if test_id in definitions and definitions[test_id] != fqn:
            raise RuntimeError('Conflicting TRX definitions for test ID: ' + test_id)
        definitions[test_id] = fqn

    result_rows = root.findall('.//t:Results/t:UnitTestResult', TRX_NS)
    if len(result_rows) != total:
        raise RuntimeError('TRX result count differs from counters: ' + str(path))
    execution_ids = set()
    fqns = []
    cases = []
    passed_fqns = set()
    results_by_fqn = defaultdict(list)
    for row in result_rows:
        test_id = row.attrib.get('testId', '')
        execution_id = row.attrib.get('executionId', '')
        test_name = row.attrib.get('testName', '')
        if (not test_id or not execution_id or not test_name
                or execution_id in execution_ids or row.attrib.get('outcome') != 'Passed'):
            raise RuntimeError('Missing, duplicate, or unpassed TRX result identity: ' + str(path))
        fqn = definitions.get(test_id)
        if not fqn:
            raise RuntimeError('TRX result references no test definition: ' + test_id)
        execution_ids.add(execution_id)
        fqns.append(fqn)
        cases.append((fqn, test_name))
        passed_fqns.add(fqn)
        results_by_fqn[fqn].append(execution_id)
    if len(execution_ids) != total:
        raise RuntimeError('TRX execution IDs are not unique: ' + str(path))
    return {'total': total, 'execution_ids': execution_ids, 'fqns': Counter(fqns),
            'cases': Counter(cases),
            'passed_fqns': passed_fqns, 'results_by_fqn': results_by_fqn}


def is_system_fqn(fqn):
    return any(marker in fqn for marker in SYSTEM_FILTER_MARKERS)


def is_machine_fact_fqn(fqn):
    return any('.' + class_name + '.' in fqn for class_name in MACHINE_FACT_CLASSES)


def require_system_families(discovered, name):
    for marker in SYSTEM_FILTER_MARKERS:
        if not any(marker in fqn for fqn in discovered):
            raise RuntimeError('Required SYSTEM-routed test family is absent from VSTest discovery: '
                               + name + '/' + marker)


def require_system_cleanup_evidence(system_log_lines, name):
    required = ('SYSTEM_TEST_TASK_SID=S-1-5-18',
                'SYSTEM_TEST_JOB_CLEANUP=active_processes=0',
                'SYSTEM_TEST_TASK_CLEANUP=task_absent,job_empty,wrapper_absent')
    missing = [row for row in required if row not in system_log_lines]
    if missing:
        raise RuntimeError('SYSTEM task identity/cleanup proof is incomplete: ' + name + ': ' + repr(missing))


def safe_member_name(name, is_directory=False):
    if not isinstance(name, str) or not name or '\\' in name or name.startswith('/'):
        raise RuntimeError('Unsafe package member path: ' + repr(name))
    if is_directory:
        if not name.endswith('/'):
            raise RuntimeError('Malformed package directory entry: ' + repr(name))
        name = name[:-1]
    elif name.endswith('/'):
        raise RuntimeError('Malformed package file entry: ' + repr(name))
    parts = name.split('/')
    for part in parts:
        if (part in ('', '.', '..') or re.search(r'[\x00-\x1f:*?<>|\"]', part)
                or part.endswith((' ', '.'))
                or re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', part)):
            raise RuntimeError('Unsafe package member path: ' + repr(name))
    return name


def validate_package(out, mode, summary):
    name = mode + '-release'
    package = out / (name + '-service-publish.zip')
    manifest = out / (name + '-package-manifest.txt')
    manifest_hashes = {}
    folded_manifest = set()
    for line in manifest.read_text(encoding='utf-8-sig').splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64})  (.+)', line)
        if not match:
            raise RuntimeError('Malformed package manifest row: ' + name)
        digest, member = match.groups()
        member = safe_member_name(member)
        folded = member.casefold()
        if folded in folded_manifest:
            raise RuntimeError('Duplicate or case-colliding package manifest member: ' + member)
        folded_manifest.add(folded)
        manifest_hashes[member] = digest.lower()
    if not manifest_hashes:
        raise RuntimeError('Empty package manifest: ' + name)

    with zipfile.ZipFile(package) as archive:
        package_hashes = {}
        package_directories = set()
        folded_entries = set()
        for info in archive.infolist():
            is_directory = info.is_dir()
            member = safe_member_name(info.filename, is_directory)
            folded = member.casefold()
            if folded in folded_entries:
                raise RuntimeError('Duplicate or case-colliding package entry: ' + member)
            folded_entries.add(folded)
            mode_bits = (info.external_attr >> 16) & 0o170000
            if mode_bits not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise RuntimeError('Non-regular package member: ' + member)
            if is_directory:
                if mode_bits not in (0, stat.S_IFDIR):
                    raise RuntimeError('Package directory has a non-directory type: ' + member)
                package_directories.add(member)
                continue
            if mode_bits not in (0, stat.S_IFREG):
                raise RuntimeError('Package file has a non-regular type: ' + member)
            digest = hashlib.sha256()
            with archive.open(info, 'r') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            package_hashes[member] = digest.hexdigest()
        if package_hashes != manifest_hashes:
            missing = sorted(set(manifest_hashes) - set(package_hashes))
            extra = sorted(set(package_hashes) - set(manifest_hashes))
            mismatch = sorted(k for k in set(package_hashes) & set(manifest_hashes)
                              if package_hashes[k] != manifest_hashes[k])
            raise RuntimeError('Package contents differ from retained manifest: missing=' + repr(missing)
                               + ' extra=' + repr(extra) + ' hash_mismatch=' + repr(mismatch))
        prefixes = {member.rsplit('/', 1)[0] + '/' for member in manifest_hashes if '/' in member}
        prefixes |= {parent for member in manifest_hashes for parent in
                     ('/'.join(member.split('/')[:index]) + '/'
                      for index in range(1, len(member.split('/'))))}
        if not package_directories.issubset(prefixes):
            raise RuntimeError('Unexpected empty or unrelated package directory entry: ' + name)
        exe_info = [info for info in archive.infolist()
                    if not info.is_dir() and info.filename == 'SafeUpload.Agent.Service.exe']
        if len(exe_info) != 1 or exe_info[0].file_size <= 0:
            raise RuntimeError('Package has no unique, nonempty service executable: ' + name)
        exe_hash = package_hashes.get('SafeUpload.Agent.Service.exe')
        if not exe_hash:
            raise RuntimeError('Service executable is absent from package manifest: ' + name)

    package_summary = name + ': package_sha256=' + sha(package).upper()
    exe_summary = name + ': exe_sha256=' + exe_hash.upper()
    manifest_summary = name + ': package_manifest_sha256=' + sha(manifest).upper()
    read_gate(summary, package_summary)
    read_gate(summary, exe_summary)
    read_gate(summary, manifest_summary)
    return {'path': str(package), 'sha256': sha(package).upper(),
            'exe_sha256': exe_hash.upper(), 'manifest_sha256': sha(manifest).upper(),
            'members': len(manifest_hashes)}


def required_feature_tests():
    required_feature = {('SafeUpload.Agent.Tests.AdmissionEvidenceWireTests', method)
                        for method in (
                            'Managed_status_mirrors_match_driver_sizes_and_offsets',
                            'Input_allows_only_readonly_status_commands_and_bounded_start_indices',
                            'Native_failure_keeps_hresult_and_never_exposes_zeroed_reply_buffer',
                            'Diagnostic_sends_on_one_port_are_serialized',
                            'Dispose_drains_an_inflight_diagnostic_send_and_rejects_later_sends')}
    required_feature |= {('SafeUpload.Agent.Tests.AdmissionEvidenceEndpointTests', method)
                         for method in (
                             'EvidenceTypesExistOnlyInFeatureBuilds',
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
    required_feature |= STAGED_V20_REQUIRED_TESTS
    return required_feature


def verify_matrix_outputs(out, summary):
    """Prove that both feature profiles executed every discovered case exactly once."""
    tests = {}
    packages = {}
    read_gate(summary, MATRIX_PROFILE_ROW)
    read_gate(summary, 'AgentMatrixTestLegs=4')
    for mode in MATRIX_MODES:
        for configuration in ('debug', 'release'):
            name = mode + '-' + configuration
            read_gate(summary, name + ': admission_evidence=true')
            for action in ('build', 'app-build', 'test-build', 'tests-discovery-list',
                           'tests-discovery-fqns', 'tests-user', 'tests-system', 'tests'):
                read_gate(summary, name + '-' + action + ': exit=0 warnings=0 errors=0')
            user_identity_rows = [line for line in summary.splitlines()
                                  if line.startswith(name + '-tests-user-identity: ')]
            if len(user_identity_rows) != 1:
                raise RuntimeError('Missing or ambiguous unprivileged test identity: ' + name)
            identity = re.fullmatch(name + r'-tests-user-identity: name=([^ ]+) sid=(S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+)',
                                    user_identity_rows[0])
            if not identity or identity.group(1).rsplit('\\', 1)[-1].casefold() != 'vika':
                raise RuntimeError('User test leg identity is not the builder SSH account: ' + name)
            read_gate(summary, name + '-tests-system-identity: S-1-5-18')
            system_log_lines = (out / (name + '-tests-system.txt')).read_text(
                encoding='utf-8-sig', errors='replace').splitlines()
            require_system_cleanup_evidence(system_log_lines, name)

            result_dir = out / (name + '-results')
            fq_file = result_dir / 'agent-tests-discovered-fq.txt'
            fqns = read_captured_text(fq_file).splitlines()
            if (not fqns or any(not fqn or fqn != fqn.strip() for fqn in fqns)
                    or len(set(fqns)) != len(fqns)):
                raise RuntimeError('Invalid discovery-only method inventory (empty, whitespace or duplicate): ' + name)
            public_cases = read_public_discovery_cases(out / (name + '-tests-discovery-list.txt'))
            discovered_methods = Counter(fqns)
            discovered_cases = bind_discovery_cases_to_methods(public_cases, fqns, name)
            for fqn, arguments in STAGED_V20_REQUIRED_CASES.items():
                required_cases = Counter({
                    (fqn, fqn if argument is None else fqn + '(' + argument + ')'): 1
                    for argument in arguments})
                actual_cases = Counter({case: count for case, count in discovered_cases.items()
                                        if case[0] == fqn})
                require_exact_case_multiset(required_cases, actual_cases,
                    'Mandatory v20 theory cases differ from required variants: ' + name + '/' + fqn)
            require_system_families(discovered_methods, name)

            user = read_trx(result_dir / 'agent-tests-user.trx')
            system = read_trx(result_dir / 'agent-tests-system.trx')
            merged = read_trx(result_dir / 'agent-tests.trx')
            expected_system = Counter({case: count for case, count in discovered_cases.items()
                                       if is_system_fqn(case[0])})
            expected_user = Counter({case: count for case, count in discovered_cases.items()
                                     if not is_system_fqn(case[0])})
            if not expected_system or not expected_user:
                raise RuntimeError('Discovery did not produce both account partitions: ' + name)
            require_exact_case_multiset(expected_user, user['cases'],
                                        'Unprivileged execution differs from exact public discovery cases: ' + name)
            require_exact_case_multiset(expected_system, system['cases'],
                                        'SYSTEM execution differs from exact public discovery cases: ' + name)
            require_exact_case_multiset(discovered_cases, merged['cases'],
                                        'Merged execution differs from exact public discovery cases: ' + name)
            if user['execution_ids'] & system['execution_ids']:
                raise RuntimeError('The same result execution ID appeared in both account legs: ' + name)
            if (user['execution_ids'] | system['execution_ids']) != merged['execution_ids']:
                raise RuntimeError('Merged TRX result IDs differ from the raw account-leg union: ' + name)
            machine_methods = {fqn for fqn in fqns if is_machine_fact_fqn(fqn)}
            for machine_class in MACHINE_FACT_CLASSES:
                if not any('.' + machine_class + '.' in fqn for fqn in machine_methods):
                    raise RuntimeError('MachineFact class is absent from VSTest discovery: '
                                       + name + '/' + machine_class)
            machine_cases = Counter({case: count for case, count in discovered_cases.items()
                                     if is_machine_fact_fqn(case[0])})
            system_machine_cases = Counter({case: count for case, count in system['cases'].items()
                                            if is_machine_fact_fqn(case[0])})
            if not machine_cases:
                raise RuntimeError('MachineFact cases are absent from public VSTest discovery: ' + name)
            require_exact_case_multiset(machine_cases, system_machine_cases,
                                        'MachineFact tests were not explicitly executed exactly once as SYSTEM: ' + name)
            if any(is_machine_fact_fqn(fqn) for fqn in user['fqns']):
                raise RuntimeError('MachineFact test ran in the unprivileged account: ' + name)

            required_result_ids = {}
            for class_name, method_name in sorted(required_feature_tests()):
                fqn = class_name + '.' + method_name
                required_result_ids[fqn] = require_required_passed_result_ids(
                    discovered_cases, merged['cases'], merged['results_by_fqn'], fqn, name)
            tests[name] = {'total': merged['total'],
                           'unique_execution_ids': len(merged['execution_ids']),
                           'required_passed_result_ids': required_result_ids}
        if mode + '-release-publish: exit=0 warnings=0 errors=0' not in summary.splitlines():
            raise RuntimeError('Incomplete publish: ' + mode)
        read_gate(summary, mode + '-release-publish: exit=0 warnings=0 errors=0')
        packages[mode] = validate_package(out, mode, summary)
    if any('SafeUploadOwnedWinFspPrototype' in line for line in summary.splitlines()):
        raise RuntimeError('Stale OwnerWinFsp profile identity appeared in matrix evidence.')
    return tests, packages


def create_feature_release_view(work, out, provenance, tests, package_info):
    """Write the old exact-agent artifact names for the verified feature Release output.

    Source identity is the same Git commit as the matrix build.
    """
    view = work / 'feature-release-view'
    view.mkdir(exist_ok=False)
    files = {}

    def copy_verified(source, target_name):
        target = view / target_name
        shutil.copyfile(source, target)
        source_hash = sha(source).upper()
        if sha(target).upper() != source_hash:
            raise RuntimeError('Compatibility view copy hash mismatch: ' + target_name)
        files[target_name] = source_hash
        return target

    copy_verified(out / 'feature-release-service-publish.zip', 'stage-service-publish.zip')
    copy_verified(out / 'feature-release-package-manifest.txt', 'package-manifest.txt')
    copy_verified(out / 'feature-release-results/agent-tests.trx', 'agent-tests.trx')
    copy_verified(out / 'feature-release-results/agent-tests-user.trx', 'agent-tests-user.trx')
    copy_verified(out / 'feature-release-results/agent-tests-system.trx', 'agent-tests-system.trx')
    copy_verified(out / 'feature-release-tests.txt', 'tests.txt')
    copy_verified(out / 'feature-release-tests-user.txt', 'tests-user.txt')
    copy_verified(out / 'feature-release-tests-system.txt', 'tests-system.txt')
    copy_verified(out / 'feature-release-tests-system.txt.stderr', 'tests-system.stderr.txt')
    copy_verified(out / 'feature-release-test-build.txt', 'test-build.txt')
    copy_verified(out / 'feature-release-build.txt', 'build.txt')
    copy_verified(out / 'feature-release-publish.txt', 'publish.txt')
    copy_verified(out / 'dotnet-info.txt', 'dotnet-info.txt')

    test_count = tests['feature-release']['total']
    summary = '\n'.join((
        'ArtifactView=exact-agent-compatible-feature-release',
        MATRIX_PROFILE_ROW,
        'AgentMatrixTestLegs=4',
        *[key + '=' + str(value) for key, value in provenance['BuilderIdentity'].items()],
        'SourceKind=GitCommit',
        'SourceCommit=' + provenance['SourceCommit'],
        'ARCHIVE_SHA256=' + provenance['ArchiveSHA256'].upper(),
        'tests: exit=0 warnings=0',
        'publish: exit=0 warnings=0',
        'tests_passed=' + str(test_count),
        'package_sha256=' + package_info['feature']['sha256'],
        'exe_sha256=' + package_info['feature']['exe_sha256'],
    )) + '\n'
    (view / 'summary.txt').write_text(summary, encoding='utf-8')
    files['summary.txt'] = sha(view / 'summary.txt').upper()
    return view


def matrix_fetch_names(diagnostic_continue):
    names = ['summary.txt', 'dotnet-info.txt']
    for mode in MATRIX_MODES:
        for configuration in ('debug', 'release'):
            name = mode + '-' + configuration
            names += [name + '-build.txt', name + '-app-build.txt', name + '-tests.txt',
                      name + '-test-build.txt', name + '-tests-user.txt',
                      name + '-tests-system.txt', name + '-tests-system.txt.stderr',
                      name + '-tests-discovery-list.txt', name + '-tests-discovery-fqns.txt',
                      name + '-results/agent-tests-discovered-fq.txt',
                      name + '-results/agent-tests.trx',
                      name + '-results/agent-tests-user.trx',
                      name + '-results/agent-tests-system.trx']
        names += [mode + '-release-publish.txt']
        if not diagnostic_continue:
            names += [mode + '-release-package-manifest.txt',
                      mode + '-release-service-publish.zip']
    if diagnostic_continue:
        names = [name for name in names if not name.endswith(('-tests.txt', '/agent-tests.trx'))]
    return names


def diagnostic_completion(out, builder, provenance, result, fetched):
    completed = False
    errors = []
    try:
        summary = (out / 'summary.txt').read_text(encoding='utf-8-sig')
        for row in receipt_lines(builder) + ['AgentMatrixGate=False', 'DiagnosticContinue=True',
                                           MATRIX_PROFILE_ROW, 'AgentMatrixTestLegs=4',
                                           'LabelKind=diagnostic', 'DiagnosticProfilesCompleted=2',
                                           'DiagnosticTestLegsAttempted=4',
                                           'SourceCommit=' + provenance['SourceCommit'],
                                           'ARCHIVE_SHA256=' + provenance['ArchiveSHA256'].upper()]:
            read_gate(summary, row)
        if 'AgentMatrixGate=True' in summary.splitlines():
            raise RuntimeError('Diagnostic summary claims a gate')
        completed = all(row['Fetched'] for row in fetched.values())
    except (OSError, RuntimeError) as exc:
        errors.append(str(exc))
    return {**receipt(builder), 'Provenance': provenance, 'AgentMatrixGate': False,
            'DiagnosticContinue': True, 'LabelKind': 'diagnostic', 'Packages': {},
            'Notice': 'DiagnosticContinue: not a gate', 'DiagnosticCompleted': completed,
            'BuildExit': result, 'Fetched': fetched, 'ReceiptErrors': errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('label')
    parser.add_argument('--commit', default='HEAD')
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--diagnostic-continue', action='store_true',
                        help='Attempt all four feature test legs; never a gate and never fetch packages')
    args = parser.parse_args()
    if not re.fullmatch('[A-Za-z0-9._-]{3,60}', args.label):
        parser.error('invalid label')
    builder = select('matrix', args.label)
    remote_root = 'C:/Users/' + builder['ssh_user'] + '/Documents/'
    remote_dest = builder['ssh_user'] + '@' + builder['host'] + ':' + remote_root
    commit = subprocess.check_output(
        ['git', 'rev-parse', '--verify', args.commit + '^{commit}'], cwd=REPO, text=True).strip()
    work = REPO / 'output' / 'exact-agent-matrix' / args.label
    work.mkdir(parents=True, exist_ok=False)
    subprocess.run(['git', 'archive', '--format=zip', '-o', str(work / 'src.zip'),
                    commit, 'agente'], cwd=REPO, check=True)
    provenance = {'SourceCommit': commit, 'ArchiveSHA256': sha(work / 'src.zip'),
                  'BuilderIdentity': receipt(builder), 'Label': args.label,
                  'Profiles': ['feature-debug', 'feature-release'], 'TestLegs': 4,
                  'LabelKind': 'diagnostic' if args.diagnostic_continue else ('parity' if builder['parity_check'] else 'gate'),
                  'DiagnosticContinue': args.diagnostic_continue,
                  'Notice': ('DiagnosticContinue: not a gate' if args.diagnostic_continue else
                             ('ParityCheck: not a gate' if builder['parity_check'] else 'gate candidate'))}
    evidence = REPO / 'driver' / 'evidence' / datetime.date.today().isoformat()
    evidence.mkdir(parents=True, exist_ok=True)
    prefix = 'exact-agent-matrix-' + args.label

    def retain(name, data):
        path = evidence / (prefix + '-' + name)
        if path.exists():
            raise FileExistsError('Evidence path already exists: ' + str(path))
        path.write_bytes(data)
        return path

    retain('source.txt', ('SourceCommit=' + commit + '\nArchiveSHA256=' + provenance['ArchiveSHA256']
                          + '\n' + '\n'.join(receipt_lines(builder)) + '\nLabel=' + args.label
                          + '\nLabelKind=' + provenance['LabelKind']
                          + '\n' + MATRIX_PROFILE_ROW + '\nAgentMatrixTestLegs=4'
                          + '\nDiagnosticContinue=' + str(args.diagnostic_continue)
                          + '\nNotice=' + provenance['Notice'] + '\n').encode())
    print('SOURCE_COMMIT=' + commit + '; archive=' + str(work / 'src.zip'), flush=True)
    if args.prepare_only:
        print('PREPARED_ONLY; network operations=0', flush=True)
        return

    def remote(ps, name):
        capture_setup = ("[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n"
                         "$OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n")
        result = subprocess.run(['python3', str(REPO / 'driver/scripts/remote_ps.py'),
                                 *remote_args(builder, 'matrix', args.label)],
                                input=(capture_setup + ps).encode('utf-8'),
                                capture_output=True, cwd=REPO)
        retain(name + '.stdout.txt', result.stdout)
        retain(name + '.stderr.txt', result.stderr)
        return result.returncode

    preflight = identity_ps(builder)
    for leaf in (prefix, prefix + '.zip',
                 'Build-ExactAgentMatrix-' + args.label + '.ps1', prefix + '-tools'):
        preflight += "if(Test-Path -LiteralPath '" + remote_root + leaf + "'){throw 'Remote build destination already exists.'}\n"
    if remote(preflight, 'builder-preflight') != 0:
        raise RuntimeError('Builder preflight failed before source delivery')
    if remote("[void](New-Item -ItemType Directory -Path '" + remote_root + prefix + "-tools')", 'tools-directory') != 0:
        raise RuntimeError('Could not create fresh builder tools directory')
    archive_sha = provenance['ArchiveSHA256']
    tool = REPO / 'driver/scripts/Build-ExactAgentMatrix.ps1'
    tool_sha = sha(tool)
    helper_checks = ''
    for local, target in ((work / 'src.zip', prefix + '.zip'),
                          (tool, 'Build-ExactAgentMatrix-' + args.label + '.ps1'),
                          (REPO / 'driver/scripts/ApprovedBuilders.ps1', prefix + '-tools/ApprovedBuilders.ps1'),
                          (REPO / 'driver/scripts/approved-builders.json', prefix + '-tools/approved-builders.json')):
        subprocess.run(['scp', *SSH, str(local), remote_dest + target], check=True)
        if local != work / 'src.zip':
            helper_checks += ("if((Get-FileHash -LiteralPath '" + remote_root + target
                              + "' -Algorithm SHA256).Hash -ne '" + sha(local)
                              + "'){throw 'Uploaded build support hash mismatch.'}\n")
    print('DELIVERED; builder identity and archive delivery verified', flush=True)
    remote_tool = remote_root + 'Build-ExactAgentMatrix-' + args.label + '.ps1'
    builder_parameters = (" -BuilderName '" + builder['name'] + "' -BuilderSupportPath '"
                          + remote_root + prefix + "-tools/ApprovedBuilders.ps1' -BuilderConfigPath '"
                          + remote_root + prefix + "-tools/approved-builders.json'")
    cleanup_selftest = "$ErrorActionPreference='Stop'\n" + helper_checks
    cleanup_selftest += "if((Get-FileHash -LiteralPath '" + remote_tool + "' -Algorithm SHA256).Hash -ne '" + tool_sha + "'){throw 'Uploaded build tool hash mismatch.'}\n"
    cleanup_selftest += "if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Harness parsing requires Windows PowerShell 5.1.'}\n"
    cleanup_selftest += "$parseTokens=$null; $parseErrors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('" + remote_tool + "',[ref]$parseTokens,[ref]$parseErrors); if($parseErrors.Count){throw 'Harness PowerShell 5.1 parse failed.'}; Write-Output 'HARNESS_POWERSHELL51_PARSE=PASS'\n"
    cleanup_selftest += "& '" + remote_tool + "' -Label '" + args.label + "' -ArchiveSha256 '" + archive_sha + "' -SourceCommit '" + commit + "'" + builder_parameters + " -CleanupSelfTestOnly\n"
    selftest_exit = remote(cleanup_selftest, 'system-job-cleanup-selftest')
    selftest_log = evidence / (prefix + '-system-job-cleanup-selftest.stdout.txt')
    if (selftest_exit != 0 or not selftest_log.exists()
            or b'SYSTEM_JOB_CLEANUP_SELFTEST=PASS spawn_record_failure,timeout,descendant_cleanup'
            not in selftest_log.read_bytes() or
            b'PROFILE_OUTPUT_CLEANUP_SELFTEST=PASS source_input_refused,source_and_evidence_retained'
            not in selftest_log.read_bytes() or
            b'HARNESS_POWERSHELL51_PARSE=PASS' not in selftest_log.read_bytes()):
        raise RuntimeError('Builder process-job cleanup self-test failed; matrix execution was not started')
    ps = "$ErrorActionPreference='Stop'\n" + helper_checks
    ps += "if((Get-FileHash -LiteralPath '" + remote_tool + "' -Algorithm SHA256).Hash -ne '" + tool_sha + "'){throw 'Uploaded build tool hash mismatch.'}\n"
    ps += "& '" + remote_tool + "' -Label '" + args.label + "' -ArchiveSha256 '" + archive_sha + "' -SourceCommit '" + commit + "'" + builder_parameters + (" -DiagnosticContinue" if args.diagnostic_continue else '') + "\n"
    result = remote(ps, 'build')
    print('BUILD_RETURNED=' + str(result) + '; collecting retained evidence', flush=True)
    out = work / 'out'
    out.mkdir()
    names = matrix_fetch_names(args.diagnostic_continue)
    fetched = {}
    for name in names:
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        fetch = subprocess.run(['scp', *SSH, remote_dest + prefix + '/out/' + name, str(path)],
                               capture_output=True)
        if fetch.returncode:
            fetched[name] = {'Fetched': False, 'Exit': fetch.returncode}
            continue
        fetched[name] = {'Fetched': True, 'Bytes': path.stat().st_size, 'SHA256': sha(path)}
        if name.endswith('.zip') and path.stat().st_size <= 0:
            raise RuntimeError('Fetched empty package: ' + name)
        retain(name.replace('/', '-'), path.read_bytes())
    retain('fetch-readout.json', (json.dumps({'Provenance': provenance, 'Fetched': fetched}, indent=2) + '\n').encode())
    durations, _ = runpy.run_path(str(Path(__file__).with_name('matrix-durations.py')))['report'](out)
    retain('durations.txt', ('\n'.join(receipt_lines(builder)) + '\nLabel=' + args.label
                            + '\nLabelKind=' + provenance['LabelKind'] + '\nNotice=' + provenance['Notice'] + '\n' + durations + '\n').encode())
    print(durations, flush=True)
    if args.diagnostic_continue:
        diagnostic_readout = diagnostic_completion(out, builder, provenance, result, fetched)
        retain('root-readout.json', (json.dumps(diagnostic_readout, indent=2) + '\n').encode())
        print('DiagnosticContinue: not a gate; AgentMatrixGate=False; DiagnosticContinue=True', flush=True)
        if not diagnostic_readout['DiagnosticCompleted'] or result != 0:
            raise RuntimeError('Diagnostic run has failures or incomplete receipts; inspect retained evidence')
        return
    if result != 0 or not all(row['Fetched'] for row in fetched.values()):
        raise RuntimeError('Build or evidence retrieval incomplete; inspect retained logs')
    summary = (out / 'summary.txt').read_text(encoding='utf-8-sig')
    for row in receipt_lines(builder):
        read_gate(summary, row)
    read_gate(summary, 'SourceCommit=' + commit)
    read_gate(summary, 'ARCHIVE_SHA256=' + archive_sha.upper())
    if builder['parity_check']:
        read_gate(summary, 'AgentMatrixGate=False')
        tests, packages = verify_matrix_outputs(out, summary)
        retain('root-readout.json', (json.dumps({'Provenance': provenance, **receipt(builder),
               'AgentMatrixGate': False, 'Tests': tests, 'Packages': packages,
               'Notice': 'ParityCheck: not a gate'}, indent=2) + '\n').encode())
        print('ParityCheck=True; not a gate; AgentMatrixGate=False; ' + json.dumps(tests), flush=True)
        return
    if 'AgentMatrixGate=True' not in summary.splitlines():
        raise RuntimeError('Matrix completion sentinel missing')
    tests, packages = verify_matrix_outputs(out, summary)
    feature_view = create_feature_release_view(work, out, provenance, tests, packages)
    feature_zip = feature_view / 'stage-service-publish.zip'
    if sha(feature_zip).upper() != packages['feature']['sha256']:
        raise RuntimeError('Feature compatibility package differs from the independently validated matrix package.')
    retain('feature-release-view-summary.txt', (feature_view / 'summary.txt').read_bytes())
    readout = {'UTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               **receipt(builder), 'DiagnosticContinue': False,
               'AgentMatrixGate': 'PASS', 'Tests': tests, 'Packages': packages,
               'FeatureReleaseCompatibilityView': str(feature_view),
               'FeatureReleaseZip': str(feature_zip), 'Provenance': provenance,
               'Fetched': fetched, 'ServiceInstalled': False, 'RuntimeQualification': False,
               'GitMutation': False}
    retain('root-readout.json', (json.dumps(readout, indent=2) + '\n').encode())
    print('ExactAgentMatrixGate=PASS; ' + json.dumps(tests), flush=True)
    print('FEATURE_RELEASE_ZIP=' + str(feature_zip), flush=True)


if __name__ == '__main__':
    main()
