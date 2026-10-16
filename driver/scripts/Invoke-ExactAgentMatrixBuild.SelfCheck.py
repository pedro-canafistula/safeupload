#!/usr/bin/env python3
"""Exercise required v20 cases with synthetic matrix artifacts, never a builder."""
import hashlib
from pathlib import Path
import sys
import tempfile
import types
import unittest
import uuid
import xml.etree.ElementTree as ET
import zipfile

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name('Invoke-ExactAgentMatrixBuild.py')
gate = types.ModuleType('exact_matrix_v20_gate_under_test')
gate.__file__ = str(SCRIPT)
exec(compile(SCRIPT.read_bytes(), str(SCRIPT), 'exec'), gate.__dict__)

STAGED = {
    'SafeUpload.Agent.Tests.StagedAttachmentV20Tests.' + method
    for method in (
        'V20_attachment_order_blocks_seal_until_handle_receipt_and_allows_positive_save',
        'V20_retire_unexposed_uses_exact_background_delete_ack_and_replays_op16',
        'V20_retire_attached_private_requires_measured_zero_and_exact_ack',
        'V20_epoch_drain_replay_is_exact_and_does_not_reauthorize_a_different_tuple',
        'V20_epoch_rejects_unpaired_drain_receipts_without_rewriting_them',
        'Ordinary_empty_profile_rejects_old_capabilities_before_accepting_an_epoch',
        'Legacy_empty_migration_requires_fresh_exact_content_and_reconciled_obligations')
} | {
    'SafeUpload.Agent.Tests.StagedTransferAllocatorTests.' + method
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
    'SafeUpload.Agent.Tests.StagedTransferJournalTests.' +
    'V19_unattached_allocation_cleanup_cannot_discard_a_sealed_version',
    'SafeUpload.Agent.Tests.StagedTransferJournalTests.Exact_private_discard_can_finish_after_a_newer_ordinary_allocation_without_touching_it',
    'SafeUpload.Agent.Tests.StagedTransferJournalTests.Empty_stage_is_measured_sealed_with_the_empty_digest_and_reserved_state_cannot_be_forged',
    'SafeUpload.Agent.Tests.StagedTransferPublisherTests.Measured_empty_content_publishes_normally_without_extraction_or_private_notice',
    'SafeUpload.Agent.Tests.StagedTransferPublisherTests.Changed_length_cannot_turn_a_measured_version_into_an_implicit_empty_approval',
    'SafeUpload.Agent.Tests.StagedTransferPublisherTests.Empty_publication_still_requires_the_kernel_permit',
    'SafeUpload.Agent.Tests.StagedInspectionFailureTests.Trivial_empty_inspection_measures_content_instead_of_trusting_declared_size'
}
ENDPOINT = 'SafeUpload.Agent.Tests.AdmissionEvidenceEndpointTests.'
FEATURE = {
    'SafeUpload.Agent.Tests.AdmissionEvidenceWireTests.' + method
    for method in (
        'Managed_status_mirrors_match_driver_sizes_and_offsets',
        'Input_allows_only_readonly_status_commands_and_bounded_start_indices',
        'Native_failure_keeps_hresult_and_never_exposes_zeroed_reply_buffer',
        'Diagnostic_sends_on_one_port_are_serialized',
        'Dispose_drains_an_inflight_diagnostic_send_and_rejects_later_sends')
} | {
    ENDPOINT + method for method in (
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
        'BackpressureDeadlineCancelsCaptureAndTerminalizesReservedHook')
}
SYSTEM = {
    'SafeUpload.Agent.Tests.' + family + '.SyntheticSystemCase'
    for family in ('MachineCertificateAuthorityTests', 'TlsInspectionProxyTests', 'TrafficDiversionTests')
}
PROFILES = ('feature-debug', 'feature-release')
NS = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'
EPOCH_THEORY = ('SafeUpload.Agent.Tests.StagedTransferAllocatorTests.'
                'V20_create_after_rejects_identityless_or_different_epoch_v1_before_child_intent')
LEGACY_CREATE_AFTER = ('SafeUpload.Agent.Tests.StagedTransferAllocatorTests.'
                       'Legacy_v19_create_after_preserves_all_legacy_chain_and_rejects_mixed_epoch_request')
OP19_CREATE_AFTER_THEORY = ('SafeUpload.Agent.Tests.StagedTransferAllocatorTests.'
                            'V20_create_after_requires_exact_op19_before_any_journal_mutation')
NEW_REQUIRED_CASES = {
    LEGACY_CREATE_AFTER: (None,),
    OP19_CREATE_AFTER_THEORY: ('receiptShape: "missing"', 'receiptShape: "pending"',
                                'receiptShape: "wrong-receipt-tuple"'),
}
REQUIRED_CASES = {
    EPOCH_THEORY: ('parentEpochShape: "identityless"', 'parentEpochShape: "different-epoch"'),
    **NEW_REQUIRED_CASES,
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def write_trx(path, profile, cases, skipped=None):
    root = ET.Element('{' + NS + '}TestRun')
    summary = ET.SubElement(root, '{' + NS + '}ResultSummary')
    ET.SubElement(summary, '{' + NS + '}Counters', total=str(len(cases)),
        executed=str(len(cases)), passed=str(len(cases) - bool(skipped)),
        notExecuted=str(int(bool(skipped))))
    definitions = ET.SubElement(root, '{' + NS + '}TestDefinitions')
    results = ET.SubElement(root, '{' + NS + '}Results')
    for fqn in sorted({fqn for fqn, _ in cases}):
        identity = str(uuid.uuid5(uuid.NAMESPACE_URL, profile + '/test/' + fqn))
        unit = ET.SubElement(definitions, '{' + NS + '}UnitTest', id=identity)
        cls, method = fqn.rsplit('.', 1)
        ET.SubElement(unit, '{' + NS + '}TestMethod', className=cls, name=method)
    seen_displays = {}
    for fqn, display in cases:
        occurrence = seen_displays.get(display, 0)
        seen_displays[display] = occurrence + 1
        result_seed = profile + '/result/' + display
        if occurrence:
            result_seed += '/duplicate/' + str(occurrence)
        ET.SubElement(results, '{' + NS + '}UnitTestResult',
            testId=str(uuid.uuid5(uuid.NAMESPACE_URL, profile + '/test/' + fqn)),
            executionId=str(uuid.uuid5(uuid.NAMESPACE_URL, result_seed)),
            testName=display, outcome='NotExecuted' if (fqn, display) == skipped else 'Passed')
    path.write_bytes(ET.tostring(root, encoding='utf-8', xml_declaration=True))


def make_matrix(out, omitted=None, skip_profile=None, omitted_case=None, replaced_case=None,
                omitted_required_case=None, replaced_required_case=None,
                duplicated_required_case=None):
    rows = ['AgentMatrixProfiles=feature-debug,feature-release', 'AgentMatrixTestLegs=4']
    for profile in PROFILES:
        mode = profile.split('-')[0]
        methods = STAGED | SYSTEM | FEATURE
        if omitted and omitted[0] == profile:
            methods = methods - {omitted[1]}
        cases = []
        for fqn in sorted(methods):
            if fqn == EPOCH_THEORY:
                for value in ('identityless', 'different-epoch'):
                    if omitted_case == (profile, value):
                        continue
                    argument = ('different_epoch' if replaced_case == (profile, value) else value)
                    cases.append((fqn, fqn + '(parentEpochShape: "' + argument + '")'))
            elif fqn == OP19_CREATE_AFTER_THEORY:
                for argument in NEW_REQUIRED_CASES[fqn]:
                    target = (profile, fqn, argument)
                    if omitted_required_case == target:
                        continue
                    display_argument = ('receiptShape: "unreviewed"'
                                        if replaced_required_case == target else argument)
                    case = (fqn, fqn + '(' + display_argument + ')')
                    cases.append(case)
                    if duplicated_required_case == target:
                        cases.append(case)
            elif fqn == LEGACY_CREATE_AFTER:
                target = (profile, fqn, None)
                if omitted_required_case == target:
                    continue
                display = (fqn + '(unexpected: "value")'
                           if replaced_required_case == target else fqn)
                case = (fqn, display)
                cases.append(case)
                if duplicated_required_case == target:
                    cases.append(case)
            else:
                cases.append((fqn, fqn))
        result_dir = out / (profile + '-results')
        result_dir.mkdir()
        (result_dir / 'agent-tests-discovered-fq.txt').write_text('\n'.join(sorted(methods)) + '\n')
        (out / (profile + '-tests-discovery-list.txt')).write_text(
            'VSTest version SYNTHETIC\n\nThe following Tests are available:\n' +
            ''.join('    ' + display + '\n' for _, display in cases))
        skipped = next((case for case in cases if case[0] in STAGED), None) if skip_profile == profile else None
        user = [case for case in cases if case[0] not in SYSTEM]
        system = [case for case in cases if case[0] in SYSTEM]
        write_trx(result_dir / 'agent-tests-user.trx', profile, user, skipped)
        write_trx(result_dir / 'agent-tests-system.trx', profile, system)
        write_trx(result_dir / 'agent-tests.trx', profile, cases, skipped)
        (out / (profile + '-tests-system.txt')).write_text(
            'SYSTEM_TEST_TASK_SID=S-1-5-18\nSYSTEM_TEST_JOB_CLEANUP=active_processes=0\n'
            'SYSTEM_TEST_TASK_CLEANUP=task_absent,job_empty,wrapper_absent\n')
        rows.append(profile + ': admission_evidence=' + ('true' if mode == 'feature' else 'false'))
        for action in ('build', 'app-build', 'test-build', 'tests-discovery-list', 'tests-discovery-fqns', 'tests-user', 'tests-system', 'tests'):
            rows.append(profile + '-' + action + ': exit=0 warnings=0 errors=0')
        rows.extend((profile + '-tests-user-identity: name=BUILDER\\vika sid=S-1-5-21-1-2-3-1001',
                     profile + '-tests-system-identity: S-1-5-18'))
    for mode in ('feature',):
        name = mode + '-release'
        package = out / (name + '-service-publish.zip')
        payload = b'SYNTHETIC NONEXECUTABLE PACKAGE FIXTURE'
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('SafeUpload.Agent.Service.exe', payload)
        manifest = out / (name + '-package-manifest.txt')
        manifest.write_text(hashlib.sha256(payload).hexdigest() + '  SafeUpload.Agent.Service.exe\n')
        rows.extend((name + '-publish: exit=0 warnings=0 errors=0',
            name + ': package_sha256=' + digest(package),
            name + ': exe_sha256=' + hashlib.sha256(payload).hexdigest().upper(),
            name + ': package_manifest_sha256=' + digest(manifest)))
    return '\n'.join(rows)


class RequiredV20MatrixControls(unittest.TestCase):
    def test_complete_synthetic_matrix_binds_every_v20_case_and_result_id(self):
        with tempfile.TemporaryDirectory(prefix='matrix-v20-positive-') as temporary:
            out = Path(temporary)
            tests, _ = gate.verify_matrix_outputs(out, make_matrix(out))
            self.assertEqual(set(PROFILES), set(tests))
            gate_staged = {class_name + '.' + method_name
                           for class_name, method_name in gate.STAGED_V20_REQUIRED_TESTS}
            self.assertEqual(STAGED, gate_staged)
            self.assertEqual(REQUIRED_CASES, gate.STAGED_V20_REQUIRED_CASES)
            self.assertEqual(26, len(STAGED))
            for profile in PROFILES:
                required = tests[profile]['required_passed_result_ids']
                self.assertTrue(STAGED <= required.keys())
                for fqn in STAGED:
                    self.assertEqual(len(REQUIRED_CASES.get(fqn, (None,))),
                                     len(required[fqn]), (profile, fqn))

    def test_each_exact_epoch_theory_case_is_required_despite_consistent_discovery_and_trx_omission(self):
        for profile in PROFILES:
            for value in ('identityless', 'different-epoch'):
                with self.subTest(profile=profile, value=value):
                    with tempfile.TemporaryDirectory(prefix='matrix-v20-case-omission-') as temporary:
                        out = Path(temporary)
                        summary = make_matrix(out, omitted_case=(profile, value))
                        with self.assertRaisesRegex(RuntimeError, 'Mandatory v20 theory cases differ'):
                            gate.verify_matrix_outputs(out, summary)

    def test_wrong_epoch_argument_cannot_replace_the_reviewed_case(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                with tempfile.TemporaryDirectory(prefix='matrix-v20-case-substitution-') as temporary:
                    out = Path(temporary)
                    summary = make_matrix(out, replaced_case=(profile, 'different-epoch'))
                    with self.assertRaisesRegex(RuntimeError, 'Mandatory v20 theory cases differ'):
                        gate.verify_matrix_outputs(out, summary)

    def test_each_new_required_case_is_rejected_when_consistently_omitted(self):
        for profile in PROFILES:
            for fqn, arguments in NEW_REQUIRED_CASES.items():
                for argument in arguments:
                    target = (profile, fqn, argument)
                    with self.subTest(profile=profile, fqn=fqn, argument=argument), \
                            tempfile.TemporaryDirectory(prefix='matrix-v20-new-case-omission-') as temporary:
                        out = Path(temporary)
                        summary = make_matrix(out, omitted_required_case=target)
                        with self.assertRaises(RuntimeError):
                            gate.verify_matrix_outputs(out, summary)

    def test_each_new_required_case_rejects_a_wrong_public_argument(self):
        for profile in PROFILES:
            for fqn, arguments in NEW_REQUIRED_CASES.items():
                for argument in arguments:
                    target = (profile, fqn, argument)
                    with self.subTest(profile=profile, fqn=fqn, argument=argument), \
                            tempfile.TemporaryDirectory(prefix='matrix-v20-new-case-substitution-') as temporary:
                        out = Path(temporary)
                        summary = make_matrix(out, replaced_required_case=target)
                        with self.assertRaisesRegex(RuntimeError, 'Mandatory v20 theory cases differ'):
                            gate.verify_matrix_outputs(out, summary)

    def test_each_new_required_case_rejects_a_consistent_duplicate_display_row(self):
        for profile in PROFILES:
            for fqn, arguments in NEW_REQUIRED_CASES.items():
                for argument in arguments:
                    target = (profile, fqn, argument)
                    with self.subTest(profile=profile, fqn=fqn, argument=argument), \
                            tempfile.TemporaryDirectory(prefix='matrix-v20-new-case-duplicate-') as temporary:
                        out = Path(temporary)
                        summary = make_matrix(out, duplicated_required_case=target)
                        with self.assertRaisesRegex(RuntimeError, 'Mandatory v20 theory cases differ'):
                            gate.verify_matrix_outputs(out, summary)

    def test_every_v20_method_is_required_in_each_profile_even_when_all_discovered_cases_pass(self):
        for profile in PROFILES:
            for fqn in sorted(STAGED):
                with self.subTest(profile=profile, omitted=fqn), tempfile.TemporaryDirectory(prefix='matrix-v20-missing-') as temporary:
                    out = Path(temporary)
                    expected_error = ('Mandatory v20 theory cases differ' if fqn in REQUIRED_CASES
                                      else 'no exact discovered cases')
                    with self.assertRaisesRegex(RuntimeError, expected_error):
                        gate.verify_matrix_outputs(out, make_matrix(out, omitted=(profile, fqn)))

    def test_skipped_required_case_cannot_pass_any_profile(self):
        for profile in PROFILES:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(prefix='matrix-v20-skipped-') as temporary:
                out = Path(temporary)
                with self.assertRaisesRegex(RuntimeError, 'skipped, warning, or failed TRX leg'):
                    gate.verify_matrix_outputs(out, make_matrix(out, skip_profile=profile))

    def test_every_feature_requirement_survives(self):
        for profile in PROFILES:
            for fqn in FEATURE:
                with self.subTest(profile=profile, fqn=fqn), tempfile.TemporaryDirectory() as temporary:
                    out = Path(temporary)
                    with self.assertRaises(RuntimeError):
                        gate.verify_matrix_outputs(out, make_matrix(out, omitted=(profile, fqn)))

    def feature_contract(self, module):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            summary = make_matrix(out)
            tests, packages = module.verify_matrix_outputs(out, summary)
            self.assertEqual(set(PROFILES), set(tests))
            self.assertEqual({'feature'}, set(packages))
            for profile in PROFILES:
                # Normal rows cannot replace a missing feature profile or account leg.
                for row in (profile + ': admission_evidence=true',
                            profile + '-tests-system: exit=0 warnings=0 errors=0',
                            profile + '-tests-user: exit=0 warnings=0 errors=0'):
                    changed = summary.replace(row, row.replace('feature-', 'normal-'))
                    with self.assertRaises(RuntimeError):
                        module.verify_matrix_outputs(out, changed)
                for account in ('user', 'system'):
                    path = out / (profile + '-results') / ('agent-tests-' + account + '.trx')
                    data = path.read_bytes()
                    path.unlink()
                    with self.assertRaises(OSError):
                        module.verify_matrix_outputs(out, summary)
                    path.write_bytes(data)
            for row in ('AgentMatrixProfiles=feature-debug,feature-release', 'AgentMatrixTestLegs=4'):
                with self.assertRaises(RuntimeError):
                    module.verify_matrix_outputs(out, summary.replace(row, ''))
        for profile in PROFILES:
            with tempfile.TemporaryDirectory() as temporary:
                out = Path(temporary)
                fqn = ENDPOINT + 'EvidenceTypesExistOnlyInFeatureBuilds'
                with self.assertRaises(RuntimeError):
                    module.verify_matrix_outputs(out, make_matrix(out, omitted=(profile, fqn)))
        names = module.matrix_fetch_names(False)
        self.assertFalse(any('normal-' in name for name in names))
        for profile in PROFILES:
            for account in ('user', 'system'):
                self.assertIn(profile + '-results/agent-tests-' + account + '.trx', names)
        self.assertIn('feature-release-service-publish.zip', names)

    def test_feature_guards_and_mutations(self):
        self.feature_contract(gate)
        source = SCRIPT.read_text()
        mutations = [
            ("MATRIX_MODES = ('feature',)", "MATRIX_MODES = ('normal', 'feature')"),
            ("for configuration in ('debug', 'release'):", "for configuration in ('debug',):"),
            ("for configuration in ('debug', 'release'):", "for configuration in ('release',):"),
            ("sorted(required_feature_tests())", "sorted(())"),
            ("'tests-user', 'tests-system', 'tests')", "'tests-user', 'tests')"),
            ("'tests-user', 'tests-system', 'tests')", "'tests-system', 'tests')"),
            ('read_gate(summary, MATRIX_PROFILE_ROW)', 'pass'),
            ("read_gate(summary, 'AgentMatrixTestLegs=4')", 'pass'),
        ]
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                mutant = types.ModuleType('feature_matrix_mutant')
                mutant.__file__ = str(SCRIPT)
                exec(compile(source.replace(old, new), str(SCRIPT), 'exec'), mutant.__dict__)
                with self.assertRaises((AssertionError, RuntimeError, OSError)):
                    self.feature_contract(mutant)


# New runner controls use fake transports only; they never contact a builder.
import base64
import contextlib
import io
import json
import os
import runpy
import subprocess
from unittest import mock
import approved_builders as approved


def wrapper_fixture(source=None, builder_name='builder1', diagnostic=False, build_exit=0, bad_identity=False):
    """Execute the real wrapper including its final verdict against retained fixtures."""
    module = types.ModuleType('matrix_wrapper_control')
    module.__file__ = str(SCRIPT)
    exec(compile(source or SCRIPT.read_text(), str(SCRIPT), 'exec'), module.__dict__)
    with tempfile.TemporaryDirectory(prefix='matrix-wrapper-') as temporary:
        root = Path(temporary)
        module.REPO = root
        scripts = root / 'driver/scripts'
        scripts.mkdir(parents=True)
        for leaf in ['Build-ExactAgentMatrix.ps1', 'ApprovedBuilders.ps1', 'approved-builders.json']:
            (scripts / leaf).write_bytes(b'fixture')
        remote = root / 'remote'
        remote.mkdir()
        summary = make_matrix(remote)
        label = 'parity-fixture' if builder_name == 'builder2' else 'fixture-control'
        builder = approved.select('matrix', label, name=builder_name)
        identity = approved.receipt_lines(builder)
        if bad_identity:
            identity[0] = 'Builder=other'
        summary += '\n' + '\n'.join(identity) + '\nSourceCommit=' + 'a' * 40
        summary += '\nARCHIVE_SHA256=' + hashlib.sha256(b'archive').hexdigest().upper()
        summary += '\nAgentMatrixGate=' + ('False' if diagnostic or builder_name == 'builder2' else 'True')
        if diagnostic:
            summary += '\nDiagnosticContinue=True\nLabelKind=diagnostic\nDiagnosticProfilesCompleted=2\nDiagnosticTestLegsAttempted=4'
        (remote / 'summary.txt').write_text(summary + '\n')
        (remote / 'dotnet-info.txt').write_text('fixture')
        # Populate captured logs independently of the production fetch selector.
        for profile in PROFILES:
            for suffix in ['-build.txt', '-app-build.txt', '-tests.txt', '-test-build.txt', '-tests-user.txt',
                           '-tests-system.txt.stderr', '-tests-discovery-fqns.txt', '-publish.txt']:
                (remote / (profile + suffix)).write_text('fixture log')
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            if command[:2] == ['git', 'archive']:
                Path(command[command.index('-o') + 1]).write_bytes(b'archive')
            elif command[0] == 'python3':
                script = kwargs['input'].decode()
                if '-CleanupSelfTestOnly' in script:
                    return subprocess.CompletedProcess(command, 0,
                        b'HARNESS_POWERSHELL51_PARSE=PASS\n'
                        b'SYSTEM_JOB_CLEANUP_SELFTEST=PASS spawn_record_failure,timeout,descendant_cleanup\n'
                        b'PROFILE_OUTPUT_CLEANUP_SELFTEST=PASS source_input_refused,source_and_evidence_retained\n', b'')
                if " -SourceCommit '" in script:
                    if diagnostic and '-DiagnosticContinue' not in script:
                        raise AssertionError('Diagnostic flag was not delivered to PowerShell')
                    return subprocess.CompletedProcess(command, build_exit, b'build fixture', b'')
            elif command[0] == 'scp' and ':C:/' in command[-2]:
                name = command[-2].split('/out/', 1)[1]
                path = remote / name
                if not path.exists():
                    return subprocess.CompletedProcess(command, 1, b'', b'missing fixture')
                Path(command[-1]).write_bytes(path.read_bytes())
            return subprocess.CompletedProcess(command, 0, b'', b'')

        stdout = io.StringIO()
        error = None
        argv = [str(SCRIPT), label, '--commit', 'a' * 40] + (['--diagnostic-continue'] if diagnostic else [])
        with mock.patch.dict(os.environ, {'SAFEUPLOAD_BUILDER': builder_name}), \
                mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(subprocess, 'check_output', return_value='a' * 40), \
                mock.patch.object(subprocess, 'run', side_effect=fake_run), contextlib.redirect_stdout(stdout):
            try:
                module.main()
            except (RuntimeError, AssertionError) as exc:
                error = exc
        receipts = {p.name: p.read_text() for p in (root / 'driver/evidence').rglob('*') if p.is_file() and (p.name.endswith('.json') or p.name.endswith('-source.txt') or p.name.endswith('-view-summary.txt'))}
        return stdout.getvalue(), calls, receipts, error


class RunnerModeControls(unittest.TestCase):
    def setUp(self):
        # Exercise the unapproved state even after a later manual, evidenced
        # promotion of builder2. Never edit the real approved-builder list.
        temporary = tempfile.TemporaryDirectory(prefix='approved-builder-controls-')
        self.addCleanup(temporary.cleanup)
        config = json.loads(approved.CONFIG.read_text())
        for row in config['builders']:
            if row['name'] == 'builder2':
                row['gate_approved'] = False
                row['roles'] = ['matrix', 'gate']  # role guard keeps a non-signing builder (owner gave builder2 kernel-sign 2026-10-15)
        fixture = Path(temporary.name) / 'approved-builders.json'
        fixture.write_text(json.dumps(config))
        patch = mock.patch.object(approved, 'CONFIG', fixture)
        patch.start()
        self.addCleanup(patch.stop)

    def test_default_builder_and_roles(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            one = approved.select('matrix', 'control-default')
        self.assertEqual(('builder1', '192.168.122.210', 'DESKTOP-O1LP5DG', 'vika', True),
                         tuple(one[k] for k in ['name', 'host', 'computer_name', 'ssh_user', 'gate_approved']))
        for role in ('kernel-sign', 'matrix', 'gate'):
            self.assertEqual('builder1', approved.select(role, 'control', name='builder1')['name'])
        for name, role, label in [('unknown', 'matrix', 'control'), ('builder2', 'kernel-sign', 'parity-control'),
                                  ('builder2', 'matrix', 'ordinary-control'), ('builder2', 'gate', 'ordinary-control')]:
            with self.subTest(name=name, role=role), self.assertRaises(ValueError):
                approved.select(role, label, name=name)
        self.assertFalse(approved.select('gate', 'parity-control', name='builder2')['gate_approved'])
        ps = approved.identity_ps(one)
        for expected in ('DESKTOP-O1LP5DG', 'C6440689-D11C-4C63-A463-F3722B7DDB69', '52-54-00-63-87-7A'):
            self.assertIn(expected, ps)

    def test_remote_refuses_before_caller_or_upload(self):
        remote = SCRIPT.with_name('remote_ps.py')
        for args, name, code in [(['192.168.122.210', '--role', 'matrix', '--label', 'parity-control'], 'builder2', 0),
                                 (['192.168.122.211', '--role', 'kernel-sign', '--label', 'parity-control'], 'builder2', 0),
                                 (['192.168.122.211', '--role', 'gate', '--label', 'control'], 'builder2', 0),
                                 (['192.168.122.210', '--role', 'matrix', '--label', 'control'], 'unknown', 0),
                                 (['192.168.122.210', '--role', 'matrix', '--label', 'control'], 'builder1', 1),
                                 (['192.168.122.210', '--role', 'matrix', '--label', 'control'], 'builder1', 255)]:
            with self.subTest(args=args, builder=name, exit=code):
                fake_stdout, fake_stderr = io.TextIOWrapper(io.BytesIO()), io.TextIOWrapper(io.BytesIO())
                with mock.patch.dict(os.environ, {'SAFEUPLOAD_BUILDER': name}), \
                        mock.patch.object(sys, 'argv', [str(remote), *args]), \
                        mock.patch.object(sys, 'stdin', io.StringIO('Write-Output CALLER_WORK\n' * 500)), \
                        mock.patch.object(sys, 'stdout', fake_stdout), mock.patch.object(sys, 'stderr', fake_stderr), \
                        mock.patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], code, b'', b'')) as checked, \
                        mock.patch.object(subprocess, 'call') as work:
                    with self.assertRaises((SystemExit, ValueError)):
                        runpy.run_path(str(remote), run_name='__main__')
                    work.assert_not_called()
                    if code:
                        self.assertEqual(1, checked.call_count)
                        command = checked.call_args.args[0]
                        self.assertIn('StrictHostKeyChecking=yes', command)
                        script = base64.b64decode(command[-1].split()[-1]).decode('utf-16le')
                        self.assertIn('Wrong builder', script)
                        self.assertNotIn('CALLER_WORK', script)
                    else:
                        checked.assert_not_called()

    def test_standalone_debuggee_transport_keeps_its_old_dependencies(self):
        with tempfile.TemporaryDirectory(prefix='debuggee-transport-') as temporary:
            script = Path(temporary) / 'remote_ps.py'
            script.write_bytes(SCRIPT.with_name('remote_ps.py').read_bytes())
            (script.parent / 'debuggees.txt').write_text('win10-debug3 192.168.122.200\n')
            with mock.patch.dict(sys.modules, {'approved_builders': None}), \
                    mock.patch.object(sys, 'argv', [str(script), '192.168.122.200']), \
                    mock.patch.object(sys, 'stdin', io.StringIO('Write-Output fixture')), \
                    mock.patch.object(subprocess, 'call', return_value=0) as remote:
                with self.assertRaises(SystemExit) as result:
                    runpy.run_path(str(script), run_name='__main__')
                self.assertEqual(0, result.exception.code)
                self.assertEqual(1, remote.call_count)
                self.assertIn('StrictHostKeyChecking=yes', remote.call_args.args[0])

    def assert_wrapper(self, source=None, diagnostic=False, builder='builder1', build_exit=0):
        output, calls, receipts, error = wrapper_fixture(source, builder, diagnostic, build_exit)
        if build_exit:
            self.assertIsInstance(error, RuntimeError)
        else:
            self.assertIsNone(error)
        self.assertTrue(receipts)
        sources = [v for k, v in receipts.items() if k.endswith('-source.txt')]
        self.assertEqual(1, len(sources))
        for row in approved.receipt_lines(approved.select('matrix', 'parity-fixture' if builder == 'builder2' else 'fixture-control', name=builder)):
            self.assertIn(row, sources[0])
        roots = [json.loads(v) for k, v in receipts.items() if k.endswith('-root-readout.json')]
        self.assertEqual(1, len(roots))
        root = roots[0]
        self.assertEqual(builder, root['Builder'])
        self.assertEqual(list(PROFILES), root['Provenance']['Profiles'])
        self.assertEqual(4, root['Provenance']['TestLegs'])
        self.assertIn('AgentMatrixProfiles=feature-debug,feature-release', sources[0])
        self.assertFalse(any(c[0] == 'scp' and ':C:/' in c[-2] and 'normal-' in c[-2] for c in calls))
        if diagnostic:
            self.assertTrue(root['DiagnosticCompleted'])
            self.assertIn('DiagnosticContinue: not a gate', output)
            self.assertIn('DiagnosticContinue=True', output)
            self.assertIn('AgentMatrixGate=False', output)
            self.assertFalse(root['AgentMatrixGate'])
            self.assertTrue(root['DiagnosticContinue'])
            self.assertEqual('diagnostic', root['LabelKind'])
            self.assertEqual({}, root['Packages'])
            self.assertIn('LabelKind=diagnostic', sources[0])
            self.assertFalse(any(c[0] == 'scp' and ':C:/' in c[-2] and
                                 ('package-manifest' in c[-2] or c[-2].endswith('.zip')) for c in calls))
        if diagnostic or builder == 'builder2':
            self.assertNotIn('ExactAgentMatrixGate=PASS', output)
            self.assertNotIn('FEATURE_RELEASE_ZIP=', output)
        else:
            self.assertIn('ExactAgentMatrixGate=PASS', output)
            view = next(v for k, v in receipts.items() if k.endswith('-view-summary.txt'))
            for row in approved.receipt_lines(approved.select('matrix', 'control', name=builder)):
                self.assertIn(row, view)
        if builder == 'builder2':
            self.assertIn('not a gate', output)
            self.assertTrue(root['ParityCheck'])
        return calls

    def test_wrapper_modes_and_receipts_even_after_failure(self):
        self.assert_wrapper()
        self.assert_wrapper(diagnostic=True)
        self.assert_wrapper(diagnostic=True, build_exit=1)
        self.assert_wrapper(builder='builder2')
        self.assert_wrapper(diagnostic=True, builder='builder2')

    def test_builder_receipt_mismatch_refuses_gate(self):
        output, _, _, error = wrapper_fixture(bad_identity=True)
        self.assertIsInstance(error, RuntimeError)
        self.assertNotIn('ExactAgentMatrixGate=PASS', output)

    def test_wrapper_guard_mutations_are_caught(self):
        source = SCRIPT.read_text()
        mutations = [
            ("if args.diagnostic_continue:\n        diagnostic_readout", "if False:\n        diagnostic_readout", True, 'builder1'),
            ("if not diagnostic_continue:\n            names +=", "if True:\n            names +=", True, 'builder1'),
            ("if builder['parity_check']:\n        read_gate", "if False:\n        read_gate", False, 'builder2'),
            ("'DiagnosticContinue: not a gate; AgentMatrixGate=False; DiagnosticContinue=True'", "'diagnostic'", True, 'builder1'),
            ("'AgentMatrixGate': False,\n            'DiagnosticContinue': True", "'AgentMatrixGate': True,\n            'DiagnosticContinue': True", True, 'builder1'),
            ("'BuilderIdentity': receipt(builder)", "'BuilderIdentity': {}", False, 'builder1'),
            ("+ '\\n' + '\\n'.join(receipt_lines(builder))", "+ '\\n'", False, 'builder1'),
        ]
        for old, new, diagnostic, builder in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                with self.assertRaises(AssertionError):
                    self.assert_wrapper(source.replace(old, new), diagnostic=diagnostic, builder=builder)

    def test_selection_guard_mutations_are_caught(self):
        path = SCRIPT.with_name('approved_builders.py')
        source = path.read_text()

        def contract(module):
            with mock.patch.dict(os.environ, {}, clear=True):
                one = module.select('matrix', 'ordinary-control')
                self.assertEqual('builder1', one['name'])
            for name, role, label in [('unknown', 'matrix', 'ordinary-control'),
                                      ('builder2', 'kernel-sign', 'parity-control'),
                                      ('builder2', 'matrix', 'ordinary-control')]:
                with self.assertRaises(ValueError):
                    module.select(role, label, name=name)
            one = module.select('matrix', 'ordinary-control', name='builder1')
            rows = module.receipt(one)
            self.assertEqual({'Builder': 'builder1', 'BuilderHost': '192.168.122.210',
                              'BuilderComputerName': 'DESKTOP-O1LP5DG', 'ParityCheck': False}, rows)
            for name in ('builder1', 'builder2'):
                self.assertTrue(module.receipt(module.select('matrix', 'parity-control', name=name))['ParityCheck'])
            identity = module.identity_ps(one)
            for item in ['DESKTOP-O1LP5DG', 'C6440689-D11C-4C63-A463-F3722B7DDB69', '52-54-00-63-87-7A']:
                self.assertIn(item, identity)
            self.assertIn('StrictHostKeyChecking=yes', module.SSH)

        contract(approved)
        changes = [
            ("get('SAFEUPLOAD_BUILDER', 'builder1')", "get('SAFEUPLOAD_BUILDER', 'builder2')"),
            ('if len(matches) != 1:', 'if False:'),
            ("if role not in row['roles']:", 'if False:'),
            ("if not row['gate_approved'] and not label.startswith('parity-'):", 'if False:'),
            ("'BuilderHost': builder['host']", "'WrongHost': builder['host']"),
            ("'BuilderComputerName': builder['computer_name']", "'WrongName': builder['computer_name']"),
            ("'parity_check': label.startswith('parity-')", "'parity_check': False"),
            ("checks = [\"$env:COMPUTERNAME -ine '\" + builder['computer_name'] + \"'\"]", "checks = ['$false']"),
            ("if 'uuid' in builder:", 'if False:'),
            ("if 'mac' in builder:", 'if False:'),
            ('StrictHostKeyChecking=yes', 'StrictHostKeyChecking=no'),
        ]
        for old, new in changes:
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                mutant = types.ModuleType('approved_builder_mutation')
                mutant.__file__ = str(path)
                exec(compile(source.replace(old, new), str(path), 'exec'), mutant.__dict__)
                mutant.CONFIG = approved.CONFIG
                with self.assertRaises((AssertionError, ValueError, IndexError)):
                    contract(mutant)

    def test_powershell_checks_are_in_windows_gate(self):
        script = SCRIPT.with_name('Invoke-HarnessWindowsGate.sh').read_text()
        for leaf in ['Build-ExactAgentMatrix.SelfCheck.ps1', 'ApprovedBuilders.SelfCheck.ps1', 'Build-ExactAgentMatrix.ps1']:
            self.assertIn(leaf, script)
        ps = SCRIPT.with_name('Build-ExactAgentMatrix.ps1').read_text()
        self.assertIn('foreach ($profile in @(Get-MatrixProfiles))', ps)
        self.assertIn('if ($DiagnosticContinue) {\n                Invoke-DiagnosticProfile', ps)
        self.assertIn('$summary += @(Get-MatrixCompletionRows $gatePassed $DiagnosticContinue.IsPresent', ps)

    def test_duration_report_fixtures_read_only_and_sorted(self):
        duration = types.ModuleType('matrix_duration_control')
        path = SCRIPT.with_name('matrix-durations.py')
        exec(compile(path.read_bytes(), str(path), 'exec'), duration.__dict__)
        with tempfile.TemporaryDirectory(prefix='matrix-durations-') as temporary:
            out = Path(temporary)
            for profile in PROFILES:
                for account in ('user', 'system'):
                    path = out / (profile + '-results') / ('agent-tests-' + account + '.trx')
                    path.parent.mkdir(exist_ok=True)
                    root = ET.Element('{' + NS + '}TestRun')
                    ET.SubElement(root, '{' + NS + '}Times', start='2026-10-15T10:00:00Z', finish='2026-10-15T10:03:01.5000000+00:00')
                    results = ET.SubElement(root, '{' + NS + '}Results')
                    for name, elapsed, outcome in [('boundary', '00:01:00', 'Passed'), ('slow', '00:01:00.0000001', 'Failed'), ('slower', '1.00:00:01', 'Passed')]:
                        ET.SubElement(results, '{' + NS + '}UnitTestResult', testName=name, duration=elapsed, outcome=outcome)
                    ET.ElementTree(root).write(path, encoding='utf-8', xml_declaration=True)
            before = {p: p.read_bytes() for p in out.rglob('*.trx')}
            output, complete = duration.report(out)
            self.assertTrue(complete)
            cli = subprocess.run([sys.executable, str(SCRIPT.with_name('matrix-durations.py')), str(out)], capture_output=True, text=True)
            self.assertEqual(0, cli.returncode)
            self.assertEqual(output + '\n', cli.stdout)
            self.assertEqual(4, len([line for line in output.splitlines() if line.startswith(PROFILES) and ': 181.500 s' in line]))
            self.assertIn('First leg:', output)
            self.assertNotIn('boundary', output)
            self.assertIn('| Failed | slow', output)
            self.assertLess(output.index('| slower'), output.index('| slow\n'))
            self.assertEqual(before, {p: p.read_bytes() for p in out.rglob('*.trx')})
            next(iter(before)).unlink()
            output, complete = duration.report(out)
            self.assertFalse(complete)
            self.assertIn('ERROR ', output)
            for value in ['-00:01:00', '00:99:00', 'bad']:
                with self.assertRaises(ValueError):
                    duration.seconds(value)
            self.assertNotIn('CLOCK JUMP', output)
            jumped = out / 'feature-release-results' / 'agent-tests-user.trx'
            root = ET.Element('{' + NS + '}TestRun')
            ET.SubElement(root, '{' + NS + '}Times', start='2026-10-15T22:10:54+01:00', finish='2026-10-16T02:19:16+01:00')
            results = ET.SubElement(root, '{' + NS + '}Results')
            ET.SubElement(results, '{' + NS + '}UnitTestResult', testName='short', duration='00:05:00', outcome='Passed')
            ET.ElementTree(root).write(jumped, encoding='utf-8', xml_declaration=True)
            output, _ = duration.report(out)
            self.assertIn('feature-release/user: 14902.000 s (CLOCK JUMP SUSPECTED: summed test time 300.000 s; use host elapsed)', output)
            self.assertEqual(1, output.count('CLOCK JUMP'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
