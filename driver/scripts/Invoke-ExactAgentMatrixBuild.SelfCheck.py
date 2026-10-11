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
PROFILES = ('normal-debug', 'normal-release', 'feature-debug', 'feature-release')
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
    rows = []
    for profile in PROFILES:
        mode = profile.split('-')[0]
        methods = STAGED | SYSTEM | (FEATURE if mode == 'feature' else {ENDPOINT + 'EvidenceTypesExistOnlyInFeatureBuilds'})
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
    for mode in ('normal', 'feature'):
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
