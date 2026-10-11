#!/usr/bin/env python3
"""Offline exact-delta and assertion-shape controls for coordinator R18."""
from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path


REPO = Path('/home/victor/Work/safeupload-staging')
CANDIDATE = REPO / 'output/review-candidates/m2-t5-notepad-coordinator-r18-luna-a1'
SRC = CANDIDATE / 'src'
CONTEXT = CANDIDATE / 'context/r17-runtime'
BASELINE_SELF = CONTEXT / 'selfcheck-r17-baseline.ps1'
ROOT_CAPTURE = CONTEXT / 'root-review-capture.json'
DIAGNOSIS = CONTEXT / 'failure-diagnosis.md'
R17_SOURCE_SELF_SHA = 'be52114a729e2861afccf6c73d900d5b03fc9f476e3664a64f10f959cb33ae47'
R18_SELF_SHA = 'abc6b472a16e772bdd11fea7ab88e8e3de82579fc2691c6ef2436229c88d74bb'
ROOT_CAPTURE_SHA = '7fd178b5560c782cecb655557e17889b1ce6b9739dc54d009191732c89289d79'
DIAGNOSIS_SHA = 'ce7213e64b57c183523fbaa5646867aacd4e9a4387f5c1290f17d9f63eabcac5'
R17_DIAG_RESULT_SHA = '334b8794c812cdcd7330104b3f269457185aeef405fb6abfbf1998438bd2edf4'
R17_DIAG_VERIFY_SHA = '5a552d5adc1e3a18c3bbdca55795b31e63aa1a7dc72279679304d353641192bc'
R17_DIAG_STDOUT_SHA = '6af33efaa7bccb8ad8c344d48af1d8bd5029fa4e627cbb31019ab0e6970a27db'
R17_DIAG_STDERR_SHA = '31db57ecf12725856215a7f0a6c4c9e41a5f7828c46d4ee7189057f61ee09b97'
R17_FAILURE_DISPOSITION_SHA = '8c312e0b8b3e43485efa9fcc821ec731456e5042bdc507c69ef82a3ba6746b99'
FAULTY = b"    Assert-T5 (@($journal.Records | Where-Object { $_.AttachmentStateV20 -eq 6 -and $_.HandleObservedRequestIdV20 -eq 19 }).Count -eq 1) 'projection retains exact HandleObserved receipt'\n"
STRENGTHENED = b"""    $observedReceipts = @($journal.Records | Where-Object {
        $_.AttachmentStateV20 -eq 6 -and
        (Get-T5UInt64Text $_.HandleObservedRequestIdV20) -ceq '19'
    })
    Assert-T5 (
        $observedReceipts.Count -eq 2 -and
        @($observedReceipts | Where-Object { $_.TransferId -ceq $parent.Transfer.TransferId }).Count -eq 1 -and
        @($observedReceipts | Where-Object { $_.TransferId -ceq $child.Transfer.TransferId }).Count -eq 1
    ) 'parent and child projections retain exact HandleObserved receipts'
"""
SOURCE_PATHS = {
    'driver/scripts/t5/notepad-coordinator.SelfCheck.ps1',
    'driver/scripts/t5/notepad-coordinator.ps1',
    'agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs',
    'agente/SafeUpload.Agent.Service/Interception/StagedJournalFile.cs',
}
TARGET = 'driver/scripts/t5/notepad-coordinator.SelfCheck.ps1'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str:
    return sha(path.read_bytes())


def require(ok: bool, message: str) -> None:
    if not ok:
        raise AssertionError(message)


def verify_replacement(source: bytes) -> list[str]:
    errors: list[str] = []
    if source.count(STRENGTHENED) != 1:
        errors.append('the complete exact parent/child assertion must occur once')
    for token, reason in [
        (b'$observedReceipts.Count -eq 2', 'exactly two state-6/op19 receipts are required'),
        (b'(Get-T5UInt64Text $_.HandleObservedRequestIdV20) -ceq \'19\'', 'op19 must use exact UInt64 text comparison'),
        (b'$parent.Transfer.TransferId }).Count -eq 1', 'exactly one parent receipt is required'),
        (b'$child.Transfer.TransferId }).Count -eq 1', 'exactly one child receipt is required'),
    ]:
        if source.count(token) != 1:
            errors.append(reason)
    if b"'projection retains exact HandleObserved receipt'" in source:
        errors.append('the faulty generic single-receipt assertion remains')
    return errors


def main() -> None:
    require(digest(ROOT_CAPTURE) == ROOT_CAPTURE_SHA, 'R17 root source capture pin mismatch')
    require(digest(DIAGNOSIS) == DIAGNOSIS_SHA, 'independent failure diagnosis pin mismatch')
    root_capture = json.loads(ROOT_CAPTURE.read_text(encoding='utf-8'))
    expected = root_capture['Groups']['src']
    require(set(expected) == SOURCE_PATHS, 'root capture source closure is not the exact four-file set')
    for group in ('author', 'context'):
        prefix = CANDIDATE / 'context/r17-root' / group
        for name, expected_sha in root_capture['Groups'][group].items():
            require(digest(prefix / name) == expected_sha, f'copied R17 {group} input pin mismatch: {name}')
    runtime_inputs = {
        'root-failure-disposition.json': R17_FAILURE_DISPOSITION_SHA,
        'diagnostic-root-result.json': R17_DIAG_RESULT_SHA,
        'diagnostic-root-verification.json': R17_DIAG_VERIFY_SHA,
        'diagnostic-controls.stdout.log': R17_DIAG_STDOUT_SHA,
        'diagnostic-controls.stderr.log': R17_DIAG_STDERR_SHA,
    }
    for name, expected_sha in runtime_inputs.items():
        require(digest(CONTEXT / name) == expected_sha, f'actual R17 failure evidence pin mismatch: {name}')
    failure_disposition = json.loads((CONTEXT / 'root-failure-disposition.json').read_text(encoding='utf-8'))
    diagnostic_result = json.loads((CONTEXT / 'diagnostic-root-result.json').read_text(encoding='utf-8'))
    diagnostic_verification = json.loads((CONTEXT / 'diagnostic-root-verification.json').read_text(encoding='utf-8'))
    require(failure_disposition['Failure'] == 'projection retains exact HandleObserved receipt' and
            failure_disposition['EarlierProjectionMutantAndHandbackAssertionsReachedAndPassed'] is True,
            'R17 retained failure disposition differs from the diagnosed run')
    require(diagnostic_result['StandaloneWindowsControlsPassed'] is False and
            diagnostic_verification['SelfCheckOutputHasExactlyOneCompletePASS'] is False and
            diagnostic_verification['OriginalDiagnosticProcessTerminal'] is True,
            'R17 diagnostic result/verification does not preserve its failed terminal outcome')
    require('projection retains exact HandleObserved receipt' in (CONTEXT / 'diagnostic-controls.stderr.log').read_text(encoding='utf-8'),
            'R17 raw failure assertion missing from captured diagnostic output')
    require(digest(BASELINE_SELF) == R17_SOURCE_SELF_SHA, 'copied R17 baseline self-check pin mismatch')
    source_capture = json.loads((CANDIDATE / 'context/r17-root/author/source-capture.json').read_text(encoding='utf-8'))
    self_rows = [r for r in source_capture['sourceFiles'] if r['path'] == 'src/driver/scripts/t5/notepad-coordinator.SelfCheck.ps1']
    require(len(self_rows) == 1 and self_rows[0]['sha256'] == R17_SOURCE_SELF_SHA,
            'R17 source capture does not pin the baseline self-check')

    current_files = {str(p.relative_to(SRC)): p.read_bytes() for p in SRC.rglob('*') if p.is_file()}
    require(set(current_files) == SOURCE_PATHS, 'R18 source closure must contain exactly four regular files')
    require(not any(p.is_symlink() for p in SRC.rglob('*')), 'R18 source closure may not contain symlinks')
    baseline_all = {}
    baseline_root = REPO / 'output/review-candidates/m2-t5-notepad-coordinator-r17-root-a1/src'
    for path in SOURCE_PATHS:
        if path == TARGET:
            baseline_all[path] = BASELINE_SELF.read_bytes()
        else:
            baseline_all[path] = (baseline_root / path).read_bytes()
    for path in SOURCE_PATHS:
        require(sha(baseline_all[path]) == expected[path], f'frozen R17 baseline hash mismatch: {path}')
    source = current_files[TARGET]
    require(source.count(FAULTY) == 0, 'generic faulty one-match assertion remains')
    require(baseline_all[TARGET].count(FAULTY) == 1, 'R17 baseline must contain exactly one diagnosed faulty assertion')
    reconstructed = baseline_all[TARGET].replace(FAULTY, STRENGTHENED, 1)
    require(source == reconstructed, 'R18 self-check contains changes beyond the one diagnosed assertion replacement')
    require(sha(source) == R18_SELF_SHA, 'R18 self-check SHA-256 changed')
    require(not verify_replacement(source), 'R18 strengthened receipt predicate is incomplete')
    for path in SOURCE_PATHS - {TARGET}:
        require(current_files[path] == baseline_all[path], f'non-self-check source changed: {path}')

    # Reject omission of each required conjunct and reintroduction of the old cardinality check.
    mutants = [
        source.replace(b"(Get-T5UInt64Text $_.HandleObservedRequestIdV20) -ceq '19'", b"$_.HandleObservedRequestIdV20 -eq 19", 1),
        source.replace(b"$observedReceipts.Count -eq 2", b"$observedReceipts.Count -eq 1", 1),
        source.replace(b"$parent.Transfer.TransferId }).Count -eq 1", b"$parent.Transfer.TransferId }).Count -eq 0", 1),
        source.replace(b"$child.Transfer.TransferId }).Count -eq 1", b"$child.Transfer.TransferId }).Count -eq 0", 1),
        source.replace(b"$observedReceipts.Count -eq 2", b"$observedReceipts.Count -eq 2", 1) + FAULTY,
    ]
    require(all(m != source for m in mutants), 'one or more assertion mutants did not apply')
    require(all(verify_replacement(m) for m in mutants), 'one or more missing/weak receipt predicate mutants were accepted')

    patch = ''.join(difflib.unified_diff(
        baseline_all[TARGET].decode('utf-8').splitlines(keepends=True),
        source.decode('utf-8').splitlines(keepends=True),
        fromfile='R17/driver/scripts/t5/notepad-coordinator.SelfCheck.ps1',
        tofile='R18/driver/scripts/t5/notepad-coordinator.SelfCheck.ps1',
    ))
    patch_path = CANDIDATE / 'author/exact-delta-from-r17.patch'
    patch_path.write_text(patch, encoding='utf-8')
    removed = [line for line in patch.splitlines() if line.startswith('-') and not line.startswith('---')]
    added = [line for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++')]
    require(len(removed) == 1 and len(added) == 9, 'exact delta must replace one assertion line with the checked projection plus one assertion')

    print('R18 offline coordinator controls: PASS')
    print('R17 root source baseline: exact 4-file closure and source hashes verified; all 15 copied author/context pins match the root capture.')
    print('R18 delta: exactly one faulty assertion line replaced; all other source bytes unchanged.')
    print('Receipt assertion: exactly two state-6/op19 records, exact UInt64 text op19, one parent TransferId and one child TransferId.')
    print('Mutation controls: PASS; raw-number comparison, wrong total cardinality, missing parent/child uniqueness, and old generic assertion are rejected.')
    print('Production coordinator and both managed schema review inputs: unchanged R17 pins.')
    print('R17 failed diagnostic: exact terminal result and raw assertion output retained; it is not treated as a pass.')
    print('Runtime boundary: no PowerShell, Windows, coordinator, service, actor, host, VM, network, or Git action.')


if __name__ == '__main__':
    main()
