#!/usr/bin/env python3
"""Offline source-only controls for the seven R16 projection fixture corrections."""
from __future__ import annotations

import difflib
import hashlib
from pathlib import Path
import sys

ROOT = Path('/home/victor/Work/safeupload-staging')
CANDIDATE = ROOT / 'output/review-candidates/m2-t5-notepad-coordinator-r17-luna-a1'
BASELINE = ROOT / 'output/review-candidates/m2-t5-notepad-coordinator-r16-root-a1'

SOURCE_PINS = {
    'src/driver/scripts/t5/notepad-coordinator.SelfCheck.ps1': 'be52114a729e2861afccf6c73d900d5b03fc9f476e3664a64f10f959cb33ae47',
    'src/driver/scripts/t5/notepad-coordinator.ps1': 'c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d',
    'src/agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs': '4b270eaef4616c06ba52e0b88deb701d72463dcef8ed6c9c8cc4c39893b23f8d',
    'src/agente/SafeUpload.Agent.Service/Interception/StagedJournalFile.cs': '5f4a5ae360513425f1ff79c3ad8c0c4fc8c2b3464f416cecc43c57c42224053a',
}
CONTEXT_PINS = {
    'context/r16/notepad-coordinator.SelfCheck.baseline.ps1': 'e64729a084d6d87db93bfc99a41cc95537cbf3e5e2f2977bf53c49761758afe8',
    'context/r16/source-capture.json': '74663932a7bcb6460a330b6b225516f1d17d87878ddd17916e32d09213db3ff6',
    'context/r16/author-result.json': '244e0d8a81effdd149cb60f6f4ed292352088030de916c4f77e52942398a6c1a',
    'context/r16/root-review-capture.json': '479cd969a36c6d010efcd0758caf1f3f6a798f235b6accffef8d7a638ccd8411',
    'context/r16/root-review-disposition.json': '643e3e24749d02b6cdfdbc1dd8236c395048b82426261e7c9980c987c8bf59a8',
    'context/r16/failure-diagnosis.md': '8328b24d9236c4ac61c322b95be2c92f77d49151fc588e409f689e5cb26ee842',
    'context/r16/diagnostic-result.json': '1060947bea2cc9892783f548ed2194099aeea5dd5872f7dc53def8f3fd0af604',
    'context/r16/diagnostic-verification.json': 'c22d5fdeb88f1f8c212f57a1bb493ed32177aba7d1b93c1427d9a85a3468e757',
}
VARIANTS = {
    'failedHandbackChild': (
        "    $failedHandbackChild.HandbackState = '3'",
        'Failed handback Released child is not terminal for EmptyHeld cleanup',
    ),
    'pendingRenameChild': (
        '    $pendingRenameChild.PendingRename = [pscustomobject]@{',
        'pending rename prevents direct-child cleanup classification',
    ),
    'sameStageChild': (
        '    $sameStageChild.StageIdentity = $releasedPendingParentProjection.StageIdentity',
        'direct child must have a distinct exact stage identity from its parent',
    ),
    'wrongCreateReservationChild': (
        '    $wrongCreateReservationChild.CreateReservationId = [guid]::NewGuid().ToString()',
        'direct child create reservation must be its exact transfer ID',
    ),
    'wrongAllocationReferenceChild': (
        '    $wrongAllocationReferenceChild.AllocationReferenceId = [guid]::NewGuid().ToString()',
        'direct child allocation reference must name the exact parent',
    ),
    'cleanupStartedChild': (
        '    $cleanupStartedChild.StageCleanupStarted = [bool]$true',
        'direct child with cleanup already started is not terminal',
    ),
    'verifiedHandbackChild': (
        '    $verifiedHandbackChild.HandbackState = \'2\'',
        'Verified handback child is terminal only after justification closes and stage deletion is acknowledged',
    ),
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    for rel, expected in SOURCE_PINS.items():
        candidate_bytes = (CANDIDATE / rel).read_bytes()
        require(sha(candidate_bytes) == expected, f'R17 source pin mismatch: {rel}')
    for rel, expected in CONTEXT_PINS.items():
        require(sha((CANDIDATE / rel).read_bytes()) == expected, f'Context pin mismatch: {rel}')

    baseline_live = (BASELINE / 'src/driver/scripts/t5/notepad-coordinator.SelfCheck.ps1').read_bytes()
    baseline_copy = (CANDIDATE / 'context/r16/notepad-coordinator.SelfCheck.baseline.ps1').read_bytes()
    r17_selfcheck = (CANDIDATE / 'src/driver/scripts/t5/notepad-coordinator.SelfCheck.ps1').read_bytes()
    require(baseline_live == baseline_copy, 'Copied R16 self-check is not byte-identical to the frozen root baseline.')

    transformed = baseline_live
    old_suffix = b' = $releasedPendingChild.PSObject.Copy()'
    new_suffix = b' = $releasedPendingChildProjection.PSObject.Copy()'
    for name in VARIANTS:
        old = ('$' + name).encode('ascii') + old_suffix
        new = ('$' + name).encode('ascii') + new_suffix
        require(transformed.count(old) == 1, f'R16 baseline must contain one raw-copy line for {name}.')
        transformed = transformed.replace(old, new, 1)
    require(transformed == r17_selfcheck, 'R17 self-check contains changes beyond the seven approved copy-source replacements.')
    require(r17_selfcheck.count(new_suffix) == len(VARIANTS), 'R17 must change exactly seven variant copy sources.')
    require(r17_selfcheck.count(old_suffix) == 0, 'One or more targeted variants still copy the raw child.')

    text = r17_selfcheck.decode('utf-8')
    for name, (mutation_line, assertion_text) in VARIANTS.items():
        assignment = f'    ${name} = $releasedPendingChildProjection.PSObject.Copy()'
        require(text.count(assignment) == 1, f'{name} is not copied exactly once from the projected child.')
        assignment_index = text.index(assignment)
        mutation_index = text.find(mutation_line, assignment_index)
        assertion_index = text.find(assertion_text, assignment_index)
        require(mutation_index > assignment_index, f'{name} expected mutation was lost or moved before its copy.')
        require(assertion_index > mutation_index, f'{name} original assertion does not follow its mutation.')

    patch = (CANDIDATE / 'author/exact-delta-from-r16.patch').read_text(encoding='utf-8')
    old_lines = baseline_live.decode('utf-8').splitlines(keepends=True)
    new_lines = r17_selfcheck.decode('utf-8').splitlines(keepends=True)
    expected_patch = ''.join(difflib.unified_diff(
        old_lines, new_lines,
        fromfile='R16/driver/scripts/t5/notepad-coordinator.SelfCheck.ps1',
        tofile='R17/driver/scripts/t5/notepad-coordinator.SelfCheck.ps1',
    ))
    require(patch == expected_patch, 'Published exact delta does not match the frozen R16 baseline and R17 source.')
    removed = [line for line in patch.splitlines() if line.startswith('-') and not line.startswith('---')]
    added = [line for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++')]
    require(len(removed) == 7 and len(added) == 7, 'Patch must contain exactly seven one-line substitutions.')

    expected_source_paths = set(SOURCE_PINS)
    actual_source_paths = {
        str(p.relative_to(CANDIDATE))
        for p in (CANDIDATE / 'src').rglob('*')
        if p.is_file()
    }
    require(actual_source_paths == expected_source_paths, 'Candidate source directory is not the exact four-file closed source set.')
    require(sha((CANDIDATE / 'context/r16/failure-diagnosis.md').read_bytes()) == '8328b24d9236c4ac61c322b95be2c92f77d49151fc588e409f689e5cb26ee842', 'Independent diagnosis pin changed.')

    print('R17 source-only coordinator controls: PASS')
    print('Frozen R16 baseline: exact hashes verified for 4 source files and 8 diagnostic/context files.')
    print('Delta: exactly seven raw-to-projected copy-source substitutions; all other bytes identical.')
    print('Variant controls: seven expected mutations and their original assertion texts remain in place.')
    print('Production source: coordinator and both managed schema review sources remain exact R16 pins.')
    print('Candidate source closure: exactly 4 files; no new helper, gate, validator, or schema change.')
    print('Runtime boundary: no PowerShell, Windows, coordinator, actor, service, host, VM, network, or Git action.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'R17 source-only coordinator controls: FAIL: {exc}', file=sys.stderr)
        raise
