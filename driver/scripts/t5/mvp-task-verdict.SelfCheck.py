#!/usr/bin/env python3
"""Offline task mapping, receipt mutants and actual launcher finalization controls."""
import ast
import importlib.util
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('mvp_verdict', root / 'mvp-task-verdict.py')
mvp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mvp)
checks = 0


def check(value, message):
    global checks
    checks += 1
    assert value, message


expected_cases = {
    'A': ('NotepadApprove', 'NotepadHandBack', 'NotepadEditApprove'),
    'B': ('ExcelSaveAsApprove', 'ExcelInPlaceApprove', 'ExcelCpfHandBack'),
    'C': ('ShellCopyIn', 'ShellMoveIn', 'ShellMoveWithin', 'PublicDeleteExplorer'),
    'D': ('ReadExisting',),
    'W': ('WordSaveAsApprove', 'WordInPlaceApprove', 'WordOverwriteApprove', 'WordCpfHandBack'),
}
check(mvp.TASK_CASES == expected_cases, 'exact owner task mapping')
all_names = sorted({name for task in expected_cases for name in mvp.dependencies(task)})
proofs = ('T5CanonicalNoUnapprovedByte INCONCLUSIVE canonical proof missing\n'
          'T5PublicDeleteExplorerDeleteBarrier INCONCLUSIVE barrier proof missing\n')
positive = ''.join(name + ' PASS exact receipt\n' for name in all_names) + proofs
outcomes, report = mvp.evaluate(positive, tuple(expected_cases))
check(set(outcomes.values()) == {'PASS'}, 'complete task dependencies pass with historical proofs unchanged')
check('historical full-row verdict and its INCONCLUSIVE proof lines are unchanged' in report, 'explicit historical distinction')
for task in expected_cases:
    for name in mvp.dependencies(task):
        check(f'MVP{task}Use SOURCE {name} PASS exact receipt' in report, 'enumerate exact source line')
for name in all_names:
    for status in ('FAIL', 'INCONCLUSIVE', 'INFO', 'MISSING', 'DUPLICATE', 'MALFORMED'):
        line = name + ' PASS exact receipt\n'
        replacement = ('' if status == 'MISSING' else line * 2 if status == 'DUPLICATE' else
                       name + '\n' if status == 'MALFORMED' else name + ' ' + status + ' exact receipt\n')
        results, _ = mvp.evaluate(positive.replace(line, replacement), tuple(expected_cases))
        for task in expected_cases:
            affected = name in mvp.dependencies(task)
            expected = ('INCONCLUSIVE' if status == 'INCONCLUSIVE' else 'FAIL') if affected else 'PASS'
            check(results[task] == expected, f'{task} dependency {name} {status} stays non-green')
check(set(mvp.evaluate('')[0].values()) == {'FAIL'}, 'empty input cannot pass')
office = 'T5RunProfile INFO OfficeExcel\n' + ''.join(name + ' PASS exact receipt\n' for name in mvp.dependencies('B')) + proofs
check(mvp.evaluate(office)[0] == {'B': 'PASS'}, 'Office profile evaluates only B')
check('MVPA NOT_RUN' in mvp.evaluate(office)[1], 'Office profile never relabels absent A/C/D as PASS')
check(mvp.evaluate(office.replace('T5OfficeBase PASS', 'T5OfficeBase FAIL'))[0] == {'B': 'FAIL'}, 'B requires Office restoration')
check(set(mvp.evaluate(office + 'T5RunProfile INFO BasicTasks\n')[0].values()) == {'FAIL'}, 'conflicting profiles cannot pass')
office_apps = 'T5RunProfile INFO OfficeApps\n' + ''.join(name + ' PASS exact receipt\n' for name in sorted(set(mvp.dependencies('B') + mvp.dependencies('W')))) + proofs
check(mvp.evaluate(office_apps)[0] == {'B': 'PASS', 'W': 'PASS'}, 'OfficeApps evaluates B and W')
check(mvp.evaluate(office_apps.replace('T5WordOverwriteApprove PASS', 'T5WordOverwriteApprove FAIL'))[0] == {'B': 'PASS', 'W': 'FAIL'}, 'failed Word overwrite does not pass or relabel Excel')
check(mvp.evaluate(office_apps.replace('T5WordCpfHandBack PASS', 'T5WordCpfHandBack INCONCLUSIVE'))[0] == {'B': 'PASS', 'W': 'INCONCLUSIVE'}, 'Word INCONCLUSIVE never turns green')
check(mvp.evaluate(office_apps.replace('T5OfficeBase PASS', 'T5OfficeBase FAIL'))[0] == {'B': 'FAIL', 'W': 'FAIL'}, 'both Office tasks require restoration')

launcher = (root.parent / 'Invoke-StageNotepad.sh').read_text()
names = {'receipt_fields', 'artifact_hashes_match', 'mode_readback_matches'}
functions = [n for block in re.findall(r"<<'PY'\n(.*?)\nPY\n", launcher, re.S)
             for n in ast.parse(block).body if isinstance(n, ast.FunctionDef) and n.name in names]
check({n.name for n in functions} == names, 'actual launcher receipt helpers present')
env = {'re': re}
exec(compile(ast.Module(body=functions, type_ignores=[]), '<launcher>', 'exec'), env)
inputs = 'LocalDriverSysSHA256='+'A'*64+'\nLocalAgentZipSHA256='+'B'*64+'\nExpectedExtractedServiceSHA256='+'C'*64+'\n'
install = 'UPLOAD_DRIVER_SHA256='+'A'*64+'\nINSTALLED_DRIVER_SHA256='+'A'*64+'\nUPLOAD_AGENT_ZIP_SHA256='+'B'*64+'\nEXTRACTED_SERVICE_EXE_SHA256='+'C'*64+'\n'
after = 'LIVE_DRIVER_SHA256='+'A'*64+'\nLIVE_SERVICE_EXE_SHA256='+'C'*64+'\n'
hashes = env['artifact_hashes_match']
check(hashes(inputs, install, after), 'matching package, driver and service hashes')
for index, text in enumerate((inputs, install, after)):
    for line in text.splitlines(keepends=True):
        for replacement in ('', line*2, line.replace('=', '=D', 1)):
            args = [inputs, install, after]
            args[index] = text.replace(line, replacement)
            check(not hashes(*args), 'missing/duplicate/wrong hash cannot pass')
mode = env['mode_readback_matches']
ordinary = 'VERIFIER= No drivers are currently verified.\n'
runtime = 'VERIFIER= Verifier Flags: 0x0000013b Verified Drivers: SafeUpload.sys\n'
armed = 'RUNTIME_VERIFIER_ARMED=True\n'
check(mode('ordinary', ordinary, ordinary, ''), 'ordinary reads back no verified drivers')
check(mode('runtime-verifier', ordinary, runtime, armed), 'runtime has arming receipt and final readback')
check(mode('boot-verifier', runtime, runtime, 'BOOT_VERIFIER_CONFIGURED=True\n'), 'existing boot mode supported')
for ready, final, receipt in ((ordinary, ordinary, armed), (ordinary, runtime, ''), (ordinary, runtime, armed*2),
                              (ordinary, runtime.replace('13b', '13a'), armed), (ordinary, runtime.replace('SafeUpload.sys', 'Other.sys'), armed)):
    check(not mode('runtime-verifier', ready, final, receipt), 'runtime readback mutant fails')
for ready, final in ((runtime, ordinary), (ordinary, runtime), ('', ordinary), (ordinary, ''), (ordinary*2, ordinary)):
    check(not mode('ordinary', ready, final, ''), 'ordinary readback mutant fails')
check(not re.search(r'\$json\.Interception\.StageSpace\.FloorOnly\s*=', launcher), 'off override never assigns FloorOnly')
check('$json.Interception.StageSpace.Enabled = $false' in launcher and
      '$readback.Interception.StageSpace.FloorOnly -ne $floorOnly' in launcher, 'off only disables budget and checks floor preservation')

# Execute the actual EXIT finalizer with a local restoration stub. This exercises
# ordering and exit preservation without running any launcher VM/network setup.
start = launcher.index('finish() {')
finish = launcher[start:launcher.index('\n}\n', start)+3]
with tempfile.TemporaryDirectory(prefix='t5-mvp-controls-') as directory:
    path = Path(directory, 'row-verdict.txt')
    for full_status, restored, expected_status in ((0, True, 0), (1, True, 1), (0, False, 22)):
        path.write_text(positive.replace('T5Restoration PASS exact receipt\n', ''))
        script = ('set -uo pipefail\n' + f'ev={shlex.quote(directory)}\ntag=row\ndom=offline\ncode_scripts={shlex.quote(str(root.parent))}\n' +
                  'run_disk_end() {\n  printf "restoration stub\\n"\n  return ' + ('0' if restored else '1') + '\n}\n' +
                  finish + f'\n(exit {full_status})\nfinish\n')
        run = subprocess.run(['bash'], input=script, text=True, capture_output=True)
        check(run.returncode == expected_status, 'full-row/restoration exit status preserved: '+run.stderr)
        final = path.read_text()
        check(proofs in final, 'historical INCONCLUSIVE lines unchanged')
        output = Path(directory, 'row-mvp-verdict.txt').read_text()
        check(('MVPA PASS' in output) == restored, 'task verdict generated after actual finalizer restoration')
        before = path.read_bytes()
        cli = subprocess.run([sys.executable, str(root / 'mvp-task-verdict.py'), str(path)], capture_output=True, text=True)
        check(cli.returncode == (0 if restored else 1), 'CLI exit matches task outcomes')
        check(path.read_bytes() == before, 'CLI never mutates input verdict')

print(f'T5MvpTaskVerdictSelfCheck=PASS;Assertions={checks};ProductQualified=False')
