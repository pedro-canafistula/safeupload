import datetime
import hashlib
import json
import subprocess
import sys
from pathlib import Path

work = Path(__file__).resolve().parent
evidence = Path('/home/victor/Work/safeupload-staging/driver/evidence/2026-10-11')
address = '192.168.122.210'
directory = 'C:\\Users\\vika\\Documents\\m2-t5-coordinator-r16-diag-1011-a1'
expected_sid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
record = {'StartedUTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'CoordinatorSourceDisposition': 'See separate root-reviewed R15 disposition', 'DiagnosticOnly': True,
          'CoordinatorInvoked': False, 'ServiceInstalled': False,
          'ProductVMStarted': False, 'GitMutation': False, 'Steps': {}}

def run(name, command, source=None):
    stdout = evidence / ('m2-t5-coordinator-r16-diag-a1-' + name + '.stdout.log')
    stderr = evidence / ('m2-t5-coordinator-r16-diag-a1-' + name + '.stderr.log')
    with stdout.open('xb') as out, stderr.open('xb') as err:
        process = subprocess.Popen(command, stdin=subprocess.PIPE if source is not None else None,
                                   stdout=out, stderr=err)
        try:
            process.communicate(source, timeout=180)
        except subprocess.TimeoutExpired:
            record['Steps'][name] = {'ObservationTimedOut': True, 'LocalTransportPID': process.pid,
                                     'RemoteProcessTerminal': False}
            # A timeout does not prove the remote process stopped; preserve evidence for re-observation.
            raise RuntimeError('Observation timed out; inspect the same remote process before any retry')
    value = stdout.read_bytes().decode('utf-8-sig', errors='replace')
    record['Steps'][name] = {'ExitCode': process.returncode, 'StdoutSHA256': hashlib.sha256(stdout.read_bytes()).hexdigest(),
                            'StderrSHA256': hashlib.sha256(stderr.read_bytes()).hexdigest()}
    if process.returncode:
        raise RuntimeError(name + ' failed: exit ' + str(process.returncode))
    return value

transport = [sys.executable, '-B', str(work / 'remote_ps.py'), address]
try:
    preflight = """$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or
    -not @(Get-NetAdapter | Where-Object { $_.MacAddress -eq '52-54-00-63-87-7A' }).Count) { throw 'Wrong builder.' }
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-21-316478115-1595729549-2803163825-1001') { throw 'Wrong diagnostic user.' }
$p='C:\\Users\\vika\\Documents\\m2-t5-coordinator-r16-diag-1011-a1'
if (Test-Path -LiteralPath $p) { throw 'Diagnostic directory already exists.' }
[void][IO.Directory]::CreateDirectory($p)
Write-Output 'FRESH_DIAGNOSTIC_DIRECTORY=CREATED'
"""
    assert 'FRESH_DIAGNOSTIC_DIRECTORY=CREATED' in run('prepare', transport, preflight.encode())
    ssh = ['-F', '/dev/null', '-i', '/home/victor/.ssh/id_ed25519', '-o', 'BatchMode=yes',
           '-o', 'ConnectTimeout=10', '-o', 'LogLevel=ERROR', '-o', 'StrictHostKeyChecking=yes']
    for index, name in enumerate(('notepad-coordinator.ps1', 'notepad-coordinator.SelfCheck.ps1')):
        run('delivery' + str(index), ['scp'] + ssh + [str(work / name),
            'vika@' + address + ':C:/Users/vika/Documents/m2-t5-coordinator-r16-diag-1011-a1/' + name])
    output = run('controls', transport, (work / 'controls-plan.ps1').read_bytes())
    assert ';SID=' + expected_sid in output
    assert output.count('T5_COORDINATOR_STANDALONE_DIAGNOSTIC=PASS') == 1
    record['StandaloneWindowsControlsPassed'] = True
except Exception as error:
    record['StandaloneWindowsControlsPassed'] = False
    record['Failure'] = str(error)
finally:
    record['FinishedUTC'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = evidence / 'm2-t5-coordinator-r16-diag-a1-root-result.json'
    with result.open('x') as handle:
        json.dump(record, handle, indent=2)
        handle.write('\n')
    print(json.dumps(record))
if not record['StandaloneWindowsControlsPassed']:
    raise SystemExit(1)
