#!/usr/bin/env python3
"""Diagnostic logic/receipt/dry-run mutants ONLY. Never native N-U5-01 evidence."""
import copy
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import uuid
import sys

sys.dont_write_bytecode = True

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('verdict', HERE / 'validate_receipt.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def fixture():
    names = ['Idle', 'Probe', 'Pair', 'CommitWire', 'CommitNotReady']
    names += [n for cause in ('Timeout', 'Failure', 'Cancellation') for n in (f'Release{cause}Held', f'Release{cause}Returned')]
    names += ['LeaseHeld', 'LegacyBlocked']
    tail = ['HeldProgressComplete', 'LegacyReleased', 'ChildrenClosed', 'DisconnectRetains', 'RevokeLatchReleased', 'DisconnectDrain']
    names += [n for n in module.REQUIRED if n not in names + tail]
    names += tail
    held, released = names.index('LeaseHeld'), names.index('LegacyReleased')
    steps = [dict(Name=n, RequestId=i+1, Status='Native' if '.' in n else
                  'Completed' if n in ('ChildCreditsBusy','OtherPoolBusy','GrowthPoolBusy') else 'Assert',
                  HResult=-1 if n in ('ChildCreditsBusy','OtherPoolBusy','GrowthPoolBusy','Malformed') else 0,
                  ElapsedMs=i, LegacyHeld=held <= i < released or n.startswith('Release') and n.endswith('Held') or n == 'DisconnectRetains', Passed=True, Detail='Synthetic logic fixture')
             for i, n in enumerate(names)]
    return dict(Schema='SafeUpload.N-U5-01.v1',RunId=uuid.uuid4().hex,Verdict='PASS',Failure=None,Scope='Synthetic logic control only',Steps=steps)

def main():
    count = 0
    def accepted(value):
        nonlocal count
        module.validate(value)
        count += 1
    def rejected(value):
        nonlocal count
        try:
            module.validate(value)
        except (AssertionError, KeyError, ValueError, TypeError):
            count += 1
        else:
            raise AssertionError('Mutant was accepted')
    original = fixture()
    accepted(original)
    for name in module.REQUIRED:
        missing = copy.deepcopy(original)
        missing['Steps'] = [s for s in missing['Steps'] if s['Name'] != name]
        rejected(missing)
        duplicate = copy.deepcopy(original)
        duplicate['Steps'].append(copy.deepcopy(next(s for s in duplicate['Steps'] if s['Name'] == name)))
        rejected(duplicate)
    for key, value in [('Schema','wrong'),('RunId','wrong'),('Verdict','FAIL'),('Failure','failure')]:
        mutant=copy.deepcopy(original); mutant[key]=value; rejected(mutant)
    for key, value in [('Passed',False),('ElapsedMs',float('nan')),('ElapsedMs',-1)]:
        mutant=copy.deepcopy(original); mutant['Steps'][0][key]=value; rejected(mutant)
    for name in ['Root1','Store0.Allocation','LocalSendsReturned','HeldProgressComplete']:
        mutant=copy.deepcopy(original)
        next(s for s in mutant['Steps'] if s['Name']==name)['LegacyHeld']=False
        rejected(mutant)
    # Exercise the CLI acceptance boundary too: a verdict string, peer or
    # transport-style receipt alone must never turn failure into native PASS.
    with tempfile.TemporaryDirectory(prefix='nu501-receipt-') as directory:
        root = pathlib.Path(directory)
        client = dict(PSVersion='5.1.19041.1', Bits=64, Boot='synthetic-boot')
        peer = dict(ServerPid=42, ServicePid=42, ServiceName='SafeUploadAgent', Boot='synthetic-boot')
        def reset():
            (root/'receipt.json').write_text(json.dumps(original))
            (root/'exit.txt').write_text('0')
            (root/'verdict.txt').write_text('N-U5-01=PASS')
            (root/'client.json').write_text(json.dumps(client))
            (root/'peer.json').write_text(json.dumps(peer))
            (root/'error.txt').unlink(missing_ok=True)
        import contextlib
        import io
        def cli():
            previous = sys.argv
            try:
                sys.argv = ['validate_receipt.py', str(root)]
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    module.main()
                assert output.getvalue() == 'N-U5-01=PASS\n'
            finally:
                sys.argv = previous
        reset(); cli(); count += 1
        mutations = [
            lambda: (root/'exit.txt').write_text('1'),
            lambda: (root/'verdict.txt').write_text('N-U5-01=FAIL'),
            lambda: (root/'error.txt').write_text('failed'),
            lambda: (root/'peer.json').write_text(json.dumps(dict(peer, ServerPid=43))),
            lambda: (root/'peer.json').write_text(json.dumps(dict(peer, Boot='different'))),
            lambda: (root/'client.json').write_text(json.dumps(dict(client, Bits=32))),
            lambda: (root/'client.json').write_text(json.dumps(dict(client, PSVersion='7.0.0'))),
            lambda: (root/'receipt.json').write_text(json.dumps(dict(original, Verdict='FAIL'))),
        ]
        for mutation in mutations:
            reset(); mutation()
            try:
                cli()
            except (AssertionError, KeyError, ValueError):
                count += 1
            else:
                raise AssertionError('CLI mutant accepted')
    # Dry-run must contact nothing and create no evidence/locks. Tool stubs
    # make any accidental external action fail with a preserved marker.
    with tempfile.TemporaryDirectory(prefix='nu501-dryrun-') as directory:
        work=pathlib.Path(directory); binaries=work/'bin'; binaries.mkdir()
        marker=work/'contacted'
        for name in ('ssh','scp','virsh','flock','curl','wget'):
            path=binaries/name
            path.write_text('#!/bin/sh\necho contacted >> "'+str(marker)+'"\nexit 99\n')
            path.chmod(0o755)
        artifact=work/'artifact'; artifact.write_bytes(b'local dry-run artifact')
        import hashlib
        sha=hashlib.sha256(artifact.read_bytes()).hexdigest()
        env=dict(os.environ,PATH=str(binaries)+':'+os.environ['PATH'],SAFEUPLOAD_DEBUGGEE='win10-debug3')
        label='nu501dry'+uuid.uuid4().hex[:10]
        command=['bash',str(HERE/'Invoke-Nu501ComponentHost.sh'),'--dry-run',label,'HEAD',str(artifact),sha,str(artifact),sha,sha]
        result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=10)
        assert result.returncode==0, result.stderr
        assert 'DryRun=True' in result.stdout and not marker.exists()
        evidence=next(l.split('=',1)[1] for l in result.stdout.splitlines() if l.startswith('Evidence='))
        assert not (HERE.parents[3]/evidence).exists()
        count+=1
        env['SAFEUPLOAD_DEBUGGEE']='win10-debug2'
        result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=10)
        assert result.returncode!=0 and not marker.exists(); count+=1
        env['SAFEUPLOAD_DEBUGGEE']='win10-debug3'
        command[-1]='f'*64 # executable hash is just a pinned input; mutate driver instead
        command[6]='0'*64
        result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=10)
        assert result.returncode!=0 and not marker.exists(); count+=1
    print(json.dumps(dict(DiagnosticOnly=True, Controls=count, Failed=0, Skipped=0)))

if __name__=='__main__':
    main()
