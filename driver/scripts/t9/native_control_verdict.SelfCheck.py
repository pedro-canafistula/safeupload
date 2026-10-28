#!/usr/bin/env python3
"""Offline synthetic receipts exercise the actual embedded runner verdicts."""
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from native_control_verdict import FAULTS, KEYS

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SHA = 'A' * 64


def observation(key, allocation=4096, eof=128, links=1):
    return dict(Identity=key + '-id', AllocationSize=allocation, EndOfFile=eof,
                Links=links, DeletePending=links == 0, Directory=False)


def frames(steps, stage=None):
    release = stage is None
    raised = replaced = False
    result = []
    for step in steps:
        raised |= step == 'BeforeFault'
        replaced |= step in ('PrefixRename', 'UnlinkedHeld')
        objects = []
        for key in KEYS:
            allocation, eof = 4096, 192 if key == 'New' else 128
            if not release and key == 'New':
                if step == 'Initial': allocation, eof = 0, 0
                elif step == 'PrefixAllocation': eof = 0
                elif step in ('PrefixWrite', 'PrefixF1'): eof = 4096
                elif step in ('BeforeFault', 'AfterFault'):
                    allocation, eof = 12288, 0 if stage < 2 else 4096 if stage < 4 else 192
                elif step in ('NormalizeEOF', 'NormalizeF2'):
                    allocation, eof = 12288, 0 if stage < 2 else 192
                elif step.startswith('Normal'): eof = 0 if stage < 2 else 192
            unlinked = key == 'Predecessor' and replaced
            closed = step == 'Closed' and key == ('Predecessor' if release else 'New')
            state = ('UnlinkedDrained' if closed else 'UnlinkedHeld') if unlinked else 'Linked'
            objects.append(dict(Key=key, Q=4096, Retained=12288 if key == 'New' and raised else 4096,
                                State=state, Object=None if closed else observation(key, allocation, eof, 0 if unlinked else 1)))
        result.append(dict(Step=step, Objects=objects, Total=sum(o['Retained'] for o in objects)))
    return result


def receipts(os='19045.2965'):
    discovery = os.endswith('6466')
    flags = dict(ExpectedOS=os, ExpectedBaselineMatches=True, TargetBaselineMatches=not discovery,
                 MechanismDiscovery=discovery, TargetEvidence=not discovery, ProductQualification=False)
    rows = [dict(Kind='Verdict', Verdict='PASS', FirstDifference=None, LabStop=False,
                 ReplacementRows=32, AllocationRows=48, FaultRows=7, RetentionRows=8, ReleaseRows=1,
                 PersistedReleaseVerified=False, **flags),
            dict(Kind='Environment', OS='10.0.'+os, ExpectBuilderTable=True, **flags),
            dict(Kind='Script', SHA256=SHA, PSVersion='5.1.19041.1', ProcessBits=64),
            dict(Kind='Token', SID='actor-sid', User='TARGET\\t5actor', Elevated=False, IntegrityRID=8192)]
    rows += [dict(Kind='ReplacementResult') for _ in range(32)]
    rows += [dict(Kind='AllocationResult') for _ in range(48)]
    for stage, name in enumerate(FAULTS):
        steps = ['Initial'] + ['Prefix'+s for s in FAULTS[:stage]] + ['BeforeFault', 'AfterFault', 'NormalizeEOF', 'NormalizeF2', 'NormalizeAllocation', 'Normalized', 'Closed']
        samples = frames(steps, stage)
        by_step = {f['Step']: f for f in samples}
        r = dict(Stage=name, Status='0xC0000043' if stage == 5 else '0xC0000022', IoStatus='0x00000000', Information=0,
                 Classification='Held', RenameAttempts=1 if stage>=5 else 0, SuccessfulRenames=1 if stage==6 else 0, L=192, P=4096, Q=4096, NormalizedEOF=0 if stage < 2 else 192,
                 Before=copy.deepcopy(by_step['BeforeFault']['Objects'][0]['Object']),
                 After=copy.deepcopy(by_step['AfterFault']['Objects'][0]['Object']),
                 Normalized=copy.deepcopy(by_step['Normalized']['Objects'][0]['Object']), Frames=samples)
        rows.append(dict(Kind='Native', InjectedFault=True, Stage=name, NTSTATUS=r['Status'], IoStatus=r['IoStatus'], Information=r['Information'],
                         Operation='NtWriteFile' if stage==1 else 'NtSetInformationFile' if stage in (0,3,5) else 'NtFlushBuffersFile',
                         Class={0:19,3:20,5:65}.get(stage,0), Flags=3 if stage==5 else 0, Access=0x130083 if stage==5 else 0x130081, Share=7, Options=0x20006A))
        rows += [dict(Kind='FaultResult', Result=r, Comparison='PASS'),
                 dict(Kind='RetentionResult', Key=name, Frames=copy.deepcopy(samples), Comparison='PASS')]
    samples = frames(['Initial', 'BeforeReplace', 'UnlinkedHeld', 'Closed'])
    r = dict(RenameStatus='0x00000000', LinkedReopenStatus='0x00000000', HeldReopenStatus='0x00000000',
             ClosedReopenStatus='0xC000000D', RenameAttempts=1, Classification='NativeDestroyedChargeHeld', NativeDestroyed=True,
             PersistedReleaseVerified=False, AccountingReleased=False,
             Before=observation('Predecessor'), Held=observation('Predecessor', links=0),
             Successor=observation('New', eof=192), Frames=samples)
    for step, status in [('LinkedById','0x00000000'),('HeldById','0x00000000'),('ClosedById','0xC000000D')]:
        rows.append(dict(Kind='Native', Operation='NtCreateFile/ById', Step=step, NTSTATUS=status, FileInternalId='01-02-03-04-05-06-07-08',
                         ExpectedIdentity=r['Before']['Identity'], Access=0x120081, Share=7, Options=0x20206A))
    rows += [dict(Kind='ReleaseResult', Result=r, Comparison='PASS'),
             dict(Kind='RetentionResult', Key='Release', Frames=copy.deepcopy(samples), Comparison='PASS'),
             dict(Kind='FreeClusterObservation', Before=10000, Held=9999, AfterClose=10001, Asserted=False)]
    return rows


def one(rows, kind): return next(r for r in rows if r['Kind'] == kind)


def target_code():
    source = (HERE/'Invoke-TargetNativeControl.sh').read_text()
    return source.split('verdict() {', 1)[1].split("<<'PY'\n", 1)[1].split('\nPY\n}', 1)[0]


def builder_code():
    source = (HERE/'Invoke-BuilderNativeControl.sh').read_text()
    return re.findall(r"<<'PY'[^\n]*\n(.*?)\nPY", source, re.S)[0]


def write_fixture(root, rows, subject):
    (root/(subject+'-exit.txt')).write_text('0\n')
    (root/(subject+'-stderr.txt')).write_text('')
    (root/(subject+'.jsonl')).write_text('\n'.join(map(json.dumps, rows))+'\nNativeStoreMechanism=PASS\n')
    token = one(rows, 'Token')
    p = dict(Subject=subject, SHA256=SHA, Parser='5.1 PASS', SID=token['SID'], User=token['User'], Admin=subject=='admin', Session=1, BootId='post-boot')
    (root/(subject+'-subject.json')).write_text(json.dumps(p))
    for suffix in ('before', 'after'):
        (root/(subject+'-'+suffix+'.txt')).write_text('BootId=post-boot\n')
    (root/'actor-initial.txt').write_text('BootId=old-boot\n')
    (root/'actor-post-reboot.txt').write_text('BootId=post-boot\n')
    (root/'actor-task-exit.txt').write_text('0\n')
    (root/'actor-session.txt').write_text('ACTOR_SESSION=1\n')
    (root/'admin-initial.txt').write_text('BootId=post-boot\n')
    (root/'admin-launch.txt').write_text('AdminWrapperExit=0\n')


def check(name, rows, expected, mode='target'):
    with tempfile.TemporaryDirectory(prefix='t9-verdict-') as temp:
        root = Path(temp)
        if mode == 'target':
            write_fixture(root, rows, 'actor')
            cmd = [sys.executable, '-', str(root), 'actor', SHA]
            code = target_code()
        else:
            collected = root/'collected'
            collected.mkdir()
            write_fixture(collected, rows, 'admin')
            p = json.loads((collected/'admin-subject.json').read_text())
            p.update(MechanismDiscovery=True, ProductQualification=False, TargetEvidence=False)
            (collected/'admin-subject.json').write_text(json.dumps(p))
            cmd = [sys.executable, '-', str(root), SHA, 'BUILDER', 'vika']
            code = builder_code()
        run = subprocess.run(cmd, input=code, text=True, cwd=REPO, capture_output=True)
        assert (run.returncode == 0) == expected, name + ': ' + run.stdout + run.stderr
        print(name + '=PASS (' + ('accepted' if expected else 'rejected') + ')')


def main():
    check('TargetPositive', receipts(), True)
    cases = []
    def mutant(name, change):
        rows = receipts(); change(rows); cases.append((name, rows))
    mutant('MissingFaultRow', lambda r: r.remove(one(r, 'FaultResult')))
    mutant('DuplicateFaultRow', lambda r: r.append(copy.deepcopy(one(r, 'FaultResult'))))
    mutant('DuplicateFaultKey', lambda r: [f for f in r if f['Kind']=='FaultResult'][1]['Result'].update(Stage='Allocation'))
    mutant('WrongExpectedOS', lambda r: one(r, 'Verdict').update(ExpectedOS='19045.6466'))
    mutant('FlippedFaultStatus', lambda r: one(r, 'FaultResult')['Result'].update(Status='0x00000000'))
    mutant('RefusedCallChangedState', lambda r: one(r, 'FaultResult')['Result']['After'].update(EndOfFile=1))
    mutant('WrongClassification', lambda r: one(r, 'FaultResult')['Result'].update(Classification='Committed'))
    for step in ('AfterFault', 'Normalized', 'Closed'):
        def decrease(rows, step=step):
            row = one(rows, 'FaultResult')['Result']
            frame = next(f for f in row['Frames'] if f['Step']==step)
            frame['Objects'][0]['Retained'] = 4096; frame['Total'] -= 8192
            receipt = next(r for r in rows if r.get('Kind')=='RetentionResult' and r['Key']==row['Stage'])
            receipt['Frames'] = copy.deepcopy(row['Frames'])
        mutant('RphysDecreased'+step, decrease)
    mutant('DestroyedObjectReopenable', lambda r: one(r, 'ReleaseResult')['Result'].update(ClosedReopenStatus='0x00000000'))
    mutant('MissingIdentityProbe', lambda r: r.remove(next(n for n in r if n.get('Operation')=='NtCreateFile/ById')))
    mutant('MissingNativeFault', lambda r: r.remove(next(n for n in r if n.get('InjectedFault'))))
    mutant('MissingRetentionReceipt', lambda r: r.remove(one(r, 'RetentionResult')))
    mutant('RepeatedRename', lambda r: one(r, 'ReleaseResult')['Result'].update(RenameAttempts=2))
    mutant('PrematureAccountingRelease', lambda r: one(r, 'ReleaseResult')['Result'].update(AccountingReleased=True))
    mutant('AssertedFreeClusterTolerance', lambda r: one(r, 'FreeClusterObservation').update(Asserted=True))
    for name, rows in cases: check(name, rows, False)
    builder = receipts('19045.6466')
    one(builder, 'Token').update(User='BUILDER\\vika', SID='admin-sid', Elevated=True, IntegrityRID=12288)
    check('BuilderPositive', builder, True, mode='builder')
    one(builder, 'Environment')['ExpectedOS'] = '19045.2965'
    check('BuilderWrongExpectedOS', builder, False, mode='builder')
    print('NativeControlHostVerdictSelfCheck=PASS')


if __name__ == '__main__': main()
