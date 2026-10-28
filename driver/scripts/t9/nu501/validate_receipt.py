#!/usr/bin/env python3
"""Independent strict component receipt check. A diagnostic self-check is not execution."""
import json
import math
import pathlib
import sys
import uuid

REQUIRED = ('Idle Probe Pair CommitWire CommitNotReady LeaseHeld LegacyBlocked '
            'ChildCreditsBusy OtherPoolBusy GrowthPoolBusy Malformed RefusedWire Refused '
            'LocalStoreBusy LocalSendBusy LocalSendsReturned HeldProgressComplete LegacyReleased '
            'ChildrenClosed DisconnectRetains RevokeLatchReleased DisconnectDrain').split()
REQUIRED += [n for cause in ('Timeout', 'Failure', 'Cancellation') for n in (f'Release{cause}Held', f'Release{cause}Returned')]
REQUIRED += [n for i in range(1, 5) for n in (f'Root{i}Wire', f'Root{i}')]
REQUIRED += [n for i in range(4) for n in
             [f'Child{i}Wire', f'Child{i}', f'Store{i}'] +
             [f'Store{i}.{step}' for step in ('Create', 'Allocation', 'Write', 'F1', 'EndOfFile', 'F2', 'F3')]]
REQUIRED += [n for pool, count in (('OtherPool', 7), ('GrowthPool', 8)) for i in range(count)
             for n in (f'{pool}{i}Wire', f'{pool}{i}')]

def validate(receipt):
    assert receipt['Schema'] == 'SafeUpload.N-U5-01.v1'
    assert uuid.UUID(hex=receipt['RunId']).hex == receipt['RunId']
    assert receipt['Verdict'] == 'PASS' and receipt['Failure'] is None
    steps = receipt['Steps']
    assert isinstance(steps, list) and 20 <= len(steps) <= 512
    for step in steps:
        assert step['Passed'] is True and isinstance(step['HResult'], int)
        assert isinstance(step['ElapsedMs'], (int, float)) and math.isfinite(step['ElapsedMs']) and step['ElapsedMs'] >= 0
        assert isinstance(step['RequestId'], int) and step['RequestId'] >= 0
        assert isinstance(step['LegacyHeld'], bool)
    def one(name):
        found = [s for s in steps if s['Name'] == name]
        assert len(found) == 1, 'missing/duplicate ' + name
        return found[0]
    for name in REQUIRED:
        one(name)
    assert all(a['ElapsedMs'] <= b['ElapsedMs'] for a, b in zip(steps, steps[1:])), 'nonmonotonic receipts'
    names = [s['Name'] for s in steps]
    assert names.index('Idle') < names.index('Probe') < names.index('Pair') < names.index('CommitNotReady') < names.index('LeaseHeld') < names.index('LegacyBlocked')
    assert names.index('HeldProgressComplete') < names.index('LegacyReleased') < names.index('DisconnectRetains') < names.index('DisconnectDrain')
    assert all(s['LegacyHeld'] is True for s in steps[names.index('LeaseHeld'):names.index('LegacyReleased')])
    for cause in ('Timeout', 'Failure', 'Cancellation'):
        assert one(f'Release{cause}Held')['LegacyHeld'] is True
        assert one(f'Release{cause}Returned')['LegacyHeld'] is False and one(f'Release{cause}Returned')['HResult'] == 0
        assert names.index(f'Release{cause}Held') < names.index(f'Release{cause}Returned') < names.index('LeaseHeld')
    assert one('DisconnectRetains')['LegacyHeld'] is True and one('RevokeLatchReleased')['LegacyHeld'] is False
    assert names.index('DisconnectRetains') < names.index('RevokeLatchReleased') < names.index('DisconnectDrain')
    for i in range(1, 5):
        root = one('Root' + str(i))
        assert root['LegacyHeld'] is True and root['RequestId'] > 0 and root['HResult'] == 0
    assert one('LegacyBlocked')['LegacyHeld'] is True
    assert one('LegacyReleased')['LegacyHeld'] is False
    for i in range(4):
        store = one('Store' + str(i))
        assert store['LegacyHeld'] is True and store['RequestId'] > 0
        for native in ('Create', 'Allocation', 'Write', 'F1', 'EndOfFile', 'F2', 'F3'):
            step = one('Store' + str(i) + '.' + native)
            assert step['LegacyHeld'] is True and step['HResult'] == 0 and step['Status'] == 'Native'
    for name in ('ChildCreditsBusy', 'OtherPoolBusy', 'GrowthPoolBusy'):
        step = one(name)
        assert step['Status'] == 'Completed' and step['HResult'] < 0 and step['RequestId'] > 0
    assert one('LocalSendBusy')['HResult'] == 0
    assert one('Malformed')['HResult'] < 0
    assert one('Refused')['HResult'] == 0
    one('ChildrenClosed')
    one('DisconnectRetains')
    one('HeldProgressComplete')
    one('LocalSendsReturned')


def main():
    root = pathlib.Path(sys.argv[1])
    receipt = json.loads((root / 'receipt.json').read_text(encoding='utf-8-sig'))
    validate(receipt)
    assert (root / 'exit.txt').read_text(encoding='utf-8-sig').strip() == '0'
    assert (root / 'verdict.txt').read_text(encoding='utf-8-sig').strip() == 'N-U5-01=PASS'
    assert not (root / 'error.txt').exists()
    client = json.loads((root / 'client.json').read_text(encoding='utf-8-sig'))
    assert client['PSVersion'].startswith('5.1.') and client['Bits'] == 64
    peer = json.loads((root / 'peer.json').read_text(encoding='utf-8-sig'))
    assert peer['ServerPid'] == peer['ServicePid'] and peer['ServerPid'] > 0 and peer['ServiceName'] == 'SafeUploadAgent'
    assert peer['Boot'] == client['Boot']
    print('N-U5-01=PASS')

if __name__ == '__main__':
    main()
