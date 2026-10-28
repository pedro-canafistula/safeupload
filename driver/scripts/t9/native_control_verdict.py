"""Shared strict host validation for N-U4-06. No transport or Windows calls."""
FAULTS = ('Allocation', 'Write', 'F1', 'EOF', 'F2', 'Rename', 'F3')
KEYS = ('New', 'Predecessor', 'Residue')


def one(rows, kind):
    values = [r for r in rows if r.get('Kind') == kind]
    assert len(values) == 1, 'Missing/duplicate ' + kind
    return values[0]


def retention(frames, steps, release=False):
    assert [f['Step'] for f in frames] == steps, 'Retention coverage/order'
    held, identities = {}, {}
    unlinked = False
    for frame in frames:
        if frame['Step'] in ('UnlinkedHeld', 'PrefixRename'):
            unlinked = True
        objects = frame['Objects']
        assert [o['Key'] for o in objects] == list(KEYS), 'Charge inventory'
        total = 0
        for obj in objects:
            key, observation = obj['Key'], obj['Object']
            assert obj['Q'] == 4096, 'Nominal Q changed'
            prior = held.get(key, obj['Q'])
            closed = frame['Step'] == 'Closed' and key == ('Predecessor' if release else 'New')
            assert (observation is None) == closed, 'Missing/extra live observation'
            state = ('UnlinkedDrained' if release and frame['Step'] == 'Closed' else 'UnlinkedHeld') if key == 'Predecessor' and unlinked else 'Linked'
            assert obj['State'] == state, 'Wrong lifetime state'
            if observation is not None:
                assert observation['Identity'] and not observation['Directory'], 'Identity/type'
                assert observation['Links'] in (0, 1) and observation['EndOfFile'] >= 0 and observation['AllocationSize'] >= 0, 'Invalid observation'
                assert observation['DeletePending'] == (observation['Links'] == 0) == (state == 'UnlinkedHeld'), 'Link/DeletePending'
                assert identities.get(key, observation['Identity']) == observation['Identity'], 'Identity changed'
                identities[key] = observation['Identity']
                prior = max(prior, ((observation['AllocationSize'] + 4095) // 4096) * 4096)
                if key != 'New':
                    initial = frames[0]['Objects'][KEYS.index(key)]['Object']
                    assert observation['AllocationSize'] == initial['AllocationSize'] and observation['EndOfFile'] == initial['EndOfFile'], 'Current/residue changed'
                    if key == 'Residue':
                        assert initial == observation, 'Residue changed'
            assert obj['Retained'] == prior, 'R_phys decreased or incorrect retained charge'
            held[key] = prior
            total += prior
        assert len(set(identities.values())) == 3 and frame['Total'] == total, 'Non-additive/aliased R_phys'


def validate(rows, expected_os, sha):
    """Return the JSON verdict only after independently checking new receipts."""
    assert expected_os in ('19045.2965', '19045.6466')
    discovery = expected_os == '19045.6466'
    v, e = one(rows, 'Verdict'), one(rows, 'Environment')
    for obj in (v, e):
        assert obj['ExpectedOS'] == expected_os and obj['ExpectedBaselineMatches'] is True, 'Wrong ExpectedOS/baseline'
        assert obj['MechanismDiscovery'] is discovery and obj['TargetEvidence'] is (not discovery) and obj['ProductQualification'] is False, 'Wrong host/evidence mode'
        assert obj['TargetBaselineMatches'] is (not discovery), 'Wrong target baseline claim'
    assert v['Verdict'] == 'PASS' and not v['FirstDifference'] and v['LabStop'] is False, 'Failed verdict'
    assert v['PersistedReleaseVerified'] is False, 'Native evidence cannot prove persisted release'
    assert e['OS'] == '10.0.' + expected_os and e['ExpectBuilderTable'] is True, 'Wrong runtime OS/mode'
    script = one(rows, 'Script')
    assert script['SHA256'].upper() == sha.upper() and script['PSVersion'].startswith('5.1.') and script['ProcessBits'] == 64, 'Script/runtime mismatch'
    for kind, field, count in [('ReplacementResult', 'ReplacementRows', 32), ('AllocationResult', 'AllocationRows', 48),
                               ('FaultResult', 'FaultRows', 7), ('RetentionResult', 'RetentionRows', 8), ('ReleaseResult', 'ReleaseRows', 1)]:
        assert v[field] == count and sum(r.get('Kind') == kind for r in rows) == count, 'Missing/duplicate ' + kind
    assert not any(r.get('Kind') in ('Error', 'Fatal') or r.get('Comparison') == 'DIFFERS' for r in rows), 'Native failure'
    faults = [r for r in rows if r.get('Kind') == 'FaultResult']
    assert sorted(r['Result']['Stage'] for r in faults) == sorted(FAULTS), 'Fault coverage'
    native_faults = [r for r in rows if r.get('Kind') == 'Native' and r.get('InjectedFault') is True]
    assert sorted(r['Stage'] for r in native_faults) == sorted(FAULTS), 'Missing/duplicate native fault receipt'
    retained = [r for r in rows if r.get('Kind') == 'RetentionResult']
    assert sorted(r['Key'] for r in retained) == sorted(FAULTS + ('Release',)), 'Retention coverage'
    for event in faults:
        r = event['Result']
        stage = FAULTS.index(r['Stage'])
        assert event['Comparison'] == 'PASS' and r['Classification'] == 'Held', 'Fault classification'
        assert r['Status'] == ('0xC0000043' if stage == 5 else '0xC0000022'), 'Fault status'
        assert isinstance(r['IoStatus'], str) and isinstance(r['Information'], int), 'Missing raw fault IO_STATUS'
        native = next(n for n in native_faults if n['Stage'] == r['Stage'])
        assert (native['NTSTATUS'], native['IoStatus'], native['Information']) == (r['Status'], r['IoStatus'], r['Information']), 'Native/result mismatch'
        assert native['Operation'] == ('NtWriteFile' if stage==1 else 'NtSetInformationFile' if stage in (0,3,5) else 'NtFlushBuffersFile'), 'Wrong fault API'
        assert native['Class'] == {0:19, 3:20, 5:65}.get(stage,0) and native['Flags'] == (3 if stage==5 else 0), 'Wrong fault class/flags'
        assert (native['Access'], native['Share'], native['Options']) == (0x130083 if stage==5 else 0x130081, 7, 0x20006A), 'Wrong fault mask/options'

        assert r['RenameAttempts'] == (1 if stage >= 5 else 0) and r['SuccessfulRenames'] == (1 if stage == 6 else 0), 'Repeated/missing rename'
        assert (r['L'], r['P'], r['Q'], r['NormalizedEOF']) == (192, 4096, 4096, 0 if stage < 2 else 192), 'Fault geometry'
        before, after, normalized = r['Before'], r['After'], r['Normalized']
        assert before == after, 'Refused call changed state'
        assert before['AllocationSize'] == 12288 and before['EndOfFile'] == (0 if stage < 2 else 4096 if stage < 4 else 192), 'Missing real overrun/prefix'
        assert normalized == dict(before, AllocationSize=4096, EndOfFile=r['NormalizedEOF']), 'Normalization state'
        steps = ['Initial'] + ['Prefix' + f for f in FAULTS[:stage]] + ['BeforeFault', 'AfterFault', 'NormalizeEOF', 'NormalizeF2', 'NormalizeAllocation', 'Normalized', 'Closed']
        retention(r['Frames'], steps)
        by_step = {f['Step']: f for f in r['Frames']}
        for name, observation in [('BeforeFault', before), ('AfterFault', after), ('Normalized', normalized)]:
            assert by_step[name]['Objects'][0]['Object'] == observation, 'Fault observation mismatch'
        assert [o['Object'] for o in by_step['BeforeFault']['Objects']] == [o['Object'] for o in by_step['AfterFault']['Objects']], 'Refusal changed current/residue'
        receipt = next(f for f in retained if f['Key'] == r['Stage'])
        assert receipt['Comparison'] == 'PASS' and receipt['Frames'] == r['Frames'], 'Retention receipt mismatch'
    event = one(rows, 'ReleaseResult')
    r = event['Result']
    assert r['RenameAttempts'] == 1, 'Repeated/missing release rename'
    assert event['Comparison'] == 'PASS' and r['Classification'] == 'NativeDestroyedChargeHeld', 'Release classification'
    assert (r['RenameStatus'], r['LinkedReopenStatus'], r['HeldReopenStatus'], r['ClosedReopenStatus']) == ('0x00000000', '0x00000000', '0x00000000', '0xC000000D'), 'Release identity status'
    assert r['NativeDestroyed'] is True and r['PersistedReleaseVerified'] is False and r['AccountingReleased'] is False, 'Release proof boundary'
    probes = [p for p in rows if p.get('Kind')=='Native' and p.get('Operation')=='NtCreateFile/ById']
    assert sorted(p['Step'] for p in probes)==['ClosedById','HeldById','LinkedById'], 'Missing/duplicate identity probe'
    assert len({p['FileInternalId'] for p in probes})==1, 'Identity probe ID changed'
    for probe in probes:
        expected = {'LinkedById':'0x00000000', 'HeldById':'0x00000000', 'ClosedById':'0xC000000D'}[probe['Step']]
        assert probe['NTSTATUS']==expected and probe['ExpectedIdentity']==r['Before']['Identity'], 'Identity probe status/binding'
        assert (probe['Access'], probe['Share'], probe['Options'])==(0x120081, 7, 0x20206A), 'Identity probe mask/options'

    before, held, successor = r['Before'], r['Held'], r['Successor']
    assert held == dict(before, Links=0, DeletePending=True) and held['AllocationSize'] >= 4096, 'Held predecessor changed/lost allocation'
    assert before['Identity'] != successor['Identity'] and before['Links'] == successor['Links'] == 1 and not before['DeletePending'] and not successor['DeletePending'], 'Predecessor/current lifetime'
    retention(r['Frames'], ['Initial', 'BeforeReplace', 'UnlinkedHeld', 'Closed'], release=True)
    assert r['Frames'][1]['Objects'][1]['Object'] == before and r['Frames'][2]['Objects'][1]['Object'] == held and r['Frames'][2]['Objects'][0]['Object'] == successor, 'Release observation mismatch'
    receipt = next(f for f in retained if f['Key'] == 'Release')
    assert receipt['Comparison'] == 'PASS' and receipt['Frames'] == r['Frames'], 'Release retention receipt mismatch'
    free = one(rows, 'FreeClusterObservation')
    assert free['Asserted'] is False and all(isinstance(free[k], int) for k in ('Before', 'Held', 'AfterClose')), 'Free clusters must be observation only'
    return v
