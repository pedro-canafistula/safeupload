#!/usr/bin/env python3
"""Offline Excel/Word receipts, secret channel and Office lifecycle; no VM/network/COM."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import struct
import sys
import tempfile
import uuid

root = Path(__file__).resolve().parent
launcher_path = root.parent / 'Invoke-StageNotepad.sh'
launcher = launcher_path.read_text()
inventory = json.loads((root / 'notepad-cases.json').read_text())
office = [c for c in inventory if c.get('Office')]
assert len(inventory) == 32 and {c['Kind'] for c in office} == {'ExcelSaveAsApprove', 'ExcelInPlaceApprove', 'ExcelCpfHandBack',
    'WordSaveAsApprove', 'WordInPlaceApprove', 'WordOverwriteApprove', 'WordCpfHandBack'}
module_spec = importlib.util.spec_from_file_location('host_controls', root / 'notepad-verdict.SelfCheck.py')
module = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(module)
names = {'office_record_matches', 'office_releases', 'office_steps_match', 'office_journal_matches', 'office_final_matches',
         'office_app', 'office_versions', 'word_alerts_match',
         'workflow_spec', 'workflow_steps_match', 'workflow_journal_matches', 'workflow_handback_matches', 'raw_case_final_matches',
         'approved_public_hash_map', 'workflow_observed_bytes_match', 'archive_payload_matches'}
functions = [n for block in re.findall(r"<<'PY'\n(.*?)\nPY\n", launcher, re.S)
             for n in ast.parse(block).body if isinstance(n, ast.FunctionDef) and n.name in names]
assert {n.name for n in functions} == names
sid = 'S-1-5-21-100-200-300-1000'
scope = r'c:\protected\t5'
env = dict(module.environment, required_cases=office, result={'ActorSid': sid, 'Cases': [],
           'HandbackDirectory': r'C:\Users\t5actor\SafeUpload\_bloqueados'})
exec(compile(ast.Module(body=functions, type_ignores=[]), str(launcher_path), 'exec'), env)
checks = 0


def check(value, message):
    global checks
    checks += 1
    assert value, message


with tempfile.TemporaryDirectory(prefix='t5-office-controls-') as temp:
    work = Path(temp)
    env['raw_dir'] = str(work / 'row-raw')
    journals = work / 'row-journal-evidence'; journals.mkdir()
    handbacks = work / 'row-handback-evidence'; handbacks.mkdir()
    alerts = work / 'row-word-alerts'; alerts.mkdir()
    for spec in office:
        app = spec.get('OfficeApp', 'Excel'); prefix = app.lower(); versions_key = app+'Versions'
        sensitive = spec['Sensitive']
        case = dict(spec, Path=scope+'\\'+spec['Leaf'], NativeStepsChecked=True, NativeStepsOk=True,
                    JournalParseErrors=[], JournalSchemaErrors=[], FinalJournalOutcomeVerified=True, SettlementStatus='PASS')
        next_op = 'word-overwrite' if spec['Kind'] == 'WordOverwriteApprove' else prefix+'-edit'
        ops = [spec['Op'], prefix+'-read'] if sensitive else [spec['Op'], next_op, prefix+'-read']
        case['WorkflowAcks'] = []
        handback_path = env['result']['HandbackDirectory']+'\\'+spec['Leaf']
        for i, op in enumerate(ops):
            final = i > 0 or sensitive
            a1 = '529.982.247-25' if sensitive else (2 if final else 1) if spec['Kind'] == 'ExcelInPlaceApprove' else 'T5 '+spec['Kind']
            ui = dict(SessionId=3, Version='16.0', Build='16.0.20326' if app == 'Word' else '20326', Action=op,
                      Saved=True, Ready=True, Closed=True, Quit=True, ReadOnly=False,
                      ProtectedViewCount=0, Windows=['Workbook - Excel'], WindowsAtExit=[], A1=a1, B1=3,
                      C1='blocked' if sensitive else 'edit' if final else 'prior', PriorCellsVerified=op == 'excel-edit')
            ui.update({app+'Pid': 600+i, app+'Sid':sid, app+'CreationTime':10000+i, app+'Exited':True})
            if app == 'Word':
                ui.update(Text='T5 Word CPF: 529.982.247-25' if sensitive else 'T5 '+spec['Kind']+(' inspected newer save' if final else ' published clean prior'),
                          PriorTextVerified=op == 'word-edit', Windows=['Document - Word'], AlertTexts=[])
                monitor = dict(WordPid=600+i, WordCreationTime=10000+i, SawWordWindow=True, MonitorPid=900+i, MonitorSid=sid, SessionId=3, Ready=True,
                               Stopped=True, TimedOut=False, PollCount=3, AlertTexts=[], Error=None)
                artifact = uuid.uuid4().hex+'.json'
                (alerts / artifact).write_text(json.dumps(monitor))
                ui['AlertMonitor'] = dict(monitor, Artifact='C:/T5/control/word-alerts/'+artifact)
            case['WorkflowAcks'].append(dict(N=i+1, Op=op, Path=handback_path if sensitive and op == prefix+'-read' else case['Path'],
                                            ActorPid=500, ActorSid=sid, Steps=prefix+'=0', Ui=ui))
        versions = []
        payloads = []
        for i in range(1 if sensitive else 2):
            payload = (f'PK exact {spec["Kind"]} workbook version {i}').encode()
            payloads.append(payload)
            digest = hashlib.sha256(payload).hexdigest().upper()
            row = dict(TransferId=uuid.uuid4().hex, DestinationPath=case['Path'], ProcessId=600+i,
                       ProcessName='WINWORD.EXE' if app == 'Word' else 'EXCEL.EXE', RequestorSid=sid, RequestorProcessCreationTime=10000+i, SessionId=3, State='6' if sensitive else '5',
                       HandbackState='2' if sensitive else '0', StageDeleted=True, SealedOnce=True,
                       Sha256Hex=digest, SealedLength=len(payload), DestinationGeneration=i+1,
                       DriverInstanceId='test-driver', StageIdentity=dict(VolumeSerialNumber=1, FileIdHigh=2, FileIdLow=3+i))
            transfer = {k: row[k] for k in ('TransferId','DestinationPath','ProcessId','ProcessName','RequestorSid','SessionId','RequestorProcessCreationTime')}
            manifest = dict(row, Transfer=transfer, State=int(row['State']), HandbackState=int(row['HandbackState']))
            data = json.dumps(manifest).encode()
            artifact = hashlib.sha256(data).hexdigest().upper()+'.bin'
            (journals / artifact).write_bytes(data)
            row['JournalArtifact'] = artifact
            if i == 0:  # Exercise the real archive branch as well as hot manifests.
                prefix16 = struct.pack('<Iiq', 0x43415553, 1, 4096+60+len(data))
                frame = struct.pack('<Iii', 0x414A5553, 1, len(data))+uuid.UUID(row['TransferId']).bytes_le+hashlib.sha256(data).digest()+data
                container = (prefix16+hashlib.sha256(prefix16).digest()).ljust(4096, b'\0')+frame
                container_name = hashlib.sha256(container).hexdigest().upper()+'.bin'
                (journals / container_name).write_bytes(container)
                row['ArchiveRecord'] = dict(Artifact=container_name, FrameOffset=4096, Length=len(data),
                                            Sha256=hashlib.sha256(data).hexdigest().upper(), TransferId=row['TransferId'])
            versions.append(row)
        case[versions_key] = versions
        case.update(Journal=copy.deepcopy(versions),
                    StageEvidence=[dict(TransferId=j['TransferId'], Exists=False) for j in versions],
                    ExpectedLength=len(payloads[-1]), ExpectedSha256=versions[-1]['Sha256Hex'])
        if spec['Kind'] == 'WordOverwriteApprove':
            case['WorkflowAcks'][1]['Ui'].update(OverwriteRequested=True,
                OverwritePriorRead=dict(Code=0, Steps='read-open=0 read=0 read-close=0', Length=versions[0]['SealedLength'], Sha256=versions[0]['Sha256Hex']))
        case['WorkflowAcks'][-1].update(Steps=prefix+'=0 read-open=0 read=0 read-close=0',
                                      Read=dict(Code=0, Length=len(payloads[-1]), Sha256=versions[-1]['Sha256Hex']))
        if sensitive:
            digest = versions[0]['Sha256Hex']
            (handbacks / (digest+'.bin')).write_bytes(payloads[0])
            case.update(HandedBack=True, ExpectedHandbackLength=len(payloads[0]), ExpectedHandbackSha256=digest,
                        Handback=dict(Status='PASS', NewFileCount=1, Path=handback_path, Length=len(payloads[0]),
                                      Sha256=digest, Artifact=digest+'.bin', Readers=[dict(Unbuffered=u, Status='OK',
                                      Length=len(payloads[0]), Sha256=digest) for u in (False, True)]))
        env['result']['Cases'] = [case]
        check(env['workflow_steps_match'](case), spec['Kind']+' COM/cell/byte receipts')
        check(env['workflow_journal_matches'](case), spec['Kind']+' retained exact journal bytes')
        allowed = env['approved_public_hash_map']()
        check(allowed[spec['Leaf']] == (set() if sensitive else {j['Sha256Hex'] for j in versions}), 'only released clean hashes public')
        observation = module.sample(1, spec['Leaf'], not sensitive)
        if not sensitive:
            for key in ('CurrentImages', 'PublicReaders', 'ObserverReaders'):
                for image in observation[key]:
                    if image['Path'].lower() == case['Path'].lower():
                        image.update(Length=len(payloads[-1]), Sha256=versions[-1]['Sha256Hex'])
                        if image.get('LogicalArtifact'): image['LogicalArtifact'].update(Length=len(payloads[-1]), Sha256=versions[-1]['Sha256Hex'])
        check(env['raw_case_final_matches'](case, [observation]), 'exact raw workbook final')
        check(env['workflow_observed_bytes_match'](observation), 'raw workbook whitelist')
        if not sensitive:
            bad = copy.deepcopy(case); bad['Journal'][-1]['State'] = '3'
            env['result']['Cases'] = [bad]
            check(versions[-1]['Sha256Hex'] not in env['approved_public_hash_map']()[spec['Leaf']], 'unreleased version never authorizes bytes')
            env['result']['Cases'] = [case]
        for mutation in ('cell', 'readonly', 'dialog', 'actor', 'excel-subject', 'live-excel', 'wrong-read', 'missing-ack', 'missing-creation'):
            bad = copy.deepcopy(case); last = bad['WorkflowAcks'][-1]
            if mutation == 'cell': last['Ui']['Text' if app == 'Word' else 'A1'] = 'wrong text/cell'
            if mutation == 'readonly': last['Ui']['ReadOnly'] = True
            if mutation == 'dialog': last['Ui']['Windows'].append('Error dialog')
            if mutation == 'actor': last['ActorSid'] = 'S-1-5-18'
            if mutation == 'excel-subject': last['Ui'][app+'Sid'] = 'S-1-5-18'
            if mutation == 'live-excel': last['Ui'][app+'Exited'] = False
            if mutation == 'wrong-read': last['Read']['Sha256'] = '0'*64
            if mutation == 'missing-ack': bad['WorkflowAcks'].pop()
            if mutation == 'missing-creation': last['Ui'][app+'CreationTime'] = None
            check(not env['workflow_steps_match'](bad), spec['Kind']+' rejects '+mutation)
        if app == 'Word':
            for mutation in ('alert', 'missing-monitor', 'monitor-subject', 'blind-monitor', 'old-process', 'monitor-timeout', 'COM-error', 'missing-log'):
                bad = copy.deepcopy(case); ui = bad['WorkflowAcks'][-1]['Ui']
                if mutation == 'alert': ui['AlertTexts'] = ['Word: file permission error']
                if mutation == 'missing-monitor': ui.pop('AlertMonitor')
                if mutation == 'monitor-subject': ui['AlertMonitor']['MonitorSid'] = 'S-1-5-18'
                if mutation == 'blind-monitor': ui['AlertMonitor']['SawWordWindow'] = False
                if mutation == 'old-process': ui['AlertMonitor']['WordCreationTime'] -= 1
                if mutation == 'monitor-timeout': ui['AlertMonitor']['TimedOut'] = True
                if mutation == 'COM-error': ui['ErrorText'] = 'HRESULT file permission error'
                if mutation == 'missing-log': ui['AlertMonitor']['Artifact'] = 'C:/T5/control/word-alerts/'+'0'*32+'.json'
                check(not env['workflow_steps_match'](bad), spec['Kind']+' rejects '+mutation)
            name = case['WorkflowAcks'][-1]['Ui']['AlertMonitor']['Artifact'].rsplit('/', 1)[-1]
            original_log = (alerts / name).read_bytes()
            log = json.loads(original_log); log['AlertTexts'] = ['Word: file permission error']
            (alerts / name).write_text(json.dumps(log))
            check(not env['workflow_steps_match'](case), spec['Kind']+' retained alert cannot be hidden by the actor receipt')
            (alerts / name).write_bytes(original_log)
            if next_op == 'word-edit' and not sensitive:
                bad = copy.deepcopy(case); bad['WorkflowAcks'][1]['Ui']['PriorTextVerified'] = False
                check(not env['workflow_steps_match'](bad), spec['Kind']+' must reopen the published prior')
            if spec['Kind'] == 'WordOverwriteApprove':
                for mutation in ('missing-request', 'wrong-prior', 'edit-instead'):
                    bad = copy.deepcopy(case)
                    if mutation == 'missing-request': bad['WorkflowAcks'][1]['Ui']['OverwriteRequested'] = False
                    if mutation == 'wrong-prior': bad['WorkflowAcks'][1]['Ui']['OverwritePriorRead']['Sha256'] = '0'*64
                    if mutation == 'edit-instead': bad['WorkflowAcks'][1]['Op'] = 'word-edit'
                    check(not env['workflow_steps_match'](bad), 'Word overwrite rejects '+mutation)
        for mutation in ('hash', 'length', 'path', 'identity', 'generation', 'uninspected', 'unreleased', 'leftover', 'missing-proof', 'process-reuse'):
            bad = copy.deepcopy(case)
            if mutation == 'hash': bad[versions_key][-1]['Sha256Hex'] = '0'*64
            if mutation == 'length': bad[versions_key][-1]['SealedLength'] += 1
            if mutation == 'path': bad[versions_key][-1]['DestinationPath'] = r'C:\outside.xlsx'
            if mutation == 'identity': bad[versions_key][-1]['StageIdentity']['FileIdLow'] += 1
            if mutation == 'generation': bad[versions_key][-1]['DestinationGeneration'] += 1
            if mutation == 'uninspected': bad[versions_key][-1]['SealedOnce'] = False
            if mutation == 'unreleased': bad[versions_key][-1]['State'] = '3'
            if mutation == 'leftover': bad['StageEvidence'][-1]['Exists'] = True
            if mutation == 'missing-proof':
                bad[versions_key][-1]['JournalArtifact'] = ''
                if bad[versions_key][-1].get('ArchiveRecord'): bad[versions_key][-1]['ArchiveRecord']['Artifact'] = ''
            if mutation == 'process-reuse': bad[versions_key][-1]['RequestorProcessCreationTime'] += 1
            check(not env['workflow_journal_matches'](bad), spec['Kind']+' rejects '+mutation)
        bad_sample = copy.deepcopy(observation)
        image = next(i for i in bad_sample['CurrentImages'] if i['Path'].lower() == case['Path'].lower())
        image.update(Absent=False, Length=1, Sha256='0'*64)
        check(not env['raw_case_final_matches'](case, [bad_sample]), 'wrong raw final workbook fails')
        check(not env['workflow_observed_bytes_match'](bad_sample), 'unapproved workbook bytes fail')
        if sensitive:
            check(not env['raw_case_final_matches'](case, [bad_sample, observation]), 'CPF transient publication cannot be erased')
            (handbacks / (digest+'.bin')).write_bytes(b'wrong hand-back')
            check(not env['workflow_journal_matches'](case), 'CPF corrupt hand-back fails')

    # Run the actual generator with a synthetic temp file, never the real secret.
    blocks = re.findall(r"<<'PY'[^\n]*\n(.*?)\nPY\n", launcher, re.S)
    secret_code = next(b for b in blocks if 'os.O_NOFOLLOW' in b)
    secret = work / 'synthetic-password.txt'
    secret.write_text('synthetic only $() ; " password\n'); secret.chmod(0o600)
    generated = subprocess.run([sys.executable, '-c', secret_code, str(secret)], capture_output=True, text=True)
    check(generated.returncode == 0 and 'AutoLogonCount -Value 1' in generated.stdout, 'one-boot password generator')
    check('synthetic only' not in generated.stdout+generated.stderr, 'password encoded as data')
    check(len(generated.stdout.encode('utf-16le'))*4//3+200 < 7000, 'fits existing encoded-command channel')
    secret.chmod(0o644)
    rejected = subprocess.run([sys.executable, '-c', secret_code, str(secret)], capture_output=True, text=True)
    check(rejected.returncode != 0 and not rejected.stdout and 'synthetic' not in rejected.stderr, 'unsafe permissions fail without leaking')
    check("<<'PY' | remote >/dev/null 2>&1" in launcher, 'remote error/source output silenced')

    start = launcher.index('t5_office_preflight() {')
    end = launcher.index('\nif [ "$office_base" = 1 ]; then t5_office_preflight', start)
    lifecycle = launcher[start:end]
    baseline = work / 'base.qcow2'; baseline.write_text('original base')
    office_disk = work / 'office.qcow2'; office_disk.write_text('Office base')
    state = work / 'states'; state.mkdir()
    prefix = f'''set -uo pipefail
ev={shlex.quote(temp)}
tag=stub
dom=win10-debug3
office_base=1
code_scripts={shlex.quote(str(root.parent))}
RUN_DISK_STATE={shlex.quote(str(state))}
t5_original_base={shlex.quote(str(baseline))}
t5_office_base={shlex.quote(str(office_disk))}
t5_office_repoint=0
printf '%s' "$t5_original_base" > "$ev/current"
printf 'shut off' > "$ev/power"
fake_virsh() {{
 case "$1" in
 domstate) if [ "$2" = win10-debug2 ]; then echo 'shut off'; else cat "$ev/power"; fi ;;
 dumpxml) printf '<domain><vda>%s</vda></domain>\\n' "$(cat "$ev/current")" ;;
 destroy) printf 'shut off' > "$ev/power"; echo destroy >> "$ev/trace" ;;
 *) echo 'unexpected fake virsh call' >&2; return 1 ;;
 esac
}}
V=fake_virsh
_rd_vda() {{ cat "$ev/current"; }}
_rd_vol() {{ if [ "$2" = format ]; then echo qcow2; else echo "$t5_original_base"; fi; }}
_rd_named_elsewhere() {{ return 1; }}
_rd_repoint() {{ [ "$(cat "$ev/power")" = 'shut off' ] || return 1; printf '%s' "$2" > "$ev/current"; printf 'repoint:%s\\n' "$2" >> "$ev/trace"; }}
_rd_shutdown() {{ printf 'shut off' > "$ev/power"; }}
'''
    for mutation in ('none', 'running', 'wrong-vda', 'parked', 'sibling-state', 'wrong-backing', 'shared'):
        extra = {'none':'', 'running':'echo running > "$ev/power"', 'wrong-vda':'echo other > "$ev/current"',
                 'parked':'touch "$RUN_DISK_STATE/win10-debug3.parked-other"', 'sibling-state':'touch "$RUN_DISK_STATE/win10-debug2"',
                 'wrong-backing':'_rd_vol() { echo wrong; }', 'shared':'_rd_named_elsewhere() { return 0; }'}[mutation]
        run = subprocess.run(['bash'], input=prefix+lifecycle+'\n'+extra+'\nt5_office_preflight\n', text=True, capture_output=True)
        check((run.returncode == 0) == (mutation == 'none'), 'preflight '+mutation+run.stderr)
        for p in state.iterdir(): p.unlink()
    for full_status, cleanup_ok in ((0, True), (1, True), (129, True), (130, True), (143, True), (0, False)):
        (work / 'stub-verdict.txt').write_text('T5RunProfile INFO OfficeExcel\n')
        (work / 'trace').write_text('')
        body = '''
t5_office_preflight || exit 90
t5_office_repoint=1
_rd_repoint "$dom" "$t5_office_base" || exit 91
printf 'disposable-overlay' > "$ev/current"
echo running > "$ev/power"
run_disk_end() {
 echo end >> "$ev/trace"
'''+(' printf "shut off" > "$ev/power"\n printf "%s" "$t5_office_base" > "$ev/current"\n return 0\n' if cleanup_ok else ' return 1\n')+''' }
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
'''+('kill -'+{129:'HUP',130:'INT',143:'TERM'}[full_status]+' $$\n' if full_status in (129,130,143) else f'exit {full_status}\n')
        run = subprocess.run(['bash'], input=prefix+lifecycle+body, text=True, capture_output=True)
        expected_status = 22 if not cleanup_ok else full_status or 1  # task receipts deliberately missing
        check(run.returncode == expected_status, 'finalizer status: '+run.stderr)
        check((work / 'current').read_text() == str(baseline), 'always return original vda')
        trace = (work / 'trace').read_text()
        check(trace.index('end') < trace.rindex('repoint:'), 'return original after run_disk_end')
        check('T5OfficeBase PASS' in (work / 'stub-verdict.txt').read_text(), 'original XML and both base stats verified')
        check(('T5Restoration FAIL' in (work / 'stub-verdict.txt').read_text()) == (not cleanup_ok), 'cleanup failure stays failed')

actor = (root / 'notepad-actor.ps1').read_text()
excel = actor[actor.index('function Invoke-T5Excel('):actor.index('function Start-T5WordAlertMonitor')]
check('[IO.Path]::Combine' in excel and 'Join-Path ' not in re.sub(r'#[^\n]*', '', excel), 'Excel COM uses CLR Combine strings')
check('$wb.SaveAs($target,51)' in excel and '$wb.Save()' in excel and '$x.Workbooks.Open($target)' in excel, 'real Excel SaveAs/Save/reopen')
word = actor[actor.index('function Invoke-T5Word('):actor.index('function Read-ActorControlText')]
check('[IO.Path]::Combine' in word and 'Join-Path ' not in re.sub(r'#[^\n]*', '', word), 'Word COM uses CLR Combine strings')
check('$doc.SaveAs2($target,16)' in word and '$doc.Save()' in word and '$w.Documents.Open($target,$false,$false)' in word,
      'real Word new/overwrite SaveAs, in-place Save and writable reopen')
check('$w.ActiveWindow.Hwnd' in word and '$w.Hwnd' not in word, 'Word identity binds the actual document window')
check('word-alerts' in launcher and 'Start-Job' in actor and 'TryGetCurrentPattern' in actor, 'interactive alert monitor logs retained even while COM blocks')
check('.BackgroundSave=' not in word and 'MemoryPressure' not in word, 'Word save pattern has no background-save or section-trimming workaround')
baseline_source = (root.parent / 'Get-StagedBaseline.ps1').read_text()
check("[switch] $OfficeBase" in baseline_source and "if ($OfficeBase)" in baseline_source, 'baseline opt-in')
check("$checks['NoTestProfiles'] = (@(Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -notmatch '\\\\vika$' }).Count -eq 0)" in baseline_source,
      'default profile check unchanged')
check('16.0.20326.20232' in baseline_source and "'NoActorAutoLogonValues'" in baseline_source, 'Office pin and no persistent autologon')
check('if ($officeBase)' in launcher and '} else {\n$password =' in launcher, 'creation guarded out of Office path')
check('Set-LocalUser' not in launcher and 'Remove-LocalUser' not in launcher, 'no reset/account deletion')
print(f'T5OfficeSelfCheck=PASS;Assertions={checks};ProductQualified=False')
