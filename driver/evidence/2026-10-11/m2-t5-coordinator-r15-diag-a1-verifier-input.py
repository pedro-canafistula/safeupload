import importlib.util,sys,re,json,datetime,subprocess,hashlib
from pathlib import Path
work=Path('/tmp/m2-t5-coordinator-r15-diag-1011-a1-root');ev=Path('/home/victor/Work/safeupload-staging/driver/evidence/2026-10-11')
spec=importlib.util.spec_from_file_location('stable', '/tmp/safeupload-t5-root-checkpoint-captures.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
result=json.loads(m.read(ev/'m2-t5-coordinator-r15-diag-a1-root-result.json')[0]);raw=m.read(ev/'m2-t5-coordinator-r15-diag-a1-controls.stdout.log')[0];text=raw.decode('utf-8-sig')
ids=re.findall(r'^CONTROL_PROCESS_ID=([1-9][0-9]*);START_FILETIME=([1-9][0-9]*)\r?$',text,re.M);assert len(ids)==1,ids
pid,start=map(int,ids[0]);assert pid>0 and start>0
old=Path('/tmp/m2-t5-coordinator-r14-diag-1011-a1-root/post-check.ps1').read_text()
plan=old.replace('r14-diag','r15-diag').replace('01277FD1696D0E8A7AF81E54ED3E1DA479FCBD20061B8353D80BE78B6CD12158','DBC00A84C456B97F6903CFCB4CCC0BA37C5FF763FC6B67E83AAB3E86E807245F').replace('3716',str(pid)).replace('134361858987731274',str(start))
assert 'r14' not in plan and str(pid) in plan and str(start) in plan
with (work/'post-check.ps1').open('x') as f:f.write(plan)
logs=[ev/'m2-t5-coordinator-r15-diag-a1-post-check.stdout.log',ev/'m2-t5-coordinator-r15-diag-a1-post-check.stderr.log']
with logs[0].open('xb') as out,logs[1].open('xb') as err:
 p=subprocess.Popen([sys.executable,'-B',str(work/'remote_ps.py'),'192.168.122.210'],stdin=subprocess.PIPE,stdout=out,stderr=err)
 try:p.communicate(plan.encode(),timeout=60)
 except subprocess.TimeoutExpired:print(json.dumps({'PostCheckObservationTimeout':True,'LocalTransportPID':p.pid,'OriginalRemotePID':pid,'StartFILETIME':start}));raise
output=m.read(logs[0])[0].decode('utf-8-sig');assert p.returncode==0 and output.count('PINNED_SOURCES_UNCHANGED_AND_ORIGINAL_PROCESS_TERMINAL')==1
prep=json.loads(m.read(ev/'m2-t5-coordinator-r15-diag-a1-preparation-root.json')[0]);pins=prep['PreparedInputsSHA256'];assert all(m.sha(m.read(work/n)[0])==h for n,h in pins.items())
for name,step in result['Steps'].items():
 for ext,key in [('stdout.log','StdoutSHA256'),('stderr.log','StderrSHA256')]:assert m.sha(m.read(ev/f'm2-t5-coordinator-r15-diag-a1-{name}.{ext}')[0])==step[key]
passes=re.findall(r'^T5 coordinator schema self-check PASS \(([1-9][0-9]*) assertions\)\.\r?$',text,re.M);assert len(passes)<=1
if result['StandaloneWindowsControlsPassed']:assert len(passes)==1
record={'VerifiedUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'DiagnosticOnly':True,'OriginalControlPID':pid,'OriginalControlStartFILETIME':start,'OriginalDiagnosticProcessTerminal':True,'RemoteDirectoryContainsOnlyTwoPinnedRegularInputs':True,'LocalPreparedInputsUnchanged':True,'StandaloneWindowsControlsPassed':result['StandaloneWindowsControlsPassed'],'Assertions':int(passes[0]) if passes else None,'SelfCheckOutputHasExactlyOneCompletePASS':len(passes)==1,'DiagnosticFailure':result.get('Failure'),'ResultSHA256':m.sha(m.read(ev/'m2-t5-coordinator-r15-diag-a1-root-result.json')[0]),'PreparationSHA256':m.sha(m.read(ev/'m2-t5-coordinator-r15-diag-a1-preparation-root.json')[0]),'PostCheckSHA256':{q.name:m.sha(m.read(q)[0]) for q in logs},'SourceInputSHA256':{n:h for n,h in pins.items() if n.startswith('notepad')},'CoordinatorInvoked':False,'ProductVMStarted':False,'ServiceInstalled':False,'HostPolicyApplied':False,'RuntimeQualified':False,'PairQualified':False,'CutoverAuthorized':False}
m.write('m2-t5-coordinator-r15-diag-a1-root-verification.json',record)
