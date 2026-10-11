import subprocess,datetime,json,hashlib
from pathlib import Path
w=Path('/tmp/m2-t5-harness-r24-full-gate-1011-a1-root');script=Path('/tmp/m2-t5-r24-post-readonly.ps1').read_bytes();assert len(script)<2450
transport=w/'tree/driver/scripts/remote_ps.py';assert hashlib.sha256(transport.read_bytes()).hexdigest()=='39ed7a7892555d61b1577380fd84888ab39278a0115a7ca9b47b16ca6c52995b'
with (w/'post-readonly.stdout.log').open('xb') as out,(w/'post-readonly.stderr.log').open('xb') as err:
 p=subprocess.Popen(['python','-I','-B',str(transport),'192.168.122.210'],stdin=subprocess.PIPE,stdout=out,stderr=err)
 print('Read-only postcheck transport PID',p.pid,flush=True);p.communicate(script);code=p.returncode
raw=(w/'post-readonly.stdout.log').read_bytes();stderr=(w/'post-readonly.stderr.log').read_bytes();r={'QueryUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'PID':p.pid,'ExitCode':code,'StdoutSHA256':hashlib.sha256(raw).hexdigest(),'StderrSHA256':hashlib.sha256(stderr).hexdigest(),'ScriptSHA256':hashlib.sha256(script).hexdigest(),'ProcessTerminal':True,'RemoteFilesObservedUnchanged':False,'RuntimeQualified':False}
if code==0 and not stderr:
 d=json.loads(raw);plan=json.loads((w/'prepared-plan.json').read_text());assert len(d['RemoteFiles'])==40
 for n,h in d['RemoteFiles'].items():assert plan['SourcePins']['driver/scripts/'+n]==h,n
 r['RemoteFilesObservedUnchanged']=True;r['AppDataAttributes']=d['AppDataAttributes'];r['OriginalRemoteProcessTerminalProof']=False
with (w/'post-readonly-root-result.json').open('x') as f:json.dump(r,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps(r),flush=True);raise SystemExit(code)
