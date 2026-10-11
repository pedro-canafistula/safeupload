import subprocess,json,datetime,hashlib,os
from pathlib import Path
work=Path(__file__).resolve().parent
plan=json.loads((work/'prepared-plan.json').read_text())
tree=Path(plan['ExecutionTree'])
for n,h in plan['SourcePins'].items():assert hashlib.sha256((tree/n).read_bytes()).hexdigest()==h
review=Path('/home/victor/Work/safeupload-staging/driver/evidence/2026-10-11/luna-t5-harness-windows-gate-r23-independent-review.md')
assert review.is_file()
expected=os.environ['SAFEUPLOAD_R23_APPROVED_REVIEW_SHA256']
assert hashlib.sha256(review.read_bytes()).hexdigest()==expected
start=datetime.datetime.now(datetime.timezone.utc).isoformat()
with (work/'run.stdout.log').open('xb') as out,(work/'run.stderr.log').open('xb') as err:
 p=subprocess.Popen(plan['Command'],stdout=out,stderr=err,cwd=work)
 with (work/'process-start.json').open('x') as f:json.dump({'PID':p.pid,'StartedUTC':start,'Command':plan['Command'],'ReviewSHA256':expected},f,indent=2)
 print('Started bounded harness shell PID',p.pid,flush=True)
 code=p.wait()
result={'StartedUTC':start,'EndedUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'LocalShellPID':p.pid,'ExitCode':code,'ReviewSHA256':expected,'RunStdoutSHA256':hashlib.sha256((work/'run.stdout.log').read_bytes()).hexdigest(),'RunStderrSHA256':hashlib.sha256((work/'run.stderr.log').read_bytes()).hexdigest(),'SourceInputsUnchanged':all(hashlib.sha256((tree/n).read_bytes()).hexdigest()==h for n,h in plan['SourcePins'].items()),'RuntimeQualified':False,'ProductVMStarted':False}
with (work/'root-run-result.json').open('x') as f:json.dump(result,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps(result),flush=True)
raise SystemExit(code)
