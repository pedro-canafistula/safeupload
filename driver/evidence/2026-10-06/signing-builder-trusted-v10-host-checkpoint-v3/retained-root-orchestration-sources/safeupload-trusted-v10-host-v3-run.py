from pathlib import Path
import hashlib,json,subprocess,sys
root=Path('/home/victor/Work/safeupload-staging');d=root/'driver/evidence/2026-10-06/signing-builder-trusted-v10-host-checkpoint-v3'
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert h(d/'execute-checkpoint.py')=='12a67e8a58a020c7777754645dd3f07fc0e80f4676660dc60eeb802d7d962b4c'
assert h(d/'execution-pins.json')=='65b4d7818802c9e4bde2a1263edaafc072a3bf00db6a69955d1659a5a08245b3'
phase=sys.argv[1];assert phase in ('shutdown','create-start','verify-host')
a=d/'review-attestation.json'
assert a.exists()
att=json.loads(a.read_text());assert att['Reviewers']=={'root':'PASS','bridge':'PASS'} and att['Verdict']=='INDEPENDENT_REVIEW_PASS'
assert att['PinnedHelperSha256']==h(d/'execute-checkpoint.py') and att['PinnedExecutionPinsSha256']==h(d/'execution-pins.json')
# Review pins are independently held in the attestation; every source review is re-read before any phase.
for rel,pin in att['ReviewEvidencePins'].items():assert h(root/rel)==pin,rel
out=d/(phase+'-actual-execution');out.mkdir(exist_ok=False)
args=['python3',str(d/'execute-checkpoint.py'),phase,h(d/'execution-pins.json'),str(a),h(a)]
(out/'argv.json').write_text(json.dumps(args,indent=2)+'\n')
with (out/'stdout.txt').open('w') as so,(out/'stderr.txt').open('w') as se:p=subprocess.run(args,stdout=so,stderr=se)
(out/'exit.json').write_text(json.dumps({'ActualHostExitCode':p.returncode,'Phase':phase,'ReviewAttestationSHA256':h(a)})+'\n')
print((out/'stdout.txt').read_text());print((out/'stderr.txt').read_text());print('ActualHostExitCode='+str(p.returncode))
raise SystemExit(p.returncode)
