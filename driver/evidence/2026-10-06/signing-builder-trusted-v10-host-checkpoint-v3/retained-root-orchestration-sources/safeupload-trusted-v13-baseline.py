from pathlib import Path
import subprocess,json,hashlib,sys,uuid
r=Path('/home/victor/Work/safeupload-staging');e=r/'driver/evidence/2026-10-06';d=e/'signing-builder-trusted-v10-baseline-v13';o=e/'signing-builder-trusted-v13-execution';h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert h(d/'source-manifest.sha256')=='b0d38fc640df010356d4c0a69fc3b8e02b3355bb089664f24e0c2b59e5eb5bcd'
for line in (d/'source-manifest.sha256').read_text().splitlines():
 if not line.strip() or line.startswith('#'):continue
 pin,name=line.split('  ',1);assert h(r/name)==pin,name
assert h(e/'signing-builder-trusted-v10-checkpoint-independent-review-luna.md')=='034b605b0f0a368589fdecd55459412fcc24c98a795890bfd30916b578cc1be5'
old=e/'signing-builder-trusted-v10-checkpoint/source-manifest.sha256'
assert h(old)=='49574cb4ae56014eabfd325f6cb16ed893efb6e300a8565b47634cb4e0aa5f11'
for line in old.read_text().splitlines():
 if not line.strip() or line.startswith('#'):continue
 pin,name=line.split('  ',1);assert h(r/name)==pin,name
phase=sys.argv[1];o.mkdir(exist_ok=True)
remoteps=['python3',str(r/'driver/scripts/remote_ps.py'),'192.168.122.210']
opts=['-F','/dev/null','-i','/home/victor/.ssh/id_ed25519','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','LogLevel=ERROR','-o','StrictHostKeyChecking=yes']
def run(label,script):
 stdout=o/(label+'.stdout.txt');stderr=o/(label+'.stderr.txt');assert not stdout.exists() and not stderr.exists()
 with stdout.open('w') as a,stderr.open('w') as b:p=subprocess.run(remoteps,input=script,text=True,stdout=a,stderr=b,cwd=r)
 (o/(label+'.exit.json')).write_text(json.dumps({'ActualRemoteExitCode':p.returncode,'ReadOnlyBaseline':True})+'\n')
 print(label+': Exit='+str(p.returncode));assert p.returncode==0;return stdout
identity="if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Builder identity mismatch'}"
if phase=='prepare':
 state=o/'guest-inputs.json';assert not state.exists()
 remote='C:\\Users\\vika\\Documents\\SafeUploadTrustedBaseline-'+uuid.uuid4().hex
 files={x.name:(x,'sources') for x in [d/'baseline-check-v13.ps1',d/'signing-guard-helpers-v8.ps1',d/'inventory-ps51-fixture-v13.ps1']}
 for n in ['signing-builder-trust-v10-root-readout.json','signing-builder-v8-cold-challenge-c-root-readout.json','signing-artifact-proof-v10-post-sign-independent.stdout.json','signing-artifact-proof-v10-post-sign-independent.stderr.txt','signing-artifact-proof-v10-root-readout.json']:files[n]=(e/n,'readouts')
 for x in (r/'output/signing-artifact-proof-v10-20261006a/public-proof').iterdir():files[x.name]=(x,'public-proof')
 assert len(files)==13
 run('staging',"$ErrorActionPreference='Stop';"+identity+";$d='"+remote+"';if(Test-Path -LiteralPath $d){throw 'Path exists'};[void](New-Item -ItemType Directory -Path $d);foreach($name in @('sources','readouts','public-proof')){[void](New-Item -ItemType Directory -Path (Join-Path $d $name))};'FreshPublicBaselineDirectory=True'")
 for n,(p,folder) in files.items():subprocess.run(['scp',*opts,str(p),'vika@192.168.122.210:'+remote.replace('\\','/')+'/'+folder+'/'+n],check=True)
 rows=';'.join("'"+folder+'\\'+n+"'='"+h(p)+"'" for n,(p,folder) in files.items())
 script="$ErrorActionPreference='Stop';"+identity+";$d='"+remote+"';$pins=@{"+rows+"};foreach($name in $pins.Keys){$p=Join-Path $d $name;if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ine $pins[$name]){throw 'Input hash mismatch'};if($name.EndsWith('.ps1')){$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($p,[ref]$tokens,[ref]$errors);if(@($errors).Count){throw 'PS5.1 parse error'};Write-Output ($name+' ParseErrors=0')};(Get-Item -LiteralPath $p).IsReadOnly=$true};if($PSVersionTable.PSVersion.ToString() -notlike '5.1.*'){throw 'Expected PS5.1'};'ExactPinsVerified=True'"
 run('ps51-parse-and-input-pins',script)
 state.write_text(json.dumps({'GuestRoot':remote,'Pins':{folder+'\\'+n:h(p) for n,(p,folder) in files.items()}},indent=2)+'\n')
else:
 s=json.loads((o/'guest-inputs.json').read_text());remote=s['GuestRoot'];rows=';'.join("'"+n+"'='"+pin+"'" for n,pin in s['Pins'].items())
 script="$ErrorActionPreference='Stop';"+identity+";$d='"+remote+"';$pins=@{"+rows+"};foreach($name in $pins.Keys){if((Get-FileHash -LiteralPath (Join-Path $d $name) -Algorithm SHA256).Hash -ine $pins[$name]){throw 'Baseline input changed'}};& (Join-Path $d 'sources\\baseline-check-v13.ps1') -PublicProofDirectory (Join-Path $d 'public-proof') -TrustRootReadoutPath (Join-Path $d 'readouts\\signing-builder-trust-v10-root-readout.json') -ColdRootReadoutPath (Join-Path $d 'readouts\\signing-builder-v8-cold-challenge-c-root-readout.json') -PostSignIndependentReadoutPath (Join-Path $d 'readouts\\signing-artifact-proof-v10-post-sign-independent.stdout.json') -PostSignStderrPath (Join-Path $d 'readouts\\signing-artifact-proof-v10-post-sign-independent.stderr.txt') -PostSignRootReadoutPath (Join-Path $d 'readouts\\signing-artifact-proof-v10-root-readout.json')"
 if phase=='fixture':
  script="$ErrorActionPreference='Stop';"+identity+";$d='"+remote+"';& (Join-Path $d 'sources\\inventory-ps51-fixture-v13.ps1') -BaselinePath (Join-Path $d 'sources\\baseline-check-v13.ps1') -MetadataPath 'C:\\Users\\vika\\Documents\\exact-mvp20261006admissioncap2\\replacement-machine-key-v8-metadata.json' -TrustReceiptPath (Join-Path $d 'public-proof\\builder-trust-receipt.json') -PostSignJsonlPath (Join-Path $d 'readouts\\signing-artifact-proof-v10-post-sign-independent.stdout.json') -ExpectedBaselineSha256 '889c80da2c235a9372d400c5549d2822ca2979d0196ab71809334c62b4673609'"
 (o/(phase+'-caller.ps1')).write_text(script,encoding='utf-8-sig')
 p=run(phase,script)
 if phase=='fixture':assert p.read_text().strip()=='V13_INVENTORY_ADAPTER_FIXTURE_PASS'
 else:
  a=json.loads(p.read_text());assert a['Verdict']=='V10_TRUSTED_SIGNER_CHECKPOINT_BASELINE_PASS'
 print('ACTUAL_READ_ONLY_CHECK_PASS')
