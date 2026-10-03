from pathlib import Path
import hashlib, os, subprocess, sys
root=Path('/home/victor/Work/safeupload-staging')
label,commit,name=sys.argv[1:4]
agent=Path('/tmp/claude-1000/exact-agent-'+label)
asummary=(agent/'summary.txt').read_text(encoding='utf-8-sig')
assert 'tests: exit=0 warnings=0' in asummary and 'publish: exit=0 warnings=0' in asummary
servicehash=hashlib.sha256((agent/'stage-service-publish.zip').read_bytes()).hexdigest().upper()
assert 'package_sha256='+servicehash in asummary
serviceleaf='stage-service-publish-'+label.replace('-','')
work=Path('/tmp/claude-1000/exact-'+label)
summary=(work/'summary.txt').read_text(encoding='utf-8-sig')
for target in ['driver:normal','driver:owned-feature','driver:normal-release','driver:owned-feature-release','inspector-normal-release','inspector-feature-release']:
 line=next(x for x in summary.splitlines() if x.startswith(target+' :'))
 assert all(x in line for x in ['exit=0','succeeded=True','warnings=0','errors=0']),line
 if target.startswith('driver:'): assert 'apivalidator=True' in line and 'prefast=True' in line
full=subprocess.check_output(['git','rev-parse',commit],cwd=root,text=True).strip()
for line in (agent/'src.manifest').read_text().splitlines():
 digest,path=line.split('  ',1)
 assert hashlib.sha256(subprocess.check_output(['git','show',full+':'+path],cwd=root)).hexdigest()==digest
for line in (work/'src.manifest').read_text().splitlines():
 digest,path=line.split('  ',1)
 assert hashlib.sha256(subprocess.check_output(['git','show',full+':'+path],cwd=root)).hexdigest()==digest
signed=hashlib.sha256((work/'SafeUpload-stage-prototype.sys').read_bytes()).hexdigest().upper()
assert 'signed_sha256='+signed in summary
leaf='SafeUpload-stage-prototype-'+label.replace('-','')+'.sys'
harness='driver/scripts/Test-StagedOwnedStreams.ps1'
harnesshash=hashlib.sha256((root/harness).read_bytes()).hexdigest().upper()
helperhash=hashlib.sha256((root/'driver/scripts/StagedTestAgent.ps1').read_bytes()).hexdigest().upper()
helperleaf='StagedTestAgent-'+helperhash[:16]+'.ps1'
identityhash=hashlib.sha256((root/'driver/scripts/StagedIdentityProbe.cs').read_bytes()).hexdigest().upper()
ev=root/'driver/evidence/2026-10-03'
assert not (ev/(name+'-gate.txt')).exists(),'Existing evidence'
pre=r"""$ErrorActionPreference='Stop';$d='C:\Users\vika\Documents'
if((Get-FileHash (Join-Path $d 'StagedTestAgent.ps1') -Algorithm SHA256).Hash -ne 'E17696FF684A27A283469989F6A58B8F6111BCB11AE8F9CABD025F711BACEFD9'){throw 'Original helper hash mismatch'}
$helper=Join-Path $d 'HELPERLEAF';if((Test-Path $helper) -and (Get-FileHash $helper -Algorithm SHA256).Hash -ne 'HELPERHASH'){throw 'Existing distinct helper hash mismatch'}
$cs=Join-Path $d 'StagedIdentityProbe.cs';if((Test-Path $cs) -and (Get-FileHash $cs -Algorithm SHA256).Hash -ne 'IDENTITYHASH'){throw 'Existing identity helper hash mismatch'}
$sys=Join-Path $d 'DRIVERLEAF';if((Test-Path $sys) -and (Get-FileHash $sys -Algorithm SHA256).Hash -ne 'DRIVERHASH'){throw 'Existing feature input mismatch'}
if(Test-Path (Join-Path $d 'POLICYBACKUP')){throw 'Existing run policy backup'}
$package=Join-Path $d 'SERVICELEAF.zip';if((Test-Path $package) -and (Get-FileHash $package -Algorithm SHA256).Hash -ne 'SERVICEHASH'){throw 'Existing package hash mismatch'}
if(Test-Path (Join-Path $d 'SERVICELEAF')){throw 'Service run directory already exists'}
'PRE_RUN_OK=True'
"""
inv=r"""$ErrorActionPreference='Stop';$d='C:\Users\vika\Documents';$driver=Join-Path $d 'DRIVERLEAF'
$sig=Get-AuthenticodeSignature $driver;if($sig.Status.ToString() -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne '220DD82C37FCF36048D59E4F10113185D81D5DC7'){throw 'Signature mismatch'}
if((Get-FileHash (Join-Path $d 'Test-StagedOwnedStreams.ps1') -Algorithm SHA256).Hash -ne 'HARNESSHASH'){throw 'Harness hash mismatch'}
if((Get-FileHash (Join-Path $d 'StagedIdentityProbe.cs') -Algorithm SHA256).Hash -ne 'IDENTITYHASH'){throw 'Identity helper hash mismatch'}
$policy='C:\ProgramData\SafeUpload\policy.json';$originalHash='29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
if((Get-FileHash $policy -Algorithm SHA256).Hash -ne $originalHash){throw 'Policy baseline mismatch'}
$backup=Join-Path $d 'POLICYBACKUP';$bytes=[IO.File]::ReadAllBytes($policy);[IO.File]::WriteAllBytes($backup,$bytes)
if((Get-FileHash $backup -Algorithm SHA256).Hash -ne $originalHash){throw 'Durable policy backup failed'}
$test=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
$test.monitoredScopes.destinationPaths=@('S:\SafeUpload\Escopo Monitorado');$test.monitoredScopes.removableDrives=$false;$test.monitoredScopes.networkPaths=$false;$test.auditOnly=$false
try {
 [IO.File]::WriteAllBytes($policy,[Text.Encoding]::UTF8.GetBytes(($test|ConvertTo-Json -Depth 20)))
 'DedicatedLocalPolicySHA256='+(Get-FileHash $policy -Algorithm SHA256).Hash
 'RegressionTaintMode=EXISTING_DEFAULT;MvpAcceptance=False'
 & (Join-Path $d 'Test-StagedOwnedStreams.ps1') -TestAgentHelperFileName 'HELPERLEAF' -Verifier -ReplacementCases -PublicationIterations 8 -FeatureDriverFileName 'DRIVERLEAF' -ExpectedFeatureSha256 'DRIVERHASH' -ServiceDirectoryName 'SERVICELEAF' -ExpectedServicePackageSha256 'SERVICEHASH'
} finally {
 [IO.File]::WriteAllBytes($policy,[IO.File]::ReadAllBytes($backup))
 if((Get-FileHash $policy -Algorithm SHA256).Hash -ne $originalHash){throw 'Policy restoration failed'}
 Remove-Item -LiteralPath $backup -Force
 'DedicatedLocalPolicyRestored=True'
}
"""
for a,b in [('DRIVERLEAF',leaf),('DRIVERHASH',signed),('HELPERHASH',helperhash),('HELPERLEAF',helperleaf),('HARNESSHASH',harnesshash),('IDENTITYHASH',identityhash),('POLICYBACKUP',name+'-original-policy.bin'),('SERVICELEAF',serviceleaf),('SERVICEHASH',servicehash)]:
 pre=pre.replace(a,b);inv=inv.replace(a,b)
lines=['HarnessSourceCommit='+subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'HelperInputFileName='+helperleaf,'SourceCommit='+full,'BuildLabel='+label,'FeatureSHA256='+signed,'ServicePackageSHA256='+servicehash,'AgentSourceCommit='+full,'Invocation='+inv,'Not MVP acceptance: existing taint enforcement and fresh-reader observer.']
for p in [harness,'driver/scripts/StagedTestAgent.ps1','driver/scripts/StagedIdentityProbe.cs','driver/scripts/Get-StagedBaseline.ps1','driver/scripts/Invoke-DebuggeeExperiment.sh','driver/scripts/remote_ps.py']:
 lines.append(hashlib.sha256((root/p).read_bytes()).hexdigest()+'  '+p)
(ev/(name+'-provenance.txt')).write_text('\n'.join(lines)+'\n')
env=os.environ.copy();env['PRE_RUN_PS']=pre;env['EXTRA_FILES']=str(work/'SafeUpload-stage-prototype.sys')+'='+leaf+' '+str(root/'driver/scripts/StagedIdentityProbe.cs')+'=StagedIdentityProbe.cs '+str(agent/'stage-service-publish.zip')+'='+serviceleaf+'.zip '+str(root/'driver/scripts/StagedTestAgent.ps1')+'='+helperleaf
raise SystemExit(subprocess.call(['driver/scripts/Invoke-DebuggeeExperiment.sh',name,harness,inv],cwd=root,env=env))
