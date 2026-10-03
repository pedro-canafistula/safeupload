from pathlib import Path
import hashlib, os, subprocess, sys, re
root=Path('/home/victor/Work/safeupload-staging')
label=sys.argv[2] if len(sys.argv)>2 else 'mvp1-irqlfix'
if label not in {'mvp1-irqlfix','mvp1-sectionpair','mvp1-idprobe2','mvp1-canary7','mvp1-local-service','mvp1-local-regression','mvp1-detached'}: raise SystemExit('Unknown build label')
work=Path('/tmp/claude-1000/exact-'+label)
summary=(work/'summary.txt').read_text(encoding='utf-8-sig')
for name in ['driver:normal','driver:owned-feature','driver:normal-release','driver:owned-feature-release','inspector-normal-release','inspector-feature-release']:
    line=next(x for x in summary.splitlines() if x.startswith(name+' :'))
    for token in ['exit=0','succeeded=True','warnings=0','errors=0']:
        if token not in line: raise SystemExit('Build gate failed: '+line)
    if name.startswith('driver:') and ('apivalidator=True' not in line or 'prefast=True' not in line): raise SystemExit('Missing analysis gate')
signed=hashlib.sha256((work/'SafeUpload-stage-prototype.sys').read_bytes()).hexdigest().upper()
inspector=hashlib.sha256((work/'inspector-feature-release.exe').read_bytes()).hexdigest().upper()
if 'signed_sha256='+signed not in summary or 'artifact_sha256='+inspector not in summary: raise SystemExit('Artifact hash mismatch')
jobs={'section-inflight-run13-detached-verifier':('section-inflight',True),'section-inflight-run14-detached':('section-inflight',False),'writer-count-run14-detached-verifier':('writer-count',True),'writer-count-run15-detached':('writer-count',False),'writer-count-run12-all-volumes-verifier':('writer-count',True),'writer-count-run13-all-volumes':('writer-count',False),'section-inflight-run11-all-volumes-verifier':('section-inflight',True),'section-inflight-run12-all-volumes':('section-inflight',False),'writer-count-run10-all-volumes-verifier':('writer-count',True),'writer-count-run11-all-volumes':('writer-count',False),'section-inflight-run9-all-volumes-verifier':('section-inflight',True),'section-inflight-run10-all-volumes':('section-inflight',False),'writer-count-run9-canary-verifier':('writer-count',True),'section-inflight-run8-canary-verifier':('section-inflight',True),'writer-count-run5-idprobe-verifier':('writer-count',True),'section-inflight-run4-idprobe-verifier':('section-inflight',True),'writer-count-run3-verifier':('writer-count',True),'section-inflight-run1':('section-inflight',False),'section-inflight-run2-verifier':('section-inflight',True),'section-inflight-run3':('section-inflight',False),'writer-count-run4-verifier':('writer-count',True)}
name=sys.argv[1]
variant,verifier=jobs[name]
ev=root/'driver/evidence/2026-10-03'
if (ev/(name+'-gate.txt')).exists(): raise SystemExit('Refusing to replace existing evidence')
driverleaf='SafeUpload-stage-prototype-'+label.replace('-','')+'.sys'
inspectorleaf='SafeUpload.Inspector.'+label.replace('-','')+'.exe'
helperhash=hashlib.sha256((root/'driver/scripts/StagedTestAgent.ps1').read_bytes()).hexdigest().upper()
helperleaf='StagedTestAgent-'+helperhash[:16]+'.ps1'
harnesshash=hashlib.sha256((root/'driver/scripts/Test-StagedAdmissionDiagnostic.ps1').read_bytes()).hexdigest().upper()
pre=r"""$ErrorActionPreference='Stop'
$d='C:\Users\vika\Documents'
$expected=@{'DRIVERLEAF'='DRIVERHASH';'INSPECTORLEAF'='INSPECTORHASH';'HELPERLEAF'='HELPERHASH'}
foreach($n in $expected.Keys){$p=Join-Path $d $n;if(Test-Path -LiteralPath $p){if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne $expected[$n]){throw ('Existing input hash mismatch: '+$n)}}}
if((Get-FileHash -LiteralPath (Join-Path $d 'StagedTestAgent.ps1') -Algorithm SHA256).Hash -ne 'E17696FF684A27A283469989F6A58B8F6111BCB11AE8F9CABD025F711BACEFD9'){throw 'Original shared helper hash mismatch'}
'PRE_RUN_OK=True'
"""
for a,b in [('DRIVERLEAF',driverleaf),('INSPECTORLEAF',inspectorleaf),('DRIVERHASH',signed),('INSPECTORHASH',inspector),('HELPERHASH',helperhash),('HELPERLEAF',helperleaf)]: pre=pre.replace(a,b)
inv=r"""$ErrorActionPreference='Stop'; $d='C:\Users\vika\Documents'; $driver=Join-Path $d 'DRIVERLEAF'; $sig=Get-AuthenticodeSignature -LiteralPath $driver; 'FeatureSignatureStatus='+$sig.Status; 'FeatureSignerThumbprint='+$sig.SignerCertificate.Thumbprint; if($sig.Status.ToString() -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne '220DD82C37FCF36048D59E4F10113185D81D5DC7'){throw 'Signature preflight failed'}; if((Get-FileHash -LiteralPath (Join-Path $d 'Test-StagedAdmissionDiagnostic.ps1') -Algorithm SHA256).Hash -ne 'HARNESSHASH'){throw 'Harness hash mismatch'}; & (Join-Path $d 'Test-StagedAdmissionDiagnostic.ps1') -TestAgentHelperFileName 'HELPERLEAF' -Variant 'VARIANT' -ExpectedFeatureSha256 'DRIVERHASH' -ExpectedInspectorSha256 'INSPECTORHASH' -FeatureDriverFileName 'DRIVERLEAF' -InspectorInputFileName 'INSPECTORLEAF' VERIFIER"""
for a,b in [('DRIVERLEAF',driverleaf),('INSPECTORLEAF',inspectorleaf),('DRIVERHASH',signed),('INSPECTORHASH',inspector),('HARNESSHASH',harnesshash),('HELPERLEAF',helperleaf),('VARIANT',variant),('VERIFIER',('-Verifier' if verifier else '')+(' -RequireAllVolumeCanaries' if label in {'mvp1-local-service','mvp1-local-regression','mvp1-detached'} else ' -RequireCanary' if label=='mvp1-canary7' else ''))]: inv=inv.replace(a,b)
full=subprocess.check_output(['git','rev-parse',{'mvp1-irqlfix':'bf43d8b4','mvp1-sectionpair':'de9743cc','mvp1-idprobe2':'43aa391d','mvp1-canary7':'dc3574d7','mvp1-local-service':'c8947bf1','mvp1-local-regression':'e34d1d0d','mvp1-detached':'70718021'}[label]],cwd=root,text=True).strip()
for line in (work/'src.manifest').read_text().splitlines():
    h,path=line.split('  ',1)
    assert hashlib.sha256(subprocess.check_output(['git','show',full+':'+path],cwd=root)).hexdigest()==h
lines=['HarnessSourceCommit='+subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'HelperInputFileName='+helperleaf,'SourceCommit='+full,'BuildLabel='+label,'FeatureSHA256='+signed,'InspectorSHA256='+inspector,'Variant='+variant,'Verifier='+str(verifier),'Invocation='+inv,'Harness and helper SHA256:']
for p in ['driver/scripts/Test-StagedAdmissionDiagnostic.ps1','driver/scripts/StagedTestAgent.ps1','driver/scripts/Get-StagedBaseline.ps1','driver/scripts/Invoke-DebuggeeExperiment.sh','driver/scripts/remote_ps.py']:
    lines.append(hashlib.sha256((root/p).read_bytes()).hexdigest()+'  '+p)
(ev/(name+'-provenance.txt')).write_text('\n'.join(lines)+'\n')
env=os.environ.copy();env['PRE_RUN_PS']=pre;env['EXTRA_FILES']=str(work/'SafeUpload-stage-prototype.sys')+'='+driverleaf+' '+str(work/'inspector-feature-release.exe')+'='+inspectorleaf+' '+str(root/'driver/scripts/StagedTestAgent.ps1')+'='+helperleaf
raise SystemExit(subprocess.call(['driver/scripts/Invoke-DebuggeeExperiment.sh',name,'driver/scripts/Test-StagedAdmissionDiagnostic.ps1',inv],cwd=root,env=env))
