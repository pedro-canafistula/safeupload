from pathlib import Path
import hashlib,json,subprocess,sys
r=Path('/home/victor/Work/safeupload-staging');d=r/'driver/evidence/2026-10-06/signing-builder-trusted-v10-host-checkpoint-v3'
label=sys.argv[1];assert label in ('first-cold-acpi-fallback','second-cold-shutdown')
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
a=json.loads((d/'review-attestation.json').read_text());assert a['Reviewers']=={'root':'PASS','bridge':'PASS'}
for rel,pin in a['ReviewEvidencePins'].items():assert h(r/rel)==pin
p=d/(label+'-guest-command');p.mkdir(exist_ok=False)
ps="""$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.User.Value -cne 'S-1-5-21-316478115-1595729549-2803163825-1001'){throw 'Wrong user SID'}
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Expected enabled administrator token'}
$actors=@(Get-Process -Name 'msiexec','MSBuild','dotnet','csc','VBCSCompiler' -ErrorAction SilentlyContinue)
if($actors.Count){throw 'Build/installer actors active; shutdown withheld'}
Write-Output 'PinnedBuilderIdentityAndNoActorsVerified=True; NormalShutdownRequested=True; ForcedShutdown=False'
& 'C:\\Windows\\System32\\shutdown.exe' /s /t 0
$code=$LASTEXITCODE
Write-Output ('NormalShutdownNativeExitCode='+$code)
if($code -ne 0){throw 'Normal shutdown command failed'}
"""
(p/'caller.ps1').write_text(ps,encoding='utf-8-sig')
x=subprocess.run(['python3',str(r/'driver/scripts/remote_ps.py'),'192.168.122.210'],input=ps,text=True,capture_output=True)
(p/'stdout.txt').write_text(x.stdout);(p/'stderr.txt').write_text(x.stderr)
(p/'exit.json').write_text(json.dumps({'ActualRemoteExitCode':x.returncode,'HostStateVerificationPending':True,'ForcedShutdown':False,'Label':label})+'\n')
print(x.stdout);print(x.stderr);print('ActualRemoteExitCode='+str(x.returncode))
raise SystemExit(x.returncode)
