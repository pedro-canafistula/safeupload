from pathlib import Path
import subprocess,hashlib,json,re,datetime
root=Path('/home/victor/Work/safeupload-staging');ev=root/'driver/evidence/2026-10-03'
ps=r"""$ErrorActionPreference='Stop'
$items=@(Get-ChildItem -LiteralPath 'C:\Users\vika\Documents' -File|Where-Object {$_.Name -match '^SafeUpload-(admission-trace-section-lower-[0-9a-f]{32}-.+|section-lower-[0-9a-f]{32}-(result\.json|failure\.jsonl|held\.jsonl|capacity-held\.jsonl|capacity-probe\.jsonl|system-(out|err)\.log))$'}|ForEach-Object {
if(($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparsed lower evidence'}
[pscustomobject]@{Name=$_.Name;SHA256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash;Bytes=$_.Length;UTC=$_.LastWriteTimeUtc.ToString('o')}
})
ConvertTo-Json -InputObject $items -Compress
"""
r=subprocess.run(['python3','driver/scripts/remote_ps.py','192.168.122.51'],input=ps,text=True,capture_output=True,check=True,cwd=root);items=json.loads(r.stdout.strip());dest=ev/'section-lower-raw';dest.mkdir(exist_ok=True)
opts=['-F','/dev/null','-i','/home/victor/.ssh/id_ed25519','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','LogLevel=ERROR','-o','StrictHostKeyChecking=accept-new']
intervals=[]
for gate in list(ev.glob('section-lower-*-gate.txt'))+list(ev.glob('section-capacity-*-gate.txt')):
 name=gate.name.removesuffix('-gate.txt');final=ev/(name+'-final-restored-state.txt');prov=ev/(name+'-provenance.txt')
 if not final.exists():continue
 a=re.search(r'^TestTimestampUTC=(.+)$',gate.read_text(),re.M);b=re.search(r'^UTC=(.+)$',final.read_text(),re.M);c=re.search(r'^SourceCommit=(.+)$',prov.read_text(),re.M)
 if a and b and c:intervals.append((datetime.datetime.fromisoformat(a[1].replace('Z','+00:00')),datetime.datetime.fromisoformat(b[1].replace('Z','+00:00')),name,c[1]))
for item in items:
 name=item['Name']
 if not re.fullmatch(r'SafeUpload-(admission-trace-section-lower-[0-9a-f]{32}-[A-Za-z0-9_.-]+|section-lower-[0-9a-f]{32}-(result\.json|failure\.jsonl|held\.jsonl|capacity-held\.jsonl|capacity-probe\.jsonl|system-(out|err)\.log))',name):raise SystemExit('Unexpected evidence filename')
 ts=datetime.datetime.fromisoformat(item['UTC'].replace('Z','+00:00'));matches=[(n,c) for a,b,n,c in intervals if a<=ts<=b]
 if len(matches)!=1:raise SystemExit('Ambiguous or unfinished experiment attribution: '+name)
 item['Run'],item['SourceCommit']=matches[0];path=dest/name
 if not path.exists():subprocess.run(['scp']+opts+['vika@192.168.122.51:C:/Users/vika/Documents/'+name,str(path)],check=True)
 if hashlib.sha256(path.read_bytes()).hexdigest().upper()!=item['SHA256']:raise SystemExit('Guest/local evidence hash mismatch')
 item['LocalPath']=str(path.relative_to(root))
(ev/'section-lower-raw-manifest.json').write_text(json.dumps(items,indent=2)+'\n');print('FetchedAndHashVerified='+str(len(items)))
