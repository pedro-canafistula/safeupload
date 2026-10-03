from pathlib import Path
import subprocess,hashlib,json,re,datetime
root=Path('/home/victor/Work/safeupload-staging');ev=root/'driver/evidence/2026-10-03'
FIRST_RUN=16  # earlier writer-count runs have their own manifests (mvp1-*-raw-traces-manifest.json)
ps=r"""$ErrorActionPreference='Stop'
$items=@(Get-ChildItem -LiteralPath 'C:\Users\vika\Documents' -File|Where-Object {$_.Name -match '^SafeUpload-admission-trace-writer-count-[0-9a-f]{32}-.+$'}|ForEach-Object {
if(($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparsed writer-count evidence'}
[pscustomobject]@{Name=$_.Name;SHA256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash;Bytes=$_.Length;UTC=$_.LastWriteTimeUtc.ToString('o')}
})
ConvertTo-Json -InputObject $items -Compress
"""
r=subprocess.run(['python3','driver/scripts/remote_ps.py','192.168.122.51'],input=ps,text=True,capture_output=True,check=True,cwd=root);items=json.loads(r.stdout.strip())
if isinstance(items,dict):items=[items]
dest=ev/'writer-count-raw';dest.mkdir(exist_ok=True)
opts=['-F','/dev/null','-i','/home/victor/.ssh/id_ed25519','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','LogLevel=ERROR','-o','StrictHostKeyChecking=accept-new']
intervals=[]
for gate in sorted(ev.glob('writer-count-run*-gate.txt')):
 name=gate.name.removesuffix('-gate.txt');num=int(re.match(r'writer-count-run(\d+)',name)[1])
 if num<FIRST_RUN:continue
 final=ev/(name+'-final-restored-state.txt');prov=ev/(name+'-provenance.txt')
 if not final.exists():continue
 a=re.search(r'^TestTimestampUTC=(.+)$',gate.read_text(),re.M);b=re.search(r'^UTC=(.+)$',final.read_text(),re.M);c=re.search(r'^SourceCommit=(.+)$',prov.read_text(),re.M)
 if a and b and c:intervals.append((datetime.datetime.fromisoformat(a[1].replace('Z','+00:00')),datetime.datetime.fromisoformat(b[1].replace('Z','+00:00')),name,c[1]))
if not intervals:raise SystemExit('No attributable runs')
earliest=min(i[0] for i in intervals);kept=[]
for item in items:
 name=item['Name'];ts=datetime.datetime.fromisoformat(item['UTC'].replace('Z','+00:00'))
 if ts<earliest:continue  # belongs to an earlier, separately manifested run
 matches=[(n,c) for a,b,n,c in intervals if a<=ts<=b]
 if len(matches)!=1:raise SystemExit('Ambiguous or unfinished experiment attribution: '+name)
 item['Run'],item['SourceCommit']=matches[0];path=dest/name
 if not path.exists():subprocess.run(['scp']+opts+['vika@192.168.122.51:C:/Users/vika/Documents/'+name,str(path)],check=True)
 if hashlib.sha256(path.read_bytes()).hexdigest().upper()!=item['SHA256']:raise SystemExit('Guest/local evidence hash mismatch')
 item['LocalPath']=str(path.relative_to(root));kept.append(item)
(ev/'writer-count-raw-manifest.json').write_text(json.dumps(kept,indent=2)+'\n')
print('FetchedAndHashVerified='+str(len(kept)));
for run in sorted({i['Run'] for i in kept}):print(run,sum(1 for i in kept if i['Run']==run))
