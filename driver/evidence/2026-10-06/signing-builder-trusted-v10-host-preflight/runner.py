from pathlib import Path
import subprocess,json,xml.etree.ElementTree as X,hashlib,os,stat,datetime
r=Path('/home/victor/Work/safeupload-staging');e=r/'driver/evidence/2026-10-06';d=e/'signing-builder-trusted-v10-host-preflight';d.mkdir(exist_ok=False)
def virsh(*args):return subprocess.check_output(['virsh','-c','qemu:///system',*args],text=True)
def save(n,s):p=d/n;p.write_text(s);return p
expected='/var/lib/libvirt/images/win10-clean.safeupload-signer-key-bearing-v8-retry2-20261006.qcow2';child='/var/lib/libvirt/images/win10-clean.safeupload-signer-trusted-v10-20261006.qcow2';excluded='/var/lib/libvirt/images/win10-clean.safeupload-signer-key-bearing-v8-retry1-20261006.qcow2'
assert virsh('domuuid','win10').strip()=='c6440689-d11c-4c63-a463-f3722b7ddb69'
state=virsh('domstate','win10').strip();assert state=='running',state;save('state.txt',state+'\n')
for leaf,args in [('live.xml',['dumpxml','win10']),('inactive.xml',['dumpxml','win10','--inactive'])]:
 raw=virsh(*args);save(leaf,raw);a=X.fromstring(raw);assert a.findtext('uuid')=='c6440689-d11c-4c63-a463-f3722b7ddb69'
 disks=[x for x in a.findall('./devices/disk') if x.find('target') is not None and x.find('target').get('dev')=='vda'];assert len(disks)==1 and disks[0].find('source').get('file')==expected
jobs=virsh('domjobinfo','win10');save('jobs.txt',jobs);assert 'Job type:' in jobs and 'None' in jobs
qmp=virsh('qemu-monitor-command','win10','{"execute":"query-block"}');save('query-block.json',qmp);a=json.loads(qmp);assert len([x for x in a['return'] if x.get('inserted',{}).get('file')==expected])==1
assert not os.path.lexists(child)
chain=subprocess.check_output(['qemu-img','info','--backing-chain','--output=json','--force-share',expected],text=True);save('backing-chain.json',chain);a=json.loads(chain);assert a[0]['filename']==expected and a[1]['filename']=='/var/lib/libvirt/images/win10-clean.safeupload-signer-fallback-recovery3-20261006.qcow2';assert all(x['filename']!=excluded and x['format']=='qcow2' for x in a)
def details(p):
 s=os.stat(p);assert stat.S_ISREG(s.st_mode) and not os.path.islink(p)
 return dict(Path=p,Device=s.st_dev,Inode=s.st_ino,Bytes=s.st_size,MtimeNS=s.st_mtime_ns,Mode=oct(stat.S_IMODE(s.st_mode)),UID=s.st_uid,GID=s.st_gid)
parent=details(expected);assert parent['Mode']=='0o600' and parent['UID']==958 and parent['GID']==958
out=dict(UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),Verdict='LIVE_HEALTHY_TRUSTED_SIGNER_HOST_PREFLIGHT_PASS',VM='win10',UUID='c6440689-d11c-4c63-a463-f3722b7ddb69',LiveAndInactiveDiskSource=expected,ChildAbsent=True,Child=child,NoDomainJob=True,FailedRetry1ExcludedFromBackingChain=True,CurrentParentStat=parent,StateMutation=False,Note='Running disk size/mtime may change; this live preflight does not freeze parent stat. Recheck immediately at phase use and after graceful shutdown.',EvidencePins={str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in d.iterdir() if p.is_file()})
p=save('root-readout.json',json.dumps(out,indent=2)+'\n');print(json.dumps(out));print('ReadoutSHA256='+hashlib.sha256(p.read_bytes()).hexdigest())
