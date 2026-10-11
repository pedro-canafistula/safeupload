import datetime,hashlib,json,os,stat,subprocess
from pathlib import Path
out=Path('/tmp/m2-t5-selected-storage-inputs-readonly-a1-root.json');assert not out.exists()
paths=['/var/lib/libvirt/images/win10-debug3.base-20261009.qcow2','/mnt/storage/libvirt/images/win10-debug2.flat-20261009.qcow2','/var/lib/libvirt/qemu/nvram/win10-debug3_VARS.fd','/var/lib/libvirt/qemu/nvram/win10-debug2_VARS.fd','/var/lib/libvirt/swtpm/ffcb9530-146b-43b1-8af7-2b5cc8ede2e3','/var/lib/libvirt/swtpm/9d6e3f02-b40a-49f0-a77f-439714f8f308']
r={'CapturedUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'Paths':{},'Commands':[],'Scope':'Read-only path/chain/capacity observations; no path-exclusion, custody, byte baseline or full persistent-state proof.','HostPolicyApplied':False,'VMChanged':False,'BaselineQualified':False}
def metadata(p):
 s=os.stat(p,follow_symlinks=False);d={'Device':s.st_dev,'Inode':s.st_ino,'Mode':s.st_mode,'UID':s.st_uid,'GID':s.st_gid,'Size':s.st_size,'LinkCount':s.st_nlink,'MTimeNS':s.st_mtime_ns,'CTimeNS':s.st_ctime_ns,'IsSymlink':stat.S_ISLNK(s.st_mode)}
 try:d['XattrNames']=sorted(os.listxattr(p,follow_symlinks=False))
 except OSError as e:d['XattrObservationError']=str(e)
 if stat.S_ISDIR(s.st_mode):
  try:d['MemberNames']=sorted(x.name for x in Path(p).iterdir())
  except OSError as e:d['MemberObservationError']=str(e)
 return d
allpaths=set(paths)
for p in paths:allpaths.update(str(x) for x in Path(p).parents)
for p in sorted(allpaths):
 try:r['Paths'][p]=metadata(p)
 except OSError as e:r['Paths'][p]={'ObservationError':str(e),'ProofEstablished':False}
cmds=[['qemu-img','info','--backing-chain','--output=json',paths[0]],['qemu-img','info','--backing-chain','--output=json',paths[1]],['df','-B1','--output=source,fstype,size,used,avail,target','/mnt/storage','/var/lib/libvirt/images'],['getfacl','-p','-n','/mnt','/mnt/storage','/mnt/storage/libvirt','/mnt/storage/libvirt/images','/var/lib/libvirt/images']]
for c in cmds:
 try:
  p=subprocess.run(c,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30);r['Commands'].append({'argv':c,'ExitCode':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace'),'StdoutSHA256':hashlib.sha256(p.stdout).hexdigest(),'StderrSHA256':hashlib.sha256(p.stderr).hexdigest()})
 except (OSError,subprocess.TimeoutExpired) as e:r['Commands'].append({'argv':c,'ObservationError':str(e),'TerminalProof':False})
with out.open('x') as f:json.dump(r,f,indent=2,sort_keys=True);f.write('\n')
print('Receipt',out,'SHA256',hashlib.sha256(out.read_bytes()).hexdigest(),'Paths',len(r['Paths']))
for c in r['Commands']:print(c['argv'][0],c.get('ExitCode'),len(c.get('stdout','')),len(c.get('stderr','')))
