import datetime,hashlib,json,os,stat
from pathlib import Path
out=Path('/tmp/m2-t5-libvirt-generation-inputs-readonly-a1-root.json');assert not out.exists()
def digest(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode);h=hashlib.sha256();size=0
  while True:
   data=os.read(fd,1048576)
   if not data:break
   h.update(data);size+=len(data)
  b=os.fstat(fd);c=os.stat(p,follow_symlinks=False)
  key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_gid)
  assert key(a)==key(b)==key(c)
  return {'SHA256':h.hexdigest(),'Size':size,'StableMetadata':list(key(a)),'ContentEmitted':False}
 finally:os.close(fd)
def obs(fn):
 try:return fn()
 except (OSError,AssertionError) as e:return {'ObservationError':str(e),'ProofEstablished':False}
r={'CapturedUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'ObserverPID':os.getpid(),'Files':{},'Directories':{},'Daemon':{},'Scope':'Read-only captured observer namespace; failed identity reads prevent generation/descendant proof. Configuration contents intentionally not emitted.','HostPolicyApplied':False,'ServiceAction':False,'APIInvoked':False,'VMChanged':False,'TerminalFenceEstablished':False}
for p in ['/usr/bin/libvirtd','/usr/lib/systemd/system/libvirtd.service.d/10-secret.conf','/usr/lib/systemd/system/libvirtd-tcp.socket','/usr/lib/systemd/system/libvirtd-tls.socket','/usr/lib/systemd/system/virtproxyd-tcp.socket','/usr/lib/systemd/system/virtproxyd-tls.socket']:
 r['Files'][p]=obs(lambda p=p:digest(p))
for p in ['/etc/libvirt','/etc/libvirt/hooks','/etc/polkit-1/rules.d']:
 r['Directories'][p]=obs(lambda p=p:{'Metadata':list((lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid))(os.stat(p,follow_symlinks=False))),'Entries':sorted(x.name for x in Path(p).iterdir()),'ContentsRead':False})
def process():
 base=Path('/proc/1205');before=(base/'stat').read_text();fields=before.rsplit(')',1)[1].split();start=fields[19]
 result={'PID':1205,'StartTicks':start,'Cgroup':obs(lambda:(base/'cgroup').read_text()),'Executable':obs(lambda:os.readlink(base/'exe')),'Namespace':{k:obs(lambda k=k:os.readlink(base/'ns'/k)) for k in ['pid','mnt','net','user']},'OpenFDNamesOnly':obs(lambda:sorted(x.name for x in (base/'fd').iterdir()))}
 assert (base/'stat').read_text()==before;result['TwoProcStatReadsEqual']=True;return result
r['Daemon']=obs(process)
r['ServiceCgroupMembers']=obs(lambda:Path('/sys/fs/cgroup/system.slice/libvirtd.service/cgroup.procs').read_text())
with out.open('x') as f:json.dump(r,f,indent=2,sort_keys=True);f.write('\n')
print('Receipt',out,'SHA256',hashlib.sha256(out.read_bytes()).hexdigest());print('Daemon',r['Daemon']);print('ServiceCgroupMembers',r['ServiceCgroupMembers']);print('Files',[{'path':p,'readable':'SHA256' in v} for p,v in r['Files'].items()])
