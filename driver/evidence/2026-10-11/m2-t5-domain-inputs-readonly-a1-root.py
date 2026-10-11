import datetime,hashlib,json,os,stat,xml.etree.ElementTree as ET
from pathlib import Path
import libvirt
out=Path('/tmp/m2-t5-domain-inputs-readonly-a1-root.json');assert not out.exists()
rawdir=Path('/tmp/m2-t5-domain-inputs-readonly-a1-root-private-xml');rawdir.mkdir(mode=0o700,exist_ok=False)
selected='ffcb9530-146b-43b1-8af7-2b5cc8ede2e3';alias='9d6e3f02-b40a-49f0-a77f-439714f8f308';builder='c6440689-d11c-4c63-a463-f3722b7ddb69'
def obs(fn):
 try:return fn()
 except (OSError,libvirt.libvirtError,ET.ParseError) as e:return {'ObservationError':str(e),'ProofEstablished':False}
def sha(x):return hashlib.sha256(x.encode()).hexdigest()
def save(n,x):
 fd=os.open(rawdir/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:f.write(x)
def devices(x):
 root=ET.fromstring(x);result={'DeviceKinds':{},'Disks':[],'NVRAM':[],'TPM':[],'FilesystemDevices':[],'QEMUCommandlinePresent':root.find('{http://libvirt.org/schemas/domain/qemu/1.0}commandline') is not None}
 for el in root.findall('./devices/*'):result['DeviceKinds'][el.tag]=result['DeviceKinds'].get(el.tag,0)+1
 def disk(e):
  source=e.find('source');driver=e.find('driver');target=e.find('target')
  r={'type':e.get('type'),'device':e.get('device'),'SourcePaths':{k:v for k,v in (source.attrib if source is not None else {}).items() if k in ['file','dev','dir','pool','volume','name','protocol']},'Target':dict(target.attrib) if target is not None else {},'DriverType':driver.get('type') if driver is not None else None,'ReadOnly':e.find('readonly') is not None,'BackingStores':[]}
  b=e.find('backingStore')
  while b is not None:
   s=b.find('source');r['BackingStores'].append({'type':b.get('type'),'SourcePaths':{k:v for k,v in (s.attrib if s is not None else {}).items() if k in ['file','dev','pool','volume','name','protocol']}});b=b.find('backingStore')
  return r
 for e in root.findall('./devices/disk'):result['Disks'].append(disk(e))
 for e in root.findall('./os/nvram'):
  source=e.find('source');result['NVRAM'].append({'text':(e.text or '').strip(),'SourcePaths':{k:v for k,v in (source.attrib if source is not None else {}).items() if k in ['file','dev']}})
 for e in root.findall('./devices/tpm'):
  b=e.find('backend');s=b.find('source') if b is not None else None;result['TPM'].append({'BackendType':b.get('type') if b is not None else None,'SourcePaths':dict(s.attrib) if s is not None else {},'Version':b.get('version') if b is not None else None})
 for e in root.findall('./devices/filesystem'):
  s=e.find('source');result['FilesystemDevices'].append({'type':e.get('type'),'SourcePaths':dict(s.attrib) if s is not None else {}})
 return result
r={'CapturedUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'Connection':'qemu:///system read-only','Domains':[],'StoragePools':[],'RawXMLPrivateDirectory':str(rawdir),'RawXMLContentsEmitted':False,'RawXMLIntendedForGit':False,'Scope':'Read-only API inventory at capture time; no request drain, complete chain/persistent-state closure, baseline or restoration claim.','APIReadOnly':True,'VMChanged':False,'HostPolicyApplied':False,'BaselineQualified':False,'RuntimeQualified':False}
conn=libvirt.openReadOnly('qemu:///system');assert conn is not None
try:
 for d in sorted(conn.listAllDomains(0),key=lambda x:x.UUIDString()):
  u=d.UUIDString();first=d.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE);live=d.XMLDesc(0);state=d.state(0);save(u+'.inactive.xml',first);save(u+'.live.xml',live)
  row={'Name':d.name(),'UUID':u,'Role':'selected' if u==selected else 'cold-alias' if u==alias else 'builder' if u==builder else 'other','StateBefore':state,'InactiveXMLSHA256':sha(first),'LiveXMLSHA256':sha(live),'InactiveDevices':devices(first),'LiveDevices':devices(live),'HasManagedSaveImage':obs(lambda:d.hasManagedSaveImage(0)),'SnapshotNames':obs(lambda:sorted(s.getName() for s in d.listAllSnapshots(0))),'ActiveJobStats':obs(lambda:d.jobStats(0)) if state[0]==libvirt.VIR_DOMAIN_RUNNING else 'NOT_QUERIED_INACTIVE','ActiveBlockJobs':{}}
  if state[0]==libvirt.VIR_DOMAIN_RUNNING:
   for disk in row['LiveDevices']['Disks']:
    target=disk['Target'].get('dev')
    if target:row['ActiveBlockJobs'][target]=obs(lambda target=target:d.blockJobInfo(target,0))
  row['InactiveXMLSecondReadEqual']=first==d.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE);row['StateSecondReadEqual']=state==d.state(0);r['Domains'].append(row)
 for p in sorted(conn.listAllStoragePools(0),key=lambda x:x.name()):
  x=p.XMLDesc(0);save('pool-'+p.UUIDString()+'.xml',x);root=ET.fromstring(x);t=root.find('./target/path');r['StoragePools'].append({'Name':p.name(),'UUID':p.UUIDString(),'IsActive':bool(p.isActive()),'XMLSHA256':sha(x),'Type':root.get('type'),'TargetPath':t.text if t is not None else None,'VolumeNames':obs(lambda:sorted(p.listVolumes())) if p.isActive() else 'NOT_QUERIED_INACTIVE'})
 assert any(x['UUID']==selected and x['Name']=='win10-debug3' for x in r['Domains']);assert any(x['UUID']==builder and x['Name']=='win10' for x in r['Domains'])
finally:conn.close()
with out.open('x') as f:json.dump(r,f,indent=2,sort_keys=True);f.write('\n')
print('Receipt',out,'SHA256',hashlib.sha256(out.read_bytes()).hexdigest(),'Domains',len(r['Domains']),'Pools',len(r['StoragePools']))
for x in r['Domains']:print(x['Role'],x['Name'],x['StateBefore'],'XMLSame',x['InactiveXMLSecondReadEqual'],'StateSame',x['StateSecondReadEqual'])
