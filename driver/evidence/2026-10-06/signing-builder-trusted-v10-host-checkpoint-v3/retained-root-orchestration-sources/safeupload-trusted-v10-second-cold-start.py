from pathlib import Path
import hashlib,json,stat,subprocess,xml.etree.ElementTree as ET
r=Path('/home/victor/Work/safeupload-staging');d=r/'driver/evidence/2026-10-06/signing-builder-trusted-v10-host-checkpoint-v3';o=d/'second-cold-host-start';o.mkdir(exist_ok=False)
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
a=json.loads((d/'review-attestation.json').read_text());assert a['Reviewers']=={'root':'PASS','bridge':'PASS'}
for rel,pin in a['ReviewEvidencePins'].items():assert h(r/rel)==pin
first=r/'driver/evidence/2026-10-06/signing-builder-trusted-v10-first-cold-root-readout.json'
assert h(first)=='d4b714c647219958a3b6711ff2af5ef238016638a7ac143402de2b252b2ac04f'
for rel,pin in json.loads(first.read_text())['EvidencePins'].items():assert h(r/rel)==pin
host=json.loads((d/'host-readout.json').read_text());parent=Path(host['Parent']);child=Path(host['Child'])
def fs(p):
 v=p.stat();return dict(Device=v.st_dev,Inode=v.st_ino,Bytes=v.st_size,MtimeNS=v.st_mtime_ns,Mode=stat.S_IMODE(v.st_mode),UID=v.st_uid,GID=v.st_gid)
def run(name,*args):
 p=subprocess.run(['virsh','-c','qemu:///system',*args],text=True,capture_output=True)
 (o/(name+'.stdout.txt')).write_text(p.stdout);(o/(name+'.stderr.txt')).write_text(p.stderr)
 (o/(name+'.exit.json')).write_text(json.dumps({'ActualHostExitCode':p.returncode,'Args':list(args)})+'\n')
 assert p.returncode==0,p.stderr;return p.stdout
assert run('uuid','domuuid','win10').strip().lower()=='c6440689-d11c-4c63-a463-f3722b7ddb69'
assert run('state','domstate','win10').strip()=='shut off'
expected=ET.fromstring((d/'domain-child.xml').read_bytes());actual=ET.fromstring(run('inactive','dumpxml','win10','--inactive'))
def canon(root):
 disk=[n for n in root.findall('./devices/disk') if n.find('target') is not None and n.find('target').get('dev')=='vda'];assert len(disk)==1
 assert disk[0].find('source').get('file')==str(child)
 for n in list(disk[0].findall('backingStore')):disk[0].remove(n)
 return ET.canonicalize(ET.tostring(root,encoding='unicode'),strip_text=True)
assert canon(actual)==canon(expected)
assert fs(parent)==host['ParentStatBefore']
c=fs(child);assert (c['Mode'],c['UID'],c['GID'])==(0o600,958,958)
marker=o/'start-attempted.marker'
import os
with marker.open('x') as f:f.write('Reviewed second normal cold start\n');f.flush();os.fsync(f.fileno())
fd=os.open(o,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
run('start','start','win10')
assert fs(parent)==host['ParentStatBefore']
print('SecondColdStartNativeExit0=True;ExactChildDefinitionVerified=True;ParentFullStatUnchanged=True;GuestBaselinePending=True')
