"""One-off nested Hyper-V controls for build H (L1 = disposable su-lab candidate on KVM); not a product runner.

Phases: export, prepare, apply, wait, upload, l1 <enable|create|check|reboot|cleanup>, l1reboot, destroy.
Run from the repository root. L1 storage lives on /mnt/storage, never on a qualified target or builder.
"""
from pathlib import Path
import base64,hashlib,ipaddress,json,os,subprocess,sys,time,xml.etree.ElementTree as ET
repo=Path.cwd(); lab=repo/'lab'; ev=Path(__file__).resolve().parent
work=lab/'work/terraform-hvhost-1021k'
name='su-lab-hvhost1021k'; hostname='SU-LAB-HVHOST'
image=lab/'output/linux-portability-1021k/safeupload-debuggee-19045.2965.qcow2'
export=Path('/mnt/storage/safeupload-lab/export-1021k')
pool_path='/mnt/storage/safeupload-lab/pools'
key=lab/'secrets/linux-portability-1021d'; hosts=work/'known_hosts'
protected=['192.168.122.52','192.168.122.210','192.168.122.211']
os.umask(0o077)
env=os.environ.copy(); env['PATH']=str(lab/'bin')+os.pathsep+env['PATH']
def run(args,**kw): return subprocess.run(args,text=True,capture_output=True,**kw)
def require(r):
    if r.returncode: raise RuntimeError(r.stdout+'\n'+r.stderr)
    return r.stdout
def tf(*args): return require(run(['terraform',*args],cwd=work,env=env))
def virsh(*args): return require(run(['virsh','-c','qemu:///system',*args]))
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(8*1024*1024),b''): h.update(block)
    return h.hexdigest()
def read_plan(path,action):
    j=json.loads(tf('show','-json',str(path)))
    changes={r['address']:r['change']['actions'] for r in j.get('resource_changes',[]) if r.get('mode')!='data' and r['change']['actions']!=['no-op']}
    expected={'random_password.admin','libvirt_pool.lab','libvirt_volume.base','libvirt_volume.disk','libvirt_cloudinit_disk.seed','libvirt_domain.debuggee'}
    assert set(changes)==expected and all(a==[action] for a in changes.values()),changes
    print('ScopedPlan='+json.dumps(changes),flush=True)

def instance():
    xml=ET.fromstring(virsh('dumpxml',name))
    nic=xml.find('devices/interface'); mac=nic.find('mac').get('address')
    assert xml.findtext('name')==name and xml.find('devices/tpm') is None
    assert xml.find('cpu').get('mode')=='host-passthrough'
    addresses=set()
    for row in virsh('net-dhcp-leases','default','--mac',mac).splitlines():
        for word in row.split():
            if '/' in word:
                try:
                    v=ipaddress.ip_interface(word)
                    if v.version==4: addresses.add(str(v.ip))
                except ValueError: pass
    assert len(addresses)==1,addresses
    address=addresses.pop(); assert address not in protected,address
    return xml.findtext('uuid').upper(),mac,address

def ssh_args(address,*extra):
    return ['-F','/dev/null','-i',str(key),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ConnectTimeout=8',
        '-o','ServerAliveInterval=30','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(hosts),*extra]
def ssh(address,script):
    command='powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+base64.b64encode(script.encode('utf-16le')).decode()
    return run(['ssh',*ssh_args(address),'vika@'+address,command],stdin=subprocess.DEVNULL)

IDENTITY=("$ErrorActionPreference='Stop'; $setup=Get-ItemProperty 'HKLM:\\SYSTEM\\Setup'; [pscustomobject]@{SetupDone=(-not ($setup.SystemSetupInProgress -or $setup.OOBEInProgress));"
    "Name=$env:COMPUTERNAME;UUID=(Get-CimInstance Win32_ComputerSystemProduct).UUID;Boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress")

def connected(timeout=1800,pin=False,previous=None):
    end=time.monotonic()+timeout; last='No lease'
    while time.monotonic()<end:
        try:
            uuid,mac,address=instance()
            if pin and not hosts.exists():
                scan=run(['ssh-keyscan','-T','5','-t','ed25519',address])
                if scan.returncode==0 and scan.stdout.strip():
                    hosts.write_text(scan.stdout); print('PinnedOwnCandidateKey='+address+';MAC='+mac,flush=True)
            r=ssh(address,IDENTITY)
            if r.returncode: last=r.stderr.strip()
            else:
                guest=json.loads(r.stdout.lstrip('\ufeff').strip())
                assert guest['UUID'].upper()==uuid,guest
                if guest['SetupDone'] and guest['Name']==hostname and guest['Boot']!=previous: return address,guest
                last='Waiting: '+json.dumps(guest)
        except AssertionError as e: last=str(e)
        time.sleep(5)
    raise RuntimeError('L1 not ready: '+last)

phase=sys.argv[1]
if phase=='export':
    expected=(image.parent/'image.sha256').read_text().split()[0]
    print(require(run(['bash',str(lab/'export-hyperv.sh'),str(image),expected,str(export)])),flush=True)
    print('Vhdx='+(export/'image.sha256').read_text().strip(),flush=True)
elif phase=='prepare':
    assert not (work/'terraform.tfstate').exists()
    expected=(image.parent/'image.sha256').read_text().split()[0]
    values=dict(name=name,hostname=hostname,image_path=str(image),image_sha256=expected,pool_path=pool_path,memory_mib=6144,vcpus=4,
        ssh_public_keys=[key.with_suffix('.pub').read_text().strip()])
    (work/'terraform.tfvars.json').write_text(json.dumps(values))
    print(tf('plan','-input=false','-no-color','-out=candidate.tfplan'),flush=True)
    read_plan(work/'candidate.tfplan','create')
elif phase=='apply':
    read_plan(work/'candidate.tfplan','create')
    print(tf('apply','-input=false','-no-color','candidate.tfplan'),flush=True)
    (work/'candidate.xml').write_text(virsh('dumpxml',name))
    print('L1Created='+name,flush=True)
elif phase=='wait':
    address,guest=connected(pin=True)
    print('L1Identity='+json.dumps(guest)+';Address='+address,flush=True)
elif phase=='upload':
    _,_,address=instance()
    require(ssh(address,"$ErrorActionPreference='Stop'; foreach($d in 'C:\\SafeUploadNested\\image','C:\\SafeUploadNested\\scripts\\hyperv'){ $null=New-Item -ItemType Directory -Force -Path $d }; 'DirectoriesReady'"))
    files=[(export/'safeupload-debuggee-19045.2965.vhdx','C:/SafeUploadNested/image/safeupload-debuggee-19045.2965.vhdx'),
           (export/'image.sha256','C:/SafeUploadNested/image/image.sha256'),
           (lab/'secrets/portability-seed1021.cer','C:/SafeUploadNested/image/seed-test.cer'),
           (lab/'hyperv/New-LabVM.ps1','C:/SafeUploadNested/scripts/hyperv/New-LabVM.ps1'),
           (lab/'Test-LabGuest.ps1','C:/SafeUploadNested/scripts/Test-LabGuest.ps1'),
           (ev/'Invoke-NestedHyperV.ps1','C:/SafeUploadNested/scripts/Invoke-NestedHyperV.ps1')]
    for source,destination in files:
        require(run(['scp','-q',*ssh_args(address),str(source),'vika@'+address+':'+destination]))
        print('Uploaded='+source.name+';SHA256='+sha(source),flush=True)
elif phase=='l1':
    _,_,address=instance()
    r=run(['ssh',*ssh_args(address),'vika@'+address,
        'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\SafeUploadNested\\scripts\\Invoke-NestedHyperV.ps1 -Phase '+sys.argv[2]],
        stdin=subprocess.DEVNULL)
    print(r.stdout,flush=True); print(r.stderr,file=sys.stderr,flush=True)
    sys.exit(r.returncode)
elif phase=='l1reboot':
    address,before=connected()
    r=ssh(address,"'REBOOT_REQUESTED'; Restart-Computer -Force"); assert 'REBOOT_REQUESTED' in r.stdout,r.stderr
    address,after=connected(previous=before['Boot'])
    print('L1Rebooted='+json.dumps(after),flush=True)
elif phase=='destroy':
    print(tf('plan','-destroy','-input=false','-no-color','-out=destroy.tfplan'),flush=True)
    read_plan(work/'destroy.tfplan','delete')
    print(tf('apply','-input=false','-no-color','destroy.tfplan'),flush=True)
    assert run(['virsh','-c','qemu:///system','dominfo',name]).returncode!=0
    assert run(['virsh','-c','qemu:///system','pool-info',name]).returncode!=0
    assert not (Path('/var/lib/libvirt/qemu/nvram')/(name+'_VARS.fd')).exists()
    assert not Path(pool_path,name).exists()
    assert sha(image)==json.loads((work/'terraform.tfvars.json').read_text())['image_sha256']
    print('L1Cleanup=PASS;SharedSourceUnchanged=True',flush=True)
else: raise SystemExit('unknown phase')
