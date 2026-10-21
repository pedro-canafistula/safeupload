"""One-off controls for the isolated su-lab-port1021k candidate; not a product runner."""
from pathlib import Path
import base64,hashlib,ipaddress,json,os,subprocess,sys,time,xml.etree.ElementTree as ET
repo=Path.cwd(); lab=repo/'lab'; work=lab/'work/terraform-linux-1021k'
name='su-lab-port1021k'; hostname='SU-LAB-PORT1'
image=lab/'output/linux-portability-1021k/safeupload-debuggee-19045.2965.qcow2'
key=lab/'secrets/linux-portability-1021d'; hosts=work/'known_hosts'
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
def read_plan(path, action, expected=None):
    j=json.loads(tf('show','-json',str(path)))
    changes={r['address']:r['change']['actions'] for r in j.get('resource_changes',[]) if r.get('mode') != 'data' and r['change']['actions']!=['no-op']}
    expected=expected or {'random_password.admin','libvirt_pool.lab','libvirt_volume.base','libvirt_volume.disk','libvirt_cloudinit_disk.seed','libvirt_domain.debuggee'}
    assert set(changes)==expected and all(a==[action] for a in changes.values()),changes
    print('ScopedPlan='+json.dumps(changes),flush=True)
    return j

def instance():
    xml=ET.fromstring(virsh('dumpxml',name))
    identity=xml.findtext('uuid').upper(); nic=xml.find('devices/interface'); mac=nic.find('mac').get('address')
    assert xml.findtext('name')==name
    assert nic.find('model').get('type')=='e1000e'
    assert xml.find('devices/tpm') is None
    rows=virsh('net-dhcp-leases','default','--mac',mac).splitlines()
    addresses=[]
    for row in rows:
        if mac.lower() in row.lower():
            for word in row.split():
                if '/' in word:
                    try:
                        v=ipaddress.ip_interface(word)
                        if v.version==4: addresses.append(str(v.ip))
                    except ValueError: pass
    assert len(set(addresses))==1,rows
    address=addresses[0]
    assert address not in ['192.168.122.52','192.168.122.210','192.168.122.211'],address
    return identity,mac,address

def ssh(address,script,identity=key):
    command='powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+base64.b64encode(script.encode('utf-16le')).decode()
    return run(['ssh','-F','/dev/null','-i',str(identity),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ConnectTimeout=8',
        '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(hosts),'vika@'+address,command],stdin=subprocess.DEVNULL)

def identity_script():
    return "$ErrorActionPreference='Stop'; $setup=Get-ItemProperty 'HKLM:\\SYSTEM\\Setup'; [pscustomobject]@{SetupDone=(-not ($setup.SystemSetupInProgress -or $setup.OOBEInProgress));Name=$env:COMPUTERNAME;UUID=(Get-CimInstance Win32_ComputerSystemProduct).UUID;Boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');Seed=(Get-Content 'C:\\ProgramData\\SafeUploadLab\\seed-applied.txt' -Raw).Trim();HostKey=(Get-FileHash 'C:\\ProgramData\\ssh\\ssh_host_ed25519_key.pub').Hash} | ConvertTo-Json -Compress"

def connected(timeout=900,pin=False,new_boot=None):
    end=time.monotonic()+timeout; last='No lease'
    while time.monotonic()<end:
        try:
            uuid,mac,address=instance()
            if pin and not hosts.exists():
                scan=run(['ssh-keyscan','-T','5','-t','ed25519',address])
                if scan.returncode==0 and scan.stdout.strip():
                    hosts.write_text(scan.stdout); print('PinnedOwnCandidateKey='+address+';MAC='+mac,flush=True)
            result=ssh(address,identity_script())
            if result.returncode: last=result.stderr
            else:
                guest=json.loads(result.stdout.lstrip('\ufeff').strip())
                assert guest['UUID'].upper()==uuid,guest
                if guest.get('SetupDone') and guest['Name']==hostname and (new_boot is None or guest['Boot']!=new_boot):
                    return address,guest
                last='Waiting for setup/seed/new boot: '+json.dumps(guest)
        except AssertionError as e:
            last=str(e)
        time.sleep(3)
    raise RuntimeError('Candidate not ready: '+last)

def upload(address,source,destination):
    payload=base64.b64encode(source.read_bytes()).decode()
    for i in range(0,len(payload),2400):
        part=payload[i:i+2400]
        # Each chunk is independently base64-aligned.
        script="$ErrorActionPreference='Stop'; $b=[Convert]::FromBase64String('"+part+"'); $f=[IO.File]::Open('"+destination+"',[IO.FileMode]::"+('Create' if i==0 else 'Append')+"); try{$f.Write($b,0,$b.Length)}finally{$f.Dispose()}"
        require(ssh(address,script))

def acceptance(address):
    result=ssh(address,"$ErrorActionPreference='Stop'; & C:\\Windows\\Temp\\Test-LabGuest.ps1 -ExpectedHostname "+hostname+" -ExpectedSshPublicKeyFiles C:\\Windows\\Temp\\lab-test-key.pub | ConvertTo-Json -Compress")
    data=json.loads(require(result).lstrip('\ufeff').strip()); assert data['CandidateAcceptance']=='PASS' and data['ProductQualification'] is False,data
    print('GuestAcceptance='+json.dumps(data),flush=True)
    thumb=hashlib.sha1((lab/'secrets/portability-seed1021.cer').read_bytes()).hexdigest().upper()
    script="$ErrorActionPreference='Stop'; foreach($store in 'Root','TrustedPublisher'){$c=Get-Item ('Cert:\\LocalMachine\\'+$store+'\\"+thumb+"'); if($c.HasPrivateKey){throw 'Seed imported a private key'}}; 'PublicCertificateSeed=PASS'"
    result=ssh(address,script); assert 'PublicCertificateSeed=PASS' in require(result)
    print('PublicCertificateSeed=PASS;Thumbprint='+thumb,flush=True)

phase=sys.argv[1]
if phase=='prepare':
    assert not (work/'terraform.tfstate').exists()
    expected=(image.parent/'image.sha256').read_text().split()[0]
    assert sha(image)==expected
    values=dict(name=name,hostname=hostname,image_path=str(image),image_sha256=expected,ssh_public_keys=[key.with_suffix('.pub').read_text().strip()],trusted_certificate_files=[str(lab/'secrets/portability-seed1021.cer')])
    (work/'terraform.tfvars.json').write_text(json.dumps(values))
    print(tf('plan','-input=false','-no-color','-out=candidate.tfplan'),flush=True)
    read_plan(work/'candidate.tfplan','create')
elif phase=='apply':
    read_plan(work/'candidate.tfplan','create')
    print(tf('apply','-input=false','-no-color','candidate.tfplan'),flush=True)
    (work/'candidate.xml').write_text(virsh('dumpxml',name))
    pool=ET.fromstring(virsh('pool-dumpxml',name))
    private=Path(pool.findtext('target/path'))
    info=private.stat()
    assert info.st_mode & 0o777 == 0o700, oct(info.st_mode)
    caps=ET.fromstring(virsh('capabilities'))
    label=next(m.findtext("baselabel[@type='kvm']") for m in caps.findall('./host/secmodel') if m.findtext('model')=='dac')
    uid,gid=(int(n.lstrip('+')) for n in label.split(':'))
    assert (info.st_uid,info.st_gid)==(uid,gid), (info.st_uid,info.st_gid,uid,gid)
    print('PrivatePool=PASS;Mode=0700;Owner='+str(uid)+':'+str(gid),flush=True)
    (work/'pool.xml').write_text(virsh('pool-dumpxml',name))
elif phase=='repair_plan':
    print(tf('plan','-input=false','-no-color','-out=candidate-b.tfplan'),flush=True)
    read_plan(work/'candidate-b.tfplan','create',expected={'libvirt_domain.debuggee'})
elif phase=='repair_apply':
    read_plan(work/'candidate-b.tfplan','create',expected={'libvirt_domain.debuggee'})
    print(tf('apply','-input=false','-no-color','candidate-b.tfplan'),flush=True)
    (work/'candidate.xml').write_text(virsh('dumpxml',name))
    pool=ET.fromstring(virsh('pool-dumpxml',name))
    private=Path(pool.findtext('target/path'))
    info=private.stat()
    assert info.st_mode & 0o777 == 0o700, oct(info.st_mode)
    caps=ET.fromstring(virsh('capabilities'))
    label=next(m.findtext("baselabel[@type='kvm']") for m in caps.findall('./host/secmodel') if m.findtext('model')=='dac')
    uid,gid=(int(n.lstrip('+')) for n in label.split(':'))
    assert (info.st_uid,info.st_gid)==(uid,gid), (info.st_uid,info.st_gid,uid,gid)
    print('PrivatePool=PASS;Mode=0700;Owner='+str(uid)+':'+str(gid),flush=True)
    (work/'pool.xml').write_text(virsh('pool-dumpxml',name))
elif phase=='check':
    address,guest=connected(pin=True)
    print('SeededIdentity='+json.dumps(guest),flush=True)
    (work/'windows-client-target.json').write_text(json.dumps({'address':address,'uuid':guest['UUID'],'hostname':guest['Name']}))
    upload(address,lab/'Test-LabGuest.ps1','C:\\Windows\\Temp\\Test-LabGuest.ps1')
    upload(address,key.with_suffix('.pub'),'C:\\Windows\\Temp\\lab-test-key.pub')
    acceptance(address)
    unrelated=work/'unrelated-key'
    require(run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(unrelated)]))
    rejected=ssh(address,"'unrelated-key-must-fail'",identity=unrelated)
    assert rejected.returncode==255 and 'Permission denied' in rejected.stderr,rejected.stderr
    print('UnrelatedSshKey=REFUSED',flush=True)
    askpass=work/'password-askpass'
    askpass.write_text('#!/usr/bin/env python3\nimport pathlib,subprocess\np=pathlib.Path(__file__).parent\nr=subprocess.run(["terraform","output","-raw","admin_password"],cwd=p,text=True,capture_output=True,check=True)\nprint(r.stdout)\n')
    askpass.chmod(0o700)
    password_env=env.copy(); password_env.update(SSH_ASKPASS=str(askpass),SSH_ASKPASS_REQUIRE='force',DISPLAY=':0')
    try:
        r=run(['ssh','-F','/dev/null','-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',
            '-o','NumberOfPasswordPrompts=1','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(hosts),
            'vika@'+address,'powershell.exe -NoProfile -NonInteractive -Command "Write-Output SeedPasswordAccepted"'],
            env=password_env,stdin=subprocess.DEVNULL,start_new_session=True)
        assert 'SeedPasswordAccepted' in require(r), 'Seed password was not accepted'
        print('SeedPasswordAuthentication=PASS',flush=True)
    finally: askpass.unlink()
    (work/'identity-before.json').write_text(json.dumps(guest))
elif phase=='reboot':
    address,before=connected()
    r=ssh(address,"'REBOOT_REQUESTED'; Restart-Computer -Force")
    assert 'REBOOT_REQUESTED' in r.stdout,r.stderr
    address,after=connected(new_boot=before['Boot'])
    assert after['HostKey']==before['HostKey'] and after['Seed']==before['Seed'],(before,after)
    acceptance(address)
    print('RebootIdempotence=PASS;Before='+json.dumps(before)+';After='+json.dumps(after),flush=True)
    (work/'identity-after.json').write_text(json.dumps(after))
elif phase=='destroy':
    print(tf('plan','-destroy','-input=false','-no-color','-out=destroy.tfplan'),flush=True)
    read_plan(work/'destroy.tfplan','delete')
    print(tf('apply','-input=false','-no-color','destroy.tfplan'),flush=True)
    assert run(['virsh','-c','qemu:///system','dominfo',name]).returncode!=0
    assert run(['virsh','-c','qemu:///system','pool-info',name]).returncode!=0
    nvram=Path('/var/lib/libvirt/qemu/nvram')/(name+'_VARS.fd')
    assert not nvram.exists(),str(nvram)
    assert not Path('/var/lib/libvirt/images/safeupload-lab',name).exists()
    values=json.loads((work/'terraform.tfvars.json').read_text())
    assert sha(image)==values['image_sha256']
    print('CandidateCleanup=PASS;SharedSourceUnchanged=True',flush=True)
else: raise SystemExit('unknown phase')
