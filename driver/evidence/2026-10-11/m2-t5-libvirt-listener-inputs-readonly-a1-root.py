import datetime,hashlib,json,os,subprocess
from pathlib import Path
out=Path('/tmp/m2-t5-libvirt-listener-inputs-readonly-a1-root.json');assert not out.exists()
units=['libvirtd.service','libvirtd.socket','libvirtd-ro.socket','libvirtd-admin.socket','virtproxyd.service','virtproxyd.socket','virtproxyd-ro.socket','virtproxyd-admin.socket','virtqemud.service','virtqemud.socket','virtqemud-ro.socket','virtqemud-admin.socket','libvirtd-tcp.socket','libvirtd-tls.socket','virtproxyd-tcp.socket','virtproxyd-tls.socket']
cmds=[['systemctl','show',*units,'--no-pager','--property=Id,LoadState,ActiveState,SubState,MainPID,InvocationID,ControlGroup,RootDirectory,RootImage,FragmentPath,DropInPaths,Listen,Triggers,TriggeredBy,ExecStart,KillMode,TimeoutStopUSec,Restart'],['ss','-lxnp'],['ss','-lntup'],['pacman','-Q','libvirt','qemu-base','systemd']]
r={'CapturedUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'Scope':'Read-only observer and systemd-manager receipts; listener/proc observations limited to captured observer namespaces. No host-wide listener closure or drain established.','Observer':{'pid':os.getpid(),'namespaces':{},'SelectedProcStatus':{}},'Commands':[],'HookDirectory':{},'HostPolicyApplied':False,'LibvirtAPIInvoked':False,'VMChanged':False,'DrainEstablished':False}
for who in ['self','1']:
 for kind in ['pid','mnt','net','user']:
  p=f'/proc/{who}/ns/{kind}'
  try:r['Observer']['namespaces'][p]=os.readlink(p)
  except OSError as e:r['Observer']['namespaces'][p]={'error':str(e)}
for line in Path('/proc/self/status').read_text().splitlines():
 if line.split(':')[0] in ['NSpid','Uid','Gid','CapEff']:r['Observer']['SelectedProcStatus'][line.split(':')[0]]=line.split(':',1)[1].strip()
for c in cmds:
 try:
  p=subprocess.run(c,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
  r['Commands'].append({'argv':c,'ExitCode':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace'),'StdoutSHA256':hashlib.sha256(p.stdout).hexdigest(),'StderrSHA256':hashlib.sha256(p.stderr).hexdigest()})
 except (OSError,subprocess.TimeoutExpired) as e:r['Commands'].append({'argv':c,'ObservationError':str(e),'TerminalOrGlobalClaim':False})
p=Path('/etc/libvirt/hooks')
try:r['HookDirectory']={'path':str(p),'exists':p.exists(),'is_directory':p.is_dir(),'entries':sorted(x.name for x in p.iterdir()) if p.is_dir() else [],'Scope':'Observer filesystem only; no deployed host hook absence claim'}
except OSError as e:r['HookDirectory']={'path':str(p),'error':str(e)}
with out.open('x') as f:json.dump(r,f,indent=2,sort_keys=True);f.write('\n')
print('Receipt',out,'SHA256',hashlib.sha256(out.read_bytes()).hexdigest())
for x in r['Commands']:print(x['argv'][0],x.get('ExitCode'),len(x.get('stdout','')),len(x.get('stderr','')))
print('Namespaces',r['Observer']['namespaces'])
