from pathlib import Path
import subprocess,hashlib,sys,re,datetime
label=sys.argv[1]
if not re.fullmatch(r'[A-Za-z0-9._-]{3,60}',label):raise SystemExit('Invalid build label')
root=Path(__file__).resolve().parents[2]
commit=subprocess.check_output(['git','rev-parse','--verify',(sys.argv[2] if len(sys.argv)>2 else 'HEAD')+'^{commit}'],cwd=root,text=True).strip()
work=Path('/tmp/claude-1000/exact-section-fault-'+label)
work.mkdir(parents=True,exist_ok=False)
subprocess.run(['git','archive','--format=zip','-o',str(work/'src.zip'),commit,'driver/SafeUpload.SectionFault'],cwd=root,check=True)
manifest=[]
for rel in subprocess.check_output(['git','ls-tree','-r','--name-only',commit,'--','driver/SafeUpload.SectionFault'],cwd=root,text=True).splitlines():
 data=subprocess.check_output(['git','show',commit+':'+rel],cwd=root)
 manifest.append(hashlib.sha256(data).hexdigest()+'  '+rel)
(work/'src.manifest').write_text('\n'.join(manifest)+'\n');opts=['-F','/dev/null','-i','/home/victor/.ssh/id_ed25519','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','LogLevel=ERROR','-o','StrictHostKeyChecking=accept-new'];d='vika@192.168.122.210:C:/Users/vika/Documents/'
for src,leaf in [(work/'src.zip','exact-section-fault-'+label+'.zip'),(work/'src.manifest','exact-section-fault-'+label+'.manifest'),(root/'driver/scripts/Build-ExactSectionFault.ps1','Build-SectionFault-'+label+'.ps1')]:subprocess.run(['scp']+opts+[str(src),d+leaf],check=True)
hashzip=hashlib.sha256((work/'src.zip').read_bytes()).hexdigest().upper();hashman=hashlib.sha256((work/'src.manifest').read_bytes()).hexdigest().upper()
ps="& 'C:\\Users\\vika\\Documents\\Build-SectionFault-"+label+".ps1' -Label '"+label+"' -ArchiveHash '"+hashzip+"' -ManifestHash '"+hashman+"'\n"
r=subprocess.run(['python3',str(root/'driver/scripts/remote_ps.py'),'192.168.122.210'],input=ps,text=True,capture_output=True);ev=root/'driver/evidence'/datetime.date.today().isoformat();ev.mkdir(parents=True,exist_ok=True);(ev/('section-fault-'+label+'-build.txt')).write_text(r.stdout+r.stderr)
for leaf in ['summary.txt','Debug-wdk.txt','Release-wdk.txt','sign.txt','SafeUploadSectionFault.sys']:
 r=subprocess.run(['scp']+opts+[d+'exact-section-fault-'+label+'/out/'+leaf,str(work/leaf)],capture_output=True)
 if r.returncode==0 and leaf.endswith('.txt'):(ev/('section-fault-'+label+'-'+leaf)).write_bytes((work/leaf).read_bytes())
(ev/('section-fault-'+label+'-source-manifest.txt')).write_bytes((work/'src.manifest').read_bytes())
provenance=['SourceCommit='+commit,'ArchiveSHA256='+hashzip,'ManifestSHA256='+hashman,'BuilderIP=192.168.122.210','Command='+ps.strip()]
for leaf in ['Invoke-ExactSectionFaultBuild.py','Build-ExactSectionFault.ps1','remote_ps.py']:
 p=root/'driver/scripts'/leaf;provenance.append(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(root)))
(ev/('section-fault-'+label+'-provenance.txt')).write_text('\n'.join(provenance)+'\n')
summary=(work/'summary.txt').read_text('utf-8-sig');print(summary)
for config in ['Debug','Release']:
 line=next(line for line in summary.splitlines() if line.startswith(config+' :'))
 if not all(token in line for token in ['exit=0','warnings=0','errors=0','prefast=True','apivalidator=True']):raise SystemExit('Companion gate failed: '+line)
if 'SignExit=0' not in summary or 'SignatureVerifyExit=0' not in summary:raise SystemExit('Signing gate failed')
if 'SignedSHA256='+hashlib.sha256((work/'SafeUploadSectionFault.sys').read_bytes()).hexdigest().upper() not in summary:raise SystemExit('Downloaded artifact hash mismatch')
