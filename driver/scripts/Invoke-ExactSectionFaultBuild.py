from pathlib import Path
import subprocess,hashlib,sys,re,datetime
label=sys.argv[1]
if not re.fullmatch(r'[A-Za-z0-9._-]{3,60}',label):raise SystemExit('Invalid build label')
root=Path(__file__).resolve().parents[2]
commit=subprocess.check_output(['git','rev-parse','--verify',(sys.argv[2] if len(sys.argv)>2 else 'HEAD')+'^{commit}'],cwd=root,text=True).strip()
tools_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
for leaf in ['Invoke-ExactSectionFaultBuild.py','Build-ExactSectionFault.ps1','remote_ps.py']:
 p=root/'driver/scripts'/leaf
 if subprocess.check_output(['git','show',tools_commit+':driver/scripts/'+leaf],cwd=root)!=p.read_bytes():raise SystemExit('Dirty build tool: '+leaf)
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
r=subprocess.run(['python3',str(root/'driver/scripts/remote_ps.py'),'192.168.122.210'],input=ps,text=True,capture_output=True);remote_exit=r.returncode;ev=root/'driver/evidence'/datetime.date.today().isoformat();ev.mkdir(parents=True,exist_ok=True);(ev/('section-fault-'+label+'-build.txt')).write_text(r.stdout+r.stderr)
missing=[]
for leaf in ['summary.txt','Debug-wdk.txt','Release-wdk.txt','sign.txt','SafeUploadSectionFault.sys']:
 r=subprocess.run(['scp']+opts+[d+'exact-section-fault-'+label+'/out/'+leaf,str(work/leaf)],capture_output=True)
 if r.returncode!=0:missing.append(leaf);continue
 if leaf.endswith('.txt'):(ev/('section-fault-'+label+'-'+leaf)).write_bytes((work/leaf).read_bytes())
(ev/('section-fault-'+label+'-source-manifest.txt')).write_bytes((work/'src.manifest').read_bytes())
provenance=['SourceCommit='+commit,'BuildToolsCommit='+tools_commit,'RemoteExit='+str(remote_exit),'MissingDownloads='+','.join(missing),'ArchiveSHA256='+hashzip,'ManifestSHA256='+hashman,'BuilderIP=192.168.122.210','Command='+ps.strip()]
for leaf in ['Invoke-ExactSectionFaultBuild.py','Build-ExactSectionFault.ps1','remote_ps.py']:
 p=root/'driver/scripts'/leaf;provenance.append(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(root)))
(ev/('section-fault-'+label+'-provenance.txt')).write_text('\n'.join(provenance)+'\n')
if missing:raise SystemExit('Missing required evidence/artifact: '+','.join(missing))
if remote_exit!=0:raise SystemExit('Remote companion build failed; inspect preserved logs')
summary=(work/'summary.txt').read_text('utf-8-sig');print(summary)
for config in ['Debug','Release']:
 rows=[line for line in summary.splitlines() if line.startswith(config+' :')]
 if len(rows)!=1:raise SystemExit('Missing or duplicate companion gate')
 fields=re.findall(r'(\w+)=([^\s]+)',rows[0]);row=dict(fields)
 if len(row)!=len(fields) or row.get('exit')!='0' or row.get('prefast')!='True' or row.get('apivalidator')!='True' or any(not re.fullmatch(r'0(?:,0)*',row.get(key,'')) for key in ['warnings','errors']):raise SystemExit('Companion gate failed: '+rows[0])
if summary.splitlines().count('SignExit=0')!=1 or summary.splitlines().count('SignerThumbprint=220DD82C37FCF36048D59E4F10113185D81D5DC7')!=1:raise SystemExit('Signing gate failed')
if summary.splitlines().count('SignedSHA256='+hashlib.sha256((work/'SafeUploadSectionFault.sys').read_bytes()).hexdigest().upper())!=1:raise SystemExit('Downloaded artifact hash mismatch')
