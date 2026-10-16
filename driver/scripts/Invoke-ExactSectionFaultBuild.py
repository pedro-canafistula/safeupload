from approved_builders import select, remote_args, identity_ps, receipt_lines
from pathlib import Path
import subprocess,hashlib,sys,re,datetime,os,json
if len(sys.argv) not in (2,3):raise SystemExit('Usage: Invoke-ExactSectionFaultBuild.py LABEL [COMMIT]')
label=sys.argv[1]
thumb=os.environ.get('SAFEUPLOAD_SIGNING_THUMBPRINT','220DD82C37FCF36048D59E4F10113185D81D5DC7').upper()
store=os.environ.get('SAFEUPLOAD_SIGNING_STORE_LOCATION','CurrentUser')
if not re.fullmatch(r'[0-9A-F]{40}',thumb):raise SystemExit('Invalid signing thumbprint')
if store not in ('CurrentUser','LocalMachine'):raise SystemExit('Invalid signing store')
if not re.fullmatch(r'[A-Za-z0-9._-]{3,60}',label):raise SystemExit('Invalid build label')
builder=select('kernel-sign',label)
remote_cli=remote_args(builder,'kernel-sign',label)
root=Path(__file__).resolve().parents[2]
commit=subprocess.check_output(['git','rev-parse','--verify',(sys.argv[2] if len(sys.argv)>2 else 'HEAD')+'^{commit}'],cwd=root,text=True).strip()
tools_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
tool_bytes={leaf:(root/'driver/scripts'/leaf).read_bytes() for leaf in ['Invoke-ExactSectionFaultBuild.py','Build-ExactSectionFault.ps1','remote_ps.py','approved_builders.py','approved-builders.json','ApprovedBuilders.ps1']}
work=Path('/tmp/claude-1000/exact-section-fault-'+label)
work.mkdir(parents=True,exist_ok=False)
for leaf,data in tool_bytes.items():(work/leaf).write_bytes(data)
(work/'build-tool-manifest.json').write_text(json.dumps({leaf:hashlib.sha256(data).hexdigest() for leaf,data in tool_bytes.items()},indent=2)+'\n')
subprocess.run(['git','archive','--format=zip','-o',str(work/'src.zip'),commit,'driver/SafeUpload.SectionFault'],cwd=root,check=True)
manifest=[]
for rel in subprocess.check_output(['git','ls-tree','-r','--name-only',commit,'--','driver/SafeUpload.SectionFault'],cwd=root,text=True).splitlines():
 data=subprocess.check_output(['git','show',commit+':'+rel],cwd=root)
 manifest.append(hashlib.sha256(data).hexdigest()+'  '+rel)
(work/'src.manifest').write_text('\n'.join(manifest)+'\n');opts=['-F','/dev/null','-i','/home/victor/.ssh/id_ed25519','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','LogLevel=ERROR','-o','StrictHostKeyChecking=yes'];d=builder['ssh_user']+'@'+builder['host']+':C:/Users/'+builder['ssh_user']+'/Documents/'
preflight=identity_ps(builder)
for leaf in ['exact-section-fault-'+label,'exact-section-fault-'+label+'.zip','exact-section-fault-'+label+'.manifest','Build-SectionFault-'+label+'.ps1']:
 preflight+="if(Test-Path -LiteralPath 'C:\\Users\\vika\\Documents\\"+leaf+"'){throw 'Remote destination already exists'}\n"
r=subprocess.run(['python3',str(work/'remote_ps.py'),*remote_cli],input=preflight,text=True,capture_output=True)
(work/'preflight.stdout.txt').write_text(r.stdout);(work/'preflight.stderr.txt').write_text(r.stderr)
if r.returncode:raise SystemExit('Builder preflight failed before source delivery')
support_dir='C:/Users/'+builder['ssh_user']+'/Documents/exact-section-fault-'+label+'-tools'
r=subprocess.run(['python3',str(work/'remote_ps.py'),*remote_cli],input="[void](New-Item -ItemType Directory -Path '"+support_dir+"')",text=True,capture_output=True)
if r.returncode:raise SystemExit('Cannot create fresh support directory')
for leaf in ['ApprovedBuilders.ps1','approved-builders.json']:
 subprocess.run(['scp']+opts+[str(work/leaf),d+'exact-section-fault-'+label+'-tools/'+leaf],check=True)
for src,leaf in [(work/'src.zip','exact-section-fault-'+label+'.zip'),(work/'src.manifest','exact-section-fault-'+label+'.manifest'),(work/'Build-ExactSectionFault.ps1','Build-SectionFault-'+label+'.ps1')]:subprocess.run(['scp']+opts+[str(src),d+leaf],check=True)
hashzip=hashlib.sha256((work/'src.zip').read_bytes()).hexdigest().upper();hashman=hashlib.sha256((work/'src.manifest').read_bytes()).hexdigest().upper()
ps="$p='C:\\Users\\vika\\Documents\\Build-SectionFault-"+label+".ps1'; if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -cne '"+hashlib.sha256(tool_bytes['Build-ExactSectionFault.ps1']).hexdigest().upper()+"'){throw 'Build helper hash mismatch'}; & 'C:\\Users\\vika\\Documents\\Build-SectionFault-"+label+".ps1' -Label '"+label+"' -ArchiveHash '"+hashzip+"' -ManifestHash '"+hashman+"' -CertificateThumbprint '"+thumb+"' -CertificateStoreLocation '"+store+"' -BuilderName '"+builder['name']+"' -BuilderSupportPath '"+support_dir+"/ApprovedBuilders.ps1' -BuilderConfigPath '"+support_dir+"/approved-builders.json'\n"
r=subprocess.run(['python3',str(work/'remote_ps.py'),*remote_cli],input=ps,text=True,capture_output=True);remote_exit=r.returncode;ev=root/'driver/evidence'/datetime.date.today().isoformat();ev.mkdir(parents=True,exist_ok=True);(ev/('section-fault-'+label+'-build.txt')).write_text(r.stdout+r.stderr)
missing=[]
for leaf in ['summary.txt','Debug-wdk.txt','Release-wdk.txt','sign.txt','signature-verification.json','Debug.sys','Release.sys','SafeUploadSectionFault.sys']:
 r=subprocess.run(['scp']+opts+[d+'exact-section-fault-'+label+'/out/'+leaf,str(work/leaf)],capture_output=True)
 if r.returncode!=0:missing.append(leaf);continue
 if leaf.endswith('.txt'):(ev/('section-fault-'+label+'-'+leaf)).write_bytes((work/leaf).read_bytes())
(ev/('section-fault-'+label+'-source-manifest.txt')).write_bytes((work/'src.manifest').read_bytes())
provenance=['SourceCommit='+commit,'BuildToolsBaseCommit='+tools_commit,'BuildToolsCapturedFromWorktree=True','RemoteExit='+str(remote_exit),'MissingDownloads='+','.join(missing),'ArchiveSHA256='+hashzip,'ManifestSHA256='+hashman,*receipt_lines(builder),'Command='+ps.strip()]
for leaf in ['Invoke-ExactSectionFaultBuild.py','Build-ExactSectionFault.ps1','remote_ps.py','approved_builders.py','approved-builders.json','ApprovedBuilders.ps1']:
 provenance.append(hashlib.sha256(tool_bytes[leaf]).hexdigest()+'  driver/scripts/'+leaf)
(ev/('section-fault-'+label+'-provenance.txt')).write_text('\n'.join(provenance)+'\n')
if missing:raise SystemExit('Missing required evidence/artifact: '+','.join(missing))
if remote_exit!=0:raise SystemExit('Remote companion build failed; inspect preserved logs')
summary=(work/'summary.txt').read_text('utf-8-sig');print(summary)
for config in ['Debug','Release']:
 rows=[line for line in summary.splitlines() if line.startswith(config+' :')]
 if len(rows)!=1:raise SystemExit('Missing or duplicate companion gate')
 fields=re.findall(r'(\w+)=([^\s]+)',rows[0]);row=dict(fields)
 if len(row)!=len(fields) or row.get('exit')!='0' or row.get('prefast')!='True' or row.get('apivalidator')!='True' or any(not re.fullmatch(r'0(?:,0)*',row.get(key,'')) for key in ['warnings','errors']):raise SystemExit('Companion gate failed: '+rows[0])
rows=[line for line in summary.splitlines() if line.startswith('sign :')]
if len(rows)!=1:raise SystemExit('Missing or duplicate signing gate')
fields=re.findall(r'(\w+)=([^\s]+)',rows[0]);row=dict(fields)
if len(row)!=len(fields) or any(row.get(k)!=v for k,v in {'exit':'0','signature_valid':'True','signer':thumb,'store':store,'unsigned_unchanged':'True'}.items()):raise SystemExit('Signing gate failed')
for field,leaf in [('unsigned_sha256','Debug.sys'),('signed_sha256','SafeUploadSectionFault.sys')]:
 if row.get(field)!=hashlib.sha256((work/leaf).read_bytes()).hexdigest().upper():raise SystemExit('Downloaded artifact hash mismatch: '+leaf)
if row.get('signing_copy_sha256')!=row.get('unsigned_sha256'):raise SystemExit('Signing copy changed before signing')
verification=json.loads((work/'signature-verification.json').read_text('utf-8-sig'))
for key,value in {'SignExit':0,'SignatureStatus':'Valid','ExpectedSigner':thumb,'CertificateStoreLocation':store,'ActualSigner':thumb,'SignatureValid':True,'UnsignedArtifactUnchanged':True,'UnsignedSHA256':row['unsigned_sha256'],'SigningCopySHA256Before':row['unsigned_sha256'],'SignedSHA256':row['signed_sha256']}.items():
 if verification.get(key)!=value:raise SystemExit('Signature evidence mismatch: '+key)
print('ExactSectionFaultBuildGate=PASS')
