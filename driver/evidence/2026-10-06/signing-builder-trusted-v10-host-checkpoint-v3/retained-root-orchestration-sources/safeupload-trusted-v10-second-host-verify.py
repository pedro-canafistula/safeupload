from pathlib import Path
import hashlib,json,xml.etree.ElementTree as ET
r=Path('/home/victor/Work/safeupload-staging');d=r/'driver/evidence/2026-10-06/signing-builder-trusted-v10-host-checkpoint-v3';o=d/'second-cold-host-verify';o.mkdir(exist_ok=False)
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=d/'execute-checkpoint.py';assert h(source)=='12a67e8a58a020c7777754645dd3f07fc0e80f4676660dc60eeb802d7d962b4c'
first=r/'driver/evidence/2026-10-06/signing-builder-trusted-v10-first-cold-root-readout.json';assert h(first)=='d4b714c647219958a3b6711ff2af5ef238016638a7ac143402de2b252b2ac04f'
for rel,pin in json.loads(first.read_text())['EvidencePins'].items():assert h(r/rel)==pin
# Load only imports, immutable input paths, and reviewed functions, stopping before the phase dispatcher.
prefix=source.read_text().split("require(len(sys.argv)",1)[0];ns={'__file__':str(source)};exec(compile(prefix,str(source),'exec'),ns)
assert ns['virsh']('domuuid','win10').strip().lower()==ns['PLAN']['UUID'].lower()
assert ns['virsh']('domstate','win10').strip()=='running'
inactive=ns['virsh']('dumpxml','win10','--inactive');live=ns['virsh']('dumpxml','win10')
(o/'inactive.xml').write_text(inactive);(o/'live.xml').write_text(live)
i=ET.fromstring(inactive);l=ET.fromstring(live);expected=ET.fromstring((d/'domain-child.xml').read_bytes());template=ET.fromstring((d/'domain-live-preflight.xml').read_bytes())
assert ns['normalized_persistent_domain'](i)==ns['normalized_persistent_domain'](expected)
assert ns['normalized_live_domain'](l)==ns['normalized_live_domain'](template)
assert ns['disk_source'](i)==ns['disk_source'](l)==str(ns['CHILD'])
q=ns['qmp_json']({'execute':'query-block'});n=ns['qmp_json']({'execute':'query-named-block-nodes'});jobs=ns['qmp_json']({'execute':'query-block-jobs'})
for name,data in [('query-block',q),('named-block-nodes',n),('block-jobs',jobs)]: (o/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
host=json.loads((d/'host-readout.json').read_text());chain=ns['image_chain'](q,ns['CHILD']);assert chain==host['BackingChain']
assert str(ns['RETRY1']) not in chain
parent=ns['file_stat'](ns['PARENT']);assert parent==host['ParentStatBefore']==host['ParentStatAfter']
parentnodes=[x for x in n['return'] if x.get('file')==str(ns['PARENT']) and x.get('drv')=='qcow2'];assert len(parentnodes)==1 and parentnodes[0]['ro'] is True
child=ns['file_stat'](ns['CHILD']);assert (child['Mode'],child['UID'],child['GID'])==(0o600,958,958)
assert jobs['return']==[]
x={'Verdict':'SECOND_COLD_HOST_DISK_AND_DOMAIN_PASS','ParentFullStatUnchanged':True,'ParentQcow2ReadOnly':True,'BackingChain':chain,'ExactChildPersistentDefinition':True,'LiveDomainMatchesReviewedRuntimeProjection':True,'ChildMode':'0600','ChildUID':958,'ChildGID':958,'NoBlockJobs':True,'StateMutationAttempted':False,'FirmwareTpmRamCheckpointed':False,'SharedNvramCheckpointed':False,'FullVmRollbackClaimed':False,'EvidencePins':{str(p.relative_to(r)):h(p) for p in o.iterdir()}}
(o/'root-readout.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
