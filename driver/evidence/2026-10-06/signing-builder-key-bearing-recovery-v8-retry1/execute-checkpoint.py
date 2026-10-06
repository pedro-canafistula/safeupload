"""Guarded cold builder checkpoint; no certificate or trust operations."""
import copy
import datetime
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path('/home/victor/Work/safeupload-staging')
HERE = Path(__file__).resolve().parent
PLAN = json.loads((HERE / 'inputs.json').read_text())
EXECUTION_PINS = HERE / 'execution-pins.json'
DOMAIN = 'win10'
PARENT = Path(PLAN['Parent'])
INITIAL_DISK = Path(PLAN.get('InitialDisk', PLAN['Parent']))
CHILD = Path(PLAN['Child'])

def virsh(*args):
    p = subprocess.run(['virsh', '-c', 'qemu:///system', *args], capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(p.stderr)
    return p.stdout

def disk(root):
    return root.find("./devices/disk/target[@dev='vda']/..")

def normalized(root):
    root = copy.deepcopy(root)
    item = disk(root)
    item.find('source').set('file', 'PERMITTED_VDA_SOURCE')
    for backing in list(item.findall('backingStore')):
        item.remove(backing)
    return ET.canonicalize(ET.tostring(root, encoding='unicode'), strip_text=True)

def file_stat(path):
    s = path.stat()
    return dict(Device=s.st_dev, Inode=s.st_ino, Bytes=s.st_size,
                MtimeNS=s.st_mtime_ns, Mode=stat.S_IMODE(s.st_mode), UID=s.st_uid, GID=s.st_gid)

def require(condition, why):
    if not condition:
        raise RuntimeError(why)

require(len(sys.argv) == 3, 'Phase and expected execution-manifest hash are required')
require(PLAN.get('ReadyForExecution') is True, 'Retry package awaits pinned failed-trust capture; refuse before any libvirt command')
failure = PLAN.get('FailureCapture', {})
require(failure.get('Status') == 'ROOT_FAILED_TRUST_CAPTURE_PINNED', 'Failed V8 trust six-store/descriptor capture is not pinned and reviewed')
failure_path = failure.get('Path', '')
failure_hash = failure.get('Sha256', '')
require(isinstance(failure_path, str) and failure_path.startswith('driver/evidence/2026-10-06/'), 'Failed-trust capture path is not a pinned repository evidence input')
require(len(failure_hash) == 64 and all(c in '0123456789abcdefABCDEF' for c in failure_hash), 'Failed-trust capture SHA-256 is incomplete')
require(PLAN['InputPins'].get(failure_path, '').lower() == failure_hash.lower(), 'Failed-trust capture is not bound to the package input pins')
require(hashlib.sha256((ROOT / failure_path).read_bytes()).hexdigest() == failure_hash.lower(), 'Failed-trust capture drift')
failure_readout = json.loads((ROOT / failure_path).read_text(encoding='utf-8-sig'))
require(failure_readout.get('Verdict') == 'FAILED_V8_TRUST_CAPTURE_PINNED' and failure_readout.get('TrustRemoteExitCode') == 1 and
        failure_readout.get('OriginalUnderlyingErrorCaptured') is False and failure_readout.get('AllSixStoresExactlyMintBaseline') is True and
        failure_readout.get('CurrentKeySddlExactlyMint') is True and failure_readout.get('ArtifactSigningAttempted') is False and
        failure_readout.get('FailedChildMustBeRetained') is True, 'Failed V8 trust capture does not prove the required preserved state')
require(failure_readout.get('MetadataSHA256', '').lower() == PLAN['MintEvidence']['CreationMetadataSha256'].lower() and
        failure_readout.get('PublicCerSHA256', '').lower() == PLAN['MintEvidence']['PublicCerSha256'].lower(), 'Failed V8 trust capture public metadata hashes differ from the minted key evidence')
for raw_path, raw_hash in failure_readout.get('EvidencePins', {}).items():
    require(PLAN['InputPins'].get(raw_path, '').lower() == raw_hash.lower(), 'Failed V8 raw evidence is not in package inputs: ' + raw_path)
    require(hashlib.sha256((ROOT / raw_path).read_bytes()).hexdigest() == raw_hash.lower(), 'Failed V8 raw evidence drift: ' + raw_path)
evidence = PLAN.get('MintEvidence', {})
require(evidence.get('Status') == 'V8_MINT_PUBLIC_READOUT_VERIFIED', 'V8 mint evidence has not been independently finalized')
for name, size in (('Thumbprint', 40), ('PublicCerSha256', 64), ('CreationMetadataSha256', 64)):
    value = evidence.get(name, '')
    require(len(value) == size and all(c in '0123456789abcdefABCDEF' for c in value), 'Incomplete V8 runtime evidence pin: ' + name)
require(evidence.get('KeyContainerUniqueName') == 'baf50051249c011374429d9bd1e26499_8e37b17a-0f0f-44e4-a0e9-4c0d9db2cdec', 'Unexpected V8 machine key container')
metadata_path = ROOT / 'driver/evidence/2026-10-06/replacement-machine-key-v8-public-metadata.json'
require(hashlib.sha256(metadata_path.read_bytes()).hexdigest() == evidence['CreationMetadataSha256'], 'V8 public creation metadata drift')
metadata = json.loads(metadata_path.read_text(encoding='utf-8-sig'))
require(metadata.get('Status') == 'CreatedAndProbed' and metadata.get('Thumbprint') == evidence['Thumbprint'] and
        metadata.get('PublicCerSHA256', '').upper() == evidence['PublicCerSha256'].upper() and
        metadata.get('NoAclWrite') is True and metadata.get('KeyAclUnchanged') is True and
        metadata.get('PrivateKeyMaterialExported') is False and metadata.get('PersistentTrustChanged') is False and
        metadata.get('ChallengeSignatureVerified') is True, 'V8 public creation metadata evidence mismatch')
require(len(metadata.get('PostMintAllStoreThumbprints', {})) == 6, 'V8 public six-store inventory missing')
require(PLAN['InputPins'].get('driver/evidence/2026-10-06/exact-mvp20261006admissioncap2-replacement-create-machine-key-v8.ps1') == evidence.get('CreatorScriptSha256'), 'V8 creator source pin mismatch')
require(PLAN['InputPins'].get('driver/evidence/2026-10-06/signing-guard-helpers-v8.ps1') == evidence.get('GuardHelperSha256'), 'V8 guard helper source pin mismatch')
require(PLAN['InputPins'].get('driver/evidence/2026-10-06/exact-mvp20261006admissioncap2-key-bearing-cold-challenge-v8.ps1') == evidence.get('ColdChallengeScriptSha256'), 'V8 cold challenge source pin mismatch')
require(PLAN['InputPins'].get('driver/evidence/2026-10-06/SafeUploadTest-Recovery-20261006-v8.cer', '').lower() == evidence.get('PublicCerSha256', '').lower(), 'V8 public CER byte hash does not equal the pinned certificate hash')
require(hashlib.sha256(EXECUTION_PINS.read_bytes()).hexdigest() == sys.argv[2], 'Execution manifest drift')
for name, pin in json.loads(EXECUTION_PINS.read_text()).items():
    require(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == pin, 'Execution source drift')

for name, pin in PLAN['InputPins'].items():
    require(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == pin, 'Checkpoint input drift')
require(virsh('domuuid', DOMAIN).strip() == PLAN['UUID'], 'Wrong builder UUID')
original = ET.fromstring((ROOT / 'driver/evidence/2026-10-06/signing-builder-checkpoint-preflight-domain-inactive.xml').read_bytes())
initial = ET.fromstring((HERE / 'domain-initial.xml').read_bytes())
require(normalized(initial) == normalized(original), 'Initial recovery definition has unrelated domain changes')
require(disk(initial).find('source').get('file') == str(INITIAL_DISK), 'Initial definition does not use the retained failed V8 key-bearing child')
current = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
require(normalized(current) == normalized(original), 'Unrelated persistent domain configuration changed')
phase = sys.argv[1]

if phase == 'shutdown':
    require(virsh('domstate', DOMAIN).strip() == 'running', 'Builder is not running')
    require(disk(current).find('source').get('file') == str(INITIAL_DISK), 'Unexpected retained failed V8 child source')
    require(not CHILD.exists(), 'Child already exists')
    require(INITIAL_DISK.exists(), 'Failed V8 key-bearing initial disk is missing')
    (HERE / 'failed-initial-running-stat.json').write_text(json.dumps(file_stat(INITIAL_DISK), indent=2) + '\n')
    require('None' in virsh('domjobinfo', DOMAIN), 'Builder has a domain job')
    require('No current block job' in virsh('blockjob', DOMAIN, 'vda', '--info'), 'Builder has a block job')
    for name in virsh('list', '--all', '--name').splitlines():
        if not name or name == DOMAIN:
            continue
        other = ET.fromstring(virsh('dumpxml', name))
        require(not any(n.get('file') == str(PARENT) for n in other.findall('./devices/disk/source')), 'Parent used as another domain disk')
    require(file_stat(PARENT)['Mode'] == 0o600, 'Original disk access is not restricted')
    (HERE / 'shutdown-command.txt').write_text(virsh('shutdown', DOMAIN))
    print('GracefulShutdownRequested=True')
elif phase == 'create-start':
    require(virsh('domstate', DOMAIN).strip() == 'shut off', 'Clean shutdown has not completed')
    require(disk(current).find('source').get('file') == str(INITIAL_DISK), 'Retained failed V8 child source changed before retry')
    require(not CHILD.exists(), 'Child already exists')
    # domjobinfo is only valid on a running domain. Confirmed shutoff above
    # excludes live domain/block jobs; do not treat that API error as a job.
    parent_stat = file_stat(PARENT)
    require(parent_stat['Mode'] == 0o600, 'Original disk access is not restricted')
    require(INITIAL_DISK.exists(), 'Failed V8 initial disk disappeared during shutdown')
    initial_before = json.loads((HERE / 'failed-initial-running-stat.json').read_text())
    initial_after_shutdown = file_stat(INITIAL_DISK)
    require((initial_before['Device'], initial_before['Inode'], initial_before['Mode'], initial_before['UID'], initial_before['GID']) ==
            (initial_after_shutdown['Device'], initial_after_shutdown['Inode'], initial_after_shutdown['Mode'], initial_after_shutdown['UID'], initial_after_shutdown['GID']), 'Retained failed V8 initial disk identity/access metadata changed')
    (HERE / 'failed-initial-shutoff-stat.json').write_text(json.dumps(initial_after_shutdown, indent=2) + '\n')
    (HERE / 'frozen-parent-stat.json').write_text(json.dumps(parent_stat, indent=2) + '\n')
    (HERE / 'volume-create.txt').write_text(virsh('vol-create', 'default', str(HERE / 'volume-child.xml')))
    require(CHILD.exists(), 'New child missing')
    child_stat = file_stat(CHILD)
    require((child_stat['Mode'], child_stat['UID'], child_stat['GID']) == (0o600, 958, 958), 'New child access differs from 0600 libvirt-qemu; preserve it')
    volume = ET.fromstring(virsh('vol-dumpxml', str(CHILD), '--pool', 'default'))
    require(volume.findtext('./backingStore/path') == str(PARENT), 'New child backing mismatch; preserve it')
    require(volume.find('./target/format').get('type') == 'qcow2', 'New child format mismatch')
    require(volume.findtext('./target/permissions/mode') == '0600' and
            volume.findtext('./target/permissions/owner') == '958' and
            volume.findtext('./target/permissions/group') == '958', 'Volume permission readback mismatch')
    (HERE / 'volume-readback.xml').write_text(ET.tostring(volume, encoding='unicode'))
    nvram_path = Path(original.findtext('./os/nvram'))
    require(nvram_path.exists(), 'Shared NVRAM file is missing')
    nvram_before = file_stat(nvram_path)
    (HERE / 'nvram-prestart-stat.json').write_text(json.dumps(dict(Path=str(nvram_path), Stat=nvram_before), indent=2) + '\n')
    (HERE / 'define.txt').write_text(virsh('define', str(HERE / 'domain-child.xml'), '--validate'))
    defined = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
    require(normalized(defined) == normalized(original), 'Non-disk configuration changed; do not start')
    require(disk(defined).find('source').get('file') == str(CHILD), 'Persistent child mismatch; do not start')
    require(file_stat(PARENT) == parent_stat, 'Frozen parent changed; do not start')
    (HERE / 'start.txt').write_text(virsh('start', DOMAIN))
    print('ColdChildStarted=True; IndependentGuestBaselinePending=True')
elif phase == 'verify-host':
    require(virsh('domstate', DOMAIN).strip() == 'running', 'Builder not running')
    require(disk(current).find('source').get('file') == str(CHILD), 'Persistent disk mismatch')
    live = ET.fromstring(virsh('dumpxml', DOMAIN))
    require(disk(live).find('source').get('file') == str(CHILD), 'Live disk mismatch')
    qmp = json.loads(virsh('qemu-monitor-command', DOMAIN, '--pretty', '{"execute":"query-block"}'))
    images = [b.get('inserted', {}).get('image', {}) for b in qmp['return']]
    image = next(i for i in images if i.get('filename') == str(CHILD))
    require(image.get('backing-image', {}).get('filename') == str(PARENT), 'QMP immediate parent mismatch')
    image_chain = []
    chain_node = image
    while chain_node:
        image_chain.append(chain_node.get('filename'))
        chain_node = chain_node.get('backing-image')
    require(str(INITIAL_DISK) not in image_chain, 'Failed V8 child was accidentally reused in the retry child chain')
    parent_before = json.loads((HERE / 'frozen-parent-stat.json').read_text())
    parent_after = file_stat(PARENT)
    for key in ('Device', 'Inode', 'Bytes', 'MtimeNS', 'Mode'):
        require(parent_before[key] == parent_after[key], 'Frozen original disk changed: ' + key)
    require((parent_before['UID'], parent_before['GID']) in ((0, 0), (958, 958)) and
            (parent_after['UID'], parent_after['GID']) == (958, 958), 'Unexpected retained-parent ownership transition')
    nodes = json.loads(virsh('qemu-monitor-command', DOMAIN, '--pretty', '{"execute":"query-named-block-nodes"}'))
    formats = [n for n in nodes['return'] if n.get('file') == str(PARENT) and n.get('drv') == 'qcow2']
    require(len(formats) == 1 and formats[0].get('ro') is True, 'Retained qcow2 parent is not uniquely read-only')
    require(INITIAL_DISK.exists(), 'Failed V8 child was not retained')
    initial_shutoff = json.loads((HERE / 'failed-initial-shutoff-stat.json').read_text())
    require(file_stat(INITIAL_DISK) == initial_shutoff, 'Retained failed V8 child changed after clean shutdown')
    (HERE / 'verified-named-block-nodes.json').write_text(json.dumps(nodes, indent=2) + '\n')
    child_stat = file_stat(CHILD)
    require((child_stat['Mode'], child_stat['UID'], child_stat['GID']) == (0o600, 958, 958), 'Live child access changed')
    (HERE / 'post-qmp.json').write_text(json.dumps(qmp, indent=2) + '\n')
    (HERE / 'post-live.xml').write_text(ET.tostring(live, encoding='unicode'))
    nvram_path = Path(original.findtext('./os/nvram'))
    nvram_before_record = json.loads((HERE / 'nvram-prestart-stat.json').read_text())
    require(nvram_before_record.get('Path') == str(nvram_path), 'Shared NVRAM path differs from pre-start pin')
    nvram_after = file_stat(nvram_path)
    for key in ('Device', 'Inode', 'Bytes', 'Mode', 'UID', 'GID'):
        require(nvram_before_record['Stat'][key] == nvram_after[key], 'Shared NVRAM identity/access metadata changed: ' + key)
    readout = dict(UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(), UUID=PLAN['UUID'],
                   Parent=str(PARENT), Child=str(CHILD), RetainedFailedInitialDisk=str(INITIAL_DISK), RetainedFailedInitialDiskStat=initial_shutoff, ParentIdentitySizeMtimeModeUnchanged=True,
                   ParentStatBefore=parent_before, ParentStatAfter=parent_after,
                   ParentOwnershipTransition=('root:root to libvirt-qemu:libvirt-qemu' if parent_before['UID'] == 0 else 'libvirt-qemu ownership unchanged'),
                   ParentQcow2ReadOnly=True, ChildMode='0600',
                   ColdBootFromKeyBearingParent=True, FailedTrustBranchRetained=True, IndependentGuestBaselinePending=True,
                   CertificateOrTrustChanged=False, CheckpointScope='System disk and signing state; fresh sibling from the verified mint baseline',
                   FirmwareTpmRamCheckpointed=False, FullVmRollbackClaimed=False,
                   SharedNvramPath=str(nvram_path), SharedNvramMetadataBefore=nvram_before_record['Stat'], SharedNvramMetadataAfter=nvram_after, SharedNvramContentHashAvailable=False)
    (HERE / 'host-readout.json').write_text(json.dumps(readout, indent=2) + '\n')
    print(json.dumps(readout))
elif phase == 'restore-definition-before-start':
    require(virsh('domstate', DOMAIN).strip() == 'shut off', 'Refuse definition restoration on a live domain')
    require(disk(current).find('source').get('file') == str(CHILD), 'Refuse restoration from an unexpected disk')
    require((HERE / 'frozen-parent-stat.json').exists(), 'No frozen parent metadata')
    require(file_stat(PARENT) == json.loads((HERE / 'frozen-parent-stat.json').read_text()), 'Frozen parent changed')
    require(not (HERE / 'start.txt').exists(), 'Child has already been started; use fresh-child recovery instead')
    require(INITIAL_DISK.exists(), 'Retained failed V8 initial disk is missing; refuse definition restoration')
    failed_initial_stat_path = HERE / 'failed-initial-shutoff-stat.json'
    require(failed_initial_stat_path.exists(), 'No post-shutdown stat was captured for the retained failed V8 initial disk')
    failed_initial_stat = json.loads(failed_initial_stat_path.read_text())
    require(file_stat(INITIAL_DISK) == failed_initial_stat, 'Retained failed V8 initial disk identity/access metadata changed; refuse definition restoration')
    before = virsh('dumpxml', DOMAIN, '--inactive')
    (HERE / 'failed-defined-child.xml').write_text(before)
    source = HERE / 'domain-initial.xml'
    (HERE / 'restore-definition.txt').write_text(virsh('define', str(source), '--validate'))
    restored = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
    require(normalized(restored) == normalized(original) and
            disk(restored).find('source').get('file') == str(INITIAL_DISK), 'Restored failed V8 child definition mismatch')
    print('OriginalDefinitionRestored=True; DomainStillShutOff=True; ChildRetained=True')
else:
    raise SystemExit('Unknown checkpoint phase')
