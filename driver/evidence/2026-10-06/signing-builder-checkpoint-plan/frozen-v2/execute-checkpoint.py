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
require(hashlib.sha256(EXECUTION_PINS.read_bytes()).hexdigest() == sys.argv[2], 'Execution manifest drift')
for name, pin in json.loads(EXECUTION_PINS.read_text()).items():
    require(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == pin, 'Execution source drift')

for name, pin in PLAN['InputPins'].items():
    require(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == pin, 'Checkpoint input drift')
require(virsh('domuuid', DOMAIN).strip() == PLAN['UUID'], 'Wrong builder UUID')
original = ET.fromstring((ROOT / 'driver/evidence/2026-10-06/signing-builder-checkpoint-preflight-domain-inactive.xml').read_bytes())
current = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
require(normalized(current) == normalized(original), 'Unrelated persistent domain configuration changed')
phase = sys.argv[1]

if phase == 'shutdown':
    require(virsh('domstate', DOMAIN).strip() == 'running', 'Builder is not running')
    require(disk(current).find('source').get('file') == str(PARENT), 'Unexpected original disk')
    require(not CHILD.exists(), 'Child already exists')
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
    require(disk(current).find('source').get('file') == str(PARENT), 'Original disk changed')
    require(not CHILD.exists(), 'Child already exists')
    # domjobinfo is only valid on a running domain. Confirmed shutoff above
    # excludes live domain/block jobs; do not treat that API error as a job.
    parent_stat = file_stat(PARENT)
    require(parent_stat['Mode'] == 0o600, 'Original disk access is not restricted')
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
    require(file_stat(PARENT) == json.loads((HERE / 'frozen-parent-stat.json').read_text()), 'Frozen original disk changed')
    child_stat = file_stat(CHILD)
    require((child_stat['Mode'], child_stat['UID'], child_stat['GID']) == (0o600, 958, 958), 'Live child access changed')
    (HERE / 'post-qmp.json').write_text(json.dumps(qmp, indent=2) + '\n')
    (HERE / 'post-live.xml').write_text(ET.tostring(live, encoding='unicode'))
    readout = dict(UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(), UUID=PLAN['UUID'],
                   Parent=str(PARENT), Child=str(CHILD), ParentUnchanged=True, ChildMode='0600',
                   ColdBootFromOriginalParent=True, IndependentGuestBaselinePending=True,
                   CertificateOrTrustChanged=False, CheckpointScope='System disk and signing state',
                   FirmwareTpmRamCheckpointed=False, FullVmRollbackClaimed=False,
                   SharedNvramMetadata=file_stat(Path(original.findtext('./os/nvram'))))
    (HERE / 'host-readout.json').write_text(json.dumps(readout, indent=2) + '\n')
    print(json.dumps(readout))
elif phase == 'restore-definition-before-start':
    require(virsh('domstate', DOMAIN).strip() == 'shut off', 'Refuse definition restoration on a live domain')
    require(disk(current).find('source').get('file') == str(CHILD), 'Refuse restoration from an unexpected disk')
    require((HERE / 'frozen-parent-stat.json').exists(), 'No frozen parent metadata')
    require(file_stat(PARENT) == json.loads((HERE / 'frozen-parent-stat.json').read_text()), 'Frozen parent changed')
    require(not (HERE / 'start.txt').exists(), 'Child has already been started; use fresh-child recovery instead')
    before = virsh('dumpxml', DOMAIN, '--inactive')
    (HERE / 'failed-defined-child.xml').write_text(before)
    source = ROOT / 'driver/evidence/2026-10-06/signing-builder-checkpoint-preflight-domain-inactive.xml'
    (HERE / 'restore-definition.txt').write_text(virsh('define', str(source), '--validate'))
    restored = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
    require(normalized(restored) == normalized(original) and
            disk(restored).find('source').get('file') == str(PARENT), 'Restored definition mismatch')
    print('OriginalDefinitionRestored=True; DomainStillShutOff=True; ChildRetained=True')
else:
    raise SystemExit('Unknown checkpoint phase')
