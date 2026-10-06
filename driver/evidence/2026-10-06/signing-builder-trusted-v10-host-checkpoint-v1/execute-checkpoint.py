"""Guarded trusted-V10 cold checkpoint; no key, certificate, trust, build, or signing operations."""
import copy
import datetime
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path('/home/victor/Work/safeupload-staging')
HERE = Path(__file__).resolve().parent
PLAN = json.loads((HERE / 'inputs.json').read_text(encoding='utf-8'))
EXECUTION_PINS = HERE / 'execution-pins.json'
DOMAIN = PLAN['Domain']
PARENT = Path(PLAN['Parent'])
INITIAL_DISK = Path(PLAN['InitialDisk'])
CHILD = Path(PLAN['Child'])
RETRY1 = Path(PLAN['ExcludedFailedRetryDisk'])
RECOVERY3 = Path(PLAN['ExpectedBackingParentOfParent'])


def require(condition, why):
    if not condition:
        raise RuntimeError(why)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_file(path, expected, why):
    path = Path(path)
    require(path.is_file(), 'Missing pinned input: ' + str(path))
    require(sha256(path).lower() == str(expected).lower(), why)


def verify_sha256_manifest(path, expected, expected_rows=None):
    path = Path(path)
    verify_file(path, expected, 'Pinned source manifest hash mismatch: ' + str(path))
    rows = []
    seen = set()
    for line in path.read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9A-Fa-f]{64})  (.+)', line)
        require(match is not None, 'Malformed source manifest row: ' + str(path))
        digest, rel = match.groups()
        require(rel not in seen, 'Duplicate source manifest path: ' + rel)
        seen.add(rel)
        rows.append((digest.lower(), rel))
    if expected_rows is not None:
        require(len(rows) == expected_rows, 'Unexpected source manifest row count: ' + str(path))
    for digest, rel in rows:
        verify_file(ROOT / rel, digest, 'Source manifest file drift: ' + rel)
    return rows


def virsh(*args):
    result = subprocess.run(['virsh', '-c', 'qemu:///system', *args],
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('virsh ' + ' '.join(args) + ' failed: ' + result.stderr)
    return result.stdout


def vda_disk(root):
    matches = []
    for item in root.findall('./devices/disk'):
        target = item.find('target')
        if target is not None and target.get('dev') == 'vda':
            matches.append(item)
    require(len(matches) == 1, 'Domain XML must contain exactly one vda disk')
    return matches[0]


def normalized_domain(root):
    normalized = copy.deepcopy(root)
    item = vda_disk(normalized)
    source = item.find('source')
    require(source is not None and source.get('file'), 'vda disk has no file source')
    source.set('file', 'PERMITTED_VDA_SOURCE')
    # libvirt may add a read-only informational backingStore node to a domain dump.
    for backing in list(item.findall('backingStore')):
        item.remove(backing)
    return ET.canonicalize(ET.tostring(normalized, encoding='unicode'), strip_text=True)


def disk_source(root):
    source = vda_disk(root).find('source')
    require(source is not None and source.get('file'), 'vda source path is missing')
    return source.get('file')


def file_stat(path):
    value = Path(path).stat()
    return dict(Device=value.st_dev, Inode=value.st_ino, Bytes=value.st_size,
                MtimeNS=value.st_mtime_ns, Mode=stat.S_IMODE(value.st_mode),
                UID=value.st_uid, GID=value.st_gid)


def stat_from_preflight(value):
    result = dict(value)
    mode = result.get('Mode')
    if isinstance(mode, str):
        result['Mode'] = int(mode, 8)
    return result


def qmp_json(command):
    return json.loads(virsh('qemu-monitor-command', DOMAIN, '--pretty', json.dumps(command)))


def image_chain(qmp, top_path):
    matches = []
    for item in qmp.get('return', []):
        image = item.get('inserted', {}).get('image', {})
        if image.get('filename') == str(top_path):
            matches.append(image)
    require(len(matches) == 1, 'QMP must contain exactly one image chain for ' + str(top_path))
    paths = []
    image = matches[0]
    while isinstance(image, dict):
        filename = image.get('filename')
        if filename:
            paths.append(filename)
        image = image.get('backing-image')
    return paths


def assert_parent_identity(stat_value, pinned_preflight):
    expected = stat_from_preflight(pinned_preflight)
    for field in ('Device', 'Inode', 'Mode', 'UID', 'GID'):
        require(stat_value[field] == expected[field], 'Healthy parent identity/access mismatch: ' + field)
    require(stat_value['Mode'] == 0o600 and stat_value['UID'] == 958 and stat_value['GID'] == 958,
            'Healthy parent must remain mode 0600 and libvirt-qemu owned')


def check_preflight():
    require(virsh('domuuid', DOMAIN).strip().lower() == PLAN['UUID'].lower(), 'Wrong builder UUID')
    state = virsh('domstate', DOMAIN).strip()
    require(state == 'running', 'Builder is not running for fresh host preflight')
    original = ET.fromstring((HERE / PLAN['DomainXml']['Initial']).read_bytes())
    expected_child = ET.fromstring((HERE / PLAN['DomainXml']['Child']).read_bytes())
    require(disk_source(original) == str(INITIAL_DISK), 'Pinned initial XML does not use the healthy retry2 parent')
    require(disk_source(expected_child) == str(CHILD), 'Pinned child XML does not use the trusted-V10 child')
    require(normalized_domain(expected_child) == normalized_domain(original),
            'Prepared domain XML changes settings outside the vda source and libvirt backing metadata')

    inactive = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
    live = ET.fromstring(virsh('dumpxml', DOMAIN))
    require(normalized_domain(inactive) == normalized_domain(original), 'Persistent domain definition differs from pinned preflight XML')
    require(normalized_domain(live) == normalized_domain(original), 'Live domain configuration differs from pinned preflight XML')
    require(disk_source(inactive) == str(PARENT) and disk_source(live) == str(PARENT),
            'Live/inactive vda must still use the healthy retry2 parent')
    require(not CHILD.exists(), 'Trusted-V10 child already exists; refuse checkpoint')
    require(RETRY1.exists(), 'Retained failed retry1 disk is missing; refuse lineage change')

    pinned_parent = PLAN['HostPreflight']['CurrentParentIdentity']
    current_parent_stat = file_stat(PARENT)
    assert_parent_identity(current_parent_stat, pinned_parent)
    require(Path(PARENT).resolve() == Path(INITIAL_DISK).resolve(), 'Initial disk and immediate parent differ')

    job_info = virsh('domjobinfo', DOMAIN)
    require('None' in job_info, 'Builder has an active domain job')
    block_job = virsh('blockjob', DOMAIN, 'vda', '--info')
    require('No current block job' in block_job, 'Builder has an active vda block job')

    chain_qmp = qmp_json({'execute': 'query-block'})
    chain = image_chain(chain_qmp, PARENT)
    require(len(chain) >= 2 and chain[0] == str(PARENT) and chain[1] == str(RECOVERY3),
            'Healthy retry2 parent does not have the pinned Recovery3 immediate backing chain')
    require(str(RETRY1) not in chain, 'Failed retry1 disk is present in the live backing chain')

    other_domains = []
    for name in virsh('list', '--all', '--name').splitlines():
        name = name.strip()
        if not name or name == DOMAIN:
            continue
        other = ET.fromstring(virsh('dumpxml', name))
        for source in other.findall('./devices/disk/source'):
            if source.get('file') == str(PARENT):
                raise RuntimeError('Healthy retry2 parent is attached to another domain: ' + name)
        other_domains.append(name)

    return dict(UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                UUID=PLAN['UUID'], Domain=DOMAIN, State=state,
                LiveAndInactiveDiskSource=str(PARENT), Child=str(CHILD), ChildAbsent=True,
                ParentStat=current_parent_stat, ParentMode='0600', ParentOwnerUid=958,
                ParentGroupGid=958, BackingChain=chain,
                FailedRetry1ExcludedFromBackingChain=True, Retry1StillRetained=RETRY1.exists(),
                NoDomainJob=('None' in job_info), NoVdaBlockJob=('No current block job' in block_job),
                OtherDomainsInspected=other_domains, StateMutation=False,
                FirmwareTpmRamCheckpointed=False, SharedNvramCheckpointed=False,
                FullVmRollbackClaimed=False)


def require_frozen_parent_unchanged(before):
    after = file_stat(PARENT)
    require(after == before, 'Healthy retry2 parent stat changed; preserve and stop')
    require(after['Mode'] == 0o600 and after['UID'] == 958 and after['GID'] == 958,
            'Healthy retry2 parent mode/ownership changed; preserve and stop')
    return after


require(len(sys.argv) == 3, 'Phase and expected execution-manifest SHA-256 are required')
phase = sys.argv[1]
allowed_phases = {'preflight', 'shutdown', 'create-start', 'verify-host', 'restore-definition-before-start'}
require(phase in allowed_phases, 'Unknown or unsupported host checkpoint phase')
require(PLAN.get('ReadyForExecution') is True, 'Trusted-V10 host package is pending review; refuse before any libvirt command')
require(PLAN.get('FirmwareTpmRamCheckpointed') is False and PLAN.get('SharedNvramCheckpointed') is False and
        PLAN.get('FullVmRollbackClaimed') is False, 'Package must remain scoped to the system disk and signing state')
require(hashlib.sha256(EXECUTION_PINS.read_bytes()).hexdigest().lower() == sys.argv[2].lower(),
        'Execution manifest drift')
for name, pin in json.loads(EXECUTION_PINS.read_text(encoding='utf-8')).items():
    verify_file(ROOT / name, pin, 'Local checkpoint package drift: ' + name)

for name, pin in PLAN['InputPins'].items():
    verify_file(ROOT / name, pin, 'Checkpoint input drift: ' + name)

v10 = PLAN['TrustedV10Baseline']
v10_manifest = ROOT / v10['V10SourceManifestPath']
verify_sha256_manifest(v10_manifest, v10['V10SourceManifestSha256'])
require(sha256(ROOT / v10['V10PlanPath']).lower() == v10['V10PlanSha256'].lower(), 'Frozen V10 plan hash mismatch')
frozen_v10_plan = json.loads((ROOT / v10['V10PlanPath']).read_text(encoding='utf-8'))
frozen_disk = frozen_v10_plan.get('DiskScope', {})
require(frozen_v10_plan.get('VM', {}).get('UUID', '').lower() == PLAN['UUID'].lower(), 'Frozen V10 plan UUID mismatch')
require(frozen_disk.get('Parent') == str(PARENT) and frozen_disk.get('Child') == str(CHILD) and
        frozen_disk.get('ExpectedBackingParentOfParent') == str(RECOVERY3) and
        frozen_disk.get('ExcludedFailedRetryDisk') == str(RETRY1), 'Trusted-V10 disk paths differ from the frozen V10 plan')
require(frozen_disk.get('ExpectedChildMode') == '0600' and frozen_disk.get('ExpectedChildOwnerUid') == 958 and
        frozen_disk.get('ExpectedChildGroupGid') == 958 and frozen_disk.get('ParentMustRemainReadOnlyInQmp') is True and
        frozen_disk.get('AllowedPersistentDomainDelta') == 'Only vda source path may change to the fresh child.',
        'Trusted-V10 permissions, parent-read-only, or domain-delta requirements differ from the frozen V10 plan')
require(frozen_disk.get('FirmwareTpmRamCheckpointed') is False and frozen_disk.get('SharedNvramCheckpointed') is False and
        frozen_disk.get('FullVmRollbackClaimed') is False, 'Frozen V10 scope makes a prohibited full-VM checkpoint claim')
v13 = PLAN['TrustedV10Baseline']
v13_manifest = ROOT / v13['V13SourceManifestPath']
verify_sha256_manifest(v13_manifest, v13['V13SourceManifestSha256'], expected_rows=42)
require(sha256(ROOT / v13['V13BaselinePath']).lower() == v13['V13BaselineSha256'].lower(), 'V13 baseline source hash mismatch')

precheck_path = ROOT / v13['V13ReadoutPath']
precheck = json.loads(precheck_path.read_text(encoding='utf-8'))
require(precheck.get('Verdict') == 'V13_TRUSTED_SIGNER_PRECHECKPOINT_BASELINE_ACTUAL_PASS', 'V13 read-only precheckpoint baseline did not pass')
require(precheck.get('SourceSHA256', '').lower() == v13['V13BaselineSha256'].lower() and
        precheck.get('SourceManifestSHA256', '').lower() == v13['V13SourceManifestSha256'].lower(),
        'V13 baseline/source-manifest readout pins differ')
for field in ('PS51ParseActualRemoteExitCode', 'InventoryFixtureActualRemoteExitCode', 'BaselineActualRemoteExitCode'):
    require(precheck.get(field) == 0, 'V13 run did not exit zero: ' + field)
for field in ('ExactSixCurrentStoresMatchReviewedV10Trust', 'DetailedAclMatchesMintAndTrust',
              'OriginalFilesAndCertificateRetained', 'SignedArtifactValidExactSigner',
              'TestSigningNo', 'NoBuildActors'):
    require(precheck.get(field) is True, 'V13 precheckpoint assertion failed: ' + field)
for field in ('HostMutationAttempted', 'PrivateKeyExported', 'TrustChanged'):
    require(precheck.get(field) is False, 'V13 baseline unexpectedly changed state: ' + field)
require('EvidencePins' in precheck and isinstance(precheck['EvidencePins'], dict), 'V13 readout evidence pins missing')
for rel, pin in precheck['EvidencePins'].items():
    verify_file(ROOT / rel, pin, 'V13 actual-run evidence drift: ' + rel)
fixture_stdout = ROOT / 'driver/evidence/2026-10-06/signing-builder-trusted-v13-execution/fixture.stdout.txt'
require(fixture_stdout.read_text(encoding='utf-8-sig').strip() == v13['V13FixtureMarker'], 'V13 fixture marker mismatch')
fixture_stderr = ROOT / 'driver/evidence/2026-10-06/signing-builder-trusted-v13-execution/fixture.stderr.txt'
require(fixture_stderr.read_bytes() == b'', 'V13 fixture emitted error output')

host_preflight = PLAN['HostPreflight']
host_readout = json.loads((ROOT / host_preflight['ReadoutPath']).read_text(encoding='utf-8'))
require(host_readout.get('Verdict') == 'LIVE_HEALTHY_TRUSTED_SIGNER_HOST_PREFLIGHT_PASS', 'Pinned host preflight is not the approved trusted-signer preflight')
require(host_readout.get('UUID', '').lower() == PLAN['UUID'].lower(), 'Pinned host preflight UUID mismatch')
require(host_readout.get('LiveAndInactiveDiskSource') == str(PARENT) and host_readout.get('Child') == str(CHILD),
        'Pinned host preflight source/child paths differ')
require(host_readout.get('ChildAbsent') is True and host_readout.get('NoDomainJob') is True and
        host_readout.get('FailedRetry1ExcludedFromBackingChain') is True and host_readout.get('StateMutation') is False,
        'Pinned host preflight state is not clean')
retry = PLAN['CurrentHealthyParentLineage']
retry_host = json.loads((ROOT / retry['HostReadoutPath']).read_text(encoding='utf-8'))
retry_guest = json.loads((ROOT / retry['GuestBaselinePath']).read_text(encoding='utf-8'))
require(retry_host.get('UUID', '').lower() == PLAN['UUID'].lower() and retry_host.get('Child') == str(PARENT) and
        retry_host.get('Parent') == str(RECOVERY3) and retry_host.get('ParentQcow2ReadOnly') is True and
        retry_host.get('CertificateOrTrustChanged') is False and retry_host.get('FailedTrustBranchRetained') is True,
        'Pinned retry2 host lineage evidence mismatch')
require(retry_guest.get('Verdict') == 'KEY_BEARING_COLD_BASELINE_VERIFIED_TWICE' and
        retry_guest.get('SixActualStoresExactlyMintEvidence') is True and retry_guest.get('TrustImported') is False and
        retry_guest.get('PrivateKeyExported') is False, 'Pinned retry2 guest lineage evidence mismatch')

captured_qmp_path = ROOT / 'driver/evidence/2026-10-06/signing-builder-trusted-v10-host-preflight-v2/query-block.json'
captured_chain = image_chain(json.loads(captured_qmp_path.read_text(encoding='utf-8')), PARENT)
require(len(captured_chain) >= 2 and captured_chain[0] == str(PARENT) and captured_chain[1] == str(RECOVERY3) and
        str(RETRY1) not in captured_chain, 'Captured host preflight QMP chain does not prove healthy retry2 lineage excluding retry1')

# Verify the prepared XML pair is an exact vda source-only edit before any libvirt call.
original_xml_bytes = (HERE / PLAN['DomainXml']['Initial']).read_bytes()
child_xml_bytes = (HERE / PLAN['DomainXml']['Child']).read_bytes()
original_xml_text = original_xml_bytes.decode('utf-8')
child_xml_text = child_xml_bytes.decode('utf-8')
require(original_xml_text.count(str(PARENT)) == 1 and
        original_xml_text.replace(str(PARENT), str(CHILD), 1) == child_xml_text,
        'Prepared child domain XML is not an exact single vda source-path edit')
original_xml = ET.fromstring(original_xml_bytes)
child_xml = ET.fromstring(child_xml_bytes)
require(disk_source(original_xml) == str(PARENT) and disk_source(child_xml) == str(CHILD),
        'Prepared domain XML vda source paths mismatch')
require(normalized_domain(original_xml) == normalized_domain(child_xml), 'Prepared domain XML changes unrelated configuration')
volume_xml = ET.fromstring((HERE / PLAN['VolumeXml']).read_bytes())
require(volume_xml.findtext('./target/path') == str(CHILD) and volume_xml.findtext('./name') == CHILD.name,
        'Prepared volume XML name/path mismatch')
require(volume_xml.findtext('./backingStore/path') == str(PARENT) and
        volume_xml.find('./target/format').get('type') == 'qcow2', 'Prepared volume XML backing/format mismatch')
require(volume_xml.findtext('./target/permissions/mode') == '0600' and
        volume_xml.findtext('./target/permissions/owner') == '958' and
        volume_xml.findtext('./target/permissions/group') == '958', 'Prepared volume permissions are not restricted to 0600/958:958')

# All file, baseline, manifest, lineage, and XML guards precede the first libvirt command.
require(virsh('domuuid', DOMAIN).strip().lower() == PLAN['UUID'].lower(), 'Wrong builder UUID')
current = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
require(normalized_domain(current) == normalized_domain(original_xml), 'Persistent domain configuration differs from pinned V10 preflight XML')

if phase == 'preflight':
    readout = check_preflight()
    (HERE / 'preflight-readout.json').write_text(json.dumps(readout, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(readout))
elif phase == 'shutdown':
    readout = check_preflight()
    (HERE / 'shutdown-preflight-readout.json').write_text(json.dumps(readout, indent=2) + '\n', encoding='utf-8')
    (HERE / 'shutdown-command.txt').write_text(virsh('shutdown', DOMAIN), encoding='utf-8')
    print('GracefulShutdownRequested=True; CheckpointChildNotCreated=True')
elif phase == 'create-start':
    require(virsh('domstate', DOMAIN).strip() == 'shut off', 'Builder has not completed graceful shutdown')
    current = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
    require(normalized_domain(current) == normalized_domain(original_xml) and disk_source(current) == str(PARENT),
            'Persistent definition changed before child creation')
    require(not CHILD.exists(), 'Trusted-V10 child already exists')
    frozen_parent = file_stat(PARENT)
    assert_parent_identity(frozen_parent, PLAN['HostPreflight']['CurrentParentIdentity'])
    (HERE / 'frozen-parent-stat.json').write_text(json.dumps(frozen_parent, indent=2) + '\n', encoding='utf-8')
    (HERE / 'volume-create.txt').write_text(virsh('vol-create', 'default', str(HERE / PLAN['VolumeXml'])), encoding='utf-8')
    require(CHILD.exists(), 'New trusted-V10 qcow2 child is missing')
    child_stat = file_stat(CHILD)
    require((child_stat['Mode'], child_stat['UID'], child_stat['GID']) == (0o600, 958, 958),
            'New trusted-V10 child permissions differ from 0600:958:958')
    volume = ET.fromstring(virsh('vol-dumpxml', str(CHILD), '--pool', 'default'))
    require(volume.findtext('./backingStore/path') == str(PARENT), 'New child immediate backing parent mismatch')
    require(volume.find('./target/format').get('type') == 'qcow2', 'New child format mismatch')
    require(volume.findtext('./target/permissions/mode') == '0600' and
            volume.findtext('./target/permissions/owner') == '958' and
            volume.findtext('./target/permissions/group') == '958', 'Volume permission readback mismatch')
    (HERE / 'volume-readback.xml').write_text(ET.tostring(volume, encoding='unicode'), encoding='utf-8')
    (HERE / 'define.txt').write_text(virsh('define', str(HERE / PLAN['DomainXml']['Child']), '--validate'), encoding='utf-8')
    defined = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
    require(normalized_domain(defined) == normalized_domain(original_xml), 'Unrelated persistent domain configuration changed')
    require(disk_source(defined) == str(CHILD), 'Persistent vda child mismatch')
    require_frozen_parent_unchanged(frozen_parent)
    (HERE / 'start.txt').write_text(virsh('start', DOMAIN), encoding='utf-8')
    print('TrustedV10ColdChildStarted=True; HostVerificationPending=True; GuestReadOnlyBaselinePending=True')
elif phase == 'verify-host':
    require(virsh('domstate', DOMAIN).strip() == 'running', 'Builder is not running')
    persistent = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
    live = ET.fromstring(virsh('dumpxml', DOMAIN))
    require(normalized_domain(persistent) == normalized_domain(original_xml) and
            normalized_domain(live) == normalized_domain(original_xml), 'Unrelated domain configuration changed')
    require(disk_source(persistent) == str(CHILD) and disk_source(live) == str(CHILD), 'Live/inactive vda child mismatch')
    qmp = qmp_json({'execute': 'query-block'})
    chain = image_chain(qmp, CHILD)
    require(len(chain) >= 2 and chain[0] == str(CHILD) and chain[1] == str(PARENT),
            'QMP child chain does not use retry2 as immediate parent')
    require(str(RETRY1) not in chain, 'Failed retry1 disk is present in the trusted child backing chain')
    parent_before = json.loads((HERE / 'frozen-parent-stat.json').read_text(encoding='utf-8'))
    parent_after = file_stat(PARENT)
    require(parent_before == parent_after, 'Healthy retry2 parent stat changed across child cold boot; preserve and stop')
    require(parent_after['Mode'] == 0o600 and parent_after['UID'] == 958 and parent_after['GID'] == 958,
            'Healthy retry2 parent permissions/ownership changed')
    named = qmp_json({'execute': 'query-named-block-nodes'})
    parent_nodes = [node for node in named.get('return', [])
                    if node.get('file') == str(PARENT) and node.get('drv') == 'qcow2']
    require(len(parent_nodes) == 1 and parent_nodes[0].get('ro') is True,
            'Healthy retry2 qcow2 parent is not uniquely read-only in QMP')
    child_stat = file_stat(CHILD)
    require((child_stat['Mode'], child_stat['UID'], child_stat['GID']) == (0o600, 958, 958),
            'Trusted-V10 child permissions changed')
    (HERE / 'verified-named-block-nodes.json').write_text(json.dumps(named, indent=2) + '\n', encoding='utf-8')
    (HERE / 'post-qmp.json').write_text(json.dumps(qmp, indent=2) + '\n', encoding='utf-8')
    (HERE / 'post-live.xml').write_text(ET.tostring(live, encoding='unicode'), encoding='utf-8')
    readout = dict(UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(), UUID=PLAN['UUID'],
                   Parent=str(PARENT), Child=str(CHILD), ParentStatBefore=parent_before,
                   ParentStatAfter=parent_after, ParentIdentitySizeMtimeModeOwnershipUnchanged=True,
                   ParentQcow2ReadOnly=True, ChildMode='0600', ChildOwnerUid=958, ChildGroupGid=958,
                   BackingChain=chain, FailedRetry1ExcludedFromBackingChain=True,
                   ColdBootFromHealthyRetry2Parent=True, GuestReadOnlyBaselinePending=True,
                   CertificateOrTrustChanged=False, PrivateKeyExported=False, BuildOrSignAttempted=False,
                   CheckpointScope=PLAN['CheckpointScope'], FirmwareTpmRamCheckpointed=False,
                   SharedNvramCheckpointed=False, FullVmRollbackClaimed=False)
    (HERE / 'host-readout.json').write_text(json.dumps(readout, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(readout))
elif phase == 'restore-definition-before-start':
    require(virsh('domstate', DOMAIN).strip() == 'shut off', 'Refuse definition restoration on a live domain')
    current = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
    require(disk_source(current) == str(CHILD), 'Refuse restoration from an unexpected disk')
    require((HERE / 'frozen-parent-stat.json').is_file(), 'No frozen healthy-parent stat')
    frozen_parent = json.loads((HERE / 'frozen-parent-stat.json').read_text(encoding='utf-8'))
    require_frozen_parent_unchanged(frozen_parent)
    require(not (HERE / 'start.txt').exists(), 'Child has been started; this pre-start restore phase is unavailable')
    (HERE / 'failed-defined-child.xml').write_text(virsh('dumpxml', DOMAIN, '--inactive'), encoding='utf-8')
    (HERE / 'restore-definition.txt').write_text(virsh('define', str(HERE / PLAN['DomainXml']['Initial']), '--validate'), encoding='utf-8')
    restored = ET.fromstring(virsh('dumpxml', DOMAIN, '--inactive'))
    require(normalized_domain(restored) == normalized_domain(original_xml) and disk_source(restored) == str(PARENT),
            'Restored persistent definition mismatch')
    print('OriginalRetry2DefinitionRestored=True; DomainStillShutOff=True; ChildRetained=True; ParentUnchanged=True')
