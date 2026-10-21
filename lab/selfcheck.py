#!/usr/bin/env python3
"""Offline CLI and real QEMU disk-conversion controls; creates no VM."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

LAB = Path(__file__).resolve().parent


def run(*args, expected=0):
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode != expected:
        raise AssertionError(f"{args}: exit={result.returncode}, expected={expected}\n{result.stdout}\n{result.stderr}")
    return result


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LabControls(unittest.TestCase):
    def test_missing_argument(self):
        self.assertIn('missing value for --iso', run('bash', str(LAB/'build-debuggee.sh'), '--iso', expected=2).stderr)

    def test_provider_seed_iso_and_hardware(self):
        with tempfile.TemporaryDirectory(prefix='safeupload seed ') as directory:
            root = Path(directory)
            (root/'user-data').write_text('{"hostname":"SU-LAB-TEST"}')
            (root/'meta-data').write_text('{}')
            (root/'network-config').write_text('')
            iso = root/'seed.iso'
            # Exact option spellings used by the pinned provider.
            run('bash', str(LAB/'bin/mkisofs'), '-output', str(iso), '-volid', 'cidata', '-joliet', '-rock',
                str(root/'user-data'), str(root/'meta-data'), str(root/'network-config'))
            run('7z', 'e', '-y', '-o'+str(root/'readback'), str(iso), 'user-data')
            self.assertEqual((root/'readback/user-data').read_bytes(), (root/'user-data').read_bytes())
            xml = root/'domain.xml'
            xml.write_text('<domain><vcpu>4</vcpu><cpu mode="host-passthrough"><topology sockets="4" cores="1" threads="1"/></cpu>'
                           '<devices><controller type="ide"/><disk type="file" device="cdrom"><readonly/>'
                           '<source file="/seed.iso"/><target dev="hdd" bus="ide"/>'
                           '<address type="drive" controller="0" bus="1" target="0" unit="1"/></disk>'
                           '<interface type="network"><model type="virtio"/></interface><video><model type="virtio"/></video></devices></domain>')
            transformed = ET.fromstring(run('xsltproc', str(LAB/'terraform/hardware.xsl'), str(xml)).stdout)
            self.assertEqual(transformed.find('cpu/topology').attrib, {'sockets':'1', 'cores':'4', 'threads':'1'})
            self.assertEqual(transformed.find('devices/interface/model').get('type'), 'e1000e')
            self.assertEqual(transformed.find('devices/video/model').get('type'), 'vga')
            self.assertIsNone(transformed.find("devices/controller[@type='ide']"))
            cdrom = transformed.find("devices/disk[@device='cdrom']")
            self.assertEqual(cdrom.find('target').attrib, {'dev':'sda', 'bus':'sata'})
            self.assertEqual(cdrom.find('source').get('file'), '/seed.iso')
            self.assertIsNotNone(cdrom.find('readonly'))
            self.assertIsNone(cdrom.find('address'))
            pool = root/'pool.xml'
            pool.write_text('<pool><name>su-lab-test</name><target><path>/private/test</path>'
                            '<permissions><mode>0711</mode><owner>0</owner><group>0</group></permissions></target></pool>')
            style = root/'pool.xsl'
            style.write_text((LAB/'terraform/pool.xsl').read_text().replace('${uid}','958').replace('${gid}','958'))
            transformed = ET.fromstring(run('xsltproc', str(style), str(pool)).stdout)
            self.assertEqual(transformed.findtext('target/path'), '/private/test')
            self.assertEqual(transformed.findtext('target/permissions/mode'), '0700')
            self.assertEqual(transformed.findtext('target/permissions/owner'), '958')
            self.assertEqual(transformed.findtext('target/permissions/group'), '958')
            self.assertEqual(len(transformed.findall('target/permissions')), 1)

    def test_conversion_and_refusals(self):
        with tempfile.TemporaryDirectory(prefix='safeupload lab ') as directory:
            root = Path(directory)
            source = root/'source.qcow2'
            run('qemu-img', 'create', '-f', 'qcow2', str(source), '16M')
            run('qemu-io', '-f', 'qcow2', '-c', 'write -P 0x5a 4096 8192', str(source))
            out = root/'export'
            exporter = str(LAB/'export-hyperv.sh')
            run('bash', exporter, str(source), '0'*64, str(out), expected=3)
            self.assertFalse(out.exists())
            run('bash', exporter, str(source), sha(source), str(out))
            disk = out/'safeupload-debuggee-19045.2965.vhdx'
            run('qemu-img', 'compare', '-f', 'qcow2', '-F', 'vhdx', str(source), str(disk))
            self.assertEqual((out/'image.sha256').read_text().split()[0], sha(disk))
            run('bash', exporter, str(source), sha(source), str(out), expected=4)
            overlay = root/'run-overlay.qcow2'
            run('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(source), str(overlay))
            run('bash', exporter, str(overlay), sha(overlay), str(root/'overlay-export'), expected=1)
            self.assertFalse((root/'overlay-export').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
