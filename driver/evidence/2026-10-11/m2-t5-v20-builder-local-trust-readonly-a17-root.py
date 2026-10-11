import datetime
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import libvirt

expected_uuid = 'c6440689-d11c-4c63-a463-f3722b7ddb69'
expected_mac = '52:54:00:63:87:7a'
expected_ip = '192.168.122.210'
output = Path('/home/victor/Work/safeupload-staging/driver/evidence/2026-10-11/m2-t5-v20-builder-local-trust-readonly-a17-root.json')
assert not output.exists()
connection = libvirt.openReadOnly('qemu:///system')
try:
    domain = connection.lookupByUUIDString(expected_uuid)
    assert domain.UUIDString().lower() == expected_uuid and domain.name() == 'win10'
    state_before = domain.state(0)
    assert state_before[0] == libvirt.VIR_DOMAIN_RUNNING
    first = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
    xml = ET.fromstring(first)
    interfaces = [node for node in xml.findall('./devices/interface')
                  if node.find('mac') is not None and
                  node.find('mac').get('address', '').lower() == expected_mac]
    assert len(interfaces) == 1 and interfaces[0].get('type') == 'network'
    network_name = interfaces[0].find('source').get('network')
    assert network_name == 'default'
    network = connection.networkLookupByName(network_name)
    network_before = network.XMLDesc(0)
    network_xml = ET.fromstring(network_before)
    assert network_xml.find('bridge').get('name') == 'virbr0'
    assert network_xml.find('forward').get('mode') == 'nat'
    assert len([node for node in network_xml.findall('ip')
                if node.get('address') == '192.168.122.1']) == 1
    leases = network.DHCPLeases(expected_mac, 0)
    assert len([lease for lease in leases
                if lease.get('mac', '').lower() == expected_mac and
                lease.get('ipaddr') == expected_ip]) == 1
    second = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
    state_after = domain.state(0)
    assert first == second and state_before == state_after
    assert network_before == network.XMLDesc(0)
    record = {
        'CapturedUTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'ReadOnlyConnection': 'qemu:///system',
        'BuilderDomainName': domain.name(), 'BuilderUUID': expected_uuid,
        'BuilderState': list(state_after), 'ExactBuilderMAC': expected_mac,
        'ExactBuilderIP': expected_ip, 'LibvirtNetwork': network_name,
        'NetworkBridge': 'virbr0', 'NetworkForwardMode': 'nat',
        'HostLocalVirtualMachine': True,
        'LeaseMapsExactBuilderMACToSourceDeliveryIP': True,
        'TwoInactiveXMLReadsAndStateEqual': True,
        'TwoNetworkXMLReadsEqual': True,
        'InactiveXMLSHA256': hashlib.sha256(first.encode()).hexdigest(),
        'NetworkXMLSHA256': hashlib.sha256(network_before.encode()).hexdigest(),
        'SourceUploaded': False, 'VMStartedOrChanged': False,
        'DriverInstalledOrLoaded': False, 'GitMutation': False
    }
    with output.open('x') as handle:
        json.dump(record, handle, indent=2)
        handle.write('\n')
    print(json.dumps(record))
finally:
    connection.close()
