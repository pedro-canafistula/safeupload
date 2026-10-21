#!/usr/bin/env python3
"""Read the daemon's QEMU DAC identity without changing host configuration."""
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

query = json.load(sys.stdin)
result = subprocess.run(
    ["virsh", "-c", query["uri"], "capabilities"],
    text=True, capture_output=True, check=True, timeout=30,
)
root = ET.fromstring(result.stdout)
for model in root.findall("./host/secmodel"):
    if model.findtext("model") != "dac":
        continue
    label = model.find("baselabel[@type='kvm']")
    match = re.fullmatch(r"\+?(\d+):\+?(\d+)", (label.text or "").strip()) if label is not None else None
    if match:
        print(json.dumps(dict(uid=match[1], gid=match[2])))
        break
else:
    sys.exit("Libvirt must advertise the QEMU kvm DAC uid/gid to create a private seed pool.")
