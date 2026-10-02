#!/usr/bin/env python3
"""Run a stdin PowerShell script on the two recorded disposable test VMs."""
import base64
import subprocess
import sys

if len(sys.argv) != 2 or sys.argv[1] not in {"192.168.122.51", "192.168.122.210"}:
    raise SystemExit("Expected the recorded SafeUpload debuggee or builder address")
script = sys.stdin.read()
if not script.strip():
    raise SystemExit("No PowerShell input")
command = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + base64.b64encode(script.encode("utf-16le")).decode()
raise SystemExit(subprocess.call([
    "ssh", "-F", "/dev/null", "-i", "/home/victor/.ssh/id_ed25519",
    "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR", "-o", "StrictHostKeyChecking=accept-new",
    "vika@" + sys.argv[1], command]))
