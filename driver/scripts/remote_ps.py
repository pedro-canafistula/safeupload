#!/usr/bin/env python3
"""Run the PowerShell script read from stdin on a Windows VM over SSH.

Usage: python3 driver/scripts/remote_ps.py <host> < script.ps1

The host is a builder or the test VM (see debuggees.txt). Output and the exit
code of the remote script are passed through.
"""
import argparse
import base64
import os
import subprocess
import sys
import tempfile
import uuid

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("host")
# Accepted for compatibility with older callers; ignored.
parser.add_argument("--role", help=argparse.SUPPRESS)
parser.add_argument("--label", help=argparse.SUPPRESS)
args = parser.parse_args()

USER = os.environ.get("SAFEUPLOAD_SSH_USER", "vika")
SSH = ["-F", "/dev/null", "-i", os.path.expanduser("~/.ssh/id_ed25519"),
       "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR"]
PREFIX = "powershell.exe -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass "

script = sys.stdin.read().removeprefix("\ufeff")
if not script.strip():
    raise SystemExit("No PowerShell input")
script = "$global:ProgressPreference = 'SilentlyContinue'\n" + script


def encoded(text: str) -> str:
    return PREFIX + "-EncodedCommand " + base64.b64encode(text.encode("utf-16le")).decode()


command = encoded(script)
if len(command) > 7000:
    # cmd.exe caps a command line at 8191 characters: upload long scripts as a file instead.
    name = "remote_ps_" + uuid.uuid4().hex + ".ps1"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8-sig", suffix=".ps1", delete=False) as handle:
        handle.write(script)
        local = handle.name
    try:
        target = f"{USER}@{args.host}:C:/Users/{USER}/AppData/Local/Temp/{name}"
        if subprocess.call(["scp", *SSH, local, target]) != 0:
            raise SystemExit("Could not upload the script to the guest")
    finally:
        os.unlink(local)
    remote = f"C:\\Users\\{USER}\\AppData\\Local\\Temp\\{name}"
    command = encoded(
        f"$p='{remote}'; try {{ & powershell.exe -NoProfile -NonInteractive -OutputFormat Text "
        f"-ExecutionPolicy Bypass -File $p; $code = $LASTEXITCODE }} "
        f"finally {{ Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }}; exit $code")

raise SystemExit(subprocess.call(["ssh", *SSH, f"{USER}@{args.host}", command]))
