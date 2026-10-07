#!/usr/bin/env python3
"""Run a stdin PowerShell script on the two recorded disposable test VMs."""
import base64
import subprocess
import sys

import pathlib
# Snapshotted tool copies (exact agent matrix) carry no debuggees.txt: then only the builder is reachable.
_list = pathlib.Path(__file__).resolve().parent / "debuggees.txt"
DEBUGGEES = {line.split()[1] for line in (_list.read_text().splitlines() if _list.is_file() else [])
             if line.strip() and not line.startswith("#")}
if len(sys.argv) != 2 or sys.argv[1] not in DEBUGGEES | {"192.168.122.210"}:
    raise SystemExit("Expected a recorded SafeUpload debuggee (debuggees.txt) or the builder address")
# A PowerShell source file may carry a UTF-8 BOM. Remove its leading marker
# before prepending our progress preference, so it cannot become an interior token.
script = sys.stdin.read().removeprefix("\ufeff")
if not script.strip():
    raise SystemExit("No PowerShell input")
script = "$global:ProgressPreference = 'SilentlyContinue'\n" + script
# Suppress module progress globally and request text when OpenSSH invokes a PowerShell shell,
# keeping serialized progress records from interleaving with stdout evidence.
SSH = ["-F", "/dev/null", "-i", "/home/victor/.ssh/id_ed25519",
       "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR", "-o", "StrictHostKeyChecking=yes"]
PREFIX = "powershell.exe -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass "
command = PREFIX + "-EncodedCommand " + base64.b64encode(script.encode("utf-16le")).decode()
if len(command) > 7000:
    # Windows OpenSSH runs the command through cmd.exe, which caps a command line at 8,191 characters, and -EncodedCommand
    # inflates the script ~2.7x ("The command line is too long": S00 attempt 2, the guest cleanup script). Larger scripts go up as a UTF-8 BOM file (PowerShell 5.1 reads
    # BOM-less files as ANSI), run with -File, and are removed; the script's exit code is passed through.
    import os, tempfile, uuid
    name = "remote_ps_" + uuid.uuid4().hex + ".ps1"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8-sig", suffix=".ps1", delete=False) as handle:
        handle.write(script)
        local = handle.name
    try:
        if subprocess.call(["scp"] + SSH + [local, "vika@" + sys.argv[1] + ":C:/Users/vika/AppData/Local/Temp/" + name]) != 0:
            raise SystemExit("Could not stage the long script on the guest")
    finally:
        os.unlink(local)
    remote = "C:\\Users\\vika\\AppData\\Local\\Temp\\" + name
    runner = ("$p='" + remote + "'; try { & powershell.exe -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass "
              "-File $p; $code = $LASTEXITCODE } finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }; exit $code")
    command = PREFIX + "-EncodedCommand " + base64.b64encode(runner.encode("utf-16le")).decode()
raise SystemExit(subprocess.call(["ssh"] + SSH + ["vika@" + sys.argv[1], command]))
