#!/usr/bin/env python3
"""Run stdin PowerShell on a recorded debuggee or a selected approved builder."""
import base64
import subprocess
import sys
import argparse

import pathlib
# Snapshotted tool copies (exact agent matrix) carry no debuggees.txt: then only the builder is reachable.
_list = pathlib.Path(__file__).resolve().parent / "debuggees.txt"
DEBUGGEES = {line.split()[1] for line in (_list.read_text().splitlines() if _list.is_file() else [])
             if line.strip() and not line.startswith("#")}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('host')
parser.add_argument('--role', choices=['kernel-sign', 'matrix', 'gate'])
parser.add_argument('--label')
args = parser.parse_args()
user = 'vika'
builder = None
# Preserve standalone debuggee snapshots: their transport needs only
# debuggees.txt. Builder snapshots must carry the approved-list dependencies.
SSH = ['-F', '/dev/null', '-i', '/home/victor/.ssh/id_ed25519',
       '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'LogLevel=ERROR',
       '-o', 'StrictHostKeyChecking=yes']
if args.host in DEBUGGEES:
    if args.role or args.label:
        parser.error('Builder arguments cannot target a debuggee')
else:
    from approved_builders import SSH, builders, select, identity_ps
    if args.host not in {row['host'] for row in builders()}:
        parser.error('Expected a recorded debuggee or the selected approved builder')
    if not args.role or not args.label:
        parser.error('Builder work requires --role and --label')
    builder = select(args.role, args.label)
    if args.host != builder['host']:
        parser.error('Host differs from selected approved builder')
    user = builder['ssh_user']
# A PowerShell source file may carry a UTF-8 BOM. Remove its leading marker
# before prepending our progress preference, so it cannot become an interior token.
script = sys.stdin.read().removeprefix("\ufeff")
if not script.strip():
    raise SystemExit("No PowerShell input")
script = "$global:ProgressPreference = 'SilentlyContinue'\n" + script
# Suppress module progress globally and request text when OpenSSH invokes a PowerShell shell,
# keeping serialized progress records from interleaving with stdout evidence.
PREFIX = "powershell.exe -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass "
if builder is not None:
    # Authenticate with known_hosts and check identity BEFORE even staging a long
    # script. This command reads identity only; no caller input is executed yet.
    preflight = PREFIX + '-EncodedCommand ' + base64.b64encode(identity_ps(builder).encode('utf-16le')).decode()
    checked = subprocess.run(['ssh', *SSH, user + '@' + args.host, preflight], capture_output=True)
    if checked.returncode:
        sys.stdout.buffer.write(checked.stdout)
        sys.stderr.buffer.write(checked.stderr)
        raise SystemExit('Builder identity/host-key preflight failed; no caller work performed')
    script = identity_ps(builder) + script
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
        if subprocess.call(["scp"] + SSH + [local, user + "@" + args.host + ":C:/Users/" + user + "/AppData/Local/Temp/" + name]) != 0:
            raise SystemExit("Could not stage the long script on the guest")
    finally:
        os.unlink(local)
    remote = "C:\\Users\\" + user + "\\AppData\\Local\\Temp\\" + name
    runner = ("$p='" + remote + "'; try { & powershell.exe -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass "
              "-File $p; $code = $LASTEXITCODE } finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }; exit $code")
    command = PREFIX + "-EncodedCommand " + base64.b64encode(runner.encode("utf-16le")).decode()
raise SystemExit(subprocess.call(["ssh"] + SSH + [user + "@" + args.host, command]))
