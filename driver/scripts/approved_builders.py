#!/usr/bin/env python3
"""Approved lab builder selection. No network or automatic parity promotion."""
import argparse
import json
import os
from pathlib import Path
import re

CONFIG = Path(__file__).with_name('approved-builders.json')
SSH = ['-F', '/dev/null', '-i', '/home/victor/.ssh/id_ed25519',
       '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'LogLevel=ERROR',
       '-o', 'StrictHostKeyChecking=yes']  # Uses the owner's existing known_hosts.


def builders():
    rows = json.loads(CONFIG.read_text(encoding='utf-8'))['builders']
    names, hosts = set(), set()
    for row in rows:
        for field, pattern in [('name', r'[A-Za-z0-9_-]+'), ('host', r'[0-9.]+'),
                               ('computer_name', r'[A-Za-z0-9-]+'), ('ssh_user', r'[A-Za-z0-9_-]+')]:
            if not isinstance(row.get(field), str) or not re.fullmatch(pattern, row[field]):
                raise ValueError('Invalid approved builder ' + field)
        if (row['name'] in names or row['host'] in hosts
                or type(row.get('gate_approved')) is not bool
                or not isinstance(row.get('roles'), list)
                or not row['roles'] or set(row['roles']) - {'kernel-sign', 'matrix', 'gate'}):
            raise ValueError('Invalid or duplicate approved builder')
        for field, pattern in [('uuid', r'[A-Fa-f0-9-]{36}'), ('mac', r'[A-Fa-f0-9-]{17}')]:
            if field in row and not re.fullmatch(pattern, row[field]):
                raise ValueError('Invalid builder ' + field)
        names.add(row['name'])
        hosts.add(row['host'])
    return rows


def select(role, label, name=None):
    name = os.environ.get('SAFEUPLOAD_BUILDER', 'builder1') if name is None else name
    matches = [row for row in builders() if row['name'] == name]
    if len(matches) != 1:
        raise ValueError('Unknown approved builder: ' + name)
    row = matches[0]
    if role not in row['roles']:
        raise ValueError('Builder lacks role ' + role + ': ' + name)
    if not re.fullmatch(r'[A-Za-z0-9._-]{3,60}', label):
        raise ValueError('Invalid builder job label')
    if not row['gate_approved'] and not label.startswith('parity-'):
        raise ValueError('Builder is not gate approved; only parity- labels are allowed')
    return {**row, 'parity_check': label.startswith('parity-')}


def receipt(builder):
    return {'Builder': builder['name'], 'BuilderHost': builder['host'],
            'BuilderComputerName': builder['computer_name'],
            'ParityCheck': builder['parity_check']}


def receipt_lines(builder):
    return [key + '=' + (str(value) if isinstance(value, bool) else value)
            for key, value in receipt(builder).items()]


def identity_ps(builder):
    """Read-only preflight; preserve builder1's additional UUID/MAC checks."""
    checks = ["$env:COMPUTERNAME -ine '" + builder['computer_name'] + "'"]
    if 'uuid' in builder:
        checks.append("(Get-CimInstance Win32_ComputerSystemProduct).UUID -ine '" + builder['uuid'] + "'")
    if 'mac' in builder:
        checks.append("-not @(Get-NetAdapter | Where-Object {$_.MacAddress -ieq '" + builder['mac'] + "'}).Count")
    return "$ErrorActionPreference='Stop'\nif(" + ' -or\n   '.join(checks) + "){throw 'Wrong builder; delivery refused.'}\n"


def remote_args(builder, role, label):
    return [builder['host'], '--role', role, '--label', label]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', required=True, choices=['kernel-sign', 'matrix', 'gate'])
    parser.add_argument('--label', required=True)
    parser.add_argument('--format', choices=['fields', 'preflight', 'receipt', 'json'], default='json')
    args = parser.parse_args()
    builder = select(args.role, args.label)
    if args.format == 'fields':
        print(' '.join(builder[key] for key in ('name', 'host', 'computer_name', 'ssh_user'))
              + ' ' + str(builder['parity_check']))
    elif args.format == 'preflight':
        print(identity_ps(builder), end='')
    elif args.format == 'receipt':
        print('\n'.join(receipt_lines(builder)))
        if builder['parity_check']:
            print('ParityCheck: not a gate')
    else:
        print(json.dumps(receipt(builder)))


if __name__ == '__main__':
    main()
