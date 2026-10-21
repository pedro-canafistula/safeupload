#!/usr/bin/env python3
"""Offline check of relative Markdown links in the tracked documentation.

Usage: python3 driver/scripts/check-doc-links.py [--baseline FILE] [--write-baseline FILE]
Scans every tracked *.md file (inline links, reference definitions and <img>/<a> targets), resolves each relative target against
the file's directory and reports the ones that do not exist. Absolute URLs, mailto/#anchor-only links and the machine-local
absolute paths that older evidence notes contain are skipped, except repository-absolute paths under /home/victor/Work/safeupload-staging.
With --baseline (default: doc-links-baseline.txt beside this script), only links that are not in the baseline file are failures (exit 1);
--write-baseline records the current set. The baseline holds historical notes whose targets never existed in the repository.
No network, no VM. Heading anchors are not validated (file existence only)."""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
LOCAL_ABSOLUTE = '/home/victor/Work/safeupload-staging/'
DEFAULT_BASELINE = Path(__file__).resolve().parent / 'doc-links-baseline.txt'
INLINE = re.compile(r'(?<!\\)\]\(\s*(<[^>]+>|[^)\s]+)(?:\s+"[^"]*")?\s*\)')
REFERENCE = re.compile(r'^\s{0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)', re.M)
HTML = re.compile(r'(?:href|src)="([^"]+)"')
FENCE = re.compile(r'^(```|~~~).*?^\1', re.M | re.S)


def tracked_markdown():
    out = subprocess.run(['git', 'ls-files', '-z', '--', '*.md'], cwd=ROOT, capture_output=True, check=True).stdout
    return [p for p in out.decode('utf-8').split('\0') if p and '/node_modules/' not in p]


def targets(text):
    text = FENCE.sub('', text)
    for pattern in (INLINE, REFERENCE, HTML):
        for match in pattern.finditer(text):
            yield match.group(1).strip('<>')


def check():
    broken = set()
    for rel in tracked_markdown():
        path = ROOT / rel
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for target in targets(text):
            if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target) or target.startswith('#') or target.startswith('//'):
                continue
            target = unquote(target.split('#', 1)[0].split('?', 1)[0])
            target = re.sub(r':\d+(?:[-:]\d+)*$', '', target)  # editor-style file.c:319 or file.c:319-340
            if not target:
                continue
            if target.startswith('/'):
                if not target.startswith(LOCAL_ABSOLUTE):
                    continue
                resolved = ROOT / target[len(LOCAL_ABSOLUTE):]
            else:
                resolved = (path.parent / target)
            if not resolved.exists():
                # Keyed by the normalized repository path so moving a document (which changes its link text) is comparable.
                normalized = Path(os.path.normpath(resolved))
                try:
                    shown = normalized.relative_to(ROOT).as_posix()
                except ValueError:
                    shown = normalized.as_posix()
                broken.add(f'{rel} -> {shown}')
    return broken


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline')
    parser.add_argument('--write-baseline')
    args = parser.parse_args()
    if not args.baseline and not args.write_baseline and DEFAULT_BASELINE.is_file():
        args.baseline = str(DEFAULT_BASELINE)
    broken = check()
    if args.write_baseline:
        Path(args.write_baseline).write_text(''.join(line + '\n' for line in sorted(broken)), encoding='utf-8')
        print(f'DocLinks baseline written: {len(broken)} broken link(s)')
        return 0
    known = set()
    if args.baseline:
        known = {line.rstrip('\n') for line in Path(args.baseline).read_text(encoding='utf-8').splitlines() if line.strip()}
    new = sorted(broken - known)
    for line in new:
        print('BROKEN ' + line)
    print(f'DocLinks={"PASS" if not new else "FAIL"}; broken={len(broken)}; new={len(new)}; baseline={len(known)}')
    return 1 if new else 0


if __name__ == '__main__':
    sys.exit(main())
