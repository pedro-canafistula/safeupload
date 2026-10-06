#!/usr/bin/env python3
"""Freeze agent worktree sources with an exact, hash-pinned new-file allowlist.

No Git mutation, upload, or VM operation. New input hashes must come from review;
this command does not approve or discover new files for inclusion automatically.
"""
import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    'snapshot', Path(__file__).with_name('Prepare-ExactWorktreeSource.py'))
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)

ROOTS = ('agente',)
TOOLS = ('driver/scripts/Build-ExactAgentMatrix.ps1',
         'driver/scripts/remote_ps.py',
         'driver/scripts/Prepare-ExactWorktreeSource.py',
         'driver/scripts/Prepare-ExactAgentWorktreeSource.py',
         'driver/scripts/Invoke-ExactAgentMatrixBuild.py')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--reviewed-untracked', type=Path)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--provenance-json')
    args = parser.parse_args()
    if args.verify:
        if not args.provenance_json or args.reviewed_untracked:
            parser.error('--verify requires --provenance-json and no new allowlist')
        print(snapshot.verify(args.output, json.loads(
            args.provenance_json, object_pairs_hook=unique_object), tools=TOOLS))
    else:
        if args.provenance_json or not args.reviewed_untracked:
            parser.error('capture requires --reviewed-untracked and no provenance')
        approved = json.loads(args.reviewed_untracked.read_text(encoding='utf-8'),
                              object_pairs_hook=unique_object)
        if (not isinstance(approved, dict)
                or any(not isinstance(n, str) or not isinstance(h, str)
                       or not n.startswith('agente/') or not n.endswith('.cs')
                       for n, h in approved.items())):
            parser.error('allowlist must map exact agente/*.cs input names to SHA-256')
        print(json.dumps(snapshot.capture(args.repo, args.output, roots=ROOTS,
                         tools=TOOLS, reviewed_untracked=approved), indent=2))
