#!/usr/bin/env python3
"""Offline agent test preflight before queuing a matrix (workflow rule 2, 2026-10-14). No build, network or VM.

1. Every test the matrix runner requires by name (STAGED_V20_REQUIRED_TESTS / _CASES in Invoke-ExactAgentMatrixBuild.py) exists as a
   test method of its class in the source, and every required theory case has its argument in the method's InlineData.
2. No test method discovered by the last passing matrix has disappeared from the source (a removed or renamed test is a stop).

This is a diagnostic: the matrix remains the gate (it cannot run theories or evaluate profile symbols here).
Usage: agent-test-preflight.py [--root <checkout>] --baseline <matrix-label>
"""
from pathlib import Path
import argparse
import importlib.util
import re
import sys

SCRIPTS = Path(__file__).resolve().parent
TEST_ATTRIBUTE = re.compile(r'\[\s*\w*(?:Fact|Theory)\b')  # includes custom ones such as [MachineFact]


def runner_requirements():
    spec = importlib.util.spec_from_file_location('matrix_runner', SCRIPTS / 'Invoke-ExactAgentMatrixBuild.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # top level only defines constants and functions
    return module.STAGED_V20_REQUIRED_TESTS, module.STAGED_V20_REQUIRED_CASES


def strip_comments(source):
    return re.sub(r'/\*.*?\*/|//[^\n]*', lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source, flags=re.S)


def class_spans(text):
    """(start, end, name) of every class body, matched by braces; records without a body are skipped."""
    spans = []
    for match in re.finditer(r'\bclass\s+(\w+)', text):
        brace = text.find('{', match.end())
        semicolon = text.find(';', match.end())
        if brace < 0 or (0 <= semicolon < brace and '(' not in text[match.end():semicolon]):
            continue
        depth, i = 0, brace
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        spans.append((brace, i, match.group(1)))
    return spans


def test_methods(root):
    """FQN -> attribute block text for every [Fact]/[Theory] method in the agent test project."""
    found = {}
    for path in sorted((root / 'agente/SafeUpload.Agent.Tests').rglob('*.cs')):
        if '/obj/' in path.as_posix() or '/bin/' in path.as_posix():
            continue
        source = strip_comments(path.read_text(encoding='utf-8-sig', errors='replace'))
        # Spans from a copy with string contents blanked (braces inside strings), attributes from the source (same offsets).
        text = re.sub(r'"(?:\\.|[^"\\\n])*"', lambda m: '"' + ' ' * (len(m[0]) - 2) + '"', source)
        namespace = re.search(r'^\s*namespace\s+([\w.]+)', text, re.M)
        namespace = namespace.group(1) if namespace else ''
        spans = class_spans(text)
        for match in re.finditer(r'(?:public|internal|private)?\s*(?:static\s+)?(?:async\s+)?(?:Task|void|ValueTask)\s+(\w+)\s*\(', text):
            lines = source[max(0, match.start() - 4000):match.start()].rstrip().split('\n')
            block = []
            for line in reversed(lines):
                stripped = line.strip()
                if stripped.startswith(('[', '#')) or stripped == '' or (block and stripped.endswith(']')):
                    block.append(stripped)
                    continue
                break
            attributes = '\n'.join(reversed(block))
            if not TEST_ATTRIBUTE.search(attributes):
                continue
            owners = [(b, e, name) for b, e, name in spans if b < match.start() < e]
            if not owners:
                continue
            owner = max(owners, key=lambda span: span[0])[2]  # innermost enclosing class
            fqn = '.'.join(filter(None, (namespace, owner, match.group(1))))
            found.setdefault(fqn, []).append(attributes)
    return found


def baseline_methods(evidence, label):
    files = sorted(evidence.glob(f'*/exact-agent-matrix-{label}-feature-debug-results-agent-tests-discovered-fq.txt'))
    if not files:
        print(f'STOP baseline {label}: no feature-debug discovered-tests list under {evidence}')
        raise SystemExit(2)
    names = set()
    for line in files[-1].read_text(encoding='utf-8-sig', errors='replace').splitlines():
        line = line.strip()
        if line:
            names.add(line.split('(')[0])
    return names, files[-1]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--root', type=Path, default=SCRIPTS.parents[1])
    parser.add_argument('--baseline', required=True, help='label of the last passing agent matrix, e.g. t5-block3')
    parser.add_argument('--evidence', type=Path, default=SCRIPTS.parent / 'evidence',
                        help='evidence directory holding matrix receipts (default: this checkout\'s driver/evidence)')
    args = parser.parse_args()
    root = args.root.resolve()
    required_tests, required_cases = runner_requirements()
    methods = test_methods(root)
    problems = []
    for cls, method in sorted(required_tests):
        if f'{cls}.{method}' not in methods:
            problems.append(f'required test missing from source: {cls}.{method}')
    for fqn, cases in sorted(required_cases.items()):
        blocks = '\n'.join(methods.get(fqn, []))
        for case in cases:
            if case is None:
                continue
            value = re.search(r'"([^"]*)"', case)
            if value and f'"{value.group(1)}"' not in blocks:
                problems.append(f'required case missing from InlineData: {fqn} {case}')
    baseline, path = baseline_methods(args.evidence.resolve(), args.baseline)
    removed = sorted(baseline - set(methods))
    for name in removed:
        problems.append(f'test removed or renamed since {args.baseline}: {name}')
    added = sorted(set(methods) - baseline)
    print(f'AgentTestPreflight root={root} baseline={args.baseline} ({path.name}) required={len(required_tests)} '
          f'source_methods={len(methods)} baseline_methods={len(baseline)} added={len(added)} removed={len(removed)}')
    for name in added:
        print('  added', name)
    for problem in problems:
        print('STOP', problem)
    print('AgentTestPreflight=' + ('FAIL' if problems else 'PASS'))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
