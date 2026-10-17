#!/usr/bin/env python3
"""Source guardrails for the namespace delta; not a PREfast/WDK result.

Audit both changed production translation units, with negative controls for the
reported annotation, residency, mixed-atomic and uninitialized-binding defects.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
K = ROOT / 'driver/SafeUpload.Minifilter'


def code(source):
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source, flags=re.S)


def definition_start(source, name):
    for m in re.finditer(r'\b'+re.escape(name)+r'\s*\(', source):
        i = source.index('(', m.start()) + 1
        depth = 1
        while depth:
            depth += (source[i] == '(') - (source[i] == ')')
            i += 1
        while source[i].isspace():
            i += 1
        if source[i] == '{':
            return m.start(), i
    raise AssertionError('Missing definition: '+name)


def audit(sources):
    sal = r'\b_(?:IRQL|In|Out|At|When|Success|Check_return|Must_inspect_result|Flt|Field|Post|Pre)\w*_'
    for file, source in sources.items():
        text = code(source)
        for m in re.finditer(r'_Use_decl_annotations_\s*([^;{}]+)\{', text):
            boundary = max(text.rfind(';', 0, m.start()), text.rfind('}', 0, m.start()),
                           text.rfind('{', 0, m.start())) + 1
            annotations = text[boundary:m.start()] + m[1]
            if re.search(sal, annotations):
                raise AssertionError(file+': _Use_decl_annotations_ combined with SAL')
        for pragma in re.finditer(r'#pragma\s+alloc_text\(\s*PAGE\s*,\s*(\w+)\s*\)', text):
            start, _ = definition_start(text, pragma[1])
            if pragma.start() > start:
                raise AssertionError(file+': late PAGE pragma '+pragma[1])
    stream = code(sources['StageStream.c'])
    for variable, ctype in (('StageDirectorySequence', 'LONG64'), ('StageDirectoryMutationActive', 'LONG')):
        spans = [m.span() for m in re.finditer(r'static\s+volatile\s+'+ctype+r'\s+'+variable+r'\s*;', stream)]
        spans += [m.span() for m in re.finditer(r'\bInterlocked\w+\s*\(\s*&'+variable+r'\b', stream)]
        for m in re.finditer(r'\b'+variable+r'\b', stream):
            if not any(a <= m.start() < b for a, b in spans):
                raise AssertionError('Non-interlocked access: '+variable)
    for m in re.finditer(r'\bSTAGE_NAMESPACE_BINDINGS\s+\w+\s*(=\s*\{0\})?\s*;', stream):
        if m[1] is None:
            raise AssertionError('Uninitialized namespace bindings')
    a, body = definition_start(stream, 'StageInstallRenameExchange')
    b = stream.index('\n}', body) + 2
    helper = stream[a:b]
    if 'PAGED_CODE' in helper or 'alloc_text(PAGE, StageInstallRenameExchange)' in stream:
        raise AssertionError('Spin section must be resident')
    header = stream[stream.rfind('}', 0, a)+1:body]
    if '_IRQL_requires_max_(DISPATCH_LEVEL)' not in header or '_IRQL_requires_same_' not in header:
        raise AssertionError('Resident helper must allow DISPATCH and restore incoming IRQL')
    _, a = definition_start(stream, 'StageRename')
    b = stream.index('\ntypedef struct _STAGE_PAGING_IO', a)
    rename = stream[a:b]
    if 'StageStreamAcquireSpinLock' in rename or 'StageInstallRenameExchange(Stream, exchange)' not in rename:
        raise AssertionError('PAGE rename must not execute the spin section')


class NamespaceContracts(unittest.TestCase):
    def test_changed_translation_units(self):
        audit({f: (K/f).read_text() for f in ('StageStream.c', 'StageWriters.c')})

    def test_reported_patterns_are_rejected(self):
        source = {f: (K/f).read_text() for f in ('StageStream.c', 'StageWriters.c')}
        for old, new in (
            ('_Use_decl_annotations_\nstatic BOOLEAN StageRenameShareAllowed', '_IRQL_requires_max_(APC_LEVEL)\n_Use_decl_annotations_\nstatic BOOLEAN StageRenameShareAllowed'),
            ('_Use_decl_annotations_\nstatic BOOLEAN StageMvpNamespaceOpen', '_IRQL_requires_max_(APC_LEVEL)\n_Use_decl_annotations_\nstatic BOOLEAN StageMvpNamespaceOpen'),
            ('namespaceSequence = InterlockedCompareExchange64(&StageDirectorySequence, 0, 0);', 'namespaceSequence = StageDirectorySequence;'),
            ('STAGE_NAMESPACE_BINDINGS bindings = {0};', 'STAGE_NAMESPACE_BINDINGS bindings;'),
            ('StageInstallRenameExchange(Stream, exchange);', 'StageStreamAcquireSpinLock(&StageListLock, &irql);'),
        ):
            with self.subTest(pattern=old):
                self.assertIn(old, source['StageStream.c'])
                changed = dict(source, **{'StageStream.c': source['StageStream.c'].replace(old, new)})
                with self.assertRaises(AssertionError):
                    audit(changed)
        # Moving an existing pragma below its definition must also be caught.
        changed = dict(source)
        pragma = '#pragma alloc_text(PAGE, StageMvpNamespaceOpen)'
        changed['StageStream.c'] = source['StageStream.c'].replace(pragma, '')+'\n'+pragma+'\n'
        with self.assertRaises(AssertionError):
            audit(changed)


if __name__ == '__main__':
    unittest.main()
